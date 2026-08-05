//! The scan command.
//!
//! Walks a project, parses what it can, runs the rules and emits a report. The
//! parts that matter are the ones that keep the report honest: every file the
//! walk could not read reaches the coverage statement, every import no rule
//! claims is listed rather than dropped, and every rule that failed to load or
//! compile reaches the report as a diagnostic.
//!
//! Two invariants hold the last of those together. A grammar with no usable rule
//! set is not scanned, so its files are declared as unparsed rather than counted
//! as read. And a run whose rules did not all load refuses to report a pass,
//! because a clean report produced by an engine with no rules in it is the exact
//! failure this tool exists to find elsewhere.
//!
//! When the caller points the run at a directory of runtime events, or at one of
//! network flows, the same walk gains a second half: what was observed is read,
//! reconciled against the code points the walk found, and whatever the sources
//! disagree about reaches the report as a derived finding. That half is opt in,
//! and deliberately so. A run with neither directory produces the report it
//! always produced, declares itself `static_only`, and derives nothing, because
//! a source that did not run is never compensated for. In particular `full` is
//! never written by a run that was handed no flows.

mod reconcile;

use std::collections::BTreeSet;
use std::path::Path;

use periskop_core::coverage::UnparsedReason;
use periskop_core::finding::Finding;
use periskop_reconcile::settings::ReconcileSettings;
use periskop_report::coverage::{
    CoverageLanguage, CoverageStatement, RuntimeCoverage, RuntimeStatus, UnparsedFile,
};
use periskop_report::report::{
    Diagnostic, DiagnosticCode, DiagnosticComponent, Envelope, ReportBuilder, RuleHit, ScanInputs,
    ScanReport, Verdict,
};
use periskop_static_scanner::discovery::{discover, read_source, DiscoveryOptions};
use periskop_static_scanner::engine::detect;
use periskop_static_scanner::language::Language;
use periskop_static_scanner::parser::parse_as;
use periskop_static_scanner::rules::compiler::compile_partial;
use periskop_static_scanner::rules::{load_directory, CompiledRules, RuleFile};

use crate::policy::ScanPolicy;

pub use reconcile::ScanSources;

/// Policy rule id recorded when the rule set did not load cleanly.
///
/// Named here rather than inline because it is the join key between the verdict
/// and the diagnostics that explain it.
const RULE_SET_GATE: &str = "engine.rule-set-loaded";

/// Everything the scan needs to know about where things live.
pub struct ScanRequest<'a> {
    pub project_root: &'a Path,
    pub rules_root: &'a Path,
    pub tool_version: &'a str,
    /// Supplied by the caller rather than read here, so this function stays
    /// deterministic and testable. The clock belongs in the envelope, which is
    /// the one block excluded from the body hash.
    pub generated_at: String,
}

pub struct ScanOutcome {
    pub report: ScanReport,
    /// Problems loading or compiling rules. Also carried in the report as
    /// diagnostics; this copy is what the command line prints to stderr.
    pub rule_errors: Vec<String>,
}

/// A static only scan, which is what a run without runtime hooks can support.
///
/// Kept as its own entry point rather than folded into [`run_with_events`] with
/// an extra field on [`ScanRequest`]. The request is built by more than one
/// caller, and a new required field would make every one of them state a runtime
/// source it does not have.
pub fn run(request: ScanRequest<'_>) -> ScanOutcome {
    run_with_sources(
        request,
        ScanSources::default(),
        ReconcileSettings::default(),
    )
}

/// The same scan, reconciled against what the runtime hooks recorded.
///
/// `None` is not "an empty event directory". It is the absence of the runtime
/// source altogether, and the two produce different reports on purpose: an empty
/// directory means the hooks were watching and saw no calls, while no directory
/// means nobody was watching. Reading the first as the second is how a tool ends
/// up reporting a live codebase as dead.
pub fn run_with_events(request: ScanRequest<'_>, event_dir: Option<&Path>) -> ScanOutcome {
    run_with_events_and_settings(request, event_dir, ReconcileSettings::default())
}

/// The same scan with every observation source the caller has.
///
/// The entry point the command line uses. The three narrower ones above remain
/// because they are what several callers already state, and widening their
/// signatures would make each of them name a source it has no opinion about.
///
/// The third argument is the policy this run was decided under, and
/// [`ReconcileSettings`] converts into one, so a caller that has thresholds and
/// no document keeps the shorter call. The command line hands over a real
/// [`ScanPolicy`], which carries the document's identity into the report and the
/// refusal into the verdict when the file could not be applied.
pub fn run_with_sources(
    request: ScanRequest<'_>,
    sources: ScanSources<'_>,
    policy: impl Into<ScanPolicy>,
) -> ScanOutcome {
    scan(request, sources, policy.into())
}

/// The same run, with the reconciliation thresholds stated by the caller.
///
/// Only one threshold exists today and it decides whether this run may say a
/// code point never executed: `min_dormant_window_ms`, ten minutes by default,
/// because an absence observed over five minutes tells nobody anything. The
/// default belongs to the product, but the number cannot only be a default. A
/// short lived batch job is watched for seconds and a soak test for hours, and
/// the same threshold cannot serve both; a caller that cannot state it is left
/// choosing between a claim it cannot support and no claim at all.
///
/// Kept as a separate entry point rather than a field on [`ScanRequest`], for
/// the reason [`run`] gives: the request is built by several callers and a new
/// required field would make every one of them state a threshold it has no
/// opinion about. The command line states these thresholds through
/// `periskop-policy.toml` rather than through a flag, which is where the policy
/// contract puts them: a knob that changes which findings exist and leaves no
/// trace in the report is worse than no knob, and the policy travels into
/// `policy_ref` where a reader can see which thresholds decided the run.
pub fn run_with_events_and_settings(
    request: ScanRequest<'_>,
    event_dir: Option<&Path>,
    settings: ReconcileSettings,
) -> ScanOutcome {
    scan(
        request,
        ScanSources {
            event_dir,
            flow_dir: None,
        },
        settings.into(),
    )
}

/// The walk itself, with whatever observation sources the caller stated.
fn scan(request: ScanRequest<'_>, sources: ScanSources<'_>, policy: ScanPolicy) -> ScanOutcome {
    let settings = policy.settings().clone();
    let (rules, load_errors) = load_directory(request.rules_root);
    let mut rule_errors: Vec<String> = load_errors.iter().map(|e| e.to_string()).collect();

    // A rule set with nothing in it is not a clean rule set. `load_directory`
    // reports the files it could not read and has nothing to say about a
    // directory that held no rule at all, so a scan pointed at an empty or wrong
    // path walked the whole tree with no detector loaded, found nothing, and
    // reported a pass with a full coverage claim behind it. That is the defect
    // this product exists to report, produced by the product: a check that looks
    // like it covers something and covers nothing. The path is deliberately not
    // in the detail, because a report has to diff equal across machines.
    if rules.is_empty() {
        rule_errors.push(
            "the rule set loaded no rule at all, so no detector ran and a clean report here \
             would mean nothing was looked for"
                .to_owned(),
        );
    }

    let discovery = discover(request.project_root, &DiscoveryOptions::default());

    let mut builder = ReportBuilder::new();
    let mut coverage = CoverageStatement::static_only();
    let mut unclaimed: BTreeSet<String> = BTreeSet::new();
    // Engine faults, kept apart from rule problems because they are a different
    // claim: a rule that will not load is a file someone wrote, an engine fault
    // is the scanner disagreeing with itself. Both reach the report, neither
    // reaches the coverage counters (K-10).
    let mut engine_faults: BTreeSet<String> = discovery.diagnostics.iter().cloned().collect();

    coverage.unparsed_files = discovery
        .skipped
        .iter()
        .map(|s| UnparsedFile {
            path: report_path(&s.path),
            reason: s.reason,
        })
        .collect();

    let compiled = compile_rule_families(&rules, &mut rule_errors);

    let mut parsed_files = 0u64;
    // Every grammar a file was found for, whether or not it could be scanned.
    // The runtime block is built from this rather than from a fixed list, so a
    // repository in a language the list forgot is not left unmentioned.
    let mut languages_seen: BTreeSet<Language> = BTreeSet::new();
    // Held here rather than handed straight to the builder, because
    // reconciliation reads the code side out of these findings and the builder
    // does not give them back. The builder still decides their order and their
    // identity; this is only where they wait.
    let mut static_findings: Vec<Finding> = Vec::new();

    for file in &discovery.files {
        languages_seen.insert(file.language);
        // The rule lookup happens before the file is read, and that order is the
        // fix rather than an optimisation. A grammar with no usable detector was
        // never examined, so counting its files as parsed would turn "nobody
        // looked here" into "looked here and found nothing".
        let Some((_, compiled_rules, family_rules)) =
            compiled.iter().find(|(l, _, _)| *l == file.language)
        else {
            coverage.unparsed_files.push(UnparsedFile {
                path: report_path(&file.path),
                // no_grammar out of the eight fixed reasons. The set is closed by
                // contract, and this is the member that means "the language was
                // recognised, and this build still has no way to analyse it".
                // A grammar with no rule family bound to it can produce a syntax
                // tree and nothing else, which is the same blind spot from the
                // reader's side: recognised, not analysed. The alternatives all
                // say something untrue. parse_error and partial_parse claim the
                // file was read, unknown_language claims the extension was not
                // recognised, and io_error claims the disk refused it.
                reason: UnparsedReason::NoGrammar,
            });
            continue;
        };

        let source = match read_source(request.project_root, &file.path) {
            Ok(source) => source,
            Err(reason) => {
                coverage.unparsed_files.push(UnparsedFile {
                    path: report_path(&file.path),
                    reason,
                });
                continue;
            }
        };

        let parsed = match parse_as(file.path.clone(), source, file.language) {
            Ok(parsed) => parsed,
            Err(failure) => {
                coverage.unparsed_files.push(UnparsedFile {
                    path: report_path(&file.path),
                    reason: failure.coverage_reason(),
                });
                continue;
            }
        };

        parsed_files += 1;

        // A file the grammar only half understood still yields findings from the
        // regions that parsed, and still owes the reader a coverage entry for the
        // regions that did not.
        if parsed.is_partial() {
            coverage.unparsed_files.push(UnparsedFile {
                path: report_path(&file.path),
                reason: UnparsedReason::PartialParse,
            });
        }

        let found = detect(&parsed, compiled_rules, family_rules);
        unclaimed.extend(found.unclaimed_imports);
        coverage.unresolved_targets.extend(found.unresolved_targets);
        engine_faults.extend(found.engine_faults);
        static_findings.extend(found.findings);
    }

    // The observation half runs on the complete code side, so it sits after the
    // walk rather than inside it. A point reconciled file by file would be
    // compared against whichever records happened to have been read by then, and
    // the result would depend on the walk order.
    if sources.any() {
        let stage = reconcile::run(sources, &static_findings, &settings);
        coverage.dropped_events = stage.dropped_events;
        coverage.unlinked_events = stage.unlinked_events;
        coverage.unresolved_event_targets = stage.unresolved_event_targets;
        coverage.observation_window_ms = stage.observation_window_ms;
        coverage.reconciliation_mode = stage.reconciliation_mode;
        // Written only when a sensor fed the run. Five zeros left by a static
        // scan would say the sensor watched and the machine stayed quiet, and
        // three of the buckets are the ones that produce no finding: a bucket
        // that keeps traffic out of the count and then reads as an observation
        // nobody made is the silent swallow K-15 exists to prevent.
        //
        // `in_scope_flows` is written with them because the other three are
        // meaningless without it. A reader who is told 412 flows were out of
        // scope cannot act on that number until the report also says what it is
        // 412 of, and K-15's attribution accuracy gate is a ratio nobody can
        // compute from a numerator.
        if let Some(wire) = stage.wire {
            coverage.in_scope_flows = wire.in_scope_flows;
            coverage.out_of_scope_flows = wire.out_of_scope_flows;
            coverage.known_benign_flows = wire.known_benign_flows;
            coverage.unattributed_flows = wire.unattributed_flows;
            coverage.unclassified_flows = wire.unclassified_flows;
            coverage.sensor_platform_class = stage.sensor_platform_class;
        }
        for diagnostic in stage.diagnostics {
            builder.add_diagnostic(diagnostic);
        }
        builder.add_findings(stage.findings);
    }

    builder.add_findings(static_findings);

    coverage.parsed_files = parsed_files;
    coverage.undetected_libraries = unclaimed.into_iter().collect();
    coverage.runtime_coverage = if languages_seen.is_empty() {
        every_coverage_language()
    } else {
        runtime_coverage_for(&languages_seen)
    };

    // Without these the scan identity would rest on the findings alone, so two
    // unrelated trees that happen to produce the same result would share a
    // report id. The rule set digest is folded in for the same reason: changing
    // which detectors ran changes what the report means, even when the findings
    // come out identical.
    builder.scan_inputs(ScanInputs {
        scan_root_id: scan_root_id(request.project_root),
        rule_set_hash: rule_set_hash(&rules),
    });

    // Rule problems travel as diagnostics, never as coverage. Coverage counts what
    // the scan could not read; a rule that would not compile is a different thing,
    // and mixing the two would make any threshold over coverage meaningless.
    for detail in &rule_errors {
        builder.add_diagnostic(Diagnostic {
            code: DiagnosticCode::RuleLoadError,
            component: DiagnosticComponent::StaticScanner,
            detail: Some(detail.clone()),
        });
    }

    for detail in engine_faults {
        builder.add_diagnostic(internal_diagnostic(
            DiagnosticComponent::StaticScanner,
            detail,
        ));
    }

    // What the policy file had to say about itself: a document this build
    // refused, or rules it read and does not evaluate. Both are claims about the
    // run rather than about the code, so they travel as diagnostics, and the
    // refusal also travels as a failing hit below.
    for diagnostic in policy.diagnostics() {
        builder.add_diagnostic(diagnostic);
    }

    // Two gates, one list. A broken rule set and an unapplied policy both stop a
    // run from reporting a pass, and neither may hide the other: a report that
    // named only the first would send somebody to fix the rules while the policy
    // they wrote was still being ignored.
    let mut rule_hits = rule_set_hits(&rule_errors);
    rule_hits.extend(policy.rule_hits());
    rule_hits.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));

    let report = builder.build(
        Envelope {
            generated_at: request.generated_at,
            tool_version: request.tool_version.to_owned(),
            host: None,
        },
        policy.policy_ref(rule_hits),
        coverage,
    );

    ScanOutcome {
        report,
        rule_errors,
    }
}

/// The engine reporting on its own run, in the one code the contract leaves for
/// anything that is not a named load failure.
fn internal_diagnostic(component: DiagnosticComponent, detail: String) -> Diagnostic {
    Diagnostic {
        code: DiagnosticCode::Internal,
        component,
        detail: Some(detail),
    }
}

/// Stable identity for the scanned tree.
///
/// Derived from the directory name rather than the full path. An absolute path
/// would put the build machine into an identity that has to compare equal across
/// machines, which is the property the whole report rests on.
fn scan_root_id(root: &Path) -> String {
    let name = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project");
    periskop_core::ids::short_hash("root/v1", &[name])
}

/// Digest of the rule set that actually loaded.
///
/// Built from each rule's own content hash, sorted, so the digest tracks what the
/// engine ran rather than the order the files happened to be read in.
fn rule_set_hash(rules: &[RuleFile]) -> String {
    let mut parts: Vec<&str> = rules.iter().map(|r| r.rule_hash.as_str()).collect();
    parts.sort_unstable();
    periskop_core::ids::short_hash("rs/v1", &parts)
}

/// Compiles each grammar's rule family and records every rule that failed.
///
/// A family that yielded no usable pattern is left out of the result. That
/// omission is what sends its files to the coverage statement in the loop above:
/// there is no compiled entry to find, so nothing claims those files were read.
fn compile_rule_families(
    rules: &[RuleFile],
    errors: &mut Vec<String>,
) -> Vec<(Language, CompiledRules, Vec<RuleFile>)> {
    // Rules are compiled once per grammar rather than once per file. Compiling
    // inside the file loop would repeat identical work for every source file.
    let mut compiled = Vec::new();

    for language in Language::ALL {
        let for_family: Vec<RuleFile> = rules
            .iter()
            .filter(|r| r.language == language.rule_family())
            .cloned()
            .collect();
        if for_family.is_empty() {
            continue;
        }

        let outcome = compile_partial(language, &for_family);
        // The grammar is named, not only the family. Three grammars draw from the
        // TypeScript family, and a query can compile against one and fail against
        // another, so "typescript" alone would not tell the reader which.
        errors.extend(
            outcome
                .errors
                .iter()
                .map(|e| format!("{language:?} grammar: {e}")),
        );

        if let Some(usable) = outcome.compiled.filter(|c| c.pattern_count() > 0) {
            compiled.push((language, usable, for_family));
        }
    }

    compiled
}

/// The rule hit that stops a scan with a broken rule set from reporting a pass.
///
/// The verdict is computed from rule hits and nothing else, so a run whose rules
/// did not load has to record one here or it exits zero with an empty finding
/// list and a full coverage claim. Recording it as a failed hit is what makes the
/// diagnostics above load bearing rather than decorative.
fn rule_set_hits(rule_errors: &[String]) -> Vec<RuleHit> {
    if rule_errors.is_empty() {
        return Vec::new();
    }
    vec![RuleHit {
        rule_id: RULE_SET_GATE.to_owned(),
        verdict: Verdict::Fail,
        finding_ids: None,
        coverage_condition: None,
    }]
}

/// A path as the report spells it: relative to the scan root, forward slashed.
///
/// Written once because every coverage entry needs the same spelling. A backslash
/// would make the same tree serialize differently on Windows, and two reports of
/// one tree are supposed to compare equal.
fn report_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// What the runtime layer saw, which in this build is nothing at all.
///
/// Two things were wrong with the list this replaces, and both told the reader
/// something untrue.
///
/// The two statuses carry different meanings and the contract keeps them apart on
/// purpose: `not_instrumented` is a switch the user did not turn on, `unsupported`
/// is a gap in the product. A reader who sees the first goes looking for the
/// switch, and one who sees the second does not, so reporting the wrong one wastes
/// their time or hides a real limit.
///
/// Which one applies is therefore a property of the language rather than of the
/// run. Python and Node ship hooks, so a static only scan of them is a choice not
/// yet made. Go and Java have no hook in this build, and saying otherwise would
/// send a reader hunting for a switch that does not exist.
///
/// The list was also fixed at three languages, so a repository of Go or Java
/// source had no runtime line at all. It is built from the grammars the scan
/// actually saw instead.
fn runtime_status_for(language: Language) -> RuntimeStatus {
    match language {
        // A hook exists and this run did not use it.
        Language::Python | Language::TypeScript | Language::Tsx | Language::JavaScript => {
            RuntimeStatus::NotInstrumented
        }
        // No mechanism is defined for these yet.
        Language::Go | Language::Java => RuntimeStatus::Unsupported,
    }
}

fn runtime_coverage_for(languages: &BTreeSet<Language>) -> Vec<RuntimeCoverage> {
    let mut out: Vec<RuntimeCoverage> = languages
        .iter()
        .map(|language| RuntimeCoverage {
            language: language.coverage_language(),
            status: runtime_status_for(*language),
            hook_mechanism: None,
        })
        .collect();
    // TypeScript and TSX report under one name, so the two grammars would
    // otherwise produce the same line twice.
    out.sort();
    out.dedup();
    out
}

/// Every language the coverage vocabulary can name, for a scan that found none.
///
/// A report with an empty runtime block says nothing about any language, which
/// is the silence the block exists to break. When the walk turned up no source
/// at all there is no observed set to build from, so the full vocabulary is
/// declared unsupported.
fn every_coverage_language() -> Vec<RuntimeCoverage> {
    [
        CoverageLanguage::Python,
        CoverageLanguage::Typescript,
        CoverageLanguage::Javascript,
        CoverageLanguage::Java,
        CoverageLanguage::Csharp,
        CoverageLanguage::Go,
        CoverageLanguage::Rust,
        CoverageLanguage::Kotlin,
        CoverageLanguage::Ruby,
        CoverageLanguage::Php,
    ]
    .into_iter()
    .map(|language| RuntimeCoverage {
        language,
        status: RuntimeStatus::Unsupported,
        hook_mechanism: None,
    })
    .collect()
}
