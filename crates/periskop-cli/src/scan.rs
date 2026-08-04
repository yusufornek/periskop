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
//! When the caller points the run at a directory of runtime events the same walk
//! gains a second half: the events are read, reconciled against the code points
//! the walk found, and whatever the two sources disagree about reaches the report
//! as a derived finding. That half is opt in, and deliberately so. A run with no
//! event directory produces the report it always produced, declares itself
//! `static_only`, and derives nothing, because a source that did not run is never
//! compensated for.

use std::collections::BTreeSet;
use std::path::Path;

use periskop_core::coverage::UnparsedReason;
use periskop_core::finding::{Finding, Kind};
use periskop_reconcile::capability::Suppression;
use periskop_reconcile::{
    reconcile, DeclaredPoint, DeclaredSource, ObservationWindow, ReconcileInputs, RuntimeSource,
    Sources, WireSource,
};
use periskop_report::coverage::{
    CoverageLanguage, CoverageStatement, ReconciliationMode, RuntimeCoverage, RuntimeStatus,
    UnparsedFile,
};
use periskop_report::report::{
    Diagnostic, DiagnosticCode, DiagnosticComponent, Envelope, PolicyRef, ReportBuilder, RuleHit,
    ScanInputs, ScanReport, Verdict,
};
use periskop_static_scanner::discovery::{discover, read_source, DiscoveryOptions};
use periskop_static_scanner::engine::detect;
use periskop_static_scanner::language::Language;
use periskop_static_scanner::parser::parse_as;
use periskop_static_scanner::rules::compiler::compile_partial;
use periskop_static_scanner::rules::{load_directory, CompiledRules, RuleFile};

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
    run_with_events(request, None)
}

/// The same scan, reconciled against what the runtime hooks recorded.
///
/// `None` is not "an empty event directory". It is the absence of the runtime
/// source altogether, and the two produce different reports on purpose: an empty
/// directory means the hooks were watching and saw no calls, while no directory
/// means nobody was watching. Reading the first as the second is how a tool ends
/// up reporting a live codebase as dead.
pub fn run_with_events(request: ScanRequest<'_>, event_dir: Option<&Path>) -> ScanOutcome {
    let (rules, load_errors) = load_directory(request.rules_root);
    let mut rule_errors: Vec<String> = load_errors.iter().map(|e| e.to_string()).collect();

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

    // The runtime half runs on the complete code side, so it sits after the walk
    // rather than inside it. A point reconciled file by file would be compared
    // against whichever events happened to have been read by then, and the
    // result would depend on the walk order.
    if let Some(event_dir) = event_dir {
        let stage = reconcile_stage(event_dir, &static_findings);
        coverage.dropped_events = stage.dropped_events;
        coverage.unlinked_events = stage.unlinked_events;
        coverage.observation_window_ms = stage.observation_window_ms;
        coverage.reconciliation_mode = stage.reconciliation_mode;
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

    let report = builder.build(
        Envelope {
            generated_at: request.generated_at,
            tool_version: request.tool_version.to_owned(),
            host: None,
        },
        PolicyRef {
            policy_id: "default".to_owned(),
            policy_version: "1.0.0".to_owned(),
            policy_hash: blake3::hash(b"default/1.0.0").to_hex().to_string(),
            rule_hits: rule_set_hits(&rule_errors),
        },
        coverage,
    );

    ScanOutcome {
        report,
        rule_errors,
    }
}

/// What the runtime half of a run contributed.
///
/// Collected into one value rather than written into the report as it is
/// produced, so the static path cannot be reached by any of it. A run with no
/// event directory never builds one of these, and therefore its coverage
/// counters and its diagnostics come out exactly as they did before this half
/// existed.
struct ReconciledStage {
    findings: Vec<Finding>,
    diagnostics: Vec<Diagnostic>,
    dropped_events: u64,
    unlinked_events: u64,
    observation_window_ms: u64,
    reconciliation_mode: ReconciliationMode,
}

/// Reads the hook's event stream and reconciles it against the code side.
///
/// Returns a stage rather than a `Result` for the reason the collector states
/// one layer down: damaged events are data. A scan that abandoned its report
/// because an event file was truncated would hand any misbehaving hook the power
/// to blind the whole run.
fn reconcile_stage(event_dir: &Path, static_findings: &[Finding]) -> ReconciledStage {
    let collected = periskop_runtime_collector::collect(event_dir);

    // Every line the collector could not read is named here. The count alone
    // reaches `dropped_events` below, and a count with no location is a number
    // nobody can act on. Files it could not open at all raise no count, so
    // without this they would leave no trace anywhere.
    let mut diagnostics: Vec<Diagnostic> = collected
        .malformed
        .iter()
        .map(|loss| {
            internal_diagnostic(
                DiagnosticComponent::RuntimeHooks,
                format!("event stream: {loss}"),
            )
        })
        .collect();

    let points = declared_points(static_findings, &mut diagnostics);

    // The wire source is absent by construction, not by configuration: this
    // build ships no network sensor, so there is no value a caller could pass
    // that would make it present. That is what keeps `reconciliation_mode` from
    // ever being written as `full` here, and the two kinds that need the wire
    // are reported as suppressed rather than left as silence.
    let sources = Sources::new(
        DeclaredSource::Present(points),
        RuntimeSource::Present(collected.events),
        WireSource::Absent,
    );

    // No window is claimed. `schemas/egress-event.schema.json` carries no clock
    // value, by design, so nothing in the event stream says how long the hooks
    // were watching, and the command line has no second source to read it from.
    // Declaring a duration it did not measure would be inventing the one fact
    // every `dormant_egress_point` finding rests on, so the run declares none
    // and the suppression that follows says exactly that.
    let outcome = reconcile(&ReconcileInputs::new(sources, ObservationWindow::NONE));

    diagnostics.extend(outcome.suppressed.iter().map(suppression_diagnostic));
    // The engine disagreeing with itself. A diagnostic, never a coverage
    // counter: a derivation that failed is a different thing from something the
    // run could not see.
    diagnostics.extend(
        outcome
            .faults
            .iter()
            .map(|fault| internal_diagnostic(DiagnosticComponent::Reconciliation, fault.clone())),
    );

    // Two parts of the outcome have no home in the report contract and are
    // therefore not written anywhere. `resolved_targets` is the destination an
    // observation supplied for a point the scanner could not read: dropping the
    // point from `coverage.unresolved_targets` on the strength of it would
    // delete a declared gap without recording what replaced it, since no field
    // carries the observed value. `matches` is the join ladder, which the derived
    // findings already carry in their own evidence. Both are filed as contract
    // requests in `hub/memory/interfaces.md` rather than approximated here.
    ReconciledStage {
        findings: outcome.findings,
        diagnostics,
        dropped_events: collected.dropped,
        unlinked_events: outcome.unlinked_events,
        observation_window_ms: outcome.observation_window_ms,
        reconciliation_mode: outcome.reconciliation_mode,
    }
}

/// The code side of the join, read out of the findings the walk produced.
///
/// Suspected findings are included. A call site the scanner could not fully
/// prove is still a place in the code, and leaving it out would make it
/// invisible to reconciliation entirely; what it cannot do is strengthen a
/// derived claim, because a downgraded point carries no destination and the
/// drift rule has nothing to compare.
fn declared_points(findings: &[Finding], diagnostics: &mut Vec<Diagnostic>) -> Vec<DeclaredPoint> {
    findings
        .iter()
        .filter(|finding| finding.kind == Kind::DeclaredEgressPoint)
        .filter_map(|finding| match DeclaredPoint::from_finding(finding) {
            Ok(point) => Some(point),
            // A finding this build produced and cannot read back is the scanner
            // and the reconciler disagreeing about the contract between them.
            // Skipping it silently would drop a code point out of reconciliation
            // with nothing in the report to show it was ever there.
            Err(error) => {
                diagnostics.push(internal_diagnostic(
                    DiagnosticComponent::Reconciliation,
                    format!(
                        "{} could not be read as a code point: {error}",
                        finding.finding_id
                    ),
                ));
                None
            }
        })
        .collect()
}

/// A derived kind this run did not produce, written where a reader will find it.
///
/// The report has two places a statement like this can go and neither was built
/// for it. The coverage statement counts what the scan could not read and its
/// field list is closed, so a suppression has no counter there; `diagnostics[]`
/// is the block for everything the engine has to say about its own run, and its
/// `detail` field is free text. `INTERNAL` is the only code in the closed enum
/// not already claimed by a specific failure, so it is the one used, and the
/// detail carries the contract spelling of both the kind and the reason. A
/// dedicated code is filed against the contract owner in
/// `hub/memory/interfaces.md`; until it exists, this is the choice that loses
/// nothing.
fn suppression_diagnostic(suppression: &Suppression) -> Diagnostic {
    // Serialized rather than matched on, so a reason renamed in the contract
    // cannot leave this line reporting a vocabulary that no longer exists. The
    // fallback keeps the reason readable if it ever stops being a plain string.
    let reason = serde_json::to_value(suppression.reason)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{:?}", suppression.reason));

    internal_diagnostic(
        DiagnosticComponent::Reconciliation,
        format!(
            "not derived: {} ({reason})",
            suppression.kind.kind().as_str()
        ),
    )
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
