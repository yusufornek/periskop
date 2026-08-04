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

use std::collections::BTreeSet;
use std::path::Path;

use periskop_core::coverage::UnparsedReason;
use periskop_report::coverage::{CoverageStatement, RuntimeCoverage, RuntimeStatus, UnparsedFile};
use periskop_report::report::{
    Diagnostic, DiagnosticCode, DiagnosticComponent, Envelope, PolicyRef, ReportBuilder, RuleHit,
    ScanInputs, ScanReport, VerdictOrder,
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

pub fn run(request: ScanRequest<'_>) -> ScanOutcome {
    let (rules, load_errors) = load_directory(request.rules_root);
    let mut rule_errors: Vec<String> = load_errors.iter().map(|e| e.to_string()).collect();

    let discovery = discover(request.project_root, &DiscoveryOptions::default());

    let mut builder = ReportBuilder::new();
    let mut coverage = CoverageStatement::static_only();
    let mut unclaimed: BTreeSet<String> = BTreeSet::new();

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

    for file in &discovery.files {
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
        builder.add_findings(found.findings);
    }

    coverage.parsed_files = parsed_files;
    coverage.undetected_libraries = unclaimed.into_iter().collect();
    coverage.runtime_coverage = runtime_coverage_for_static_scan();

    builder.coverage(coverage);

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
    );

    ScanOutcome {
        report,
        rule_errors,
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
        verdict: VerdictOrder::Fail,
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

/// What the runtime layer saw, which in a static scan is nothing.
///
/// Reported explicitly rather than left empty. "No hook was running" and "the
/// hook found nothing" look the same in an empty list and mean opposite things.
fn runtime_coverage_for_static_scan() -> Vec<RuntimeCoverage> {
    ["python", "typescript", "javascript"]
        .into_iter()
        .map(|language| RuntimeCoverage {
            language: language.to_owned(),
            status: RuntimeStatus::NotInstrumented,
            hook_mechanism: None,
        })
        .collect()
}
