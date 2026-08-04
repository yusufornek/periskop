//! The scan command.
//!
//! Walks a project, parses what it can, runs the rules and emits a report. The
//! parts that matter are the ones that keep the report honest: every file the
//! walk could not read reaches the coverage statement, and every import no rule
//! claims is listed rather than dropped.

use std::collections::BTreeSet;
use std::path::Path;

use periskop_core::coverage::UnparsedReason;
use periskop_report::coverage::{CoverageStatement, RuntimeCoverage, RuntimeStatus, UnparsedFile};
use periskop_report::report::{Envelope, PolicyRef, ReportBuilder, ScanReport};
use periskop_static_scanner::discovery::{discover, read_source, DiscoveryOptions};
use periskop_static_scanner::engine::detect;
use periskop_static_scanner::language::Language;
use periskop_static_scanner::parser::parse_as;
use periskop_static_scanner::rules::{compile, load_directory, RuleFile};

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
    /// Problems loading rules. Reported as diagnostics, never as coverage.
    pub rule_errors: Vec<String>,
}

pub fn run(request: ScanRequest<'_>) -> ScanOutcome {
    let (rules, load_errors) = load_directory(request.rules_root);
    let rule_errors: Vec<String> = load_errors.iter().map(|e| e.to_string()).collect();

    let discovery = discover(request.project_root, &DiscoveryOptions::default());

    let mut builder = ReportBuilder::new();
    let mut coverage = CoverageStatement::static_only();
    let mut unclaimed: BTreeSet<String> = BTreeSet::new();

    coverage.unparsed_files = discovery
        .skipped
        .iter()
        .map(|s| UnparsedFile {
            path: s.path.to_string_lossy().replace('\\', "/"),
            reason: s.reason,
        })
        .collect();

    // Rules are compiled once per grammar rather than once per file. Compiling
    // inside the file loop would repeat identical work for every source file.
    let compiled = Language::ALL
        .into_iter()
        .filter_map(|language| {
            let for_family: Vec<RuleFile> = rules
                .iter()
                .filter(|r| r.language == language.rule_family())
                .cloned()
                .collect();
            if for_family.is_empty() {
                return None;
            }
            compile(language, &for_family)
                .ok()
                .map(|c| (language, c, for_family))
        })
        .collect::<Vec<_>>();

    let mut parsed_files = 0u64;

    for file in &discovery.files {
        let source = match read_source(request.project_root, &file.path) {
            Ok(source) => source,
            Err(reason) => {
                coverage.unparsed_files.push(UnparsedFile {
                    path: file.path.to_string_lossy().replace('\\', "/"),
                    reason,
                });
                continue;
            }
        };

        let parsed = match parse_as(file.path.clone(), source, file.language) {
            Ok(parsed) => parsed,
            Err(failure) => {
                coverage.unparsed_files.push(UnparsedFile {
                    path: file.path.to_string_lossy().replace('\\', "/"),
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
                path: file.path.to_string_lossy().replace('\\', "/"),
                reason: UnparsedReason::PartialParse,
            });
        }

        let Some((_, compiled_rules, family_rules)) =
            compiled.iter().find(|(l, _, _)| *l == file.language)
        else {
            continue;
        };

        let found = detect(&parsed, compiled_rules, family_rules);
        unclaimed.extend(found.unclaimed_imports);
        builder.add_findings(found.findings);
    }

    coverage.parsed_files = parsed_files;
    coverage.undetected_libraries = unclaimed.into_iter().collect();
    coverage.runtime_coverage = runtime_coverage_for_static_scan();

    builder.coverage(coverage);

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
            rule_hits: Vec::new(),
        },
    );

    ScanOutcome {
        report,
        rule_errors,
    }
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
