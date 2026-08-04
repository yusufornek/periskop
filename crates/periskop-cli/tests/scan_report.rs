#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! The scan command, end to end.
//!
//! Schema conformance of the emitted JSON is checked in continuous integration,
//! where a real validator runs against the contract files. These tests cover what
//! a validator cannot: that the same tree scanned twice produces identical bytes,
//! and that the coverage block is populated rather than merely present.

use std::path::{Path, PathBuf};

use periskop_core::coverage::UnparsedReason;
use periskop_report::report::DiagnosticCode;
use periskop_report::{to_canonical_json, Verdict};

#[path = "../src/scan.rs"]
mod scan;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures() -> PathBuf {
    repo_root().join("crates/periskop-static-scanner/fixtures/python")
}

fn run(generated_at: &str) -> scan::ScanOutcome {
    let root = repo_root();
    run_in(&fixtures(), &root.join("rules"), generated_at)
}

fn run_in(project_root: &Path, rules_root: &Path, generated_at: &str) -> scan::ScanOutcome {
    scan::run(scan::ScanRequest {
        project_root,
        rules_root,
        tool_version: "0.0.0-test",
        generated_at: generated_at.to_owned(),
    })
}

/// A throwaway directory tree, built by hand.
///
/// Written out rather than pulled in: a test only dependency is still a
/// dependency decision, and this needs a few lines.
struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(name: &str) -> Self {
        // The process id keeps two test runs on one machine from deleting each
        // other's tree, which would show up as a failure with no obvious cause.
        let root =
            std::env::temp_dir().join(format!("periskop-scan-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn write(&self, relative: &str, contents: &str) -> &Self {
        let path = self.root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
        self
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        // Cleanup failure must not mask the assertion that already ran.
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A rule that loads and compiles, so a family built from it is usable.
const WORKING_PYTHON_RULE: &str = r#"
schema_version = "1.0"
language = "python"
provider = "openai"
rule_id = "python.static.openai-chat-completions"
rule_version = "1.0.0"

[[match]]
kind = "call"
query = "(call) @call"

[classify]
egress_kind = "llm_chat"
default_confidence = "confirmed"
"#;

#[test]
fn a_scan_finds_the_positive_fixtures() {
    let outcome = run("2026-08-04T09:00:00Z");
    assert!(
        outcome.report.findings.len() >= 5,
        "expected the positive fixtures to be found, got {}",
        outcome.report.findings.len()
    );
    assert!(outcome.rule_errors.is_empty(), "{:?}", outcome.rule_errors);
}

#[test]
fn negative_and_evasion_fixtures_contribute_nothing() {
    let outcome = run("2026-08-04T09:00:00Z");
    for finding in &outcome.report.findings {
        let path = finding
            .location
            .as_ref()
            .and_then(|l| l.path.clone())
            .unwrap_or_default();
        assert!(
            path.starts_with("positive/"),
            "{path} produced a finding but is not a positive fixture"
        );
    }
}

#[test]
fn two_runs_at_different_times_produce_the_same_body() {
    // The reproducibility claim, checked on real output rather than a stub. The
    // timestamps differ; everything the hash covers does not.
    let morning = run("2026-08-04T09:00:00Z");
    let evening = run("2026-08-04T21:30:00Z");

    let a = periskop_report::body_hash(&morning.report).unwrap();
    let b = periskop_report::body_hash(&evening.report).unwrap();
    assert_eq!(a, b);

    // The envelope is expected to differ. If it did not, the test above would be
    // passing for the wrong reason.
    assert_ne!(
        morning.report.envelope.generated_at,
        evening.report.envelope.generated_at
    );
}

#[test]
fn the_serialized_report_is_byte_identical_across_runs() {
    let a = to_canonical_json(&run("2026-08-04T09:00:00Z").report).unwrap();
    let b = to_canonical_json(&run("2026-08-04T09:00:00Z").report).unwrap();
    assert_eq!(a, b);
}

#[test]
fn the_coverage_block_is_filled_in_not_just_present() {
    let outcome = run("2026-08-04T09:00:00Z");
    let coverage = &outcome.report.coverage;

    assert!(coverage.parsed_files > 0, "no file was recorded as read");
    assert!(
        !coverage.runtime_coverage.is_empty(),
        "runtime status must be stated, since an empty list reads as though a hook ran and found nothing"
    );
    assert!(coverage
        .runtime_coverage
        .iter()
        .all(|r| r.status == periskop_report::coverage::RuntimeStatus::NotInstrumented));
}

#[test]
fn output_keys_are_sorted() {
    let json = to_canonical_json(&run("2026-08-04T09:00:00Z").report).unwrap();
    let coverage = json.find("\"coverage\"").unwrap();
    let findings = json.find("\"findings\"").unwrap();
    let verdict = json.find("\"verdict\"").unwrap();
    assert!(coverage < findings, "coverage should precede findings");
    assert!(findings < verdict, "findings should precede verdict");
}

#[test]
fn a_rule_set_that_does_not_load_is_reported_and_denied_a_pass() {
    // The error class this test catches: silent loss of the whole detection layer.
    // A rule file that will not parse, or a query that will not compile, used to
    // be swallowed. The scan then ran with no rules, matched nothing, and printed
    // zero findings, full coverage, PASS and exit code zero, which reads exactly
    // like a clean repository. Nothing in the report said the rules never loaded.
    let tree = TempTree::new("broken-rules");
    tree.write(
        "project/app.py",
        "import openai\nclient = openai.OpenAI()\n",
    )
    // Not valid TOML: the loader rejects the file before it is a rule at all.
    .write("rules/python/broken-syntax.toml", "language = python\n")
    // Valid TOML, valid rule, query against a node the grammar does not have.
    .write(
        "rules/python/broken-query.toml",
        &WORKING_PYTHON_RULE.replace("(call) @call", "(no_such_node) @call"),
    );

    let outcome = run_in(
        &tree.path("project"),
        &tree.path("rules"),
        "2026-08-04T09:00:00Z",
    );
    let report = &outcome.report;

    let rule_problems: Vec<&str> = report
        .diagnostics
        .iter()
        .filter(|d| d.code == DiagnosticCode::RuleLoadError)
        .filter_map(|d| d.detail.as_deref())
        .collect();
    assert_eq!(
        rule_problems.len(),
        2,
        "both the unloadable file and the uncompilable query belong in diagnostics: {:?}",
        report.diagnostics
    );
    assert!(
        rule_problems
            .iter()
            .any(|d| d.contains("broken-syntax.toml")),
        "{rule_problems:?}"
    );
    assert!(
        rule_problems
            .iter()
            .any(|d| d.contains("python.static.openai-chat-completions")),
        "{rule_problems:?}"
    );

    // FAIL specifically, not merely "not PASS": the command line maps FAIL to a
    // nonzero exit code and everything else to zero, so a WARN here would put the
    // silent pass back exactly where it was.
    assert_eq!(report.verdict, Verdict::Fail);

    // The Python family produced no usable pattern, so no Python file was looked
    // at. Counting them as parsed would claim a scan that never happened.
    assert_eq!(report.coverage.parsed_files, 0);
    assert!(
        report
            .coverage
            .unparsed_files
            .iter()
            .any(|f| f.path == "app.py" && f.reason == UnparsedReason::NoGrammar),
        "{:?}",
        report.coverage.unparsed_files
    );
}

#[test]
fn files_of_a_language_with_no_rules_are_declared_unparsed_not_counted_as_scanned() {
    // The error class this test catches: coverage inflated by files nothing ever
    // looked at. A file used to be parsed, counted in parsed_files, and only then
    // skipped for having no rule family. A repository written in such a language
    // therefore reported one hundred percent coverage with no findings, and passed
    // the --max-unparsed-ratio gate, because the gap left no trace anywhere.
    let tree = TempTree::new("language-without-rules");
    tree.write("project/app.py", "value = 1\n")
        .write("project/main.go", "package main\n\nfunc main() {}\n")
        .write("rules/python/openai.toml", WORKING_PYTHON_RULE);

    let outcome = run_in(
        &tree.path("project"),
        &tree.path("rules"),
        "2026-08-04T09:00:00Z",
    );
    let coverage = &outcome.report.coverage;

    assert!(outcome.rule_errors.is_empty(), "{:?}", outcome.rule_errors);
    assert_eq!(
        coverage.parsed_files, 1,
        "only the Python file had a rule family to scan it with"
    );
    assert!(
        coverage
            .unparsed_files
            .iter()
            .any(|f| f.path == "main.go" && f.reason == UnparsedReason::NoGrammar),
        "{:?}",
        coverage.unparsed_files
    );
    assert!(
        coverage.unparsed_ratio_basis_points() > 0,
        "the gap has to move the ratio, or a coverage gate cannot see it"
    );

    // A coverage gap on its own still does not fail the run. The gap is declared
    // rather than punished; the policy decides what to do about it.
    assert_eq!(outcome.report.verdict, Verdict::Pass);
    assert!(outcome.report.diagnostics.is_empty());
}

#[test]
fn no_absolute_path_reaches_the_report() {
    // An absolute path would embed the build machine into output that is supposed
    // to compare equal across machines.
    let json = to_canonical_json(&run("2026-08-04T09:00:00Z").report).unwrap();
    assert!(
        !json.contains("/Users/"),
        "absolute path leaked into report"
    );
    assert!(!json.contains("/home/"), "absolute path leaked into report");
}
