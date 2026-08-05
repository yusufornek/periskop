#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! The scan command, end to end.
//!
//! Schema conformance of the emitted JSON is checked in continuous integration,
//! where a real validator runs against the contract files. These tests cover what
//! a validator cannot: that the same tree scanned twice produces identical bytes,
//! and that the coverage block is populated rather than merely present.

use std::path::{Path, PathBuf};

use periskop_core::coverage::UnparsedReason;
use periskop_report::coverage::{RuleSetSource, RuntimeStatus};
use periskop_report::report::DiagnosticCode;
use periskop_report::{to_canonical_json, Verdict};

// The crate's own module, not a second copy of the file. A `#[path]` include
// compiled `scan.rs` again inside this binary, so the tests exercised a
// duplicate rather than the surface the binary and the rpc bridge use, and the
// day that module touched something only `main.rs` provides they would have
// stopped compiling for a reason that reads as unrelated.
use periskop_cli::scan;
use periskop_cli::scan::RuleSource;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures() -> PathBuf {
    repo_root().join("crates/periskop-static-scanner/fixtures/python")
}

fn run(generated_at: &str) -> scan::ScanOutcome {
    let root = repo_root();
    run_in(
        &fixtures(),
        RuleSource::Directory(&root.join("rules")),
        generated_at,
    )
}

fn run_in(project_root: &Path, rules: RuleSource<'_>, generated_at: &str) -> scan::ScanOutcome {
    scan::run(scan::ScanRequest {
        project_root,
        rules,
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
fn a_run_on_the_shipped_detectors_says_so_in_the_report() {
    // stderr already announces the source, and stderr is not what gets archived.
    // An auditor reading a stored report has to be able to ask "clean according
    // to what" and get an answer out of the document itself.
    let outcome = run_in(&fixtures(), RuleSource::Embedded, "2026-08-04T09:00:00Z");
    assert_eq!(
        outcome.report.coverage.rule_set_source,
        RuleSetSource::Embedded
    );
}

#[test]
fn a_run_on_a_named_directory_says_that_instead_and_names_no_path() {
    // The case the field exists for. An operator can point --rules at a narrow
    // directory, get a clean report, and archive it; without this field nothing
    // in the document separates that run from one made with the shipped set.
    let rules = repo_root().join("rules");
    let outcome = run_in(
        &fixtures(),
        RuleSource::Directory(&rules),
        "2026-08-04T09:00:00Z",
    );
    assert_eq!(
        outcome.report.coverage.rule_set_source,
        RuleSetSource::Directory
    );

    // The other half of the decision. The source reaches the report, the path
    // does not: an absolute path differs between machines and would mean two
    // runs over one tree no longer produce the same bytes.
    let document = to_canonical_json(&outcome.report).unwrap();
    assert!(
        !document.contains(&*rules.to_string_lossy()),
        "the rule directory reached the report body: {document}"
    );
}

#[test]
fn changing_only_the_source_changes_only_that_field() {
    // The embedded set is the repository's `rules/` tree compiled in, which
    // `tests/embedded_rules.rs` pins byte for byte. Handing the same rules to the
    // same fixtures by the other route therefore has exactly one legitimate
    // consequence: the sentence about where they came from.
    //
    // What this protects is the diff. Finding identities, the run identity and
    // the report identity all have to survive the change, because none of them
    // is about provenance: a reader who sees `scan_run_id` move reads it as "the
    // thing that was analysed changed", and here nothing was.
    let rules = repo_root().join("rules");
    let embedded = run_in(&fixtures(), RuleSource::Embedded, "2026-08-04T09:00:00Z");
    let named = run_in(
        &fixtures(),
        RuleSource::Directory(&rules),
        "2026-08-04T09:00:00Z",
    );

    assert_ne!(
        embedded.report.coverage.rule_set_source, named.report.coverage.rule_set_source,
        "the two runs did not differ in the field under test, so the rest proves nothing"
    );

    let mut aligned = named.report.clone();
    aligned.coverage.rule_set_source = embedded.report.coverage.rule_set_source;
    assert_eq!(
        to_canonical_json(&aligned).unwrap(),
        to_canonical_json(&embedded.report).unwrap(),
        "the two runs differ somewhere other than the rule set source"
    );
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

    // What this pins is that a status is declared for every language the scan
    // saw. The value itself is not pinned any more: the old assertion demanded
    // `not_instrumented`, which the contract defines as a mechanism that exists
    // and was not switched on. No hook mechanism exists in this build, so that
    // was a false statement held in place by a test, and correcting the code
    // would have looked like breaking it.
    let languages: Vec<&str> = coverage
        .runtime_coverage
        .iter()
        .map(|r| r.language.as_str())
        .collect();
    assert!(
        languages.contains(&"python"),
        "the fixtures are Python and no Python line was declared: {languages:?}"
    );
    // Python ships a hook, so a static only scan of Python source is a switch the
    // user did not turn on rather than a gap in the product. Reporting it as
    // unsupported would send a reader looking for a mechanism that is right there.
    assert!(
        coverage
            .runtime_coverage
            .iter()
            .all(|r| r.status == RuntimeStatus::NotInstrumented),
        "python has a hook, so its line is not_instrumented: {:?}",
        coverage.runtime_coverage
    );
}

#[test]
fn a_call_whose_destination_cannot_be_read_is_declared_unresolved() {
    // The error class this test catches: `[extract]` and `[[classify.downgrade]]`
    // were parsed, validated, and then read by nothing. A client pointed at a
    // base_url the scanner cannot see was reported as confirmed anyway, and
    // coverage.unresolved_targets came back empty in every report the tool had
    // ever produced, so one of the three coverage promises went unkept.
    let tree = TempTree::new("unresolved-target");
    tree.write(
        "project/app.py",
        "import os\nfrom openai import OpenAI\n\nclient = OpenAI(base_url=os.environ[\"LLM_URL\"])\n\n\ndef ask(record):\n    return client.chat.completions.create(model=\"gpt-4\", messages=[{\"content\": record}])\n",
    );

    let outcome = run_in(
        &tree.path("project"),
        RuleSource::Directory(&repo_root().join("rules")),
        "2026-08-04T09:00:00Z",
    );
    let report = &outcome.report;

    assert!(
        report.findings.is_empty(),
        "a destination the scanner cannot read must not stay confirmed: {:?}",
        report.findings
    );
    assert_eq!(report.suspect_findings.len(), 1, "{:?}", report);
    assert_eq!(
        report.coverage.unresolved_targets.len(),
        1,
        "{:?}",
        report.coverage.unresolved_targets
    );
    let target = &report.coverage.unresolved_targets[0];
    assert_eq!(
        target.reason,
        periskop_report::coverage::UnresolvedReason::EnvVar
    );
    assert_eq!(
        target.egress_point_id, report.suspect_findings[0].refs[0].ref_id,
        "the coverage entry has to name the egress point it is about"
    );
}

#[test]
fn a_destination_the_scanner_can_read_stays_confirmed() {
    // The other half of the downgrade: a client that does not override the base
    // url uses the library default, which is a determinate destination. Treating
    // an absent keyword as unresolved would weaken every ordinary call.
    let tree = TempTree::new("resolved-target");
    tree.write(
        "project/app.py",
        "from openai import OpenAI\n\nclient = OpenAI()\n\n\ndef ask(record):\n    return client.chat.completions.create(model=\"gpt-4\", messages=[{\"content\": record}])\n",
    );

    let outcome = run_in(
        &tree.path("project"),
        RuleSource::Directory(&repo_root().join("rules")),
        "2026-08-04T09:00:00Z",
    );

    assert_eq!(outcome.report.findings.len(), 1, "{:?}", outcome.report);
    assert!(outcome.report.coverage.unresolved_targets.is_empty());
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
        RuleSource::Directory(&tree.path("rules")),
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
fn a_rule_set_that_loads_nothing_at_all_is_denied_a_pass() {
    // The half of the test above that nothing covered, and the one that survived
    // into a continuous integration gate. A broken rule file is reported because
    // the loader has something to complain about; a rule directory that is empty,
    // or misspelled, or points at a tree the checkout does not contain, gives the
    // loader nothing to complain about at all. The scan then walked the project
    // with no detector loaded, matched nothing, and reported zero findings, PASS
    // and exit code zero. `.github/workflows/ci.yml` ran exactly that command
    // against this repository, which means the step could not have failed no
    // matter what happened to the rules.
    let tree = TempTree::new("empty-rules");
    tree.write(
        "project/app.py",
        "import openai\nclient = openai.OpenAI()\n",
    );
    std::fs::create_dir_all(tree.path("rules")).unwrap();

    let outcome = run_in(
        &tree.path("project"),
        RuleSource::Directory(&tree.path("rules")),
        "2026-08-04T09:00:00Z",
    );

    assert_eq!(
        outcome.report.verdict,
        Verdict::Fail,
        "a scan with no detector loaded reported a verdict a pipeline reads as clean"
    );
    let rule_problems: Vec<&str> = outcome
        .report
        .diagnostics
        .iter()
        .filter(|d| d.code == DiagnosticCode::RuleLoadError)
        .filter_map(|d| d.detail.as_deref())
        .collect();
    assert_eq!(
        rule_problems.len(),
        1,
        "the empty rule set has to say so in the artefact, not only in the verdict: {:?}",
        outcome.report.diagnostics
    );
    assert!(
        rule_problems[0].contains("no rule at all"),
        "{rule_problems:?}"
    );
    // The detail travels into a report that has to diff equal between machines,
    // so it may not carry the absolute path of somebody's temporary directory.
    assert!(
        !rule_problems[0].contains(&tree.path("rules").display().to_string()),
        "the diagnostic carries an absolute path: {rule_problems:?}"
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
        RuleSource::Directory(&tree.path("rules")),
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
    //
    // Checked structurally rather than by searching for `/Users/` and `/home/`.
    // Those two strings are the layout of two operating systems; a leak under
    // `/root`, `/var/lib` or `C:\Users` went straight through.
    let report = run("2026-08-04T09:00:00Z").report;

    let mut paths: Vec<String> = report
        .findings
        .iter()
        .chain(report.suspect_findings.iter())
        .filter_map(|f| f.location.as_ref())
        .filter_map(|l| l.path.clone())
        .collect();
    paths.extend(
        report
            .coverage
            .unparsed_files
            .iter()
            .map(|f| f.path.clone()),
    );
    assert!(!paths.is_empty(), "nothing to check");

    for path in &paths {
        assert!(
            Path::new(path).is_relative(),
            "absolute path leaked into report: {path}"
        );
        assert!(
            !path.starts_with('/') && !path.starts_with('\\'),
            "rooted path leaked into report: {path}"
        );
        let windows_drive = path
            .as_bytes()
            .get(1)
            .is_some_and(|b| *b == b':' && path.is_char_boundary(1));
        assert!(!windows_drive, "drive qualified path leaked: {path}");
    }
}
