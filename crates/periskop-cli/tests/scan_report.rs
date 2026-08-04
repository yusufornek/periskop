#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! The scan command, end to end.
//!
//! Schema conformance of the emitted JSON is checked in continuous integration,
//! where a real validator runs against the contract files. These tests cover what
//! a validator cannot: that the same tree scanned twice produces identical bytes,
//! and that the coverage block is populated rather than merely present.

use std::path::{Path, PathBuf};

use periskop_report::to_canonical_json;

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
    scan::run(scan::ScanRequest {
        project_root: &fixtures(),
        rules_root: &root.join("rules"),
        tool_version: "0.0.0-test",
        generated_at: generated_at.to_owned(),
    })
}

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
