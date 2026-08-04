#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! The scan command with a runtime source attached.
//!
//! The defect these tests were written against is the one the component could
//! not see from the inside: `periskop-reconcile` was complete and tested, and
//! nothing in the pipeline called it. Every unit test in that crate passed while
//! no real scan had ever produced a `dormant_egress_point` or a `target_drift`,
//! and the reconciliation trace surface refused every finding it was handed.
//!
//! So these tests run the command, not the component. What they pin is the
//! wiring: that the events are actually read, that a disagreement between the
//! two sources becomes a finding in a report, that the coverage counters the
//! runtime half owns are filled from it, and that a kind this build cannot
//! derive is named rather than left as silence. Two of them exist for the other
//! direction: a run with no event directory has to produce exactly the report it
//! produced before any of this was wired, because the hookless path is the one
//! almost every user is on.

use std::path::{Path, PathBuf};
use std::process::Command;

use periskop_report::coverage::ReconciliationMode;
use periskop_report::report::DiagnosticComponent;
use periskop_report::to_canonical_json;
use periskop_runtime_collector::event::{
    EgressEvent, Language, Library, Mechanism, PayloadShape, Process, Target,
};

use periskop_cli::scan;

/// A code point that names where it goes.
///
/// The destination is written out rather than left to the library default,
/// because the join compares destinations and a default the scanner does not
/// read into the finding gives it nothing to compare.
const CLIENT_WITH_A_DECLARED_TARGET: &str = "from openai import OpenAI\n\nclient = OpenAI(base_url=\"https://api.openai.com/v1\")\n\n\ndef ask(record):\n    return client.chat.completions.create(model=\"gpt-4\", messages=[{\"content\": record}])\n";

const GENERATED_AT: &str = "2026-08-04T09:00:00Z";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A throwaway project and its event directory.
///
/// The project directory is named `project` in every tree, which is not
/// cosmetic: the report identity is derived from the name of the scanned
/// directory, so two trees that are meant to compare equal have to agree on it.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("periskop-reconcile-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("project")).unwrap();
        std::fs::create_dir_all(root.join("events")).unwrap();
        let fixture = Self { root };
        fixture.write_source(CLIENT_WITH_A_DECLARED_TARGET);
        fixture
    }

    fn write_source(&self, contents: &str) -> &Self {
        std::fs::write(self.root.join("project/app.py"), contents).unwrap();
        self
    }

    /// Writes one event file, one record per line.
    fn write_events(&self, file_name: &str, events: &[EgressEvent]) -> &Self {
        let body: String = events
            .iter()
            .map(|event| format!("{}\n", serde_json::to_string(event).unwrap()))
            .collect();
        std::fs::write(self.root.join("events").join(file_name), body).unwrap();
        self
    }

    fn write_raw_events(&self, file_name: &str, contents: &str) -> &Self {
        std::fs::write(self.root.join("events").join(file_name), contents).unwrap();
        self
    }

    fn project(&self) -> PathBuf {
        self.root.join("project")
    }

    fn events(&self) -> PathBuf {
        self.root.join("events")
    }

    fn scan(&self) -> scan::ScanOutcome {
        run_with(&self.project(), Some(&self.events()))
    }

    fn scan_without_events(&self) -> scan::ScanOutcome {
        run_with(&self.project(), None)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // A cleanup failure must not mask the assertion that already ran.
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn run_with(project_root: &Path, event_dir: Option<&Path>) -> scan::ScanOutcome {
    scan::run_with_events(
        scan::ScanRequest {
            project_root,
            rules_root: &repo_root().join("rules"),
            tool_version: "0.0.0-test",
            generated_at: GENERATED_AT.to_owned(),
        },
        event_dir,
    )
}

/// One call as a hook records it.
fn event(module: &str, operation: &str, host: &str, provider: &str) -> EgressEvent {
    EgressEvent::new(
        Process {
            language: Language::Python,
            runtime: "cpython/3.12".to_owned(),
            entrypoint_hint: None,
        },
        Library {
            module: module.to_owned(),
            mechanism: Mechanism::SdkWrapper,
        },
        operation,
        Target {
            host_id: host.to_owned(),
            port: Some(443),
            path_template: Some("/v1/chat/completions".to_owned()),
            provider_ref: Some(provider.to_owned()),
        },
        PayloadShape {
            field_paths: vec!["messages[].content".to_owned()],
            byte_size_estimate: 512,
            truncated_depth: None,
        },
    )
    .unwrap()
}

/// The call the fixture's code makes, as it would be recorded if it went where
/// the code says it goes.
fn call_to(host: &str) -> EgressEvent {
    event("openai", "chat.completions.create", host, "openai")
}

fn derived(outcome: &scan::ScanOutcome) -> Vec<&periskop_core::finding::Finding> {
    outcome
        .report
        .findings
        .iter()
        .chain(outcome.report.suspect_findings.iter())
        .filter(|finding| finding.source == periskop_core::finding::Source::Reconciled)
        .collect()
}

fn details(outcome: &scan::ScanOutcome, component: DiagnosticComponent) -> Vec<String> {
    outcome
        .report
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.component == component)
        .filter_map(|diagnostic| diagnostic.detail.clone())
        .collect()
}

#[test]
fn a_scan_with_no_event_directory_reports_exactly_what_it_always_did() {
    // The compatibility claim, and the one that is not negotiable: almost every
    // run of this tool has no hook installed, and wiring a second source in must
    // not change what those runs say.
    let fixture = Fixture::new("static-only");
    let outcome = fixture.scan_without_events();
    let coverage = &outcome.report.coverage;

    assert_eq!(coverage.reconciliation_mode, ReconciliationMode::StaticOnly);
    assert_eq!(coverage.observation_window_ms, 0);
    assert_eq!(coverage.dropped_events, 0);
    assert_eq!(coverage.unlinked_events, 0);
    assert!(
        derived(&outcome).is_empty(),
        "a run with no runtime source derives nothing: {:?}",
        derived(&outcome)
    );
    // Not even the suppression list. A scan that never asked for a second source
    // owes the reader no account of what a second source would have added, and
    // eight diagnostics on every static run is how a diagnostics block stops
    // being read.
    assert!(
        outcome.report.diagnostics.is_empty(),
        "{:?}",
        outcome.report.diagnostics
    );
    assert_eq!(outcome.report.findings.len(), 1, "{:?}", outcome.report);
}

#[test]
fn an_event_directory_is_read_and_the_report_says_which_sources_fed_it() {
    let fixture = Fixture::new("mode");
    fixture.write_events("worker-1.jsonl", &[call_to("api.openai.com")]);

    let outcome = fixture.scan();

    assert_eq!(
        outcome.report.coverage.reconciliation_mode,
        ReconciliationMode::StaticPlusRuntime,
        "the runtime source fed this run and the mode has to name it"
    );
    // The call went where the code said it would, so nothing was left
    // unattributed and nothing drifted.
    assert_eq!(outcome.report.coverage.unlinked_events, 0);
    assert_eq!(outcome.report.coverage.dropped_events, 0);
    assert!(derived(&outcome).is_empty(), "{:?}", derived(&outcome));
}

#[test]
fn a_call_that_reached_another_host_becomes_a_target_drift_finding() {
    // The finding this whole task exists to make producible. Before the wiring,
    // `target_drift` was derivable in a unit test and unreachable from any real
    // scan, so the product's central claim had no path to a user.
    let fixture = Fixture::new("drift");
    fixture.write_events("worker-1.jsonl", &[call_to("llm-gateway.internal")]);

    let outcome = fixture.scan();
    let drifts: Vec<_> = derived(&outcome)
        .into_iter()
        .filter(|finding| finding.kind == periskop_core::finding::Kind::TargetDrift)
        .collect();

    assert_eq!(
        drifts.len(),
        1,
        "code says api.openai.com, the call reached llm-gateway.internal: {:?}",
        outcome.report
    );
    let drift = drifts[0];
    assert_eq!(
        drift.detector.component,
        periskop_core::finding::Component::Reconciliation
    );
    // The evidence has to carry the join that produced it, or the finding cannot
    // be argued with.
    let evidence: Vec<&str> = drift
        .evidence
        .iter()
        .map(|evidence| evidence.r#ref.as_str())
        .collect();
    assert!(
        evidence
            .iter()
            .any(|text| text.contains("declared=api.openai.com")
                && text.contains("observed=llm-gateway.internal")),
        "{evidence:?}"
    );
    // The observation it rests on is referenced, not merely summarised.
    assert!(
        drift
            .refs
            .iter()
            .any(|reference| reference.ref_type == periskop_core::finding::RefType::EgressEvent),
        "{:?}",
        drift.refs
    );
}

#[test]
fn an_observation_that_reaches_no_code_point_is_counted_not_reported() {
    // K-10: failing to attribute an observation is a loss of coverage, never a
    // finding. Promoting it would inflate both the finding count and the false
    // positive rate with the tool's own blind spots.
    let fixture = Fixture::new("unlinked");
    fixture.write_events(
        "worker-1.jsonl",
        &[event(
            "anthropic",
            "messages.create",
            "api.anthropic.com",
            "anthropic",
        )],
    );

    let outcome = fixture.scan();

    assert_eq!(outcome.report.coverage.unlinked_events, 1);
    assert!(
        derived(&outcome).is_empty(),
        "an unattributed call is a counter, not a finding: {:?}",
        derived(&outcome)
    );
}

#[test]
fn a_damaged_event_line_is_counted_and_does_not_cost_the_scan() {
    // The normal state of a file a live process is still appending to. A scan
    // that gave up here would hand any misbehaving hook the power to blind the
    // whole run.
    let fixture = Fixture::new("damaged");
    let good = serde_json::to_string(&call_to("llm-gateway.internal")).unwrap();
    fixture.write_raw_events(
        "worker-1.jsonl",
        &format!("{good}\n{{ half a record, no closing\n"),
    );

    let outcome = fixture.scan();

    assert_eq!(outcome.report.coverage.dropped_events, 1);
    // The readable record still did its work.
    assert_eq!(
        derived(&outcome).len(),
        1,
        "the intact line still produced its finding: {:?}",
        outcome.report
    );
    // And the loss is located, not just counted.
    let losses = details(&outcome, DiagnosticComponent::RuntimeHooks);
    assert!(
        losses
            .iter()
            .any(|detail| detail.contains("worker-1.jsonl:2") && detail.contains("unparsable")),
        "{losses:?}"
    );
}

#[test]
fn the_full_mode_is_never_written_by_a_build_that_has_no_network_sensor() {
    // Two sources making a three source claim would discredit the product's
    // central argument more thoroughly than missing a finding would. `full` means
    // the wire was watched, and nothing in this build can watch it.
    let fixture = Fixture::new("never-full");
    fixture.write_events(
        "worker-1.jsonl",
        &[call_to("api.openai.com"), call_to("llm-gateway.internal")],
    );

    for mode in [
        fixture.scan().report.coverage.reconciliation_mode,
        fixture
            .scan_without_events()
            .report
            .coverage
            .reconciliation_mode,
    ] {
        assert_ne!(mode, ReconciliationMode::Full);
        assert_ne!(
            mode,
            ReconciliationMode::StaticPlusWire,
            "there is no wire source to put in a mode"
        );
    }

    // Stated as suppressions too, so the absence is written down rather than
    // inferred from a missing finding kind.
    let suppressed = details(&fixture.scan(), DiagnosticComponent::Reconciliation);
    assert!(
        suppressed
            .iter()
            .any(|detail| detail.contains("unmatched_wire_traffic")
                && detail.contains("wire_source_absent")),
        "{suppressed:?}"
    );
}

#[test]
fn two_runs_over_one_tree_and_one_event_directory_write_the_same_bytes() {
    let fixture = Fixture::new("determinism");
    fixture.write_events(
        "worker-1.jsonl",
        &[
            call_to("llm-gateway.internal"),
            event(
                "anthropic",
                "messages.create",
                "api.anthropic.com",
                "anthropic",
            ),
        ],
    );

    let first = to_canonical_json(&fixture.scan().report).unwrap();
    let second = to_canonical_json(&fixture.scan().report).unwrap();

    assert_eq!(first, second);
}

#[test]
fn the_names_of_the_event_files_do_not_reach_the_report() {
    // Same three calls, split across files two different ways. A report that
    // differed would differ because a worker restarted under a new pid, which is
    // exactly the kind of change a diff must not light up on.
    let one = Fixture::new("layout-a");
    one.write_events("z-worker.jsonl", &[call_to("llm-gateway.internal")])
        .write_events(
            "a-worker.jsonl",
            &[event(
                "anthropic",
                "messages.create",
                "api.anthropic.com",
                "anthropic",
            )],
        );

    let other = Fixture::new("layout-b");
    other.write_events(
        "m-worker.jsonl",
        &[
            event(
                "anthropic",
                "messages.create",
                "api.anthropic.com",
                "anthropic",
            ),
            call_to("llm-gateway.internal"),
        ],
    );

    assert_eq!(
        to_canonical_json(&one.scan().report).unwrap(),
        to_canonical_json(&other.scan().report).unwrap()
    );
}

#[test]
fn an_empty_event_directory_is_an_observation_rather_than_an_absent_source() {
    // The distinction the whole runtime source model rests on. Hooks that were
    // installed and saw nothing is a fact about the program; no hooks at all is
    // a fact about the run, and the report must not spell them the same way.
    let fixture = Fixture::new("empty-events");

    let watched = fixture.scan();
    let unwatched = fixture.scan_without_events();

    assert_eq!(
        watched.report.coverage.reconciliation_mode,
        ReconciliationMode::StaticPlusRuntime
    );
    assert_eq!(
        unwatched.report.coverage.reconciliation_mode,
        ReconciliationMode::StaticOnly
    );
    assert_eq!(watched.report.coverage.dropped_events, 0);
    assert_eq!(watched.report.coverage.unlinked_events, 0);
    // No window was measured, so nothing may be concluded from the silence.
    assert!(
        derived(&watched).is_empty(),
        "an unmeasured window cannot support a dormancy claim: {:?}",
        derived(&watched)
    );
}

#[test]
fn a_derived_kind_this_run_could_not_produce_is_named_rather_than_left_silent() {
    // Silence would be indexed the same way by a reader whether a kind found
    // nothing or was never attempted. This is the case the example in the spec
    // is about: the window is unknown, so a dormancy claim has nothing under it,
    // and the report says so instead of simply omitting the kind.
    let fixture = Fixture::new("suppression");
    fixture.write_events("worker-1.jsonl", &[call_to("api.openai.com")]);

    let outcome = fixture.scan();
    let stated = details(&outcome, DiagnosticComponent::Reconciliation);

    assert!(
        stated
            .iter()
            .any(|detail| detail.contains("dormant_egress_point")
                && detail.contains("observation_window_too_short")),
        "{stated:?}"
    );
    assert!(
        stated
            .iter()
            .any(|detail| detail.contains("volume_anomaly")),
        "{stated:?}"
    );
    // Suppressions are not coverage. Mixing them in would make any threshold
    // over the coverage counters meaningless.
    assert_eq!(outcome.report.coverage.dropped_events, 0);
    assert_eq!(outcome.report.coverage.unlinked_events, 0);
}

#[test]
fn an_event_directory_that_is_not_there_stops_the_command() {
    // A mistyped path must not become a report claiming static_plus_runtime with
    // nothing observed, which reads as a hooked application that made no calls.
    let fixture = Fixture::new("missing-dir");
    let absent = fixture.events().join("never-created");

    let status = Command::new(env!("CARGO_BIN_EXE_periskop"))
        .arg("scan")
        .arg(fixture.project())
        .arg("--rules")
        .arg(repo_root().join("rules"))
        .arg("--events")
        .arg(&absent)
        .output()
        .unwrap();

    assert_eq!(status.status.code(), Some(2), "{status:?}");
    assert!(
        String::from_utf8_lossy(&status.stderr).contains("no event directory"),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
}

#[test]
fn the_event_directory_can_be_named_by_the_environment_the_hook_prints() {
    // `hook install` prints PERISKOP_EVENT_DIR and the application is started
    // with it. A scan that could only be told the path by flag would make the
    // hooked case the awkward one.
    let fixture = Fixture::new("env-var");
    fixture.write_events("worker-1.jsonl", &[call_to("llm-gateway.internal")]);

    let output = Command::new(env!("CARGO_BIN_EXE_periskop"))
        .arg("scan")
        .arg(fixture.project())
        .arg("--rules")
        .arg(repo_root().join("rules"))
        .arg("--json")
        .env("PERISKOP_EVENT_DIR", fixture.events())
        .output()
        .unwrap();

    let report = String::from_utf8_lossy(&output.stdout);
    assert!(
        report.contains("\"static_plus_runtime\""),
        "the variable has to reach the run: {report}"
    );
    assert!(report.contains("target_drift"), "{report}");
}

#[test]
fn the_static_findings_survive_the_reconciled_run() {
    // A derived finding is added to the report, never substituted for the code
    // point it was derived from. Losing the declared finding would take the
    // inventory with it.
    let fixture = Fixture::new("static-survives");
    fixture.write_events("worker-1.jsonl", &[call_to("llm-gateway.internal")]);

    let with_events = fixture.scan();
    let without = fixture.scan_without_events();

    let declared = |outcome: &scan::ScanOutcome| {
        outcome
            .report
            .findings
            .iter()
            .filter(|finding| finding.kind == periskop_core::finding::Kind::DeclaredEgressPoint)
            .count()
    };
    assert_eq!(declared(&with_events), declared(&without));
    assert_eq!(declared(&with_events), 1, "{:?}", with_events.report);
    assert!(with_events.report.findings.len() > without.report.findings.len());
}

#[test]
fn no_absolute_path_reaches_the_report_through_the_event_side() {
    // The event directory is an absolute path on every machine that runs this.
    // None of it may reach output that two machines are supposed to be able to
    // compare.
    let fixture = Fixture::new("no-abs-path");
    fixture.write_raw_events("worker-1.jsonl", "{ not a record at all\n");

    let outcome = fixture.scan();
    let json = to_canonical_json(&outcome.report).unwrap();
    let root = fixture.root.to_string_lossy().to_string();

    assert!(
        !json.contains(&root),
        "the temporary directory leaked into the report"
    );
    // The loss is still reported, so the absence above is not the absence of a
    // diagnostic.
    assert!(
        !details(&outcome, DiagnosticComponent::RuntimeHooks).is_empty(),
        "{:?}",
        outcome.report.diagnostics
    );
}
