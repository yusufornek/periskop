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

use periskop_network_sensor::flow::{
    FiveTuple, Mechanism as CaptureMechanism, ProcessRecord, Proto, ResolvedHostSource, SniSource,
};
use periskop_network_sensor::observation::Observation;
use periskop_network_sensor::scope::FlowScope;
use periskop_network_sensor::Flow;
use periskop_reconcile::settings::{ReconcileSettings, VolumeBand};
use periskop_report::coverage::{ReconciliationMode, SensorPlatformClass};
use periskop_report::report::DiagnosticComponent;
use periskop_report::to_canonical_json;
use periskop_runtime_collector::event::{
    DegradedReason, EgressEvent, Language, Library, Mechanism, PayloadShape, Process, Target,
};

use periskop_cli::scan;

/// A code point that names where it goes.
///
/// The destination is written out rather than left to the library default,
/// because the join compares destinations and a default the scanner does not
/// read into the finding gives it nothing to compare.
const CLIENT_WITH_A_DECLARED_TARGET: &str = "from openai import OpenAI\n\nclient = OpenAI(base_url=\"https://api.openai.com/v1\")\n\n\ndef ask(record):\n    return client.chat.completions.create(model=\"gpt-4\", messages=[{\"content\": record}])\n";

const GENERATED_AT: &str = "2026-08-04T09:00:00Z";

/// Set in continuous integration so a machine with no python3 fails the end to
/// end proof rather than skipping it, exactly as `proof.rs` uses it. One switch
/// for both gates, because two would mean a green pipeline could still be
/// hiding one of them.
const REQUIRE_PROOF: &str = "PERISKOP_REQUIRE_PROOF";

/// The sample the hook runs: two egress points, one of which is never called.
///
/// The two differ in both keys the join compares, the operation and the
/// destination, which is what makes the untouched one genuinely unobserved
/// rather than silenced by the call the other one made. A second call site
/// sharing either key would be attributed through it, which is correct and
/// would prove nothing here.
const TWO_POINTS_ONE_CALL: &str = r#""""Two places this code can send data. One line runs, the other never does.

Nothing here is unusual: a vendor client and a gateway client side by side is
what a deployment with a staging route looks like. The point of the sample is
that only one of the two is reached while the process is watched.
"""

import time

from openai import OpenAI

client = OpenAI(base_url="https://api.openai.com/v1")
gateway = OpenAI(base_url="https://llm-gateway.internal/v1")


def ask(record):
    return client.chat.completions.create(
        model="gpt-4", messages=[{"content": record}])


def embed(record):
    return gateway.embeddings.create(model="text-embedding-3", input=record)


if __name__ == "__main__":
    ask("ticket 4471: the invoice total does not match the order")
    # The window is a duration the hook measures, so the sample has to occupy
    # one. Fifty milliseconds is far above the threshold this test states and
    # far below one anybody waits for.
    time.sleep(0.05)
"#;

/// Stand in for the OpenAI SDK, cut down to the shape the hook patches.
///
/// The same trade `proof.rs` makes for `requests`, for the same two reasons:
/// the test installs no third party package, so it measures the hook rather
/// than the machine's site-packages, and it opens no socket, because a test
/// that reached a provider would prove the machine had a network and would send
/// a request on every `cargo test`.
///
/// What it does not soften is the thing under test. The resource classes are
/// the exact attributes `periskop_hook.wrappers.openai_sdk` names, and the base
/// url is read off the client the way the real SDK holds it, so at the point the
/// hook observes this is indistinguishable from the library.
const OPENAI_SDK_STUB: &str = r#""""Minimal stand in for the openai package, for the periskop pipeline test.

Only the surface the hook patches is present: the resource classes it names, and
a client object holding the base url the wrapper reads the destination from.
"""

import types


class _Resource(object):
    def __init__(self, client):
        self._client = client


class Completions(_Resource):
    def create(self, **kwargs):
        return "chat-response"


class AsyncCompletions(_Resource):
    def create(self, **kwargs):
        return "chat-response"


class Responses(_Resource):
    def create(self, **kwargs):
        return "response"


class AsyncResponses(_Resource):
    def create(self, **kwargs):
        return "response"


class Embeddings(_Resource):
    def create(self, **kwargs):
        return "embedding"


class AsyncEmbeddings(_Resource):
    def create(self, **kwargs):
        return "embedding"


resources = types.SimpleNamespace(
    chat=types.SimpleNamespace(
        completions=types.SimpleNamespace(
            Completions=Completions, AsyncCompletions=AsyncCompletions)),
    responses=types.SimpleNamespace(
        Responses=Responses, AsyncResponses=AsyncResponses),
    embeddings=types.SimpleNamespace(
        Embeddings=Embeddings, AsyncEmbeddings=AsyncEmbeddings),
)


class OpenAI(object):
    def __init__(self, base_url=None):
        self.base_url = base_url
        self.chat = types.SimpleNamespace(completions=Completions(self))
        self.embeddings = Embeddings(self)
"#;

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
        std::fs::create_dir_all(root.join("flows")).unwrap();
        let fixture = Self { root };
        fixture.write_source(CLIENT_WITH_A_DECLARED_TARGET);
        fixture
    }

    fn write_source(&self, contents: &str) -> &Self {
        std::fs::write(self.root.join("project/app.py"), contents).unwrap();
        self
    }

    /// Writes another file into the scanned tree.
    fn write_project_file(&self, relative: &str, contents: &str) -> &Self {
        std::fs::write(self.root.join("project").join(relative), contents).unwrap();
        self
    }

    /// Writes one status sidecar, the accounting a hook leaves beside a stream.
    fn write_status(&self, stream_name: &str, contents: &str) -> &Self {
        std::fs::write(
            self.root
                .join("events")
                .join(format!("{stream_name}.status.json")),
            contents,
        )
        .unwrap();
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

    /// Writes one flow record file, one record per line.
    fn write_flows(&self, file_name: &str, flows: &[Flow]) -> &Self {
        let body: String = flows
            .iter()
            .map(|flow| format!("{}\n", serde_json::to_string(flow).unwrap()))
            .collect();
        std::fs::write(self.root.join("flows").join(file_name), body).unwrap();
        self
    }

    fn write_raw_flows(&self, file_name: &str, contents: &str) -> &Self {
        std::fs::write(self.root.join("flows").join(file_name), contents).unwrap();
        self
    }

    fn project(&self) -> PathBuf {
        self.root.join("project")
    }

    fn events(&self) -> PathBuf {
        self.root.join("events")
    }

    fn flows(&self) -> PathBuf {
        self.root.join("flows")
    }

    fn scan(&self) -> scan::ScanOutcome {
        run_with(&self.project(), Some(&self.events()))
    }

    fn scan_without_events(&self) -> scan::ScanOutcome {
        run_with(&self.project(), None)
    }

    /// The scan with every source this fixture has: code, calls and connections.
    fn scan_all_sources(&self) -> scan::ScanOutcome {
        self.scan_with_sources(
            scan::ScanSources {
                event_dir: Some(&self.events()),
                flow_dir: Some(&self.flows()),
            },
            ReconcileSettings::default(),
        )
    }

    /// The scan with the wire source and no hooks: two sources, one of them the
    /// one the product's headline finding needs.
    fn scan_with_flows_only(&self) -> scan::ScanOutcome {
        self.scan_with_sources(
            scan::ScanSources {
                event_dir: None,
                flow_dir: Some(&self.flows()),
            },
            ReconcileSettings::default(),
        )
    }

    fn scan_with_sources(
        &self,
        sources: scan::ScanSources<'_>,
        settings: ReconcileSettings,
    ) -> scan::ScanOutcome {
        scan::run_with_sources(
            scan::ScanRequest {
                project_root: &self.project(),
                rules_root: &repo_root().join("rules"),
                tool_version: "0.0.0-test",
                generated_at: GENERATED_AT.to_owned(),
            },
            sources,
            settings,
        )
    }

    /// The same scan with the dormancy threshold the caller states.
    ///
    /// The default is ten minutes, which no test can wait for. What a test may
    /// not do instead is fake the window: the duration under the threshold has
    /// to be one a real hook really measured, or the proof is of nothing. So the
    /// window stays real and the threshold moves, which is the one of the two
    /// the contract lets a caller state.
    fn scan_with_min_window(&self, minimum_ms: u64) -> scan::ScanOutcome {
        scan::run_with_events_and_settings(
            scan::ScanRequest {
                project_root: &self.project(),
                rules_root: &repo_root().join("rules"),
                tool_version: "0.0.0-test",
                generated_at: GENERATED_AT.to_owned(),
            },
            Some(&self.events()),
            ReconcileSettings::default().with_min_dormant_window_ms(minimum_ms),
        )
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

/// The same call as a hook records it when it could not read the destination.
///
/// The contract will not let the field be omitted, so the absence is written as
/// a sentinel and the reason travels beside it.
fn call_to_somewhere_unreadable() -> EgressEvent {
    call_to("unknown").with_degraded_reasons(vec![DegradedReason::TargetNotResolved])
}

/// One connection the sensor watched, as it writes one to disk.
///
/// The process is the application under scan, which is what puts the record in
/// the only bucket that can produce a finding.
fn connection(host: &str, provider: &str, scope: FlowScope, src_port: u16) -> Flow {
    Flow::from_observation(
        Observation::new(
            "h_9f2c4a17be0d5386",
            1_785_834_000,
            FiveTuple {
                src_port,
                dst_ip: "104.18.7.1".to_owned(),
                dst_port: 443,
                proto: Proto::Tcp,
            },
            SniSource::ClientHello,
        )
        .with_duration_ms(120)
        .resolved(host, ResolvedHostSource::DnsAndSni)
        .with_provider_ref(provider)
        .kernel_attributed(ProcessRecord {
            pid: 4821,
            pid_start_time: Some(1_785_833_900),
            comm: Some("python3".to_owned()),
            exe: Some("/srv/app/venv/bin/python3".to_owned()),
            cmdline_hash: None,
        })
        .with_volume(2_048, 8_192),
        scope,
        CaptureMechanism::Ebpf,
    )
    .unwrap()
}

/// Traffic to a destination this fixture's code never mentions.
fn unexplained_traffic(scope: FlowScope, src_port: u16) -> Flow {
    connection("telemetry.vendor.example", "unknown", scope, src_port)
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
fn a_call_whose_destination_the_hook_could_not_read_produces_no_drift() {
    // The most expensive false positive this tool can print, run end to end.
    // The hook watched a call it could not resolve a destination for and wrote
    // the sentinel the contract requires. Read as a host, it differs from
    // everything the code declares, so every such call became a confirmed
    // `target_drift`: the report would state that code declaring
    // api.openai.com sent data somewhere else, when nothing was seen to go
    // anywhere at all. A security reader opens an incident on that line.
    let fixture = Fixture::new("unreadable-target");
    fixture.write_events("worker-1.jsonl", &[call_to_somewhere_unreadable()]);

    let outcome = fixture.scan();

    assert!(
        derived(&outcome).is_empty(),
        "not knowing where a call went is a gap in observation, never a drift: {:?}",
        derived(&outcome)
    );
    // The observation is not discarded either: the operation still attributes
    // it to the code point, so it is not counted as reaching nothing.
    assert_eq!(outcome.report.coverage.unlinked_events, 0);
    assert_eq!(outcome.report.coverage.dropped_events, 0);
    // And the run reports no internal disagreement over the record itself. The
    // stream is named in a diagnostic only when something in it was lost, and
    // a call whose destination the hook could not read is not a loss. The run
    // does report that nobody stated a window, which is a fact about the
    // directory rather than about this event.
    assert!(
        !details(&outcome, DiagnosticComponent::RuntimeHooks)
            .iter()
            .any(|detail| detail.contains("worker-1.jsonl")),
        "{:?}",
        outcome.report.diagnostics
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
fn the_full_mode_is_never_written_by_a_run_that_was_handed_no_flows() {
    // Two sources making a three source claim would discredit the product's
    // central argument more thoroughly than missing a finding would. `full` means
    // the wire was watched, and no flag on this run said it was.
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
    // And no run without flows writes a flow counter.
    let coverage = &fixture.scan().report.coverage;
    assert_eq!(coverage.out_of_scope_flows, 0);
    assert_eq!(coverage.sensor_platform_class, SensorPlatformClass::None);
}

#[test]
fn traffic_no_code_and_no_call_explains_becomes_a_finding_in_a_real_report() {
    // **Milestone 56, end to end.** The claim the whole product is built to
    // make, produced by the command rather than by the component: a process
    // belonging to the scanned codebase opened a connection to a destination the
    // repository never mentions, the hooks recorded no call that went there, and
    // the report says so. Neither of the other two sources could have.
    let fixture = Fixture::new("unmatched-wire");
    fixture
        .write_events("worker-1.jsonl", &[call_to("api.openai.com")])
        .write_flows(
            "sensor-1.jsonl",
            &[
                unexplained_traffic(FlowScope::InScope, 54_321),
                // The call the code declares, seen on the wire as well. It is
                // explained, so it produces nothing, and its presence is what
                // makes the finding above about one connection rather than about
                // every connection.
                connection("api.openai.com", "openai", FlowScope::InScope, 54_322),
            ],
        );

    let outcome = fixture.scan_all_sources();
    let unmatched = findings_of_kind(&outcome, periskop_core::finding::Kind::UnmatchedWireTraffic);

    assert_eq!(
        outcome.report.coverage.reconciliation_mode,
        ReconciliationMode::Full,
        "three sources fed this run"
    );
    assert_eq!(
        unmatched.len(),
        1,
        "one connection nothing accounts for: {:?}",
        outcome.report
    );
    let finding = unmatched[0];
    assert_eq!(
        finding.detector.component,
        periskop_core::finding::Component::Reconciliation
    );
    assert_eq!(finding.source, periskop_core::finding::Source::Reconciled);
    // The connection it is about is referenced, not merely summarised.
    assert_eq!(
        finding.refs[0].ref_type,
        periskop_core::finding::RefType::Flow
    );
    let evidence: Vec<&str> = finding
        .evidence
        .iter()
        .map(|piece| piece.r#ref.as_str())
        .collect();
    assert!(
        evidence
            .iter()
            .any(|text| text.contains("target=telemetry.vendor.example")
                && text.contains("flow_scope=in_scope")),
        "{evidence:?}"
    );
    assert_eq!(
        outcome.report.coverage.sensor_platform_class,
        SensorPlatformClass::LinuxEbpf
    );
}

#[test]
fn a_call_the_hook_could_not_place_costs_the_headline_claim_its_certainty() {
    // **Critic round K1, end to end.** The failure the report could not show:
    // the hook could not read where one call went, so the call took part in no
    // join and left no trace, and the traffic it may well have produced came out
    // as a confirmed accusation. The run below has three connections and three
    // calls, one of which went somewhere the hook could not name.
    let fixture = Fixture::new("unreadable-call");
    fixture
        .write_events(
            "worker-1.jsonl",
            &[
                call_to("api.openai.com"),
                call_to_somewhere_unreadable(),
                event("requests", "http.post", "unknown", "unknown")
                    .with_degraded_reasons(vec![DegradedReason::TargetNotResolved]),
            ],
        )
        .write_flows(
            "sensor-1.jsonl",
            &[
                unexplained_traffic(FlowScope::InScope, 54_321),
                connection(
                    "analytics.vendor.example",
                    "unknown",
                    FlowScope::InScope,
                    54_322,
                ),
                connection("api.openai.com", "openai", FlowScope::InScope, 54_323),
            ],
        );

    let outcome = fixture.scan_all_sources();
    let unmatched = findings_of_kind(&outcome, periskop_core::finding::Kind::UnmatchedWireTraffic);

    // The two unexplained connections are still reported: the point is not to
    // hide them, it is to state them at the strength the evidence carries.
    assert_eq!(unmatched.len(), 2, "{:?}", outcome.report);
    for finding in &unmatched {
        assert_eq!(
            finding.confidence,
            periskop_core::finding::Confidence::Suspect,
            "{finding:?}"
        );
        assert_eq!(
            finding.coverage_impact,
            Some(periskop_core::finding::CoverageImpact::UnresolvedTarget),
            "{finding:?}"
        );
    }
    // And the count reaches the coverage statement, which is the only place a
    // reader can find out why the claim was downgraded.
    assert_eq!(outcome.report.coverage.unresolved_event_targets, 2);
    // A suspected finding lives in its own list, so the downgrade also moves it
    // out of the confirmed one.
    assert!(outcome
        .report
        .findings
        .iter()
        .all(|finding| finding.kind != periskop_core::finding::Kind::UnmatchedWireTraffic));
}

#[test]
fn a_hook_that_read_every_destination_still_produces_the_confirmed_claim() {
    // The other edge of K1, so the downgrade above cannot be met by downgrading
    // everything. The same three sources with nothing unreadable in them: the
    // product's headline finding is stated as certain and the counter is zero.
    let fixture = Fixture::new("readable-calls");
    fixture
        .write_events("worker-1.jsonl", &[call_to("api.openai.com")])
        .write_flows(
            "sensor-1.jsonl",
            &[unexplained_traffic(FlowScope::InScope, 54_321)],
        );

    let outcome = fixture.scan_all_sources();
    let unmatched = findings_of_kind(&outcome, periskop_core::finding::Kind::UnmatchedWireTraffic);

    assert_eq!(unmatched.len(), 1, "{:?}", outcome.report);
    assert_eq!(
        unmatched[0].confidence,
        periskop_core::finding::Confidence::Confirmed
    );
    assert_eq!(outcome.report.coverage.unresolved_event_targets, 0);
}

#[test]
fn a_rung_that_silenced_the_headline_finding_says_so_in_the_report() {
    // **Critic round O1, end to end.** The repository declares one provider, and
    // every in scope connection to that provider is therefore silenced by the
    // weakest rung in the ladder. Spec §6: no class stays out of the report, so
    // the silence is counted where a reader will find it.
    let fixture = Fixture::new("provider-rung");
    fixture.write_flows(
        "sensor-1.jsonl",
        &[
            connection("eu.api.openai.com", "openai", FlowScope::InScope, 54_321),
            connection("us.api.openai.com", "openai", FlowScope::InScope, 54_322),
        ],
    );

    let outcome = fixture.scan_with_flows_only();

    assert!(
        findings_of_kind(&outcome, periskop_core::finding::Kind::UnmatchedWireTraffic).is_empty(),
        "{:?}",
        outcome.report
    );
    let stated = details(&outcome, DiagnosticComponent::Reconciliation);
    assert!(
        stated
            .iter()
            .any(|detail| detail.contains("J3 rung") && detail.contains("2 connections")),
        "{stated:?}"
    );
}

#[test]
fn the_flow_buckets_are_written_with_the_denominator_they_are_read_against() {
    // **Critic round O2, end to end.** Three of the four buckets were in the
    // report and the fourth was dropped on the floor, so "one flow out of scope"
    // could not be read: out of two, or out of two thousand. K-15's attribution
    // gate is a ratio, and a ratio needs the number underneath it.
    let fixture = Fixture::new("bucket-denominator");
    fixture.write_flows(
        "sensor-1.jsonl",
        &[
            connection("api.openai.com", "openai", FlowScope::InScope, 54_321),
            connection("api.openai.com", "openai", FlowScope::InScope, 54_322),
            connection("api.openai.com", "openai", FlowScope::InScope, 54_323),
            unexplained_traffic(FlowScope::OutOfScopeProcess, 54_324),
            unexplained_traffic(FlowScope::KnownBenign, 54_325),
        ],
    );

    let coverage = fixture.scan_with_flows_only().report.coverage;

    assert_eq!(coverage.in_scope_flows, 3);
    assert_eq!(coverage.out_of_scope_flows, 1);
    assert_eq!(coverage.known_benign_flows, 1);
    assert_eq!(coverage.unattributed_flows, 0);
}

#[test]
fn a_static_scan_writes_no_denominator_because_no_sensor_counted_anything() {
    // The zero has to mean the same thing as the other four buckets' zeros: not
    // "the sensor saw no in scope traffic" but "there was no sensor". The mode
    // is what carries that, and the counter must not imply an observation.
    let fixture = Fixture::new("bucket-denominator-static");
    let coverage = fixture.scan_without_events().report.coverage;

    assert_eq!(coverage.in_scope_flows, 0);
    assert_eq!(coverage.reconciliation_mode, ReconciliationMode::StaticOnly);
}

#[test]
fn the_same_traffic_produces_nothing_when_it_is_not_the_scanned_codebase() {
    // **Milestone 56's non negotiable constraint, through the command.** The
    // identical connection in the three quiet buckets, and the report gains no
    // finding from any of them. This is the developer machine case K-15 is
    // about: the editor assistant on the same laptop talking to the same
    // provider is not this project's egress.
    let fixture = Fixture::new("quiet-buckets");
    fixture.write_flows(
        "sensor-1.jsonl",
        &[
            unexplained_traffic(FlowScope::OutOfScopeProcess, 54_321),
            unexplained_traffic(FlowScope::KnownBenign, 54_322),
            unexplained_traffic(FlowScope::Undetermined, 54_323),
        ],
    );

    let outcome = fixture.scan_with_flows_only();

    assert!(
        findings_of_kind(&outcome, periskop_core::finding::Kind::UnmatchedWireTraffic).is_empty(),
        "{:?}",
        outcome.report
    );
    // And not one of them disappeared. A bucket that keeps traffic out of the
    // count and then vanishes from the report is a silent swallow, which is what
    // K-15's attribution gate exists to prevent.
    let coverage = &outcome.report.coverage;
    assert_eq!(coverage.out_of_scope_flows, 1);
    assert_eq!(coverage.known_benign_flows, 1);
    assert_eq!(coverage.unattributed_flows, 1);
    assert_eq!(coverage.unclassified_flows, 3);
    assert_eq!(
        coverage.reconciliation_mode,
        ReconciliationMode::StaticPlusWire
    );
}

#[test]
fn a_sensor_that_watched_and_saw_nothing_is_not_a_sensor_that_never_ran() {
    // The distinction the whole source model rests on, on the wire side. Both
    // runs have no traffic in them and only one of them was watching, and the
    // mode is where a reader sees which.
    let fixture = Fixture::new("quiet-sensor");

    let watched = fixture.scan_with_flows_only();
    let unwatched = fixture.scan_without_events();

    assert_eq!(
        watched.report.coverage.reconciliation_mode,
        ReconciliationMode::StaticPlusWire
    );
    assert_eq!(
        unwatched.report.coverage.reconciliation_mode,
        ReconciliationMode::StaticOnly
    );
    // A sensor with nothing to report is still a sensor, so the kind that needs
    // it is not suppressed for want of a source.
    let stated = details(&watched, DiagnosticComponent::Reconciliation);
    assert!(
        !stated
            .iter()
            .any(|detail| detail.contains("unmatched_wire_traffic")),
        "{stated:?}"
    );
}

#[test]
fn a_volume_claim_is_not_derived_until_a_policy_declares_the_band() {
    // **Milestone 57.** The threshold comes from policy, and the command line
    // states none, so the report names the missing threshold instead of
    // inventing one. The second half runs the same three sources with a band and
    // shows the finding was reachable all along.
    let fixture = Fixture::new("volume-band");
    fixture
        .write_events("worker-1.jsonl", &[call_to("api.openai.com")])
        .write_flows(
            "sensor-1.jsonl",
            &[connection(
                "api.openai.com",
                "openai",
                FlowScope::InScope,
                54_321,
            )],
        );

    let without = fixture.scan_all_sources();
    assert!(
        findings_of_kind(&without, periskop_core::finding::Kind::VolumeAnomaly).is_empty(),
        "{:?}",
        without.report
    );
    let stated = details(&without, DiagnosticComponent::Reconciliation);
    assert!(
        stated.iter().any(|detail| detail.contains("volume_anomaly")
            && detail.contains("volume_band_not_declared")),
        "{stated:?}"
    );

    // 2048 bytes on the wire against a declared payload of 512 is four times,
    // outside a band that admits three.
    let with = fixture.scan_with_sources(
        scan::ScanSources {
            event_dir: Some(&fixture.events()),
            flow_dir: Some(&fixture.flows()),
        },
        ReconcileSettings::default().with_volume_band(VolumeBand::declared(5_000, 30_000).unwrap()),
    );
    assert_eq!(
        findings_of_kind(&with, periskop_core::finding::Kind::VolumeAnomaly).len(),
        1,
        "{:?}",
        with.report
    );
}

#[test]
fn a_sensor_that_counted_no_bytes_is_not_a_run_without_anomalies() {
    // **Critic round K2, end to end, first half.** The band is declared and the
    // capture mechanism reported connections without volume. Every comparison is
    // impossible, and the report used to say what it says for a clean run:
    // nothing. The suppression is what tells the two apart.
    let fixture = Fixture::new("volume-unmeasured");
    let mut uncounted = connection("api.openai.com", "openai", FlowScope::InScope, 54_321);
    uncounted.bytes_out = None;
    let mut also_uncounted = connection("api.openai.com", "openai", FlowScope::InScope, 54_322);
    also_uncounted.bytes_out = None;
    fixture
        .write_events("worker-1.jsonl", &[call_to("api.openai.com")])
        .write_flows("sensor-1.jsonl", &[uncounted, also_uncounted]);

    let outcome = fixture.scan_with_sources(
        scan::ScanSources {
            event_dir: Some(&fixture.events()),
            flow_dir: Some(&fixture.flows()),
        },
        ReconcileSettings::default().with_volume_band(VolumeBand::declared(5_000, 30_000).unwrap()),
    );

    assert!(
        findings_of_kind(&outcome, periskop_core::finding::Kind::VolumeAnomaly).is_empty(),
        "{:?}",
        outcome.report
    );
    let stated = details(&outcome, DiagnosticComponent::Reconciliation);
    assert!(
        stated
            .iter()
            .any(|detail| detail.contains("volume_anomaly")
                && detail.contains("volume_not_measured")),
        "{stated:?}"
    );
}

#[test]
fn a_call_the_hook_could_not_size_produces_no_volume_anomaly_and_says_why() {
    // **Critic round K2, end to end, second half, and the worse one.** Two calls
    // travelled over one connection and the hook could size only one of them, so
    // the expected total was half of what was really declared and an anomaly
    // appeared out of the missing half. The subject of that finding was the
    // hook's blind spot, presented as the machine's behaviour.
    let fixture = Fixture::new("volume-unsized-call");
    let sized = call_to("api.openai.com");
    let mut unmeasured = event("openai", "embeddings.create", "api.openai.com", "openai");
    unmeasured.payload_shape.byte_size_estimate = 0;
    fixture
        .write_events("worker-1.jsonl", &[sized, unmeasured])
        .write_flows(
            "sensor-1.jsonl",
            &[connection(
                "api.openai.com",
                "openai",
                FlowScope::InScope,
                54_321,
            )],
        );

    let outcome = fixture.scan_with_sources(
        scan::ScanSources {
            event_dir: Some(&fixture.events()),
            flow_dir: Some(&fixture.flows()),
        },
        ReconcileSettings::default().with_volume_band(VolumeBand::declared(5_000, 30_000).unwrap()),
    );

    assert!(
        findings_of_kind(&outcome, periskop_core::finding::Kind::VolumeAnomaly).is_empty(),
        "{:?}",
        outcome.report
    );
    let stated = details(&outcome, DiagnosticComponent::Reconciliation);
    assert!(
        stated
            .iter()
            .any(|detail| detail.contains("declared no payload size")),
        "{stated:?}"
    );
}

#[test]
fn two_runs_over_one_tree_and_one_flow_directory_write_the_same_bytes() {
    let fixture = Fixture::new("wire-determinism");
    fixture
        .write_events("worker-1.jsonl", &[call_to("api.openai.com")])
        .write_flows(
            "sensor-1.jsonl",
            &[
                unexplained_traffic(FlowScope::InScope, 54_321),
                unexplained_traffic(FlowScope::OutOfScopeProcess, 54_322),
            ],
        );

    let first = to_canonical_json(&fixture.scan_all_sources().report).unwrap();
    let second = to_canonical_json(&fixture.scan_all_sources().report).unwrap();

    assert_eq!(first, second);
}

#[test]
fn the_names_of_the_flow_files_do_not_reach_the_report() {
    // Same traffic, split across files two different ways. A report that
    // differed would differ because the sensor rotated its output, which is
    // exactly the kind of change a diff must not light up on.
    let one = Fixture::new("wire-layout-a");
    one.write_flows(
        "z-sensor.jsonl",
        &[unexplained_traffic(FlowScope::InScope, 54_321)],
    )
    .write_flows(
        "a-sensor.jsonl",
        &[unexplained_traffic(FlowScope::OutOfScopeProcess, 54_322)],
    );

    let other = Fixture::new("wire-layout-b");
    other.write_flows(
        "m-sensor.jsonl",
        &[
            unexplained_traffic(FlowScope::OutOfScopeProcess, 54_322),
            unexplained_traffic(FlowScope::InScope, 54_321),
        ],
    );

    assert_eq!(
        to_canonical_json(&one.scan_with_flows_only().report).unwrap(),
        to_canonical_json(&other.scan_with_flows_only().report).unwrap()
    );
}

#[test]
fn a_damaged_flow_record_is_reported_and_does_not_cost_the_scan() {
    // The normal state of a file a live sensor is still appending to. A scan
    // that gave up here would hand any misbehaving sensor the power to blind the
    // whole run.
    let fixture = Fixture::new("damaged-flow");
    let good = serde_json::to_string(&unexplained_traffic(FlowScope::InScope, 54_321)).unwrap();
    fixture.write_raw_flows(
        "sensor-1.jsonl",
        &format!("{good}\n{{ half a record, no closing\n"),
    );

    let outcome = fixture.scan_with_flows_only();

    // The intact record still did its work.
    assert_eq!(
        findings_of_kind(&outcome, periskop_core::finding::Kind::UnmatchedWireTraffic).len(),
        1,
        "{:?}",
        outcome.report
    );
    // And the loss is located, not merely absorbed.
    let losses = details(&outcome, DiagnosticComponent::NetworkSensor);
    assert!(
        losses
            .iter()
            .any(|detail| detail.contains("sensor-1.jsonl:2") && detail.contains("unparsable")),
        "{losses:?}"
    );
}

#[test]
fn no_absolute_path_reaches_the_report_through_the_flow_side() {
    // The flow directory is an absolute path on every machine that runs this.
    // None of it may reach output two machines are supposed to be able to
    // compare.
    let fixture = Fixture::new("no-abs-path-wire");
    fixture.write_raw_flows("sensor-1.jsonl", "{ not a record at all\n");

    let outcome = fixture.scan_with_flows_only();
    let json = to_canonical_json(&outcome.report).unwrap();

    assert!(
        !json.contains(&fixture.root.to_string_lossy().to_string()),
        "the temporary directory leaked into the report"
    );
    // The loss is still reported, so the absence above is not the absence of a
    // diagnostic.
    assert!(
        !details(&outcome, DiagnosticComponent::NetworkSensor).is_empty(),
        "{:?}",
        outcome.report.diagnostics
    );
}

#[test]
fn a_flow_directory_that_is_not_there_stops_the_command() {
    // A mistyped path must not become a report claiming `full` with no traffic
    // in it, which reads as a machine that sent nothing.
    let fixture = Fixture::new("missing-flow-dir");
    let absent = fixture.flows().join("never-created");

    let status = Command::new(env!("CARGO_BIN_EXE_periskop"))
        .arg("scan")
        .arg(fixture.project())
        .arg("--rules")
        .arg(repo_root().join("rules"))
        .arg("--flows")
        .arg(&absent)
        .output()
        .unwrap();

    assert_eq!(status.status.code(), Some(2), "{status:?}");
    assert!(
        String::from_utf8_lossy(&status.stderr).contains("no flow directory"),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
}

#[test]
fn the_command_reaches_the_full_mode_when_it_is_given_all_three_sources() {
    // The wiring, through the binary rather than the library: both flags, one
    // report, and the mode the product's central claim is entitled to.
    let fixture = Fixture::new("cli-full");
    fixture
        .write_events("worker-1.jsonl", &[call_to("api.openai.com")])
        .write_flows(
            "sensor-1.jsonl",
            &[unexplained_traffic(FlowScope::InScope, 54_321)],
        );

    let output = Command::new(env!("CARGO_BIN_EXE_periskop"))
        .arg("scan")
        .arg(fixture.project())
        .arg("--rules")
        .arg(repo_root().join("rules"))
        .arg("--events")
        .arg(fixture.events())
        .arg("--flows")
        .arg(fixture.flows())
        .arg("--json")
        .output()
        .unwrap();

    let report = String::from_utf8_lossy(&output.stdout);
    assert!(report.contains("\"full\""), "{report}");
    assert!(report.contains("unmatched_wire_traffic"), "{report}");
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

/// The interpreter to run the sample with, or the reason there is none.
///
/// Same policy as `proof.rs`, and deliberately the same switch: a machine with
/// no python3 says so loudly and states that this run did not close the gate,
/// and continuous integration sets [`REQUIRE_PROOF`] so that a skip there is a
/// failure. Two policies would mean a green pipeline could still be hiding one
/// of the two gates.
fn python_interpreter() -> Result<String, String> {
    for candidate in ["python3", "python"] {
        match Command::new(candidate).arg("--version").output() {
            Ok(output) if output.status.success() => return Ok(candidate.to_owned()),
            Ok(output) => {
                return Err(format!(
                    "{candidate} is on PATH but `{candidate} --version` exited with {}",
                    output.status
                ))
            }
            Err(_) => continue,
        }
    }
    Err("no python3 or python interpreter on PATH".to_owned())
}

/// Runs the sample under the real hook, the documented fallback way.
///
/// `PYTHONPATH` points at `hooks/python`, whose `sitecustomize.py` installs the
/// hook before the application's first line. The application is not modified,
/// which is the property the whole runtime source rests on.
fn run_hooked(interpreter: &str, project: &Path, event_dir: &Path) -> std::process::Output {
    Command::new(interpreter)
        .arg("app.py")
        .current_dir(project)
        .env("PYTHONPATH", repo_root().join("hooks/python"))
        // Keeps the run from leaving __pycache__ directories in a source tree
        // the test does not own.
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PERISKOP_EVENT_DIR", event_dir)
        .env("PERISKOP_HOOK_ENTRYPOINT", "pipeline-app")
        // A developer who switched the hook off in their shell would otherwise
        // get an empty event directory and a failure with no obvious cause.
        .env_remove("PERISKOP_HOOK")
        .env_remove("PERISKOP_HOOK_OUTPUT")
        .output()
        .expect("the interpreter answered --version, so it can run a script")
}

/// The window the hook itself wrote, read straight off the sidecar.
///
/// Read from the file rather than taken from the report, so that the assertion
/// comparing the two is comparing two sources and not one value with itself.
fn window_the_hook_wrote(event_dir: &Path) -> u64 {
    let mut windows: Vec<u64> = Vec::new();
    for entry in std::fs::read_dir(event_dir)
        .expect("event directory")
        .flatten()
    {
        let path = entry.path();
        if !path.to_string_lossy().ends_with(".status.json") {
            continue;
        }
        let document: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("status file"))
                .expect("the hook writes JSON");
        windows.push(
            document["observation_window_ms"]
                .as_u64()
                .expect("the hook states how long it was watching"),
        );
    }
    assert_eq!(windows.len(), 1, "the sample runs exactly one process");
    windows[0]
}

/// The code point a finding is about.
fn egress_point_of(finding: &periskop_core::finding::Finding) -> &str {
    finding
        .refs
        .iter()
        .find(|reference| reference.ref_type == periskop_core::finding::RefType::EgressPoint)
        .map(|reference| reference.ref_id.as_str())
        .expect("every finding about a call site names it")
}

fn findings_of_kind(
    outcome: &scan::ScanOutcome,
    kind: periskop_core::finding::Kind,
) -> Vec<&periskop_core::finding::Finding> {
    outcome
        .report
        .findings
        .iter()
        .chain(outcome.report.suspect_findings.iter())
        .filter(|finding| finding.kind == kind)
        .collect()
}

/// **The gate for F2-N. A run in which this does not pass has not closed it.**
///
/// Everything before this test proved a piece: the hook measures a window, the
/// collector folds one out of the sidecars, the scan converts it. None of that
/// is worth anything on its own, because the defect being fixed was exactly a
/// chain of correct pieces that no real run ever assembled: `dormant_egress_point`
/// was derivable in a unit test, the pipeline passed `ObservationWindow::NONE`,
/// and every scan of a real repository suppressed the finding.
///
/// So this runs the real hook in a real interpreter over a sample with two
/// egress points, calls one of them, and asks the scan whether it reports the
/// other. The window under the claim is the one that process actually measured;
/// nothing in the test writes it.
#[test]
fn a_call_site_the_running_program_never_reached_is_reported_dormant() {
    let interpreter = match python_interpreter() {
        Ok(interpreter) => interpreter,
        Err(reason) => {
            assert!(
                std::env::var_os(REQUIRE_PROOF).is_none(),
                "{REQUIRE_PROOF} is set and the F2-N gate cannot run: {reason}"
            );
            eprintln!(
                "\n  SKIPPED: the dormant_egress_point end to end proof did not run.\n  \
                 Reason: {reason}\n  \
                 This run does not close F2-N. Install a python3 interpreter, or set \
                 {REQUIRE_PROOF}=1\n  to make the missing interpreter a failure instead \
                 of a skip.\n"
            );
            return;
        }
    };

    let fixture = Fixture::new("dormant-end-to-end");
    fixture
        .write_source(TWO_POINTS_ONE_CALL)
        .write_project_file("openai.py", OPENAI_SDK_STUB);

    // (a) The program runs, hooked. A non zero exit would be a fail-open
    //     failure before it proved anything about findings.
    let run = run_hooked(&interpreter, &fixture.project(), &fixture.events());
    assert!(
        run.status.success(),
        "the hooked application did not exit cleanly.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    // (b) The window is one the hook measured, not one this test invented.
    let measured = window_the_hook_wrote(&fixture.events());
    assert!(
        measured >= 50,
        "the sample occupies fifty milliseconds, so the hook measured at least that: {measured}"
    );

    // (c) The scan. The threshold is stated rather than the default ten
    //     minutes, which no test can wait for; the window it is compared
    //     against is real.
    let outcome = fixture.scan_with_min_window(1);

    assert_eq!(
        outcome.report.coverage.reconciliation_mode,
        ReconciliationMode::StaticPlusRuntime
    );
    assert_eq!(
        outcome.report.coverage.observation_window_ms, measured,
        "the window in the report is the one the hook wrote: {:?}",
        outcome.report.coverage
    );

    // (d) Two call sites were declared and one call was observed.
    let declared = findings_of_kind(&outcome, periskop_core::finding::Kind::DeclaredEgressPoint);
    assert_eq!(declared.len(), 2, "{declared:?}");
    let point_for = |operation: &str| -> &str {
        declared
            .iter()
            .find(|finding| finding.operation.as_deref() == Some(operation))
            .map(|finding| egress_point_of(finding))
            .unwrap_or_else(|| panic!("the scanner read no point for {operation}: {declared:?}"))
    };

    // (e) The finding. One, for the line the program never reached.
    let dormant = findings_of_kind(&outcome, periskop_core::finding::Kind::DormantEgressPoint);
    assert_eq!(
        dormant.len(),
        1,
        "one line ran and one did not, so exactly one dormancy is derivable: {:?}",
        outcome.report
    );
    assert_eq!(
        egress_point_of(dormant[0]),
        point_for("embeddings.create"),
        "the dormant finding is about the line that never ran"
    );
    assert_ne!(
        egress_point_of(dormant[0]),
        point_for("chat.completions.create"),
        "the line the program did run must not be reported as never executed"
    );
    assert_eq!(
        dormant[0].detector.component,
        periskop_core::finding::Component::Reconciliation
    );
    // The claim is stated no more firmly than the run can defend: a call to this
    // vendor was observed, so any of its call sites could have made it.
    assert_eq!(
        dormant[0].confidence,
        periskop_core::finding::Confidence::Suspect
    );
    // And the window it rests on travels with it, so the claim can be argued
    // with rather than only read.
    let evidence: Vec<&str> = dormant[0]
        .evidence
        .iter()
        .map(|evidence| evidence.r#ref.as_str())
        .collect();
    assert!(
        evidence
            .iter()
            .any(|text| text.contains(&format!("observation_window_ms={measured}"))),
        "{evidence:?}"
    );
    // Nothing was lost on the way: this is a clean run, not one whose events
    // the collector could not read.
    assert_eq!(outcome.report.coverage.dropped_events, 0);
    assert_eq!(outcome.report.coverage.unlinked_events, 0);
}

#[test]
fn a_window_no_hook_measured_suppresses_the_claim_and_the_report_says_which() {
    // The other half of the gate. A hook that died before it could flush leaves
    // its stream and no accounting, and the run then knows a call happened and
    // not how long it watched. Deriving a dormancy from that would state the one
    // fact the finding rests on without having measured it.
    let fixture = Fixture::new("window-unmeasured");
    fixture.write_events("worker-1.jsonl", &[call_to("api.openai.com")]);

    let outcome = fixture.scan_with_min_window(1);

    assert!(
        findings_of_kind(&outcome, periskop_core::finding::Kind::DormantEgressPoint).is_empty(),
        "an unmeasured window cannot support a dormancy claim: {:?}",
        outcome.report
    );
    // Suppressed is not the same as absent, so the report carries both halves:
    // that the kind was not derived, and that the window was never measured.
    // Without the second line a reader sees observation_window_ms: 0 and cannot
    // tell a hook that watched nothing from one that never said.
    let stated = details(&outcome, DiagnosticComponent::Reconciliation);
    assert!(
        stated
            .iter()
            .any(|detail| detail.contains("dormant_egress_point")
                && detail.contains("observation_window_too_short")),
        "{stated:?}"
    );
    let hooks = details(&outcome, DiagnosticComponent::RuntimeHooks);
    assert!(
        hooks
            .iter()
            .any(|detail| detail.contains("observation window not measured")),
        "{hooks:?}"
    );
    assert_eq!(outcome.report.coverage.observation_window_ms, 0);
}

#[test]
fn a_measured_window_and_an_unmeasured_one_do_not_produce_the_same_report() {
    // The distinction the whole change rests on, held against the one field the
    // coverage statement has for it. Both runs write 0 or a duration into
    // observation_window_ms, and only the diagnostics say which of the two
    // silences the reader is looking at.
    let measured = Fixture::new("window-measured");
    measured
        .write_events("worker-1.jsonl", &[call_to("api.openai.com")])
        .write_status(
            "worker-1.jsonl",
            r#"{"hook_status":"active","reason":"","dropped_events_count":0,
                "written_events_count":1,"failures":[],
                "observation_window_ms":900000}"#,
        );

    let outcome = measured.scan();

    assert_eq!(outcome.report.coverage.observation_window_ms, 900_000);
    assert!(
        !details(&outcome, DiagnosticComponent::RuntimeHooks)
            .iter()
            .any(|detail| detail.contains("observation window not measured")),
        "a run that measured its window must not report that it did not: {:?}",
        outcome.report.diagnostics
    );
    // Nine hundred seconds is over the declared threshold, so the kind is not
    // suppressed for want of a window either.
    assert!(
        !details(&outcome, DiagnosticComponent::Reconciliation)
            .iter()
            .any(|detail| detail.contains("dormant_egress_point")
                && detail.contains("observation_window_too_short")),
        "{:?}",
        outcome.report.diagnostics
    );
}

#[test]
fn one_process_that_ran_un_hooked_takes_the_dormancy_claim_with_it() {
    // A window of zero rather than an unknown one, and it decides the run: part
    // of the program ran in nobody's call path, so no silence observed anywhere
    // else can be read as code that never executes.
    let fixture = Fixture::new("window-unhooked-process");
    fixture
        .write_events("worker-1.jsonl", &[call_to("api.openai.com")])
        .write_status(
            "worker-1.jsonl",
            r#"{"hook_status":"active","reason":"","dropped_events_count":0,
                "written_events_count":1,"failures":[],
                "observation_window_ms":900000}"#,
        )
        .write_status(
            "worker-2.jsonl",
            r#"{"hook_status":"disabled","reason":"install_failed",
                "dropped_events_count":0,"written_events_count":0,"failures":[]}"#,
        );

    let outcome = fixture.scan_with_min_window(1);

    assert_eq!(outcome.report.coverage.observation_window_ms, 0);
    assert!(
        findings_of_kind(&outcome, periskop_core::finding::Kind::DormantEgressPoint).is_empty(),
        "{:?}",
        outcome.report
    );
    // The window was measured, so this is not the unmeasured case and must not
    // be reported as one. Which process cost the run is named instead.
    let hooks = details(&outcome, DiagnosticComponent::RuntimeHooks);
    assert!(
        !hooks
            .iter()
            .any(|detail| detail.contains("observation window not measured")),
        "{hooks:?}"
    );
    assert!(
        hooks
            .iter()
            .any(|detail| detail.contains("hook_not_active: install_failed")),
        "{hooks:?}"
    );
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

/// A policy declaring the band the engine refuses to invent.
///
/// 5000 to 30000 basis points is half to three times the payload the calls
/// declared. The fixture's connection carries 2048 bytes against a declared 512,
/// which is four times and outside it.
const POLICY_WITH_BAND: &str = r#"
[policy]
name = "fixture-policy"
version = 7

[reconciliation]
volume_band = { min_basis_points = 5000, max_basis_points = 30000 }
"#;

/// The wiring F3-GAP2 was about: a threshold written in a file changes which
/// findings exist.
///
/// Run through the binary rather than the library, because the library could
/// already do this and had been able to since the rule was written. What did not
/// exist was any path from a file on disk to `ReconcileSettings`, so the field
/// could be declared in a policy and nothing read it, and `volume_anomaly` could
/// not be produced by a real pipeline run at all.
#[test]
fn a_volume_band_declared_in_a_policy_file_produces_the_finding_through_the_binary() {
    let fixture = Fixture::new("policy-band-cli");
    fixture
        .write_events("worker-1.jsonl", &[call_to("api.openai.com")])
        .write_flows(
            "sensor-1.jsonl",
            &[connection(
                "api.openai.com",
                "openai",
                FlowScope::InScope,
                54_321,
            )],
        )
        .write_project_file("periskop-policy.toml", POLICY_WITH_BAND);

    let report = scan_json(&fixture, &[]);

    assert!(
        report.contains("volume_anomaly"),
        "the band was declared and the finding did not appear: {report}"
    );
    // The policy that decided the run is named in the report, or an auditor
    // cannot say which thresholds produced it.
    assert!(report.contains("fixture-policy"), "{report}");
    assert!(report.contains("\"policy_version\": \"7\""), "{report}");
}

#[test]
fn the_same_tree_without_the_policy_file_derives_nothing_and_says_why() {
    // The other half of the claim above. Without a declared band the kind is
    // suppressed with its reason rather than silently absent, and no invented
    // default fills in for the missing threshold.
    let fixture = Fixture::new("policy-band-absent");
    fixture
        .write_events("worker-1.jsonl", &[call_to("api.openai.com")])
        .write_flows(
            "sensor-1.jsonl",
            &[connection(
                "api.openai.com",
                "openai",
                FlowScope::InScope,
                54_321,
            )],
        );

    let report = scan_json(&fixture, &[]);

    assert!(!report.contains("\"volume_anomaly\""), "{report}");
    assert!(report.contains("volume_band_not_declared"), "{report}");
}

#[test]
fn a_policy_file_that_cannot_be_applied_fails_the_run_instead_of_being_skipped() {
    // The contract's rule 2. A policy present, unusable and quietly replaced by
    // the defaults is the exact defect this product looks for in other people's
    // systems: a control that is there, inert, and reported as fine.
    let fixture = Fixture::new("policy-inverted");
    fixture.write_project_file(
        "periskop-policy.toml",
        r#"
[policy]
name = "fixture-policy"
version = 1

[reconciliation]
volume_band = { min_basis_points = 30000, max_basis_points = 5000 }
"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_periskop"))
        .arg("scan")
        .arg(fixture.project())
        .arg("--rules")
        .arg(repo_root().join("rules"))
        .arg("--json")
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(1), "{report}");
    assert!(report.contains("POLICY_LOAD_ERROR"), "{report}");
    assert!(report.contains("engine.policy-loaded"), "{report}");
    assert!(report.contains("\"FAIL\""), "{report}");
    // The file name reaches the report and the absolute path does not.
    assert!(report.contains("periskop-policy.toml"), "{report}");
    assert!(
        !report.contains(&fixture.root.to_string_lossy().to_string()),
        "{report}"
    );
}

#[test]
fn a_policy_path_that_is_not_there_stops_the_command() {
    // A mistyped policy path must not silently become the engine's defaults, for
    // the reason a mistyped flow directory must not become a quiet machine.
    let fixture = Fixture::new("policy-missing");
    let absent = fixture.project().join("nowhere.toml");

    let output = Command::new(env!("CARGO_BIN_EXE_periskop"))
        .arg("scan")
        .arg(fixture.project())
        .arg("--rules")
        .arg(repo_root().join("rules"))
        .arg("--policy")
        .arg(&absent)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no policy file"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_rule_block_this_build_does_not_evaluate_is_reported_rather_than_swallowed() {
    // The failure this prevents: a user writes a `fail` condition, reads a
    // passing report, and believes the condition held.
    let fixture = Fixture::new("policy-unevaluated-rules");
    fixture.write_project_file(
        "periskop-policy.toml",
        r#"
[policy]
name = "fixture-policy"
version = 2

[[condition]]
id = "no-unmatched-traffic"
when = { field = "kind", equals = "unmatched_wire_traffic" }
severity = "fail"
"#,
    );

    let report = scan_json(&fixture, &[]);
    assert!(
        report.contains("condition:no-unmatched-traffic"),
        "{report}"
    );
    assert!(report.contains("not evaluated by this build"), "{report}");
}

/// Runs the binary over a fixture with every source it has, and returns the JSON.
fn scan_json(fixture: &Fixture, extra: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_periskop"))
        .arg("scan")
        .arg(fixture.project())
        .arg("--rules")
        .arg(repo_root().join("rules"))
        .arg("--events")
        .arg(fixture.events())
        .arg("--flows")
        .arg(fixture.flows())
        .arg("--json")
        .args(extra)
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}
