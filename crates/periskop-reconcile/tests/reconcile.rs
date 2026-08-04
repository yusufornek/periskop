//! End to end reconciliation, driven through the public surface only.
//!
//! The unit tests in each module pin one rule at a time. What is checked here is
//! the property that only shows up when the rules run together: a run states what
//! it could not do, and it states it in a form that survives being written out
//! twice.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use periskop_core::finding::{
    Component, Confidence, Detector, EntityRef, Evidence, EvidenceType, Finding, Kind, Location,
    RefType, Source,
};
use periskop_network_sensor::flow::{
    FiveTuple, Mechanism as CaptureMechanism, ProcessRecord, Proto, ResolvedHostSource, SniSource,
};
use periskop_network_sensor::observation::Observation;
use periskop_network_sensor::scope::FlowScope;
use periskop_network_sensor::Flow;
use periskop_reconcile::capability::{DerivedKind, SuppressionReason};
use periskop_reconcile::settings::{ReconcileSettings, VolumeBand};
use periskop_reconcile::{
    reconcile, DeclaredPoint, DeclaredSource, ObservationWindow, ReconcileInputs, ReconcileOutcome,
    RuntimeSource, Sources, WireSource,
};
use periskop_runtime_collector::event::{
    EgressEvent, Language, Library, Mechanism, PayloadShape, Process, Target,
};

const EP_ONE: &str = "ep_3f0a91c7d4e28b56";
const EP_TWO: &str = "ep_0000000000000001";
const EP_THREE: &str = "ep_00000000000000ff";

/// Long enough for a dormant claim under the declared default.
const LONG_WINDOW: ObservationWindow = ObservationWindow::of_ms(3_600_000);
/// A one minute session: what the task calls a window nothing can be concluded from.
const SHORT_WINDOW: ObservationWindow = ObservationWindow::of_ms(60_000);

fn scanner_finding(egress_point_id: &str, provider: &str) -> Finding {
    Finding::new(
        Kind::DeclaredEgressPoint,
        Confidence::Confirmed,
        provider,
        EntityRef {
            ref_type: RefType::EgressPoint,
            ref_id: egress_point_id.to_owned(),
        },
        Evidence {
            evidence_type: EvidenceType::AstNode,
            r#ref: "call@services/customer.py".to_owned(),
            hash: None,
        },
        Detector {
            component: Component::StaticScanner,
            rule_id: "python.static.openai-chat-completions".to_owned(),
            rule_version: "1.0.0".to_owned(),
            rule_hash: "0".repeat(64),
        },
    )
    .unwrap()
    .with_egress_kind("llm_chat")
    .with_location(Location {
        component: Component::StaticScanner,
        path: Some("services/customer.py".to_owned()),
        span: None,
        symbol: None,
    })
}

fn point(egress_point_id: &str, host: &str, operation: &str) -> DeclaredPoint {
    point_for("openai", egress_point_id, host, operation)
}

fn point_for(provider: &str, egress_point_id: &str, host: &str, operation: &str) -> DeclaredPoint {
    DeclaredPoint::from_finding(&scanner_finding(egress_point_id, provider))
        .unwrap()
        .with_target(host, None)
        .unwrap()
        .with_operation(operation)
}

fn point_without_operation(egress_point_id: &str, host: &str) -> DeclaredPoint {
    DeclaredPoint::from_finding(&scanner_finding(egress_point_id, "openai"))
        .unwrap()
        .with_target(host, None)
        .unwrap()
}

fn call(module: &str, operation: &str, host: &str, provider: &str) -> EgressEvent {
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

fn run(
    points: Vec<DeclaredPoint>,
    events: Vec<EgressEvent>,
    window: ObservationWindow,
) -> ReconcileOutcome {
    reconcile(&ReconcileInputs::new(
        Sources::new(
            DeclaredSource::Present(points),
            RuntimeSource::Present(events),
            WireSource::Absent,
        ),
        window,
    ))
}

/// A three source run: code, calls and connections.
fn run_full(
    points: Vec<DeclaredPoint>,
    events: Vec<EgressEvent>,
    flows: Vec<Flow>,
    settings: ReconcileSettings,
) -> ReconcileOutcome {
    reconcile(
        &ReconcileInputs::new(
            Sources::new(
                DeclaredSource::Present(points),
                RuntimeSource::Present(events),
                WireSource::Present(flows),
            ),
            LONG_WINDOW,
        )
        .with_settings(settings),
    )
}

/// One connection the sensor watched, in the bucket the caller states.
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

/// Traffic to a destination no rule in this test file declares.
fn unexplained(scope: FlowScope, src_port: u16) -> Flow {
    connection("telemetry.vendor.example", "unknown", scope, src_port)
}

/// The call the declared point makes, so a wire test is not also a dormancy
/// test. Without it every three source run below would derive a dormant point
/// as well, and the assertions would be about two rules at once.
fn the_declared_call() -> Vec<EgressEvent> {
    vec![call(
        "openai",
        "chat.completions.create",
        "api.openai.com",
        "openai",
    )]
}

fn kinds_of(outcome: &ReconcileOutcome) -> Vec<Kind> {
    outcome.findings.iter().map(|f| f.kind).collect()
}

fn reasons_for(outcome: &ReconcileOutcome, kind: DerivedKind) -> Vec<SuppressionReason> {
    outcome
        .suppressed
        .iter()
        .filter(|s| s.kind == kind)
        .map(|s| s.reason)
        .collect()
}

#[test]
fn a_run_with_nothing_in_it_produces_nothing_and_says_why() {
    let outcome = reconcile(&ReconcileInputs::new(
        Sources::new(
            DeclaredSource::Absent,
            RuntimeSource::Absent,
            WireSource::Absent,
        ),
        ObservationWindow::NONE,
    ));

    assert!(outcome.findings.is_empty());
    assert_eq!(outcome.unlinked_events, 0);
    assert_eq!(
        outcome.reconciliation_mode,
        periskop_report::coverage::ReconciliationMode::StaticOnly
    );
    // Silence would be indistinguishable from a clean run. Every kind names its
    // reason instead.
    for kind in DerivedKind::ALL {
        assert!(!reasons_for(&outcome, kind).is_empty(), "{kind:?}");
    }
}

#[test]
fn a_static_only_run_derives_nothing_and_reports_the_missing_sources() {
    let outcome = reconcile(&ReconcileInputs::new(
        Sources::new(
            DeclaredSource::Present(vec![point(
                EP_ONE,
                "api.openai.com",
                "chat.completions.create",
            )]),
            RuntimeSource::Absent,
            WireSource::Absent,
        ),
        ObservationWindow::NONE,
    ));

    assert!(outcome.findings.is_empty());
    assert_eq!(
        outcome.reconciliation_mode,
        periskop_report::coverage::ReconciliationMode::StaticOnly
    );
    assert!(reasons_for(&outcome, DerivedKind::DormantEgressPoint)
        .contains(&SuppressionReason::RuntimeSourceAbsent));
    assert!(reasons_for(&outcome, DerivedKind::TargetDrift)
        .contains(&SuppressionReason::RuntimeSourceAbsent));
}

#[test]
fn observation_without_a_scan_attributes_nothing_and_counts_it() {
    // Nothing to compare against, so every call is unattributed. That is a
    // coverage number, not a list of findings about the code.
    let outcome = reconcile(&ReconcileInputs::new(
        Sources::new(
            DeclaredSource::Absent,
            RuntimeSource::Present(vec![call(
                "openai",
                "chat.completions.create",
                "api.openai.com",
                "openai",
            )]),
            WireSource::Absent,
        ),
        LONG_WINDOW,
    ));

    assert!(outcome.findings.is_empty());
    assert_eq!(outcome.unlinked_events, 1);
    assert!(reasons_for(&outcome, DerivedKind::DormantEgressPoint)
        .contains(&SuppressionReason::DeclaredSourceAbsent));
}

#[test]
fn a_point_nothing_called_is_reported_dormant_when_the_window_supports_it() {
    let outcome = run(
        vec![point(EP_ONE, "api.openai.com", "chat.completions.create")],
        Vec::new(),
        LONG_WINDOW,
    );

    assert_eq!(kinds_of(&outcome), [Kind::DormantEgressPoint]);
    assert_eq!(outcome.findings[0].source, Source::Reconciled);
    assert_eq!(
        outcome.findings[0].detector.component,
        Component::Reconciliation
    );
}

#[test]
fn a_one_minute_session_produces_no_dormant_finding_at_all() {
    // The claim under test: code that did not run during a minute of observation
    // is not dead code, and reporting it as such is a false statement about the
    // system rather than a weak one.
    let outcome = run(
        vec![point(EP_ONE, "api.openai.com", "chat.completions.create")],
        Vec::new(),
        SHORT_WINDOW,
    );

    assert!(outcome.findings.is_empty());
    assert_eq!(
        reasons_for(&outcome, DerivedKind::DormantEgressPoint),
        [SuppressionReason::ObservationWindowTooShort]
    );
    // The threshold that decided it travels with the result.
    assert_eq!(outcome.observation_window_ms, 60_000);
    assert_eq!(outcome.settings.min_dormant_window_ms(), 600_000);
}

#[test]
fn a_zero_length_window_produces_no_dormant_finding_either() {
    let outcome = run(
        vec![point(EP_ONE, "api.openai.com", "chat.completions.create")],
        Vec::new(),
        ObservationWindow::NONE,
    );

    assert!(outcome.findings.is_empty());
    assert!(reasons_for(&outcome, DerivedKind::DormantEgressPoint)
        .contains(&SuppressionReason::ObservationWindowTooShort));
}

#[test]
fn the_window_threshold_is_configurable_and_the_result_says_which_one_ran() {
    let inputs = ReconcileInputs::new(
        Sources::new(
            DeclaredSource::Present(vec![point(
                EP_ONE,
                "api.openai.com",
                "chat.completions.create",
            )]),
            RuntimeSource::Present(Vec::new()),
            WireSource::Absent,
        ),
        SHORT_WINDOW,
    )
    .with_settings(ReconcileSettings::default().with_min_dormant_window_ms(30_000));
    let outcome = reconcile(&inputs);

    assert_eq!(kinds_of(&outcome), [Kind::DormantEgressPoint]);
    assert_eq!(outcome.settings.min_dormant_window_ms(), 30_000);
}

#[test]
fn a_call_that_reached_another_destination_is_reported_as_drift() {
    let outcome = run(
        vec![point(EP_ONE, "api.openai.com", "chat.completions.create")],
        vec![call(
            "openai",
            "chat.completions.create",
            "llm-gateway.internal",
            "unknown",
        )],
        LONG_WINDOW,
    );

    assert_eq!(kinds_of(&outcome), [Kind::TargetDrift]);
    assert_eq!(outcome.findings[0].confidence, Confidence::Confirmed);
    assert_eq!(outcome.unlinked_events, 0);
}

#[test]
fn drift_is_still_derived_when_the_window_is_too_short_for_dormancy() {
    // A drift is a statement about a call that did happen, so the length of the
    // window has no bearing on it.
    let outcome = run(
        vec![point(EP_ONE, "api.openai.com", "chat.completions.create")],
        vec![call(
            "openai",
            "chat.completions.create",
            "llm-gateway.internal",
            "unknown",
        )],
        SHORT_WINDOW,
    );

    assert_eq!(kinds_of(&outcome), [Kind::TargetDrift]);
}

#[test]
fn one_request_seen_by_two_hooks_at_two_layers_is_attributed_once() {
    // The trap. The Python hook wraps the SDK and names the module `openai`; the
    // Node hook wraps the transport and names it `node:https`, with the HTTP
    // method as its operation. Same request, two records, nothing in common but
    // the destination.
    let outcome = run(
        vec![point_without_operation(EP_ONE, "api.openai.com")],
        vec![
            call(
                "openai",
                "chat.completions.create",
                "api.openai.com",
                "openai",
            ),
            call("node:https", "post", "api.openai.com", "openai"),
        ],
        LONG_WINDOW,
    );

    assert!(outcome.findings.is_empty(), "{:?}", kinds_of(&outcome));
    assert_eq!(outcome.unlinked_events, 0);
    assert_eq!(outcome.matches.len(), 2);
}

#[test]
fn a_module_name_never_decides_a_match_on_its_own() {
    // Same module on both sides, and nothing else in common. A join keyed on the
    // module would tie these together and report a call that never happened here.
    let outcome = run(
        vec![point(EP_ONE, "api.openai.com", "chat.completions.create")],
        vec![call(
            "openai",
            "messages.create",
            "api.anthropic.com",
            "anthropic",
        )],
        LONG_WINDOW,
    );

    assert!(outcome.matches.is_empty());
    assert_eq!(outcome.unlinked_events, 1);
    assert_eq!(kinds_of(&outcome), [Kind::DormantEgressPoint]);
    // The unattributed call is what keeps the absence from being stated firmly.
    assert_eq!(outcome.findings[0].confidence, Confidence::Suspect);
}

#[test]
fn no_wire_source_means_no_unmatched_traffic_finding() {
    // Milestone 44, the one that decides whether the product's central claim
    // survives contact with a two source run. Whatever else this build derives,
    // it may not say anything about traffic no code explains.
    let outcome = run(
        vec![point(EP_ONE, "api.openai.com", "chat.completions.create")],
        vec![call(
            "openai",
            "chat.completions.create",
            "llm-gateway.internal",
            "unknown",
        )],
        LONG_WINDOW,
    );

    assert!(!kinds_of(&outcome).contains(&Kind::UnmatchedWireTraffic));
    assert!(reasons_for(&outcome, DerivedKind::UnmatchedWireTraffic)
        .contains(&SuppressionReason::WireSourceAbsent));
    assert_eq!(
        outcome.reconciliation_mode,
        periskop_report::coverage::ReconciliationMode::StaticPlusRuntime
    );
}

#[test]
fn three_sources_declare_the_full_mode_and_unlock_the_claim_that_needs_all_three() {
    // Milestone 55. The mode is the report's statement of how much of the
    // product's argument this run is entitled to make, and only a run with all
    // three sources may write `full`.
    let outcome = run_full(
        vec![point(EP_ONE, "api.openai.com", "chat.completions.create")],
        the_declared_call(),
        vec![unexplained(FlowScope::InScope, 54_321)],
        ReconcileSettings::default(),
    );

    assert_eq!(
        outcome.reconciliation_mode,
        periskop_report::coverage::ReconciliationMode::Full
    );
    assert!(reasons_for(&outcome, DerivedKind::UnmatchedWireTraffic).is_empty());
    assert_eq!(kinds_of(&outcome), [Kind::UnmatchedWireTraffic]);
}

#[test]
fn traffic_no_code_and_no_call_explains_is_produced_only_by_a_three_source_run() {
    // The claim that makes the third source worth having, held against every
    // combination of sources. The same traffic, the same absent explanation, and
    // the finding exists in exactly the runs entitled to it.
    let points = vec![point(EP_ONE, "api.openai.com", "chat.completions.create")];
    let flows = vec![unexplained(FlowScope::InScope, 54_321)];

    for wire in [WireSource::Absent, WireSource::Present(flows.clone())] {
        for runtime in [RuntimeSource::Absent, RuntimeSource::Present(vec![])] {
            for declared in [
                DeclaredSource::Absent,
                DeclaredSource::Present(points.clone()),
            ] {
                let entitled = matches!(wire, WireSource::Present(_))
                    && matches!(declared, DeclaredSource::Present(_));
                let outcome = reconcile(&ReconcileInputs::new(
                    Sources::new(declared, runtime.clone(), wire.clone()),
                    LONG_WINDOW,
                ));
                assert_eq!(
                    kinds_of(&outcome).contains(&Kind::UnmatchedWireTraffic),
                    entitled,
                    "{:?}",
                    outcome.suppressed
                );
                // The volume kind needs a declared band as well, and none of
                // these runs has one.
                assert!(!kinds_of(&outcome).contains(&Kind::VolumeAnomaly));
            }
        }
    }
}

#[test]
fn a_two_source_run_states_why_the_wire_claim_is_missing_rather_than_omitting_it() {
    // Milestone 55's critical criterion, from the reader's side: a report that
    // simply lacks the kind is indistinguishable from one that looked and found
    // nothing.
    let outcome = run(
        vec![point(EP_ONE, "api.openai.com", "chat.completions.create")],
        Vec::new(),
        LONG_WINDOW,
    );

    assert_eq!(
        reasons_for(&outcome, DerivedKind::UnmatchedWireTraffic),
        [SuppressionReason::WireSourceAbsent]
    );
    assert!(outcome.wire.is_none(), "{:?}", outcome.wire);
}

#[test]
fn only_the_in_scope_bucket_produces_a_finding_and_the_others_stay_in_the_report() {
    // Milestone 56's non negotiable pair, and K-15's developer machine gate:
    // three buckets produce nothing and not one of them disappears. A bucket
    // that keeps traffic out of the count and then vanishes is a silent swallow,
    // and a wrong out of scope attribution is a silent miss.
    let outcome = run_full(
        vec![point(EP_ONE, "api.openai.com", "chat.completions.create")],
        the_declared_call(),
        vec![
            unexplained(FlowScope::InScope, 54_321),
            unexplained(FlowScope::OutOfScopeProcess, 54_322),
            unexplained(FlowScope::KnownBenign, 54_323),
            unexplained(FlowScope::Undetermined, 54_324),
        ],
        ReconcileSettings::default(),
    );

    assert_eq!(kinds_of(&outcome), [Kind::UnmatchedWireTraffic]);
    let wire = outcome
        .wire
        .expect("a run with a sensor states its buckets");
    assert_eq!(wire.in_scope_flows, 1);
    assert_eq!(wire.out_of_scope_flows, 1);
    assert_eq!(wire.known_benign_flows, 1);
    assert_eq!(wire.unattributed_flows, 1);
    // Every one of the four named a host no signature matched.
    assert_eq!(wire.unclassified_flows, 4);
    assert_eq!(wire.total(), 4);
}

#[test]
fn a_sensor_that_watched_and_saw_nothing_still_states_its_counters() {
    // The distinction the whole source model rests on, on the wire side. Five
    // zeros written by a sensor that ran is a different report from no counters
    // at all, and only the second means nobody was watching.
    let quiet = run_full(
        vec![point(EP_ONE, "api.openai.com", "chat.completions.create")],
        the_declared_call(),
        Vec::new(),
        ReconcileSettings::default(),
    );

    let wire = quiet.wire.expect("the sensor ran");
    assert_eq!(wire.total(), 0);
    assert!(kinds_of(&quiet).is_empty());
}

#[test]
fn a_volume_claim_without_a_declared_band_is_suppressed_rather_than_invented() {
    // Milestone 57. The threshold is a policy input; there is no default, and a
    // run without one derives nothing and says which threshold was missing.
    let flows = vec![connection(
        "api.openai.com",
        "openai",
        FlowScope::InScope,
        54_321,
    )];
    let events = vec![call(
        "openai",
        "chat.completions.create",
        "api.openai.com",
        "openai",
    )];
    let points = vec![point(EP_ONE, "api.openai.com", "chat.completions.create")];

    let without = run_full(
        points.clone(),
        events.clone(),
        flows.clone(),
        ReconcileSettings::default(),
    );
    assert!(!kinds_of(&without).contains(&Kind::VolumeAnomaly));
    assert_eq!(
        reasons_for(&without, DerivedKind::VolumeAnomaly),
        [SuppressionReason::VolumeBandNotDeclared]
    );

    // The same three sources with a band a policy declared. 2048 bytes on the
    // wire against 512 declared is four times, outside a band that admits three.
    let with = run_full(
        points,
        events,
        flows,
        ReconcileSettings::default().with_volume_band(VolumeBand::declared(5_000, 30_000).unwrap()),
    );
    assert!(kinds_of(&with).contains(&Kind::VolumeAnomaly), "{with:?}");
    assert!(reasons_for(&with, DerivedKind::VolumeAnomaly).is_empty());
}

#[test]
fn the_time_tolerance_decides_how_many_findings_a_burst_of_connections_produces() {
    // The J1 time constraint, on the data that carries one. Two connections to
    // the same destination from the same process are one conversation or two
    // depending on the tolerance, and the tolerance is a stated setting rather
    // than a constant buried in a deriver.
    let points = vec![point(EP_ONE, "api.openai.com", "chat.completions.create")];
    let near = unexplained(FlowScope::InScope, 54_321);
    let mut later = unexplained(FlowScope::InScope, 54_322);
    // Ten seconds after the first, on the sensor's one second buckets.
    later.t_start_bucket += 10;

    let narrow = run_full(
        points.clone(),
        the_declared_call(),
        vec![near.clone(), later.clone()],
        ReconcileSettings::default(),
    );
    let wide = run_full(
        points,
        the_declared_call(),
        vec![near, later],
        ReconcileSettings::default().with_join_tolerance_ms(60_000),
    );

    assert_eq!(narrow.findings.len(), 2, "{:?}", narrow.findings);
    assert_eq!(wide.findings.len(), 1, "{:?}", wide.findings);
}

#[test]
fn a_run_with_several_points_reports_each_one_once_and_in_order() {
    // One point called exactly as declared, one whose call went elsewhere, one
    // nothing reached. All three readings come out of a single pass.
    let outcome = run(
        vec![
            point(EP_ONE, "api.openai.com", "chat.completions.create"),
            point_for("anthropic", EP_TWO, "api.anthropic.com", "messages.create"),
            point_for("cohere", EP_THREE, "api.cohere.com", "chat"),
        ],
        vec![
            call(
                "openai",
                "chat.completions.create",
                "api.openai.com",
                "openai",
            ),
            call(
                "anthropic",
                "messages.create",
                "eu.api.anthropic.com",
                "anthropic",
            ),
        ],
        LONG_WINDOW,
    );

    let mut kinds = kinds_of(&outcome);
    kinds.sort();
    assert_eq!(kinds, [Kind::DormantEgressPoint, Kind::TargetDrift]);
    assert_eq!(outcome.unlinked_events, 0);

    // Ordered by identity when the result is built, not when it is written.
    let ids: Vec<&str> = outcome
        .findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);
}

#[test]
fn the_same_inputs_reconcile_to_the_same_bytes_twice() {
    let inputs = || {
        (
            vec![
                point(EP_ONE, "api.openai.com", "chat.completions.create"),
                point(EP_TWO, "api.anthropic.com", "messages.create"),
            ],
            vec![call(
                "openai",
                "chat.completions.create",
                "eu.api.openai.com",
                "openai",
            )],
        )
    };

    let (points, events) = inputs();
    let first = serde_json::to_string(&run(points, events, LONG_WINDOW)).unwrap();
    let (points, events) = inputs();
    let second = serde_json::to_string(&run(points, events, LONG_WINDOW)).unwrap();

    assert_eq!(first, second);
}

#[test]
fn the_order_the_sources_handed_records_over_in_does_not_reach_the_output() {
    let points = vec![
        point(EP_ONE, "api.openai.com", "chat.completions.create"),
        point(EP_TWO, "api.anthropic.com", "messages.create"),
    ];
    let events = vec![
        call(
            "openai",
            "chat.completions.create",
            "eu.api.openai.com",
            "openai",
        ),
        call(
            "anthropic",
            "messages.create",
            "api.anthropic.com",
            "anthropic",
        ),
    ];
    let reversed_points = vec![points[1].clone(), points[0].clone()];
    let reversed_events = vec![events[1].clone(), events[0].clone()];

    let forward = serde_json::to_string(&run(points, events, LONG_WINDOW)).unwrap();
    let backward =
        serde_json::to_string(&run(reversed_points, reversed_events, LONG_WINDOW)).unwrap();

    assert_eq!(forward, backward);
}

#[test]
fn nothing_in_the_result_carries_a_clock_or_a_machine_path() {
    let outcome = run(
        vec![
            point(EP_ONE, "api.openai.com", "chat.completions.create"),
            point(EP_TWO, "api.anthropic.com", "messages.create"),
        ],
        vec![call(
            "openai",
            "chat.completions.create",
            "eu.api.openai.com",
            "openai",
        )],
        LONG_WINDOW,
    );

    let json = serde_json::to_value(&outcome).unwrap();
    let mut keys = Vec::new();
    let mut values = Vec::new();
    walk(&json, &mut keys, &mut values);

    for key in &keys {
        for banned in ["timestamp", "generated_at", "_at", "clock", "epoch"] {
            assert!(!key.contains(banned), "{key} carries a clock value");
        }
    }
    for value in &values {
        assert!(!value.starts_with('/'), "{value} is an absolute path");
        assert!(
            !value.contains(":\\") && !value.contains("C:/"),
            "{value} is an absolute path"
        );
    }
}

// The three cases below are escapes: known, reproducible, and not fixed here.
// They are written as tests rather than left in a document because a gap nobody
// can run is a gap nobody notices has widened. Each one pins the behaviour this
// build actually has, so a later change to it is visible as a failing test
// rather than as a silent change of meaning.

#[test]
fn escape_a_drift_with_nothing_to_join_on_reads_as_dormancy() {
    // The code names a destination but no operation, and the call reached a
    // gateway that classifies as nothing. No rung of the ladder connects them,
    // so the drift is missed and the point is reported as never called. The fix
    // is on the static side: a declared operation would put this pair on the
    // operation rung. Filed in hub/memory/interfaces.md.
    let outcome = run(
        vec![point_without_operation(EP_ONE, "api.openai.com")],
        vec![call("httpx", "post", "llm-gateway.internal", "unknown")],
        LONG_WINDOW,
    );

    assert_eq!(kinds_of(&outcome), [Kind::DormantEgressPoint]);
    // What keeps this from being a confident false claim: the call nobody could
    // attribute leaves the absence merely suspected.
    assert_eq!(outcome.findings[0].confidence, Confidence::Suspect);
    assert_eq!(outcome.unlinked_events, 1);
}

#[test]
fn escape_an_internationalised_host_is_not_folded_to_punycode() {
    // Normalisation lower cases and trims, and it stops there: converting a name
    // to punycode needs a table this workspace does not carry, and approximating
    // it would fold destinations that are genuinely different. The cost is here:
    // two spellings of one host read as a drift.
    let outcome = run(
        vec![point(
            EP_ONE,
            "api.öpenai.example",
            "chat.completions.create",
        )],
        vec![call(
            "openai",
            "chat.completions.create",
            "api.xn--penai-9ua.example",
            "openai",
        )],
        LONG_WINDOW,
    );

    assert_eq!(kinds_of(&outcome), [Kind::TargetDrift]);
}

#[test]
fn a_provider_level_match_neither_silences_a_dormant_point_nor_accuses_it() {
    // Two call sites reaching one provider, and one call that went to neither of
    // the destinations either of them named and invoked neither of the
    // operations either of them invokes. The only thing joining that call to
    // either line is the vendor name.
    //
    // This test used to record the opposite of what it records now, filed as a
    // deliberate under claim, and it was the clearest evidence that the rule was
    // wrong: the same weakest rung was silencing every dormancy finding in the
    // repository and manufacturing a drift for every point it silenced. Neither
    // reading survives contact with a real code base, where every call site for
    // one vendor shares its provider with every other.
    let outcome = run(
        vec![
            point(EP_ONE, "api.openai.com", "chat.completions.create"),
            point(EP_TWO, "api.openai.com", "embeddings.create"),
        ],
        vec![call(
            "openai",
            "images.generate",
            "eu.api.openai.com",
            "openai",
        )],
        LONG_WINDOW,
    );

    // Neither line was seen to run, so both are reported, and neither is
    // reported firmly: a call to their vendor was seen and either could have
    // made it.
    assert_eq!(
        kinds_of(&outcome),
        [Kind::DormantEgressPoint, Kind::DormantEgressPoint]
    );
    assert!(outcome
        .findings
        .iter()
        .all(|finding| finding.confidence == Confidence::Suspect));
    // The link is still established and still visible; what changed is what may
    // be concluded from it.
    assert_eq!(outcome.matches.len(), 2);
    assert_eq!(outcome.unlinked_events, 0);
}

fn walk(value: &serde_json::Value, keys: &mut Vec<String>, strings: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                keys.push(key.clone());
                walk(child, keys, strings);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                walk(child, keys, strings);
            }
        }
        serde_json::Value::String(text) => strings.push(text.clone()),
        _ => {}
    }
}
