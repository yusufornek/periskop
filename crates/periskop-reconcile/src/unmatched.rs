//! `unmatched_wire_traffic`: data left the machine and no code explains it.
//!
//! This is the finding the product exists for. The static scanner reads what the
//! code can reach, the hooks record what it did reach, and neither of them can
//! see a connection that came from somewhere else; only the third source can,
//! and only by disagreeing with the other two. Nothing here is derivable from
//! any single source, which is why the whole crate is shaped around never
//! claiming it without all the evidence.
//!
//! Three rules bound it, and each one exists because breaking it would make the
//! finding worthless in a different way.
//!
//! **Only the `in_scope` bucket produces it** (`reconciliation/spec.md` §5.0.1,
//! K-15). The other three buckets hold traffic from processes that are not the
//! codebase under scan: the developer's editor assistant, an operating system
//! service, a connection nobody could attribute. Reporting those would drown the
//! real finding on the machine where the tool is most often run. They are still
//! counted and still shown, in [`crate::wire::WireCoverage`], because a bucket
//! that keeps flows out of the count and then vanishes from the report is a
//! silent swallow, and a wrong `out_of_scope` attribution is a silent miss,
//! which is worse than a wrong `in_scope` one.
//!
//! **A destination the code already names is not unexplained.** Traffic to a
//! provider the repository declares somewhere is traffic the code accounts for,
//! even when no hook watched the call. That is the J3 rung, and it never
//! produces confidence of its own; here it only silences.
//!
//! **A run with no hooks may not state the finding firmly.** Without the
//! runtime source, "no application call explains this" means "nobody was
//! listening for one", so the claim is stated as suspected and the coverage
//! impact says which gap produced it (`data-model.md` §3).

use periskop_core::finding::{Confidence, CoverageImpact, Finding, Kind};

use crate::declared::DeclaredPoint;
use crate::emit;
use crate::j1::J1Result;
use crate::settings::ReconcileSettings;
use crate::wire::WireEpisode;

pub(crate) const RULE_ID: &str = "any.reconciled.unmatched-wire-traffic";

/// The reverse list value, which is a classification result and never a name.
const UNKNOWN_PROVIDER: &str = "unknown";

#[derive(Debug, Default)]
pub(crate) struct Derived {
    pub findings: Vec<Finding>,
    pub faults: Vec<String>,
}

/// Derives one finding per stretch of traffic nothing in the run accounts for.
pub(crate) fn derive(
    episodes: &[WireEpisode],
    j1: &J1Result,
    points: &[DeclaredPoint],
    runtime_watched: bool,
    settings: &ReconcileSettings,
) -> Derived {
    let mut derived = Derived::default();

    for episode in episodes {
        if !episode.counts_toward_findings() {
            continue;
        }
        if !j1.is_unmatched(&episode.flow_id) {
            continue;
        }
        // Not a fault and not a finding: the code accounts for this
        // destination, which is the answer the reader wanted.
        if code_explains(episode, points) {
            continue;
        }

        let evidence = emit::join_evidence(format!(
            "J1:none J3:none flow_scope={} target={} provider={} classification={} \
             attribution={} flows={} span_ms={} bytes_out={} tolerance_ms={} \
             runtime_source={}",
            episode.scope.as_str(),
            episode.target,
            episode.provider_ref,
            classification_of(episode),
            attribution_of(episode),
            episode.flow_count(),
            episode.interval.span_ms(),
            episode
                .bytes_out
                .map_or_else(|| "not_counted".to_owned(), |bytes| bytes.to_string()),
            settings.effective_join_tolerance_ms(),
            if runtime_watched { "present" } else { "absent" },
        ));

        match emit::derived_finding_anchored(
            Kind::UnmatchedWireTraffic,
            confidence_for(episode, runtime_watched),
            &episode.provider_ref,
            emit::flow_ref(&episode.flow_id),
            evidence,
            settings,
            RULE_ID,
        ) {
            Ok(finding) => {
                let mut finding = finding.with_coverage_impact(if runtime_watched {
                    CoverageImpact::None
                } else {
                    // The traffic may well have had an application call behind
                    // it that nothing was there to record. That is a gap in
                    // coverage, and the finding says so rather than implying the
                    // process was silent.
                    CoverageImpact::UnhookedProcess
                });
                emit::attach_flow_refs(&mut finding, &episode.flow_ids);
                derived.findings.push(finding);
            }
            // The episode already carries a contract shaped flow identity, so
            // this is the engine disagreeing with itself rather than bad input.
            // Naming it is the only alternative to dropping traffic out of the
            // report with nothing to show it was ever seen.
            Err(error) => derived.faults.push(format!(
                "unmatched wire derivation could not build a finding for {}: {error}",
                episode.flow_id
            )),
        }
    }

    derived
}

/// How firmly the claim may be stated.
///
/// Confirmed needs both halves of the argument. Something had to be listening
/// for application calls, or "no call explains this" is a statement about the
/// tool rather than about the machine. And the destination has to have a name,
/// because a claim about traffic to a bare address is one a reader cannot check
/// and cannot act on.
fn confidence_for(episode: &WireEpisode, runtime_watched: bool) -> Confidence {
    if runtime_watched && episode.named {
        Confidence::Confirmed
    } else {
        Confidence::Suspect
    }
}

/// Whether any code point accounts for this destination.
///
/// Two rungs, both weak by construction and both only ever used to silence.
/// Naming the same destination is the stronger one. Naming the same provider is
/// `data-model.md`'s J3, which may never produce a confirmed claim; it is
/// admitted here because the finding it would silence is an accusation, and the
/// bar for accusing is higher than the bar for staying quiet.
fn code_explains(episode: &WireEpisode, points: &[DeclaredPoint]) -> bool {
    points.iter().any(|point| {
        point.target() == Some(&episode.target)
            || (episode.provider_ref != UNKNOWN_PROVIDER
                && point.provider_ref() == episode.provider_ref)
    })
}

fn classification_of(episode: &WireEpisode) -> &'static str {
    use periskop_network_sensor::flow::Classification;
    match episode.classification {
        Classification::Classified => "classified",
        Classification::Unclassified => "unclassified",
        Classification::Opaque => "opaque",
    }
}

fn attribution_of(episode: &WireEpisode) -> &'static str {
    use periskop_network_sensor::flow::ProcessAttribution;
    match episode.attribution {
        ProcessAttribution::KernelAttributed => "kernel_attributed",
        ProcessAttribution::Inferred => "inferred",
        ProcessAttribution::Unattributed => "unattributed",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::declared::tests::{point, unresolved_point};
    use crate::j1;
    use crate::join::tests::event;
    use crate::wire::episodes;
    use crate::wire::tests::{flow, named_flow, opaque_flow, TOLERANCE_MS};
    use periskop_network_sensor::scope::FlowScope;
    use periskop_network_sensor::Flow;
    use periskop_runtime_collector::EgressEvent;

    const EP: &str = "ep_3f0a91c7d4e28b56";
    const BUCKET: u64 = 1_785_834_000;

    fn derive_with(
        flows: &[Flow],
        events: &[EgressEvent],
        points: &[DeclaredPoint],
        runtime_watched: bool,
    ) -> Derived {
        let (episodes, _) = episodes(flows, TOLERANCE_MS);
        let j1 = j1::join(&episodes, events);
        derive(
            &episodes,
            &j1,
            points,
            runtime_watched,
            &ReconcileSettings::default(),
        )
    }

    fn evidence_of(derived: &Derived) -> String {
        derived.findings[0]
            .evidence
            .iter()
            .map(|piece| piece.r#ref.clone())
            .collect::<Vec<_>>()
            .join(" | ")
    }

    #[test]
    fn traffic_no_code_and_no_call_explains_is_the_finding_this_phase_exists_for() {
        // A process from the codebase reached a destination the repository never
        // mentions, and nothing the hooks recorded went there. Neither of the
        // other two sources could have said this.
        let flows = [named_flow(
            "telemetry.vendor.example",
            "unknown",
            BUCKET,
            FlowScope::InScope,
            54_321,
        )];
        let events = [event(
            "openai",
            "chat.completions.create",
            "api.openai.com",
            "openai",
        )];
        let points = [point(EP, "api.openai.com", "chat.completions.create")];
        let derived = derive_with(&flows, &events, &points, true);

        assert_eq!(derived.findings.len(), 1, "{:?}", derived.faults);
        assert_eq!(derived.findings[0].kind, Kind::UnmatchedWireTraffic);
        assert_eq!(derived.findings[0].confidence, Confidence::Confirmed);
        assert_eq!(
            derived.findings[0].source,
            periskop_core::finding::Source::Reconciled
        );
        let evidence = evidence_of(&derived);
        assert!(
            evidence.contains("target=telemetry.vendor.example"),
            "{evidence}"
        );
        assert!(evidence.contains("flow_scope=in_scope"), "{evidence}");
        assert!(evidence.contains("bytes_out=2048"), "{evidence}");
        assert!(derived.faults.is_empty());
    }

    #[test]
    fn traffic_a_watched_call_explains_produces_nothing() {
        let flows = [flow("api.openai.com", BUCKET, FlowScope::InScope)];
        let events = [event(
            "openai",
            "chat.completions.create",
            "api.openai.com",
            "openai",
        )];
        let points = [point(EP, "api.openai.com", "chat.completions.create")];

        assert!(derive_with(&flows, &events, &points, true)
            .findings
            .is_empty());
    }

    #[test]
    fn traffic_the_code_names_produces_nothing_even_with_no_call_behind_it() {
        // The repository declares this destination. Nothing was watched calling
        // it, which is a dormancy question rather than unexplained traffic.
        let flows = [flow("api.openai.com", BUCKET, FlowScope::InScope)];
        let points = [point(EP, "api.openai.com", "chat.completions.create")];

        assert!(derive_with(&flows, &[], &points, true).findings.is_empty());
    }

    #[test]
    fn traffic_to_a_provider_the_code_uses_elsewhere_produces_nothing() {
        // The J3 rung. The repository uses this vendor, so the vendor's regional
        // endpoint is not traffic nobody can account for, and accusing on a
        // provider level tie is exactly what the ladder forbids.
        let flows = [named_flow(
            "eu.api.openai.com",
            "openai",
            BUCKET,
            FlowScope::InScope,
            54_321,
        )];
        let points = [unresolved_point(EP, "openai")];

        assert!(derive_with(&flows, &[], &points, true).findings.is_empty());
    }

    #[test]
    fn not_one_of_the_three_quiet_buckets_produces_a_finding() {
        // The non negotiable constraint of milestone 56. The same traffic, the
        // same absent explanation, three buckets, no findings.
        for quiet in [
            FlowScope::OutOfScopeProcess,
            FlowScope::KnownBenign,
            FlowScope::Undetermined,
        ] {
            let flows = [named_flow(
                "telemetry.vendor.example",
                "unknown",
                BUCKET,
                quiet,
                54_321,
            )];
            let derived = derive_with(&flows, &[], &[], true);
            assert!(
                derived.findings.is_empty(),
                "{quiet:?} produced a finding: {:?}",
                derived.findings
            );
        }
    }

    #[test]
    fn a_run_with_no_hooks_states_the_claim_as_suspected_and_says_which_gap() {
        // Without the runtime source "no call explains this" is a statement
        // about the tool. The finding still appears, because the traffic did.
        let flows = [named_flow(
            "telemetry.vendor.example",
            "unknown",
            BUCKET,
            FlowScope::InScope,
            54_321,
        )];
        let derived = derive_with(&flows, &[], &[], false);

        assert_eq!(derived.findings.len(), 1);
        assert_eq!(derived.findings[0].confidence, Confidence::Suspect);
        assert_eq!(
            derived.findings[0].coverage_impact,
            Some(CoverageImpact::UnhookedProcess)
        );
    }

    #[test]
    fn traffic_to_a_bare_address_is_reported_and_never_stated_as_certain() {
        // The destination nobody could name is the one most worth reporting and
        // the one a reader can check least.
        let flows = [opaque_flow("10.2.3.4", BUCKET, FlowScope::InScope)];
        let derived = derive_with(&flows, &[], &[], true);

        assert_eq!(derived.findings.len(), 1);
        assert_eq!(derived.findings[0].confidence, Confidence::Suspect);
        assert!(evidence_of(&derived).contains("classification=opaque"));
    }

    #[test]
    fn a_burst_of_connections_to_one_destination_is_one_finding() {
        // Spec §6: a thousand connections to one place is one fact, with the
        // count and the volume summarised.
        let flows = [
            named_flow(
                "telemetry.vendor.example",
                "unknown",
                BUCKET,
                FlowScope::InScope,
                54_321,
            ),
            named_flow(
                "telemetry.vendor.example",
                "unknown",
                BUCKET,
                FlowScope::InScope,
                54_322,
            ),
            named_flow(
                "telemetry.vendor.example",
                "unknown",
                BUCKET,
                FlowScope::InScope,
                54_323,
            ),
        ];
        let derived = derive_with(&flows, &[], &[], true);

        assert_eq!(derived.findings.len(), 1);
        assert_eq!(derived.findings[0].refs.len(), 3);
        let evidence = evidence_of(&derived);
        assert!(evidence.contains("flows=3"), "{evidence}");
        assert!(evidence.contains("bytes_out=6144"), "{evidence}");
    }

    #[test]
    fn the_finding_does_not_depend_on_the_order_the_records_arrived_in() {
        let one = named_flow(
            "telemetry.vendor.example",
            "unknown",
            BUCKET,
            FlowScope::InScope,
            54_321,
        );
        let other = named_flow(
            "analytics.vendor.example",
            "unknown",
            BUCKET,
            FlowScope::InScope,
            54_322,
        );

        let forward = derive_with(&[one.clone(), other.clone()], &[], &[], true);
        let backward = derive_with(&[other, one], &[], &[], true);

        assert_eq!(forward.findings.len(), 2);
        assert_eq!(forward.findings, backward.findings);
    }

    #[test]
    fn no_absolute_clock_value_reaches_the_evidence() {
        // Spec §8 rule 4: the same recorded traffic reconciled tomorrow has to
        // produce the same bytes, so only spans travel, never stamps.
        let flows = [named_flow(
            "telemetry.vendor.example",
            "unknown",
            BUCKET,
            FlowScope::InScope,
            54_321,
        )];
        let evidence = evidence_of(&derive_with(&flows, &[], &[], true));

        assert!(!evidence.contains(&BUCKET.to_string()), "{evidence}");
        assert!(evidence.contains("span_ms=120"), "{evidence}");
    }
}
