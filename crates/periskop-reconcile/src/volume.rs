//! `volume_anomaly`: more, or less, left the machine than the calls declared.
//!
//! The comparison is between two numbers written by two sources that never see
//! each other. A hook records how large a request body it was handed; the sensor
//! counts the bytes that went out of the socket. They are never equal, because
//! TLS records, headers and retransmissions sit between them, so the finding
//! rests on a band rather than on equality.
//!
//! **Where the band comes from is the whole point of the task.** It is declared
//! by policy and carried in the settings; there is no default, and a run without
//! one derives nothing and says so ([`crate::capability`]). The alternative was
//! a number invented here, and an invented threshold is worse than no finding:
//! a batch job and a chat endpoint disagree about what a normal ratio is by
//! orders of magnitude, so any constant would be wrong for most users while
//! looking authoritative in every report.
//!
//! The arithmetic is integer throughout (`reconciliation/spec.md` §8 rule 6).
//! A float ratio would make two platforms disagree about whether a run has a
//! finding in it.
//!
//! This finding never sees content. It says an unusual amount of something left,
//! not what left.

use periskop_core::finding::{Confidence, CoverageImpact, Finding, Kind};

use crate::emit;
use crate::j1::{J1Result, MatchQuality};
use crate::settings::{ReconcileSettings, VolumeBand};
use crate::wire::WireEpisode;

use periskop_runtime_collector::event::EgressEvent;

pub(crate) const RULE_ID: &str = "any.reconciled.volume-anomaly";

#[derive(Debug, Default)]
pub(crate) struct Derived {
    pub findings: Vec<Finding>,
    pub faults: Vec<String>,
}

/// Derives one finding per stretch of traffic whose volume the calls do not
/// account for.
///
/// `band` is taken as an argument rather than read from the settings inside the
/// loop, because a caller that reached this function without one has a bug: the
/// capability table is what decides whether this deriver runs at all, and taking
/// the value here makes that ordering a compile time fact instead of a
/// convention.
pub(crate) fn derive(
    episodes: &[WireEpisode],
    j1: &J1Result,
    events: &[EgressEvent],
    band: VolumeBand,
    settings: &ReconcileSettings,
) -> Derived {
    let mut derived = Derived::default();

    for episode in episodes {
        if !episode.counts_toward_findings() {
            continue;
        }
        let Some(quality) = j1.quality_for(&episode.flow_id) else {
            // No call was tied to this connection, so there is nothing to
            // compare its volume against. That absence is the other finding's
            // business, not this one's.
            continue;
        };
        // A connection whose bytes nothing counted is not a connection that
        // carried none. Reading the absence as zero would make every such
        // record an anomaly against any declared payload.
        let Some(observed) = episode.bytes_out else {
            continue;
        };
        let expected = declared_bytes(episode, j1, events);
        // Nothing was declared to be sent, so there is no band: every positive
        // byte count would sit outside a band anchored on zero, and the reason
        // would be that the hook could not size the payload rather than that
        // anything unusual happened.
        if expected == 0 {
            continue;
        }
        if band.admits(observed, expected) {
            continue;
        }

        // The tied calls are named in the evidence rather than added to `refs`.
        // The contract sorts references by type and reads the identity off the
        // first one, so an event reference on a finding anchored on a connection
        // would take the primary position and contradict the identity already
        // derived from the flow.
        let calls: Vec<&str> = j1
            .matches_for(&episode.flow_id)
            .map(|matched| matched.egress_event_id.as_str())
            .collect();
        let evidence = emit::join_evidence(format!(
            "J1:{} target={} expected_bytes={expected} observed_bytes={observed} \
             band_bytes={}..{} band_basis_points={}..{} flows={} calls={}",
            quality.as_str(),
            episode.target,
            band.low(expected),
            band.high(expected),
            band.min_basis_points(),
            band.max_basis_points(),
            episode.flow_count(),
            calls.join(","),
        ));

        match emit::derived_finding_anchored(
            Kind::VolumeAnomaly,
            confidence_for(quality),
            &episode.provider_ref,
            emit::flow_ref(&episode.flow_id),
            evidence,
            settings,
            RULE_ID,
        ) {
            Ok(finding) => {
                let mut finding = finding.with_coverage_impact(CoverageImpact::None);
                emit::attach_flow_refs(&mut finding, &episode.flow_ids);
                derived.findings.push(finding);
            }
            Err(error) => derived.faults.push(format!(
                "volume derivation could not build a finding for {}: {error}",
                episode.flow_id
            )),
        }
    }

    derived
}

/// How much the calls tied to this connection said they were sending.
///
/// Summed over every tied call, because keep alive puts many requests on one
/// connection and comparing the socket's total against one of them would report
/// every reused connection as an anomaly.
fn declared_bytes(episode: &WireEpisode, j1: &J1Result, events: &[EgressEvent]) -> u64 {
    j1.matches_for(&episode.flow_id)
        .filter_map(|matched| {
            events
                .iter()
                .find(|event| event.egress_event_id == matched.egress_event_id)
        })
        .fold(0u64, |total, event| {
            total.saturating_add(event.payload_shape.byte_size_estimate)
        })
}

/// How firmly the claim may be stated.
///
/// An ambiguous link means more than one call could have travelled here, or the
/// destination was only an address, or the owning process was inferred. In every
/// one of those the expected total may belong to a different conversation, so
/// the difference is a suspicion rather than a measurement.
fn confidence_for(quality: MatchQuality) -> Confidence {
    match quality {
        MatchQuality::Exact => Confidence::Confirmed,
        MatchQuality::Ambiguous => Confidence::Suspect,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::j1;
    use crate::join::tests::event;
    use crate::wire::episodes;
    use crate::wire::tests::{flow, named_flow, TOLERANCE_MS};
    use periskop_network_sensor::scope::FlowScope;
    use periskop_network_sensor::Flow;

    const BUCKET: u64 = 1_785_834_000;

    /// Half to three times the declared payload, which admits the ordinary TLS
    /// and header overhead and refuses an order of magnitude.
    fn band() -> VolumeBand {
        VolumeBand::declared(5_000, 30_000).unwrap()
    }

    fn derive_with(flows: &[Flow], events: &[EgressEvent], band: VolumeBand) -> Derived {
        let (episodes, _) = episodes(flows, TOLERANCE_MS);
        let j1 = j1::join(&episodes, events);
        derive(
            &episodes,
            &j1,
            events,
            band,
            &ReconcileSettings::default().with_volume_band(band),
        )
    }

    /// A call declaring a payload of the given size.
    fn call_of(bytes: u64) -> EgressEvent {
        call_to("api.openai.com", "chat.completions.create", bytes)
    }

    /// The same, with the destination and the operation stated.
    ///
    /// The operation is a constructor argument rather than a field to assign
    /// afterwards, because the event identity is derived when the record is
    /// built: two records differing only in a field written later would carry
    /// one identity and be read as one call.
    fn call_to(host: &str, operation: &str, bytes: u64) -> EgressEvent {
        let mut call = event("openai", operation, host, "openai");
        call.payload_shape.byte_size_estimate = bytes;
        call
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
    fn far_more_on_the_wire_than_the_call_declared_is_an_anomaly() {
        // The connection carried 2048 bytes and the call said it was sending
        // 100. Three times the payload is the declared ceiling.
        let flows = [flow("api.openai.com", BUCKET, FlowScope::InScope)];
        let derived = derive_with(&flows, &[call_of(100)], band());

        assert_eq!(derived.findings.len(), 1, "{:?}", derived.faults);
        assert_eq!(derived.findings[0].kind, Kind::VolumeAnomaly);
        assert_eq!(derived.findings[0].confidence, Confidence::Confirmed);
        let evidence = evidence_of(&derived);
        assert!(evidence.contains("expected_bytes=100"), "{evidence}");
        assert!(evidence.contains("observed_bytes=2048"), "{evidence}");
        assert!(evidence.contains("band_bytes=50..300"), "{evidence}");
    }

    #[test]
    fn far_less_on_the_wire_than_the_call_declared_is_an_anomaly_too() {
        // The more interesting direction: the application believes it sent
        // something the wire never carried.
        let flows = [flow("api.openai.com", BUCKET, FlowScope::InScope)];
        let derived = derive_with(&flows, &[call_of(100_000)], band());

        assert_eq!(derived.findings.len(), 1);
        assert!(evidence_of(&derived).contains("observed_bytes=2048"));
    }

    #[test]
    fn a_volume_inside_the_band_produces_nothing() {
        let flows = [flow("api.openai.com", BUCKET, FlowScope::InScope)];
        assert!(derive_with(&flows, &[call_of(1_024)], band())
            .findings
            .is_empty());
    }

    #[test]
    fn a_wider_band_admits_what_a_narrow_one_refused() {
        // The threshold is a policy input and the whole result turns on it.
        let flows = [flow("api.openai.com", BUCKET, FlowScope::InScope)];
        let events = [call_of(100)];

        assert_eq!(derive_with(&flows, &events, band()).findings.len(), 1);
        assert!(
            derive_with(&flows, &events, VolumeBand::declared(1, 1_000_000).unwrap())
                .findings
                .is_empty()
        );
    }

    #[test]
    fn every_call_on_a_reused_connection_counts_towards_what_was_expected() {
        // Keep alive puts several requests on one socket. Comparing the socket
        // total against a single request would report every reused connection.
        let flows = [flow("api.openai.com", BUCKET, FlowScope::InScope)];
        let events = [call_of(700), call_of(700), call_of(700)];
        let derived = derive_with(&flows, &events, band());

        assert!(derived.findings.is_empty(), "{:?}", derived.findings);
    }

    #[test]
    fn a_link_that_could_belong_to_another_call_is_only_ever_suspected() {
        // Two different calls to one destination: either of them could have
        // travelled over this connection, so the expected total may belong to a
        // conversation this connection never carried.
        let flows = [flow("api.openai.com", BUCKET, FlowScope::InScope)];
        let events = [
            call_of(10),
            call_to("api.openai.com", "embeddings.create", 10),
        ];
        let derived = derive_with(&flows, &events, band());

        assert_eq!(derived.findings.len(), 1);
        assert_eq!(derived.findings[0].confidence, Confidence::Suspect);
        assert!(evidence_of(&derived).contains("J1:ambiguous"));
    }

    #[test]
    fn a_connection_no_call_reached_has_no_volume_to_compare() {
        // That absence is the unmatched traffic finding's business. Reporting it
        // here too would state one fact twice under two names.
        let flows = [named_flow(
            "telemetry.vendor.example",
            "unknown",
            BUCKET,
            FlowScope::InScope,
            54_321,
        )];
        assert!(derive_with(&flows, &[], band()).findings.is_empty());
    }

    #[test]
    fn a_connection_whose_bytes_nothing_counted_produces_nothing() {
        // Absent is not zero. Reading it as zero would make every uncounted
        // record an anomaly against any declared payload.
        let mut uncounted = flow("api.openai.com", BUCKET, FlowScope::InScope);
        uncounted.bytes_out = None;
        assert!(derive_with(&[uncounted], &[call_of(100)], band())
            .findings
            .is_empty());
    }

    #[test]
    fn a_call_that_declared_no_payload_size_anchors_no_band() {
        // A band anchored on zero admits only zero, so every byte would be an
        // anomaly and the reason would be that the hook could not size the
        // payload.
        let flows = [flow("api.openai.com", BUCKET, FlowScope::InScope)];
        assert!(derive_with(&flows, &[call_of(0)], band())
            .findings
            .is_empty());
    }

    #[test]
    fn the_three_quiet_buckets_produce_no_volume_finding_either() {
        for quiet in [
            FlowScope::OutOfScopeProcess,
            FlowScope::KnownBenign,
            FlowScope::Undetermined,
        ] {
            let flows = [named_flow(
                "api.openai.com",
                "openai",
                BUCKET,
                quiet,
                54_321,
            )];
            let derived = derive_with(&flows, &[call_of(1)], band());
            assert!(
                derived.findings.is_empty(),
                "{quiet:?}: {:?}",
                derived.findings
            );
        }
    }

    #[test]
    fn the_finding_does_not_depend_on_the_order_the_records_arrived_in() {
        let one = flow("api.openai.com", BUCKET, FlowScope::InScope);
        let other = named_flow(
            "api.anthropic.com",
            "anthropic",
            BUCKET,
            FlowScope::InScope,
            54_999,
        );
        let call = call_of(1);
        let anthropic = {
            let mut call = event(
                "anthropic",
                "messages.create",
                "api.anthropic.com",
                "anthropic",
            );
            call.payload_shape.byte_size_estimate = 1;
            call
        };

        let forward = derive_with(
            &[one.clone(), other.clone()],
            &[call.clone(), anthropic.clone()],
            band(),
        );
        let backward = derive_with(&[other, one], &[anthropic, call], band());

        assert_eq!(forward.findings.len(), 2);
        assert_eq!(forward.findings, backward.findings);
    }
}
