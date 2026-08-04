//! The third source: what actually left the machine.
//!
//! This module turns a list of `Flow` records into the shape the derivers
//! compare against, and it makes two decisions on the way that both change which
//! findings exist.
//!
//! The first is grouping. A single conversation with one destination is many
//! connections: a client reconnects, a pool opens a second socket, keep alive
//! closes one and opens another. `reconciliation/spec.md` §6 asks for exactly
//! one finding out of that, and the alternative is a report with four hundred
//! copies of one fact. Connections to the same destination from the same process
//! are therefore collected into an episode, and the tolerance decides where one
//! episode ends and the next begins.
//!
//! The second is what a destination is. A flow names one when DNS or the
//! handshake produced a name; when neither did, the address is all there is.
//! Both are carried, and which of the two a record has is kept, because a claim
//! about traffic to a name a reader can check is worth more than one about a
//! bare address.
//!
//! Nothing here counts as a finding. The three buckets that produce none are
//! still counted, in [`WireCoverage`], for the reason `flow_scope` exists at
//! all: a bucket that keeps flows out of the count and then disappears from the
//! report is a silent swallow (K-15).

use serde::Serialize;

use periskop_network_sensor::flow::{Classification, Flow, ProcessAttribution};
use periskop_network_sensor::scope::FlowScope;

use crate::target::TargetId;

/// Which process a flow came from, as far as the record states it.
///
/// The start time is part of the identity rather than decoration: a pid is
/// reused, and over an hour long observation two unrelated processes can carry
/// the same one. Two flows are only the same conversation if the process behind
/// them is the same process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub pid_start_time: Option<u64>,
}

/// When a connection was open, in milliseconds on the machine's own clock.
///
/// Absolute, and it never leaves this crate as an absolute value: only spans and
/// gaps derived from it reach a finding. `reconciliation/spec.md` §8 rule 4 is
/// the reason. A stamp in the evidence would make the same recorded flows
/// reconcile to different bytes tomorrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Interval {
    start_ms: u64,
    end_ms: u64,
}

impl Interval {
    /// Reads the interval a flow record states.
    ///
    /// The start is a one second bucket by contract, so it is scaled rather than
    /// used raw. An absent duration means the end was not observed, which is a
    /// fact and not a zero; the interval is then the instant the connection was
    /// first seen, and the tolerance is what decides whether anything joins onto
    /// it.
    pub fn of_flow(t_start_bucket: u64, duration_ms: Option<u64>) -> Self {
        let start_ms = t_start_bucket.saturating_mul(1_000);
        Self {
            start_ms,
            end_ms: start_ms.saturating_add(duration_ms.unwrap_or(0)),
        }
    }

    pub fn span_ms(self) -> u64 {
        self.end_ms.saturating_sub(self.start_ms)
    }

    /// The distance between two intervals, zero when they overlap.
    pub fn gap_ms(self, other: Self) -> u64 {
        if self.start_ms > other.end_ms {
            return self.start_ms - other.end_ms;
        }
        if other.start_ms > self.end_ms {
            return other.start_ms - self.end_ms;
        }
        0
    }

    /// Whether two intervals are close enough to describe one exchange.
    pub fn within(self, other: Self, tolerance_ms: u64) -> bool {
        self.gap_ms(other) <= tolerance_ms
    }

    /// The interval covering both.
    fn joined(self, other: Self) -> Self {
        Self {
            start_ms: self.start_ms.min(other.start_ms),
            end_ms: self.end_ms.max(other.end_ms),
        }
    }
}

/// One destination, reached by one process, over one stretch of time.
///
/// Fields are crate visible rather than accessor wrapped because every reader is
/// in this crate and each one needs most of them; a getter per field would be
/// eleven functions that say nothing the field name does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireEpisode {
    /// The identity a finding derived from this episode is anchored on.
    ///
    /// The lowest flow identity in the episode, so a report does not change
    /// because the sensor handed its records over in another order.
    pub(crate) flow_id: String,
    pub(crate) flow_ids: Vec<String>,
    pub(crate) target: TargetId,
    /// Whether the destination is a name or only an address.
    pub(crate) named: bool,
    pub(crate) provider_ref: String,
    pub(crate) classification: Classification,
    pub(crate) scope: FlowScope,
    pub(crate) attribution: ProcessAttribution,
    pub(crate) process: Option<ProcessIdentity>,
    pub(crate) interval: Interval,
    /// Total outbound bytes, and whether any record stated one at all. A run
    /// where no mechanism could count bytes must not read as a run that sent
    /// none.
    pub(crate) bytes_out: Option<u64>,
}

impl WireEpisode {
    fn of_flow(flow: &Flow) -> Option<Self> {
        let (target, named) = target_of(flow)?;
        Some(Self {
            flow_id: flow.flow_id.clone(),
            flow_ids: vec![flow.flow_id.clone()],
            target,
            named,
            provider_ref: flow
                .provider_ref
                .clone()
                .unwrap_or_else(|| periskop_network_sensor::flow::UNKNOWN_PROVIDER.to_owned()),
            classification: flow.classification,
            scope: flow.flow_scope,
            attribution: flow.process_attribution,
            process: flow.process.as_ref().map(|process| ProcessIdentity {
                pid: process.pid,
                pid_start_time: process.pid_start_time,
            }),
            interval: Interval::of_flow(flow.t_start_bucket, flow.duration_ms),
            bytes_out: flow.bytes_out,
        })
    }

    /// Whether two records describe the same conversation.
    ///
    /// The bucket is the pair the contract joins on: the destination and the
    /// process. The scope travels with the process, so two flows that agree on
    /// the process agree on the bucket as well; it is compared anyway, because a
    /// record read back was written by a build that is not this one and an
    /// episode that mixed buckets would produce a finding from traffic the
    /// operator declared out of scope.
    fn same_conversation(&self, other: &Self) -> bool {
        self.target == other.target
            && self.process == other.process
            && self.scope == other.scope
            && self.attribution == other.attribution
    }

    fn absorb(&mut self, other: Self) {
        self.flow_ids.extend(other.flow_ids);
        self.interval = self.interval.joined(other.interval);
        self.bytes_out = match (self.bytes_out, other.bytes_out) {
            (Some(left), Some(right)) => Some(left.saturating_add(right)),
            (Some(left), None) => Some(left),
            (None, right) => right,
        };
        // The weaker classification wins: an episode is only as classified as
        // its least classified record, so a single opaque connection is not
        // hidden behind a named one.
        self.classification = self.classification.max(other.classification);
        self.named &= other.named;
    }

    fn seal(mut self) -> Self {
        self.flow_ids.sort();
        self.flow_ids.dedup();
        // The anchor is the lowest identity rather than the first record read,
        // so the finding keeps its identity whatever order the sensor wrote in.
        if let Some(first) = self.flow_ids.first() {
            self.flow_id.clone_from(first);
        }
        self
    }

    pub(crate) fn flow_count(&self) -> u64 {
        self.flow_ids.len() as u64
    }

    /// Whether this episode may produce a derived finding at all.
    ///
    /// One bucket, by contract (`reconciliation/spec.md` §5.0.1). The other
    /// three are counted in [`WireCoverage`] and never suppressed from the
    /// report.
    pub(crate) fn counts_toward_findings(&self) -> bool {
        self.scope.counts_toward_findings()
    }
}

/// The destination a flow reached, and whether it has a name.
///
/// The name wins when there is one. An address is a destination too and is used
/// when nothing named it, because a flow nobody could name is exactly the flow
/// most worth reporting; what it may not do is silently look like a named one.
fn target_of(flow: &Flow) -> Option<(TargetId, bool)> {
    let port = Some(flow.five_tuple.dst_port);
    if let Some(host) = flow.resolved_host.as_deref().or(flow.sni.as_deref()) {
        if let Some(target) = TargetId::parse(host, port) {
            return Some((target, true));
        }
    }
    TargetId::parse(&flow.five_tuple.dst_ip, port).map(|target| (target, false))
}

/// Collects flows into the conversations they belong to.
///
/// Deterministic by construction: the records are ordered by destination,
/// process and start before anything is grouped, so neither the order the sensor
/// wrote them in nor the order a directory was read in reaches the result.
///
/// A record whose destination cannot be read at all is dropped from the
/// grouping and named in the returned losses. That is not a silent skip: such a
/// record names no address and no host, so there is nothing for any of the three
/// keys to compare, and the loss travels to the report diagnostics.
pub(crate) fn episodes(flows: &[Flow], tolerance_ms: u64) -> (Vec<WireEpisode>, Vec<String>) {
    let mut losses = Vec::new();
    let mut singles: Vec<WireEpisode> = Vec::new();
    for flow in flows {
        match WireEpisode::of_flow(flow) {
            Some(episode) => singles.push(episode),
            None => losses.push(format!(
                "a flow record names neither a host nor a readable address and took no part in the join: {}",
                flow.flow_id
            )),
        }
    }

    singles.sort_by(|a, b| {
        a.target
            .cmp(&b.target)
            .then_with(|| a.process.cmp(&b.process))
            .then_with(|| a.scope.cmp(&b.scope))
            .then_with(|| a.attribution.cmp(&b.attribution))
            .then_with(|| a.interval.cmp(&b.interval))
            .then_with(|| a.flow_id.cmp(&b.flow_id))
    });

    let mut episodes: Vec<WireEpisode> = Vec::new();
    for episode in singles {
        match episodes.last_mut() {
            Some(open)
                if open.same_conversation(&episode)
                    && open.interval.within(episode.interval, tolerance_ms) =>
            {
                open.absorb(episode);
            }
            _ => episodes.push(episode),
        }
    }

    let mut episodes: Vec<WireEpisode> = episodes.into_iter().map(WireEpisode::seal).collect();
    episodes.sort_by(|a, b| a.flow_id.cmp(&b.flow_id));
    losses.sort();
    losses.dedup();
    (episodes, losses)
}

/// What the wire source saw, in the counters the coverage statement carries.
///
/// All five are always written when a sensor fed the run, including the zeros.
/// Three of them count flows that produce no finding, and they are the reason
/// this type is not a single number: the reader has to be able to say "this much
/// of the traffic to a provider on this machine is not the project under scan"
/// without that sentence depending on a bucket happening to be non empty.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct WireCoverage {
    pub in_scope_flows: u64,
    pub out_of_scope_flows: u64,
    pub known_benign_flows: u64,
    pub unattributed_flows: u64,
    /// Flows whose destination no signature matched, and flows with no
    /// destination name to match. Both are `provider_ref = unknown` by contract.
    pub unclassified_flows: u64,
}

impl WireCoverage {
    /// Counts every flow the sensor handed over, whatever became of it.
    pub(crate) fn of(flows: &[Flow]) -> Self {
        let mut coverage = Self::default();
        for flow in flows {
            let counter = match flow.flow_scope {
                FlowScope::InScope => &mut coverage.in_scope_flows,
                FlowScope::OutOfScopeProcess => &mut coverage.out_of_scope_flows,
                FlowScope::KnownBenign => &mut coverage.known_benign_flows,
                FlowScope::Undetermined => &mut coverage.unattributed_flows,
            };
            *counter = counter.saturating_add(1);
            if flow.classification != Classification::Classified {
                coverage.unclassified_flows = coverage.unclassified_flows.saturating_add(1);
            }
        }
        coverage
    }

    pub fn total(self) -> u64 {
        self.in_scope_flows
            + self.out_of_scope_flows
            + self.known_benign_flows
            + self.unattributed_flows
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;
    use periskop_network_sensor::flow::{
        FiveTuple, Mechanism, ProcessRecord, Proto, ResolvedHostSource, SniSource,
    };
    use periskop_network_sensor::observation::Observation;

    /// The tolerance a run uses by default, once the bucket width is taken into
    /// account.
    pub(crate) const TOLERANCE_MS: u64 = 1_000;

    pub(crate) fn process(pid: u32) -> ProcessRecord {
        ProcessRecord {
            pid,
            pid_start_time: Some(1_785_833_900),
            comm: Some("python3".to_owned()),
            exe: Some("/srv/app/venv/bin/python3".to_owned()),
            cmdline_hash: None,
        }
    }

    /// One connection, as the sensor records one.
    pub(crate) fn flow(host: &str, bucket: u64, scope: FlowScope) -> Flow {
        named_flow(host, "openai", bucket, scope, 54_321)
    }

    pub(crate) fn named_flow(
        host: &str,
        provider: &str,
        bucket: u64,
        scope: FlowScope,
        src_port: u16,
    ) -> Flow {
        Flow::from_observation(
            Observation::new(
                "h_9f2c4a17be0d5386",
                bucket,
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
            .kernel_attributed(process(4821))
            .with_volume(2_048, 8_192),
            scope,
            Mechanism::Ebpf,
        )
        .unwrap()
    }

    /// A connection nothing could name: no DNS answer, an encrypted handshake.
    pub(crate) fn opaque_flow(dst_ip: &str, bucket: u64, scope: FlowScope) -> Flow {
        Flow::from_observation(
            Observation::new(
                "h_9f2c4a17be0d5386",
                bucket,
                FiveTuple {
                    src_port: 54_322,
                    dst_ip: dst_ip.to_owned(),
                    dst_port: 443,
                    proto: Proto::Tcp,
                },
                SniSource::EncryptedClientHello,
            )
            .with_duration_ms(90)
            .kernel_attributed(process(4821))
            .with_volume(4_096, 512),
            scope,
            Mechanism::Ebpf,
        )
        .unwrap()
    }

    #[test]
    fn connections_to_one_destination_within_the_tolerance_are_one_episode() {
        // The report §6 asks for: a pool that opened three sockets to one
        // provider is one fact, not three.
        let flows = [
            flow("api.openai.com", 1_785_834_000, FlowScope::InScope),
            named_flow(
                "api.openai.com",
                "openai",
                1_785_834_000,
                FlowScope::InScope,
                54_322,
            ),
            named_flow(
                "api.openai.com",
                "openai",
                1_785_834_001,
                FlowScope::InScope,
                54_323,
            ),
        ];
        let (episodes, losses) = episodes(&flows, TOLERANCE_MS);

        assert_eq!(episodes.len(), 1, "{episodes:?}");
        assert_eq!(episodes[0].flow_count(), 3);
        assert_eq!(episodes[0].bytes_out, Some(6_144));
        assert!(losses.is_empty());
    }

    #[test]
    fn connections_further_apart_than_the_tolerance_are_separate_episodes() {
        // The other edge of the same rule. Two bursts an hour apart are two
        // things that happened, and collapsing them would hide one of them
        // behind the other's evidence.
        let flows = [
            flow("api.openai.com", 1_785_834_000, FlowScope::InScope),
            named_flow(
                "api.openai.com",
                "openai",
                1_785_837_600,
                FlowScope::InScope,
                54_322,
            ),
        ];
        let (episodes, _) = episodes(&flows, TOLERANCE_MS);

        assert_eq!(episodes.len(), 2, "{episodes:?}");
    }

    #[test]
    fn the_tolerance_decides_the_boundary_and_a_wider_one_moves_it() {
        // The tolerance is a knob whose value changes which findings exist, so
        // the same records have to group differently under two settings.
        let flows = [
            flow("api.openai.com", 1_785_834_000, FlowScope::InScope),
            named_flow(
                "api.openai.com",
                "openai",
                1_785_834_010,
                FlowScope::InScope,
                54_322,
            ),
        ];

        // Ten seconds apart: outside a one second tolerance, inside a minute.
        assert_eq!(episodes(&flows, TOLERANCE_MS).0.len(), 2);
        assert_eq!(episodes(&flows, 60_000).0.len(), 1);
    }

    #[test]
    fn two_processes_reaching_one_destination_are_two_episodes() {
        // A pid names a process and the traffic of two processes is two facts,
        // even when they went to the same place at the same moment.
        let mut second = flow("api.openai.com", 1_785_834_000, FlowScope::InScope);
        second.five_tuple.src_port = 54_999;
        second.process = Some(process(9_100));
        let flows = [
            flow("api.openai.com", 1_785_834_000, FlowScope::InScope),
            second,
        ];

        assert_eq!(episodes(&flows, TOLERANCE_MS).0.len(), 2);
    }

    #[test]
    fn the_grouping_does_not_depend_on_the_order_the_records_arrived_in() {
        let one = flow("api.openai.com", 1_785_834_000, FlowScope::InScope);
        let other = opaque_flow("10.2.3.4", 1_785_834_000, FlowScope::OutOfScopeProcess);

        let forward = episodes(&[one.clone(), other.clone()], TOLERANCE_MS).0;
        let backward = episodes(&[other, one], TOLERANCE_MS).0;
        assert_eq!(forward, backward);
        assert_eq!(forward.len(), 2);
    }

    #[test]
    fn a_destination_with_no_name_is_still_a_destination_and_says_so() {
        let flows = [opaque_flow("10.2.3.4", 1_785_834_000, FlowScope::InScope)];
        let (episodes, _) = episodes(&flows, TOLERANCE_MS);

        assert_eq!(episodes[0].target.host(), "10.2.3.4");
        assert!(!episodes[0].named);
        assert_eq!(episodes[0].classification, Classification::Opaque);
    }

    #[test]
    fn every_bucket_is_counted_including_the_ones_that_produce_nothing() {
        // K-15: three of the four buckets never enter false positive accounting,
        // and a bucket that vanishes from the report is a silent swallow.
        let flows = [
            flow("api.openai.com", 1_785_834_000, FlowScope::InScope),
            named_flow(
                "api.openai.com",
                "openai",
                1_785_834_000,
                FlowScope::OutOfScopeProcess,
                54_322,
            ),
            named_flow(
                "telemetry.internal",
                "unknown",
                1_785_834_000,
                FlowScope::KnownBenign,
                54_323,
            ),
            opaque_flow("10.2.3.4", 1_785_834_000, FlowScope::Undetermined),
        ];
        let coverage = WireCoverage::of(&flows);

        assert_eq!(coverage.in_scope_flows, 1);
        assert_eq!(coverage.out_of_scope_flows, 1);
        assert_eq!(coverage.known_benign_flows, 1);
        assert_eq!(coverage.unattributed_flows, 1);
        // The benign one named a host nothing matched, the opaque one had no
        // name to match at all. Both are unclassified by contract.
        assert_eq!(coverage.unclassified_flows, 2);
        assert_eq!(coverage.total(), 4);
    }

    #[test]
    fn an_episode_reports_its_span_and_never_the_clock_it_was_read_from() {
        let flows = [
            flow("api.openai.com", 1_785_834_000, FlowScope::InScope),
            named_flow(
                "api.openai.com",
                "openai",
                1_785_834_001,
                FlowScope::InScope,
                54_322,
            ),
        ];
        let (episodes, _) = episodes(&flows, TOLERANCE_MS);

        // One second between the two starts, plus the second one's duration.
        assert_eq!(episodes[0].interval.span_ms(), 1_120);
    }

    #[test]
    fn a_flow_with_no_observed_end_still_takes_part() {
        // An absent duration means the end was not seen, which is a fact rather
        // than a zero, and it may not remove the flow from the join.
        let mut open = flow("api.openai.com", 1_785_834_000, FlowScope::InScope);
        open.duration_ms = None;
        let (episodes, losses) = episodes(&[open], TOLERANCE_MS);

        assert_eq!(episodes.len(), 1);
        assert_eq!(episodes[0].interval.span_ms(), 0);
        assert!(losses.is_empty());
    }

    #[test]
    fn a_gap_is_measured_from_the_nearer_edge_in_either_direction() {
        let early = Interval::of_flow(1_000, Some(500));
        let late = Interval::of_flow(1_002, Some(500));

        assert_eq!(early.gap_ms(late), 1_500);
        assert_eq!(late.gap_ms(early), 1_500);
        assert!(early.within(late, 1_500));
        assert!(!early.within(late, 1_499));
        // Overlapping intervals have no gap at all, in either direction.
        assert_eq!(early.gap_ms(Interval::of_flow(1_000, Some(100))), 0);
    }
}
