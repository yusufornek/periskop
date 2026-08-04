//! One observation pass, and the statement it produces.
//!
//! [`observe`] cannot fail. That is the point of the module: a scan asked the
//! sensor what left the machine, and "nothing, because I was not allowed to
//! look" is an answer. Returning a `Result` here would let a caller write `?`
//! and turn a missing capability into a failed scan, which is how an
//! observation tool ends up being the reason a product cannot run.
//!
//! The outcome keeps two platform values apart, and the difference is the whole
//! reason this type exists. `detected_platform` says what this machine could
//! have offered; `coverage_platform_class` says what a report may claim, and it
//! is `none` whenever nothing was observed, whatever the cause. So "there was
//! no sensor here" and "there was a sensor and it saw nothing" stay distinct:
//! the first is `none` with a reason, the second is `linux_ebpf` with an empty
//! flow list.

use crate::flow::{DegradedReason, Flow};
use crate::platform::{self, SensorPlatformClass};
use crate::privilege::{self, Privileges, SensorUnavailable};
use crate::resolve::DnsObservation;
use crate::scope::{ScopePolicy, ScopeTally};
use crate::source::{FlowSource, SourceCoverage};

/// Whether the sensor observed anything at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorState {
    Observed,
    NotStarted(SensorUnavailable),
}

/// What one observation pass produced, including everything it could not do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorOutcome {
    detected_platform: SensorPlatformClass,
    state: SensorState,
    flows: Vec<Flow>,
    tally: ScopeTally,
    rejected: Vec<&'static str>,
    coverage: SourceCoverage,
}

impl SensorOutcome {
    fn not_started(detected_platform: SensorPlatformClass, reason: SensorUnavailable) -> Self {
        Self {
            detected_platform,
            state: SensorState::NotStarted(reason),
            flows: Vec::new(),
            tally: ScopeTally::default(),
            rejected: Vec::new(),
            coverage: SourceCoverage::default(),
        }
    }

    /// What this machine could have offered, whether or not it did.
    pub fn detected_platform(&self) -> SensorPlatformClass {
        self.detected_platform
    }

    /// The value the coverage statement carries.
    ///
    /// `none` unless observation actually happened. A run denied by a missing
    /// capability on a Linux host has a detected platform of `linux_ebpf` and
    /// still declares `none`, because the field's contract says `none` means
    /// there was no network observation at all, and a reader who sees
    /// `linux_ebpf` will believe the network was watched.
    pub fn coverage_platform_class(&self) -> SensorPlatformClass {
        match self.state {
            SensorState::Observed => self.detected_platform,
            SensorState::NotStarted(_) => SensorPlatformClass::None,
        }
    }

    pub fn state(&self) -> SensorState {
        self.state
    }

    /// The fixed label for why nothing was observed, if nothing was.
    pub fn unavailable_reason(&self) -> Option<&'static str> {
        match self.state {
            SensorState::Observed => None,
            SensorState::NotStarted(reason) => Some(reason.as_str()),
        }
    }

    /// Observed flows, ordered by identity so two passes over the same traffic
    /// serialize the same way.
    pub fn flows(&self) -> &[Flow] {
        &self.flows
    }

    /// All four buckets, including the empty ones.
    pub fn tally(&self) -> ScopeTally {
        self.tally
    }

    /// Observations that could not become records, by fixed reason label.
    ///
    /// Kept because a contradictory observation is a loss like any other. A
    /// mechanism that produces records this build rejects would otherwise show
    /// up as a quiet shortfall in the flow count.
    pub fn rejected(&self) -> &[&'static str] {
        &self.rejected
    }

    /// Whether plaintext DNS could be watched, or `None` if nothing was
    /// watched at all.
    ///
    /// Deliberately optional. The coverage contract closes this field at two
    /// values, both of which are statements about a run that happened; a sensor
    /// that never started has made neither, and defaulting to `available` would
    /// put a measurement in a report where there was none.
    pub fn dns_observation(&self) -> Option<DnsObservation> {
        match self.state {
            SensorState::Observed => Some(self.coverage.dns_observation),
            SensorState::NotStarted(_) => None,
        }
    }

    /// Events the capture transport lost under load.
    ///
    /// Zero on a sensor that never started, which is true rather than a
    /// default: nothing was dropped because nothing was read.
    pub fn dropped_events(&self) -> u64 {
        self.coverage.dropped_events
    }

    /// Events that named a connection the pass never saw open.
    pub fn unlinked_events(&self) -> u64 {
        self.coverage.unlinked_events
    }
}

/// Runs one observation pass on this machine.
pub fn observe<S: FlowSource>(
    source: &mut S,
    privileges: &Privileges,
    policy: &ScopePolicy,
) -> SensorOutcome {
    observe_on(platform::detect(), source, privileges, policy)
}

/// The pass with the platform supplied.
///
/// Separate so the Linux path can be exercised on any machine the workspace
/// builds on. Not public: a caller that could name its own platform could put a
/// class into a report that nothing on the machine backs.
pub(crate) fn observe_on<S: FlowSource>(
    detected_platform: SensorPlatformClass,
    source: &mut S,
    privileges: &Privileges,
    policy: &ScopePolicy,
) -> SensorOutcome {
    let grant = match privilege::evaluate(detected_platform, privileges) {
        Ok(grant) => grant,
        Err(reason) => return SensorOutcome::not_started(detected_platform, reason),
    };

    let Some(mechanism) = detected_platform.mechanism() else {
        // Unreachable through `evaluate`, which only admits classes that have
        // one. Written as a branch rather than an unwrap so that a future class
        // without a mechanism cannot make the sensor panic inside a scan.
        return SensorOutcome::not_started(
            detected_platform,
            SensorUnavailable::UnsupportedPlatform,
        );
    };

    if let Err(reason) = source.attach(&grant) {
        return SensorOutcome::not_started(detected_platform, reason);
    }

    let mut flows = Vec::new();
    let mut tally = ScopeTally::default();
    let mut rejected = Vec::new();

    for observation in source.drain() {
        let scope = policy.classify(&observation);
        // True of every flow in this pass, so it is recorded on every flow
        // rather than in a run level note a per record reader would never see.
        let observation = if grant.tc_available {
            observation
        } else {
            observation.degraded(vec![DegradedReason::TcUnavailable])
        };

        match Flow::from_observation(observation, scope, mechanism) {
            Ok(flow) => {
                tally.record(scope);
                flows.push(flow);
            }
            Err(error) => rejected.push(error.reason()),
        }
    }

    // Neither the order the kernel handed events over in nor the order a stub
    // listed them may reach the output.
    flows.sort_by(|a, b| a.flow_id.cmp(&b.flow_id).then_with(|| a.cmp(b)));
    rejected.sort_unstable();

    SensorOutcome {
        detected_platform,
        state: SensorState::Observed,
        flows,
        tally,
        rejected,
        // Read after the drain, because a mechanism only knows what it lost
        // once it has finished handing over what it kept.
        coverage: source.coverage(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::flow::tests::{five_tuple, process};
    use crate::flow::{
        FiveTuple, Mechanism, ProcessAttribution, ProcessRecord, Proto, ResolvedHostSource,
        SniSource,
    };
    use crate::observation::Observation;
    use crate::scope::FlowScope;
    use crate::source::{EbpfFlowSource, SourceCoverage, StubFlowSource};

    fn capable() -> Privileges {
        Privileges {
            effective_uid: Some(1000),
            cap_bpf: true,
            cap_perfmon: true,
            cap_net_admin: true,
            btf_available: true,
        }
    }

    fn policy() -> ScopePolicy {
        ScopePolicy::for_codebase(["/srv/app/venv/bin/python3"])
    }

    fn app_process() -> ProcessRecord {
        ProcessRecord {
            exe: Some("/srv/app/venv/bin/python3".to_owned()),
            ..process()
        }
    }

    fn observation(dst_ip: &str) -> Observation {
        Observation::new(
            "h_9f2c4a17be0d5386",
            1_785_834_000,
            FiveTuple {
                dst_ip: dst_ip.to_owned(),
                ..five_tuple()
            },
            SniSource::ClientHello,
        )
        .with_boot_id("b_3f0a91c7d4e28b56")
    }

    #[test]
    fn a_denied_sensor_hands_back_an_answer_rather_than_an_error() {
        // The non negotiable one. There is no `?` a caller could write here,
        // because `observe` has no error to propagate.
        let outcome = observe_on(
            SensorPlatformClass::LinuxEbpf,
            &mut StubFlowSource::yielding(Vec::new()),
            &Privileges::default(),
            &policy(),
        );
        assert_eq!(
            outcome.state(),
            SensorState::NotStarted(SensorUnavailable::MissingCapability)
        );
        assert_eq!(outcome.unavailable_reason(), Some("missing_capability"));
        assert!(outcome.flows().is_empty());
    }

    #[test]
    fn a_denied_sensor_declares_no_observation_while_still_naming_the_machine() {
        // The distinction the coverage field exists for: a Linux host that
        // refused permission has a detected platform and still tells the report
        // that nothing was watched.
        let outcome = observe_on(
            SensorPlatformClass::LinuxEbpf,
            &mut StubFlowSource::yielding(Vec::new()),
            &Privileges::default(),
            &policy(),
        );
        assert_eq!(outcome.detected_platform(), SensorPlatformClass::LinuxEbpf);
        assert_eq!(outcome.coverage_platform_class(), SensorPlatformClass::None);
    }

    #[test]
    fn a_sensor_that_ran_and_saw_nothing_is_not_a_sensor_that_never_ran() {
        let observed = observe_on(
            SensorPlatformClass::LinuxEbpf,
            &mut StubFlowSource::yielding(Vec::new()),
            &capable(),
            &policy(),
        );
        assert_eq!(observed.state(), SensorState::Observed);
        assert!(observed.flows().is_empty());
        assert_eq!(
            observed.coverage_platform_class(),
            SensorPlatformClass::LinuxEbpf
        );
        assert_eq!(observed.unavailable_reason(), None);
    }

    #[test]
    fn a_platform_without_a_sensor_declares_none_instead_of_going_quiet() {
        let outcome = observe_on(
            SensorPlatformClass::None,
            &mut StubFlowSource::yielding(vec![observation("104.18.7.1")]),
            &capable(),
            &policy(),
        );
        assert_eq!(outcome.coverage_platform_class(), SensorPlatformClass::None);
        assert_eq!(outcome.unavailable_reason(), Some("unsupported_platform"));
        assert_eq!(outcome.tally().total(), 0);
    }

    #[test]
    fn the_shipped_build_never_takes_the_scan_down_on_any_machine() {
        // Runs `observe` itself, so whatever this machine is, the contract
        // holds: an outcome, a stated reason, and no panic.
        let mut source = EbpfFlowSource::new("h_9f2c4a17be0d5386");
        let outcome = observe(&mut source, &Privileges::probe(), &policy());
        assert!(matches!(outcome.state(), SensorState::NotStarted(_)));
        assert!(outcome.unavailable_reason().is_some_and(|r| !r.is_empty()));
        assert_eq!(outcome.coverage_platform_class(), SensorPlatformClass::None);
    }

    #[test]
    fn a_sensor_that_never_started_states_no_dns_observation_at_all() {
        // The coverage contract closes the field at two values, and both are
        // claims about a run that happened. A denied sensor made neither.
        let outcome = observe_on(
            SensorPlatformClass::LinuxEbpf,
            &mut StubFlowSource::yielding(Vec::new()),
            &Privileges::default(),
            &policy(),
        );
        assert_eq!(outcome.dns_observation(), None);
        assert_eq!(outcome.dropped_events(), 0);
    }

    #[test]
    fn what_the_mechanism_lost_reaches_the_outcome() {
        // Otherwise a run that dropped a thousand events and a quiet run look
        // identical from the report's side.
        let mut source = StubFlowSource::yielding(Vec::new()).losing(SourceCoverage {
            dropped_events: 1_000,
            unlinked_events: 3,
            dns_observation: DnsObservation::UnavailableEncryptedDns,
        });
        let outcome = observe_on(
            SensorPlatformClass::LinuxEbpf,
            &mut source,
            &capable(),
            &policy(),
        );
        assert_eq!(outcome.dropped_events(), 1_000);
        assert_eq!(outcome.unlinked_events(), 3);
        assert_eq!(
            outcome.dns_observation(),
            Some(DnsObservation::UnavailableEncryptedDns)
        );
    }

    #[test]
    fn a_source_that_cannot_attach_is_reported_in_its_own_words() {
        let outcome = observe_on(
            SensorPlatformClass::LinuxEbpf,
            &mut StubFlowSource::refusing(SensorUnavailable::LoaderNotBuilt),
            &capable(),
            &policy(),
        );
        assert_eq!(outcome.unavailable_reason(), Some("loader_not_built"));
    }

    #[test]
    fn observations_become_records_in_the_right_buckets() {
        // End to end: four observations, four buckets, one report.
        let policy = policy().with_declared_benign_host("telemetry.internal");
        let mut source = StubFlowSource::yielding(vec![
            observation("104.18.7.1")
                .kernel_attributed(app_process())
                .resolved("api.openai.com", ResolvedHostSource::DnsAndSni)
                .with_provider_ref("openai"),
            observation("104.18.7.2")
                .kernel_attributed(process())
                .resolved("api.anthropic.com", ResolvedHostSource::Sni),
            observation("10.0.0.9")
                .kernel_attributed(app_process())
                .resolved("telemetry.internal", ResolvedHostSource::Dns),
            observation("104.18.7.3"),
        ]);

        let outcome = observe_on(
            SensorPlatformClass::LinuxEbpf,
            &mut source,
            &capable(),
            &policy,
        );

        assert_eq!(outcome.state(), SensorState::Observed);
        assert_eq!(outcome.flows().len(), 4);
        assert_eq!(outcome.tally().count(FlowScope::InScope), 1);
        assert_eq!(outcome.tally().count(FlowScope::OutOfScopeProcess), 1);
        assert_eq!(outcome.tally().count(FlowScope::KnownBenign), 1);
        assert_eq!(outcome.tally().count(FlowScope::Undetermined), 1);
        assert_eq!(outcome.tally().total(), 4);
        assert!(outcome.rejected().is_empty());

        for flow in outcome.flows() {
            assert_eq!(flow.mechanism, Mechanism::Ebpf);
            flow.validate().unwrap();
        }
    }

    #[test]
    fn the_three_quiet_buckets_stay_visible_in_the_outcome() {
        // Three of the four flows produce no finding. If the outcome only
        // exposed what feeds findings, they would leave no trace at all.
        let mut source = StubFlowSource::yielding(vec![
            observation("104.18.7.2").kernel_attributed(process()),
            observation("104.18.7.3"),
        ]);
        let outcome = observe_on(
            SensorPlatformClass::LinuxEbpf,
            &mut source,
            &capable(),
            &policy(),
        );

        let counters = outcome.tally().counters();
        assert_eq!(counters.len(), FlowScope::ALL.len());
        assert_eq!(outcome.flows().len(), 2);
        assert!(outcome
            .flows()
            .iter()
            .all(|flow| !flow.flow_scope.counts_toward_findings()));
    }

    #[test]
    fn records_come_out_in_identity_order_whatever_order_they_arrived_in() {
        let first = observation("104.18.7.1");
        let second = observation("104.18.7.2");
        let third = observation("10.0.0.9");

        let mut forwards =
            StubFlowSource::yielding(vec![first.clone(), second.clone(), third.clone()]);
        let mut backwards = StubFlowSource::yielding(vec![third, second, first]);

        let a = observe_on(
            SensorPlatformClass::LinuxEbpf,
            &mut forwards,
            &capable(),
            &policy(),
        );
        let b = observe_on(
            SensorPlatformClass::LinuxEbpf,
            &mut backwards,
            &capable(),
            &policy(),
        );

        assert_eq!(a.flows(), b.flows());
        let ids: Vec<&str> = a.flows().iter().map(Flow::id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn without_net_admin_every_record_says_the_tc_helper_was_missing() {
        let no_tc = Privileges {
            cap_net_admin: false,
            ..capable()
        };
        let mut source = StubFlowSource::yielding(vec![observation("104.18.7.1")
            .with_boot_id("b_1")
            .degraded(vec![DegradedReason::Ech])]);

        let outcome = observe_on(
            SensorPlatformClass::LinuxEbpf,
            &mut source,
            &no_tc,
            &policy(),
        );

        assert_eq!(
            outcome.flows()[0].degraded_reasons,
            Some(vec![DegradedReason::Ech, DegradedReason::TcUnavailable])
        );
    }

    #[test]
    fn a_contradictory_observation_is_counted_rather_than_dropped() {
        // A mechanism claiming attribution with no process record. The record
        // cannot be written, and the loss has to be visible or the flow count
        // simply comes up short with no explanation.
        let mut broken = observation("104.18.7.1");
        broken.process_attribution = ProcessAttribution::KernelAttributed;
        let mut source = StubFlowSource::yielding(vec![broken, observation("104.18.7.2")]);

        let outcome = observe_on(
            SensorPlatformClass::LinuxEbpf,
            &mut source,
            &capable(),
            &policy(),
        );

        assert_eq!(outcome.flows().len(), 1);
        assert_eq!(outcome.rejected(), ["attribution_disagrees_with_process"]);
    }

    #[test]
    fn a_udp_observation_is_recorded_like_any_other() {
        // QUIC and DNS arrive over UDP and are the two paths the sensor is
        // weakest on. Weak resolution is not a reason to leave the flow out.
        let quic = Observation::new(
            "h_1",
            1_785_834_000,
            FiveTuple {
                src_port: 54321,
                dst_ip: "104.18.7.1".to_owned(),
                dst_port: 443,
                proto: Proto::Udp,
            },
            SniSource::EncryptedClientHello,
        );
        let mut source = StubFlowSource::yielding(vec![quic]);

        let outcome = observe_on(
            SensorPlatformClass::LinuxEbpf,
            &mut source,
            &capable(),
            &policy(),
        );

        assert_eq!(outcome.flows().len(), 1);
        assert_eq!(outcome.flows()[0].five_tuple.proto, Proto::Udp);
        assert_eq!(
            outcome.flows()[0].sni_source,
            SniSource::EncryptedClientHello
        );
    }
}
