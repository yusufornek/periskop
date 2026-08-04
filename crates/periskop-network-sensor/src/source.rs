//! Where observations come from.
//!
//! The capture mechanism sits behind this trait rather than inside the sensor.
//! Two reasons, and neither is tidiness. The mechanism is the only part of the
//! sensor that needs kernel objects, a verifier and eventually a foreign
//! function boundary, and everything this crate asserts about buckets,
//! identities and privileges has to be testable without any of that. And the
//! platform matrix in ADR-008 says there will be more than one implementation,
//! so the seam is going to exist whether or not it is drawn now.
//!
//! [`EbpfFlowSource`] is the Linux implementation. It is a real one: it turns
//! the grant into an attach plan, reads the kernel's event stream, joins the
//! process side to the packet side, ages the DNS map and produces observations
//! with names, volumes and attribution on them. The only thing it does not do
//! itself is open the kernel objects, which is [`crate::kernel::loader`]'s job
//! and is behind its own decision (ADR-014). When that refuses, this source
//! reports the refusal in the vocabulary a permission failure uses; it never
//! hands back an empty observation list as if it had looked.
//!
//! Nothing here changes when the loader is compiled in. That was ADR-014's
//! prediction and it is worth having held to: the feature moves the seam
//! underneath [`crate::kernel::PlatformKernel`], and everything above it, the
//! join, the ageing, the naming and the record, is the same code exercised by
//! the same tests on every platform in the workspace. The one visible
//! difference is which cause an attach reports.

use std::collections::BTreeMap;

use crate::assemble::FlowAssembler;
use crate::kernel::{self, KernelEvents, PlatformKernel};
use crate::observation::Observation;
use crate::privilege::{Grant, SensorUnavailable};
use crate::resolve::DnsObservation;

/// What a mechanism could not do, stated per run rather than per record.
///
/// A source has to report this even when it observed nothing, which is why it
/// is on the trait with no default implementation. A default would let a
/// mechanism inherit "DNS was fine, nothing was dropped" without ever having
/// checked, and a coverage statement assembled out of defaults is worse than
/// none: it reads as a measurement.
///
/// Not `Copy`, since the rejected sample tally is a map. A copy of a tally is a
/// tally that stops counting, and the shape it has here is the one the open
/// request against `coverage-statement.schema.json` asks the contract for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceCoverage {
    /// Events the transport lost before user space read them.
    pub dropped_events: u64,
    /// Events that named a connection the pass never saw open.
    pub unlinked_events: u64,
    pub dns_observation: DnsObservation,
    /// Payload samples the parsers refused, by fixed cause label.
    ///
    /// The connection behind such a sample was still seen; what was lost is its
    /// destination name. A run that lost a thousand of them and one that lost
    /// none must not read alike, which is what carrying the tally here rather
    /// than leaving it inside the kernel object is for.
    pub rejected_payload_samples: BTreeMap<&'static str, u64>,
    /// Names the DNS map dropped to stay inside its address budget.
    pub dns_names_evicted: u64,
    /// Evictions whose address the map could no longer remember.
    ///
    /// While this is above zero a flow carrying no `map_overflow` reason may
    /// still have lost a name, and the run says so rather than presenting the
    /// per flow answers as complete.
    pub dns_evictions_forgotten: u64,
}

/// A capture mechanism the sensor can read observations from.
pub trait FlowSource {
    /// Attaches to the kernel, or explains why it cannot.
    ///
    /// The grant is passed in rather than looked up, so an implementation
    /// cannot decide for itself that it has permission it was not given. An
    /// implementation that finds it needs something the grant lacks says so
    /// here instead of failing later with a record already half written.
    fn attach(&mut self, grant: &Grant) -> Result<(), SensorUnavailable>;

    /// Hands over what has been observed since the last call.
    ///
    /// Returns observations rather than flows: a mechanism knows what it saw
    /// and cannot know which codebase was under scan, so it never decides a
    /// bucket.
    fn drain(&mut self) -> Vec<Observation>;

    /// What this mechanism lost, whether or not it observed anything.
    fn coverage(&self) -> SourceCoverage;
}

/// The Linux eBPF source.
///
/// Generic over the kernel event stream so the join, the classification and the
/// record production are exercised on every machine the workspace builds on.
/// The default parameter is the real one, so `EbpfFlowSource::new(..)` is the
/// shipped sensor and a test that wants a scripted kernel has to say so.
#[derive(Debug, Clone)]
pub struct EbpfFlowSource<K = PlatformKernel> {
    kernel: K,
    assembler: FlowAssembler,
}

impl EbpfFlowSource<PlatformKernel> {
    /// The sensor as it ships, reading from this machine's kernel.
    pub fn new(host_id: impl Into<String>) -> Self {
        Self::over(PlatformKernel::default(), host_id)
    }
}

impl<K: KernelEvents> EbpfFlowSource<K> {
    /// The sensor over a given event stream.
    pub fn over(kernel: K, host_id: impl Into<String>) -> Self {
        Self {
            kernel,
            assembler: FlowAssembler::new(host_id),
        }
    }

    /// Records the boot the observation belongs to, which is what keeps a flow
    /// identity from colliding with one from before a restart.
    pub fn with_boot_id(mut self, boot_id: impl Into<String>) -> Self {
        self.assembler = self.assembler.with_boot_id(boot_id);
        self
    }
}

impl<K: KernelEvents> FlowSource for EbpfFlowSource<K> {
    fn attach(&mut self, grant: &Grant) -> Result<(), SensorUnavailable> {
        // The plan is derived from the grant here and handed down, so the
        // loader cannot attach a program the privilege check did not allow.
        self.kernel.attach(&kernel::plan(grant))
    }

    fn drain(&mut self) -> Vec<Observation> {
        let batch = self.kernel.poll();
        // A read from a kernel with nothing attached is not a window in which
        // the machine stayed quiet, so nothing is sealed from it. Feeding it to
        // the assembler would age the DNS map and close observations on the
        // strength of time that nobody was watching, and the empty list that
        // came back would be indistinguishable from a silent network.
        if !batch.observed() {
            return Vec::new();
        }
        self.assembler.record_dropped(batch.dropped);
        for event in batch.events {
            self.assembler.ingest(event);
        }
        // One pass, one sealed window. Sealing here rather than per event is
        // what lets a flow be weighed against every DNS answer the window saw,
        // whichever side of the connection they arrived on.
        self.assembler.seal()
    }

    fn coverage(&self) -> SourceCoverage {
        SourceCoverage {
            dropped_events: self.assembler.dropped_events(),
            unlinked_events: self.assembler.unlinked_events(),
            dns_observation: self.assembler.dns_observation(),
            // Read from the kernel object rather than the assembler: a sample
            // the parsers refused never became an event, so the assembler never
            // saw it and only the seam knows it existed.
            rejected_payload_samples: self.kernel.rejected_samples(),
            dns_names_evicted: self.assembler.dns_names_evicted(),
            dns_evictions_forgotten: self.assembler.dns_evictions_forgotten(),
        }
    }
}

/// A source that hands over observations a test wrote by hand.
///
/// Lives behind `cfg(test)` because it is a stand in for a kernel, and a stand
/// in for a kernel that shipped in the library would be a way to produce
/// records that look observed and are not.
#[cfg(test)]
pub(crate) struct StubFlowSource {
    attach: Result<(), SensorUnavailable>,
    observations: Vec<Observation>,
    coverage: SourceCoverage,
    pub(crate) attached_with: Option<Grant>,
}

#[cfg(test)]
impl StubFlowSource {
    pub(crate) fn yielding(observations: Vec<Observation>) -> Self {
        Self {
            attach: Ok(()),
            observations,
            coverage: SourceCoverage::default(),
            attached_with: None,
        }
    }

    pub(crate) fn refusing(reason: SensorUnavailable) -> Self {
        Self {
            attach: Err(reason),
            observations: Vec::new(),
            coverage: SourceCoverage::default(),
            attached_with: None,
        }
    }

    pub(crate) fn losing(mut self, coverage: SourceCoverage) -> Self {
        self.coverage = coverage;
        self
    }
}

#[cfg(test)]
impl FlowSource for StubFlowSource {
    fn attach(&mut self, grant: &Grant) -> Result<(), SensorUnavailable> {
        self.attached_with = Some(*grant);
        self.attach
    }

    fn drain(&mut self) -> Vec<Observation> {
        std::mem::take(&mut self.observations)
    }

    fn coverage(&self) -> SourceCoverage {
        self.coverage.clone()
    }
}

/// A kernel that hands over exactly the events a test wrote.
#[cfg(test)]
pub(crate) struct ScriptedKernel {
    attach: Result<(), SensorUnavailable>,
    batches: Vec<kernel::KernelBatch>,
    rejected: BTreeMap<&'static str, u64>,
    pub(crate) planned: Option<kernel::AttachPlan>,
}

#[cfg(test)]
impl ScriptedKernel {
    pub(crate) fn yielding(batch: kernel::KernelBatch) -> Self {
        Self {
            attach: Ok(()),
            batches: vec![batch],
            rejected: BTreeMap::new(),
            planned: None,
        }
    }

    /// A kernel that also handed up samples no parser could read.
    ///
    /// Scriptable because the real path to this state needs the loader feature
    /// and a machine that can hold eBPF programs, and the property under test
    /// is on this side of the seam: what the sensor does with a count the
    /// kernel object reports.
    pub(crate) fn refusing_samples(mut self, cause: &'static str, count: u64) -> Self {
        self.rejected.insert(cause, count);
        self
    }
}

#[cfg(test)]
impl KernelEvents for ScriptedKernel {
    fn attach(&mut self, plan: &kernel::AttachPlan) -> Result<(), SensorUnavailable> {
        self.planned = Some(plan.clone());
        self.attach
    }

    fn poll(&mut self) -> kernel::KernelBatch {
        if self.batches.is_empty() {
            // A scripted kernel that has run out of script is an attached
            // sensor watching a quiet machine, not an unattached one: the
            // difference decides whether the drain that follows is a
            // measurement.
            return kernel::KernelBatch::quiet();
        }
        self.batches.remove(0)
    }

    fn rejected_samples(&self) -> BTreeMap<&'static str, u64> {
        self.rejected.clone()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::flow::tests::five_tuple;
    use crate::flow::{ProcessAttribution, SniSource};
    use crate::kernel::event::{ConnectEvent, KernelBatch, KernelEvent, KernelProcess};
    use crate::kernel::key::tests::key;
    use crate::kernel::Program;

    fn grant() -> Grant {
        Grant {
            tc_available: true,
            elevated_as_root: false,
        }
    }

    fn connect_batch() -> KernelBatch {
        KernelBatch::of(vec![KernelEvent::Connect(ConnectEvent {
            key: key("104.18.7.1", 443, 54321),
            t_start_bucket: 1_785_834_000,
            at_secs: 1,
            process: KernelProcess {
                pid: 4821,
                pid_start_time: Some(1_785_833_900),
                comm: Some("python3".to_owned()),
            },
            pre_existing: false,
        })])
    }

    #[test]
    fn the_shipped_source_reports_a_cause_rather_than_a_clean_empty_run() {
        // Whatever machine this is, and whether or not the loader feature is
        // compiled in, an attach that cannot happen says so. The alternative
        // would be a source that attaches, observes nothing and lets the run
        // report a network picture it never looked at.
        //
        // The set of causes is left open here rather than pinned to one: with
        // the loader compiled in, an unprivileged Linux machine answers
        // `missing_capability` and a machine with no BTF answers
        // `kernel_unsupported`, and both are correct. What must hold everywhere
        // is that there is a cause and that nothing was handed back.
        let mut source = EbpfFlowSource::new("h_1");
        let refusal = source.attach(&grant()).unwrap_err();
        assert!(!refusal.as_str().is_empty());
        assert!(source.drain().is_empty());
    }

    #[test]
    fn an_unattached_source_still_reports_the_losses_it_has_not_measured_as_none() {
        // A refusal must not leave the coverage looking like a measurement. The
        // sensor states the cause separately; what this asserts is that the
        // numbers alongside it are the honest zeroes of a run that never
        // started, not defaults standing in for a count.
        let mut source = EbpfFlowSource::new("h_1");
        assert!(source.attach(&grant()).is_err());
        assert_eq!(source.coverage(), SourceCoverage::default());
    }

    #[test]
    fn the_source_attaches_only_what_the_grant_planned() {
        // The grant is the authority. A source that widened it here would be
        // attaching a program the privilege check refused.
        let mut source =
            EbpfFlowSource::over(ScriptedKernel::yielding(KernelBatch::default()), "h_1");
        source
            .attach(&Grant {
                tc_available: false,
                elevated_as_root: false,
            })
            .unwrap();
        let planned = source.kernel.planned.clone().unwrap();
        assert!(!planned.includes_payload_helper());
        assert!(planned.programs().contains(&Program::KprobeTcpV4Connect));
    }

    #[test]
    fn a_connect_event_becomes_an_attributed_observation() {
        // Milestone 51 through the whole source: a kernel event in, a record
        // with a process on it out.
        let mut source = EbpfFlowSource::over(ScriptedKernel::yielding(connect_batch()), "h_1")
            .with_boot_id("b_1");
        source.attach(&grant()).unwrap();

        let observations = source.drain();
        assert_eq!(observations.len(), 1);
        let observation = observations.first().unwrap();
        assert_eq!(
            observation.process_attribution,
            ProcessAttribution::KernelAttributed
        );
        assert_eq!(observation.boot_id.as_deref(), Some("b_1"));
    }

    #[test]
    fn a_second_pass_over_an_empty_kernel_hands_back_nothing_twice() {
        let mut source = EbpfFlowSource::over(ScriptedKernel::yielding(connect_batch()), "h_1");
        source.attach(&grant()).unwrap();
        assert_eq!(source.drain().len(), 1);
        assert!(source.drain().is_empty());
    }

    #[test]
    fn what_the_transport_lost_survives_into_the_coverage() {
        let mut source = EbpfFlowSource::over(
            ScriptedKernel::yielding(KernelBatch {
                state: kernel::PollState::Attached,
                events: Vec::new(),
                dropped: 42,
            }),
            "h_1",
        );
        source.attach(&grant()).unwrap();
        source.drain();
        assert_eq!(source.coverage().dropped_events, 42);
    }

    #[test]
    fn samples_no_parser_could_read_reach_the_coverage_the_run_reports() {
        // The gap this closes: the seam counted refused samples by cause and
        // nothing outside its own tests could read the number, so a run where
        // every ClientHello was unreadable reported the same coverage as a run
        // where every destination resolved. The connections were seen either
        // way; what differs is how many of them the report can name.
        let mut source = EbpfFlowSource::over(
            ScriptedKernel::yielding(connect_batch()).refusing_samples("tls_not_client_hello", 7),
            "h_1",
        );
        source.attach(&grant()).unwrap();
        source.drain();

        let coverage = source.coverage();
        assert_eq!(
            coverage
                .rejected_payload_samples
                .get("tls_not_client_hello"),
            Some(&7)
        );
    }

    #[test]
    fn a_source_starts_out_claiming_no_losses_it_has_not_measured() {
        let source = EbpfFlowSource::over(ScriptedKernel::yielding(KernelBatch::quiet()), "h_1");
        assert_eq!(source.coverage(), SourceCoverage::default());
    }

    #[test]
    fn a_read_from_an_unattached_kernel_is_not_counted_as_a_quiet_window() {
        // Critic round k3, at the consumer. A batch from a kernel with nothing
        // attached carries losses that were never measured and a silence that
        // was never observed. Taking it as a window would put a dropped count
        // into the coverage statement of a run that read nothing, which is a
        // measurement of a machine nobody watched.
        let mut source = EbpfFlowSource::over(
            ScriptedKernel::yielding(KernelBatch {
                state: kernel::PollState::NotAttached,
                events: connect_batch().events,
                dropped: 42,
            }),
            "h_1",
        );
        source.attach(&grant()).unwrap();

        assert!(source.drain().is_empty());
        assert_eq!(source.coverage(), SourceCoverage::default());
    }

    #[test]
    fn a_stub_hands_each_observation_over_once() {
        let mut source = StubFlowSource::yielding(vec![Observation::new(
            "h_1",
            1,
            five_tuple(),
            SniSource::Absent,
        )]);
        assert!(source.attach(&grant()).is_ok());
        assert_eq!(source.drain().len(), 1);
        assert!(source.drain().is_empty());
    }

    #[test]
    fn a_source_is_told_what_it_was_granted() {
        // An implementation must not decide for itself that it may attach the
        // tc helper.
        let mut source = StubFlowSource::yielding(Vec::new());
        source.attach(&grant()).unwrap();
        assert_eq!(source.attached_with, Some(grant()));
    }
}
