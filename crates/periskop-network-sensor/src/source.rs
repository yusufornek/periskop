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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SourceCoverage {
    /// Events the transport lost before user space read them.
    pub dropped_events: u64,
    /// Events that named a connection the pass never saw open.
    pub unlinked_events: u64,
    pub dns_observation: DnsObservation,
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
        Self::over(PlatformKernel, host_id)
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
        self.coverage
    }
}

/// A kernel that hands over exactly the events a test wrote.
#[cfg(test)]
pub(crate) struct ScriptedKernel {
    attach: Result<(), SensorUnavailable>,
    batches: Vec<kernel::KernelBatch>,
    pub(crate) planned: Option<kernel::AttachPlan>,
}

#[cfg(test)]
impl ScriptedKernel {
    pub(crate) fn yielding(batch: kernel::KernelBatch) -> Self {
        Self {
            attach: Ok(()),
            batches: vec![batch],
            planned: None,
        }
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
            return kernel::KernelBatch::default();
        }
        self.batches.remove(0)
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
        // Whatever machine this is, an attach that cannot happen says so. The
        // alternative would be a source that attaches, observes nothing and
        // lets the run report a network picture it never looked at.
        let mut source = EbpfFlowSource::new("h_1");
        let refusal = source.attach(&grant()).unwrap_err();
        assert!(matches!(
            refusal,
            SensorUnavailable::LoaderNotBuilt | SensorUnavailable::UnsupportedPlatform
        ));
        assert!(source.drain().is_empty());
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
    fn a_source_starts_out_claiming_no_losses_it_has_not_measured() {
        let source = EbpfFlowSource::over(ScriptedKernel::yielding(KernelBatch::default()), "h_1");
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
