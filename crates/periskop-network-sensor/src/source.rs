//! Where observations come from.
//!
//! The eBPF loader sits behind this trait rather than inside the sensor. Two
//! reasons, and neither is tidiness. The loader is the only part of the sensor
//! that will need kernel objects, a verifier and eventually a foreign function
//! boundary, and everything this crate asserts about buckets, identities and
//! privileges has to be testable without any of that. And the platform matrix
//! in ADR-008 says there will be more than one implementation, so the seam is
//! going to exist whether or not it is drawn now.
//!
//! This round ships the seam and a loader that honestly reports it is not
//! built. `EbpfFlowSource` compiles, attaches to nothing and says
//! `loader_not_built`; the programs themselves land in their own milestone.

use crate::observation::Observation;
use crate::privilege::{Grant, SensorUnavailable};

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
}

/// The Linux eBPF source.
///
/// Present so the platform decision, the privilege check and the sensor loop
/// are wired to the shape the real loader will have. It attaches to nothing
/// yet, and it says that in the same vocabulary a permission failure uses, so a
/// report from this build states plainly that no observation happened and why.
/// It never returns an empty observation list as if it had looked.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EbpfFlowSource;

impl FlowSource for EbpfFlowSource {
    fn attach(&mut self, _grant: &Grant) -> Result<(), SensorUnavailable> {
        Err(SensorUnavailable::LoaderNotBuilt)
    }

    fn drain(&mut self) -> Vec<Observation> {
        Vec::new()
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
    pub(crate) attached_with: Option<Grant>,
}

#[cfg(test)]
impl StubFlowSource {
    pub(crate) fn yielding(observations: Vec<Observation>) -> Self {
        Self {
            attach: Ok(()),
            observations,
            attached_with: None,
        }
    }

    pub(crate) fn refusing(reason: SensorUnavailable) -> Self {
        Self {
            attach: Err(reason),
            observations: Vec::new(),
            attached_with: None,
        }
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
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::flow::tests::five_tuple;
    use crate::flow::SniSource;

    fn grant() -> Grant {
        Grant {
            tc_available: true,
            elevated_as_root: false,
        }
    }

    #[test]
    fn the_shipped_loader_says_it_is_not_built() {
        // The alternative would be a source that attaches, observes nothing and
        // lets the run report a clean network picture it never looked at.
        let mut source = EbpfFlowSource;
        assert_eq!(
            source.attach(&grant()),
            Err(SensorUnavailable::LoaderNotBuilt)
        );
        assert!(source.drain().is_empty());
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
