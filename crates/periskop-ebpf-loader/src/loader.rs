//! The gate: what has to be true before a program is loaded, and what this
//! build does when all of it is.
//!
//! Every check here is one a machine can fail, and they run in a fixed order so
//! that the cause a report carries does not depend on which condition happened
//! to be evaluated first. A machine can fail several at once, and an operator
//! reading two reports from two machines needs the same answer to mean the same
//! thing.
//!
//! The order is platform, then authority to load at all, then authority for the
//! optional helper, then kernel support, then this build's own gap. It runs
//! outwards from the conditions with no remedy to the conditions with one:
//! telling somebody to grant `CAP_BPF` on a macOS laptop wastes the time the
//! report was supposed to save.
//!
//! # The refusal at the end
//!
//! When every check passes, [`EbpfLoader::load`] reports
//! [`LoaderUnavailable::LoaderNotBuilt`], because there is no kernel side
//! program object in this build to load. That is where the `bpf(2)` calls will
//! go, in a module named `syscall` that will hold this crate's entire share of
//! the workspace's `unsafe` exception.
//!
//! It is worth being exact about why that refusal is preferable to code that
//! tries. ADR-014 §4 put it as a comparison: a loader whose foreign function
//! path has never been compiled by any gate in the development environment says
//! "I am loading" and has not been checked, while this says "I am not loading,
//! and here is the reason". The first is the failure mode this entire product
//! exists to expose, appearing inside the product.

use crate::capability::Capabilities;
use crate::hook::Hook;
use crate::platform::HostPlatform;
use crate::record::RawEvent;
use crate::unavailable::LoaderUnavailable;

/// One read of the ring buffer.
///
/// `dropped` is not an error path. A fixed size buffer under load loses records,
/// `network-sensor/spec.md` §8 requires the count to reach the coverage
/// statement, and a batch type that could not express the loss would make it
/// disappear at the first hop.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawBatch {
    pub events: Vec<RawEvent>,
    pub dropped: u64,
}

/// The kernel side of the sensor.
///
/// Holds no state today because it owns no descriptors today. When it owns
/// them, `Copy` has to go and the sensor's `EbpfFlowSource` will have to stop
/// deriving `Clone`, since two handles to one ring buffer would each read half
/// the records.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EbpfLoader;

impl EbpfLoader {
    /// Loads and attaches the requested programs, or says why it cannot.
    ///
    /// The hooks and the capabilities are both passed in rather than discovered,
    /// so this cannot decide for itself to attach a program the caller's
    /// privilege evaluation did not allow. The capabilities are re-checked here
    /// even though the caller already evaluated them, because the check that
    /// matters is the one immediately before the syscall: a process can lose
    /// authority between the two.
    pub fn load(
        &mut self,
        platform: HostPlatform,
        capabilities: &Capabilities,
        hooks: &[Hook],
    ) -> Result<(), LoaderUnavailable> {
        if !platform.supports_ebpf() {
            return Err(LoaderUnavailable::UnsupportedPlatform);
        }

        if !capabilities.may_load_programs() {
            return Err(LoaderUnavailable::MissingCapability);
        }

        // Refused rather than trimmed. Attaching what is permitted and dropping
        // the rest would leave a sensor running with a plan nobody asked for and
        // no record of the difference; the caller decides what to do without the
        // helper, and it already has a way to ask for a plan that omits it.
        if hooks.iter().any(|hook| hook.needs_traffic_control())
            && !capabilities.may_attach_traffic_control()
        {
            return Err(LoaderUnavailable::MissingCapability);
        }

        if !capabilities.btf_available {
            return Err(LoaderUnavailable::KernelUnsupported);
        }

        // Everything a machine can supply is here. What is missing is in this
        // build, and it says so rather than reporting a machine problem that
        // does not exist.
        Err(LoaderUnavailable::LoaderNotBuilt)
    }

    /// Reads whatever the ring buffer holds, along with what it lost.
    ///
    /// Always empty, and reachable only if a caller ignored the refusal from
    /// [`Self::load`]. An empty batch is the correct answer here and nowhere
    /// else: nothing was attached, so nothing was seen, and the sensor states
    /// that through the load error rather than by handing back a plausible
    /// looking empty result.
    pub fn poll(&mut self) -> RawBatch {
        RawBatch::default()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn capable() -> Capabilities {
        Capabilities {
            cap_bpf: true,
            cap_perfmon: true,
            cap_net_admin: true,
            root: false,
            btf_available: true,
        }
    }

    /// The six process context hooks, which is what a grant without
    /// `CAP_NET_ADMIN` produces.
    const ATTRIBUTING_HOOKS: [Hook; 6] = [
        Hook::KprobeTcpV4Connect,
        Hook::KprobeTcpV6Connect,
        Hook::KprobeUdpSendmsg,
        Hook::KprobeTcpSendmsg,
        Hook::KprobeTcpRecvmsg,
        Hook::KprobeTcpClose,
    ];

    fn every_hook() -> Vec<Hook> {
        let mut hooks = ATTRIBUTING_HOOKS.to_vec();
        hooks.push(Hook::TrafficControlEgress);
        hooks.push(Hook::TrafficControlIngress);
        hooks
    }

    fn load_on(
        platform: HostPlatform,
        capabilities: &Capabilities,
        hooks: &[Hook],
    ) -> LoaderUnavailable {
        EbpfLoader
            .load(platform, capabilities, hooks)
            .expect_err("this build has no program object, so no load can succeed")
    }

    #[test]
    fn a_fully_permitted_load_still_reports_that_this_build_carries_no_loader() {
        // The honest end state, and the one this milestone ships. If this ever
        // starts returning `Ok`, something claimed to have loaded a program that
        // does not exist.
        assert_eq!(
            load_on(HostPlatform::Linux, &capable(), &every_hook()),
            LoaderUnavailable::LoaderNotBuilt
        );
    }

    #[test]
    fn off_linux_the_cause_is_the_platform_and_not_the_missing_build() {
        // The two remedies are different: one is "build the loader", the other
        // is "there is nothing to build for this machine in v1".
        assert_eq!(
            load_on(HostPlatform::Other, &capable(), &every_hook()),
            LoaderUnavailable::UnsupportedPlatform
        );
    }

    #[test]
    fn the_platform_is_reported_before_anything_a_grant_could_fix() {
        // On a machine with no mechanism at all, capability advice is noise, and
        // an operator who follows it has been sent to do something that changes
        // nothing.
        assert_eq!(
            load_on(HostPlatform::Other, &Capabilities::default(), &every_hook()),
            LoaderUnavailable::UnsupportedPlatform
        );
    }

    #[test]
    fn without_the_capability_pair_the_loader_does_not_start() {
        assert_eq!(
            load_on(
                HostPlatform::Linux,
                &Capabilities::default(),
                &ATTRIBUTING_HOOKS
            ),
            LoaderUnavailable::MissingCapability
        );
    }

    #[test]
    fn a_missing_capability_is_reported_before_a_kernel_limit() {
        // An unprivileged process cannot read whether the kernel exposes BTF in
        // the first place, so reporting the kernel would be reporting a
        // conclusion nobody was in a position to reach.
        let neither = Capabilities {
            btf_available: false,
            ..Capabilities::default()
        };
        assert_eq!(
            load_on(HostPlatform::Linux, &neither, &ATTRIBUTING_HOOKS),
            LoaderUnavailable::MissingCapability
        );
    }

    #[test]
    fn a_kernel_without_btf_is_not_reported_as_a_permission_problem() {
        // Granting capabilities would not fix it, so the report must not send an
        // operator to do that.
        let no_btf = Capabilities {
            btf_available: false,
            ..capable()
        };
        assert_eq!(
            load_on(HostPlatform::Linux, &no_btf, &ATTRIBUTING_HOOKS),
            LoaderUnavailable::KernelUnsupported
        );
    }

    #[test]
    fn asking_for_the_payload_helper_without_net_admin_is_refused_outright() {
        // Not trimmed to what is permitted. A loader that quietly dropped the
        // two `tc` programs would leave the sensor believing it had SNI
        // resolution it does not have, and the loss would never be declared.
        let no_net_admin = Capabilities {
            cap_net_admin: false,
            ..capable()
        };
        assert_eq!(
            load_on(HostPlatform::Linux, &no_net_admin, &every_hook()),
            LoaderUnavailable::MissingCapability
        );
    }

    #[test]
    fn without_net_admin_a_plan_that_omits_the_helper_gets_all_the_way_through() {
        // ADR-008's rule: the payload helper is resolution, not correctness.
        // Losing `CAP_NET_ADMIN` costs server names, never the sensor.
        let no_net_admin = Capabilities {
            cap_net_admin: false,
            ..capable()
        };
        assert_eq!(
            load_on(HostPlatform::Linux, &no_net_admin, &ATTRIBUTING_HOOKS),
            LoaderUnavailable::LoaderNotBuilt
        );
    }

    #[test]
    fn root_gets_through_every_check_without_holding_a_single_capability() {
        // Supported and discouraged. Refusing it would push operators toward
        // worse workarounds than running one binary as root.
        let root = Capabilities {
            root: true,
            btf_available: true,
            ..Capabilities::default()
        };
        assert_eq!(
            load_on(HostPlatform::Linux, &root, &every_hook()),
            LoaderUnavailable::LoaderNotBuilt
        );
    }

    #[test]
    fn a_load_that_was_refused_hands_back_no_events_and_no_losses() {
        // Not "no events" as a plausible looking result: the caller was already
        // told why, and this must not look like a quiet network.
        let mut loader = EbpfLoader;
        let _ = loader.load(HostPlatform::current(), &capable(), &every_hook());
        let batch = loader.poll();
        assert!(batch.events.is_empty());
        assert_eq!(batch.dropped, 0);
    }

    #[test]
    fn the_same_machine_gets_the_same_answer_every_time() {
        // The cause reaches a report, and a report has to be diffable. A gate
        // with any order dependence in it would make two runs on one machine
        // produce two different coverage statements.
        let mut loader = EbpfLoader;
        let first = loader.load(HostPlatform::Linux, &capable(), &every_hook());
        let second = loader.load(HostPlatform::Linux, &capable(), &every_hook());
        assert_eq!(first, second);
    }

    #[test]
    fn an_empty_hook_list_is_not_treated_as_a_reason_to_skip_the_checks() {
        // A caller that asked for nothing still has to be told what this build
        // cannot do, or it will read the absence of an error as a working
        // sensor.
        assert_eq!(
            load_on(HostPlatform::Linux, &capable(), &[]),
            LoaderUnavailable::LoaderNotBuilt
        );
        assert_eq!(
            load_on(HostPlatform::Linux, &Capabilities::default(), &[]),
            LoaderUnavailable::MissingCapability
        );
    }
}
