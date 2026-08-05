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
//! # What happens when every check passes
//!
//! It depends on whether this binary carries a kernel side object, and the
//! difference is decided at build time by `build.rs` rather than at run time:
//!
//! - **With one** (`periskop_kernel_object`, Linux only), the programs are
//!   loaded and attached, the capabilities that allowed it are dropped
//!   immediately afterwards (`network-sensor/spec.md` §9), and [`Self::poll`]
//!   starts returning what the ring buffer holds.
//! - **Without one**, which is every build on the machine this repository is
//!   developed on, [`EbpfLoader::load`] reports
//!   [`LoaderUnavailable::LoaderNotBuilt`]. That is the truth about that binary,
//!   not a placeholder: it carries no program, so it observes nothing, and it
//!   says which of the two it is.
//!
//! ADR-014 §4 put the reason for keeping the second path exact: a loader that
//! says "I am loading" without any gate having compiled the path is worse than
//! one that says "I am not loading, and here is why". That comparison is why
//! `loader_not_built` survives as a first class answer even now that the loading
//! path exists.
//!
//! # Detail beside the cause
//!
//! The cause vocabulary is closed on purpose (see [`LoaderUnavailable`]): five
//! labels where there were four would reach reports with no remedy column for
//! the fifth. But a verifier rejection has something specific to say, and losing
//! it would leave an operator with "the kernel cannot host the programs" and no
//! way to find out why. So the sentence the kernel produced is kept beside the
//! cause, in [`EbpfLoader::last_refusal_detail`], where a gate artefact and a
//! log line can carry it and a report does not have to.

use crate::capability::Capabilities;
use crate::hook::Hook;
use crate::platform::HostPlatform;
use crate::record::RawEvent;
use crate::unavailable::LoaderUnavailable;

use crate::object;

#[cfg(all(target_os = "linux", periskop_kernel_object))]
use crate::{attached::Attached, attached::OpenError, syscall};

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
    /// Frames that arrived and the decoder refused.
    ///
    /// Separate from `dropped` because the two are different losses with
    /// different remedies: a dropped frame is a buffer that overran under load,
    /// and an undecodable one is a kernel object that does not share this
    /// build's record layout. Folding them together would let a version mismatch
    /// present itself as a busy machine.
    pub undecodable: u64,
}

/// The kernel side of the sensor.
///
/// Owns the descriptors on a build that has a program object, which is why it is
/// no longer `Copy` or `Clone`: two handles on one ring buffer would each read
/// half the records and neither would know it. The sensor's `EbpfFlowSource`
/// lost its derived `Clone` for the same reason and in the same change.
#[derive(Default)]
pub struct EbpfLoader {
    /// Everything the kernel is holding for this loader. Dropping it detaches
    /// every program.
    #[cfg(all(target_os = "linux", periskop_kernel_object))]
    attached: Option<Attached>,
    /// What the kernel said about the last refusal, when it said anything.
    ///
    /// Cleared at the start of every load, so it can never describe an older
    /// failure than the one being reported.
    refusal_detail: Option<String>,
}

/// Written out rather than derived because the interesting fact about a loader
/// is whether it is holding anything, and the kernel objects it holds have no
/// useful debug form.
impl std::fmt::Debug for EbpfLoader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EbpfLoader")
            .field("attached", &self.is_attached())
            .field("refusal_detail", &self.refusal_detail)
            .finish()
    }
}

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
        // Cleared first, so a detail left over from an earlier attempt cannot be
        // read as an explanation of this one.
        self.refusal_detail = None;

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

        // Everything a machine can supply is here. What happens next depends on
        // whether this build carries a program object at all.
        self.open(hooks)
    }

    /// What the kernel said when it refused, when it said anything.
    ///
    /// Never part of a report. It exists so that a verifier rejection, which is
    /// the one refusal that means the program is wrong rather than the machine,
    /// reaches whoever has to fix it instead of being flattened into a label.
    pub fn last_refusal_detail(&self) -> Option<&str> {
        self.refusal_detail.as_deref()
    }

    /// Whether the kernel is currently holding programs for this loader.
    pub fn is_attached(&self) -> bool {
        #[cfg(all(target_os = "linux", periskop_kernel_object))]
        {
            self.attached.is_some()
        }
        #[cfg(not(all(target_os = "linux", periskop_kernel_object)))]
        {
            false
        }
    }

    /// A hook the program table has nothing for, if the plan names one.
    ///
    /// Consulted by both builds, and before anything reaches a kernel rather
    /// than partway through: attaching what is present and stopping at the first
    /// hook with no program would leave programs loaded that nothing is reading,
    /// and the sensor believing it observes something it does not.
    fn missing_program(hooks: &[Hook]) -> Option<String> {
        hooks
            .iter()
            .find(|hook| !object::carries(**hook))
            .map(|hook| {
                format!(
                    "no program is defined for {} in any build of this crate",
                    hook.attach_point()
                )
            })
    }

    /// The build with no program object in it.
    #[cfg(not(all(target_os = "linux", periskop_kernel_object)))]
    fn open(&mut self, hooks: &[Hook]) -> Result<(), LoaderUnavailable> {
        // Two different absences, and the detail says which. One is a hook
        // nothing in this crate ever attaches; the other is this binary having
        // been built without the object. An operator sent to build the loader
        // when the first is the problem would build it and see no change.
        self.refusal_detail = Some(Self::missing_program(hooks).unwrap_or_else(|| {
            "this binary was built without a kernel side program object".to_owned()
        }));
        Err(LoaderUnavailable::LoaderNotBuilt)
    }

    /// Loads, attaches, and then gives up the authority that allowed it.
    ///
    /// The order is the two stage structure `network-sensor/spec.md` §9
    /// requires, and the drop is checked rather than assumed: a `capset` that
    /// returned zero without taking effect would leave a long lived observer
    /// holding the authority to load kernel programs, which is the quietest
    /// possible way to fail this requirement. A drop that did not take effect
    /// detaches everything and refuses, because a sensor that kept running would
    /// be running under a structure nobody agreed to.
    #[cfg(all(target_os = "linux", periskop_kernel_object))]
    fn open(&mut self, hooks: &[Hook]) -> Result<(), LoaderUnavailable> {
        if let Some(missing) = Self::missing_program(hooks) {
            self.refusal_detail = Some(missing);
            return Err(LoaderUnavailable::LoaderNotBuilt);
        }

        // The reading that decides whether the syscall will succeed is the one
        // immediately before it. A kernel that would not answer at all is not
        // treated as a refusal: the caller's own evaluation already passed, and
        // inventing a denial from an unreadable interface would report a
        // permission problem nobody has.
        if let Some(live) = syscall::effective_capabilities() {
            if !live.may_load_programs() {
                self.refusal_detail = Some(
                    "the capabilities were dropped between the privilege check and the load"
                        .to_owned(),
                );
                return Err(LoaderUnavailable::MissingCapability);
            }
        }

        let (monotonic_ns, epoch_ns) = self.clock()?;
        let attached = Attached::open(hooks, monotonic_ns, epoch_ns).map_err(|error| {
            let (cause, detail) = describe(error);
            self.refusal_detail = Some(detail);
            cause
        })?;

        // Held before the drop so that a failed drop detaches it. `attached`
        // going out of scope is what closes every descriptor.
        match syscall::drop_load_capabilities() {
            Some(remaining) if !remaining.may_load_programs() => {
                self.attached = Some(attached);
                Ok(())
            }
            other => {
                self.refusal_detail = Some(match other {
                    Some(_) => "the capabilities survived the drop this sensor requires after \
                                loading (network-sensor/spec.md §9)"
                        .to_owned(),
                    None => "the capabilities could not be dropped after loading \
                             (network-sensor/spec.md §9)"
                        .to_owned(),
                });
                Err(LoaderUnavailable::KernelUnsupported)
            }
        }
    }

    /// The two clock readings the kernel program cannot take for itself.
    #[cfg(all(target_os = "linux", periskop_kernel_object))]
    fn clock(&mut self) -> Result<(u64, u64), LoaderUnavailable> {
        let monotonic_ns = syscall::monotonic_ns().ok_or(LoaderUnavailable::KernelUnsupported);
        let epoch_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|since| u64::try_from(since.as_nanos()).ok())
            .ok_or(LoaderUnavailable::KernelUnsupported);
        match (monotonic_ns, epoch_ns) {
            (Ok(monotonic_ns), Ok(epoch_ns)) => Ok((monotonic_ns, epoch_ns)),
            _ => {
                // Refused rather than defaulted. A kernel program handed a wrong
                // offset stamps every record with a wall clock time that is
                // wrong by the machine's uptime, and nothing downstream can tell.
                self.refusal_detail = Some(
                    "this machine would not report both a monotonic and a wall clock reading, \
                          so the kernel program could not be told what time it is"
                        .to_owned(),
                );
                Err(LoaderUnavailable::KernelUnsupported)
            }
        }
    }

    /// Reads whatever the ring buffer holds, along with what it lost.
    ///
    /// On a build with nothing attached this is empty, and reachable only if a
    /// caller ignored the refusal from [`Self::load`]. An empty batch is the
    /// correct answer there and nowhere else: nothing was attached, so nothing
    /// was seen, and the sensor states that through the load error rather than
    /// by handing back a plausible looking empty result.
    pub fn poll(&mut self) -> RawBatch {
        #[cfg(all(target_os = "linux", periskop_kernel_object))]
        {
            let Some(attached) = self.attached.as_mut() else {
                return RawBatch::default();
            };
            let mut batch = RawBatch {
                dropped: attached.dropped(),
                ..RawBatch::default()
            };
            for frame in attached.drain() {
                match RawEvent::decode(&frame) {
                    Ok(event) => batch.events.push(event),
                    // Counted, never repaired. A frame this build cannot read
                    // was written by something that does not share its layout,
                    // and guessing at the intent would put invented values in a
                    // report.
                    Err(_) => batch.undecodable = batch.undecodable.saturating_add(1),
                }
            }
            batch
        }
        #[cfg(not(all(target_os = "linux", periskop_kernel_object)))]
        {
            RawBatch::default()
        }
    }
}

/// The cause a report carries, and the sentence it does not.
///
/// The mapping is the only place a kernel refusal becomes one of the four
/// labels, so it is the only place to check that none of them is being used to
/// mean something it does not.
#[cfg(all(target_os = "linux", periskop_kernel_object))]
fn describe(error: OpenError) -> (LoaderUnavailable, String) {
    match error {
        // The kernel would not take these programs. That is what the label says,
        // and the verifier's own words go in the detail because "a newer kernel"
        // is the remedy for one of the two reasons this happens and not for the
        // other.
        OpenError::Rejected(detail) => (LoaderUnavailable::KernelUnsupported, detail),
        OpenError::ClockUnreadable => (
            LoaderUnavailable::KernelUnsupported,
            "the monotonic clock read later than the wall clock, so no offset could be derived"
                .to_owned(),
        ),
        OpenError::MapMissing(name) => (
            LoaderUnavailable::LoaderNotBuilt,
            format!("the program object declares no map named {name}"),
        ),
        OpenError::ProgramMissing(name) => (
            LoaderUnavailable::LoaderNotBuilt,
            format!("the program object contains no program named {name}"),
        ),
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
        EbpfLoader::default()
            .load(platform, capabilities, hooks)
            .expect_err(
                "these tests run where no kernel object is compiled in, so no load can succeed",
            )
    }

    /// True where these tests can safely ask for a load that would otherwise
    /// reach the kernel.
    ///
    /// A unit test must not attach programs to the machine running it. Two of
    /// the tests below drive a plan every check passes, which on a build with a
    /// program object and a privileged process would do exactly that, so they
    /// are compiled only where it cannot happen. The rest ask for plans that are
    /// refused on grounds no build changes: the platform, the capabilities, and
    /// a hook this object carries no program for.
    const KERNEL_OBJECT_COMPILED_IN: bool = cfg!(all(target_os = "linux", periskop_kernel_object));

    #[test]
    fn a_plan_including_the_payload_helper_is_refused_by_every_build_of_this_crate() {
        // No build of this crate carries a `clsact` classifier, so the full plan
        // ends in the same refusal whether or not a program object is compiled
        // in. If a classifier is ever added, this goes red and whoever added it
        // has to say so in the gate artefact, which lists name resolution among
        // the things it does not prove.
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
        if KERNEL_OBJECT_COMPILED_IN {
            // Skipped by construction rather than by an environment guess: this
            // plan passes every check, so on a build that can load it the next
            // thing that happens is programs entering the kernel of whatever
            // machine is running the suite. The equivalent assertion for that
            // build lives in `tests/kernel_required.rs`, which is `#[ignore]`d
            // and run deliberately.
            return;
        }
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
        let mut loader = EbpfLoader::default();
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
        let mut loader = EbpfLoader::default();
        let first = loader.load(HostPlatform::Linux, &capable(), &every_hook());
        let second = loader.load(HostPlatform::Linux, &capable(), &every_hook());
        assert_eq!(first, second);
    }

    #[test]
    fn an_empty_hook_list_is_not_treated_as_a_reason_to_skip_the_checks() {
        // A caller that asked for nothing still has to be told what this build
        // cannot do, or it will read the absence of an error as a working
        // sensor.
        // The refusal that holds in every build: an empty plan does not buy a
        // pass on the privilege check.
        assert_eq!(
            load_on(HostPlatform::Linux, &Capabilities::default(), &[]),
            LoaderUnavailable::MissingCapability
        );
        if KERNEL_OBJECT_COMPILED_IN {
            return;
        }
        assert_eq!(
            load_on(HostPlatform::Linux, &capable(), &[]),
            LoaderUnavailable::LoaderNotBuilt
        );
    }
}
