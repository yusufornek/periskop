//! What the machine granted the process that is about to load.
//!
//! Plain data with no probing of its own. The loader is handed this rather than
//! reading it, for the same reason the sensor hands the attach plan down rather
//! than letting the loader build one: a component that establishes its own
//! authority can conclude it has authority nobody gave it, and the failure then
//! surfaces halfway through a load sequence instead of before it.
//!
//! Reading `/proc/self/status` happens once, in
//! `periskop-network-sensor::privilege`, where it is parsed on every platform
//! the workspace builds on. Duplicating that parse here would put a second
//! answer to the same question in the tree, and the two would drift.
//!
//! The loader checks anyway rather than trusting the sensor's earlier
//! evaluation, and that is not belt and braces. Between the privilege
//! evaluation and the load there is a window: the process may have dropped
//! capabilities, moved namespace, or been re-executed. The check that matters
//! is the one immediately before the syscall.

/// The authority a load will actually be attempted with.
///
/// [`Default`] is the honest empty answer, which denies. Failing closed is the
/// right direction here: a sensor that assumes authority nobody confirmed tries,
/// fails deeper, and reports the wrong cause.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// `CAP_BPF`, which is what loading a program needs.
    pub cap_bpf: bool,
    /// `CAP_PERFMON`, which is what attaching a probe needs.
    pub cap_perfmon: bool,
    /// `CAP_NET_ADMIN`. Only the payload helper needs this one; without it the
    /// sensor runs and loses server name resolution, which is a declared loss
    /// rather than a failure (ADR-008).
    pub cap_net_admin: bool,
    /// The process is running as root. Accepted because operators have it and
    /// refusing would push them toward worse workarounds, and recorded so the
    /// run can say it used more authority than it needed.
    pub root: bool,
    /// The kernel exposes BTF, which CO-RE requires. Its absence is a kernel
    /// limit and not a permission problem, and the two must not reach a report
    /// wearing the same label.
    pub btf_available: bool,
}

impl Capabilities {
    /// Whether the programs may be loaded and the probes attached at all.
    ///
    /// The capability pair is checked first and root is only a fallback, so the
    /// least privilege claim in `network-sensor/spec.md` §9 is something the
    /// accepting path demonstrates rather than something the prose asserts.
    pub fn may_load_programs(self) -> bool {
        (self.cap_bpf && self.cap_perfmon) || self.root
    }

    /// Whether the `tc` payload helper may be attached.
    pub fn may_attach_traffic_control(self) -> bool {
        self.cap_net_admin || self.root
    }
}

#[cfg(test)]
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

    #[test]
    fn the_capability_pair_is_enough_and_root_is_never_consulted() {
        // The least privilege claim, made testable: nothing in the accepting
        // path looks at root.
        let capabilities = capable();
        assert!(capabilities.may_load_programs());
        assert!(capabilities.may_attach_traffic_control());
        assert!(!capabilities.root);
    }

    #[test]
    fn half_the_pair_does_not_load() {
        // `CAP_BPF` alone gets as far as the program load and then fails on the
        // probe attach, with half the programs already in the kernel.
        let half = Capabilities {
            cap_perfmon: false,
            ..capable()
        };
        assert!(!half.may_load_programs());
    }

    #[test]
    fn root_can_do_both_without_either_capability() {
        let root = Capabilities {
            root: true,
            ..Capabilities::default()
        };
        assert!(root.may_load_programs());
        assert!(root.may_attach_traffic_control());
    }

    #[test]
    fn net_admin_alone_does_not_buy_a_program_load() {
        // The payload helper is an addition to a working sensor, never a way
        // into one.
        let only_tc = Capabilities {
            cap_net_admin: true,
            ..Capabilities::default()
        };
        assert!(!only_tc.may_load_programs());
        assert!(only_tc.may_attach_traffic_control());
    }

    #[test]
    fn a_process_that_was_asked_nothing_is_granted_nothing() {
        // The default has to deny. A default that said yes would let a caller
        // that forgot to probe attempt a load and get the wrong error back.
        let unknown = Capabilities::default();
        assert!(!unknown.may_load_programs());
        assert!(!unknown.may_attach_traffic_control());
        assert!(!unknown.btf_available);
    }
}
