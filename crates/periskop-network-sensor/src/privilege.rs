//! What the sensor is allowed to do, and what it says when it is not.
//!
//! Loading an eBPF program needs privileges a scan does not. The rule that
//! follows is not negotiable: when the privileges are absent the sensor does
//! not start, states why in a fixed vocabulary, and the scan carries on. An
//! observation tool that makes the product unusable when it cannot observe has
//! inverted its own purpose, so no function in this crate returns a `Result`
//! that would let a caller turn a denied sensor into a failed run.
//!
//! Least privilege is the other half. `CAP_BPF` plus `CAP_PERFMON` is enough
//! and full root is never required; root is accepted because operators have it
//! and refusing would push them toward worse workarounds, but it is flagged so
//! the report can say the sensor ran with more authority than it needed.
//!
//! **Not here yet:** dropping privileges after the programs are loaded, which
//! the component spec requires in two phases. It needs a syscall this build
//! cannot make (ADR-002 forbids `unsafe`, and no dependency may be added
//! without an ADR) and it belongs next to the code that opens the descriptors,
//! which arrives with the real loader. Stated rather than omitted.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::platform::SensorPlatformClass;

/// Where the kernel publishes the state of the running process.
///
/// Read as text rather than through a capability library: the parse is a few
/// lines, and a new dependency needs an ADR. On a machine without procfs the
/// read simply fails and the answer is "no privileges", which is the correct
/// answer there anyway.
const PROC_SELF_STATUS: &str = "/proc/self/status";

/// CO-RE needs BTF. Its absence is a kernel limit, not a permission problem,
/// and the two must not arrive at the report wearing the same label.
const BTF_VMLINUX: &str = "/sys/kernel/btf/vmlinux";

/// Capability bit positions, from the kernel's `capability.h`.
const CAP_NET_ADMIN: u32 = 12;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

/// Why the sensor is not running.
///
/// A fixed vocabulary rather than a message, because this value is declared in
/// a report and a reader has to be able to count and compare occurrences of it.
/// The variants are distinct causes with distinct remedies; merging any two
/// would tell an operator to fix the wrong thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorUnavailable {
    /// This build observes nothing on this platform. Remedy: none in v1.
    UnsupportedPlatform,
    /// Neither the capabilities nor root. Remedy: grant `CAP_BPF` and
    /// `CAP_PERFMON`.
    MissingCapability,
    /// The kernel cannot host the programs, for example with no BTF. Remedy: a
    /// newer kernel, or the pcap path once it exists.
    ///
    /// Strictly about what the kernel *can* do. It never covers a question this
    /// build failed to ask; see [`Self::PrivilegeStateUnreadable`].
    KernelUnsupported,
    /// The privileges were there and this build carries no loader to use them.
    LoaderNotBuilt,
    /// The machine could not be asked what this process holds.
    ///
    /// `/proc/self/status` was missing, unreadable, or carried no capability
    /// line this build recognises. Remedy: mount procfs, or run somewhere the
    /// process can read its own status; granting capabilities does not help,
    /// and neither does a newer kernel.
    ///
    /// A separate value rather than a shade of one of the four above, because
    /// each of those names a remedy and all three plausible substitutes send the
    /// operator somewhere useless. `missing_capability` says grant `CAP_BPF` to a
    /// process that may already hold it. `kernel_unsupported` says the kernel is
    /// too old, when a perfectly capable kernel is simply not being asked. An
    /// unreadable privilege state is not a kernel limit; it is our own blind
    /// spot, and a report that cannot tell the two apart sends somebody to
    /// upgrade a kernel that was never the problem.
    PrivilegeStateUnreadable,
}

impl SensorUnavailable {
    /// The fixed label a report carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::MissingCapability => "missing_capability",
            Self::KernelUnsupported => "kernel_unsupported",
            Self::LoaderNotBuilt => "loader_not_built",
            Self::PrivilegeStateUnreadable => "privilege_state_unreadable",
        }
    }
}

/// Whether the kernel's statement about this process could be read at all.
///
/// Kept apart from the capability flags because the two answer different
/// questions and point at different remedies. All flags false can mean "the
/// kernel says this process holds nothing", which an operator fixes by granting
/// capabilities, or "nothing could be read", which granting capabilities does
/// not fix and which the report used to present as the first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PrivilegeStatement {
    /// `/proc/self/status` was read and its capability line parsed. The flags
    /// below are the kernel's answer.
    Read,
    /// The file could not be read, or carried no capability line this build
    /// recognises. The flags carry no answer, and the default is this one so a
    /// value nobody filled in cannot claim to be a measurement.
    #[default]
    Unreadable,
}

/// What the machine grants this process.
///
/// Plain data with no probing of its own, so the evaluation below can be tested
/// on any machine, including one where the answer is fixed by the operating
/// system.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Privileges {
    /// `None` when it could not be established, which is treated as "not root":
    /// assuming authority nobody confirmed is the wrong direction to guess in.
    pub effective_uid: Option<u32>,
    pub cap_bpf: bool,
    pub cap_perfmon: bool,
    /// Only the `tc` helper needs this one. Without it the sensor still runs
    /// and loses SNI resolution, which is a declared loss and not an error.
    pub cap_net_admin: bool,
    pub btf_available: bool,
    /// Whether the flags above are an answer or the absence of one.
    pub statement: PrivilegeStatement,
}

impl Privileges {
    pub fn is_root(&self) -> bool {
        self.effective_uid == Some(0)
    }

    /// Reads what this process actually has.
    pub fn probe() -> Self {
        let status = std::fs::read_to_string(PROC_SELF_STATUS).unwrap_or_default();
        Self::from_proc_status(&status, Path::new(BTF_VMLINUX).exists())
    }

    /// Parses the `/proc/self/status` fields that matter.
    ///
    /// Split from [`Self::probe`] so the parse is exercised on every platform
    /// the workspace builds on, not only on the one where the file exists. An
    /// unreadable or unrecognised blob yields no privileges **and says so**,
    /// which fails closed twice over: the sensor declines to start, and the
    /// reason it states is the one an operator can act on.
    pub fn from_proc_status(status: &str, btf_available: bool) -> Self {
        let capabilities = status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:"))
            .and_then(|value| u64::from_str_radix(value.trim(), 16).ok());

        // Uid: real effective saved filesystem. The effective one decides what
        // the process may do right now.
        let effective_uid = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|value| value.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok());

        let Some(capabilities) = capabilities else {
            // No capability line means no answer, not an answer of zero. The
            // uid is dropped with it: on its own it would let a process read as
            // root on the strength of half a file this build could not parse.
            return Self {
                btf_available,
                ..Self::default()
            };
        };

        Self {
            effective_uid,
            cap_bpf: has_capability(capabilities, CAP_BPF),
            cap_perfmon: has_capability(capabilities, CAP_PERFMON),
            cap_net_admin: has_capability(capabilities, CAP_NET_ADMIN),
            btf_available,
            statement: PrivilegeStatement::Read,
        }
    }
}

fn has_capability(mask: u64, bit: u32) -> bool {
    mask & (1u64 << bit) != 0
}

/// What the sensor may do once it has been allowed to start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    /// Whether the `tc` helper can be attached. When false the sensor runs
    /// without SNI: a loss of resolution, declared per flow, not a loss of
    /// correctness.
    pub tc_available: bool,
    /// The sensor was started with more authority than it needs. Kept so the
    /// run can say so rather than quietly accepting it.
    pub elevated_as_root: bool,
}

/// Decides whether the sensor may start.
///
/// The checks run in a fixed order so that the reason a report carries does not
/// depend on which condition happened to be evaluated first: platform, then
/// whether the machine could be asked at all, then privileges, then kernel
/// support. A machine can fail more than one at once, and an operator reading
/// the report needs the same answer every time.
///
/// **Why an unreadable status has a value of its own.** It used to be reported
/// as `missing_capability`, which told an operator on a host with no procfs to
/// grant `CAP_BPF` to a process that may well have held it already. It was then
/// reported as `kernel_unsupported`, which is wrong in the other direction: a
/// perfectly capable kernel gets blamed for a question this build could not ask,
/// and the remedy that label implies is a kernel upgrade that changes nothing.
/// The vocabulary now carries [`SensorUnavailable::PrivilegeStateUnreadable`]
/// (ADR-014 section 8.6a), and `kernel_unsupported` keeps its narrow meaning:
/// what the kernel cannot do, never what we failed to read.
pub fn evaluate(
    platform: SensorPlatformClass,
    privileges: &Privileges,
) -> Result<Grant, SensorUnavailable> {
    if platform != SensorPlatformClass::LinuxEbpf {
        return Err(SensorUnavailable::UnsupportedPlatform);
    }

    if privileges.statement == PrivilegeStatement::Unreadable {
        return Err(SensorUnavailable::PrivilegeStateUnreadable);
    }

    let by_capability = privileges.cap_bpf && privileges.cap_perfmon;
    if !by_capability && !privileges.is_root() {
        return Err(SensorUnavailable::MissingCapability);
    }

    if !privileges.btf_available {
        return Err(SensorUnavailable::KernelUnsupported);
    }

    Ok(Grant {
        tc_available: privileges.cap_net_admin || privileges.is_root(),
        elevated_as_root: privileges.is_root(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn capable() -> Privileges {
        Privileges {
            effective_uid: Some(1000),
            cap_bpf: true,
            cap_perfmon: true,
            cap_net_admin: true,
            btf_available: true,
            statement: PrivilegeStatement::Read,
        }
    }

    /// A machine that answered, and answered that this process holds nothing.
    ///
    /// Not `Privileges::default()`, which is the machine that did not answer at
    /// all. Keeping the two apart in the fixtures is the point of the finding.
    fn unprivileged() -> Privileges {
        Privileges {
            statement: PrivilegeStatement::Read,
            ..Privileges::default()
        }
    }

    #[test]
    fn capabilities_without_root_are_enough() {
        // The least privilege claim, made testable: nothing in the accepting
        // path looks at uid 0.
        let grant = evaluate(SensorPlatformClass::LinuxEbpf, &capable()).unwrap();
        assert!(grant.tc_available);
        assert!(!grant.elevated_as_root);
    }

    #[test]
    fn root_is_accepted_and_flagged() {
        let root = Privileges {
            effective_uid: Some(0),
            cap_bpf: false,
            cap_perfmon: false,
            cap_net_admin: false,
            btf_available: true,
            statement: PrivilegeStatement::Read,
        };
        let grant = evaluate(SensorPlatformClass::LinuxEbpf, &root).unwrap();
        assert!(grant.elevated_as_root);
        assert!(grant.tc_available);
    }

    #[test]
    fn a_denied_sensor_names_a_cause_an_operator_can_act_on() {
        let denied = evaluate(SensorPlatformClass::LinuxEbpf, &unprivileged()).unwrap_err();
        assert_eq!(denied, SensorUnavailable::MissingCapability);
        assert_eq!(denied.as_str(), "missing_capability");
    }

    #[test]
    fn half_the_capabilities_is_not_enough() {
        let partial = Privileges {
            cap_bpf: true,
            ..unprivileged()
        };
        assert_eq!(
            evaluate(SensorPlatformClass::LinuxEbpf, &partial),
            Err(SensorUnavailable::MissingCapability)
        );
    }

    #[test]
    fn a_kernel_without_btf_is_not_a_permission_problem() {
        // Granting capabilities would not fix it, so the report must not send
        // an operator to do that.
        let no_btf = Privileges {
            btf_available: false,
            ..capable()
        };
        assert_eq!(
            evaluate(SensorPlatformClass::LinuxEbpf, &no_btf),
            Err(SensorUnavailable::KernelUnsupported)
        );
    }

    #[test]
    fn an_unsupported_platform_is_reported_before_anything_else() {
        // On a machine with no sensor at all, capability advice would be noise.
        assert_eq!(
            evaluate(SensorPlatformClass::None, &capable()),
            Err(SensorUnavailable::UnsupportedPlatform)
        );
        assert_eq!(
            evaluate(SensorPlatformClass::MacosPcap, &Privileges::default()),
            Err(SensorUnavailable::UnsupportedPlatform)
        );
    }

    #[test]
    fn missing_net_admin_costs_resolution_and_not_the_run() {
        let no_tc = Privileges {
            cap_net_admin: false,
            ..capable()
        };
        let grant = evaluate(SensorPlatformClass::LinuxEbpf, &no_tc).unwrap();
        assert!(!grant.tc_available);
    }

    #[test]
    fn a_status_file_that_could_not_be_read_is_not_reported_as_a_missing_capability() {
        // The finding, produced: a Linux host whose `/proc/self/status` cannot
        // be read (no procfs, a restricted sandbox, a format this build does
        // not recognise) used to answer `missing_capability`, which sends the
        // operator to grant `CAP_BPF` and `CAP_PERFMON`. The process may hold
        // both already; nothing about granting them makes the file readable, so
        // the remedy the report names cannot work. It then answered
        // `kernel_unsupported`, which names a remedy that is wrong in the other
        // direction: upgrading a kernel that was never the obstacle. BTF is
        // present here precisely so that a `kernel_unsupported` answer cannot be
        // explained away as a kernel limit.
        let unreadable = Privileges::from_proc_status("", true);
        assert_eq!(unreadable.statement, PrivilegeStatement::Unreadable);
        assert_eq!(
            evaluate(SensorPlatformClass::LinuxEbpf, &unreadable),
            Err(SensorUnavailable::PrivilegeStateUnreadable),
            "an unreadable privilege statement was reported as something an operator can act on"
        );
    }

    #[test]
    fn a_status_file_without_a_capability_line_states_nothing_rather_than_zero() {
        // A blob with a uid and no `CapEff:` is half an answer. Taking the uid
        // from it would let a process read as root on the strength of a file
        // this build could not parse, and the capability flags would read as a
        // kernel statement that the process holds nothing.
        let partial = Privileges::from_proc_status("Uid:\t0\t0\t0\t0\n", true);
        assert_eq!(partial.statement, PrivilegeStatement::Unreadable);
        assert_eq!(partial.effective_uid, None);
        assert!(!partial.is_root());
    }

    #[test]
    fn the_status_blob_is_parsed_the_way_the_kernel_writes_it() {
        // CAP_BPF is bit 39 and CAP_PERFMON bit 38, so the two together are
        // 0xc000000000; CAP_NET_ADMIN is bit 12, which this mask lacks.
        let status = "Name:\tperiskop\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t000000c000000000\n";
        let privileges = Privileges::from_proc_status(status, true);
        assert!(privileges.cap_bpf);
        assert!(privileges.cap_perfmon);
        assert!(!privileges.cap_net_admin);
        assert_eq!(privileges.effective_uid, Some(1000));
        assert!(!privileges.is_root());
    }

    #[test]
    fn a_root_status_blob_reads_as_root() {
        let status = "Uid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\n";
        let privileges = Privileges::from_proc_status(status, true);
        assert!(privileges.is_root());
        assert!(privileges.cap_net_admin);
    }

    #[test]
    fn an_unreadable_status_blob_fails_closed() {
        // A machine with no procfs, or a format this build does not recognise.
        // Assuming privileges nobody confirmed would make the sensor try, fail
        // somewhere deeper, and report the wrong cause.
        let privileges = Privileges::from_proc_status("", false);
        assert!(!privileges.cap_bpf);
        assert!(!privileges.is_root());
        assert_eq!(privileges.effective_uid, None);
        assert_eq!(
            evaluate(SensorPlatformClass::LinuxEbpf, &privileges),
            Err(SensorUnavailable::PrivilegeStateUnreadable)
        );
    }

    #[test]
    fn an_unreadable_privilege_state_is_not_a_kernel_limit() {
        // The two conditions are separable and the labels must separate them. A
        // machine with BTF and no readable status is not the same machine as one
        // with a readable status and no BTF, and an operator handed one label for
        // both would fix whichever of the two the label happened to name.
        let no_statement = Privileges::from_proc_status("", true);
        let no_btf = Privileges {
            btf_available: false,
            ..capable()
        };
        assert_eq!(
            evaluate(SensorPlatformClass::LinuxEbpf, &no_statement),
            Err(SensorUnavailable::PrivilegeStateUnreadable)
        );
        assert_eq!(
            evaluate(SensorPlatformClass::LinuxEbpf, &no_btf),
            Err(SensorUnavailable::KernelUnsupported)
        );
    }

    #[test]
    fn probing_this_machine_never_panics_and_never_over_claims() {
        // Runs on every platform in the workspace. Off Linux the reads fail and
        // the result has to be the honest empty one rather than a default that
        // says yes.
        let probed = Privileges::probe();
        if !cfg!(target_os = "linux") {
            assert_eq!(probed, Privileges::default());
        }
    }

    #[test]
    fn every_unavailable_reason_has_a_distinct_label() {
        let reasons = [
            SensorUnavailable::UnsupportedPlatform,
            SensorUnavailable::MissingCapability,
            SensorUnavailable::KernelUnsupported,
            SensorUnavailable::LoaderNotBuilt,
            SensorUnavailable::PrivilegeStateUnreadable,
        ];
        let labels: std::collections::BTreeSet<&str> = reasons.iter().map(|r| r.as_str()).collect();
        assert_eq!(labels.len(), reasons.len());
        for reason in reasons {
            assert_eq!(
                serde_json::to_value(reason).unwrap(),
                serde_json::json!(reason.as_str())
            );
        }
    }
}
