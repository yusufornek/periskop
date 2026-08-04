//! The tests that need a real machine, and are marked so rather than skipped.
//!
//! Everything else in this crate runs everywhere, because the seam was drawn so
//! that it could. What is left here genuinely depends on the machine underneath:
//! whether it is Linux, whether the kernel exposes BTF, and whether this process
//! was given `CAP_BPF`. None of those can be arranged inside a test.
//!
//! They are `#[ignore]`d with the reason in the attribute, so `cargo test`
//! prints the name and the word "ignored" and a reader can see what was not
//! checked. A test that quietly arranged to pass on the wrong machine, by
//! returning early or by asserting only what is true everywhere, would be worse
//! than no test: the run would be green and nobody would know the assertion had
//! not happened.
//!
//! Run them where they apply:
//!
//! ```text
//! sudo -E cargo test -p periskop-ebpf-loader -- --ignored
//! ```
//!
//! **These are the tests that fail first when the loader lands**, and that is
//! deliberate. Each one pins the current honest end state, which is that a
//! fully privileged Linux machine still has no program object to load. When
//! there is one, they go red and have to be rewritten to assert an attach.

use std::path::Path;

use periskop_ebpf_loader::{Capabilities, EbpfLoader, Hook, HostPlatform, LoaderUnavailable};

/// Where the kernel publishes the state of the running process.
const PROC_SELF_STATUS: &str = "/proc/self/status";

/// CO-RE needs this. Its absence is a kernel limit, not a permission problem.
const BTF_VMLINUX: &str = "/sys/kernel/btf/vmlinux";

/// Capability bit positions, from the kernel's `capability.h`.
const CAP_NET_ADMIN: u32 = 12;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

/// Reads this process's real authority off the running kernel.
///
/// Deliberately not the sensor's parser: these tests exist to check the machine,
/// so borrowing the production reader would make them agree with it by
/// construction even when both were wrong about the machine.
fn capabilities_of_this_process() -> Capabilities {
    let status = std::fs::read_to_string(PROC_SELF_STATUS).unwrap_or_default();
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .unwrap_or(0);
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|value| value.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u32>().ok());
    Capabilities {
        cap_bpf: effective & (1u64 << CAP_BPF) != 0,
        cap_perfmon: effective & (1u64 << CAP_PERFMON) != 0,
        cap_net_admin: effective & (1u64 << CAP_NET_ADMIN) != 0,
        root: uid == Some(0),
        btf_available: Path::new(BTF_VMLINUX).exists(),
    }
}

const EVERY_HOOK: [Hook; 8] = [
    Hook::KprobeTcpV4Connect,
    Hook::KprobeTcpV6Connect,
    Hook::KprobeUdpSendmsg,
    Hook::KprobeTcpSendmsg,
    Hook::KprobeTcpRecvmsg,
    Hook::KprobeTcpClose,
    Hook::TrafficControlEgress,
    Hook::TrafficControlIngress,
];

const ATTRIBUTING_HOOKS: [Hook; 6] = [
    Hook::KprobeTcpV4Connect,
    Hook::KprobeTcpV6Connect,
    Hook::KprobeUdpSendmsg,
    Hook::KprobeTcpSendmsg,
    Hook::KprobeTcpRecvmsg,
    Hook::KprobeTcpClose,
];

#[test]
#[ignore = "needs a Linux kernel with BTF and this process holding CAP_BPF and CAP_PERFMON; \
            neither is arrangeable on the macOS development machine or in an unprivileged runner"]
fn on_a_privileged_linux_kernel_the_only_thing_still_missing_is_the_program_object() {
    let capabilities = capabilities_of_this_process();
    // Asserted rather than skipped over. If the machine running this does not
    // meet the precondition, the honest outcome is a failure that says so, not a
    // pass that checked nothing.
    assert_eq!(
        HostPlatform::current(),
        HostPlatform::Linux,
        "this test asserts kernel behaviour and was run somewhere else"
    );
    assert!(
        capabilities.may_load_programs(),
        "run with CAP_BPF and CAP_PERFMON, or as root"
    );
    assert!(
        capabilities.btf_available,
        "this kernel exposes no BTF at {BTF_VMLINUX}, so CO-RE cannot work here"
    );

    assert_eq!(
        EbpfLoader.load(HostPlatform::current(), &capabilities, &ATTRIBUTING_HOOKS),
        Err(LoaderUnavailable::LoaderNotBuilt),
        "every machine side condition passed, so the only remaining cause must be this build"
    );
}

#[test]
#[ignore = "needs a Linux machine where this process holds CAP_NET_ADMIN, \
            which an unprivileged runner and the macOS development machine do not"]
fn on_a_linux_kernel_with_net_admin_the_payload_helper_is_permitted() {
    let capabilities = capabilities_of_this_process();
    assert_eq!(HostPlatform::current(), HostPlatform::Linux);
    assert!(
        capabilities.may_attach_traffic_control(),
        "run with CAP_NET_ADMIN, or as root"
    );
    assert!(capabilities.may_load_programs());
    assert!(capabilities.btf_available);

    // The helper being permitted has to be visible as something other than the
    // capability refusal, or a machine that granted CAP_NET_ADMIN would be
    // indistinguishable from one that did not.
    assert_eq!(
        EbpfLoader.load(HostPlatform::current(), &capabilities, &EVERY_HOOK),
        Err(LoaderUnavailable::LoaderNotBuilt)
    );
}

#[test]
#[ignore = "needs a Linux machine where this process holds no eBPF capabilities; \
            a root runner and the macOS development machine both fail the precondition"]
fn an_unprivileged_linux_process_is_refused_for_the_capability_and_not_the_platform() {
    let capabilities = capabilities_of_this_process();
    assert_eq!(HostPlatform::current(), HostPlatform::Linux);
    assert!(
        !capabilities.may_load_programs(),
        "this process holds the capabilities, so it cannot demonstrate the refusal"
    );

    // The distinction that matters to whoever reads the report: this machine can
    // observe and was not allowed to, which has a remedy, rather than this
    // machine cannot observe, which does not.
    assert_eq!(
        EbpfLoader.load(HostPlatform::current(), &capabilities, &ATTRIBUTING_HOOKS),
        Err(LoaderUnavailable::MissingCapability)
    );
}
