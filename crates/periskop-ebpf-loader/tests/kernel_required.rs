#![allow(clippy::expect_used)]
//! The tests that need a real machine, and are marked so rather than skipped.
//!
//! Everything else in this crate runs everywhere, because the seam was drawn so
//! that it could. What is left here genuinely depends on the machine underneath:
//! whether it is Linux, whether the kernel exposes BTF, whether this process was
//! given `CAP_BPF`, and whether this binary was built with a kernel side program
//! object. None of those can be arranged inside a test.
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
//! sudo -E cargo test -p periskop-ebpf-loader --all-features -- --ignored --test-threads=1
//! ```
//!
//! `--test-threads=1` is not a preference. [`the_load_gives_up_the_capabilities_
//! that_allowed_it`] drops this process's capabilities, which is a change to the
//! whole process rather than to one test, so a second test reading them
//! concurrently would read them at an unpredictable moment.
//!
//! # Why two of these assert one thing or the other
//!
//! Not to arrange a pass. Each branch asserts a claim of its own and the two are
//! different claims about the same loader: with the authority, that it loads and
//! then gives the authority up; without it, that it refuses for the capability
//! and not for something else. Which branch ran is printed, and the phase gate
//! that has to see the first one is `proof_f4_kernel.rs`, which fails rather
//! than branches when `PERISKOP_REQUIRE_KERNEL_PROOF` is set.

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

/// Whether this binary carries a kernel side program object.
///
/// Read from the same cfg the loader is compiled under, so a test cannot expect
/// a load from a binary that has nothing to load.
const KERNEL_OBJECT_COMPILED_IN: bool = cfg!(all(target_os = "linux", periskop_kernel_object));

/// Reads this process's real authority off the running kernel.
///
/// Deliberately not the sensor's parser: these tests exist to check the machine,
/// so borrowing the production reader would make them agree with it by
/// construction even when both were wrong about the machine.
///
/// # Why an unreadable procfs stops the test instead of answering zero
///
/// Every reading here used to fall back to a default, and the default was "this
/// process holds nothing". That value is used twice, and the two uses are what
/// made it dangerous: it is the input handed to `loader.load(...)` **and** the
/// selector deciding which of the two assertion branches runs. So a run that
/// could not read `/proc/self/status` invented an unprivileged process, took the
/// "this machine cannot load" branch, and asserted `first.is_err()`, which was
/// already true of the input it had just made up. The claim these tests exist
/// for, that a load succeeds and then genuinely gives the capabilities up, never
/// ran, and `ci.yml`'s count only looks at `passed > 0` and `skipped == 0`, so
/// the run reported as a pass.
///
/// The function's own heading is what settles the direction of the fix: these
/// tests are here to check the machine. A machine it cannot read is a machine it
/// has nothing to say about, and saying it anyway is the one outcome that must
/// not be available.
fn capabilities_of_this_process() -> Capabilities {
    let status = std::fs::read_to_string(PROC_SELF_STATUS).expect(
        "/proc/self/status could not be read, so this process's authority is unknown; these \
         tests assert what the machine does and must not invent an answer for it",
    );
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .expect(
            "/proc/self/status carries no readable CapEff line, so the capability set below \
             would be a guess rather than a reading",
        );
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|value| value.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u32>().ok())
        .expect(
            "/proc/self/status carries no readable effective Uid, and `root: false` on a run \
             that is actually root is the same invented answer in a smaller field",
        );
    Capabilities {
        cap_bpf: effective & (1u64 << CAP_BPF) != 0,
        cap_perfmon: effective & (1u64 << CAP_PERFMON) != 0,
        cap_net_admin: effective & (1u64 << CAP_NET_ADMIN) != 0,
        root: uid == 0,
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
#[ignore = "needs a Linux kernel with BTF, a process holding CAP_BPF and CAP_PERFMON, \
            and a binary built with a kernel side object; none is arrangeable on the \
            macOS development machine"]
fn the_load_gives_up_the_capabilities_that_allowed_it() {
    // Asserted rather than skipped over, and asserted first: the reader below
    // opens a Linux interface, so on any other machine this is the sentence that
    // should come out rather than a missing file.
    assert_eq!(
        HostPlatform::current(),
        HostPlatform::Linux,
        "this test asserts kernel behaviour and was run somewhere else"
    );
    let capabilities = capabilities_of_this_process();

    let mut loader = EbpfLoader::default();
    let first = loader.load(HostPlatform::current(), &capabilities, &ATTRIBUTING_HOOKS);

    if !capabilities.may_load_programs()
        || !capabilities.btf_available
        || !KERNEL_OBJECT_COMPILED_IN
    {
        // The other claim, and a real one: whatever is missing, the loader names
        // it rather than trying and failing deeper.
        eprintln!(
            "  this machine cannot load: capabilities={}, btf={}, object_compiled_in={}",
            capabilities.may_load_programs(),
            capabilities.btf_available,
            KERNEL_OBJECT_COMPILED_IN
        );
        assert!(first.is_err(), "a load succeeded with nothing to load it");
        assert!(!loader.is_attached());
        return;
    }

    assert_eq!(
        first,
        Ok(()),
        "every precondition held and the load still failed: {:?}",
        loader.last_refusal_detail()
    );
    assert!(
        loader.is_attached(),
        "the load reported success and the loader is holding nothing"
    );

    // The requirement in `network-sensor/spec.md` §9, demonstrated rather than
    // asserted about: after the load, the authority that allowed it is gone, and
    // the way to show it is gone is that using it again does not work. A drop
    // that had returned success without taking effect would leave this second
    // load succeeding.
    let mut second = EbpfLoader::default();
    let after = second.load(
        HostPlatform::current(),
        &capabilities_of_this_process(),
        &ATTRIBUTING_HOOKS,
    );
    assert_eq!(
        after,
        Err(LoaderUnavailable::MissingCapability),
        "the capabilities survived a load, so the two stage privilege structure did not happen"
    );
    assert!(!second.is_attached());
}

#[test]
#[ignore = "needs a Linux machine; the macOS development machine reports the platform \
            before it reaches the question this asks"]
fn the_loader_agrees_with_the_authority_this_process_actually_holds() {
    assert_eq!(HostPlatform::current(), HostPlatform::Linux);
    let capabilities = capabilities_of_this_process();

    // The full plan, which every build of this crate refuses before it reaches a
    // kernel because no build carries a `clsact` classifier. So this asks the
    // capability question without loading anything, and it is safe to run beside
    // the test that drops capabilities.
    let mut loader = EbpfLoader::default();
    let refusal = loader
        .load(HostPlatform::current(), &capabilities, &EVERY_HOOK)
        .expect_err("no build of this crate has a program for the payload helper");

    let expected = if capabilities.may_load_programs() {
        // The distinction that matters to whoever reads the report: this machine
        // was allowed to observe and this build has no program for part of what
        // was asked, which has a remedy in the build rather than in a grant.
        LoaderUnavailable::LoaderNotBuilt
    } else {
        // And the other one: this machine can observe and was not allowed to.
        LoaderUnavailable::MissingCapability
    };
    assert_eq!(
        refusal,
        expected,
        "the loader's answer does not match this process's authority; detail: {:?}",
        loader.last_refusal_detail()
    );
    assert!(
        loader.last_refusal_detail().is_some(),
        "a refusal with no detail leaves an operator with a label and no way to act on it"
    );
}

#[test]
#[ignore = "needs a Linux kernel; asks what this machine exposes rather than what this \
            build believes about it"]
fn the_kernel_this_runs_on_exposes_what_co_re_needs() {
    // Read off the machine rather than from the loader, so that a build whose
    // own probe was wrong cannot make this agree with it. The loader's answer
    // depends on this file existing, and this is the only test that checks the
    // file rather than the answer.
    assert_eq!(HostPlatform::current(), HostPlatform::Linux);
    assert!(
        Path::new(BTF_VMLINUX).exists(),
        "this kernel exposes no BTF at {BTF_VMLINUX}, so CO-RE cannot work here"
    );
    let size = std::fs::metadata(BTF_VMLINUX)
        .map(|meta| meta.len())
        .unwrap_or(0);
    assert!(
        size > 0,
        "{BTF_VMLINUX} is present and empty, which no loader can relocate against"
    );
}
