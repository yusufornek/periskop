//! The whole of this workspace's `unsafe` exception, in one file.
//!
//! ADR-002 sets `unsafe_code = "forbid"` for the workspace and names the eBPF
//! loader as one of three places allowed an exception. ADR-014 §5 made the grant
//! narrower than the crate: every operation that uses it belongs in one module
//! named `syscall`, and `tests/unsafe_boundary.rs` fails the build if any other
//! file in this crate opens one. This is that module.
//!
//! # What is in here, and why each thing has to be
//!
//! Three calls, and none of them has a safe equivalent in `std`:
//!
//! - **`capget`** reads the capabilities this process holds right now. The
//!   sensor already parses `/proc/self/status`, and this is not a second copy of
//!   that: it is the reading taken immediately before the `bpf(2)` call and
//!   immediately after the capabilities are dropped, at moments where a file
//!   read of a text interface would be answering a slightly older question.
//! - **`capset`** is the drop itself (`network-sensor/spec.md` §9). The sensor
//!   loads with `CAP_BPF` and `CAP_PERFMON` and then must not keep them: a
//!   long lived observer holding the authority to load kernel programs is a
//!   larger thing to compromise than one that gave it up a second after start.
//! - **`clock_gettime(CLOCK_MONOTONIC)`** is the clock the kernel program reads
//!   through `bpf_ktime_get_ns`. The loader measures the offset between it and
//!   the epoch once and hands the offset down, because no eBPF helper returns
//!   wall clock time and a record carries a wall clock bucket. `std::time::
//!   Instant` cannot serve: it is deliberately opaque and cannot be compared
//!   against a number the kernel produced.
//!
//! Notably **not** in here: loading and attaching programs, and reading the ring
//! buffer. `aya` exposes all three through a safe API, so this crate's exception
//! covers less than ADR-014 expected it to. That is worth stating rather than
//! quietly enjoying, because it is the reason the exception's surface is three
//! functions rather than a subsystem.
//!
//! # What this module does not do
//!
//! It does not drop the bounding set. Removing a capability from the bounding
//! set needs `CAP_SETPCAP`, which the sensor does not ask for and should not,
//! and the effective and permitted sets are what the kernel checks when a
//! program is loaded. The remaining exposure is a process that could regain the
//! capability across an `execve`, and the sensor never execs.

use std::os::raw::{c_int, c_long};

/// Bit positions from the kernel's `capability.h`.
const CAP_NET_ADMIN: u32 = 12;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

/// `_LINUX_CAPABILITY_VERSION_3`, the 64 bit form, which is the only one worth
/// asking for: version 1 cannot express `CAP_BPF` at all, since it sits above
/// bit 31.
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Two blocks of thirty two bits, which is what version 3 defines.
const CAP_BLOCKS: usize = 2;

/// How many blocks the kernel writes for a declared capability version.
///
/// Derived from the version rather than from [`CAP_BLOCKS`], and the duplication
/// is the point rather than an oversight. The buffer is **sized** by the
/// constant and **filled** according to the number in the header, so the two are
/// free to drift apart, and the shape of that drift is a write one `CapData`
/// past the end of a stack array. Version 1 defined one block; version 3 defines
/// two.
const fn blocks_for(version: u32) -> usize {
    if version == CAPABILITY_VERSION_3 {
        2
    } else {
        1
    }
}

/// The buffer and the version it declares, made to agree at compile time.
///
/// One of the two things standing between this module and a kernel writing past
/// the end of a stack array. The other is the interpreter: this catches the two
/// constants drifting apart, and the miri tests below catch the pointer walk
/// that would do the writing. Neither replaces the other, and until both existed
/// the answer was "nothing", because the syscall cannot be exercised by any test
/// this repository can run.
const _: () = assert!(blocks_for(CAPABILITY_VERSION_3) == CAP_BLOCKS);

/// The header `capget` and `capset` are handed.
///
/// `pid` of zero means this thread, which is the only subject this crate is
/// entitled to change.
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: c_int,
}

/// One thirty two bit block of each of the three sets.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// The three capabilities that matter to this loader, as the kernel holds them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effective {
    pub cap_bpf: bool,
    pub cap_perfmon: bool,
    pub cap_net_admin: bool,
}

impl Effective {
    fn from_blocks(blocks: &[CapData; CAP_BLOCKS]) -> Self {
        Self {
            cap_bpf: holds(blocks, CAP_BPF),
            cap_perfmon: holds(blocks, CAP_PERFMON),
            cap_net_admin: holds(blocks, CAP_NET_ADMIN),
        }
    }

    /// Whether a program load can be expected to succeed.
    pub fn may_load_programs(self) -> bool {
        self.cap_bpf && self.cap_perfmon
    }
}

fn block_of(capability: u32) -> usize {
    (capability / 32) as usize
}

fn bit_of(capability: u32) -> u32 {
    1u32 << (capability % 32)
}

fn holds(blocks: &[CapData; CAP_BLOCKS], capability: u32) -> bool {
    blocks
        .get(block_of(capability))
        .is_some_and(|block| block.effective & bit_of(capability) != 0)
}

/// What this process holds at this instant, or nothing if the kernel refused to
/// say.
///
/// A refusal is reported as absence rather than as an empty grant, because the
/// two would send a reader to different remedies: one is "grant the capability",
/// the other is "this kernel did not answer a question every Linux kernel
/// answers".
pub fn effective_capabilities() -> Option<Effective> {
    let blocks = read_capabilities()?;
    Some(Effective::from_blocks(&blocks))
}

fn read_capabilities() -> Option<[CapData; CAP_BLOCKS]> {
    read_capabilities_with(|header, blocks| {
        // SAFETY: both pointers address stack locals of exactly the shapes the
        // kernel's `capget` contract names, the header declares version 3 and
        // the data buffer is the two blocks version 3 defines. The call reads
        // the header and writes the blocks; nothing else in this process
        // observes either while it runs.
        unsafe { libc::syscall(libc::SYS_capget, header, blocks) }
    })
}

/// The buffer half of a `capget`, with the call itself handed in.
///
/// # Why the call is a parameter
///
/// ADR-014 §5 requires a miri target for this module, and miri does not execute
/// foreign functions: a test that reached `libc::syscall` would stop the
/// interpreter with an unsupported operation rather than check anything. That is
/// how the miri job came to compile the exception without ever interpreting it.
///
/// Everything that can actually be wrong here is on this side of the call: the
/// buffer's size, the version the header declares, and the assumption that the
/// kernel fills exactly as many blocks as that version defines. Handing the call
/// in leaves all of it interpretable, and the module's tests drive it with a
/// stand-in that writes what the kernel writes, through the same raw pointer,
/// into the same stack array. `cargo miri test -p periskop-ebpf-loader --lib`
/// then reports a buffer that is too small for the version in the header, which
/// is the one defect nothing else in this repository can see.
fn read_capabilities_with(
    capget: impl FnOnce(*mut CapHeader, *mut CapData) -> c_long,
) -> Option<[CapData; CAP_BLOCKS]> {
    let mut header = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut blocks = [CapData::default(); CAP_BLOCKS];
    let result = capget(std::ptr::addr_of_mut!(header), blocks.as_mut_ptr());
    (result == 0).then_some(blocks)
}

/// The buffer half of a `capset`, on the same terms as the read above.
///
/// Returns whether the kernel accepted the write, and nothing else: what the
/// process holds afterwards is read back through `capget` rather than inferred
/// from this, for the reason [`drop_load_capabilities`] gives.
fn write_capabilities_with(
    blocks: &[CapData; CAP_BLOCKS],
    capset: impl FnOnce(*mut CapHeader, *const CapData) -> c_long,
) -> bool {
    let mut header = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    capset(std::ptr::addr_of_mut!(header), blocks.as_ptr()) == 0
}

/// Gives up the authority to load programs and to attach to traffic control.
///
/// Called the moment the descriptors are open. What is already loaded keeps
/// running: a program in the kernel and a ring buffer already mapped do not need
/// the capability that put them there, which is the whole reason the two stage
/// structure in `network-sensor/spec.md` §9 is possible.
///
/// Returns what the process holds afterwards, read back from the kernel rather
/// than assumed from the fact that the call returned zero. A drop that reported
/// success without being checked would be the quietest possible failure: the
/// sensor would run for hours believing it had given up authority it still had.
pub fn drop_load_capabilities() -> Option<Effective> {
    let mut blocks = read_capabilities()?;
    for capability in [CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN] {
        let Some(block) = blocks.get_mut(block_of(capability)) else {
            continue;
        };
        let mask = !bit_of(capability);
        block.effective &= mask;
        // The permitted set goes too. Leaving it would let anything later in
        // this process raise the capability back into the effective set, which
        // would make the drop a gesture rather than a change.
        block.permitted &= mask;
        block.inheritable &= mask;
    }
    let accepted = write_capabilities_with(&blocks, |header, data| {
        // SAFETY: same shapes as the read above, and the data buffer is the one
        // this function just filled from a successful `capget`, so every field
        // the kernel will interpret came from the kernel.
        unsafe { libc::syscall(libc::SYS_capset, header, data) }
    });
    if !accepted {
        return None;
    }
    effective_capabilities()
}

/// The monotonic clock in nanoseconds, which is the clock `bpf_ktime_get_ns`
/// reads.
///
/// Returns nothing rather than a fabricated reading if the kernel refuses, and
/// the caller then refuses to load: a kernel program that was handed a wrong
/// offset would stamp every record with a wall clock time that is wrong by the
/// machine's uptime, and nothing downstream could tell.
pub fn monotonic_ns() -> Option<u64> {
    let mut spec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: the pointer addresses a stack local of the exact type
    // `clock_gettime` writes, and `CLOCK_MONOTONIC` is a constant this kernel
    // defines. The call writes the two fields and returns.
    let result: c_int = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut spec) };
    if result != 0 {
        return None;
    }
    let seconds = u64::try_from(spec.tv_sec).ok()?;
    let nanos = u64::try_from(spec.tv_nsec).ok()?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// The kernel's side of `capget`, as far as this buffer is concerned.
    ///
    /// It reads the version out of the header the caller filled in and writes
    /// that many blocks through the pointer it was handed, which is what the
    /// kernel does. Under an interpreter that is the whole check: if
    /// [`CAP_BLOCKS`] ever stops matching the version the header declares, the
    /// last write lands past the end of a stack array, and nothing outside an
    /// interpreter would notice, because the kernel writes into whatever is
    /// there and the process carries on.
    ///
    /// This is why `cargo miri test -p periskop-ebpf-loader --lib` is a required
    /// job rather than a courtesy: the two functions this crate's `unsafe`
    /// exists for cannot be called under miri at all, and this is the shape of
    /// them that can.
    fn a_kernel_that_answers(header: *mut CapHeader, blocks: *mut CapData, granted: u64) -> c_long {
        // SAFETY: both pointers were built by `read_capabilities_with` from a
        // stack header and a stack array that are alive for the whole of this
        // call, and the number of blocks written is the number the header
        // declares, which is the contract `capget` itself follows.
        unsafe {
            let version = (*header).version;
            for index in 0..blocks_for(version) {
                let half = (granted >> (index * 32)) as u32;
                blocks.add(index).write(CapData {
                    effective: half,
                    permitted: half,
                    inheritable: 0,
                });
            }
        }
        0
    }

    #[test]
    fn the_buffer_is_large_enough_for_the_version_the_header_declares() {
        // The interpreted half of `effective_capabilities`. `CAP_BPF` is bit 39,
        // so a reading that carries it at all is a reading that came out of the
        // second block, and the second block only exists if the buffer was sized
        // for the version the header asked for.
        let granted = (1u64 << CAP_BPF) | (1u64 << CAP_PERFMON) | (1u64 << CAP_NET_ADMIN);
        let blocks =
            read_capabilities_with(|header, blocks| a_kernel_that_answers(header, blocks, granted))
                .expect("a kernel that returns zero produces a reading");
        let effective = Effective::from_blocks(&blocks);
        assert!(effective.may_load_programs());
        assert!(effective.cap_net_admin);
        assert_eq!(blocks_for(CAPABILITY_VERSION_3), CAP_BLOCKS);
    }

    #[test]
    fn a_refused_capget_is_absence_rather_than_a_buffer_of_zeroes() {
        // The other arm, and the one a caller must not read as "no capabilities":
        // a kernel that would not answer wrote nothing into the buffer, so the
        // zeroes still in it are the initial value and not a reading.
        assert!(read_capabilities_with(|_, _| -1).is_none());
    }

    #[test]
    fn capset_is_handed_every_block_the_declared_version_covers() {
        // The interpreted half of `drop_load_capabilities`. A buffer shorter than
        // the header's version would have the kernel read past its end, which is
        // the same defect as the write above with the direction reversed.
        let mut blocks = [CapData::default(); CAP_BLOCKS];
        blocks[1].effective = bit_of(CAP_BPF);
        blocks[0].effective = bit_of(CAP_NET_ADMIN);
        let mut observed: Vec<CapData> = Vec::new();
        let accepted = write_capabilities_with(&blocks, |header, data| {
            // SAFETY: both pointers were built by `write_capabilities_with` from
            // a stack header and the caller's array, both alive for this call,
            // and the number of blocks read is the number the header declares.
            unsafe {
                let version = (*header).version;
                for index in 0..blocks_for(version) {
                    observed.push(data.add(index).read());
                }
            }
            0
        });
        assert!(accepted);
        assert_eq!(observed.len(), CAP_BLOCKS);
        assert_eq!(observed[1].effective, bit_of(CAP_BPF));
        assert_eq!(observed[0].effective, bit_of(CAP_NET_ADMIN));
    }

    #[test]
    fn a_refused_capset_is_reported_as_a_refusal() {
        let blocks = [CapData::default(); CAP_BLOCKS];
        assert!(!write_capabilities_with(&blocks, |_, _| -1));
    }

    #[test]
    fn a_capability_above_bit_thirty_one_lands_in_the_second_block() {
        // The reason version 3 is the only version worth asking for. Reading
        // `CAP_BPF` out of the first block would find whichever bit seven
        // happens to be, which is `CAP_SETUID`.
        assert_eq!(block_of(CAP_BPF), 1);
        assert_eq!(bit_of(CAP_BPF), 1 << 7);
        assert_eq!(block_of(CAP_NET_ADMIN), 0);
        assert_eq!(bit_of(CAP_NET_ADMIN), 1 << 12);
    }

    #[test]
    fn a_grant_is_read_out_of_the_block_the_capability_belongs_to() {
        let mut blocks = [CapData::default(); CAP_BLOCKS];
        blocks[1].effective = bit_of(CAP_BPF) | bit_of(CAP_PERFMON);
        blocks[0].effective = bit_of(CAP_NET_ADMIN);
        let effective = Effective::from_blocks(&blocks);
        assert!(effective.cap_bpf);
        assert!(effective.cap_perfmon);
        assert!(effective.cap_net_admin);
        assert!(effective.may_load_programs());
    }

    #[test]
    fn half_the_pair_is_not_a_permission_to_load() {
        let mut blocks = [CapData::default(); CAP_BLOCKS];
        blocks[1].effective = bit_of(CAP_BPF);
        assert!(!Effective::from_blocks(&blocks).may_load_programs());
    }

    #[test]
    fn an_empty_grant_reads_as_no_capabilities_rather_than_as_all_of_them() {
        let blocks = [CapData::default(); CAP_BLOCKS];
        let effective = Effective::from_blocks(&blocks);
        assert!(!effective.cap_bpf);
        assert!(!effective.cap_perfmon);
        assert!(!effective.cap_net_admin);
    }

    #[test]
    fn the_monotonic_clock_moves_forward_and_does_not_restart() {
        // The offset handed to the kernel program is only meaningful if this
        // clock is the same one `bpf_ktime_get_ns` reads: monotonic, in
        // nanoseconds, and not the wall clock. A reading that went backwards
        // would put a record before the observation that produced it.
        let first = monotonic_ns().expect("CLOCK_MONOTONIC is readable on Linux");
        let second = monotonic_ns().expect("CLOCK_MONOTONIC is readable on Linux");
        assert!(second >= first);
        assert!(first > 0);
    }
}
