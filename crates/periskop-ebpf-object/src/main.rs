//! The programs periskop loads into a kernel (milestone F4-98).
//!
//! Six attach points, fixed by ADR-008 and restated as a closed list in
//! `periskop-ebpf-loader`: connection setup on the IPv4 and IPv6 paths, datagram
//! send, the two byte counters, and connection teardown. What each one produces
//! is a frame in the layout ADR-014 section 6.5 fixed, written by [`wire`] and
//! read by the loader's decoder, which is tested on every machine in the
//! workspace.
//!
//! # What this object reads out of the kernel, and what it refuses to
//!
//! Every field it reads comes from the first eighteen bytes of `struct sock`,
//! which is `struct sock_common`'s leading union of addresses and ports. That
//! prefix has not moved in the kernel's history and does not depend on build
//! configuration. Everything past it does: `skc_net` is present only with
//! network namespaces compiled in, and `skc_v6_daddr` sits after it, so their
//! offsets are a property of the kernel somebody built rather than of the
//! kernel's interface.
//!
//! So this object does not read them, and the consequences are declared rather
//! than papered over:
//!
//! - **The network namespace is reported absent**, not zero. The decoder has a
//!   flag for exactly this and the sensor keeps the flow out of any conclusion
//!   that would need a namespace.
//! - **Only `AF_INET` connections produce records.** An `AF_INET6` socket is
//!   seen by the same programs and skipped, because reading its addresses would
//!   mean trusting an offset this object cannot verify. A wrong address in a
//!   report is worse than a missing one: a reader cannot tell it is wrong.
//! - **`pid_start_time` is reported absent.** It lives in `task_struct`, which
//!   is the same class of problem.
//!
//! This is a deviation from ADR-008's CO-RE decision and it is recorded as one
//! in ADR-014 section 8. The thing that keeps it from being an untested
//! assumption is the gate: `proof_f4_kernel.rs` connects to a listener it opened
//! itself and fails unless the destination this object reports is the one the
//! test dialled. An offset that were wrong anywhere would produce an address
//! that is not that one.
//!
//! # Why the clock arrives from user space
//!
//! A record carries a wall clock bucket, and no eBPF helper returns wall clock
//! time. The loader measures the offset between the monotonic clock and the
//! epoch once, at load, and writes it into [`CONFIG`]; this object adds it to
//! `bpf_ktime_get_ns` and rounds. Computing the bucket here rather than on the
//! way out is what keeps a raw stamp from ever existing in a value a report is
//! derived from.
//!
//! # What is not here
//!
//! No `tc` classifier. ADR-008 assigns DNS answers and TLS server names to the
//! two `clsact` programs and this object carries neither, so a run with it
//! resolves no destination names. That is a stated absence with a stated cost,
//! not a silent one: the loader reports `loader_not_built` when a caller asks
//! for a hook this object has no program for, and the gate artefact lists name
//! resolution among the things it does not prove.
//!
//! No payload is read anywhere in this file. There is no code path that copies
//! bytes out of a packet, which is how "periskop does not inspect TLS content"
//! is a property of the program rather than a promise about it.
//!
//! # This crate can be type checked on the development machine
//!
//! ADR-014 section 8 says the object is built only in CI, and that is true of
//! *building* it: linking needs `bpf-linker`, which needs a matching LLVM.
//! Type checking needs neither. The first version of this file was written blind
//! against a remembered API, four of its assumptions were wrong, and CI found
//! them one round trip at a time. It did not have to:
//!
//! ```text
//! cd crates/periskop-ebpf-object
//! RUSTC_BOOTSTRAP=1 cargo check  --release
//! RUSTC_BOOTSTRAP=1 cargo clippy --release -- -D warnings
//! ```
//!
//! Three facts make that work, and each is worth knowing because losing any one
//! of them takes the check with it. The `bpfel-unknown-none` target
//! specification is built into `rustc`, so nothing needs installing for it to be
//! named. What is missing is a precompiled `core`, and `build-std` in
//! `.cargo/config.toml` compiles one from the `rust-src` that ships in the
//! Homebrew toolchain's sysroot. `build-std` is nightly gated, and
//! `RUSTC_BOOTSTRAP=1` is what lets the pinned stable accept it. `cargo check`
//! and `cargo clippy` stop before the linker, which is the one part that
//! genuinely needs CI.
//!
//! What this does **not** prove, and what still waits for CI: that `bpf-linker`
//! emits an ELF, and that the verifier accepts the programs in it. It compiles
//! with the root's stable rather than the nightly this crate pins, so it is a
//! check against a slightly different compiler than the one that builds the
//! artefact. Everything short of those is answerable here in ten seconds.
//!
//! # The `aya-ebpf` surface this file depends on
//!
//! Recorded because guessing at it is what produced the first round of errors.
//! Each row was read out of the vendored source rather than recalled, so a
//! future failure can be checked against this list instead of against a memory.
//! Paths are relative to `aya-ebpf-0.2.1/src` and `aya-ebpf-bindings-0.2.0/src`
//! in the cargo registry.
//!
//! | Call | Signature | Read from |
//! |---|---|---|
//! | `ProbeContext::arg` | `fn arg<T: Argument>(&self, n: usize) -> Option<T>` | `programs/probe.rs:37` |
//! | `RetProbeContext::ret` | `fn ret<T: Argument>(&self) -> T` | `programs/retprobe.rs:28` |
//! | `bpf_ktime_get_ns` | `pub unsafe fn bpf_ktime_get_ns() -> __u64` | `x86_64/helpers.rs:48` |
//! | `bpf_get_current_pid_tgid` | `pub fn bpf_get_current_pid_tgid() -> u64` | `helpers.rs:648` |
//! | `bpf_get_current_comm` | `pub fn bpf_get_current_comm() -> Result<[u8; TASK_COMM_LEN], i32>` | `helpers.rs:617` |
//! | `TASK_COMM_LEN` | `pub const TASK_COMM_LEN: usize = 16` | `helpers.rs:598` |
//! | `bpf_probe_read_kernel` | `pub unsafe fn bpf_probe_read_kernel<T>(src: *const T) -> Result<T, i32>` | `helpers.rs:211` |
//! | `RingBuf::output` | `fn output<T: ?Sized>(&self, data: impl Borrow<T>, flags: u64) -> Result<(), i32>` | `maps/ring_buf.rs:200` |
//! | `Array::get` | `fn get(&self, index: u32) -> Option<&T>` | `maps/array.rs:24` |
//! | `Array::get_ptr_mut` | `fn get_ptr_mut(&self, index: u32) -> Option<*mut T>` | `maps/array.rs:34` |
//! | `HashMap::get` | `pub unsafe fn get(&self, key: impl Borrow<K>) -> Option<&V>` | `maps/hash_map.rs:49` |
//! | `HashMap::insert` | `fn insert(&self, key: impl Borrow<K>, value: impl Borrow<V>, flags: u64) -> Result<(), i32>` | `maps/hash_map.rs:71` |
//! | `HashMap::remove` | `fn remove(&self, key: impl Borrow<K>) -> Result<(), i32>` | `maps/hash_map.rs:81` |
//!
//! Two of those shapes are worth stating in words, because they are the ones the
//! first draft got wrong and they are wrong in opposite directions.
//!
//! **`ret` is not fallible.** It hands back the return register coerced to `T`,
//! with no `Option` around it, because a return probe always has a return value.
//! A kernel function that failed put a negative errno in that register, so this
//! file compares against zero rather than unwrapping something.
//!
//! **`output` is generic in a way that needs help.** `T` appears only behind
//! `impl Borrow<T>`, and a `&[u8; N]` satisfies that for both `T = [u8; N]` and
//! `T = &[u8; N]`, so inference has two answers and picks neither. The call site
//! names `T` explicitly. Left implicit it does not compile, which is the good
//! case; the bad one would be it inferring the reference and writing eight bytes
//! of pointer into the ring buffer.

#![no_std]
#![no_main]

mod wire;

use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel,
};
use aya_ebpf::macros::{kprobe, kretprobe, map};
use aya_ebpf::maps::{Array, HashMap, RingBuf};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use aya_ebpf::TASK_COMM_LEN;

/// The kernel's `comm` field and the layout's `comm` field are the same width.
///
/// Asserted rather than assumed because the two come from different places: one
/// is `aya-ebpf`'s idea of `TASK_COMM_LEN`, the other is the sixteen bytes ADR-014
/// section 6.5 reserved. They agree today. If a future `aya-ebpf` widened its
/// buffer, the copy below would still compile against a coincidence, and this
/// stops that at the build rather than at the first truncated process name.
const _: () = assert!(TASK_COMM_LEN == 16);

/// A megabyte of ring buffer.
///
/// Losses are counted by the kernel and carried out by the loader into the
/// coverage statement, so a buffer that overruns understates traffic visibly
/// rather than silently. Sized to survive a burst rather than a sustained flood:
/// the alternative, a buffer large enough that loss is impossible, does not
/// exist.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

/// The socket a task is part way through connecting to, or reading from.
///
/// Keyed by the task, not by the socket, because that is what identifies the
/// call in flight. Both users of this map delete their entry on the way out, and
/// a task that never returns leaves one behind.
///
/// What a full map costs, stated rather than implied: this is a plain hash map,
/// not an LRU one, so the kernel refuses the insert rather than evicting
/// somebody. The call that could not stash its socket produces no record at all,
/// which is a loss this object does not count. It is the one loss here that the
/// coverage statement cannot name, and it is recorded as such rather than hidden
/// behind a map type whose eviction would have made it look like nothing
/// happened.
#[map]
static IN_FLIGHT: HashMap<u64, u64> = HashMap::with_max_entries(10_240, 0);

/// What the loader measured before it attached anything.
///
/// Slot zero is the nanoseconds to add to `bpf_ktime_get_ns` to reach the epoch,
/// slot one is the monotonic reading at attach, slot two is the bucket width in
/// seconds. All three are facts about the machine that no helper can supply.
#[map]
static CONFIG: Array<u64> = Array::with_max_entries(4, 0);

/// Frames the ring buffer had no room for.
///
/// Counted here because this is the only side that sees a reservation fail. The
/// loader reads it and the sensor declares it, so a run that lost a thousand
/// records does not look like a run that lost none.
#[map]
static DROPPED: Array<u64> = Array::with_max_entries(1, 0);

const CONFIG_WALL_OFFSET_NS: u32 = 0;
const CONFIG_ATTACHED_AT_NS: u32 = 1;
const CONFIG_BUCKET_SECS: u32 = 2;

/// Offsets into `struct sock`, which begins with `struct sock_common`.
///
/// The leading union of addresses and ports, in the order the kernel declares
/// it. Named rather than spelled inline so that the one place this object trusts
/// a layout is the one place a reader has to check.
const SKC_DADDR: usize = 0;
const SKC_RCV_SADDR: usize = 4;
const SKC_DPORT: usize = 12;
const SKC_NUM: usize = 14;
const SKC_FAMILY: usize = 16;

const AF_INET: u16 = 2;

const NANOS_PER_SEC: u64 = 1_000_000_000;

#[kprobe]
pub fn periskop_connect_entry(ctx: ProbeContext) -> u32 {
    // The socket is not yet filled in here: the addresses and the source port
    // are assigned inside the function this probe sits on the entry of. So the
    // pointer is stashed and the record is written on the way out, which is the
    // only point where the key this record needs actually exists.
    let Some(sk) = ctx.arg::<*const u8>(0) else {
        return 0;
    };
    // The insert can fail, and what it costs is stated on the map: a full map
    // means this call is not tracked and produces no record at all. Nothing here
    // can recover from that, and there is no counter it belongs in, so it is
    // discarded deliberately rather than by omission.
    let _ = IN_FLIGHT.insert(bpf_get_current_pid_tgid(), sk as u64, 0);
    0
}

#[kretprobe]
pub fn periskop_connect_return(ctx: RetProbeContext) -> u32 {
    let task = bpf_get_current_pid_tgid();
    let Some(sk) = take_in_flight(task) else {
        return 0;
    };
    // A failed connect leaves a socket whose addresses mean nothing. Reporting
    // it would put a destination in the report that was never reached.
    //
    // `ret` hands back the return register itself, not an option around it, so
    // there is nothing here to unwrap: the kernel put either zero or a negative
    // errno there, and everything that is not zero is a connect that did not
    // happen.
    if ctx.ret::<i32>() != 0 {
        return 0;
    }
    let Some(key) = key_of(sk) else {
        return 0;
    };
    // A `comm` the helper could not read is left as sixteen zero bytes, which the
    // decoder reads as no name rather than as an empty one; its test
    // `an_empty_comm_field_is_absent_rather_than_an_empty_name` is what fixes
    // that meaning. So the failure is reported as an absent name, not swallowed
    // into a plausible one.
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let frame = wire::connect(
        &key,
        wire::PROTOCOL_TCP,
        // No namespace and no process start time: both are declared absent
        // rather than written as zero, which the decoder would otherwise have to
        // guess the meaning of.
        0,
        bucket_now(),
        seconds_since_attach(),
        (task >> 32) as u32,
        &comm,
    );
    emit(&frame);
    0
}

#[kprobe]
pub fn periskop_tcp_sendmsg(ctx: ProbeContext) -> u32 {
    sent(&ctx, wire::PROTOCOL_TCP)
}

#[kprobe]
pub fn periskop_udp_sendmsg(ctx: ProbeContext) -> u32 {
    // Only a connected datagram socket has a destination on the socket itself.
    // An unconnected `sendto` carries it in the message header, whose layout is
    // not in the prefix this object trusts, so those sends are not reported.
    // `key_of` rejects them, because a socket with no destination has a zero
    // address and a zero port.
    sent(&ctx, wire::PROTOCOL_UDP)
}

#[kprobe]
pub fn periskop_tcp_recvmsg_entry(ctx: ProbeContext) -> u32 {
    // The third argument is the size of the buffer the caller offered, not the
    // number of bytes that arrived. Counting it would overstate inbound volume
    // by whatever the caller happened to ask for, so the count is taken from the
    // return value instead and the socket is stashed to get there.
    let Some(sk) = ctx.arg::<*const u8>(0) else {
        return 0;
    };
    // The insert can fail, and what it costs is stated on the map: a full map
    // means this call is not tracked and produces no record at all. Nothing here
    // can recover from that, and there is no counter it belongs in, so it is
    // discarded deliberately rather than by omission.
    let _ = IN_FLIGHT.insert(bpf_get_current_pid_tgid(), sk as u64, 0);
    0
}

#[kretprobe]
pub fn periskop_tcp_recvmsg_return(ctx: RetProbeContext) -> u32 {
    let Some(sk) = take_in_flight(bpf_get_current_pid_tgid()) else {
        return 0;
    };
    // The return register holds what `tcp_recvmsg` returned: a byte count, or a
    // negative errno, or zero for an orderly shutdown. Only a positive count is
    // bytes that arrived, and the other two produce no record rather than a
    // record claiming zero bytes on a connection that moved some.
    let received = ctx.ret::<i32>();
    if received <= 0 {
        return 0;
    }
    let Some(key) = key_of(sk) else {
        return 0;
    };
    let frame = wire::volume(&key, wire::PROTOCOL_TCP, 0, 0, received as u64, 0);
    emit(&frame);
    0
}

#[kprobe]
pub fn periskop_tcp_close(ctx: ProbeContext) -> u32 {
    let Some(sk) = ctx.arg::<*const u8>(0) else {
        return 0;
    };
    let Some(key) = key_of(sk as u64) else {
        return 0;
    };
    // The duration flag stays clear. Measuring it would mean holding the start
    // time per socket, and a connection whose duration was never recorded and
    // one that lasted under a millisecond are different facts the decoder keeps
    // apart on this flag.
    let frame = wire::close(&key, wire::PROTOCOL_TCP, 0, 0);
    emit(&frame);
    0
}

/// The bytes one send call moved, as a volume record.
///
/// `segments_out` counts calls rather than packets, which is what the record's
/// contract says it is: a kprobe on the socket layer sees calls, and inventing a
/// packet count from one would be a number nobody measured.
fn sent(ctx: &ProbeContext, protocol: u8) -> u32 {
    let Some(sk) = ctx.arg::<*const u8>(0) else {
        return 0;
    };
    let Some(size) = ctx.arg::<usize>(2) else {
        return 0;
    };
    let Some(key) = key_of(sk as u64) else {
        return 0;
    };
    let frame = wire::volume(&key, protocol, 0, size as u64, 0, 1);
    emit(&frame);
    0
}

/// The socket a task stashed on its way in, removed as it is read.
///
/// Removed rather than left, because the entry probe and the return probe are a
/// pair: an entry whose return never came must not be picked up by the next call
/// on the same task and reported as that call's socket.
fn take_in_flight(task: u64) -> Option<u64> {
    // SAFETY: the map is this object's own and holds plain `u64` values, so the
    // reference the helper hands back points at a value of the type the map was
    // declared with. It is read out before the entry is removed.
    let sk = unsafe { IN_FLIGHT.get(task).copied() };
    // A remove that fails is a key that was not there, which is the case the
    // caller already handles by getting nothing back.
    let _ = IN_FLIGHT.remove(task);
    sk
}

/// The flow key a record carries, or nothing when the socket cannot supply one.
///
/// Refuses on three conditions and each refusal is a record that is not written
/// rather than a record with a hole in it: a family this object does not read, a
/// destination that is not set, and a source port that is not assigned.
fn key_of(sk: u64) -> Option<wire::Key> {
    let base = sk as *const u8;
    // SAFETY: `bpf_probe_read_kernel` is the checked read the kernel provides
    // for exactly this: it faults into an error rather than into a crash if the
    // address is not readable. The offsets are `struct sock_common`'s leading
    // union, documented at the top of this file.
    let (family, daddr, saddr, dport, num) = unsafe {
        (
            read_at::<u16>(base, SKC_FAMILY),
            read_at::<u32>(base, SKC_DADDR),
            read_at::<u32>(base, SKC_RCV_SADDR),
            read_at::<u16>(base, SKC_DPORT),
            read_at::<u16>(base, SKC_NUM),
        )
    };
    // A family that could not be read compares unequal to `AF_INET` rather than
    // falling back to it, which is why the comparison is against the option and
    // not against an unwrapped value.
    if family != Some(AF_INET) {
        return None;
    }
    // The source address joins the other three rather than defaulting to zero on
    // a failed read. Zero is a real value here, `0.0.0.0` on a socket the kernel
    // has not bound yet, so a read that failed and a socket that is genuinely
    // unbound would arrive at the decoder as the same thing. A read this object
    // could not make is a record it does not write.
    let (daddr, dport, num, saddr) = (daddr?, dport?, num?, saddr?);
    if daddr == 0 || dport == 0 || num == 0 {
        return None;
    }
    let mut src_ip = [0u8; 16];
    let mut dst_ip = [0u8; 16];
    // Both are already in network order in the socket, and the layout wants the
    // address bytes in that order, so they are copied rather than converted.
    src_ip[..4].copy_from_slice(&saddr.to_ne_bytes());
    dst_ip[..4].copy_from_slice(&daddr.to_ne_bytes());
    Some(wire::Key {
        netns: 0,
        src_ip,
        dst_ip,
        // The destination port is network order on the socket and the layout
        // wants a host order number, which is what the decoder reads.
        src_port: num,
        dst_port: u16::from_be(dport),
    })
}

/// Reads a field out of kernel memory, or nothing if it could not be read.
///
/// # Safety
///
/// `base` must be a kernel address this program was handed by the probe context.
/// The helper itself is fault tolerant, so a wrong address costs a record rather
/// than the machine.
#[inline(always)]
unsafe fn read_at<T>(base: *const u8, offset: usize) -> Option<T> {
    // SAFETY: the caller supplies a kernel pointer from a probe argument, and
    // the helper checks the read.
    unsafe { bpf_probe_read_kernel(base.add(offset) as *const T).ok() }
}

/// The monotonic clock, in nanoseconds since boot.
///
/// `aya-ebpf` exposes this one as the raw binding rather than as a checked
/// wrapper, so it is `unsafe` and returns a bare `u64` with no error to inspect.
/// Wrapped once here so that the `unsafe` block holds a single call and nothing
/// else, and so that the reason it is sound is written down once instead of at
/// each of the two call sites.
#[inline(always)]
fn ktime_ns() -> u64 {
    // SAFETY: `bpf_ktime_get_ns` takes no arguments, touches no memory this
    // program owns and reads no pointer. It is `unsafe` because every generated
    // binding is: they are transmutes of a helper id into a function pointer.
    // The verifier is what guarantees the helper is callable from a kprobe, and
    // it is, from every program type this object carries.
    unsafe { bpf_ktime_get_ns() }
}

/// Wall clock seconds, rounded down to the bucket the loader chose.
fn bucket_now() -> u64 {
    let wall_secs = (config(CONFIG_WALL_OFFSET_NS).saturating_add(ktime_ns())) / NANOS_PER_SEC;
    let bucket = config(CONFIG_BUCKET_SECS).max(1);
    wall_secs - (wall_secs % bucket)
}

/// Seconds since the loader attached, which is what ages the name map.
fn seconds_since_attach() -> u64 {
    ktime_ns().saturating_sub(config(CONFIG_ATTACHED_AT_NS)) / NANOS_PER_SEC
}

fn config(slot: u32) -> u64 {
    CONFIG.get(slot).copied().unwrap_or(0)
}

/// Hands a frame to the ring buffer, or counts it as lost.
///
/// A reservation that fails is a full buffer, and the loss is counted rather
/// than discarded. That count is the difference between a sensor that missed a
/// thousand connections and a sensor that saw a quiet machine, and only one of
/// the two is a measurement.
fn emit<const N: usize>(frame: &[u8; N]) {
    // `T` is named rather than inferred. `output` takes `impl Borrow<T>` and a
    // `&[u8; N]` borrows as both `[u8; N]` and `&[u8; N]`, so an unannotated call
    // is ambiguous. Naming the array is also what makes `size_of_val` inside the
    // helper equal to the frame length instead of the width of a pointer.
    if EVENTS.output::<[u8; N]>(frame, 0).is_ok() {
        return;
    }
    // SAFETY: the pointer addresses this object's own single element array, and
    // nothing else in this program writes to it, so there is no other reference
    // to the slot while it is incremented.
    if let Some(slot) = DROPPED.get_ptr_mut(0) {
        unsafe { *slot = (*slot).saturating_add(1) };
    }
}

/// Required by the kernel before it will let a program call the helpers this one
/// calls: `bpf_probe_read_kernel` is GPL only, and the licence a program
/// declares is what the verifier checks that against.
///
/// This object alone carries it. The rest of the repository is Apache-2.0, this
/// file links into no host binary, and the choice is recorded as a decision with
/// its consequence in ADR-014 section 8 rather than left as a string somebody
/// copied from a tutorial.
#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Unreachable: this object has no panicking path, `panic = "abort"` is set
    // and the verifier would reject a program that could reach an infinite loop.
    // It exists because `no_std` requires it.
    loop {}
}
