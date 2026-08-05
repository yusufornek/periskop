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

#![no_std]
#![no_main]

mod wire;

use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel,
};
use aya_ebpf::macros::{kprobe, kretprobe, map};
use aya_ebpf::maps::{Array, HashMap, RingBuf};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};

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
/// a task that never returns leaves one behind until the map fills; the map is
/// therefore bounded and the oldest entry loses, which costs a record rather
/// than correctness.
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
    let _ = IN_FLIGHT.insert(&bpf_get_current_pid_tgid(), &(sk as u64), 0);
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
    if ctx.ret::<i32>().unwrap_or(-1) != 0 {
        return 0;
    }
    let Some(key) = key_of(sk) else {
        return 0;
    };
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
    let _ = IN_FLIGHT.insert(&bpf_get_current_pid_tgid(), &(sk as u64), 0);
    0
}

#[kretprobe]
pub fn periskop_tcp_recvmsg_return(ctx: RetProbeContext) -> u32 {
    let Some(sk) = take_in_flight(bpf_get_current_pid_tgid()) else {
        return 0;
    };
    let received = ctx.ret::<i32>().unwrap_or(0);
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
    let sk = unsafe { IN_FLIGHT.get(&task).copied() };
    let _ = IN_FLIGHT.remove(&task);
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
    let (daddr, dport, num) = (daddr?, dport?, num?);
    if daddr == 0 || dport == 0 || num == 0 {
        return None;
    }
    let mut src_ip = [0u8; 16];
    let mut dst_ip = [0u8; 16];
    // Both are already in network order in the socket, and the layout wants the
    // address bytes in that order, so they are copied rather than converted.
    src_ip[..4].copy_from_slice(&saddr.unwrap_or(0).to_ne_bytes());
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

/// Wall clock seconds, rounded down to the bucket the loader chose.
fn bucket_now() -> u64 {
    let wall_secs =
        (config(CONFIG_WALL_OFFSET_NS).saturating_add(bpf_ktime_get_ns())) / NANOS_PER_SEC;
    let bucket = config(CONFIG_BUCKET_SECS).max(1);
    wall_secs - (wall_secs % bucket)
}

/// Seconds since the loader attached, which is what ages the name map.
fn seconds_since_attach() -> u64 {
    bpf_ktime_get_ns().saturating_sub(config(CONFIG_ATTACHED_AT_NS)) / NANOS_PER_SEC
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
    if EVENTS.output(frame, 0).is_ok() {
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
