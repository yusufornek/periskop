//! The record layout ADR-014 section 6.5 fixed, written from the kernel side.
//!
//! The decoder for this layout lives in `periskop-ebpf-loader/src/record.rs` and
//! is fully tested on every machine in the workspace. This module is the writer,
//! and the two are deliberately **not** sharing a constant table: the loader is
//! a workspace member on a stable toolchain and this is a `no_std` binary for a
//! different target, so a shared crate would drag one set of constraints into
//! the other. They agree because the layout is written down in the ADR and
//! because a frame this side builds wrongly is a frame the decoder refuses
//! rather than misreads.
//!
//! That refusal is the whole reason the version byte and the reserved field are
//! in the header. A writer and a reader that disagree announce themselves at the
//! first frame instead of producing a report full of plausible nonsense.
//!
//! # Why the frames are fixed size arrays
//!
//! Every builder here returns a `[u8; N]` with `N` a constant, never a slice cut
//! to length. The verifier has to prove the bounds of everything handed to
//! `bpf_ringbuf_output`, and a length that varies at run time is a proof
//! obligation this code would then have to discharge with checks that exist only
//! to satisfy it. A constant is free.

/// The layout this object writes. The loader's decoder refuses anything else.
pub const LAYOUT_VERSION: u8 = 1;

pub const KIND_CONNECT: u8 = 1;
pub const KIND_VOLUME: u8 = 2;
pub const KIND_CLOSE: u8 = 3;

/// From the IP header, the values `/etc/protocols` uses.
pub const PROTOCOL_TCP: u8 = 6;
pub const PROTOCOL_UDP: u8 = 17;

/// The flag byte in full, none of which this object ever sets.
///
/// Every flag says a field is known. This object reads no IPv6 address, no
/// namespace and no `task_struct`, and it measures no duration, so every record
/// it writes carries a flag byte of zero and the decoder reports those fields
/// absent. That is the deviation ADR-014 section 8 records, and it is the whole
/// reason the flags exist: absence is a value here, not a gap.
///
/// They are named anyway rather than trimmed to the ones in use, because the
/// flag byte is half of what the decoder reads out of a frame and a writer that
/// listed only its own flags would leave the next person to set one guessing at
/// the bit. `expect` rather than `allow`, so that the day one of them is set the
/// attribute goes red and has to be removed rather than sitting there covering
/// for nothing.
#[expect(dead_code, reason = "the layout's full flag vocabulary")]
pub const FLAG_IPV6: u8 = 1 << 0;
#[expect(dead_code, reason = "the layout's full flag vocabulary")]
pub const FLAG_NETNS_KNOWN: u8 = 1 << 1;
#[expect(dead_code, reason = "the layout's full flag vocabulary")]
pub const FLAG_PRE_EXISTING: u8 = 1 << 2;
#[expect(dead_code, reason = "the layout's full flag vocabulary")]
pub const FLAG_PID_START_KNOWN: u8 = 1 << 3;
#[expect(dead_code, reason = "the layout's full flag vocabulary")]
pub const FLAG_DURATION_KNOWN: u8 = 1 << 4;

const HEADER: usize = 8;
const KEY: usize = 44;

pub const CONNECT_FRAME: usize = HEADER + KEY + 48;
pub const VOLUME_FRAME: usize = HEADER + KEY + 24;
pub const CLOSE_FRAME: usize = HEADER + KEY + 8;

/// The connection a frame belongs to, in the shape the loader's `RawKey` is
/// decoded from.
///
/// `src_ip` is sixteen bytes for both address families because the layout gives
/// both the same room; an IPv4 address occupies the first four and the rest are
/// zero, which is what the decoder reads when the IPv6 flag is clear.
pub struct Key {
    pub netns: u64,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
}

/// Writes the eight byte header into the front of a frame.
///
/// `body_len` is the frame minus the header, and the decoder compares it against
/// what actually arrived. A ring buffer overrun that cut a record in half is
/// therefore a length mismatch rather than a record with a real key and invented
/// counts.
fn header(frame: &mut [u8], kind: u8, protocol: u8, flags: u8, body_len: u16) {
    frame[0] = kind;
    frame[1] = protocol;
    frame[2] = flags;
    frame[3] = LAYOUT_VERSION;
    let len = body_len.to_le_bytes();
    frame[4] = len[0];
    frame[5] = len[1];
    // Bytes six and seven are reserved and the decoder refuses a frame that
    // carries anything in them. Writing them explicitly rather than trusting the
    // buffer to be zeroed is the difference between a guarantee and a habit.
    frame[6] = 0;
    frame[7] = 0;
}

fn key_bytes(frame: &mut [u8], key: &Key) {
    let netns = key.netns.to_le_bytes();
    frame[HEADER..HEADER + 8].copy_from_slice(&netns);
    frame[HEADER + 8..HEADER + 24].copy_from_slice(&key.src_ip);
    frame[HEADER + 24..HEADER + 40].copy_from_slice(&key.dst_ip);
    let src = key.src_port.to_le_bytes();
    frame[HEADER + 40] = src[0];
    frame[HEADER + 41] = src[1];
    let dst = key.dst_port.to_le_bytes();
    frame[HEADER + 42] = dst[0];
    frame[HEADER + 43] = dst[1];
}

/// A connection being opened, in the context of the task that opened it.
///
/// `pid_start_time` is absent rather than zero, and the flag says so. This
/// object does not read `task_struct`, whose field offsets are not in the stable
/// prefix the rest of this program confines itself to, so the field it cannot
/// measure is declared missing instead of filled with a plausible number. The
/// cost is real and is stated in the gate artefact: two processes handed the
/// same pid during one observation are not told apart.
pub fn connect(
    key: &Key,
    protocol: u8,
    flags: u8,
    t_start_bucket: u64,
    at_secs: u64,
    pid: u32,
    comm: &[u8; 16],
) -> [u8; CONNECT_FRAME] {
    let mut frame = [0u8; CONNECT_FRAME];
    header(
        &mut frame,
        KIND_CONNECT,
        protocol,
        flags,
        (CONNECT_FRAME - HEADER) as u16,
    );
    key_bytes(&mut frame, key);
    let body = HEADER + KEY;
    frame[body..body + 8].copy_from_slice(&t_start_bucket.to_le_bytes());
    frame[body + 8..body + 16].copy_from_slice(&at_secs.to_le_bytes());
    frame[body + 16..body + 20].copy_from_slice(&pid.to_le_bytes());
    // Bytes twenty to twenty four are padding, so the two sixty four bit fields
    // either side of the pid sit where a C structure would put them.
    frame[body + 32..body + 48].copy_from_slice(comm);
    frame
}

/// Bytes moved, accumulated per call rather than per packet.
pub fn volume(
    key: &Key,
    protocol: u8,
    flags: u8,
    bytes_out: u64,
    bytes_in: u64,
    segments_out: u64,
) -> [u8; VOLUME_FRAME] {
    let mut frame = [0u8; VOLUME_FRAME];
    header(
        &mut frame,
        KIND_VOLUME,
        protocol,
        flags,
        (VOLUME_FRAME - HEADER) as u16,
    );
    key_bytes(&mut frame, key);
    let body = HEADER + KEY;
    frame[body..body + 8].copy_from_slice(&bytes_out.to_le_bytes());
    frame[body + 8..body + 16].copy_from_slice(&bytes_in.to_le_bytes());
    frame[body + 16..body + 24].copy_from_slice(&segments_out.to_le_bytes());
    frame
}

/// A connection ending.
///
/// The duration flag is left clear when this object could not measure one, and
/// the decoder then reports absence rather than a zero millisecond connection.
pub fn close(key: &Key, protocol: u8, flags: u8, duration_ms: u64) -> [u8; CLOSE_FRAME] {
    let mut frame = [0u8; CLOSE_FRAME];
    header(
        &mut frame,
        KIND_CLOSE,
        protocol,
        flags,
        (CLOSE_FRAME - HEADER) as u16,
    );
    key_bytes(&mut frame, key);
    let body = HEADER + KEY;
    frame[body..body + 8].copy_from_slice(&duration_ms.to_le_bytes());
    frame
}
