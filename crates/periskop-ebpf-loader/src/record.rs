//! The layout the kernel program writes and this crate reads.
//!
//! This is the contract across the seam, and pinning it down is most of what
//! makes the remaining loader work a hookup rather than a design. It is also the
//! one part of the seam that can be written and tested today: a frame is a byte
//! slice, and a decoder over a byte slice runs on every machine in the
//! workspace and can be fed truncated, reordered and hostile input in a way a
//! ring buffer never can be.
//!
//! # Decisions the layout makes
//!
//! **Little endian, everywhere.** Every target in ADR-002 is little endian and
//! so is the BPF instruction set on all of them. Writing "native endian" into a
//! wire format would mean the decoder's correctness depended on which machine
//! read the buffer, which is exactly the class of bug a fixed layout exists to
//! remove.
//!
//! **Decoded field by field, never reinterpreted.** A frame arrives as bytes
//! with no alignment guarantee and contents this process did not write. Casting
//! that to a `#[repr(C)]` structure would be undefined behaviour on the
//! alignment alone, and would additionally accept any bit pattern as a valid
//! value of every field. Reading each field with [`u64::from_le_bytes`] and
//! friends is both correct and, notably, needs no part of the exception this
//! crate holds. The exception is for opening the buffer, not for reading it.
//!
//! **A version byte and a reserved field, both checked.** A decoder that
//! ignored them would keep decoding confidently after the layout changed, and
//! would misread a longer record as a truncated one. Refusing an unknown version
//! is how a mismatched kernel object announces itself instead of producing
//! plausible nonsense.
//!
//! # What a record may and may not carry
//!
//! [`RawEvent::Connect`], [`RawEvent::Volume`] and [`RawEvent::Close`] come from
//! the kprobe hooks, which run in the calling task's context, so
//! [`RawEvent::Connect`] carries a process and it is the right one.
//!
//! [`RawEvent::Payload`] comes from the `tc` helper, which sees packets far
//! below the socket layer where no task context exists. **It has no process
//! field, and that is the design**: ADR-008 makes it a binding rule that `tc`
//! never produces process attribution, and a variant with a nullable process
//! field would leave the rule to whoever writes the next branch. Here it is not
//! expressible.
//!
//! [`RawEvent::Payload`] is also the only place in this crate where packet bytes
//! exist. They cross the seam once, into the sensor's parsers, and the facts are
//! what travel onward; nothing downstream of that call can hold a packet. The
//! parse happens on the sensor's side rather than here because what a DNS answer
//! or a handshake *means* is a decision about what a report says, and ADR-014 §3
//! keeps every one of those on the side that runs in continuous integration.

use std::net::IpAddr;

/// Header, then the flow key, then a body that depends on the kind.
const HEADER_BYTES: usize = 8;
/// `netns`, both addresses, both ports.
const KEY_BYTES: usize = 44;
/// Start bucket, observation clock, pid, padding, pid start time, `comm`.
const CONNECT_BODY_BYTES: usize = 48;
/// Bytes out, bytes in, segments out.
const VOLUME_BODY_BYTES: usize = 24;
/// Duration.
const CLOSE_BODY_BYTES: usize = 8;
/// Start bucket and observation clock, ahead of the sample itself.
const PAYLOAD_BODY_BYTES: usize = 16;
/// The kernel's `TASK_COMM_LEN`.
const COMM_BYTES: usize = 16;

/// The layout this build decodes. Bumped when a field moves.
const LAYOUT_VERSION: u8 = 1;

const KIND_CONNECT: u8 = 1;
const KIND_VOLUME: u8 = 2;
const KIND_CLOSE: u8 = 3;
const KIND_PAYLOAD: u8 = 4;

/// From the IP header, so the values are the ones `/etc/protocols` uses.
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;

const FLAG_IPV6: u8 = 1 << 0;
const FLAG_NETNS_KNOWN: u8 = 1 << 1;
const FLAG_PRE_EXISTING: u8 = 1 << 2;
const FLAG_PID_START_KNOWN: u8 = 1 << 3;
const FLAG_DURATION_KNOWN: u8 = 1 << 4;
const FLAG_PAYLOAD_IS_DNS: u8 = 1 << 5;

/// Why a frame could not be read.
///
/// A frame this decoder rejects is a frame nothing downstream will ever see, so
/// the reason has to be specific enough for somebody to act on. "Malformed"
/// alone would leave a kernel object built against a different layout looking
/// identical to a ring buffer overrun that cut a record in half.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// The frame ended before a field the layout requires.
    #[error("frame needs at least {needed} bytes and carried {got}")]
    Truncated { needed: usize, got: usize },
    /// The header's length field and the frame disagree, which means the writer
    /// and this decoder do not have the same layout in mind.
    #[error("frame declared {declared} body bytes and carried {actual}")]
    LengthMismatch { declared: usize, actual: usize },
    /// A record kind this build has no meaning for.
    #[error("unknown record kind {0}")]
    UnknownKind(u8),
    /// A transport this sensor does not observe.
    #[error("unknown transport protocol {0}")]
    UnknownProtocol(u8),
    /// A layout this build was not written against.
    #[error("record layout version {0} is not the one this build decodes")]
    UnsupportedVersion(u8),
    /// Reserved header bytes carried something. Ignoring them is how a decoder
    /// keeps working confidently after the layout has changed underneath it.
    #[error("reserved header bytes were not zero")]
    ReservedNotZero,
}

/// The transports this sensor observes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    /// The label the sensor and the report use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    fn decode(raw: u8) -> Result<Self, RecordError> {
        match raw {
            PROTOCOL_TCP => Ok(Self::Tcp),
            PROTOCOL_UDP => Ok(Self::Udp),
            other => Err(RecordError::UnknownProtocol(other)),
        }
    }
}

/// The connection a record belongs to.
///
/// Carries the source address because that is what the join needs, and the
/// sensor drops it in the one place that turns a key into something a record may
/// hold. It identifies the machine rather than the connection, and reports in
/// this project have to compare equal across machines.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RawKey {
    /// Network namespace inode, absent where the kernel did not supply one.
    /// Absence is a flag rather than a zero, because zero is a value a decoder
    /// would otherwise have to guess the meaning of.
    pub netns: Option<u64>,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: Protocol,
}

/// The process context a kprobe read out of the running task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawProcess {
    pub pid: u32,
    /// Distinguishes two processes given the same pid over a long observation.
    pub pid_start_time: Option<u64>,
    /// The short name the kernel keeps. Absent when the field was empty or held
    /// bytes that are not text; a mangled name in a report is worse than none,
    /// because a reader cannot tell it was mangled.
    pub comm: Option<String>,
}

/// Which of the two parses the sensor should run on a sample.
///
/// Decided by the `tc` program, which knows the port and direction the packet
/// arrived on. Which parse to run is not the same question as what the result
/// means, and only the first one is answered here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    /// A DNS response, for the address to name map.
    DnsResponse,
    /// The first packet of a TLS connection, for the server name.
    TlsClientHello,
}

/// One thing a hook reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawEvent {
    /// A connection being opened, seen in the context of the task opening it.
    Connect {
        key: RawKey,
        /// Start time already rounded to the contract's bucket. Rounding in the
        /// capture path keeps a raw stamp from ever existing in a value a report
        /// is derived from.
        t_start_bucket: u64,
        /// Seconds since the sensor started looking. Not a wall clock: it ages
        /// the DNS map and must not reach a record.
        at_secs: u64,
        process: RawProcess,
        /// Set for connections found by scanning existing sockets at startup
        /// rather than by the hook firing. Their counts are lower bounds.
        pre_existing: bool,
    },
    /// Bytes moved, accumulated per call rather than per packet.
    Volume {
        key: RawKey,
        bytes_out: u64,
        bytes_in: u64,
        segments_out: u64,
    },
    /// A connection ending.
    Close {
        key: RawKey,
        duration_ms: Option<u64>,
    },
    /// A packet sample, with no process and no interpretation.
    Payload {
        key: RawKey,
        t_start_bucket: u64,
        at_secs: u64,
        kind: PayloadKind,
        /// The bounded sample the `tc` program copied. Bounded by the program's
        /// own snaplen, and the only bytes in this crate.
        sample: Vec<u8>,
    },
}

impl RawEvent {
    /// The connection this event belongs to.
    pub fn key(&self) -> &RawKey {
        match self {
            Self::Connect { key, .. }
            | Self::Volume { key, .. }
            | Self::Close { key, .. }
            | Self::Payload { key, .. } => key,
        }
    }

    /// Reads one ring buffer frame.
    ///
    /// Rejects rather than repairs. A frame this build cannot read is a frame
    /// written by something that does not share its layout, and guessing at the
    /// intent would put invented values in a report.
    pub fn decode(frame: &[u8]) -> Result<Self, RecordError> {
        let Some(&[kind, protocol, flags, version, len_low, len_high, reserved_low, reserved_high]) =
            frame.get(..HEADER_BYTES)
        else {
            return Err(RecordError::Truncated {
                needed: HEADER_BYTES,
                got: frame.len(),
            });
        };

        if version != LAYOUT_VERSION {
            return Err(RecordError::UnsupportedVersion(version));
        }
        if u16::from_le_bytes([reserved_low, reserved_high]) != 0 {
            return Err(RecordError::ReservedNotZero);
        }

        let declared = usize::from(u16::from_le_bytes([len_low, len_high]));
        let body = frame.get(HEADER_BYTES..).unwrap_or_default();
        if body.len() != declared {
            return Err(RecordError::LengthMismatch {
                declared,
                actual: body.len(),
            });
        }

        let key = decode_key(body, Protocol::decode(protocol)?, flags)?;
        let tail = body.get(KEY_BYTES..).unwrap_or_default();
        match kind {
            KIND_CONNECT => decode_connect(key, tail, flags),
            KIND_VOLUME => decode_volume(key, tail),
            KIND_CLOSE => decode_close(key, tail, flags),
            KIND_PAYLOAD => decode_payload(key, tail, flags),
            other => Err(RecordError::UnknownKind(other)),
        }
    }
}

fn decode_key(body: &[u8], protocol: Protocol, flags: u8) -> Result<RawKey, RecordError> {
    let key = body.get(..KEY_BYTES).ok_or(RecordError::Truncated {
        needed: KEY_BYTES,
        got: body.len(),
    })?;
    let ipv6 = flags & FLAG_IPV6 != 0;
    Ok(RawKey {
        netns: flag_guarded(flags, FLAG_NETNS_KNOWN, u64_at(key, 0)?),
        src_ip: ip_at(key, 8, ipv6)?,
        dst_ip: ip_at(key, 24, ipv6)?,
        src_port: u16_at(key, 40)?,
        dst_port: u16_at(key, 42)?,
        protocol,
    })
}

fn decode_connect(key: RawKey, tail: &[u8], flags: u8) -> Result<RawEvent, RecordError> {
    let body = exactly(tail, CONNECT_BODY_BYTES)?;
    Ok(RawEvent::Connect {
        key,
        t_start_bucket: u64_at(body, 0)?,
        at_secs: u64_at(body, 8)?,
        process: RawProcess {
            pid: u32_at(body, 16)?,
            // Bytes 20 to 24 are padding, so the two 64 bit fields either side
            // of the pid stay where a C structure would put them.
            pid_start_time: flag_guarded(flags, FLAG_PID_START_KNOWN, u64_at(body, 24)?),
            comm: comm_at(body, 32)?,
        },
        pre_existing: flags & FLAG_PRE_EXISTING != 0,
    })
}

fn decode_volume(key: RawKey, tail: &[u8]) -> Result<RawEvent, RecordError> {
    let body = exactly(tail, VOLUME_BODY_BYTES)?;
    Ok(RawEvent::Volume {
        key,
        bytes_out: u64_at(body, 0)?,
        bytes_in: u64_at(body, 8)?,
        segments_out: u64_at(body, 16)?,
    })
}

fn decode_close(key: RawKey, tail: &[u8], flags: u8) -> Result<RawEvent, RecordError> {
    let body = exactly(tail, CLOSE_BODY_BYTES)?;
    Ok(RawEvent::Close {
        key,
        duration_ms: flag_guarded(flags, FLAG_DURATION_KNOWN, u64_at(body, 0)?),
    })
}

fn decode_payload(key: RawKey, tail: &[u8], flags: u8) -> Result<RawEvent, RecordError> {
    let head = tail
        .get(..PAYLOAD_BODY_BYTES)
        .ok_or(RecordError::Truncated {
            needed: PAYLOAD_BODY_BYTES,
            got: tail.len(),
        })?;
    let sample = tail.get(PAYLOAD_BODY_BYTES..).unwrap_or_default();
    Ok(RawEvent::Payload {
        key,
        t_start_bucket: u64_at(head, 0)?,
        at_secs: u64_at(head, 8)?,
        kind: if flags & FLAG_PAYLOAD_IS_DNS != 0 {
            PayloadKind::DnsResponse
        } else {
            PayloadKind::TlsClientHello
        },
        sample: sample.to_vec(),
    })
}

/// A field that is only meaningful when the writer said it filled it in.
///
/// Zero is a legal value for both fields this guards, so "zero means absent"
/// would turn a real measurement into a missing one.
fn flag_guarded(flags: u8, bit: u8, value: u64) -> Option<u64> {
    (flags & bit != 0).then_some(value)
}

fn exactly(body: &[u8], expected: usize) -> Result<&[u8], RecordError> {
    if body.len() == expected {
        Ok(body)
    } else {
        Err(RecordError::LengthMismatch {
            declared: expected,
            actual: body.len(),
        })
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, RecordError> {
    Ok(u16::from_le_bytes(array_at(bytes, offset)?))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, RecordError> {
    Ok(u32::from_le_bytes(array_at(bytes, offset)?))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, RecordError> {
    Ok(u64::from_le_bytes(array_at(bytes, offset)?))
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], RecordError> {
    bytes
        .get(offset..offset.saturating_add(N))
        .and_then(|slice| <[u8; N]>::try_from(slice).ok())
        .ok_or(RecordError::Truncated {
            needed: offset.saturating_add(N),
            got: bytes.len(),
        })
}

/// Both address families occupy the same sixteen bytes, so one layout serves
/// both and a v4 record is not a different shape from a v6 one.
fn ip_at(bytes: &[u8], offset: usize, ipv6: bool) -> Result<IpAddr, RecordError> {
    let raw: [u8; 16] = array_at(bytes, offset)?;
    if ipv6 {
        return Ok(IpAddr::from(raw));
    }
    let four: [u8; 4] = array_at(&raw, 0)?;
    Ok(IpAddr::from(four))
}

/// The kernel's `comm` is a fixed sixteen byte field, NUL padded, and its
/// contents are whatever the program was named.
///
/// Not text is treated as not present. The alternative, a lossy conversion,
/// would put replacement characters in a report where a reader would take them
/// for the process name.
fn comm_at(bytes: &[u8], offset: usize) -> Result<Option<String>, RecordError> {
    let raw: [u8; COMM_BYTES] = array_at(bytes, offset)?;
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(COMM_BYTES);
    let Some(text) = raw
        .get(..end)
        .and_then(|slice| std::str::from_utf8(slice).ok())
    else {
        return Ok(None);
    };
    Ok((!text.is_empty()).then(|| text.to_owned()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// Builds a frame the way the kernel program will have to build one.
    ///
    /// Lives in the test module rather than in the crate: an encoder in the
    /// shipped library would be a way to manufacture records that look observed
    /// and are not, which is the one thing this whole component exists to make
    /// impossible.
    struct Frame {
        kind: u8,
        protocol: u8,
        flags: u8,
        version: u8,
        reserved: u16,
        key: Vec<u8>,
        tail: Vec<u8>,
    }

    impl Frame {
        fn new(kind: u8) -> Self {
            let mut key = Vec::new();
            key.extend_from_slice(&4_026_531_840u64.to_le_bytes());
            key.extend_from_slice(&mapped(&[10, 1, 2, 3]));
            key.extend_from_slice(&mapped(&[104, 18, 7, 1]));
            key.extend_from_slice(&54_321u16.to_le_bytes());
            key.extend_from_slice(&443u16.to_le_bytes());
            Self {
                kind,
                protocol: PROTOCOL_TCP,
                flags: FLAG_NETNS_KNOWN,
                version: LAYOUT_VERSION,
                reserved: 0,
                key,
                tail: Vec::new(),
            }
        }

        fn connect() -> Self {
            let mut frame = Self::new(KIND_CONNECT);
            frame.flags |= FLAG_PID_START_KNOWN;
            frame
                .tail
                .extend_from_slice(&1_785_834_000u64.to_le_bytes());
            frame.tail.extend_from_slice(&7u64.to_le_bytes());
            frame.tail.extend_from_slice(&4_821u32.to_le_bytes());
            frame.tail.extend_from_slice(&0u32.to_le_bytes());
            frame
                .tail
                .extend_from_slice(&1_785_833_900u64.to_le_bytes());
            frame.with_comm(b"python3")
        }

        fn with_comm(mut self, comm: &[u8]) -> Self {
            let mut padded = [0u8; COMM_BYTES];
            padded.get_mut(..comm.len()).unwrap().copy_from_slice(comm);
            self.tail.extend_from_slice(&padded);
            self
        }

        fn flagged(mut self, bit: u8) -> Self {
            self.flags |= bit;
            self
        }

        fn unflagged(mut self, bit: u8) -> Self {
            self.flags &= !bit;
            self
        }

        fn bytes(&self) -> Vec<u8> {
            let body_len = self.key.len() + self.tail.len();
            let mut frame = vec![self.kind, self.protocol, self.flags, self.version];
            frame.extend_from_slice(&u16::try_from(body_len).unwrap().to_le_bytes());
            frame.extend_from_slice(&self.reserved.to_le_bytes());
            frame.extend_from_slice(&self.key);
            frame.extend_from_slice(&self.tail);
            frame
        }

        fn decode(&self) -> Result<RawEvent, RecordError> {
            RawEvent::decode(&self.bytes())
        }
    }

    /// Sixteen bytes for both families, v4 in the first four.
    fn mapped(address: &[u8]) -> [u8; 16] {
        let mut raw = [0u8; 16];
        raw.get_mut(..address.len())
            .unwrap()
            .copy_from_slice(address);
        raw
    }

    fn volume() -> Frame {
        let mut frame = Frame::new(KIND_VOLUME);
        frame.tail.extend_from_slice(&8_192u64.to_le_bytes());
        frame.tail.extend_from_slice(&1_024u64.to_le_bytes());
        frame.tail.extend_from_slice(&6u64.to_le_bytes());
        frame
    }

    fn close() -> Frame {
        let mut frame = Frame::new(KIND_CLOSE).flagged(FLAG_DURATION_KNOWN);
        frame.tail.extend_from_slice(&1_500u64.to_le_bytes());
        frame
    }

    fn payload(sample: &[u8], dns: bool) -> Frame {
        let mut frame = Frame::new(KIND_PAYLOAD);
        if dns {
            frame.flags |= FLAG_PAYLOAD_IS_DNS;
        }
        frame
            .tail
            .extend_from_slice(&1_785_834_000u64.to_le_bytes());
        frame.tail.extend_from_slice(&3u64.to_le_bytes());
        frame.tail.extend_from_slice(sample);
        frame
    }

    #[test]
    fn a_connect_frame_decodes_into_the_process_that_opened_the_connection() {
        let event = Frame::connect().decode().unwrap();
        let RawEvent::Connect {
            key,
            t_start_bucket,
            at_secs,
            process,
            pre_existing,
        } = event
        else {
            panic!("a connect frame decoded as something else: {event:?}");
        };
        assert_eq!(key.dst_ip.to_string(), "104.18.7.1");
        assert_eq!(key.src_port, 54_321);
        assert_eq!(key.dst_port, 443);
        assert_eq!(key.netns, Some(4_026_531_840));
        assert_eq!(key.protocol, Protocol::Tcp);
        assert_eq!(t_start_bucket, 1_785_834_000);
        assert_eq!(at_secs, 7);
        assert_eq!(process.pid, 4_821);
        assert_eq!(process.pid_start_time, Some(1_785_833_900));
        assert_eq!(process.comm.as_deref(), Some("python3"));
        assert!(!pre_existing);
    }

    #[test]
    fn a_volume_frame_decodes_into_the_counts_the_kprobe_accumulated() {
        let event = volume().decode().unwrap();
        assert_eq!(
            event,
            RawEvent::Volume {
                key: event.key().clone(),
                bytes_out: 8_192,
                bytes_in: 1_024,
                segments_out: 6,
            }
        );
    }

    #[test]
    fn a_close_frame_without_the_duration_flag_says_absent_rather_than_zero() {
        // A connection that closed in under a millisecond and a connection whose
        // duration the kernel never recorded are different facts. Reading an
        // unset field as zero would report the second as the first.
        let measured = close().decode().unwrap();
        assert!(matches!(
            measured,
            RawEvent::Close {
                duration_ms: Some(1_500),
                ..
            }
        ));
        let unmeasured = close().unflagged(FLAG_DURATION_KNOWN).decode().unwrap();
        assert!(matches!(
            unmeasured,
            RawEvent::Close {
                duration_ms: None,
                ..
            }
        ));
    }

    #[test]
    fn a_namespace_the_kernel_did_not_supply_is_absent_and_not_inode_zero() {
        let unnamed = Frame::connect()
            .unflagged(FLAG_NETNS_KNOWN)
            .decode()
            .unwrap();
        assert_eq!(unnamed.key().netns, None);
    }

    #[test]
    fn a_pid_start_time_the_kernel_did_not_supply_is_absent() {
        // Without it, two processes that were handed the same pid over a long
        // observation collapse into one, and the flows of the second are
        // attributed to the first.
        let event = Frame::connect()
            .unflagged(FLAG_PID_START_KNOWN)
            .decode()
            .unwrap();
        let RawEvent::Connect { process, .. } = event else {
            panic!("expected a connect event");
        };
        assert_eq!(process.pid_start_time, None);
    }

    #[test]
    fn a_pre_existing_connection_is_marked_as_one() {
        // Its counts are lower bounds, and a record that did not say so would
        // understate volume without anything indicating that it had.
        let event = Frame::connect()
            .flagged(FLAG_PRE_EXISTING)
            .decode()
            .unwrap();
        assert!(matches!(
            event,
            RawEvent::Connect {
                pre_existing: true,
                ..
            }
        ));
    }

    #[test]
    fn an_ipv6_frame_decodes_both_addresses_as_ipv6() {
        let mut frame = Frame::connect().flagged(FLAG_IPV6);
        let mut key = Vec::new();
        key.extend_from_slice(&4_026_531_840u64.to_le_bytes());
        key.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        key.extend_from_slice(&[
            0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x68, 0x10, 0x07, 0x01,
        ]);
        key.extend_from_slice(&54_321u16.to_le_bytes());
        key.extend_from_slice(&443u16.to_le_bytes());
        frame.key = key;
        let event = frame.decode().unwrap();
        assert_eq!(event.key().dst_ip.to_string(), "2606:4700::6810:701");
        assert!(event.key().src_ip.is_ipv6());
    }

    #[test]
    fn a_payload_frame_carries_the_sample_and_nowhere_to_put_a_process() {
        // ADR-008 forbids `tc` from producing attribution. Making it
        // inexpressible is stronger than checking for it.
        let event = payload(&[0x16, 0x03, 0x01], false).decode().unwrap();
        let RawEvent::Payload {
            kind,
            sample,
            at_secs,
            ..
        } = &event
        else {
            panic!("expected a payload event");
        };
        assert_eq!(*kind, PayloadKind::TlsClientHello);
        assert_eq!(sample, &[0x16, 0x03, 0x01]);
        assert_eq!(*at_secs, 3);
        let printed = format!("{event:?}");
        assert!(!printed.contains("pid"), "tc gained a process: {printed}");
    }

    #[test]
    fn a_dns_payload_is_flagged_for_the_other_parser() {
        let event = payload(&[0x00, 0x01], true).decode().unwrap();
        assert!(matches!(
            event,
            RawEvent::Payload {
                kind: PayloadKind::DnsResponse,
                ..
            }
        ));
    }

    #[test]
    fn an_empty_payload_sample_decodes_rather_than_being_rejected() {
        // The helper copies up to its snaplen and may see a packet with nothing
        // in it. That is a sample with no facts in it, not a broken frame, and
        // the parsers on the other side already have a vocabulary for it.
        let event = payload(&[], true).decode().unwrap();
        let RawEvent::Payload { sample, .. } = &event else {
            panic!("expected a payload event");
        };
        assert!(sample.is_empty());
    }

    #[test]
    fn a_frame_shorter_than_the_header_is_rejected_and_not_padded() {
        assert_eq!(
            RawEvent::decode(&[1, 6, 0]),
            Err(RecordError::Truncated {
                needed: HEADER_BYTES,
                got: 3
            })
        );
        assert_eq!(
            RawEvent::decode(&[]),
            Err(RecordError::Truncated {
                needed: HEADER_BYTES,
                got: 0
            })
        );
    }

    #[test]
    fn a_frame_cut_short_after_the_header_is_a_length_mismatch() {
        // What a ring buffer overrun looks like from here. Decoding the part
        // that arrived would produce a record with a real key and invented
        // counts.
        let mut bytes = Frame::connect().bytes();
        bytes.truncate(bytes.len() - 4);
        assert!(matches!(
            RawEvent::decode(&bytes),
            Err(RecordError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn a_frame_longer_than_it_declared_is_rejected_rather_than_trimmed() {
        // Trimming would silently accept a record written by a newer kernel
        // object with extra fields, and read its new field as the old one.
        let mut bytes = Frame::connect().bytes();
        bytes.push(0);
        assert!(matches!(
            RawEvent::decode(&bytes),
            Err(RecordError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn a_layout_version_this_build_does_not_know_is_refused() {
        // The whole point of the field: a kernel object from a different build
        // announces itself instead of producing plausible nonsense.
        let mut frame = Frame::connect();
        frame.version = LAYOUT_VERSION + 1;
        assert_eq!(
            frame.decode(),
            Err(RecordError::UnsupportedVersion(LAYOUT_VERSION + 1))
        );
    }

    #[test]
    fn reserved_bytes_carrying_something_are_refused() {
        let mut frame = Frame::connect();
        frame.reserved = 1;
        assert_eq!(frame.decode(), Err(RecordError::ReservedNotZero));
    }

    #[test]
    fn a_record_kind_this_build_has_no_meaning_for_is_refused() {
        let mut frame = Frame::connect();
        frame.kind = 9;
        assert_eq!(frame.decode(), Err(RecordError::UnknownKind(9)));
    }

    #[test]
    fn a_transport_this_sensor_does_not_observe_is_refused() {
        // ICMP, for instance. Decoding it as TCP would put a flow in the report
        // with ports that are not ports.
        let mut frame = Frame::connect();
        frame.protocol = 1;
        assert_eq!(frame.decode(), Err(RecordError::UnknownProtocol(1)));
    }

    #[test]
    fn udp_decodes_as_udp() {
        let mut frame = Frame::connect();
        frame.protocol = PROTOCOL_UDP;
        assert_eq!(frame.decode().unwrap().key().protocol, Protocol::Udp);
        assert_eq!(Protocol::Udp.as_str(), "udp");
        assert_eq!(Protocol::Tcp.as_str(), "tcp");
    }

    #[test]
    fn a_comm_the_kernel_wrote_in_bytes_that_are_not_text_is_absent_not_mangled() {
        // A lossy conversion would put replacement characters in a report where
        // a reader would take them for the program's actual name.
        let mut frame = Frame::new(KIND_CONNECT);
        frame.flags |= FLAG_PID_START_KNOWN;
        frame
            .tail
            .extend_from_slice(&1_785_834_000u64.to_le_bytes());
        frame.tail.extend_from_slice(&7u64.to_le_bytes());
        frame.tail.extend_from_slice(&4_821u32.to_le_bytes());
        frame.tail.extend_from_slice(&0u32.to_le_bytes());
        frame
            .tail
            .extend_from_slice(&1_785_833_900u64.to_le_bytes());
        let event = frame.with_comm(&[0xff, 0xfe]).decode().unwrap();
        let RawEvent::Connect { process, .. } = event else {
            panic!("expected a connect event");
        };
        assert_eq!(process.comm, None);
    }

    #[test]
    fn an_empty_comm_field_is_absent_rather_than_an_empty_name() {
        let mut frame = Frame::new(KIND_CONNECT);
        frame
            .tail
            .extend_from_slice(&1_785_834_000u64.to_le_bytes());
        frame.tail.extend_from_slice(&7u64.to_le_bytes());
        frame.tail.extend_from_slice(&4_821u32.to_le_bytes());
        frame.tail.extend_from_slice(&0u32.to_le_bytes());
        frame.tail.extend_from_slice(&0u64.to_le_bytes());
        let event = frame.with_comm(b"").decode().unwrap();
        let RawEvent::Connect { process, .. } = event else {
            panic!("expected a connect event");
        };
        assert_eq!(process.comm, None);
    }

    #[test]
    fn a_comm_that_fills_the_field_is_read_without_a_terminator() {
        // Sixteen bytes with no NUL is what the kernel writes for a name that
        // fills the field, and a decoder looking for the terminator first would
        // read past it.
        let mut frame = Frame::new(KIND_CONNECT);
        frame
            .tail
            .extend_from_slice(&1_785_834_000u64.to_le_bytes());
        frame.tail.extend_from_slice(&7u64.to_le_bytes());
        frame.tail.extend_from_slice(&4_821u32.to_le_bytes());
        frame.tail.extend_from_slice(&0u32.to_le_bytes());
        frame.tail.extend_from_slice(&0u64.to_le_bytes());
        let event = frame.with_comm(b"sixteencharname!").decode().unwrap();
        let RawEvent::Connect { process, .. } = event else {
            panic!("expected a connect event");
        };
        assert_eq!(process.comm.as_deref(), Some("sixteencharname!"));
    }

    #[test]
    fn the_same_frame_decodes_the_same_way_twice() {
        // Determinism at the entry point. Everything downstream is derived from
        // this, so a decoder with any state in it would make two captures of one
        // connection serialize differently.
        let frame = Frame::connect().bytes();
        assert_eq!(RawEvent::decode(&frame), RawEvent::decode(&frame));
    }

    #[test]
    fn every_kind_reports_the_flow_it_belongs_to() {
        let frames = [
            Frame::connect().bytes(),
            volume().bytes(),
            close().bytes(),
            payload(&[1, 2], true).bytes(),
        ];
        for frame in frames {
            let event = RawEvent::decode(&frame).unwrap();
            assert_eq!(event.key().dst_port, 443);
        }
    }
}
