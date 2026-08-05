//! The bytes of `vault.psk`: a header, then an append-only block of frames.
//!
//! ADR-007 names the header's *fields* and says nothing about their order, their
//! width or their byte order. SB-9 is that gap. ADR-014 section 6.5 did the same
//! job for the network sensor's ring buffer and the four decisions it recorded
//! are the four made here, for the same reasons:
//!
//! - **Little endian, everywhere.** Writing "native endian" would make a file
//!   written on one machine unreadable on another while looking correct on both.
//! - **Field by field decoding, no reinterpretation.** Nothing is cast to a
//!   `#[repr(C)]` struct. A cast would be undefined behaviour on an unaligned
//!   buffer, would accept every bit pattern as a valid value, and would need
//!   `unsafe`, which the root manifest forbids.
//! - **The version and the reserved fields are checked.** A file from an
//!   incompatible layout says so instead of producing plausible nonsense, and a
//!   reserved field that is not zero is a refusal rather than a field silently
//!   ignored.
//! - **Absence is a flag, never a zero.** Nothing in this layout uses zero to mean
//!   "not set"; zero is a legitimate record counter and a legitimate timestamp.
//!
//! # The map
//!
//! ```text
//! header, 128 bytes
//!   0   8  magic          "PSKVAULT"
//!   8   2  layout version major, minor
//!  10   1  key derivation tag   1 = Argon2id
//!  11   1  aead tag             1 = XChaCha20-Poly1305
//!  12   4  Argon2id memory, KiB   u32 LE
//!  16   4  Argon2id iterations    u32 LE
//!  20   4  Argon2id parallelism   u32 LE
//!  24  16  Argon2id salt
//!  40   8  reserved               u64 LE, must be zero
//!  -- the prefix above is what M_0 covers; nothing below it is ever hashed into M_0 --
//!  48   8  record_counter         u64 LE, monotonic across compaction
//!  56   8  frame_count            u64 LE, frames this header authenticates
//!  64  32  M_n, the chain tail
//!  96  32  header MAC
//!
//! frame, 96 bytes plus two variable fields
//!   0   4  frame length, this field included   u32 LE
//!   4   1  frame version
//!   5   1  record type tag
//!   6   2  reserved                            u16 LE, must be zero
//!   8   8  stored_at_ms                        u64 LE
//!  16  16  session id
//!  32  32  alias seed
//!  64  24  record nonce
//!  88   2  alias length                        u16 LE
//!  90   2  reserved                            u16 LE, must be zero
//!  92   4  sealed body length                  u32 LE
//!  96  ..  alias bytes
//!      ..  sealed body
//! ```
//!
//! # Why the record counter is not the frame count
//!
//! `record_counter` is a high water mark: it counts every record this vault has
//! ever appended and it never goes down, not even when compaction drops half the
//! file. `frame_count` is how many frames are in the file right now. Collapsing
//! them into one number would make every compaction look like a rollback, which
//! is the one thing the counter exists to detect.
//!
//! # What is in the clear, and why that is not a leak
//!
//! A frame carries the session id, the alias seed, the alias string and the
//! timestamp outside the AEAD, because the first two are inputs to the record's
//! AAD and cannot be recovered from the ciphertext they authenticate. The alias
//! is beside them for the same practical reason and one substantive one: the alias
//! is the string that was sent to the provider, so it is by construction the part
//! of the mapping that is already public. What is never in the clear is the value
//! the alias stands for. These fields are not unprotected either: the chain in
//! [`super::chain`] runs over whole frames, so none of them can be edited, swapped
//! or removed without breaking the file.

use super::chain::{ChainTag, TAG_BYTES};
use super::error::{VaultError, VaultField};
use super::key::{ClaimedKdfParameters, Salt, SALT_BYTES};
use super::record::{SealedRecord, ALIAS_SEED_BYTES, NONCE_BYTES};
use super::session::SESSION_ID_BYTES;
use super::AliasSeed;
use super::SessionId;

/// The first eight bytes of every vault file.
pub(super) const MAGIC: [u8; 8] = *b"PSKVAULT";

/// The layout this build writes and the only one it reads, as major and minor.
///
/// A minor bump is a field appended inside a reserved area; a major bump is a
/// file this build refuses. Both are checked, because a version field nobody
/// checks is documentation.
pub(super) const LAYOUT_VERSION: [u8; 2] = [1, 0];

/// Argon2id, the only key derivation this format knows (ADR-007).
const KDF_ARGON2ID: u8 = 1;
/// XChaCha20-Poly1305, the only AEAD this format knows (ADR-007 D-14, K-17).
const AEAD_XCHACHA20POLY1305: u8 = 1;

/// Bytes of the header prefix: the part `M_0` covers.
pub(super) const PREFIX_BYTES: usize = 48;
/// Bytes of the whole header.
pub(super) const HEADER_BYTES: usize = 128;

/// Bytes of a frame before its two variable length fields.
const FRAME_HEAD_BYTES: usize = 96;
/// The frame layout version.
const FRAME_VERSION: u8 = 1;

/// Longest alias a frame may carry.
///
/// ADR-010 bounds every alias by a per type maximum and the widest generator in
/// the table is well under this. The cap is here so that a forged length field
/// cannot ask this process for an arbitrary allocation before any MAC has been
/// checked.
const ALIAS_CEILING_BYTES: usize = 512;
/// Longest sealed body a frame may carry, for the same reason.
const BODY_CEILING_BYTES: usize = 64 * 1024;

/// The header, decoded but not yet trusted.
///
/// "Not yet trusted" is the whole point of the type: the Argon2id parameters are
/// [`ClaimedKdfParameters`] rather than a validated profile, because they came out
/// of a file and the key that authenticates them has not been derived yet.
#[derive(Clone, Debug)]
pub(super) struct Header {
    /// The bytes `M_0` is computed over, kept verbatim so that re-encoding cannot
    /// disagree with what was read.
    pub(super) prefix: [u8; PREFIX_BYTES],
    pub(super) claimed_kdf: ClaimedKdfParameters,
    pub(super) salt: Salt,
    pub(super) record_counter: u64,
    pub(super) frame_count: u64,
    pub(super) chain_tail: ChainTag,
    /// What the file claims the header tag is. Never compared with `==`.
    pub(super) header_mac: [u8; TAG_BYTES],
}

impl Header {
    /// Lays out the fixed prefix for a vault that is being created.
    pub(super) fn prefix_bytes(claimed: &ClaimedKdfParameters, salt: &Salt) -> [u8; PREFIX_BYTES] {
        let mut prefix = [0u8; PREFIX_BYTES];
        prefix[..8].copy_from_slice(&MAGIC);
        prefix[8..10].copy_from_slice(&LAYOUT_VERSION);
        prefix[10] = KDF_ARGON2ID;
        prefix[11] = AEAD_XCHACHA20POLY1305;
        prefix[12..16].copy_from_slice(&claimed.memory_kib.to_le_bytes());
        prefix[16..20].copy_from_slice(&claimed.iterations.to_le_bytes());
        prefix[20..24].copy_from_slice(&claimed.parallelism.to_le_bytes());
        prefix[24..40].copy_from_slice(salt.as_bytes());
        // 40..48 stays zero: the reserved word, checked on the way back in.
        prefix
    }

    /// Writes the whole header.
    pub(super) fn encode(
        prefix: &[u8; PREFIX_BYTES],
        record_counter: u64,
        frame_count: u64,
        chain_tail: &ChainTag,
        header_mac: &ChainTag,
    ) -> [u8; HEADER_BYTES] {
        let mut header = [0u8; HEADER_BYTES];
        header[..PREFIX_BYTES].copy_from_slice(prefix);
        header[48..56].copy_from_slice(&record_counter.to_le_bytes());
        header[56..64].copy_from_slice(&frame_count.to_le_bytes());
        header[64..96].copy_from_slice(chain_tail.as_bytes());
        header[96..128].copy_from_slice(header_mac.as_bytes());
        header
    }

    /// Reads a header, checking every fixed field before believing any variable
    /// one.
    ///
    /// Nothing here derives a key or allocates on a length the file chose. A file
    /// that is not this format is refused for a few comparisons, which is the same
    /// discipline `KdfProfile::validate` applies one step later.
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() < HEADER_BYTES {
            return Err(VaultError::VaultFileMalformed {
                field: VaultField::HeaderLength,
            });
        }

        if bytes[..8] != MAGIC {
            return Err(VaultError::VaultFileMalformed {
                field: VaultField::Magic,
            });
        }
        if bytes[8..10] != LAYOUT_VERSION {
            return Err(VaultError::VaultFileUnsupported {
                field: VaultField::LayoutVersion,
                found: u32::from(bytes[8]) * 1000 + u32::from(bytes[9]),
            });
        }
        if bytes[10] != KDF_ARGON2ID {
            return Err(VaultError::VaultFileUnsupported {
                field: VaultField::KdfAlgorithm,
                found: u32::from(bytes[10]),
            });
        }
        if bytes[11] != AEAD_XCHACHA20POLY1305 {
            return Err(VaultError::VaultFileUnsupported {
                field: VaultField::Aead,
                found: u32::from(bytes[11]),
            });
        }
        if read_u64(bytes, 40)? != 0 {
            // A reserved field that is not zero means the writer used it for
            // something this build does not know about. Ignoring it would be
            // reading a newer layout while claiming to understand it.
            return Err(VaultError::VaultFileMalformed {
                field: VaultField::HeaderReserved,
            });
        }

        let mut prefix = [0u8; PREFIX_BYTES];
        prefix.copy_from_slice(&bytes[..PREFIX_BYTES]);

        let mut chain_tail = [0u8; TAG_BYTES];
        chain_tail.copy_from_slice(&bytes[64..96]);
        let mut header_mac = [0u8; TAG_BYTES];
        header_mac.copy_from_slice(&bytes[96..128]);

        let mut salt = [0u8; SALT_BYTES];
        salt.copy_from_slice(&bytes[24..40]);

        Ok(Self {
            prefix,
            claimed_kdf: ClaimedKdfParameters {
                memory_kib: read_u32(bytes, 12)?,
                iterations: read_u32(bytes, 16)?,
                parallelism: read_u32(bytes, 20)?,
            },
            salt: Salt::from_bytes(salt),
            record_counter: read_u64(bytes, 48)?,
            frame_count: read_u64(bytes, 56)?,
            chain_tail: ChainTag::from_bytes(chain_tail),
            header_mac,
        })
    }
}

/// Why one frame could not be read, split by the remedy it implies.
///
/// The split exists because the caller answers the two with different words. A
/// frame whose bytes are simply not all there is a record the header counted and
/// the file does not hold, which is the chain's business; a frame whose bytes are
/// present but whose own fields do not describe them is a corrupt file, which is
/// not. `proxy/spec.md` section 10 gives those two rows opposite instructions
/// ("dur, ortamı düzelt" against "durdur ve incele"), so collapsing them here
/// would decide the operator's next move wrongly one row at a time.
#[derive(Debug)]
pub(super) enum FrameError {
    /// Fewer bytes remain than this frame needs, so a record the header counted
    /// is missing from the file.
    Truncated,
    /// The bytes are all there and a field in them is wrong. Carries the field,
    /// because the field name is the only part of this an operator can act on.
    Malformed(VaultError),
}

/// One record on disk.
#[derive(Clone)]
pub(super) struct Frame {
    pub(super) stored_at_ms: u64,
    pub(super) session: SessionId,
    pub(super) alias_seed: AliasSeed,
    pub(super) alias: String,
    pub(super) sealed: SealedRecord,
}

/// The alias, a stamp and two lengths, and no more than that.
///
/// `proxy/spec.md` section 9 fixes what may appear at `TRACE`: `entity_type`,
/// `alias`, `offset` and `confidence`. A derived `Debug` here would put the
/// session identifier, the alias seed and the sealed body into the first `{:?}` a
/// maintainer reaches for; none of those is a plaintext value, and none of them
/// belongs in a log line either.
impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("alias", &self.alias)
            .field("stored_at_ms", &self.stored_at_ms)
            .field("sealed_bytes", &self.sealed.body().len())
            .finish()
    }
}

impl Frame {
    /// Writes one frame.
    ///
    /// Refuses rather than truncating when a field is too long: a vault that
    /// silently stored a shortened alias would restore the wrong string, which is
    /// the class of silent wrong answer this component exists to rule out.
    pub(super) fn encode(&self) -> Result<Vec<u8>, VaultError> {
        let alias = self.alias.as_bytes();
        if alias.len() > ALIAS_CEILING_BYTES {
            return Err(VaultError::VaultFileMalformed {
                field: VaultField::AliasLength,
            });
        }
        let body = self.sealed.body();
        if body.len() > BODY_CEILING_BYTES {
            return Err(VaultError::VaultFileMalformed {
                field: VaultField::BodyLength,
            });
        }

        let length = FRAME_HEAD_BYTES + alias.len() + body.len();
        let Ok(length_field) = u32::try_from(length) else {
            return Err(VaultError::VaultFileMalformed {
                field: VaultField::FrameLength,
            });
        };

        let mut frame = vec![0u8; FRAME_HEAD_BYTES];
        frame[..4].copy_from_slice(&length_field.to_le_bytes());
        frame[4] = FRAME_VERSION;
        frame[5] = super::record::RecordType::Alias.tag();
        // 6..8 reserved, left zero.
        frame[8..16].copy_from_slice(&self.stored_at_ms.to_le_bytes());
        frame[16..32].copy_from_slice(self.session.as_bytes());
        frame[32..64].copy_from_slice(self.alias_seed.as_bytes());
        frame[64..88].copy_from_slice(self.sealed.nonce());
        // Both casts are inside the ceilings checked above.
        frame[88..90].copy_from_slice(&(alias.len() as u16).to_le_bytes());
        // 90..92 reserved, left zero.
        frame[92..96].copy_from_slice(&(body.len() as u32).to_le_bytes());
        frame.extend_from_slice(alias);
        frame.extend_from_slice(body);
        Ok(frame)
    }

    /// Reads one frame out of `bytes`, returning it with the bytes it occupied.
    ///
    /// The frame's own bytes come back because the chain is computed over them
    /// verbatim: re-encoding a decoded frame to hash it would let a difference
    /// between the reader and the writer pass unnoticed.
    /// The order of the checks is what separates a corrupt frame from a missing
    /// one. Everything the fixed head can be judged on is judged first, on bytes
    /// that are known to be present; only then is the declared length compared
    /// with what remains. A length word that disagrees with the two length fields
    /// beside it is wrong wherever the file ends, so it is answered as a corrupt
    /// field rather than as a short file.
    pub(super) fn decode(bytes: &[u8]) -> Result<(Self, &[u8]), FrameError> {
        if bytes.len() < FRAME_HEAD_BYTES {
            return Err(FrameError::Truncated);
        }

        // Every offset below is inside the fixed head, which the check above
        // proved is present, so none of these reads can run off the end.
        let length = read_u32(bytes, 0).map_err(FrameError::Malformed)? as usize;
        if bytes[4] != FRAME_VERSION {
            return Err(FrameError::Malformed(VaultError::VaultFileUnsupported {
                field: VaultField::FrameVersion,
                found: u32::from(bytes[4]),
            }));
        }
        let Some(record_type) = super::record::RecordType::from_tag(bytes[5]) else {
            return Err(FrameError::Malformed(VaultError::VaultFileUnsupported {
                field: VaultField::RecordType,
                found: u32::from(bytes[5]),
            }));
        };
        // One variant today, and the binding exists so that adding a second one
        // has to decide what a reader older than it should do.
        let super::record::RecordType::Alias = record_type;

        if read_u16(bytes, 6).map_err(FrameError::Malformed)? != 0
            || read_u16(bytes, 90).map_err(FrameError::Malformed)? != 0
        {
            return Err(FrameError::Malformed(VaultError::VaultFileMalformed {
                field: VaultField::FrameReserved,
            }));
        }

        let alias_len = read_u16(bytes, 88).map_err(FrameError::Malformed)? as usize;
        let body_len = read_u32(bytes, 92).map_err(FrameError::Malformed)? as usize;
        if alias_len > ALIAS_CEILING_BYTES {
            return Err(FrameError::Malformed(VaultError::VaultFileMalformed {
                field: VaultField::AliasLength,
            }));
        }
        if body_len > BODY_CEILING_BYTES {
            return Err(FrameError::Malformed(VaultError::VaultFileMalformed {
                field: VaultField::BodyLength,
            }));
        }
        // The declared length has to be exactly what the two variable fields add
        // up to. Accepting a longer one would leave bytes inside a frame that
        // nothing describes, which is where a second record could hide.
        if length != FRAME_HEAD_BYTES + alias_len + body_len {
            return Err(FrameError::Malformed(VaultError::VaultFileMalformed {
                field: VaultField::FrameLength,
            }));
        }
        // Self consistent, and longer than what is left: the frame is described
        // correctly and its bytes were cut off.
        if length > bytes.len() {
            return Err(FrameError::Truncated);
        }

        let mut session = [0u8; SESSION_ID_BYTES];
        session.copy_from_slice(&bytes[16..32]);
        let mut alias_seed = [0u8; ALIAS_SEED_BYTES];
        alias_seed.copy_from_slice(&bytes[32..64]);
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.copy_from_slice(&bytes[64..88]);

        let alias_at = FRAME_HEAD_BYTES;
        let body_at = alias_at + alias_len;
        let Ok(alias) = std::str::from_utf8(&bytes[alias_at..body_at]) else {
            // An alias is a string the proxy published; bytes that are not text
            // did not come from this product.
            return Err(FrameError::Malformed(VaultError::VaultFileMalformed {
                field: VaultField::Alias,
            }));
        };

        let frame = Self {
            stored_at_ms: read_u64(bytes, 8).map_err(FrameError::Malformed)?,
            session: SessionId::from_bytes(session),
            alias_seed: AliasSeed::from_bytes(alias_seed),
            alias: alias.to_owned(),
            sealed: SealedRecord::from_parts(nonce, bytes[body_at..length].to_vec()),
        };
        Ok((frame, &bytes[..length]))
    }
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16, VaultError> {
    let field = bytes
        .get(at..at + 2)
        .ok_or(VaultError::VaultFileMalformed {
            field: VaultField::FrameLength,
        })?;
    let mut word = [0u8; 2];
    word.copy_from_slice(field);
    Ok(u16::from_le_bytes(word))
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, VaultError> {
    let field = bytes
        .get(at..at + 4)
        .ok_or(VaultError::VaultFileMalformed {
            field: VaultField::FrameLength,
        })?;
    let mut word = [0u8; 4];
    word.copy_from_slice(field);
    Ok(u32::from_le_bytes(word))
}

fn read_u64(bytes: &[u8], at: usize) -> Result<u64, VaultError> {
    let field = bytes
        .get(at..at + 8)
        .ok_or(VaultError::VaultFileMalformed {
            field: VaultField::HeaderLength,
        })?;
    let mut word = [0u8; 8];
    word.copy_from_slice(field);
    Ok(u64::from_le_bytes(word))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::vault::chain::TAG_BYTES;

    fn claimed() -> ClaimedKdfParameters {
        ClaimedKdfParameters {
            memory_kib: 262_144,
            iterations: 3,
            parallelism: 4,
        }
    }

    fn salt() -> Salt {
        Salt::from_bytes([0xA1; SALT_BYTES])
    }

    fn header_bytes() -> [u8; HEADER_BYTES] {
        Header::encode(
            &Header::prefix_bytes(&claimed(), &salt()),
            0x0102_0304_0506_0708,
            9,
            &ChainTag::from_bytes([0x5A; TAG_BYTES]),
            &ChainTag::from_bytes([0x5B; TAG_BYTES]),
        )
    }

    fn frame() -> Frame {
        Frame {
            stored_at_ms: 1_700_000_000_000,
            session: SessionId::from_bytes([0x0A; SESSION_ID_BYTES]),
            alias_seed: AliasSeed::from_bytes([0x0B; ALIAS_SEED_BYTES]),
            alias: "PSK_PERSON_1".to_owned(),
            sealed: SealedRecord::from_parts([0x0C; NONCE_BYTES], b"sealed bytes".to_vec()),
        }
    }

    /// The byte order decision, pinned where a change has to be deliberate.
    ///
    /// ADR-014 section 6.5 made the same call for the same reason: a file written
    /// on one machine has to read the same on another, and "native endian" makes
    /// correctness a property of the reader's CPU.
    #[test]
    fn every_multi_byte_field_is_little_endian() {
        let header = header_bytes();
        assert_eq!(&header[12..16], &262_144u32.to_le_bytes());
        assert_eq!(&header[48..56], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&header[56..64], &9u64.to_le_bytes());
        // Not big endian, said as its own assertion so that a reversed write
        // cannot pass by coincidence on a palindromic value.
        assert_ne!(&header[48..56], &0x0102_0304_0506_0708u64.to_be_bytes());

        let encoded = frame().encode().unwrap();
        assert_eq!(&encoded[..4], &(encoded.len() as u32).to_le_bytes());
        assert_eq!(&encoded[8..16], &1_700_000_000_000u64.to_le_bytes());
        assert_eq!(&encoded[88..90], &12u16.to_le_bytes());
    }

    #[test]
    fn the_header_is_the_fixed_layout_the_map_describes() {
        let header = header_bytes();
        assert_eq!(header.len(), 128);
        assert_eq!(&header[..8], b"PSKVAULT");
        assert_eq!(&header[8..10], &[1, 0]);
        assert_eq!(header[10], 1, "Argon2id");
        assert_eq!(header[11], 1, "XChaCha20-Poly1305");
        assert_eq!(&header[24..40], &[0xA1; SALT_BYTES]);
        assert_eq!(&header[40..48], &[0u8; 8], "reserved");
        assert_eq!(&header[64..96], &[0x5A; TAG_BYTES]);
        assert_eq!(&header[96..128], &[0x5B; TAG_BYTES]);
    }

    #[test]
    fn a_header_survives_a_round_trip() {
        let decoded = Header::decode(&header_bytes()).unwrap();
        assert_eq!(decoded.claimed_kdf, claimed());
        assert_eq!(decoded.salt, salt());
        assert_eq!(decoded.record_counter, 0x0102_0304_0506_0708);
        assert_eq!(decoded.frame_count, 9);
        assert_eq!(decoded.chain_tail.as_bytes(), &[0x5A; TAG_BYTES]);
        assert_eq!(decoded.header_mac, [0x5B; TAG_BYTES]);
        assert_eq!(decoded.prefix, Header::prefix_bytes(&claimed(), &salt()));
    }

    #[test]
    fn a_header_that_is_not_this_format_is_refused_field_by_field() {
        let cases: [(usize, u8, VaultField); 4] = [
            (0, b'X', VaultField::Magic),
            (10, 2, VaultField::KdfAlgorithm),
            (11, 2, VaultField::Aead),
            (40, 1, VaultField::HeaderReserved),
        ];

        for (at, byte, expected) in cases {
            let mut header = header_bytes();
            header[at] = byte;
            match Header::decode(&header) {
                Err(VaultError::VaultFileMalformed { field })
                | Err(VaultError::VaultFileUnsupported { field, .. }) => {
                    assert_eq!(field, expected, "byte {at}");
                }
                other => panic!("byte {at} was accepted: {other:?}"),
            }
        }
    }

    /// The version field is checked, which is what makes it a version field.
    #[test]
    fn a_header_from_another_layout_version_says_so_rather_than_guessing() {
        for (at, value) in [(8usize, 2u8), (9, 1)] {
            let mut header = header_bytes();
            header[at] = value;
            match Header::decode(&header) {
                Err(VaultError::VaultFileUnsupported { field, .. }) => {
                    assert_eq!(field, VaultField::LayoutVersion);
                }
                other => panic!("version byte {at} was accepted: {other:?}"),
            }
        }
    }

    #[test]
    fn a_header_shorter_than_the_layout_is_refused() {
        let header = header_bytes();
        for length in [0usize, 8, 47, 127] {
            assert!(matches!(
                Header::decode(&header[..length]),
                Err(VaultError::VaultFileMalformed {
                    field: VaultField::HeaderLength
                })
            ));
        }
    }

    #[test]
    fn a_frame_survives_a_round_trip_and_reports_the_bytes_it_used() {
        let original = frame();
        let mut encoded = original.encode().unwrap();
        let used_length = encoded.len();
        // A frame is decoded out of the middle of a file, so there are more bytes
        // after it and the decoder has to stop at its own boundary.
        encoded.extend_from_slice(b"the next frame starts here");

        let (decoded, used) = Frame::decode(&encoded).unwrap();
        assert_eq!(used.len(), used_length);
        assert_eq!(decoded.stored_at_ms, original.stored_at_ms);
        assert_eq!(decoded.session, original.session);
        assert_eq!(decoded.alias_seed, original.alias_seed);
        assert_eq!(decoded.alias, original.alias);
        assert_eq!(decoded.sealed, original.sealed);
    }

    #[test]
    fn a_frame_whose_length_disagrees_with_its_fields_is_refused() {
        let mut encoded = frame().encode().unwrap();
        let honest = encoded.len() as u32;

        // Longer than the fields describe: the gap is where a second record would
        // hide, unnoticed by anything that trusted the length field.
        encoded[..4].copy_from_slice(&(honest + 1).to_le_bytes());
        assert!(matches!(
            Frame::decode(&encoded),
            Err(FrameError::Malformed(VaultError::VaultFileMalformed {
                field: VaultField::FrameLength
            }))
        ));

        // Shorter: the tail of the body would be read as the start of the next
        // frame.
        encoded[..4].copy_from_slice(&(honest - 1).to_le_bytes());
        assert!(matches!(
            Frame::decode(&encoded),
            Err(FrameError::Malformed(VaultError::VaultFileMalformed {
                field: VaultField::FrameLength
            }))
        ));
    }

    /// The length word is judged against the fields beside it, not against where
    /// the file happens to end.
    ///
    /// A frame whose length disagrees with its own two length fields is corrupt
    /// even when there are plenty of bytes after it, and it stays corrupt when
    /// there are not: `Truncated` would send the caller to the chain, which
    /// answers "somebody wrote to this vault" for a fault nobody wrote.
    #[test]
    fn a_length_that_disagrees_with_its_fields_is_corrupt_and_not_merely_short() {
        let mut encoded = frame().encode().unwrap();
        let honest = encoded.len() as u32;
        // Longer than the fields describe *and* longer than the buffer, so the
        // only thing that can tell the two verdicts apart is which check runs
        // first.
        encoded[..4].copy_from_slice(&(honest + 4096).to_le_bytes());
        assert!(matches!(
            Frame::decode(&encoded),
            Err(FrameError::Malformed(VaultError::VaultFileMalformed {
                field: VaultField::FrameLength
            }))
        ));
    }

    #[test]
    fn a_frame_with_a_reserved_field_set_or_an_unknown_version_is_refused() {
        let encoded = frame().encode().unwrap();

        for at in [6usize, 7, 90, 91] {
            let mut tampered = encoded.clone();
            tampered[at] = 1;
            assert!(
                matches!(
                    Frame::decode(&tampered),
                    Err(FrameError::Malformed(VaultError::VaultFileMalformed {
                        field: VaultField::FrameReserved
                    }))
                ),
                "reserved byte {at} was accepted"
            );
        }

        let mut tampered = encoded.clone();
        tampered[4] = 2;
        assert!(matches!(
            Frame::decode(&tampered),
            Err(FrameError::Malformed(VaultError::VaultFileUnsupported {
                field: VaultField::FrameVersion,
                ..
            }))
        ));

        let mut tampered = encoded;
        tampered[5] = 7;
        assert!(matches!(
            Frame::decode(&tampered),
            Err(FrameError::Malformed(VaultError::VaultFileUnsupported {
                field: VaultField::RecordType,
                ..
            }))
        ));
    }

    /// A forged length field must not be able to ask this process for memory
    /// before a single MAC has been checked.
    #[test]
    fn a_forged_length_field_is_refused_before_anything_is_allocated() {
        let mut encoded = frame().encode().unwrap();
        encoded[92..96].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            Frame::decode(&encoded),
            Err(FrameError::Malformed(VaultError::VaultFileMalformed {
                field: VaultField::BodyLength
            }))
        ));

        encoded[92..96].copy_from_slice(&12u32.to_le_bytes());
        encoded[88..90].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(matches!(
            Frame::decode(&encoded),
            Err(FrameError::Malformed(VaultError::VaultFileMalformed {
                field: VaultField::AliasLength
            }))
        ));
    }

    /// Bytes cut off the end are a record that is not there, which is the chain's
    /// business and not the format's.
    #[test]
    fn a_frame_that_runs_past_the_end_of_the_file_is_refused_as_a_short_frame() {
        let encoded = frame().encode().unwrap();
        for cut in [
            0usize,
            FRAME_HEAD_BYTES - 1,
            FRAME_HEAD_BYTES,
            encoded.len() - 1,
        ] {
            assert!(
                matches!(Frame::decode(&encoded[..cut]), Err(FrameError::Truncated)),
                "a frame truncated to {cut} bytes was not reported as short"
            );
        }
    }

    #[test]
    fn an_alias_that_is_not_text_is_refused() {
        let mut encoded = frame().encode().unwrap();
        encoded[FRAME_HEAD_BYTES] = 0xFF;
        assert!(matches!(
            Frame::decode(&encoded),
            Err(FrameError::Malformed(VaultError::VaultFileMalformed {
                field: VaultField::Alias
            }))
        ));
    }

    #[test]
    fn the_sealed_body_is_the_only_place_a_value_can_be() {
        // Stated as a test because the frame carries four fields in the clear and
        // a fifth would be easy to add without noticing what it exposes.
        let encoded = frame().encode().unwrap();
        let head = &encoded[..FRAME_HEAD_BYTES];
        assert!(!head.windows(5).any(|window| window == b"seale"));
    }
}
