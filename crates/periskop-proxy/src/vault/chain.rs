//! The integrity chain over a vault file: what the AEAD cannot say.
//!
//! [`super::record`] authenticates one record against the slot it belongs in.
//! That is a statement about a record and says nothing about the *set* of them.
//! An attacker with write access to `vault.psk` can delete a record, truncate the
//! file after any record, reorder two of them, or put yesterday's whole file back,
//! and every surviving record still authenticates perfectly. ADR-007 section
//! "3. Dosya bütünlüğü" answers that with a chain:
//!
//! ```text
//! M_0 = MAC(K_chain, header_prefix)
//! M_i = MAC(K_chain, M_{i-1} || frame_i)
//! ```
//!
//! `M_n` and the record counter are stored in the header, and the header itself
//! is authenticated under the same key (ADR-007 section 4). Removing, changing or
//! reordering any link changes `M_n`, and `M_n` cannot be recomputed without
//! `K_chain`, which is expanded from the passphrase.
//!
//! # Why three domain separators and not one key used three ways
//!
//! The same key computes three different kinds of statement here: the seed over
//! the header prefix, a link over a frame, and the header tag over the mutable
//! header fields. Without a domain separator, a byte string that is a valid input
//! to one of them is a valid input to the others, and an attacker who can choose
//! part of an input gets to move a tag from one role to another. The separators
//! cost nothing and remove the whole question. ADR-007 fixes the *key's* HKDF
//! label and says nothing about these three; they follow the label pattern the
//! previous wave used (`periskop/vault/record/v1`) and are filed as a contract
//! request in `hub/memory/interfaces.md`.
//!
//! # Comparisons are constant time
//!
//! Every check goes through `Mac::verify_slice`, which compares in constant time.
//! The tags are not secret, but the attacker supplies the value being compared
//! against, and a byte-at-a-time comparison would let them find a matching tag by
//! measuring how long the refusal takes.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::error::VaultError;
use super::secret::ChainKey;

/// Bytes of a chain tag: HMAC-SHA256's output.
pub(super) const TAG_BYTES: usize = 32;

/// The zeroth link, over the part of the header that never changes.
const SEED_DOMAIN: &[u8] = b"periskop/vault/chain/seed/v1";
/// Every link after it, over the previous tag and one frame.
const LINK_DOMAIN: &[u8] = b"periskop/vault/chain/link/v1";
/// The header tag, over the header fields an append rewrites.
const HEADER_DOMAIN: &[u8] = b"periskop/vault/chain/header/v1";

/// One link of the chain.
///
/// No `PartialEq`: comparing two of these with `==` would be the variable time
/// comparison this module exists to avoid. [`ChainMac::verify`] is the only way to
/// ask whether a tag matches.
#[derive(Clone, Copy)]
pub(super) struct ChainTag([u8; TAG_BYTES]);

/// Says nothing, like every other type in this vault.
///
/// A chain tag is not personal data, but a uniform rule is one a reviewer can
/// check: no vault type renders its bytes, so no `{:?}` anywhere can be the place
/// something leaks.
impl std::fmt::Debug for ChainTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChainTag(<opaque>)")
    }
}

impl ChainTag {
    pub(super) fn from_bytes(bytes: [u8; TAG_BYTES]) -> Self {
        Self(bytes)
    }

    pub(super) fn as_bytes(&self) -> &[u8; TAG_BYTES] {
        &self.0
    }
}

/// The chain, and the key it is computed under.
pub(super) struct ChainMac {
    key: ChainKey,
}

impl std::fmt::Debug for ChainMac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChainMac(<redacted>)")
    }
}

impl ChainMac {
    pub(super) fn new(key: ChainKey) -> Self {
        Self { key }
    }

    /// `M_0 = MAC(K_chain, header_prefix)`.
    ///
    /// The prefix is the part of the header that an append never rewrites: the
    /// magic, the layout version, the algorithm tags, the Argon2id parameters and
    /// the salt. Anchoring the chain here is what makes weakening a parameter
    /// visible: the derived key changes, so `M_0` changes, so every link after it
    /// changes.
    pub(super) fn seed(&self, header_prefix: &[u8]) -> Result<ChainTag, VaultError> {
        self.tag(SEED_DOMAIN, &[header_prefix])
    }

    /// `M_i = MAC(K_chain, M_{i-1} || frame_i)`.
    ///
    /// The whole frame goes in, its own length field included, so the boundary
    /// between two frames is authenticated too and a byte cannot be moved from one
    /// frame into the next.
    pub(super) fn link(&self, previous: &ChainTag, frame: &[u8]) -> Result<ChainTag, VaultError> {
        self.tag(LINK_DOMAIN, &[previous.as_bytes(), frame])
    }

    /// The header tag over the fields an append rewrites.
    ///
    /// ADR-007 calls the header the zeroth link of the chain and stores `M_n` and
    /// the record counter in it. That is circular if taken literally: `M_0` would
    /// have to cover a field derived from `M_0`. It is resolved by splitting the
    /// header in two. The fixed prefix is what `M_0` covers; the counter, the
    /// frame count and `M_n` are covered by this tag instead. Both are computed
    /// under `K_chain`, so both fail when a parameter in the prefix is weakened.
    pub(super) fn header(
        &self,
        header_prefix: &[u8],
        record_counter: u64,
        frame_count: u64,
        tail: &ChainTag,
    ) -> Result<ChainTag, VaultError> {
        self.tag(
            HEADER_DOMAIN,
            &[
                header_prefix,
                &record_counter.to_le_bytes(),
                &frame_count.to_le_bytes(),
                tail.as_bytes(),
            ],
        )
    }

    /// Whether a tag matches what the file claims, compared in constant time.
    ///
    /// Double HMAC verification: both sides are blinded under the chain key and
    /// the blinded values are compared with `verify_slice`. A plain comparison of
    /// the raw tags would stop at the first differing byte, and the claimed value
    /// comes from a file an attacker wrote, so the time it took to refuse would
    /// tell them how many leading bytes they had guessed right. Blinding also
    /// removes the length signal: a claim of the wrong length produces a digest
    /// of the same width rather than an early exit.
    pub(super) fn verify(&self, computed: &ChainTag, claimed: &[u8]) -> bool {
        let Some(blinded_claim) = self.blind(claimed) else {
            return false;
        };
        match Hmac::<Sha256>::new_from_slice(self.key.as_bytes()) {
            Ok(mut mac) => {
                mac.update(computed.as_bytes());
                mac.verify_slice(&blinded_claim).is_ok()
            }
            // A 32 byte key is always an acceptable HMAC key, so this arm is
            // unreachable. It answers "no match" rather than panicking, because a
            // panic inside the vault is an outage with no diagnosis.
            Err(_) => false,
        }
    }

    /// One side of the comparison above.
    fn blind(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.as_bytes()).ok()?;
        mac.update(bytes);
        Some(mac.finalize().into_bytes().to_vec())
    }

    fn tag(&self, domain: &[u8], parts: &[&[u8]]) -> Result<ChainTag, VaultError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.as_bytes())
            // HMAC accepts a key of any length and this one is a constant 32
            // bytes, so this cannot fire. Mapped rather than unwrapped for the
            // same reason as everywhere else in this module.
            .map_err(|_| VaultError::KeyDerivationFailed)?;
        mac.update(domain);
        for part in parts {
            mac.update(part);
        }

        let bytes = mac.finalize().into_bytes();
        let mut tag = [0u8; TAG_BYTES];
        // HMAC-SHA256 produces exactly 32 bytes, so the widths agree by
        // construction; `copy_from_slice` would panic if that ever stopped being
        // true, so the length is checked instead.
        if bytes.len() != TAG_BYTES {
            return Err(VaultError::KeyDerivationFailed);
        }
        tag.copy_from_slice(&bytes);
        Ok(ChainTag(tag))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::vault::secret::Key;

    fn chain(byte: u8) -> ChainMac {
        ChainMac::new(Key::from_bytes([byte; 32]))
    }

    const PREFIX: &[u8] = b"a header prefix";

    #[test]
    fn the_same_inputs_produce_the_same_tag() {
        let mac = chain(0x11);
        assert_eq!(
            mac.seed(PREFIX).unwrap().as_bytes(),
            mac.seed(PREFIX).unwrap().as_bytes()
        );
    }

    #[test]
    fn the_three_roles_do_not_share_a_tag() {
        // Without the domain separators, a value that is a valid seed input is
        // also a valid link input, and a tag computed for one role could be
        // presented for another.
        let mac = chain(0x22);
        let seed = mac.seed(PREFIX).unwrap();
        let link = mac
            .link(&ChainTag::from_bytes([0u8; TAG_BYTES]), PREFIX)
            .unwrap();
        let header = mac
            .header(PREFIX, 0, 0, &ChainTag::from_bytes([0u8; TAG_BYTES]))
            .unwrap();

        assert_ne!(seed.as_bytes(), link.as_bytes());
        assert_ne!(seed.as_bytes(), header.as_bytes());
        assert_ne!(link.as_bytes(), header.as_bytes());
    }

    #[test]
    fn a_different_key_produces_a_different_tag() {
        assert_ne!(
            chain(0x33).seed(PREFIX).unwrap().as_bytes(),
            chain(0x34).seed(PREFIX).unwrap().as_bytes()
        );
    }

    /// The property the whole file format rests on: changing anything about the
    /// record set moves the tail.
    #[test]
    fn dropping_reordering_or_editing_a_link_moves_the_tail() {
        let mac = chain(0x44);
        let seed = mac.seed(PREFIX).unwrap();

        let walk = |frames: &[&[u8]]| {
            let mut tag = seed;
            for frame in frames {
                tag = mac.link(&tag, frame).unwrap();
            }
            *tag.as_bytes()
        };

        let whole = walk(&[b"one", b"two", b"three"]);
        assert_ne!(whole, walk(&[b"one", b"three"]), "a dropped record");
        assert_ne!(whole, walk(&[b"one", b"two"]), "a truncated file");
        assert_ne!(whole, walk(&[b"two", b"one", b"three"]), "a reordering");
        assert_ne!(whole, walk(&[b"one", b"tw0", b"three"]), "an edited record");
        assert_ne!(
            whole,
            walk(&[b"one", b"two", b"three", b"four"]),
            "an append"
        );
    }

    #[test]
    fn the_header_tag_covers_the_counter_the_frame_count_and_the_tail() {
        let mac = chain(0x55);
        let tail = mac.seed(PREFIX).unwrap();
        let base = mac.header(PREFIX, 7, 7, &tail).unwrap();

        assert_ne!(
            base.as_bytes(),
            mac.header(PREFIX, 6, 7, &tail).unwrap().as_bytes()
        );
        assert_ne!(
            base.as_bytes(),
            mac.header(PREFIX, 7, 6, &tail).unwrap().as_bytes()
        );
        assert_ne!(
            base.as_bytes(),
            mac.header(PREFIX, 7, 7, &ChainTag::from_bytes([9u8; TAG_BYTES]))
                .unwrap()
                .as_bytes()
        );
        assert_ne!(
            base.as_bytes(),
            mac.header(b"another prefix", 7, 7, &tail)
                .unwrap()
                .as_bytes()
        );
    }

    /// A frame's length field goes into the link, so bytes cannot be moved across
    /// a frame boundary without changing the chain.
    #[test]
    fn moving_a_byte_across_a_frame_boundary_moves_the_tail() {
        let mac = chain(0x66);
        let seed = mac.seed(PREFIX).unwrap();

        let split_here = mac.link(&mac.link(&seed, b"abcd").unwrap(), b"ef").unwrap();
        let split_there = mac.link(&mac.link(&seed, b"abc").unwrap(), b"def").unwrap();
        assert_ne!(split_here.as_bytes(), split_there.as_bytes());
    }

    #[test]
    fn verification_accepts_the_matching_tag_and_refuses_everything_else() {
        let mac = chain(0x77);
        let tag = mac.seed(PREFIX).unwrap();

        assert!(mac.verify(&tag, tag.as_bytes()));

        let mut flipped = *tag.as_bytes();
        flipped[0] ^= 0x01;
        assert!(!mac.verify(&tag, &flipped));

        let mut last = *tag.as_bytes();
        last[TAG_BYTES - 1] ^= 0x80;
        assert!(!mac.verify(&tag, &last), "a difference in the final byte");

        assert!(!mac.verify(&tag, &[]), "an empty claim");
        assert!(
            !mac.verify(&tag, &tag.as_bytes()[..16]),
            "a truncated claim"
        );

        let mut longer = tag.as_bytes().to_vec();
        longer.push(0);
        assert!(!mac.verify(&tag, &longer), "a padded claim");
    }

    #[test]
    fn a_tag_does_not_render_its_bytes() {
        let tag = chain(0x88).seed(PREFIX).unwrap();
        let rendered = format!("{tag:?} {:?}", chain(0x88));
        assert!(rendered.contains("<opaque>"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        for byte in tag.as_bytes() {
            assert!(!rendered.contains(&format!("{byte}")), "{rendered}");
        }
    }
}
