//! Sealing one vault record, and binding it to the identity it belongs to.
//!
//! # The cipher
//!
//! XChaCha20-Poly1305, with a 24 byte nonce drawn from the operating system for
//! every record and no state kept anywhere (ADR-007, D-14 revision). The rejected
//! design was AES-256-GCM with a counter nonce, and the reason it was rejected is
//! worth keeping next to the code: a counter is a promise that state is never
//! lost, and a vault file is restored from backups, copied between machines and
//! recovered after crashes. When the counter rolls back, GCM does not merely leak
//! a plaintext, it exposes the authentication key. A 192 bit random nonce removes
//! the promise instead of defending it: at 2^40 records the collision probability
//! is around 2^-113, and this vault holds 10,000 aliases per session.
//!
//! # The AAD, and why swapping two records has to fail
//!
//! ```text
//! AAD = "periskop/vault/v1" | schema_version | record_type | session_id | alias_seed
//! ```
//!
//! The original AAD carried the record type and schema version alone, so a record
//! was bound to its *type* and nothing else. Anyone who could write to the vault
//! could exchange the sealed bodies of two records of the same type, and both
//! would still authenticate: `PERSON_1` would decrypt to a different real
//! person's name, and the restore path would inject it into the user's response
//! without a single error anywhere. That is D-10 finding 37, and it is a silent
//! wrong answer rather than a failure, which is the worst class of defect this
//! product recognises.
//!
//! Adding `session_id` and `alias_seed` binds a record to the one slot it belongs
//! in. A swapped record is opened under an AAD it was not sealed under, Poly1305
//! refuses, and the caller gets a 503 instead of a stranger's data. The check
//! lives in the AEAD rather than in an `if` after decryption on purpose
//! (ADR-007's last rejected alternative): a forgotten branch would restore the
//! silent substitution, whereas a forgotten AAD field cannot decrypt at all.

use std::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use super::error::VaultError;
use super::secret::{random_bytes, RecordKey, SecretValue};
use super::session::{SessionId, SESSION_ID_BYTES};

/// Bytes of nonce, per record. XChaCha20's 192 bits are what make a random nonce
/// safe without a counter.
pub const NONCE_BYTES: usize = 24;

/// Bytes of an alias seed: the HMAC-SHA256 digest alias generation produces
/// (`proxy/spec.md` section 4.1), and the record's identity inside a session.
pub const ALIAS_SEED_BYTES: usize = 32;

/// The namespace every vault AAD opens with.
const NAMESPACE: &[u8] = b"periskop/vault/v1";
/// Its length, needed as a constant for the fixed layout below.
const NAMESPACE_BYTES: usize = 17;

/// The record layout version, as major and minor. Rendered "1.0" in prose, the
/// same discipline every other contract in this repository uses.
pub const RECORD_SCHEMA_VERSION: [u8; 2] = [1, 0];

/// Total AAD length. Every field is fixed width, so no separator is needed and no
/// two different identities can encode to the same bytes.
const AAD_BYTES: usize =
    NAMESPACE_BYTES + RECORD_SCHEMA_VERSION.len() + 1 + SESSION_ID_BYTES + ALIAS_SEED_BYTES;

/// What kind of record this is.
///
/// One kind today. The dictionary the proxy imports at startup
/// (`proxy-dictionary.schema.json`) becomes the second, in the wave that writes
/// detection layer B; it is not declared here, because a variant nothing produces
/// is a variant nothing tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordType {
    /// The original value an alias stands for.
    Alias,
}

impl RecordType {
    /// The byte that goes into the AAD, and into a vault file's frame header.
    /// Explicit rather than a cast of the discriminant, because reordering the
    /// variants would then silently change what every stored record
    /// authenticates against.
    pub(super) fn tag(self) -> u8 {
        match self {
            Self::Alias => 1,
        }
    }

    /// Reads the byte back, refusing one this build does not know.
    ///
    /// `None` rather than a default: a frame carrying an unknown record type came
    /// from a newer layout or from somebody guessing, and treating it as an alias
    /// record would open it under the wrong AAD.
    pub(super) fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Alias),
            _ => None,
        }
    }
}

/// A record's identity inside a session: which alias, in which session, of which
/// kind.
///
/// Produced by the alias layer in a later wave. The vault treats it as opaque;
/// what it needs is that it is unique per record, which is what
/// `HMAC-SHA256(K_session, type || value)` gives it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AliasSeed([u8; ALIAS_SEED_BYTES]);

/// Written by hand, because a seed is a keyed digest **of the masked value**.
///
/// The bytes are not the personal data, but they are a stable identifier derived
/// from it: the same original in the same session always produces the same seed,
/// so a log line carrying one lets a reader link every occurrence of a value they
/// were never shown. `proxy/spec.md` section 9 lists what `TRACE` may carry and
/// this is not on the list.
impl fmt::Debug for AliasSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AliasSeed(<redacted>)")
    }
}

impl AliasSeed {
    pub fn from_bytes(bytes: [u8; ALIAS_SEED_BYTES]) -> Self {
        Self(bytes)
    }

    pub(super) fn as_bytes(&self) -> &[u8; ALIAS_SEED_BYTES] {
        &self.0
    }
}

/// Everything a record is bound to. Borrowed rather than owned so that building
/// one costs nothing on the request path.
#[derive(Clone, Copy)]
pub struct RecordIdentity<'a> {
    pub record_type: RecordType,
    pub session: &'a SessionId,
    pub alias_seed: &'a AliasSeed,
}

/// The kind, which is a closed vocabulary, and nothing that identifies anybody.
///
/// The derived form printed the session and the seed through their own renderings,
/// so it is only as safe as those two stay; written out here it is safe on its own.
impl fmt::Debug for RecordIdentity<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordIdentity")
            .field("record_type", &self.record_type)
            .field("session", &"<redacted>")
            .field("alias_seed", &"<redacted>")
            .finish()
    }
}

impl RecordIdentity<'_> {
    /// The additional authenticated data, laid out field by field.
    fn aad(&self) -> [u8; AAD_BYTES] {
        const VERSION_AT: usize = NAMESPACE_BYTES;
        const TYPE_AT: usize = VERSION_AT + 2;
        const SESSION_AT: usize = TYPE_AT + 1;
        const SEED_AT: usize = SESSION_AT + SESSION_ID_BYTES;

        let mut aad = [0u8; AAD_BYTES];
        aad[..NAMESPACE_BYTES].copy_from_slice(NAMESPACE);
        aad[VERSION_AT..TYPE_AT].copy_from_slice(&RECORD_SCHEMA_VERSION);
        aad[TYPE_AT] = self.record_type.tag();
        aad[SESSION_AT..SEED_AT].copy_from_slice(self.session.as_bytes());
        aad[SEED_AT..].copy_from_slice(self.alias_seed.as_bytes());
        aad
    }
}

/// One sealed record: its nonce and its ciphertext with the Poly1305 tag.
///
/// There is no counter, no sequence number and no timestamp in here. Anything of
/// that shape would be state, and state is what rolls back.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedRecord {
    nonce: [u8; NONCE_BYTES],
    body: Vec<u8>,
}

/// Lengths, not bytes.
///
/// The body is ciphertext, so printing it does not hand over a value; it hands
/// over the exact bytes an attacker needs to replay a record into another file,
/// and it does so through the one call every logger reaches for. The nonce is
/// worse: it is the input that must never repeat, and a log of nonces is a map of
/// which records were written when.
impl fmt::Debug for SealedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedRecord")
            .field("nonce", &"<redacted>")
            .field("body", &"<redacted>")
            .finish()
    }
}

impl SealedRecord {
    pub fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }

    /// The ciphertext with its Poly1305 tag, for the file backend that writes it
    /// down and reads it back.
    ///
    /// Crate private, and it hands out sealed bytes rather than a value: there is
    /// no accessor anywhere that produces a plaintext without going through
    /// [`unseal`].
    pub(super) fn body(&self) -> &[u8] {
        &self.body
    }

    /// Rebuilds a record from what a vault file stored.
    ///
    /// This constructor makes no claim about the bytes. They are opened under the
    /// identity the caller believes they belong to, and if that belief is wrong
    /// the AEAD refuses; nothing here can turn tampered bytes into a value.
    pub(super) fn from_parts(nonce: [u8; NONCE_BYTES], body: Vec<u8>) -> Self {
        Self { nonce, body }
    }
}

/// Seals a value under the identity it belongs to.
///
/// The nonce is drawn here, per call, and never reused or derived from anything.
pub(super) fn seal(
    key: &RecordKey,
    identity: &RecordIdentity<'_>,
    plaintext: &[u8],
) -> Result<SealedRecord, VaultError> {
    let nonce: [u8; NONCE_BYTES] = random_bytes()?;
    let body = cipher(key)?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &identity.aad(),
            },
        )
        // The AEAD's encrypt fails only when the buffer cannot be produced. A
        // vault that cannot seal must not carry on with the value in the clear.
        .map_err(|_| seal_refusal(STAGE_SEALING))?;

    Ok(SealedRecord { nonce, body })
}

/// Opens a record, under one identity and no other.
///
/// A failure here is not a decoding problem to be retried or worked around. It
/// means the bytes on hand were not sealed for this slot, and the only safe
/// answer is to hand back nothing (`proxy/spec.md` section 10: the value from a
/// swapped record reaches the user under no circumstances).
pub(super) fn unseal(
    key: &RecordKey,
    identity: &RecordIdentity<'_>,
    sealed: &SealedRecord,
) -> Result<SecretValue, VaultError> {
    let plaintext = cipher(key)?
        .decrypt(
            XNonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.body,
                aad: &identity.aad(),
            },
        )
        .map_err(|_| VaultError::RecordTamper)?;

    Ok(SecretValue::new(plaintext))
}

fn cipher(key: &RecordKey) -> Result<XChaCha20Poly1305, VaultError> {
    // The key is a fixed 32 bytes by construction, so the length check cannot
    // fail; it is mapped rather than unwrapped because a panic inside the vault
    // is an outage with no diagnosis.
    XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| seal_refusal(STAGE_BUILDING))
}

/// The two moments the record cipher can refuse, named so that the refusal says
/// which one it was.
const STAGE_BUILDING: &str = "building the record cipher";
const STAGE_SEALING: &str = "sealing a record body";

/// The class an AEAD refusal on the sealing side belongs to.
///
/// Both call sites run with the key already derived and in hand, so neither can be
/// a key derivation failure: XChaCha20-Poly1305 refuses to be constructed only on
/// a wrong key length, which [`RecordKey`] makes impossible, and refuses a seal
/// only when it cannot produce the output buffer. Telling an operator that the key
/// could not be derived sends them to the passphrase, which is the one part of the
/// system already known to have worked, and a refusal that names the wrong remedy
/// costs more time to resolve than one that names none.
fn seal_refusal(stage: &'static str) -> VaultError {
    VaultError::SealFailed { stage }
}

/// What the vault has to report about record authentication.
///
/// `record_tamper` feeds `ProxyEvent.vault_record_tamper`
/// (`schemas/proxy-event.schema.json`), where every non zero value is a security
/// event that ended in a 503. It is a count rather than a flag because the number
/// of attempts is what tells an operator whether they saw an accident or a
/// campaign.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordCounters {
    record_tamper: u64,
}

impl RecordCounters {
    pub fn record_tamper(&self) -> u64 {
        self.record_tamper
    }

    pub(super) fn count_tamper(&mut self) {
        self.record_tamper = self.record_tamper.saturating_add(1);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::vault::session::SessionLimits;
    use crate::vault::{MasterKey, Vault};

    const SESSION: SessionId = SessionId::from_bytes([0x0A; SESSION_ID_BYTES]);
    const OTHER_SESSION: SessionId = SessionId::from_bytes([0x0B; SESSION_ID_BYTES]);
    const AHMET: &[u8] = b"Ahmet Yilmaz";
    const AYSE: &[u8] = b"Ayse Demir";
    const NOW: u64 = 1_700_000_000_000;

    fn seed(byte: u8) -> AliasSeed {
        AliasSeed::from_bytes([byte; ALIAS_SEED_BYTES])
    }

    fn identity<'a>(session: &'a SessionId, seed: &'a AliasSeed) -> RecordIdentity<'a> {
        RecordIdentity {
            record_type: RecordType::Alias,
            session,
            alias_seed: seed,
        }
    }

    /// The three identifiers in this module print nothing a reader could join on.
    ///
    /// A derived `Debug` here is not an abstract risk: a seed is a keyed digest of
    /// the masked value, so the same original always produces the same bytes, and a
    /// log line carrying them lets somebody link every occurrence of a value they
    /// were never shown. The sealed body and its nonce are the bytes an attacker
    /// needs to replay a record into another file.
    #[test]
    fn no_identifier_in_this_module_prints_its_bytes() {
        let seed = seed(0xAB);
        let sealed = SealedRecord::from_parts([0xCD; NONCE_BYTES], vec![0xEF; 16]);
        let identity = identity(&SESSION, &seed);

        let rendered = format!("{seed:?} {sealed:?} {identity:?} {SESSION:?}");
        for byte in ["171", "ab", "AB", "205", "cd", "239", "ef", "10, 10"] {
            assert!(!rendered.contains(byte), "{rendered} carries {byte}");
        }
        assert_eq!(rendered.matches("<redacted>").count(), 6, "{rendered}");
        // The kind is a closed vocabulary and stays readable, or the rendering
        // would be useless rather than careful.
        assert!(rendered.contains("Alias"), "{rendered}");
    }

    fn key() -> RecordKey {
        RecordKey::from_bytes([0x5A; 32])
    }

    fn vault() -> Vault {
        Vault::from_master_key(MasterKey::from_bytes([0x33; 32]), SessionLimits::default()).unwrap()
    }

    #[test]
    fn a_record_opens_under_the_identity_it_was_sealed_under() {
        let key = key();
        let seed = seed(1);
        let identity = identity(&SESSION, &seed);

        let sealed = seal(&key, &identity, AHMET).unwrap();
        assert_eq!(unseal(&key, &identity, &sealed).unwrap().expose(), AHMET);
    }

    /// The swap test. D-10 finding 37's regression lock, at the record layer.
    ///
    /// Two records of the *same type* in the *same session*: exactly the pair the
    /// original AAD could not tell apart. Their sealed bodies are exchanged, and
    /// both openings have to fail. If either one succeeded, a user would be handed
    /// a stranger's name in place of their own.
    #[test]
    fn two_records_of_the_same_type_cannot_have_their_sealed_bodies_swapped() {
        let key = key();
        let first_seed = seed(1);
        let second_seed = seed(2);
        let first = identity(&SESSION, &first_seed);
        let second = identity(&SESSION, &second_seed);

        let sealed_first = seal(&key, &first, AHMET).unwrap();
        let sealed_second = seal(&key, &second, AYSE).unwrap();

        assert_eq!(
            unseal(&key, &first, &sealed_second).unwrap_err(),
            VaultError::RecordTamper
        );
        assert_eq!(
            unseal(&key, &second, &sealed_first).unwrap_err(),
            VaultError::RecordTamper
        );
    }

    #[test]
    fn a_record_cannot_be_moved_to_another_session() {
        let key = key();
        let seed = seed(1);
        let sealed = seal(&key, &identity(&SESSION, &seed), AHMET).unwrap();

        assert_eq!(
            unseal(&key, &identity(&OTHER_SESSION, &seed), &sealed).unwrap_err(),
            VaultError::RecordTamper
        );
    }

    #[test]
    fn a_record_does_not_open_under_a_different_vault_key() {
        let seed = seed(1);
        let identity = identity(&SESSION, &seed);
        let sealed = seal(&key(), &identity, AHMET).unwrap();

        let other = RecordKey::from_bytes([0x5B; 32]);
        assert_eq!(
            unseal(&other, &identity, &sealed).unwrap_err(),
            VaultError::RecordTamper
        );
    }

    #[test]
    fn a_flipped_ciphertext_byte_is_refused() {
        let key = key();
        let seed = seed(1);
        let identity = identity(&SESSION, &seed);

        let mut sealed = seal(&key, &identity, AHMET).unwrap();
        sealed.body[0] ^= 0x01;
        assert_eq!(
            unseal(&key, &identity, &sealed).unwrap_err(),
            VaultError::RecordTamper
        );
    }

    /// The swap test again, end to end through the vault, for the two claims the
    /// record layer cannot make on its own: the counter moves and the caller is
    /// told 503.
    #[test]
    fn a_swapped_record_increments_vault_record_tamper_and_answers_503() {
        let mut vault = vault();
        let first = seed(1);
        let second = seed(2);

        vault
            .store_alias(&SESSION, first, "PSK_PERSON_1", AHMET, NOW)
            .unwrap();
        vault
            .store_alias(&SESSION, second, "PSK_PERSON_2", AYSE, NOW)
            .unwrap();
        assert_eq!(vault.counters().record_tamper(), 0);

        // An attacker with write access to the vault exchanges the two bodies.
        // Nothing in the shipped code can do this, which is the point: the test
        // has to reach past the public surface to produce the state the AAD
        // binding exists to survive.
        assert!(vault.swap_sealed_bodies_for_test(&SESSION, &first, &second));

        let refusal = vault.restore(&SESSION, "PSK_PERSON_1", NOW).unwrap_err();
        assert_eq!(refusal, VaultError::RecordTamper);
        assert_eq!(refusal.http_status(), 503);
        assert_eq!(vault.counters().record_tamper(), 1);

        // The other half of the swap is just as refused, and counted.
        assert_eq!(
            vault.restore(&SESSION, "PSK_PERSON_2", NOW).unwrap_err(),
            VaultError::RecordTamper
        );
        assert_eq!(vault.counters().record_tamper(), 2);
    }

    #[test]
    fn the_aad_is_the_fixed_layout_the_adr_names() {
        assert_eq!(NAMESPACE.len(), NAMESPACE_BYTES);
        assert_eq!(AAD_BYTES, 17 + 2 + 1 + 16 + 32);

        let seed = seed(0xEE);
        let aad = identity(&SESSION, &seed).aad();

        // Frozen field by field. A reordering or a width change here silently
        // invalidates every record a previous version sealed, so it has to be a
        // decision rather than an edit.
        assert_eq!(&aad[..17], b"periskop/vault/v1");
        assert_eq!(&aad[17..19], &[1, 0]);
        assert_eq!(aad[19], 1);
        assert_eq!(&aad[20..36], &[0x0A; 16]);
        assert_eq!(&aad[36..68], &[0xEE; 32]);
    }

    #[test]
    fn every_nonce_is_drawn_fresh() {
        let key = key();
        let seed = seed(1);
        let identity = identity(&SESSION, &seed);

        let nonces: BTreeSet<[u8; NONCE_BYTES]> = (0..1_000)
            .map(|_| *seal(&key, &identity, AHMET).unwrap().nonce())
            .collect();
        assert_eq!(nonces.len(), 1_000);
    }

    /// The property a counter based nonce cannot have.
    ///
    /// Two vaults opened from the same master key seal their first record under
    /// different nonces. With a counter, both would start at zero and both would
    /// use the same nonce with the same key: the restored backup scenario ADR-007
    /// D-14 was written for. Distinct ciphertexts for the same plaintext are the
    /// same statement from the other side.
    #[test]
    fn two_vaults_from_one_key_do_not_repeat_a_nonce() {
        let key = key();
        let seed = seed(1);
        let identity = identity(&SESSION, &seed);

        let first = seal(&key, &identity, AHMET).unwrap();
        let second = seal(&key, &identity, AHMET).unwrap();

        assert_ne!(first.nonce(), second.nonce());
        assert_ne!(first.body, second.body);
    }

    #[test]
    fn a_sealed_record_carries_nothing_but_its_nonce_and_body() {
        // Stated as a test so that adding a counter, a sequence number or a
        // timestamp to the record has to break something. Each of those is state,
        // and state is what rolls back when a file is restored.
        let sealed = seal(&key(), &identity(&SESSION, &seed(1)), AHMET).unwrap();
        assert_eq!(sealed.nonce().len(), NONCE_BYTES);
        // Ciphertext plus the 16 byte Poly1305 tag, and nothing else.
        assert_eq!(sealed.body.len(), AHMET.len() + 16);
    }

    #[test]
    fn the_ciphertext_does_not_contain_the_plaintext() {
        let sealed = seal(&key(), &identity(&SESSION, &seed(1)), AHMET).unwrap();
        assert!(!sealed
            .body
            .windows(AHMET.len())
            .any(|window| window == AHMET));
    }

    /// A cipher failure is not a passphrase failure, and the message decides which
    /// one an operator goes looking for.
    ///
    /// Neither call site can be driven to fail from here: the key is 32 bytes by
    /// construction and the AEAD refuses a seal only when it cannot produce the
    /// output buffer. What is testable is the class the two sites assign, which is
    /// the whole of what reaches the operator, so that is asserted directly.
    #[test]
    fn a_cipher_refusal_is_not_reported_as_a_key_derivation_failure() {
        for stage in [STAGE_BUILDING, STAGE_SEALING] {
            let refusal = seal_refusal(stage);
            assert_ne!(
                refusal,
                VaultError::KeyDerivationFailed,
                "a seal that failed with the key in hand blamed the key derivation"
            );
            // Still a vault outage, so still 503: the class changed, the answer
            // did not (`proxy/spec.md` section 10, "Kasa kullanılamaz").
            assert_eq!(refusal.http_status(), 503);
            // Not one of the three integrity violations either; nothing was
            // tampered with.
            assert_eq!(refusal.integrity(), None);

            let rendered = refusal.to_string();
            assert!(rendered.contains(stage), "{rendered}");
            assert!(!rendered.contains("passphrase"), "{rendered}");
            assert!(!rendered.contains("could not be derived"), "{rendered}");
        }
    }
}
