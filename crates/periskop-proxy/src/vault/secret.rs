//! Key material, plaintext values, and the single door to the entropy source.
//!
//! Three rules shape this module, and each one is a type rather than a habit.
//!
//! **Nothing secret prints.** Every type here writes its own `Debug` by hand and
//! prints a placeholder. There is no `Display`, no `Serialize` and no public
//! accessor for key bytes. `proxy/spec.md` section 9 makes this a reviewable
//! invariant: vault content may not appear at any log level, and a derived
//! `Debug` puts it in the first `{:?}` somebody reaches for.
//!
//! **Nothing secret outlives its use.** Every buffer clears itself on drop
//! (`zeroize`), which is half of the memory discipline the spec asks for. The
//! other half, holding pages out of swap with `mlock`, needs an operating system
//! call and is quarantined in its own crate by ADR-016 section 5. Until that
//! crate exists the loss is real and recorded: `zeroize` clears a value *after*
//! use, and a page reaches swap *during* use. One does not stand in for the other.
//!
//! **Keys of different purposes are different types.** A session key cannot be
//! passed where a record key belongs, because HKDF's whole job is separating
//! them and a `[u8; 32]` argument would undo that at the first call site.

use std::fmt;
use std::marker::PhantomData;

use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::error::VaultError;

/// Every key in this vault is 256 bits: what Argon2id emits, what HKDF expands
/// to, and what XChaCha20-Poly1305 takes.
pub(super) const KEY_BYTES: usize = 32;

/// What a key is for.
///
/// The label exists so a redacted `Debug` can still say which key it refused to
/// print, which is the difference between a readable log line and a mystery.
pub trait KeyPurpose {
    const LABEL: &'static str;
}

/// A purpose whose key is expanded from the master key with HKDF.
///
/// The info string is the domain separator, and it lives beside the purpose so
/// that adding a key means naming what it is for. ADR-007 fixes these strings.
pub trait DerivedPurpose: KeyPurpose {
    const INFO: &'static [u8];
}

/// The key the passphrase derives. Not expanded from anything; everything else is
/// expanded from it.
#[derive(Debug)]
pub struct Master;

impl KeyPurpose for Master {
    const LABEL: &'static str = "master";
}

/// The per session key alias derivation runs under (ADR-007 "Takma ad üretimi").
///
/// Its salt is the session id, which is what makes aliases unlinkable across
/// sessions: a new session id changes every alias the same value produces.
#[derive(Debug)]
pub struct SessionScope;

impl KeyPurpose for SessionScope {
    const LABEL: &'static str = "session";
}

impl DerivedPurpose for SessionScope {
    const INFO: &'static [u8] = b"periskop/alias/v1";
}

/// The key vault records are sealed under, `K_vault` in ADR-007.
///
/// Expanded rather than used raw so that it is a sibling of the chain key the
/// file backend needs ("K_chain ... kayıt anahtarından ayrı"), instead of the
/// chain key being a child of the record key.
#[derive(Debug)]
pub struct RecordScope;

impl KeyPurpose for RecordScope {
    const LABEL: &'static str = "record";
}

impl DerivedPurpose for RecordScope {
    const INFO: &'static [u8] = b"periskop/vault/record/v1";
}

/// The key the `vault.psk` integrity chain is computed under, `K_chain` in
/// ADR-007 section "3. Dosya bütünlüğü".
///
/// Separate from [`RecordScope`] because the two answer different questions. The
/// record key says "this record was sealed for this slot"; the chain key says
/// "this is the whole set of records, in this order, under this header". A single
/// key doing both would mean that a leak of the one used on every request also
/// hands over the ability to forge a file the vault would open.
#[derive(Debug)]
pub struct ChainScope;

impl KeyPurpose for ChainScope {
    const LABEL: &'static str = "chain";
}

impl DerivedPurpose for ChainScope {
    /// Fixed by ADR-007 by name; it is not ours to choose.
    const INFO: &'static [u8] = b"periskop/vault/chain/v1";
}

/// A 256 bit key that knows what it is for, clears itself, and prints nothing.
pub struct Key<P: KeyPurpose> {
    bytes: Zeroizing<[u8; KEY_BYTES]>,
    purpose: PhantomData<P>,
}

impl<P: KeyPurpose> fmt::Debug for Key<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("purpose", &P::LABEL)
            .field("material", &"<redacted>")
            .finish()
    }
}

impl<P: KeyPurpose> Key<P> {
    pub(super) fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
            purpose: PhantomData,
        }
    }

    /// The bytes, for the two callers that must have them: HKDF and the AEAD.
    ///
    /// Crate private on purpose. A public accessor would let any future caller
    /// copy a key into a buffer that does not clear itself.
    pub(super) fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.bytes
    }
}

/// Backed by the `Zeroizing` field above, and declared so that a reader gets the
/// guarantee from the type rather than from reading the field.
impl<P: KeyPurpose> ZeroizeOnDrop for Key<P> {}

/// The key derived from the operator's passphrase.
pub type MasterKey = Key<Master>;
/// The per session key alias derivation will run under.
pub type SessionKey = Key<SessionScope>;

impl SessionKey {
    /// The 32 bytes `alias::derive` runs its HMAC over.
    ///
    /// **The one key accessor that leaves this module, and the name says so.**
    /// It closes the request F4-D left in `hub/memory/interfaces.md`: `alias`
    /// needs `K_session` to derive an alias seed, `Key::as_bytes` is
    /// `pub(in crate::vault)`, and without a bridge the request path would have
    /// had to mint under a key that is not session scoped. Aliases would then be
    /// linkable across conversations, which is the exact property ADR-007 spends a
    /// per session HKDF expansion to remove.
    ///
    /// Option (a) of the two the request offered, for the reason it gave: the
    /// alternative handed the vault a dependency on the alias module and reversed
    /// the direction of the arrow between them. The precedent is
    /// [`SecretValue::expose`], the caller is `alias::derive::alias_seed`, and the
    /// name is deliberately uncomfortable so that a second caller has to justify
    /// itself.
    ///
    /// The bytes are borrowed, never copied out into a buffer of the caller's
    /// own: `AliasKey` wraps them in `Zeroizing` on the way in.
    pub fn expose_for_alias_derivation(&self) -> &[u8; KEY_BYTES] {
        self.as_bytes()
    }
}
/// The key records are sealed under.
pub type RecordKey = Key<RecordScope>;
/// The key the vault file's integrity chain is computed under.
pub type ChainKey = Key<ChainScope>;

/// What the operator typed, on its way to Argon2id and nowhere else.
pub struct Passphrase(Zeroizing<Vec<u8>>);

impl ZeroizeOnDrop for Passphrase {}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Not even the length: it is the one fact about a passphrase that helps
        // a guesser and helps nobody else.
        f.write_str("Passphrase(<redacted>)")
    }
}

impl Passphrase {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A passphrase with nothing in it is not a passphrase.
    ///
    /// The vault refuses to open on one rather than deriving a key from the empty
    /// string, which would be a vault anybody can open while looking encrypted.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A decrypted vault record: the original value an alias stands for.
///
/// Handed back only by the restore path, and only after the AEAD has confirmed
/// the record was sealed under the identity it is being opened under.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl ZeroizeOnDrop for SecretValue {}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The length is withheld here too. A masked value's length is a fact
        // about the personal data this component exists to keep from leaking.
        f.write_str("SecretValue(<redacted>)")
    }
}

impl SecretValue {
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Hands out the plaintext, for the one caller whose job is to write it back
    /// into a response.
    ///
    /// Named to be uncomfortable. Every use of it is a place where personal data
    /// enters a buffer this module no longer controls.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// The one door to the operating system's entropy source.
///
/// Nonces and session identifiers come through here and from nowhere else. There
/// is no seed, no counter and no cached pool, which is exactly the property
/// ADR-007's D-14 revision bought: state that does not exist cannot roll back
/// when a file is restored from a backup.
pub(super) fn random_bytes<const N: usize>() -> Result<[u8; N], VaultError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| VaultError::EntropyUnavailable)?;
    Ok(bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_absent_from_its_debug_rendering() {
        let key = MasterKey::from_bytes([0xAB; KEY_BYTES]);
        let rendered = format!("{key:?}");

        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("master"), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}");
        assert!(!rendered.contains("ab"), "{rendered}");
    }

    #[test]
    fn a_passphrase_and_a_decrypted_value_are_absent_from_their_debug_rendering() {
        let passphrase = Passphrase::new(b"correct horse battery staple".to_vec());
        let value = SecretValue::new(b"Ahmet Yilmaz".to_vec());

        let rendered = format!("{passphrase:?} {value:?}");
        assert!(!rendered.contains("horse"), "{rendered}");
        assert!(!rendered.contains("Ahmet"), "{rendered}");
        // Nor the length, which is the fact people leak while thinking they are
        // being careful.
        assert!(!rendered.contains("28"), "{rendered}");
        assert!(!rendered.contains("12"), "{rendered}");
    }

    #[test]
    fn every_expanded_purpose_uses_a_different_info_string() {
        // The whole point of expanding rather than reusing the master key. If any
        // two of these collide, two keys become one key, and for the chain key
        // that would mean the key an attacker needs to forge a vault file is the
        // key every request already uses.
        let labels = [SessionScope::INFO, RecordScope::INFO, ChainScope::INFO];
        let distinct: std::collections::BTreeSet<&[u8]> = labels.into_iter().collect();
        assert_eq!(distinct.len(), labels.len());
    }

    #[test]
    fn the_chain_key_carries_the_info_string_the_adr_fixes() {
        // ADR-007 section "3. Dosya bütünlüğü" writes this string out. Changing it
        // silently invalidates every vault file a previous version wrote, so it
        // has to be a decision rather than an edit.
        assert_eq!(ChainScope::INFO, b"periskop/vault/chain/v1");
    }

    #[test]
    fn an_empty_passphrase_is_recognised_as_empty() {
        assert!(Passphrase::new(Vec::new()).is_empty());
        assert!(!Passphrase::new(b"x".to_vec()).is_empty());
    }

    /// The half of the memory discipline this crate can keep on its own
    /// (`proxy/spec.md` section 9). Stated as a compile time check so that a
    /// future type carrying key material has to declare the same thing.
    #[test]
    fn every_secret_here_clears_itself_on_drop() {
        fn clears_itself<T: ZeroizeOnDrop>() {}

        clears_itself::<MasterKey>();
        clears_itself::<SessionKey>();
        clears_itself::<RecordKey>();
        clears_itself::<ChainKey>();
        clears_itself::<Passphrase>();
        clears_itself::<SecretValue>();
    }

    #[test]
    fn two_draws_from_the_entropy_source_differ() {
        let first: [u8; 24] = random_bytes().unwrap();
        let second: [u8; 24] = random_bytes().unwrap();
        assert_ne!(first, second);
        assert_ne!(first, [0u8; 24]);
    }
}
