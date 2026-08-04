//! Deriving an alias from a value: the seed, the normalisation, and the bytes a
//! generator draws from.
//!
//! # The derivation (`proxy/spec.md` section 4.1, ADR-007)
//!
//! ```text
//! alias_seed = HMAC-SHA256(K_session, ENTITY_TAG || 0x00 || normalize(value))
//! ```
//!
//! Three properties come out of that line and all three are load bearing.
//!
//! **The same value masks to the same alias inside one conversation.** Without
//! it, a model reading two turns of one conversation sees two customers where
//! there is one, and every answer that counts, compares or refers back is wrong.
//!
//! **The same value masks to a different alias in a different conversation.**
//! `K_session` is expanded from the master key under the session id (ADR-007),
//! so a provider holding two sessions cannot join them on an alias. This is the
//! property that makes aliases unlinkable, and it is why the key is per session
//! rather than per vault.
//!
//! **The seed is not the alias.** The alias is rendered from the seed, and the
//! way back from an alias to a value is a vault lookup, never a computation.
//! Somebody holding an alias holds nothing.
//!
//! # Normalisation, and the harm it prevents
//!
//! [`normalize`] is what makes two spellings of one entity one entity: an IBAN
//! with and without its grouping spaces, an address written in either case.
//! Where it is missing the failure is quiet rather than loud, and quiet is the
//! worse half: the same person picks up two aliases in one conversation and the
//! model treats them as two people.
//!
//! It runs in one direction only. Nothing here reconstructs the original from
//! the normalised form, and the vault stores the original bytes as they arrived.
//!
//! # The byte stream
//!
//! Generators need more than 32 bytes (a 128 byte secret body, for one), so the
//! seed is expanded the way HKDF expands: repeated HMAC under the seed itself
//! with a block counter. It is a deterministic stream and not entropy. The same
//! seed always renders the same alias, which is what makes a golden test
//! possible and what makes a conversation consistent.

use core::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::entity::EntityType;
use super::error::AliasError;
use crate::vault::record::ALIAS_SEED_BYTES;
use crate::vault::AliasSeed;

/// Bytes of seed material every generator has available.
///
/// Sized against the worst case draw with room to spare: a 128 character secret
/// body at two bytes per character is 256, and this is twice that. The window is
/// not unlimited on purpose, but it may not be tight either. An earlier 192 byte
/// window wrapped in the middle of a long key body and the alias visibly
/// repeated its own first characters, which is not a P-0 failure but is a
/// pattern that should not be in an alias.
const STREAM_BYTES: usize = 512;

/// The key alias derivation runs under, `K_session` in ADR-007.
///
/// A separate type from the vault's `SessionKey` on purpose. The vault holds key
/// material and hands out none of it; this layer needs 32 bytes to run HMAC
/// over. Building one of these from a live session is the request path's job and
/// needs a vault side accessor that does not exist yet: it is an open interface
/// request, not a hole punched through the vault's boundary from here.
pub struct AliasKey {
    bytes: Zeroizing<[u8; 32]>,
}

impl AliasKey {
    /// Wraps 32 bytes of session scoped key material.
    pub fn from_key_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }
}

/// Backed by the `Zeroizing` field, declared so the guarantee reads from the
/// type rather than from the field.
impl ZeroizeOnDrop for AliasKey {}

impl fmt::Debug for AliasKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The same discipline as every secret in the vault: a derived `Debug`
        // puts key material into the first `{:?}` somebody reaches for.
        f.write_str("AliasKey(<redacted>)")
    }
}

/// What one value is called inside one session.
///
/// The alias layer's own type rather than the vault's [`AliasSeed`], because the
/// vault treats a seed as opaque bytes it never looks into and this layer has to
/// expand it. [`ValueSeed::to_vault_seed`] is the one way across, which keeps
/// the direction of the dependency pointing at the vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueSeed([u8; ALIAS_SEED_BYTES]);

impl ValueSeed {
    pub fn as_bytes(&self) -> &[u8; ALIAS_SEED_BYTES] {
        &self.0
    }

    /// The record identity the vault seals a value under.
    pub fn to_vault_seed(self) -> AliasSeed {
        AliasSeed::from_bytes(self.0)
    }
}

/// `HMAC-SHA256(K_session, ENTITY_TAG || 0x00 || normalize(value))`.
///
/// The zero byte is a separator and it is not decoration: without it the pair
/// (`ORG`, `_1`) and the pair (`ORG_1`, empty) would hash the same, and two
/// different entities would share one vault slot.
pub fn alias_seed(
    key: &AliasKey,
    entity: EntityType,
    value: &str,
) -> Result<ValueSeed, AliasError> {
    let normalised = normalize(entity, value);
    if normalised.is_empty() {
        return Err(AliasError::EmptyValue { entity });
    }
    let digest = mac(
        &key.bytes,
        &[entity.tag().as_bytes(), &[0x00], normalised.as_bytes()],
    )?;
    Ok(ValueSeed(digest))
}

/// The seed one rendering attempt draws from.
///
/// `counter` is zero for the first attempt and rises only when the rendered
/// alias is already spoken for (`proxy/spec.md` section 4.4: the seed is derived
/// again with a counter). The record's identity stays the counter zero seed, so
/// walking the counter changes what is rendered without changing which vault
/// slot the value owns.
pub fn render_seed(
    key: &AliasKey,
    seed: &ValueSeed,
    counter: u32,
) -> Result<[u8; ALIAS_SEED_BYTES], AliasError> {
    mac(
        &key.bytes,
        &[
            b"periskop/alias/render/v1",
            seed.as_bytes(),
            &counter.to_le_bytes(),
        ],
    )
}

/// A deterministic byte stream expanded from one render seed.
pub struct SeedStream {
    bytes: Zeroizing<[u8; STREAM_BYTES]>,
    taken: usize,
}

impl SeedStream {
    /// Expands the seed into the fixed window every generator shares.
    pub fn new(seed: &[u8; ALIAS_SEED_BYTES]) -> Result<Self, AliasError> {
        let mut bytes = [0u8; STREAM_BYTES];
        let mut written = 0usize;
        let mut block_index = 0u32;
        while written < STREAM_BYTES {
            let block = mac(
                seed,
                &[b"periskop/alias/expand/v1", &block_index.to_le_bytes()],
            )?;
            for byte in block {
                if written == STREAM_BYTES {
                    break;
                }
                bytes[written] = byte;
                written += 1;
            }
            block_index += 1;
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes),
            taken: 0,
        })
    }

    /// The next byte, wrapping around at the end of the window.
    pub fn byte(&mut self) -> u8 {
        let index = self.taken % STREAM_BYTES;
        self.taken += 1;
        self.bytes[index]
    }

    /// A value below `bound`, or zero for a bound of zero.
    ///
    /// Modulo, so the distribution is very slightly uneven for bounds that do
    /// not divide 2^32. That is acceptable here and would not be in a key: this
    /// decides which of a few hundred documented addresses to use, and
    /// unlinkability comes from the session key rather than from this being
    /// uniform.
    pub fn below(&mut self, bound: u32) -> u32 {
        if bound == 0 {
            return 0;
        }
        let mut value = 0u32;
        for _ in 0..4 {
            value = (value << 8) | u32::from(self.byte());
        }
        value % bound
    }

    /// One decimal digit.
    ///
    /// One byte, so a long run of digits stays inside the window. The modulo
    /// leaves six values of 256 slightly more likely, which changes nothing here:
    /// these digits fill the shape of an identifier that is invalid on purpose,
    /// and they are not what any secrecy claim rests on.
    pub fn digit(&mut self) -> u8 {
        self.byte() % 10
    }

    /// `count` decimal digits.
    pub fn digits(&mut self, count: usize) -> String {
        (0..count)
            .map(|_| char::from(b'0' + self.digit()))
            .collect()
    }

    /// `count` lower case hexadecimal characters.
    pub fn hex(&mut self, count: usize) -> String {
        let mut out = String::with_capacity(count);
        while out.len() < count {
            let byte = self.byte();
            for nibble in [byte >> 4, byte & 0x0F] {
                if out.len() == count {
                    break;
                }
                // Every nibble is below sixteen, so the fallback is unreachable
                // and exists only because this crate does not panic.
                out.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
            }
        }
        out
    }

    /// One entry of an alphabet.
    pub fn pick<'a>(&mut self, alphabet: &[&'a str]) -> &'a str {
        if alphabet.is_empty() {
            return "";
        }
        let index = self.short() as usize % alphabet.len();
        alphabet.get(index).copied().unwrap_or_default()
    }

    /// One character of a string of candidates.
    ///
    /// Two bytes rather than one, which matters for exactly one caller: a key
    /// body drawn from a 62 character alphabet. One byte would leave eight of
    /// the sixty two characters slightly likelier and drop the min entropy per
    /// character to about 5.68 bits, so a 22 character body would carry 125 bits
    /// and threat model R14's "at most 2^-128" would stop being true by a
    /// hair. Two bytes puts it at about 5.95 bits per character.
    pub fn pick_char(&mut self, alphabet: &str) -> char {
        let count = alphabet.chars().count();
        if count == 0 {
            return '0';
        }
        let index = self.short() as usize % count;
        alphabet.chars().nth(index).unwrap_or('0')
    }

    /// Two bytes as one number.
    fn short(&mut self) -> u16 {
        (u16::from(self.byte()) << 8) | u16::from(self.byte())
    }
}

/// Type specific canonicalisation.
///
/// Every arm answers one question: which two spellings are the same entity? The
/// cost of getting it wrong is not a crash, it is one person wearing two aliases
/// in one conversation, so each arm says what it treats as presentation.
pub fn normalize(entity: EntityType, value: &str) -> String {
    let trimmed = value.trim();
    match entity {
        // Grouping spaces and hyphens are presentation, and so is case: ISO
        // 13616 writes an IBAN in upper case.
        EntityType::Iban => trimmed
            .chars()
            .filter(|character| !matches!(character, ' ' | '-' | '.'))
            .flat_map(char::to_uppercase)
            .collect(),
        // Digit groups are written with spaces, dots or hyphens in all three.
        EntityType::Tckn | EntityType::Vkn | EntityType::CreditCard => {
            trimmed.chars().filter(char::is_ascii_digit).collect()
        }
        // E.164, with a written out international prefix folded into the plus.
        EntityType::Phone => normalize_phone(trimmed),
        // Domains are case insensitive and a trailing dot is the root label
        // written out. The local part is folded too: mail systems treat it as
        // case sensitive in the standard and as case insensitive in practice,
        // and folding is the choice that keeps one person to one alias.
        EntityType::Email => match trimmed.split_once('@') {
            Some((local, domain)) => {
                format!("{}@{}", local.to_ascii_lowercase(), normalize_host(domain))
            }
            None => trimmed.to_ascii_lowercase(),
        },
        EntityType::Host | EntityType::Url => normalize_host(trimmed),
        EntityType::Ipv4 => trimmed.to_owned(),
        EntityType::Ipv6 => trimmed.to_ascii_lowercase(),
        // Key material is bytes. Case, punctuation and length are all part of
        // the value, and folding any of them would merge two different secrets
        // into one alias and one vault record.
        EntityType::ApiKey | EntityType::Secret => trimmed.to_owned(),
        // Names: Turkish aware folding, then whitespace collapsed. The Turkish
        // pairs are why this is not `to_lowercase`: the dotless letter means
        // "IŞIK" has to fold to "ışık", and a name that folds two ways on two
        // turns picks up two aliases.
        EntityType::Person | EntityType::Org | EntityType::Loc | EntityType::Address => {
            fold_turkish(trimmed)
        }
        // Not minted. Normalising a value nothing aliases has no meaning; the
        // trimmed form keeps the function total rather than adding a panic.
        EntityType::Date => trimmed.to_owned(),
    }
}

/// Digits only, with the leading plus kept when the caller wrote one.
fn normalize_phone(value: &str) -> String {
    let digits: String = value.chars().filter(char::is_ascii_digit).collect();
    if let Some(rest) = digits.strip_prefix("00") {
        return format!("+{rest}");
    }
    if value.starts_with('+') {
        return format!("+{digits}");
    }
    digits
}

/// Lower case, without the root label's trailing dot.
fn normalize_host(value: &str) -> String {
    value.trim_end_matches('.').trim().to_ascii_lowercase()
}

/// Turkish aware case folding with runs of whitespace collapsed.
fn fold_turkish(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_was_space = false;
    for character in value.chars() {
        if character.is_whitespace() {
            if !last_was_space && !out.is_empty() {
                out.push(' ');
            }
            last_was_space = true;
            continue;
        }
        last_was_space = false;
        match character {
            // The two pairs Unicode's default casing gets wrong for Turkish.
            'I' => out.push('\u{131}'),
            '\u{130}' => out.push('i'),
            other => out.extend(other.to_lowercase()),
        }
    }
    out.trim_end().to_owned()
}

/// One HMAC-SHA256 over a list of parts.
fn mac(key: &[u8; 32], parts: &[&[u8]]) -> Result<[u8; ALIAS_SEED_BYTES], AliasError> {
    // HMAC accepts a key of any length and this one is a fixed 32 bytes, so the
    // error arm cannot fire. Mapped rather than unwrapped because a panic here
    // would take down a request path with no diagnosis.
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| AliasError::KeyUnusable)?;
    for part in parts {
        hmac.update(part);
    }
    let digest = hmac.finalize().into_bytes();
    if digest.len() != ALIAS_SEED_BYTES {
        return Err(AliasError::KeyUnusable);
    }
    let mut out = [0u8; ALIAS_SEED_BYTES];
    out.copy_from_slice(&digest);
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::entity::AliasStyle;
    use super::super::mint::{tests::source_for, Minter};
    use super::*;

    /// A session, pinned to a key so that a golden file can exist at all.
    fn session(key_byte: u8) -> Minter {
        Minter::new(
            AliasKey::from_key_bytes([key_byte; 32]),
            AliasStyle::TypePreserving,
        )
    }

    /// The types whose alias is derived from the seed.
    ///
    /// The label types are deliberately not here. `PERSON_1` is a counter, not a
    /// derivation, so it reads the same in every session, and that is not a
    /// correlation channel: the string carries nothing about the value, so two
    /// sessions holding `PERSON_1` have learned nothing about each other. What
    /// would leak is a seed derived alias repeating across sessions, and that is
    /// exactly what the test below forbids.
    fn seed_derived() -> Vec<EntityType> {
        EntityType::ALL
            .into_iter()
            .filter(|entity| {
                !matches!(
                    entity,
                    EntityType::Person
                        | EntityType::Org
                        | EntityType::Loc
                        | EntityType::Address
                        | EntityType::Date
                        | EntityType::Url
                )
            })
            .collect()
    }

    #[test]
    fn one_value_keeps_one_alias_for_the_life_of_a_session() {
        let mut book = session(0x11);
        for entity in EntityType::ALL {
            if matches!(entity, EntityType::Date | EntityType::Url) {
                continue;
            }
            let first = book.mint(entity, source_for(entity)).unwrap();
            let again = book.mint(entity, source_for(entity)).unwrap();
            assert_eq!(first.alias, again.alias, "{entity}");
            assert_eq!(first.seed, again.seed, "{entity}");
            assert!(!first.reused);
            assert!(again.reused, "{entity} was minted twice");
        }
        // A repeat is not a second alias, so it does not eat a slot of the
        // session ceiling either.
        assert_eq!(book.issued_count(), EntityType::ALL.len() - 2);
    }

    #[test]
    fn the_same_value_in_another_session_gets_another_alias() {
        // The unlinkability property, and the reason the key is per session:
        // a provider holding two conversations may not join them on an alias.
        let mut first = session(0x21);
        let mut second = session(0x22);
        for entity in seed_derived() {
            let here = first.mint(entity, source_for(entity)).unwrap();
            let there = second.mint(entity, source_for(entity)).unwrap();
            assert_ne!(
                here.alias, there.alias,
                "{entity} produced the same alias in two sessions"
            );
            assert_ne!(here.seed, there.seed, "{entity} seeds are linkable");
        }
    }

    #[test]
    fn two_spellings_of_one_entity_are_one_entity() {
        let mut book = session(0x31);
        let pairs = [
            (
                EntityType::Iban,
                "TR33 0006 1005 1978 6457 8413 26",
                "tr330006100519786457841326",
            ),
            (
                EntityType::Email,
                "Ahmet.Yilmaz@Example.Com.TR",
                "ahmet.yilmaz@example.com.tr.",
            ),
            (EntityType::Phone, "+90 532 123 45 67", "0090-532-123-45-67"),
            (
                EntityType::CreditCard,
                "4111 1111 1111 1111",
                "4111-1111-1111-1111",
            ),
            (EntityType::Tckn, "100 000 001 46", "10000000146"),
            (EntityType::Person, "AHMET  YILMAZ", "ahmet yılmaz"),
            (EntityType::Host, "API.Internal.Corp.", "api.internal.corp"),
        ];
        for (entity, written, other) in pairs {
            let first = book.mint(entity, written).unwrap();
            let second = book.mint(entity, other).unwrap();
            assert_eq!(
                first.alias, second.alias,
                "{entity}: two spellings picked up two aliases"
            );
            assert!(second.reused, "{entity}");
        }
    }

    #[test]
    fn two_different_values_are_two_different_entities() {
        let mut book = session(0x41);
        let first = book
            .mint(EntityType::Iban, "TR330006100519786457841326")
            .unwrap();
        let second = book
            .mint(EntityType::Iban, "TR330006100519786457841327")
            .unwrap();
        assert_ne!(first.seed, second.seed);
        assert_ne!(first.alias, second.alias);

        // And the separator earns its place: a tag and a value that could be cut
        // in a different place must not hash to one seed.
        let key = AliasKey::from_key_bytes([0x41; 32]);
        let left = alias_seed(&key, EntityType::Org, "_1").unwrap();
        let right = alias_seed(&key, EntityType::Org, "1").unwrap();
        assert_ne!(left, right);
    }

    #[test]
    fn a_fixed_key_renders_the_same_bytes_every_run() {
        // The golden file. Pinned to a key rather than to a session id because
        // this layer is handed the derived key; if any of these lines changes,
        // conversations in flight change meaning and vault records written by an
        // earlier build stop matching what a later build renders.
        let mut book = session(0x7A);
        let mut rendered = String::new();
        for entity in EntityType::ALL {
            if matches!(entity, EntityType::Date | EntityType::Url) {
                continue;
            }
            let minted = book.mint(entity, source_for(entity)).unwrap();
            rendered.push_str(&format!("{entity} {}\n", minted.alias));
        }
        let host = book
            .mint_url_host("https://api.internal.corp/v1/users?id=7")
            .unwrap();
        rendered.push_str(&format!("URL_HOST {}\n", host.minted.alias));

        assert_eq!(rendered, GOLDEN);
    }

    /// The rendering above, byte for byte.
    ///
    /// Produced by running the generators, never typed. The two key lines
    /// changed when the key body was broken into groups, and the shape they
    /// changed into is the point: `sk_live_` still opens the line, and what
    /// follows it stops after eight characters, so no secret scanner reads the
    /// line as a credential (`tests/p0_invariants.rs`).
    const GOLDEN: &str = "\
IBAN TR168365097991956726085801
TCKN 19714840601
VKN 5377639395
CREDIT_CARD 4012888888881881
EMAIL user51179@example-a.invalid
PHONE +9000168386985
IPV4 203.0.113.100
IPV6 2001:db8:bcbb:2e7f::2da1
API_KEY ghp_rHdPO71r.0OLuEWTa.Ph6XhJ84.X9P2vHTE.Q0UMUnzp.lvlslem.RhvtvSG
SECRET sk_live_O9VQFZo3.ki5v8pU.jYuKaho
HOST host257.example-f.invalid
PERSON PERSON_1
ORG ORG_1
LOC LOC_1
ADDRESS ADDRESS_1
URL_HOST host257.example-f.invalid
";

    #[test]
    fn normalisation_never_grows_a_value_back() {
        // One directional by construction: nothing here reconstructs an original
        // from a normalised form, and the vault keeps the original bytes.
        // Counted in characters rather than bytes, because folding a dotted I to
        // a dotless one costs a byte and removes a character's worth of
        // information all the same.
        for entity in EntityType::ALL {
            let source = source_for(entity);
            let normalised = normalize(entity, source);
            assert!(
                normalised.chars().count() <= source.chars().count(),
                "{entity} normalisation grew the value"
            );
        }
    }

    #[test]
    fn the_turkish_pairs_fold_the_way_turkish_folds() {
        // "IŞIK" folded by Unicode's default rules becomes "ışık" only if the
        // dotless letter is handled; the default mapping produces an "i" with a
        // dot and a name that folds two ways picks up two aliases.
        assert_eq!(normalize(EntityType::Person, "IŞIK"), "ışık");
        assert_eq!(normalize(EntityType::Person, "İstanbul"), "istanbul");
        assert_eq!(
            normalize(EntityType::Person, "  Ahmet   Yilmaz  "),
            "ahmet yilmaz"
        );
        assert_eq!(normalize(EntityType::Person, "ÇAĞLA"), "çağla");
    }

    #[test]
    fn the_stream_is_a_function_of_its_seed_and_nothing_else() {
        let mut first = SeedStream::new(&[9u8; 32]).unwrap();
        let mut second = SeedStream::new(&[9u8; 32]).unwrap();
        let mut other = SeedStream::new(&[10u8; 32]).unwrap();
        assert_eq!(first.digits(40), second.digits(40));
        assert_ne!(first.hex(16), other.hex(16));

        // And it keeps producing after the window is used up, deterministically.
        let mut long = SeedStream::new(&[9u8; 32]).unwrap();
        let drawn = long.digits(400);
        assert_eq!(drawn.len(), 400);
        let mut again = SeedStream::new(&[9u8; 32]).unwrap();
        assert_eq!(drawn, again.digits(400));
    }

    #[test]
    fn a_key_prints_nothing_of_itself() {
        let key = AliasKey::from_key_bytes([0xAB; 32]);
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("ab"), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}");
    }
}
