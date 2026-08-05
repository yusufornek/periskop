//! The session's alias book: what has been handed out, and what may not be.
//!
//! # Three jobs, and each one prevents a specific wrong answer
//!
//! **Remembering.** One value gets one alias for the life of a conversation. A
//! second alias for the same customer turns one customer into two in the
//! model's reading of the thread.
//!
//! **Collision resolution.** Two different values may render to the same string,
//! and small output spaces make that reachable rather than theoretical. The
//! resolution is a counter walk over the render seed (`proxy/spec.md` section
//! 4.4), and it is deterministic. The alternative, letting two values share an
//! alias, means restoration hands the user the wrong person's data under an
//! alias they were shown.
//!
//! **Withholding.** A user who writes `PERSON_1` in their own prompt has written
//! a string this session might otherwise have produced. It is taken out of the
//! pool (spec section 4.2: "the alias is marked as preserved and the value is
//! removed from the pool"). Without that, the response path finds `PERSON_1`,
//! looks it up and substitutes a real person's name into a sentence the user
//! wrote about something else. ADR-010 section 6 calls this the second link of
//! the protection chain; the first is that only aliases actually produced in
//! this session are ever restored.
//!
//! # What this module does not do
//!
//! It does not store values. The alias to value map is the vault's, sealed and
//! keyed (ADR-007); what is here is the alias string, the seed that names the
//! record, and counters. A caller mints an alias and then hands the pair to the
//! vault, and the two agree because both are keyed by the same seed.

use std::collections::{BTreeMap, BTreeSet};

use super::card;
use super::derive::{self, AliasKey, SeedStream, ValueSeed};
use super::entity::{AliasStyle, EntityType, LadderRung, Minting};
use super::error::AliasError;
use super::limits::l_type_max;
use super::opaque;
use super::phone;
use super::rung_i;
use super::rung_l;
use super::rung_r;

/// Attempts a generator gets on a documented pool before the pool is treated as
/// exhausted.
///
/// "Exhausted" is a statement about this session rather than about the published
/// list: after this many collisions the free part of the pool is small enough
/// that walking further costs more than falling to the next rung. Falling is
/// safe by construction, and it is counted.
pub const POOL_ATTEMPTS: u32 = 12;

/// Attempts before a mint is refused outright.
///
/// Reached only when even the fallback rung keeps colliding, which needs a
/// 64 bit opaque body to repeat. Refusing is the only safe end: reusing an alias
/// would make one string mean two people.
pub const MAX_ATTEMPTS: u32 = 32;

/// One rendering attempt's result.
pub struct Rendered {
    pub alias: String,
    /// The rung this string actually came from, which is not always the rung the
    /// type entered the ladder at.
    pub rung: LadderRung,
    /// A documented pool ran out and the generator fell to a lower rung
    /// (`alias_stats.alias_pool_exhausted`, KG-012).
    pub pool_exhausted: bool,
    /// A secret was longer than the largest length class
    /// (`alias_stats.alias_length_class_capped`).
    pub length_class_capped: bool,
}

/// An alias handed out, and everything the caller needs to file it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Minted {
    pub entity_type: EntityType,
    pub alias: String,
    /// The record identity: what the vault seals the original value under.
    pub seed: ValueSeed,
    /// The rung that produced it. Note that what a run *reports* for the key
    /// types is deliberately weaker; see [`AliasStats`].
    pub rung: LadderRung,
    /// This value already had an alias in this session and kept it.
    pub reused: bool,
}

/// A URL's host, aliased in place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlHostAlias {
    /// Byte range of the host inside the source URL. The caller replaces exactly
    /// these bytes and leaves the path, the query and the fragment alone.
    pub host_start: usize,
    pub host_end: usize,
    pub minted: Minted,
}

/// Per type counters, in the shape `proxy-event.schema.json` requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypeStat {
    /// Distinct aliases produced. A value masked twice in one conversation is
    /// one alias and is counted once.
    pub count: u32,
    /// The weakest rung any alias of this type came from in this run, after the
    /// entropic types are downgraded (threat model R14).
    pub ladder_rung: LadderRung,
}

/// What a run reports about alias generation (`proxy-events.md`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AliasStats {
    pub by_type: BTreeMap<EntityType, TypeStat>,
    pub alias_pool_exhausted: u32,
    pub alias_length_class_capped: u32,
}

impl AliasStats {
    /// Folds one newly issued alias of `entity`, produced at `rung`.
    ///
    /// Two rules live here rather than at the call sites. The reported rung is
    /// the **weakest** one this type reached, so a session where the card pool
    /// ran out reads as `I` rather than as `R` with a footnote; and
    /// [`EntityType::reported_rung`] then downgrades the types whose evidence is
    /// entropy, which is threat model R14.
    ///
    /// Public because a second set of counters folds the same aliases: a
    /// [`Minter`] accumulates over a conversation and `ProxyEvent` is written per
    /// request, so `http::request_path` keeps a request scoped copy. A second
    /// implementation of the two rules above is a second thing to get wrong, and
    /// the one that would be wrong is the one nobody reads.
    pub fn fold(&mut self, entity: EntityType, rung: LadderRung) {
        let reported = entity.reported_rung(rung);
        let slot = self.by_type.entry(entity).or_insert(TypeStat {
            count: 0,
            ladder_rung: reported,
        });
        slot.count = slot.count.saturating_add(1);
        if evidence_rank(reported) > evidence_rank(slot.ladder_rung) {
            slot.ladder_rung = reported;
        }
    }
}

/// What happened to a literal the user wrote that looks like an alias.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reservation {
    /// Withheld: no value will be given this string in this session.
    Withheld,
    /// This session already produced this alias, so it belongs to a value and
    /// the restore path owns it. Withholding it would break the round trip.
    AlreadyIssued,
}

/// What one value's alias is, and where it came from.
#[derive(Clone, Debug)]
struct Issued {
    alias: String,
    rung: LadderRung,
}

/// One session's alias generation.
pub struct Minter {
    key: AliasKey,
    style: AliasStyle,
    issued: BTreeMap<ValueSeed, Issued>,
    taken: BTreeMap<String, ValueSeed>,
    withheld: BTreeSet<String>,
    labels: BTreeMap<EntityType, u32>,
    stats: AliasStats,
}

impl core::fmt::Debug for Minter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Counts, never content. The alias strings are in here and
        // `proxy/spec.md` section 9 keeps them out of every log level.
        f.debug_struct("Minter")
            .field("style", &self.style.as_str())
            .field("issued", &self.issued.len())
            .field("withheld", &self.withheld.len())
            .finish()
    }
}

impl Minter {
    /// A new session's book, empty.
    pub fn new(key: AliasKey, style: AliasStyle) -> Self {
        Self {
            key,
            style,
            issued: BTreeMap::new(),
            taken: BTreeMap::new(),
            withheld: BTreeSet::new(),
            labels: BTreeMap::new(),
            stats: AliasStats::default(),
        }
    }

    pub fn style(&self) -> AliasStyle {
        self.style
    }

    /// How many distinct aliases this session has handed out.
    pub fn issued_count(&self) -> usize {
        self.issued.len()
    }

    /// Every alias this session actually produced, in sorted order.
    ///
    /// This is what the response side's frozen automaton is built from
    /// (`proxy/spec.md` section 6.2 step 2), and what it leaves out is the point:
    /// a string the **user** wrote that merely looks like one of ours is in
    /// `withheld`, not here, so it is never matched on the way back and never
    /// replaced by somebody else's value (ADR-010 section 6).
    pub fn issued_aliases(&self) -> impl Iterator<Item = &str> {
        self.taken.keys().map(String::as_str)
    }

    /// Takes a literal out of the pool.
    ///
    /// Called for every string in the request that could be an alias. Answering
    /// [`Reservation::AlreadyIssued`] rather than withholding matters: the user
    /// pasting back a previous answer is the normal case, and that string has to
    /// keep meaning what it meant.
    pub fn reserve_literal(&mut self, literal: &str) -> Reservation {
        if self.taken.contains_key(literal) {
            return Reservation::AlreadyIssued;
        }
        self.withheld.insert(literal.to_owned());
        Reservation::Withheld
    }

    /// Whether a string is free to be handed out.
    pub fn is_free(&self, alias: &str) -> bool {
        !self.taken.contains_key(alias) && !self.withheld.contains(alias)
    }

    /// The alias a seed was given, if it has one.
    pub fn alias_for(&self, seed: &ValueSeed) -> Option<&str> {
        self.issued.get(seed).map(|issued| issued.alias.as_str())
    }

    /// The counters a run reports.
    pub fn stats(&self) -> AliasStats {
        self.stats.clone()
    }

    /// Masks one value.
    pub fn mint(&mut self, entity: EntityType, value: &str) -> Result<Minted, AliasError> {
        match entity.minting() {
            Minting::NotMinted => return Err(AliasError::NotMinted { entity }),
            Minting::HostComponent => return Err(AliasError::UrlMintsViaHost),
            Minting::EntersAt(_) => {}
        }

        let seed = derive::alias_seed(&self.key, entity, value)?;
        if let Some(issued) = self.issued.get(&seed) {
            // The same value, again, in the same conversation. Same alias, no
            // second slot, no second entry in the counters.
            return Ok(Minted {
                entity_type: entity,
                alias: issued.alias.clone(),
                seed,
                rung: issued.rung,
                reused: true,
            });
        }

        let normalised = derive::normalize(entity, value);
        let probe_base = probe_base_of(&seed);
        let label_start = self.labels.get(&entity).copied().unwrap_or(1);
        let ceiling = l_type_max(entity);

        for attempt in 0..MAX_ATTEMPTS {
            let render_seed = derive::render_seed(&self.key, &seed, attempt)?;
            let mut stream = SeedStream::new(&render_seed)?;
            let rendered = render(
                entity,
                self.style,
                &normalised,
                label_start.saturating_add(attempt),
                probe_base,
                attempt,
                &mut stream,
            );

            // A generator that broke its own ceiling is a bug, and the streaming
            // hold depends on the ceiling being true, so the request stops here
            // rather than emitting an alias that can be flushed in halves.
            if rendered.alias.len() > ceiling {
                return Err(AliasError::LengthCeilingExceeded {
                    entity,
                    bytes: rendered.alias.len(),
                    ceiling,
                });
            }

            if !self.is_free(&rendered.alias) {
                continue;
            }

            if matches!(entity.minting(), Minting::EntersAt(LadderRung::Label)) {
                self.labels.insert(
                    entity,
                    label_start.saturating_add(attempt).saturating_add(1),
                );
            }
            self.record(entity, &rendered);
            self.issued.insert(
                seed,
                Issued {
                    alias: rendered.alias.clone(),
                    rung: rendered.rung,
                },
            );
            self.taken.insert(rendered.alias.clone(), seed);
            return Ok(Minted {
                entity_type: entity,
                alias: rendered.alias,
                seed,
                rung: rendered.rung,
                reused: false,
            });
        }

        Err(AliasError::CollisionUnresolved {
            entity,
            attempts: MAX_ATTEMPTS,
        })
    }

    /// Masks the host inside a URL, and only the host.
    ///
    /// ADR-010 section 2 removed whole URL aliasing because the alias carried the
    /// source URL's length, and an unbounded alias is an unbounded streaming
    /// hold. The path and the query are the detection layer's business, entity by
    /// entity.
    ///
    /// This is the entry point for a caller holding a whole URL, which is where
    /// the P-0 gate reads it from. The masking pass does **not** come through
    /// here: detection layer A narrows a `URL` candidate to the host bytes
    /// before anything is minted, so it already has the span this function would
    /// go and compute, and it reaches the same generator through
    /// [`EntityType::minted_as`]. One generator, two entry points, and neither
    /// parses a URL the other has already parsed.
    pub fn mint_url_host(&mut self, url: &str) -> Result<UrlHostAlias, AliasError> {
        let (host_start, host_end) = rung_r::host_span(url).ok_or(AliasError::HostNotFound)?;
        let host = url
            .get(host_start..host_end)
            .ok_or(AliasError::HostNotFound)?;
        let minted = self.mint(EntityType::Host, host)?;
        Ok(UrlHostAlias {
            host_start,
            host_end,
            minted,
        })
    }

    /// Folds one alias into the counters.
    fn record(&mut self, entity: EntityType, rendered: &Rendered) {
        if rendered.pool_exhausted {
            self.stats.alias_pool_exhausted = self.stats.alias_pool_exhausted.saturating_add(1);
        }
        if rendered.length_class_capped {
            self.stats.alias_length_class_capped =
                self.stats.alias_length_class_capped.saturating_add(1);
        }

        self.stats.fold(entity, rendered.rung);
    }
}

/// Whether a literal reads as a string this build's generators could hand out.
///
/// This is the question [`Minter::reserve_literal`]'s caller has to ask, and it
/// is asked here rather than at the call site so that the answer cannot drift
/// from the generators that produce the strings. It used to be asked as
/// `word.starts_with("PSK_")`, which is the **opaque** style's shape: under the
/// default `type-preserving` style no alias begins with `PSK_`, so nothing was
/// ever withheld and the mechanism ADR-010 section 6 calls the second link of
/// the protection chain was dead in the shipped configuration. A user who wrote
/// `PERSON_1` in their own sentence got that string handed to a real person, and
/// the response path then resolved the user's own words into somebody's name.
///
/// Two shapes, and no more. `PSK_...` covers the opaque style whole. The label
/// rung covers `PERSON_1`, `ORG_2`, `LOC_3` and `ADDRESS_4`, and the tag has to
/// be a type that actually mints a label, so `HTTP_2` and `TOTAL_5` in an
/// ordinary sentence stay in the pool. The remaining type-preserving aliases are
/// deliberately **not** here: a `.invalid` host, a TEST-NET address or a card
/// from the published pool cannot be told from a value a user meant, and
/// withholding those would take real values out of the pool instead of masking
/// them.
pub fn is_alias_shaped(word: &str) -> bool {
    if opaque::is_opaque(word) {
        return true;
    }
    // From the right: `CREDIT_CARD_1` splits at the wrong underscore otherwise,
    // and a tag with an underscore in it is the case that would be missed.
    let Some((tag, index)) = word.rsplit_once('_') else {
        return false;
    };
    if index.is_empty() || !index.chars().all(|character| character.is_ascii_digit()) {
        return false;
    }
    EntityType::from_tag(tag)
        .is_some_and(|entity| matches!(entity.minting(), Minting::EntersAt(LadderRung::Label)))
}

/// How weak a rung's evidence is: higher is weaker.
///
/// `L` sits with the strongest because there is nothing to allocate at all, and
/// no type mixes `L` with another rung anyway.
fn evidence_rank(rung: LadderRung) -> u8 {
    match rung {
        LadderRung::Label | LadderRung::Reserved => 0,
        LadderRung::Invalid => 1,
        LadderRung::Opaque => 2,
    }
}

/// A stable starting point for a pool probe, from the value's own seed.
///
/// Stable across attempts, unlike the render stream, which is what turns the
/// retry walk into a linear probe that covers a finite pool exactly once.
fn probe_base_of(seed: &ValueSeed) -> u32 {
    let bytes = seed.as_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// One attempt at rendering, on whichever rung the type and the style select.
fn render(
    entity: EntityType,
    style: AliasStyle,
    normalised: &str,
    label_index: u32,
    probe_base: u32,
    attempt: u32,
    stream: &mut SeedStream,
) -> Rendered {
    // The policy's opaque style drops every type to rung O before the ladder is
    // consulted at all (ADR-010 section 5.2). P-0 holds in both styles; this one
    // simply declines the shape.
    if style == AliasStyle::Opaque {
        return plain(opaque::render(entity, stream), LadderRung::Opaque);
    }

    match entity {
        EntityType::Person | EntityType::Org | EntityType::Loc | EntityType::Address => {
            plain(rung_l::render(entity, label_index), LadderRung::Label)
        }
        EntityType::Email => documented_or_opaque(entity, rung_r::email(stream), attempt, stream),
        EntityType::Host | EntityType::Url => {
            documented_or_opaque(entity, rung_r::host(stream), attempt, stream)
        }
        EntityType::Ipv4 => documented_or_opaque(entity, rung_r::ipv4(stream), attempt, stream),
        EntityType::Ipv6 => documented_or_opaque(entity, rung_r::ipv6(stream), attempt, stream),
        EntityType::CreditCard => card::render(stream, normalised, probe_base, attempt),
        EntityType::Phone => phone::render(stream, normalised, attempt, POOL_ATTEMPTS),
        EntityType::Iban => match rung_i::iban(stream, normalised) {
            Some(alias) => plain(alias, LadderRung::Invalid),
            // The source is not shaped like an IBAN, so no country code can be
            // preserved honestly. Opaque rather than invented.
            None => plain(opaque::render(entity, stream), LadderRung::Opaque),
        },
        EntityType::Tckn => plain(rung_i::tckn(stream), LadderRung::Invalid),
        EntityType::Vkn => plain(rung_i::vkn(stream), LadderRung::Invalid),
        EntityType::ApiKey | EntityType::Secret => {
            let produced = rung_i::key(stream, normalised);
            Rendered {
                alias: produced.alias,
                rung: LadderRung::Invalid,
                pool_exhausted: false,
                length_class_capped: produced.length_class_capped,
            }
        }
        // Refused before this function is reached.
        EntityType::Date => plain(opaque::render(entity, stream), LadderRung::Opaque),
    }
}

/// A rung `R` alias while the documented pool still has room, opaque after.
///
/// The fall is what keeps P-0 true when a finite pool fills up: stepping outside
/// a documentation block would put the alias on somebody's real network.
fn documented_or_opaque(
    entity: EntityType,
    alias: String,
    attempt: u32,
    stream: &mut SeedStream,
) -> Rendered {
    if attempt < POOL_ATTEMPTS {
        return plain(alias, LadderRung::Reserved);
    }
    Rendered {
        alias: opaque::render(entity, stream),
        rung: LadderRung::Opaque,
        pool_exhausted: true,
        length_class_capped: false,
    }
}

/// A rendering with no flags raised.
fn plain(alias: String, rung: LadderRung) -> Rendered {
    Rendered {
        alias,
        rung,
        pool_exhausted: false,
        length_class_capped: false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod tests {
    use super::*;

    fn minter(byte: u8) -> Minter {
        Minter::new(
            AliasKey::from_key_bytes([byte; 32]),
            AliasStyle::TypePreserving,
        )
    }

    /// A value each type could plausibly have been detected from.
    ///
    /// Shared by the tests that walk the whole registry. It matters that these
    /// are shaped like the real thing: a TCKN generator handed a sentence has no
    /// digits to normalise and refuses, which is correct behaviour and a useless
    /// test.
    ///
    /// The two key sources carry a provider prefix but are broken up so that no
    /// secret scanner will call them a key. Nothing here needs a long run of
    /// characters: the key generator reads the total length and the first
    /// underscore and nothing else, and a fixture that is itself a scanner match
    /// becomes a credential alert in every clone of this repository.
    pub(crate) fn source_for(entity: EntityType) -> &'static str {
        match entity {
            EntityType::Iban => "TR33 0006 1005 1978 6457 8413 26",
            EntityType::Tckn => "10000000146",
            EntityType::Vkn => "4980312208",
            EntityType::CreditCard => "4111 1111 1111 1111",
            EntityType::Email => "Ahmet.Yilmaz@Example.Com.TR",
            EntityType::Phone => "+90 532 123 45 67",
            EntityType::Ipv4 => "192.168.1.10",
            EntityType::Ipv6 => "2a00:1450:4001:80b::200e",
            EntityType::ApiKey => "ghp_ABCDEFGH.IJKLMNOP.QRSTUVWX.YZ012345",
            EntityType::Secret => "sk_live_ABCDEFGH.IJKLMNOP",
            EntityType::Url => "https://api.internal.corp/v1/users?id=7",
            EntityType::Host => "api.internal.corp",
            EntityType::Date => "2026-08-04",
            EntityType::Person => "Ahmet Yilmaz",
            EntityType::Org => "Kahve Dunyasi Anonim Sirketi",
            EntityType::Loc => "Kadikoy",
            EntityType::Address => "Bagdat Caddesi 12, Istanbul",
        }
    }

    #[test]
    fn labels_count_up_per_type_and_never_repeat() {
        let mut book = minter(1);
        let first = book.mint(EntityType::Person, "Ahmet Yilmaz").unwrap();
        let second = book.mint(EntityType::Person, "Ayse Demir").unwrap();
        let org = book.mint(EntityType::Org, "Kahve Dunyasi").unwrap();

        assert_eq!(first.alias, "PERSON_1");
        assert_eq!(second.alias, "PERSON_2");
        assert_eq!(org.alias, "ORG_1");
        assert_eq!(book.issued_count(), 3);
    }

    #[test]
    fn a_literal_the_user_wrote_is_taken_out_of_the_pool() {
        // The user's own prompt says PERSON_1. Nothing in this session may be
        // given that string, or the response path would substitute a real name
        // into the user's sentence.
        let mut book = minter(2);
        assert_eq!(book.reserve_literal("PERSON_1"), Reservation::Withheld);

        let first = book.mint(EntityType::Person, "Ahmet Yilmaz").unwrap();
        let second = book.mint(EntityType::Person, "Ayse Demir").unwrap();
        assert_eq!(first.alias, "PERSON_2");
        assert_eq!(second.alias, "PERSON_3");
        assert!(book.alias_for(&first.seed).is_some());

        // And nothing at all maps back to the withheld string, so a restore
        // cannot find a value for it.
        assert!(!book.taken.contains_key("PERSON_1"));
    }

    #[test]
    fn a_literal_this_session_already_issued_stays_the_alias_it_is() {
        // The user pastes the model's previous answer back. Withholding the
        // string there would break the round trip it is supposed to protect.
        let mut book = minter(3);
        let minted = book.mint(EntityType::Person, "Ahmet Yilmaz").unwrap();
        assert_eq!(
            book.reserve_literal(&minted.alias),
            Reservation::AlreadyIssued
        );
        assert!(book.withheld.is_empty());
        let again = book.mint(EntityType::Person, "Ahmet Yilmaz").unwrap();
        assert!(again.reused);
        assert_eq!(again.alias, minted.alias);
    }

    #[test]
    fn a_type_that_mints_nothing_says_so_rather_than_producing_something() {
        let mut book = minter(4);
        assert_eq!(
            book.mint(EntityType::Date, "2026-08-04"),
            Err(AliasError::NotMinted {
                entity: EntityType::Date
            })
        );
        assert_eq!(
            book.mint(EntityType::Url, "https://api.example.com/v1"),
            Err(AliasError::UrlMintsViaHost)
        );
        assert_eq!(
            book.mint(EntityType::Person, "   "),
            Err(AliasError::EmptyValue {
                entity: EntityType::Person
            })
        );
    }

    #[test]
    fn a_url_gives_up_its_host_and_keeps_its_length_to_itself() {
        let mut book = minter(5);
        let long = format!("https://api.example.com/{}?q=1", "segment/".repeat(200));
        let aliased = book.mint_url_host(&long).unwrap();

        assert_eq!(
            &long[aliased.host_start..aliased.host_end],
            "api.example.com"
        );
        assert_eq!(aliased.minted.entity_type, EntityType::Host);
        // The alias is a host alias and carries nothing of the URL's length.
        assert!(aliased.minted.alias.len() <= l_type_max(EntityType::Host));
        assert!(aliased.minted.alias.ends_with(".invalid"));

        assert_eq!(
            book.mint_url_host("https:///nothing"),
            Err(AliasError::HostNotFound)
        );
    }

    #[test]
    fn counters_report_the_weakest_rung_a_type_reached() {
        let mut book = minter(6);
        // Enough distinct cards to walk past the published list for this brand
        // and length, which is the KG-012 path.
        for index in 0..12u32 {
            let source = format!("4111111111{index:06}");
            book.mint(EntityType::CreditCard, &source).unwrap();
        }
        let stats = book.stats();
        let cards = stats.by_type.get(&EntityType::CreditCard).unwrap();
        assert_eq!(cards.count, 12);
        assert_eq!(cards.ladder_rung, LadderRung::Invalid);
        assert!(stats.alias_pool_exhausted > 0);
    }

    #[test]
    fn a_capped_secret_is_counted() {
        let mut book = minter(7);
        book.mint(EntityType::Secret, &"x".repeat(200)).unwrap();
        let stats = book.stats();
        assert_eq!(stats.alias_length_class_capped, 1);
        // Threat model R14: the report says O for this type whatever the
        // generator did.
        assert_eq!(
            stats.by_type.get(&EntityType::Secret).unwrap().ladder_rung,
            LadderRung::Opaque
        );
    }

    #[test]
    fn the_opaque_style_drops_every_type_to_the_bottom_rung() {
        let mut book = Minter::new(AliasKey::from_key_bytes([8; 32]), AliasStyle::Opaque);
        for entity in EntityType::ALL {
            if matches!(entity, EntityType::Date | EntityType::Url) {
                continue;
            }
            let minted = book.mint(entity, source_for(entity)).unwrap();
            assert!(minted.alias.starts_with("PSK_"), "{}", minted.alias);
            assert_eq!(minted.rung, LadderRung::Opaque);
            assert!(minted.alias.len() <= 32, "{}", minted.alias);
        }
    }

    #[test]
    fn two_values_never_share_an_alias() {
        let mut book = minter(9);
        let mut seen = BTreeSet::new();
        for index in 0..200u32 {
            let minted = book
                .mint(EntityType::Person, &format!("Person Number {index}"))
                .unwrap();
            assert!(seen.insert(minted.alias.clone()), "{}", minted.alias);
        }
        for index in 0..200u32 {
            let minted = book
                .mint(
                    EntityType::Ipv4,
                    &format!("10.0.{}.{}", index / 256, index % 256),
                )
                .unwrap();
            assert!(seen.insert(minted.alias.clone()), "{}", minted.alias);
        }
    }
}
