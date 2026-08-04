#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The P-0 gate: no alias may be a value that belongs to somebody.
//!
//! This file is F4's fifth exit criterion. It is not a unit test of a generator;
//! it is the place where the product's heaviest promise is checked as a whole,
//! and it is written to fail in the two ways a gate usually fails to fail.
//!
//! **A gate that finds nothing to run must not pass.** Every registered type is
//! counted against a table of cases here. A type added to
//! [`EntityType::ALL`](periskop_proxy::alias::EntityType::ALL) with no case in
//! `CASES` fails the coverage test by name; a case whose body stopped checking
//! anything fails the floor on checks performed. Neither can quietly become
//! zero, which is the shape CLAUDE.md's O6b was written about.
//!
//! **A gate that only checks one example is checking luck.** Every invariant
//! runs over a sweep of session keys, so a generator that leaves its documented
//! range for one seed in a hundred fails here rather than once a week in
//! production.
//!
//! # What is being kept out
//!
//! ADR-010 section 5's P-0: a generator may not produce a value that could be
//! **allocated** to a real person, company or account. The failure it prevents is
//! concrete and it is not the leak everybody thinks of. It is the reverse: a
//! masked prompt reaches the model with a valid IBAN in it that belongs to
//! somebody who was never part of this conversation, restoration fails, and the
//! user is shown a stranger's account number as if it were their own.
//!
//! # The four invariants (ADR-010 section 5.1)
//!
//! | Rung | What has to hold |
//! |---|---|
//! | `R` | the alias lies inside a range whose citation is in the rule file |
//! | `I` | the type's own validator rejects the alias, for every input |
//! | `O` | the alias starts with `PSK_` |
//! | `L` | the alias is `TAG_index` and nothing else |
//!
//! Plus two the report has to keep: `API_KEY` and `SECRET` report rung `O`
//! whatever they produced (threat model R14), and `alias_style = "opaque"` puts
//! every type on rung `O` (P-0 is the same in both styles).
//!
//! # And one invariant that is not about allocation
//!
//! An alias may not be a string a secret scanner will call a credential
//! ([`SCANNERS`]). This one arrived from the field: the key generator kept the
//! source's prefix and filled the rest from a base62 stream, which reproduced
//! the Stripe pattern exactly, and a push was refused because of it. The push is
//! the small half. A masked prompt is meant to be safe to keep, so it lands in
//! logs, tickets and repositories, and every scanner downstream of us would
//! raise a credential alert on a prompt that contains no credential. Preventing
//! a leak by manufacturing false alerts moves the cost onto a security team, and
//! alert fatigue is how a real leak gets missed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use periskop_proxy::alias::catalog;
use periskop_proxy::alias::checksum::{self, Verdict};
use periskop_proxy::alias::entity::{AliasStyle, EntityType, LadderRung, Minting};
use periskop_proxy::alias::limits::l_type_max;
use periskop_proxy::alias::mint::{Minted, Reservation};
use periskop_proxy::alias::{rung_i, rung_l};
use periskop_proxy::alias::{AliasError, AliasKey, Minter};

/// Session keys each case is exercised under.
///
/// One example proves nothing about a generator that draws from a seed: the
/// invariants have to hold for every value of it, so the sweep is part of the
/// gate rather than a nicety.
const SESSIONS: u8 = 24;

/// The fewest checks a single type's case may perform before the gate treats it
/// as gutted rather than passing.
const MIN_CHECKS_PER_TYPE: usize = SESSIONS as usize;

/// How a type is exercised.
enum Exercise {
    /// The ordinary path: this value is masked.
    Mints(&'static str),
    /// The type mints nothing at all, and the gate checks that it refuses.
    NeverMints(&'static str),
    /// Only the host component of this URL is aliased.
    ViaHost(&'static str),
}

/// One registered type's proof obligation.
struct Case {
    entity: EntityType,
    exercise: Exercise,
    /// What has to be true of this type's alias beyond its rung invariant.
    ///
    /// Returns the number of claims it checked, so that a body which stopped
    /// checking cannot pass as a body that checked and found nothing wrong.
    specific: fn(&str, &str) -> usize,
}

/// Every registered type, with the invariant test it may not be merged without.
///
/// The coverage test below is what makes this table binding: adding a variant to
/// `EntityType::ALL` without adding a line here fails the gate.
const CASES: &[Case] = &[
    Case {
        entity: EntityType::Iban,
        exercise: Exercise::Mints("TR33 0006 1005 1978 6457 8413 26"),
        specific: iban_claims,
    },
    Case {
        entity: EntityType::Tckn,
        exercise: Exercise::Mints("10000000146"),
        specific: tckn_claims,
    },
    Case {
        entity: EntityType::Vkn,
        exercise: Exercise::Mints("4980312208"),
        specific: vkn_claims,
    },
    Case {
        entity: EntityType::CreditCard,
        exercise: Exercise::Mints("4111 1111 1111 1111"),
        specific: card_claims,
    },
    Case {
        entity: EntityType::Email,
        exercise: Exercise::Mints("ahmet.yilmaz@example.com.tr"),
        specific: email_claims,
    },
    Case {
        entity: EntityType::Phone,
        exercise: Exercise::Mints("+90 532 123 45 67"),
        specific: phone_claims,
    },
    Case {
        entity: EntityType::Ipv4,
        exercise: Exercise::Mints("192.168.1.10"),
        specific: ipv4_claims,
    },
    Case {
        entity: EntityType::Ipv6,
        exercise: Exercise::Mints("2a00:1450:4001:80b::200e"),
        specific: ipv6_claims,
    },
    Case {
        entity: EntityType::ApiKey,
        exercise: Exercise::Mints("ghp_ABCDEFGH.IJKLMNOP.QRSTUVWX.YZ012345"),
        specific: key_claims,
    },
    Case {
        entity: EntityType::Secret,
        exercise: Exercise::Mints("sk_live_ABCDEFGH.IJKLMNOP"),
        specific: key_claims,
    },
    Case {
        entity: EntityType::Url,
        exercise: Exercise::ViaHost("https://api.internal.corp/v1/users?id=7&token=abc"),
        specific: host_claims,
    },
    Case {
        entity: EntityType::Host,
        exercise: Exercise::Mints("api.internal.corp"),
        specific: host_claims,
    },
    Case {
        entity: EntityType::Date,
        exercise: Exercise::NeverMints("2026-08-04"),
        specific: no_claims,
    },
    Case {
        entity: EntityType::Person,
        exercise: Exercise::Mints("Ahmet Yilmaz"),
        specific: label_claims,
    },
    Case {
        entity: EntityType::Org,
        exercise: Exercise::Mints("Kahve Dunyasi Anonim Sirketi"),
        specific: label_claims,
    },
    Case {
        entity: EntityType::Loc,
        exercise: Exercise::Mints("Kadikoy"),
        specific: label_claims,
    },
    Case {
        entity: EntityType::Address,
        exercise: Exercise::Mints("Bagdat Caddesi 12, Istanbul"),
        specific: label_claims,
    },
];

// ---------------------------------------------------------------------------
// What a secret scanner looks for
// ---------------------------------------------------------------------------

/// One published family of credential, in the two parts every scanner rule for
/// one has.
///
/// A scanner rule is a literal marker followed by a run of body characters, and
/// it fires when the run is long enough. Written as a table rather than as
/// regular expressions so this crate takes no dependency for a test, and so the
/// number that matters, `min_body`, is visible per family instead of buried in a
/// quantifier.
struct Scanner {
    /// The provider, for the failure message.
    family: &'static str,
    /// The literal a scanner anchors on.
    marker: &'static str,
    /// The shortest body its rule accepts. Deliberately at or below what the
    /// published rules use, because a gate that is looser than the tools it
    /// models is a gate that passes and then fails in somebody's CI.
    min_body: usize,
    /// Whether a character can be part of this family's body.
    body: fn(char) -> bool,
}

fn alphanumeric(character: char) -> bool {
    character.is_ascii_alphanumeric()
}

/// Alphanumeric plus the two separators several families allow inside a body.
fn alphanumeric_or_symbol(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_' || character == '-'
}

/// The families the gate holds every alias against.
///
/// Not a complete census of every credential in the world and it does not have
/// to be: `no_key_alias_offers_a_run_long_enough_for_any_scanner` states the
/// structural property that covers the families nobody has written down here,
/// and this table is what pins the named ones so a regression names itself.
const SCANNERS: &[Scanner] = &[
    // Stripe. `gitleaks` reads the body as ten or more, which is the shortest
    // body of any rule in this table and therefore the number the generator's
    // group size had to clear.
    Scanner {
        family: "stripe-live",
        marker: "sk_live_",
        min_body: 10,
        body: alphanumeric,
    },
    Scanner {
        family: "stripe-test",
        marker: "sk_test_",
        min_body: 10,
        body: alphanumeric,
    },
    // GitHub's personal access token is exactly thirty six body characters; the
    // gate takes thirty so a shorter variant is caught too.
    Scanner {
        family: "github-pat-classic",
        marker: "ghp_",
        min_body: 30,
        body: alphanumeric,
    },
    // The fine grained token is eighty two; twenty two is far under it and
    // still far over anything this generator can produce.
    Scanner {
        family: "github-pat-fine-grained",
        marker: "github_pat_",
        min_body: 22,
        body: alphanumeric_or_symbol,
    },
    // AWS access key id: the marker plus sixteen upper case or digit.
    Scanner {
        family: "aws-access-key-id",
        marker: "AKIA",
        min_body: 16,
        body: alphanumeric,
    },
    // Slack bot token.
    Scanner {
        family: "slack-bot-token",
        marker: "xoxb-",
        min_body: 10,
        body: alphanumeric_or_symbol,
    },
    // Google API key: the marker plus thirty five.
    Scanner {
        family: "google-api-key",
        marker: "AIza",
        min_body: 30,
        body: alphanumeric_or_symbol,
    },
];

/// The family a scanner would report for this string, if any.
///
/// Every occurrence of the marker is tried, not only the first: a marker that
/// appears in the middle of a body is exactly as loud as one at the start.
fn scanner_verdict(text: &str) -> Option<&'static str> {
    for scanner in SCANNERS {
        let mut from = 0;
        while let Some(found) = text.get(from..).and_then(|rest| rest.find(scanner.marker)) {
            let at = from + found + scanner.marker.len();
            let run = text
                .get(at..)
                .unwrap_or_default()
                .chars()
                .take_while(|character| (scanner.body)(*character))
                .count();
            if run >= scanner.min_body {
                return Some(scanner.family);
            }
            from = at;
        }
    }
    None
}

/// The claim, phrased so that both a source and an alias can be held to it.
fn assert_no_scanner_match(text: &str, what: &str) {
    assert_eq!(
        scanner_verdict(text),
        None,
        "{what} would be reported as a credential: {text}"
    );
}

/// The longest run of alphanumeric characters, which is the quantity every
/// scanner rule counts.
fn longest_alphanumeric_run(text: &str) -> usize {
    let mut longest = 0;
    let mut current = 0;
    for character in text.chars() {
        if character.is_ascii_alphanumeric() {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

#[test]
fn every_registered_type_has_an_invariant_test() {
    // The counting half of the gate. A type with no case is a type with no P-0
    // proof obligation, and it fails here by name rather than by absence.
    let covered: BTreeSet<EntityType> = CASES.iter().map(|case| case.entity).collect();
    let registered: BTreeSet<EntityType> = EntityType::ALL.into_iter().collect();

    let missing: Vec<EntityType> = registered.difference(&covered).copied().collect();
    assert!(
        missing.is_empty(),
        "these registered types have no invariant test: {missing:?}"
    );

    // A duplicate would let one type's case stand in for another's count.
    assert_eq!(
        covered.len(),
        CASES.len(),
        "a type appears twice in the case table"
    );
    // And an empty table is not a passing gate. Both sides are counted from the
    // values rather than from the constants, so a table that emptied itself
    // fails here instead of passing with nothing to do (CLAUDE.md O6b).
    assert_eq!(covered.len(), EntityType::ALL.len());
    assert!(!covered.is_empty());
    assert!(!registered.is_empty());
}

#[test]
fn every_generator_keeps_the_invariant_of_the_rung_it_produced_on() {
    let mut checks_by_type: BTreeMap<EntityType, usize> = BTreeMap::new();

    for case in CASES {
        let mut checks = 0;
        for session in 0..SESSIONS {
            checks += exercise(case, session);
        }
        checks_by_type.insert(case.entity, checks);
    }

    // Every case did work, and the work is visible. A case whose body was
    // emptied reports zero and fails here rather than passing quietly.
    for case in CASES {
        let checks = checks_by_type.get(&case.entity).copied().unwrap_or(0);
        assert!(
            checks >= MIN_CHECKS_PER_TYPE,
            "{} performed only {checks} checks",
            case.entity
        );
    }
    let total: usize = checks_by_type.values().sum();
    assert!(total >= CASES.len() * MIN_CHECKS_PER_TYPE, "{total} checks");
    println!(
        "p0 gate: {total} invariant checks over {} types",
        CASES.len()
    );
}

/// Runs one case under one session key and returns the number of claims checked.
fn exercise(case: &Case, session: u8) -> usize {
    let mut book = Minter::new(
        AliasKey::from_key_bytes([session; 32]),
        AliasStyle::TypePreserving,
    );

    match case.exercise {
        Exercise::NeverMints(source) => {
            // The type mints nothing, and the refusal is the invariant. Anything
            // else would mean a value nobody decided to produce.
            let refused = book.mint(case.entity, source);
            assert_eq!(
                refused,
                Err(AliasError::NotMinted {
                    entity: case.entity
                }),
                "{} produced an alias",
                case.entity
            );
            1
        }
        Exercise::ViaHost(url) => {
            // A URL is never aliased whole (ADR-010 section 2).
            assert_eq!(
                book.mint(case.entity, url),
                Err(AliasError::UrlMintsViaHost),
                "{} was aliased as a whole",
                case.entity
            );
            let aliased = book.mint_url_host(url).unwrap();
            let host = &url[aliased.host_start..aliased.host_end];
            let mut checks = 1 + rung_invariant(&aliased.minted, host);
            checks += (case.specific)(&aliased.minted.alias, host);

            // The reason whole URL aliasing was removed: the alias may not carry
            // the source URL's length into the streaming buffer.
            let longer = format!("{url}{}", "/segment".repeat(100));
            let from_longer = book.mint_url_host(&longer).unwrap();
            assert!(from_longer.minted.alias.len() <= l_type_max(EntityType::Host));
            checks + 1
        }
        Exercise::Mints(source) => {
            let minted = book.mint(case.entity, source).unwrap();
            let checks = rung_invariant(&minted, source);
            checks + (case.specific)(&minted.alias, source)
        }
    }
}

/// The invariant ADR-010 section 5.1 attaches to the rung this alias came from,
/// plus the two claims every alias has to keep.
fn rung_invariant(minted: &Minted, source: &str) -> usize {
    let entity = minted.entity_type;
    let alias = minted.alias.as_str();

    match minted.rung {
        LadderRung::Reserved => assert!(
            catalog::is_in_documented_range(entity, alias),
            "{entity} produced {alias} on rung R, outside every documented range"
        ),
        LadderRung::Invalid => {
            if entity.evidence_is_entropic() {
                // Threat model R14: no publication and no total validator exist
                // for these, so the invariant is the counting argument, checked
                // in `key_claims`, and the report is downgraded to O below.
                assert_eq!(
                    checksum::verdict(entity, alias),
                    Verdict::NoDocumentedCheck,
                    "{entity} claims a validator it does not have"
                );
            } else {
                assert_eq!(
                    checksum::verdict(entity, alias),
                    Verdict::Invalid,
                    "{entity} produced {alias} on rung I and its own validator accepts it"
                );
            }
        }
        LadderRung::Opaque => assert!(
            alias.starts_with("PSK_"),
            "{entity} produced {alias} on rung O"
        ),
        LadderRung::Label => assert!(
            rung_l::is_counted_label(alias),
            "{entity} produced {alias} on rung L"
        ),
    }

    // The alias may not be the value. Nothing else in this file would catch a
    // generator that simply passed its input through.
    assert_ne!(alias, source, "{entity} handed back its own input");
    // And it may not be a string a scanner will call a credential. Checked for
    // every type rather than for the two key types, because an alias of any
    // shape can grow into a scanner match: it takes a marker and a long enough
    // run, and neither is the private property of `API_KEY`.
    assert_no_scanner_match(alias, &format!("{entity}'s alias"));
    // The ceiling the streaming hold is built on.
    assert!(
        alias.len() <= l_type_max(entity),
        "{entity} produced {} bytes over its {} ceiling",
        alias.len(),
        l_type_max(entity)
    );
    // The rung may fall below the one the type entered at, never above it.
    let entered = entity
        .entry_rung()
        .expect("a minting type has an entry rung");
    assert!(
        rung_rank(minted.rung) >= rung_rank(entered),
        "{entity} claims stronger evidence than it entered with"
    );
    5
}

/// How strong a rung's evidence is: lower is stronger.
fn rung_rank(rung: LadderRung) -> u8 {
    match rung {
        LadderRung::Label | LadderRung::Reserved => 0,
        LadderRung::Invalid => 1,
        LadderRung::Opaque => 2,
    }
}

#[test]
fn the_opaque_style_puts_every_type_on_the_bottom_rung() {
    // P-0 does not depend on the style, and neither does this: the opaque style
    // is the second supported way (ADR-010 section 5.2), not a debug mode.
    let mut checks = 0;
    for case in CASES {
        let mut book = Minter::new(AliasKey::from_key_bytes([0x5C; 32]), AliasStyle::Opaque);
        let (alias, rung) = match case.exercise {
            Exercise::NeverMints(source) => {
                assert!(book.mint(case.entity, source).is_err());
                checks += 1;
                continue;
            }
            Exercise::ViaHost(url) => {
                let aliased = book.mint_url_host(url).unwrap();
                (aliased.minted.alias, aliased.minted.rung)
            }
            Exercise::Mints(source) => {
                let minted = book.mint(case.entity, source).unwrap();
                (minted.alias, minted.rung)
            }
        };
        assert_eq!(
            rung,
            LadderRung::Opaque,
            "{} stayed off rung O",
            case.entity
        );
        assert!(alias.starts_with("PSK_"), "{alias}");
        // The opaque ceiling, which is what the streaming buffer is sized to in
        // this style.
        assert!(alias.len() <= 32, "{alias} is over the opaque ceiling");
        checks += 3;
    }
    assert!(checks >= CASES.len(), "{checks} checks");
}

#[test]
fn the_key_types_report_opaque_and_claim_nothing_stronger() {
    // Threat model R14. The evidence for these two is entropic rather than
    // documentary, and a run that reported `I` for them would be reporting a
    // proof nobody has.
    let mut book = Minter::new(
        AliasKey::from_key_bytes([0x6D; 32]),
        AliasStyle::TypePreserving,
    );
    book.mint(
        EntityType::ApiKey,
        "ghp_ABCDEFGH.IJKLMNOP.QRSTUVWX.YZ012345",
    )
    .unwrap();
    book.mint(EntityType::Secret, "sk_live_ABCDEFGH.IJKLMNOP")
        .unwrap();
    book.mint(EntityType::Iban, "TR330006100519786457841326")
        .unwrap();

    let stats = book.stats();
    for entity in [EntityType::ApiKey, EntityType::Secret] {
        let stat = stats
            .by_type
            .get(&entity)
            .expect("a masked type is counted");
        assert_eq!(
            stat.ladder_rung,
            LadderRung::Opaque,
            "{entity} claimed {} in the report",
            stat.ladder_rung
        );
    }
    // And the downgrade is theirs alone: a type with a real proof still reports
    // it, or the measurement would say nothing at all.
    assert_eq!(
        stats
            .by_type
            .get(&EntityType::Iban)
            .expect("a masked type is counted")
            .ladder_rung,
        LadderRung::Invalid
    );

    // The two marked types are exactly the two the registry marks.
    let marked: Vec<EntityType> = EntityType::ALL
        .into_iter()
        .filter(|entity| entity.evidence_is_entropic())
        .collect();
    assert_eq!(marked, vec![EntityType::ApiKey, EntityType::Secret]);
}

/// The key sources the scanner sweep runs.
///
/// One per family in [`SCANNERS`], so that the carried prefix path is exercised
/// with every marker a scanner anchors on, plus two shapes that belong to no
/// family. None of them is a scanner match itself, and the test below is what
/// keeps that true.
const KEY_SOURCES: &[&str] = &[
    "sk_live_01234567.0123456",
    "sk_test_01234567.01234567.01234567",
    "ghp_01234567.01234567.01234567.0123",
    "github_pat_01234567.01234567.01234567",
    "AKIA0123.45678901",
    "xoxb-0123.45678901.23456789",
    "AIza0123.45678901.23456789.01234567",
    "x",
    "01234567.01234567.01234567.01234567.01234567.01234567.01234567.01234567.0123",
];

/// Every key alias one sweep of the session keys produces.
fn key_aliases() -> Vec<String> {
    let mut produced = Vec::new();
    for session in 0..SESSIONS {
        let mut book = Minter::new(
            AliasKey::from_key_bytes([session; 32]),
            AliasStyle::TypePreserving,
        );
        for entity in [EntityType::ApiKey, EntityType::Secret] {
            for source in KEY_SOURCES {
                produced.push(book.mint(entity, source).unwrap().alias);
            }
        }
    }
    produced
}

#[test]
fn no_alias_is_a_string_a_secret_scanner_would_report() {
    // A family in the table with no source to exercise it is a row that proves
    // nothing, so the coverage half comes first and fails by name.
    for scanner in SCANNERS {
        assert!(
            KEY_SOURCES
                .iter()
                .any(|source| source.starts_with(scanner.marker)),
            "{} is in the table with no source that carries its marker",
            scanner.family
        );
    }

    // The fixtures are held to the same claim as the aliases. A test input that
    // is itself a match turns every clone of this repository into a credential
    // alert, and nothing here needs one: the key generator reads the total
    // length and the first underscore and nothing else.
    for source in KEY_SOURCES {
        assert_no_scanner_match(source, "a sweep source");
    }
    for case in CASES {
        let (Exercise::Mints(source) | Exercise::NeverMints(source) | Exercise::ViaHost(source)) =
            case.exercise;
        assert_no_scanner_match(source, "a case source");
    }

    let aliases = key_aliases();
    for alias in &aliases {
        assert_no_scanner_match(alias, "a key alias");
    }
    assert_eq!(aliases.len(), SESSIONS as usize * 2 * KEY_SOURCES.len());
    assert!(!aliases.is_empty());
}

#[test]
fn no_key_alias_offers_a_run_long_enough_for_any_scanner() {
    // The half that survives a family nobody has written into `SCANNERS` yet. A
    // scanner rule is a marker and then a run of body characters; the generator
    // interrupts every run at `KEY_GROUP`, so any rule whose body is longer than
    // that cannot be finished, whether or not this file has heard of it.
    let shortest = SCANNERS
        .iter()
        .map(|scanner| scanner.min_body)
        .min()
        .expect("the scanner table is not empty");
    assert!(
        rung_i::KEY_GROUP < shortest,
        "a run of {} characters finishes the shortest body in the table, {shortest}",
        rung_i::KEY_GROUP
    );

    let aliases = key_aliases();
    for alias in &aliases {
        let run = longest_alphanumeric_run(alias);
        assert!(
            run <= rung_i::KEY_GROUP,
            "{alias} offers a run of {run}, over the {} the generator promises",
            rung_i::KEY_GROUP
        );
    }
    assert_eq!(aliases.len(), SESSIONS as usize * 2 * KEY_SOURCES.len());
}

#[test]
fn every_card_produced_after_the_published_list_runs_out_still_fails_luhn() {
    // The gate used to exercise cards on their first attempt only, which is
    // always a published number, so the rung the pool falls to was never
    // reached here. A mutation that removed the Luhn breaking step left this
    // file green, and that is the whole reason this test exists: KG-012's
    // fallback is the path where a generator could hand out a working card.
    let mut book = Minter::new(
        AliasKey::from_key_bytes([0x4C; 32]),
        AliasStyle::TypePreserving,
    );
    let mut fallbacks = 0;
    for index in 0..(catalog::TEST_PANS.len() * 2) {
        let source = format!("4111 1111 1111 {index:04}");
        let minted = book.mint(EntityType::CreditCard, &source).unwrap();
        assert!(
            catalog::pan_is_documented(&minted.alias) || !checksum::luhn_is_valid(&minted.alias),
            "{} is Luhn valid and nobody published it",
            minted.alias
        );
        if minted.rung == LadderRung::Invalid {
            assert!(
                !checksum::luhn_is_valid(&minted.alias),
                "{} came off the fallback rung and still passes Luhn",
                minted.alias
            );
            assert!(!catalog::pan_is_documented(&minted.alias));
            fallbacks += 1;
        }
    }

    // The fallback was actually reached, or this test proved nothing.
    assert!(fallbacks > 0, "the published pool never ran out");
    let stats = book.stats();
    assert!(
        stats.alias_pool_exhausted >= fallbacks,
        "{fallbacks} cards fell to the lower rung and {} were reported",
        stats.alias_pool_exhausted
    );
    assert_eq!(
        stats
            .by_type
            .get(&EntityType::CreditCard)
            .expect("cards are counted")
            .ladder_rung,
        LadderRung::Invalid,
        "a run that fell to the fallback rung reported the stronger one"
    );
}

#[test]
fn an_alias_the_user_already_wrote_is_never_given_to_a_value() {
    // ADR-010 section 6's second link. A user who writes a string that this
    // session would otherwise produce has to have it withheld, or the response
    // path finds it, looks it up, and substitutes a real person's data into a
    // sentence the user wrote about something else.
    let mut checked = 0;
    for case in CASES {
        let Exercise::Mints(source) = case.exercise else {
            continue;
        };

        // What this session would hand out, learned from an identical session.
        let mut probe = Minter::new(
            AliasKey::from_key_bytes([0x71; 32]),
            AliasStyle::TypePreserving,
        );
        let would_be = probe.mint(case.entity, source).unwrap().alias;

        let mut book = Minter::new(
            AliasKey::from_key_bytes([0x71; 32]),
            AliasStyle::TypePreserving,
        );
        assert_eq!(
            book.reserve_literal(&would_be),
            Reservation::Withheld,
            "{} did not withhold a literal the user wrote",
            case.entity
        );
        let minted = book.mint(case.entity, source).unwrap();
        assert_ne!(
            minted.alias, would_be,
            "{} handed out a string the user had already written",
            case.entity
        );
        // And the withheld string is still free of meaning: nothing in this
        // session maps it back to a value.
        assert!(!book.is_free(&would_be));
        checked += 3;
    }
    assert!(checked >= 3 * 14, "only {checked} claims were checked");
}

#[test]
fn an_alias_is_not_masked_a_second_time_by_the_detection_rule() {
    // ADR-010 section 5.1's deliberate complementarity. Detection layer A does
    // not classify a value whose checksum fails (`proxy/spec.md` section 3.1),
    // and every rung I alias fails its checksum on purpose, so an alias that
    // comes back in the next turn of the conversation is not masked again into
    // an alias of an alias.
    //
    // The rule is expressed here as the predicate the detection layer will use,
    // because that layer is a later wave. When it lands it calls exactly these
    // validators, and this test is what keeps the two ends together.
    // A VKN this build considers valid, built rather than quoted: unlike the
    // IBAN and the TCKN below, no published vector is carried for this type
    // (see the reviewer's note on `checksum::vkn_is_valid`), so the valid side
    // of the comparison is constructed from the rule itself.
    let vkn_body = [4u8, 9, 8, 0, 3, 1, 2, 2, 0];
    let valid_vkn = format!(
        "{}{}",
        vkn_body.map(|digit| digit.to_string()).join(""),
        checksum::vkn_check_digit(&vkn_body)
    );
    let checksum_types = [
        (EntityType::Iban, "TR330006100519786457841326"),
        (EntityType::Tckn, "10000000146"),
        (EntityType::Vkn, valid_vkn.as_str()),
    ];
    for session in 0..SESSIONS {
        let mut book = Minter::new(
            AliasKey::from_key_bytes([session; 32]),
            AliasStyle::TypePreserving,
        );
        for (entity, source) in checksum_types {
            let minted = book.mint(entity, source).unwrap();
            assert_eq!(
                checksum::verdict(entity, &minted.alias),
                Verdict::Invalid,
                "a detector would classify {} as a {entity} and mask it again",
                minted.alias
            );
            // The source, by contrast, is exactly what a detector does classify.
            assert_eq!(checksum::verdict(entity, source), Verdict::Valid);
        }
    }
}

#[test]
fn a_second_session_cannot_be_joined_to_the_first_on_an_alias() {
    // The unlinkability half of ADR-007's derivation, at the gate level: a
    // provider holding two conversations may not learn that they are about the
    // same person by comparing strings.
    let seed_derived: Vec<&Case> = CASES
        .iter()
        .filter(|case| {
            matches!(case.exercise, Exercise::Mints(_))
                && !matches!(
                    case.entity.minting(),
                    Minting::EntersAt(LadderRung::Label) | Minting::NotMinted
                )
        })
        .collect();
    assert!(!seed_derived.is_empty());

    for case in seed_derived {
        let Exercise::Mints(source) = case.exercise else {
            continue;
        };
        let mut here = Minter::new(
            AliasKey::from_key_bytes([0x01; 32]),
            AliasStyle::TypePreserving,
        );
        let mut there = Minter::new(
            AliasKey::from_key_bytes([0x02; 32]),
            AliasStyle::TypePreserving,
        );
        assert_ne!(
            here.mint(case.entity, source).unwrap().alias,
            there.mint(case.entity, source).unwrap().alias,
            "{} produced one alias in two sessions",
            case.entity
        );
    }
}

// ---------------------------------------------------------------------------
// The path ADR-010 forbids by name
// ---------------------------------------------------------------------------

/// Functions whose name mentions Luhn, and why each is allowed to exist.
///
/// `luhn_is_valid` reads a number and answers. `luhn_breaking` moves the last
/// digit by one, which breaks the sum without computing what would satisfy it.
/// A third name is a review, not an edit.
const LUHN_FUNCTIONS_ALLOWED: &[&str] = &["luhn_is_valid", "luhn_breaking"];

#[test]
fn no_code_here_completes_a_card_number() {
    // ADR-010 forbids "take the 4111 prefix and compute a valid Luhn digit" by
    // name, because the result is a well formed number in a real issuer's range.
    // The behavioural half of this claim is in `card.rs`: every card produced
    // after the published pool runs out fails Luhn. This half is structural, so
    // that the path cannot be reintroduced and left untested.
    let sources = alias_sources();
    assert!(
        sources.len() >= 10,
        "only {} alias sources found, so this scan checked almost nothing",
        sources.len()
    );

    let mut offences = Vec::new();
    let mut scanned = 0;
    for source in &sources {
        let name = file_name(source);
        let text = production_part(source);
        scanned += 1;

        for (number, line) in text.lines().enumerate() {
            let at = number + 1;
            // A comment is not a code path. Both modules below discuss the
            // forbidden construction at length, which is the point of them, and
            // the same convention is what `vault_touches_no_files.rs` uses.
            if line.trim_start().starts_with("//") {
                continue;
            }
            // A function that computes a check digit for a card.
            if let Some(function) = function_name(line) {
                if function.contains("luhn") && !LUHN_FUNCTIONS_ALLOWED.contains(&function.as_str())
                {
                    offences.push(format!("{name}:{at} defines {function}"));
                }
                if function.contains("check_digit") && name == "card.rs" {
                    offences.push(format!("{name}:{at} defines {function}"));
                }
            }
            // The BIN the ADR names, anywhere outside the published list.
            if name != "catalog.rs" && line.contains("4111") {
                offences.push(format!("{name}:{at} names the 4111 prefix"));
            }
            // A card sized digit run outside the rule file is a number somebody
            // wrote down rather than one a publication carries.
            if name != "catalog.rs" {
                if let Some(run) = longest_digit_run(line) {
                    if run >= 12 {
                        offences.push(format!("{name}:{at} carries a {run} digit literal"));
                    }
                }
            }
        }
    }

    assert!(offences.is_empty(), "{offences:#?}");
    assert_eq!(scanned, sources.len());
}

#[test]
fn every_documented_range_the_generators_use_is_cited() {
    // Rung R's evidence is somebody else's publication, so the gate checks that
    // the publication is named. The rule file's own test walks every entry; this
    // one is the gate level statement that a range with no citation may not be
    // used at all.
    let mut checked = 0;
    for block in catalog::IPV4_DOCUMENTATION {
        assert!(block.citation.is_filled_in(), "{}", block.name);
        checked += 1;
    }
    for pan in catalog::TEST_PANS {
        assert!(pan.citation.is_filled_in(), "{}", pan.digits);
        checked += 1;
    }
    for plan in catalog::PHONE_PLANS {
        assert!(plan.length_citation.is_filled_in(), "{}", plan.country_code);
        checked += 1;
        if let Some(fiction) = plan.fiction {
            assert!(fiction.citation.is_filled_in(), "{}", plan.country_code);
            checked += 1;
        }
    }
    assert!(catalog::INVALID_TLD_CITATION.is_filled_in());
    assert!(catalog::IPV6_DOCUMENTATION_CITATION.is_filled_in());
    checked += 2;
    assert!(checked >= 20, "only {checked} citations were checked");
}

// ---------------------------------------------------------------------------
// Per type claims
// ---------------------------------------------------------------------------

fn iban_claims(alias: &str, source: &str) -> usize {
    let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(alias.len(), compact.len(), "{alias}");
    assert_eq!(alias.get(..2), compact.get(..2), "{alias}");
    let check: u8 = alias.get(2..4).unwrap().parse().unwrap();
    assert!((2..=98).contains(&check), "{alias}");
    assert!(!checksum::iban_is_valid(alias), "{alias}");
    4
}

fn tckn_claims(alias: &str, _source: &str) -> usize {
    assert_eq!(alias.len(), 11, "{alias}");
    assert!(alias.chars().all(|c| c.is_ascii_digit()), "{alias}");
    assert_ne!(alias.chars().next(), Some('0'), "{alias}");
    assert!(!checksum::tckn_is_valid(alias), "{alias}");
    4
}

fn vkn_claims(alias: &str, _source: &str) -> usize {
    assert_eq!(alias.len(), 10, "{alias}");
    assert!(alias.chars().all(|c| c.is_ascii_digit()), "{alias}");
    assert!(!checksum::vkn_is_valid(alias), "{alias}");
    3
}

fn card_claims(alias: &str, source: &str) -> usize {
    assert!(alias.chars().all(|c| c.is_ascii_digit()), "{alias}");
    let digits: usize = source.chars().filter(|c| c.is_ascii_digit()).count();
    assert_eq!(alias.len(), digits, "{alias}");
    // Either it is one of the published test numbers, or it fails Luhn. There is
    // no third possibility, and the third possibility is the one ADR-010 forbids:
    // a Luhn valid number that nobody published.
    assert!(
        catalog::pan_is_documented(alias) || !checksum::luhn_is_valid(alias),
        "{alias} is Luhn valid and is not on the published list"
    );
    3
}

fn email_claims(alias: &str, _source: &str) -> usize {
    assert!(alias.contains('@'), "{alias}");
    assert!(
        alias.ends_with(".invalid") || alias.starts_with("PSK_"),
        "{alias}"
    );
    2
}

fn phone_claims(alias: &str, source: &str) -> usize {
    // The range D-14 removed, in the two shapes it could come back in.
    assert!(!alias.contains("+90 555"), "{alias}");
    assert!(!alias.starts_with("+90555"), "{alias}");
    if source.starts_with("+90") {
        // Turkey publishes no fiction range, so the alias is a national number
        // one digit past the plan and behind a leading zero: two independent
        // published rules broken on purpose.
        assert!(alias.starts_with("+900"), "{alias}");
        assert_eq!(alias.trim_start_matches("+90").len(), 11, "{alias}");
    }
    3
}

fn ipv4_claims(alias: &str, _source: &str) -> usize {
    assert!(
        catalog::ipv4_is_documented(alias) || alias.starts_with("PSK_"),
        "{alias}"
    );
    1
}

fn ipv6_claims(alias: &str, _source: &str) -> usize {
    assert!(
        catalog::ipv6_is_documented(alias) || alias.starts_with("PSK_"),
        "{alias}"
    );
    1
}

fn key_claims(alias: &str, source: &str) -> usize {
    // The length class, which is what keeps a secret's own length out of the
    // alias and the streaming buffer bounded.
    assert!(
        [32usize, 64, 128].contains(&alias.len()),
        "{alias} is {} bytes",
        alias.len()
    );
    assert!(alias.len() <= 128, "{alias}");
    // The prefix survives so the model can still tell a GitHub token from a
    // Stripe key, and nothing else of the source does. This is the half of the
    // design the scanner fix was not allowed to break: dropping the prefix would
    // have made the alias unreportable and the routing decision downstream of it
    // wrong.
    if let Some((prefix, _)) = source.split_once('_') {
        if prefix.len() <= 7 {
            assert!(alias.starts_with(prefix), "{alias}");
        }
    }
    // The counting argument threat model R14 rests on: at least 22 characters
    // drawn from the stream, which is over 128 bits at roughly 5.95 bits each.
    // Counted as drawn characters rather than as bytes, because the group
    // separators are structure and a body that spent its length on them would
    // still measure the same in bytes.
    let head = alias.rfind('_').map_or(0, |at| at + 1);
    let drawn = alias
        .get(head..)
        .unwrap_or_default()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .count();
    assert!(drawn >= 22, "{alias} drew only {drawn} characters");
    assert!(!alias.contains("IJKLMNOP"), "{alias} carried the source");
    5
}

fn host_claims(alias: &str, source: &str) -> usize {
    assert!(
        alias.ends_with(".invalid") || alias.starts_with("PSK_"),
        "{alias}"
    );
    assert!(!alias.contains(source), "{alias}");
    2
}

fn label_claims(alias: &str, _source: &str) -> usize {
    assert!(rung_l::is_counted_label(alias), "{alias}");
    let (tag, index) = alias.split_once('_').unwrap();
    assert!(!tag.is_empty() && !index.is_empty(), "{alias}");
    assert!(index.parse::<u32>().unwrap() >= 1, "{alias}");
    3
}

fn no_claims(_alias: &str, _source: &str) -> usize {
    // DATE mints nothing, so there is no alias to make a claim about. The
    // invariant is the refusal itself, and `exercise` checks it.
    0
}

// ---------------------------------------------------------------------------
// Reading this crate's own source
// ---------------------------------------------------------------------------

/// Every module under `src/alias/`.
fn alias_sources() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/alias");
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(&root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            found.push(path);
        }
    }
    found.sort();
    found
}

/// A source file with its test module cut off.
///
/// The tests carry example IBANs, test card numbers and Turkish identity numbers
/// on purpose, and scanning them would make the screen below useless. What is
/// scanned is what ships.
fn production_part(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    text.split("#[cfg(test)]")
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned()
}

/// The name of the function a line defines, if it defines one.
fn function_name(line: &str) -> Option<String> {
    let code = line.trim_start();
    if code.starts_with("//") {
        return None;
    }
    let at = code.find("fn ")? + 3;
    let rest = code.get(at..)?;
    let end = rest
        .find(|character: char| !character.is_alphanumeric() && character != '_')
        .unwrap_or(rest.len());
    let name = rest.get(..end)?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

/// The longest run of consecutive digits on a line.
fn longest_digit_run(line: &str) -> Option<usize> {
    let mut longest = 0;
    let mut current = 0;
    for character in line.chars() {
        if character.is_ascii_digit() {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    (longest > 0).then_some(longest)
}
