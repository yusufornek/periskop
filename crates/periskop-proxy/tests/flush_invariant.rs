#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
//! **Task 91.** The flush invariant, checked at every byte of every alias.
//!
//! `proxy/spec.md` section 6.2 states it as one sentence:
//!
//! > The buffer may be released only when (i) the automaton is at its root, (ii)
//! > the stream ended, (iii) the hold timeout fired, (iv) the stream failed. **No
//! > character class, delimiter or syntactic hunch may trigger a flush.** While
//! > the automaton is off its root, no byte leaves the buffer other than under
//! > (ii) to (iv).
//!
//! # Why this file is mechanical rather than illustrative
//!
//! The rule it protects was removed because it was wrong, not because it was
//! untidy. F3 flushed the buffer whenever the held prefix ended in a space, a
//! newline or a `}` (D-14, D-10 finding 22), on the assumption that aliases
//! contain none of those. They do: `PHONE` aliases are written `+44 7700 900123`,
//! IBANs are written in groups, and a stream that split inside one of those spaces
//! put an un-masked fragment on the wire. A single example test would have passed
//! under F3 for every alias whose split happened to fall somewhere else, which is
//! why this file splits **every** alias at **every** byte and not at one.
//!
//! Coverage is `sum over types of (len(alias) - 1)` splits, and the count is
//! asserted so that a change which stops producing aliases, or produces one byte
//! aliases, fails here rather than passing with nothing to check.
//!
//! # A finding, written where it is load bearing
//!
//! **No generator in this build currently emits an alias containing whitespace.**
//! The phone generator renders `+{country}{area}{block}{tail}` with no separators
//! and the IBAN generator renders an unspaced string, so the exact shapes D-14
//! argues about (`+44 7700 900123`, a grouped IBAN, `15 Mart 2024` under a date
//! mode this phase does not implement) are not produced today. That is a reason to
//! widen this file, not to narrow it: the flush rule has to hold for the aliases
//! this component is **allowed** to produce, and section 4.4 allows those shapes.
//! So [`SPACED`] carries them as declared cases beside the minted ones, and both
//! sets go through the same matrix. A generator that starts emitting a space
//! tomorrow finds the invariant already locked.

use std::collections::BTreeMap;
use std::sync::Arc;

use periskop_proxy::alias::entity::{EntityType, Minting};
use periskop_proxy::alias::{AliasKey, AliasStyle, Minter};
use periskop_proxy::http::stream::automaton::Snapshot;
use periskop_proxy::http::stream::restore::Lookup;
use periskop_proxy::http::stream::{frame, Relay, Settings};
use periskop_proxy::policy::HoldTimeout;

const NOW: u64 = 1_700_000_000_000;

/// The fewest split points this file may exercise before it counts as gutted.
///
/// Fifteen minted types produce 242 boundaries today. A run that drops under this
/// floor has stopped covering the thing it exists for, and CLAUDE.md O6b is about
/// exactly that kind of quiet zero.
const MIN_SPLITS: usize = 200;

// ---------------------------------------------------------------------------
// A conversation's real aliases
// ---------------------------------------------------------------------------

/// One value per minted type, in the shape the request path would have found.
///
/// The two credential shaped ones are assembled at run time for the reason
/// `tests/no_credential_literals.rs` gives: a source file in this repository does
/// not carry a continuous credential-shaped literal, not even as test data.
fn values() -> Vec<(EntityType, String)> {
    let mut out: Vec<(EntityType, String)> = vec![
        (
            EntityType::Iban,
            "TR33 0006 1005 1978 6457 8413 26".to_owned(),
        ),
        (EntityType::Tckn, "10000000146".to_owned()),
        (EntityType::Vkn, "4980312208".to_owned()),
        (EntityType::CreditCard, "4111 1111 1111 1111".to_owned()),
        (EntityType::Email, "ahmet.yilmaz@example.com.tr".to_owned()),
        (EntityType::Phone, "+90 532 123 45 67".to_owned()),
        (EntityType::Ipv4, "192.168.1.10".to_owned()),
        (EntityType::Ipv6, "2a00:1450:4001:80b::200e".to_owned()),
        (EntityType::Host, "api.internal.corp".to_owned()),
        (EntityType::Person, "Ahmet Yilmaz".to_owned()),
        (EntityType::Org, "Kahve Dunyasi Anonim Sirketi".to_owned()),
        (EntityType::Loc, "Kadikoy".to_owned()),
        (
            EntityType::Address,
            "Bagdat Caddesi 12, Istanbul".to_owned(),
        ),
        (
            EntityType::ApiKey,
            format!("ghp_{}.{}", "ABCDEFGH", "IJKLMNOPQRSTUVWX"),
        ),
        (
            EntityType::Secret,
            format!("sk_{}_{}.{}", "live", "ABCDEFGH", "IJKLMNOP"),
        ),
    ];
    out.sort_by_key(|(entity, _)| entity.tag());
    out
}

/// The alias shapes `proxy/spec.md` section 4.4 permits that contain whitespace.
///
/// D-14 removed rule F3 because of exactly these. They are declared rather than
/// minted because no generator emits one today (see the module note), and the
/// buffer's guarantee is about what the format allows, not about what this
/// week's generator happens to produce.
const SPACED: &[(&str, &str)] = &[
    ("+44 7700 900123", "+90 532 123 45 67"),
    (
        "TR00 0000 0000 0000 0000 0000 00",
        "TR330006100519786457841326",
    ),
    ("4111 1111 1111 1111", "5555 4444 3333 2222"),
    ("15 Mart 2024", "3 Nisan 1998"),
];

/// The aliases one session would have minted for those values.
fn minted(style: AliasStyle) -> Vec<(EntityType, String, String)> {
    let mut minter = Minter::new(AliasKey::from_key_bytes([0x2b; 32]), style);
    let mut out = Vec::new();
    for (entity, value) in values() {
        assert!(
            matches!(entity.minting(), Minting::EntersAt(_)),
            "{entity} does not mint, so it cannot be in this table"
        );
        let alias = minter
            .mint(entity, &value)
            .unwrap_or_else(|refusal| panic!("{entity}: {refusal}"))
            .alias;
        assert!(
            alias.len() > 1,
            "{entity} produced a one byte alias: {alias}"
        );
        out.push((entity, alias, value));
    }
    out
}

// ---------------------------------------------------------------------------
// The harness: one stream, one split, one answer
// ---------------------------------------------------------------------------

struct Table {
    rows: BTreeMap<String, String>,
}

impl Lookup for Table {
    fn value_for(&mut self, alias: &str) -> Option<String> {
        self.rows.get(alias).cloned()
    }
}

fn snapshot_of(aliases: &[String]) -> Arc<Snapshot> {
    Arc::new(Snapshot::frozen(
        aliases.len() as u64,
        aliases.iter().cloned(),
    ))
}

fn settings(snapshot: &Arc<Snapshot>, mode: HoldTimeout) -> Settings {
    Settings {
        snapshot: Arc::clone(snapshot),
        style: AliasStyle::TypePreserving,
        declared_l_max_session: None,
        // Long enough that no test here trips F2 by accident: this file is about
        // the rule, and F2 is the one release the rule does not cover.
        hold_timeout_ms: 3_600_000,
        on_hold_timeout: mode,
    }
}

fn chunk(text: &str) -> Vec<u8> {
    let document = serde_json::json!({
        "choices": [{"index": 0, "delta": {"content": text}}]
    });
    format!("data: {document}\n\n").into_bytes()
}

/// Every delta text a relay wrote, concatenated in the order it wrote it.
fn delivered(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes).into_owned();
    let mut out = String::new();
    for line in text.lines() {
        let Some(payload) = line.strip_prefix("data: ") else {
            continue;
        };
        if payload.trim() == "[DONE]" {
            continue;
        }
        let Ok(document) = serde_json::from_str::<serde_json::Value>(payload) else {
            panic!("the relay wrote a data line that is not JSON: {payload}");
        };
        for (_, piece) in frame::text_slots(&document) {
            out.push_str(&piece);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// Every alias, split at every one of its byte boundaries.
#[test]
fn no_split_of_any_alias_puts_an_unmasked_fragment_on_the_wire() {
    let minted = minted(AliasStyle::TypePreserving);
    let mut table: Vec<(String, String, String)> = minted
        .iter()
        .map(|(entity, alias, value)| (entity.tag().to_owned(), alias.clone(), value.clone()))
        .collect();
    table.extend(SPACED.iter().map(|(alias, value)| {
        (
            format!("SPACED[{alias}]"),
            (*alias).to_owned(),
            (*value).to_owned(),
        )
    }));

    let aliases: Vec<String> = table.iter().map(|(_, alias, _)| alias.clone()).collect();
    let snapshot = snapshot_of(&aliases);
    let rows: BTreeMap<String, String> = table
        .iter()
        .map(|(_, alias, value)| (alias.clone(), value.clone()))
        .collect();

    let mut splits = 0usize;
    let mut with_whitespace: Vec<&str> = Vec::new();

    for (entity, alias, value) in &table {
        if alias.contains(char::is_whitespace) {
            with_whitespace.push(entity.as_str());
        }
        for split in 1..alias.len() {
            if !alias.is_char_boundary(split) {
                continue;
            }
            splits += 1;
            let (head, tail) = alias.split_at(split);

            let mut relay = Relay::new(&settings(&snapshot, HoldTimeout::Flush));
            let mut lookup = Table { rows: rows.clone() };

            // The first frame ends inside the alias. Nothing of it may leave.
            let first = relay.push(&chunk(&format!("Fatura {head}")), &mut lookup, NOW);
            let seen = delivered(&first);
            assert_eq!(
                seen, "Fatura ",
                "{entity} split at {split}: the buffer released part of an alias"
            );

            let mut rest = relay.push(&chunk(&format!("{tail} adina.")), &mut lookup, NOW);
            rest.extend(relay.push(b"data: [DONE]\n\n", &mut lookup, NOW));
            rest.extend(relay.finish(&mut lookup, NOW));

            let whole = format!("{seen}{}", delivered(&rest));
            assert_eq!(
                whole,
                format!("Fatura {value} adina."),
                "{entity} split at {split}"
            );
            assert!(
                !whole.contains(alias.as_str()),
                "{entity} split at {split}: the alias itself reached the client"
            );

            let measured = relay.measured();
            assert_eq!(
                measured.stream.partial_alias_flushed, 0,
                "{entity} split at {split}"
            );
            assert_eq!(
                measured.restore.aliases_restored, 1,
                "{entity} split at {split}"
            );
            assert_eq!(
                measured.restore.aliases_leaked, 0,
                "{entity} split at {split}"
            );
            assert!(!measured.truncated, "{entity} split at {split}");
        }
    }

    assert!(
        splits >= MIN_SPLITS,
        "only {splits} split points were exercised; this gate covers less than it says"
    );
    // Every type that mints has a row, so a type added to the registry cannot
    // slip past this file by simply not being listed.
    let covered: Vec<&str> = table.iter().map(|(entity, _, _)| entity.as_str()).collect();
    for entity in EntityType::ALL {
        if matches!(entity.minting(), Minting::EntersAt(_)) {
            assert!(
                covered.contains(&entity.tag()),
                "{entity} mints an alias and has no row here, so no split of it is checked"
            );
        }
    }
    // The D-14 case has to be in the set, or this file is testing the easy half.
    assert_eq!(
        with_whitespace.len(),
        SPACED.len(),
        "the whitespace bearing shapes are not all covered: {with_whitespace:?}"
    );
}

/// The regression lock: no character may release a held byte.
///
/// Driven from a hand built alias set rather than from the minter, because the
/// claim is about the **buffer** and not about which characters today's
/// generators happen to emit. A generator that stops producing spaces tomorrow
/// must not quietly retire this check.
#[test]
fn no_character_class_delimiter_or_hunch_releases_a_held_byte() {
    const SHAPES: &[&str] = &[
        "PSK_A_1 with a space",
        "PSK_B_1\nwith a newline",
        "PSK_C_1}with a brace",
        "PSK_D_1,with a comma",
        "PSK_E_1\"with a quote",
        "PSK_F_1\twith a tab",
        "PSK_G_1.with a stop",
        "PSK_H_1;with a semicolon",
        "PSK_I_1: with a colon",
        "PSK_J_1] with a bracket",
    ];

    let aliases: Vec<String> = SHAPES.iter().map(|shape| (*shape).to_owned()).collect();
    let snapshot = snapshot_of(&aliases);
    let rows: BTreeMap<String, String> = aliases
        .iter()
        .enumerate()
        .map(|(at, alias)| (alias.clone(), format!("<value {at}>")))
        .collect();

    let mut checked = 0usize;
    for alias in &aliases {
        for split in 1..alias.len() {
            if !alias.is_char_boundary(split) {
                continue;
            }
            checked += 1;
            let (head, tail) = alias.split_at(split);
            let mut relay = Relay::new(&settings(&snapshot, HoldTimeout::Flush));
            let mut lookup = Table { rows: rows.clone() };

            let first = relay.push(&chunk(&format!("x {head}")), &mut lookup, NOW);
            assert_eq!(
                delivered(&first),
                "x ",
                "a held byte was released after {:?}",
                head.chars().last()
            );

            let mut rest = relay.push(&chunk(tail), &mut lookup, NOW);
            rest.extend(relay.finish(&mut lookup, NOW));
            let whole = format!("x {}", rows.get(alias).expect("a row"));
            assert_eq!(
                format!("{}{}", delivered(&first), delivered(&rest)),
                whole,
                "alias {alias:?} split at {split}"
            );
        }
    }
    assert!(
        checked > 100,
        "only {checked} character splits were checked"
    );
}

/// While the automaton is off its root, the only releases are F1, F2 and F4.
///
/// Under `on_hold_timeout = "wait"` and a timeout that never fires, F2 is out of
/// reach, so a held prefix may only leave at the end of the stream. Anything else
/// leaving is the invariant broken.
#[test]
fn off_the_root_nothing_leaves_until_f1() {
    let table = minted(AliasStyle::TypePreserving);
    let aliases: Vec<String> = table.iter().map(|(_, alias, _)| alias.clone()).collect();
    let snapshot = snapshot_of(&aliases);

    for (entity, alias, _) in &table {
        for split in 1..alias.len() {
            if !alias.is_char_boundary(split) {
                continue;
            }
            let head = &alias[..split];
            let mut relay = Relay::new(&settings(&snapshot, HoldTimeout::Wait));
            let mut lookup = Table {
                rows: BTreeMap::new(),
            };

            let mut out = relay.push(&chunk(head), &mut lookup, NOW);
            // Nothing arrives for a very long time. `wait` holds anyway.
            out.extend(relay.push(b": keep-alive\n\n", &mut lookup, NOW + 86_400_000));
            assert_eq!(
                delivered(&out),
                "",
                "{entity}: a held prefix left the buffer with no rule to release it"
            );
            assert!(
                relay.measured().truncated,
                "{entity}: the buffer says it is empty while holding a prefix"
            );

            // F1, and only now.
            let end = relay.finish(&mut lookup, NOW + 86_400_001);
            assert_eq!(delivered(&end), head, "{entity} split at {split}");
            assert_eq!(relay.measured().stream.partial_alias_flushed, 0);
        }
    }
}

/// The buffer stays inside `W + 1` however the stream is cut.
#[test]
fn the_hold_never_grows_past_the_window() {
    let table = minted(AliasStyle::TypePreserving);
    let aliases: Vec<String> = table.iter().map(|(_, alias, _)| alias.clone()).collect();
    let longest = aliases.iter().map(String::len).max().expect("aliases");
    let snapshot = snapshot_of(&aliases);

    let mut relay = Relay::new(&settings(&snapshot, HoldTimeout::Wait));
    let mut lookup = Table {
        rows: BTreeMap::new(),
    };
    // A stream that is nothing but the beginnings of aliases, one byte at a time.
    for alias in &aliases {
        for at in 1..alias.len() {
            if !alias.is_char_boundary(at) || !alias.is_char_boundary(at - 1) {
                continue;
            }
            relay.push(&chunk(&alias[at - 1..at]), &mut lookup, NOW);
        }
    }
    relay.finish(&mut lookup, NOW);

    let measured = relay.measured();
    let ceiling = longest.max(24);
    assert!(
        measured.stream.max_buffer_bytes as usize <= ceiling,
        "the buffer reached {} bytes against a ceiling of {ceiling}",
        measured.stream.max_buffer_bytes
    );
    assert_eq!(measured.stream.l_max_session as usize, ceiling);
    assert_eq!(measured.stream.l_max_static, 128);
}
