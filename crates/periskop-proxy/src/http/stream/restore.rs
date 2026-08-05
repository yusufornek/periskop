//! Alias to value, by looking it up (`proxy/spec.md` section 6.2, task 93).
//!
//! # A lookup, never a computation
//!
//! Alias derivation is one way by construction (ADR-010): an alias is an HMAC of
//! the value under a session key, so there is nothing to invert. The only route
//! back is the vault's table, and that is what this module walks. A "reverse
//! calculation" would not be a shortcut, it would be a different, wrong answer.
//!
//! # The three answers, and the one that is never given
//!
//! [`Lookup::value_for`] answers with the value, or with nothing. It cannot answer
//! with something plausible, and that absence is the point (`threat-model.md` R5):
//! a session whose time to live has run out, a process that restarted, a model
//! that garbled an alias it was given. In every one of those the alias is
//! forwarded **exactly as the model wrote it** and the run reports
//! `masking_unresolved` through [`RestoreStats::aliases_leaked`]. Inventing a
//! value would show one user another user's data, which is the one failure
//! `roadmap.md`'s fourth exit criterion is written to prevent.
//!
//! # Why a string the user wrote is never rewritten
//!
//! The automaton is built from the aliases the session actually **issued**
//! (ADR-010 section 6). A `PSK_PERSON_1` the user typed themselves was withheld by
//! the minter on the request path, so it is not in the snapshot, so it is not
//! matched here, so it goes back as they wrote it. This module adds a second lock
//! on the same invariant: [`SessionLookup`] refuses to ask the vault about any
//! string the snapshot does not hold, so a widened match can never turn into a
//! wrong value.

use serde_json::Value;

use crate::policy::HoldTimeout;
use crate::vault::{Restored, SessionId, Vault};

use super::automaton::Snapshot;
use super::buffer::{Buffer, Piece, Window};
use super::flush::Trigger;

/// `restore_stats` (`proxy-events.md`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RestoreStats {
    /// Occurrences of this conversation's aliases in the answer.
    pub aliases_seen_in_response: u32,
    pub aliases_restored: u32,
    /// Seen and not restored. Greater than zero is a WARN and is the counter
    /// `masking_unresolved` is reported through.
    pub aliases_leaked: u32,
}

impl RestoreStats {
    fn saw(&mut self, restored: bool) {
        self.aliases_seen_in_response = self.aliases_seen_in_response.saturating_add(1);
        if restored {
            self.aliases_restored = self.aliases_restored.saturating_add(1);
        } else {
            self.aliases_leaked = self.aliases_leaked.saturating_add(1);
        }
    }

    /// Whether this run has to raise a WARN.
    pub fn warns(self) -> bool {
        self.aliases_leaked > 0
    }

    pub fn merge(&mut self, other: Self) {
        self.aliases_seen_in_response = self
            .aliases_seen_in_response
            .saturating_add(other.aliases_seen_in_response);
        self.aliases_restored = self.aliases_restored.saturating_add(other.aliases_restored);
        self.aliases_leaked = self.aliases_leaked.saturating_add(other.aliases_leaked);
    }
}

/// Where a value comes back from.
pub trait Lookup {
    /// The value this alias stands for, or `None`.
    ///
    /// `None` covers every reason at once on purpose: from here they are the same
    /// instruction, which is to forward the alias untouched. Which reason it was
    /// is the vault's to report.
    fn value_for(&mut self, alias: &str) -> Option<String>;

    /// Whether a record could not be opened because it had been tampered with.
    ///
    /// Kept apart from a plain miss because `vault_record_tamper` is a security
    /// event and a miss is not.
    fn tampered(&self) -> u32 {
        0
    }
}

/// The vault, for one conversation, at one instant.
pub struct SessionLookup<'a> {
    vault: &'a mut Vault,
    snapshot: &'a Snapshot,
    session: SessionId,
    now_ms: u64,
    tampered: u32,
}

impl<'a> SessionLookup<'a> {
    pub fn new(
        vault: &'a mut Vault,
        snapshot: &'a Snapshot,
        session: SessionId,
        now_ms: u64,
    ) -> Self {
        Self {
            vault,
            snapshot,
            session,
            now_ms,
            tampered: 0,
        }
    }
}

impl Lookup for SessionLookup<'_> {
    fn value_for(&mut self, alias: &str) -> Option<String> {
        // The second lock. The automaton should never offer a string that is not
        // in the snapshot; if a future change to the matcher ever widens what it
        // offers, the widening stops here rather than at a vault row.
        if !self.snapshot.holds(alias) {
            return None;
        }
        match self.vault.restore(&self.session, alias, self.now_ms) {
            Ok(Restored::Value(value)) => {
                // Borrowed, not copied. The bytes are a decrypted value inside a
                // `Zeroizing` buffer that clears itself on drop, and a `to_vec`
                // here would put a second, plain copy of them on the heap for the
                // conversion to read and leave behind. `str::from_utf8` looks at
                // the borrowed bytes and only the reading that succeeds allocates.
                match std::str::from_utf8(value.expose()) {
                    Ok(text) => Some(text.to_owned()),
                    // Not a miss. Everything the request path files is a JSON
                    // string's bytes (`request_path.rs`, `original.as_bytes()`),
                    // so a record that opens into something that is not UTF-8 did
                    // not come out the way it went in. Answering `None` alone put
                    // it in the same bucket as an expired session: the alias went
                    // back raw and `masking_unresolved` counted it, so "I cannot
                    // read this record" was reported as "this conversation never
                    // had one". It is counted where a record that disagrees with
                    // what was sealed belongs, and `vault_record_tamper` ends the
                    // answer with a 503 rather than delivering a message written
                    // about a value this vault can no longer vouch for.
                    Err(_) => {
                        self.tampered = self.tampered.saturating_add(1);
                        None
                    }
                }
            }
            // Expired, unknown session, unknown alias: `masking_unresolved`. No
            // value, and no guess.
            Ok(Restored::Unresolved(_)) => None,
            Err(_) => {
                self.tampered = self.tampered.saturating_add(1);
                None
            }
        }
    }

    fn tampered(&self) -> u32 {
        self.tampered
    }
}

/// Puts the values back into one finished piece of text.
///
/// The same buffer and the same flush rule as the streaming path, driven to the
/// end in one step: a whole string is a stream whose only chunk is all of it.
/// Sharing the machinery rather than writing a second matcher is what keeps the
/// non-streaming answer and the streaming one from disagreeing about which
/// strings are aliases.
pub fn restore_text(
    snapshot: &Snapshot,
    lookup: &mut dyn Lookup,
    text: &str,
) -> (String, RestoreStats) {
    let mut stats = RestoreStats::default();
    if snapshot.is_empty() || text.is_empty() {
        return (text.to_owned(), stats);
    }

    // The compile time cap is the type preserving one, which is the wider of the
    // two: the window that actually decides is the snapshot's own longest alias,
    // and capping it against the narrower ceiling could only cut it below a real
    // alias. Correctness over the optimisation, as everywhere else here.
    let window = Window::of(
        Some(snapshot.longest()),
        None,
        crate::alias::AliasStyle::TypePreserving,
    );
    let mut buffer = Buffer::new(window);
    buffer.push(text);
    let released = buffer.release(snapshot, Trigger::StreamEnd, HoldTimeout::Wait);

    let mut out = String::with_capacity(text.len());
    for piece in released.pieces {
        match piece {
            Piece::Text(text) => out.push_str(&text),
            Piece::Alias(alias) => {
                match lookup.value_for(&alias) {
                    Some(value) => {
                        stats.saw(true);
                        out.push_str(&value);
                    }
                    None => {
                        stats.saw(false);
                        // Raw, exactly as the model wrote it.
                        out.push_str(&alias);
                    }
                }
            }
        }
    }
    (out, stats)
}

/// Puts the values back into every string **value** of a JSON answer.
///
/// Keys are not touched, for the same reason the request path does not mask them
/// (`proxy/spec.md` section 7 rule 1). Numbers are not touched either, which is
/// what keeps `usage` exactly as the provider sent it: the token counts describe
/// what the provider billed and re-deriving them from a body whose length this
/// proxy changed would be a number periskop made up.
pub fn restore_json(
    snapshot: &Snapshot,
    lookup: &mut dyn Lookup,
    document: &Value,
) -> (Value, RestoreStats) {
    let mut stats = RestoreStats::default();
    let out = walk(snapshot, lookup, document, &mut stats);
    (out, stats)
}

fn walk(
    snapshot: &Snapshot,
    lookup: &mut dyn Lookup,
    value: &Value,
    stats: &mut RestoreStats,
) -> Value {
    match value {
        Value::String(text) => {
            let (restored, found) = restore_text(snapshot, lookup, text);
            stats.merge(found);
            Value::String(restored)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| walk(snapshot, lookup, item, stats))
                .collect(),
        ),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, field)| (key.clone(), walk(snapshot, lookup, field, stats)))
                .collect(),
        ),
        // Numbers, booleans and null cross untouched. `usage.total_tokens` is one
        // of these and stays the provider's own number.
        other => other.clone(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// A table stand-in for the vault, so these tests are about the restore path
    /// rather than about Argon2id.
    struct Table {
        rows: BTreeMap<String, String>,
        asked: Vec<String>,
    }

    impl Table {
        fn of(rows: &[(&str, &str)]) -> Self {
            Self {
                rows: rows
                    .iter()
                    .map(|(alias, value)| ((*alias).to_owned(), (*value).to_owned()))
                    .collect(),
                asked: Vec::new(),
            }
        }
    }

    impl Lookup for Table {
        fn value_for(&mut self, alias: &str) -> Option<String> {
            self.asked.push(alias.to_owned());
            self.rows.get(alias).cloned()
        }
    }

    fn snapshot(aliases: &[&str]) -> Snapshot {
        Snapshot::frozen(
            aliases.len() as u64,
            aliases.iter().map(|alias| (*alias).to_owned()),
        )
    }

    #[test]
    fn an_alias_is_replaced_by_the_value_the_table_holds() {
        let snapshot = snapshot(&["PSK_PERSON_1"]);
        let mut table = Table::of(&[("PSK_PERSON_1", "Ahmet Yilmaz")]);
        let (text, stats) = restore_text(&snapshot, &mut table, "Merhaba PSK_PERSON_1.");
        assert_eq!(text, "Merhaba Ahmet Yilmaz.");
        assert_eq!(stats.aliases_seen_in_response, 1);
        assert_eq!(stats.aliases_restored, 1);
        assert_eq!(stats.aliases_leaked, 0);
        assert!(!stats.warns());
    }

    #[test]
    fn an_alias_the_table_cannot_answer_goes_back_raw_and_is_counted() {
        // The expired session, the restarted process, the garbled alias: one
        // instruction, and it is never a guess.
        let snapshot = snapshot(&["PSK_PERSON_1"]);
        let mut table = Table::of(&[]);
        let (text, stats) = restore_text(&snapshot, &mut table, "Merhaba PSK_PERSON_1.");
        assert_eq!(text, "Merhaba PSK_PERSON_1.");
        assert_eq!(stats.aliases_seen_in_response, 1);
        assert_eq!(stats.aliases_restored, 0);
        assert_eq!(stats.aliases_leaked, 1);
        assert!(stats.warns());
    }

    #[test]
    fn a_string_the_session_never_issued_is_never_looked_up() {
        // F4-D's invariant on the response side: the user's own alias shaped
        // literal was withheld, so it is not in the snapshot, so it is neither
        // matched nor asked about.
        let snapshot = snapshot(&["PSK_PERSON_1"]);
        let mut table = Table::of(&[("PSK_PERSON_2", "somebody else")]);
        let (text, stats) = restore_text(&snapshot, &mut table, "PSK_PERSON_2 wrote this");
        assert_eq!(text, "PSK_PERSON_2 wrote this");
        assert_eq!(stats.aliases_seen_in_response, 0);
        assert!(table.asked.is_empty(), "{:?}", table.asked);
    }

    #[test]
    fn nothing_is_reordered() {
        let snapshot = snapshot(&["PSK_A_1", "PSK_B_1"]);
        let mut table = Table::of(&[("PSK_A_1", "one"), ("PSK_B_1", "two")]);
        let (text, _) = restore_text(&snapshot, &mut table, "x PSK_B_1 y PSK_A_1 z");
        assert_eq!(text, "x two y one z");
    }

    #[test]
    fn usage_numbers_cross_untouched() {
        // Task 93: the provider's token counts are forwarded as they arrived. The
        // replacement changes the length of the text, so a recomputed count would
        // be a number this proxy invented.
        let snapshot = snapshot(&["PSK_PERSON_1"]);
        let mut table = Table::of(&[("PSK_PERSON_1", "Ahmet Yilmaz Karaosmanoglu")]);
        let document: Value = serde_json::from_str(
            "{\"choices\":[{\"message\":{\"content\":\"hi PSK_PERSON_1\"}}],\
             \"usage\":{\"prompt_tokens\":11,\"completion_tokens\":4,\"total_tokens\":15}}",
        )
        .expect("JSON");
        let (out, stats) = restore_json(&snapshot, &mut table, &document);
        assert_eq!(out["usage"], document["usage"]);
        assert_eq!(
            out["choices"][0]["message"]["content"],
            "hi Ahmet Yilmaz Karaosmanoglu"
        );
        assert_eq!(stats.aliases_restored, 1);
    }

    #[test]
    fn a_json_key_is_not_restored() {
        let snapshot = snapshot(&["PSK_PERSON_1"]);
        let mut table = Table::of(&[("PSK_PERSON_1", "Ahmet")]);
        let document: Value = serde_json::from_str("{\"PSK_PERSON_1\":\"value\"}").expect("JSON");
        let (out, stats) = restore_json(&snapshot, &mut table, &document);
        assert!(out.get("PSK_PERSON_1").is_some(), "{out}");
        assert_eq!(stats.aliases_seen_in_response, 0);
    }

    /// The second lock, on its own.
    ///
    /// The automaton should never offer a string outside the frozen set, so this
    /// guard is unreachable through the relay. It is still here, and it is still
    /// tested here, because the failure it prevents is the worst one this
    /// component has: a matcher that widened by one character would start handing
    /// one conversation's values to another string. Tested directly rather than
    /// through the relay, because a guard nothing can reach is a guard nothing can
    /// check, and an untestable guard is the kind that gets deleted as dead code.
    #[test]
    fn the_vault_is_not_asked_about_a_string_the_frozen_set_does_not_hold() {
        use crate::vault::{AliasSeed, Backing, OpenRequest, Passphrase, ProfileName, Vault};

        const NOW: u64 = 1_700_000_000_000;
        let session = SessionId::from_bytes([0x71; 16]);
        let mut vault = Vault::open(&OpenRequest {
            passphrase: &Passphrase::new(b"an operator's passphrase".to_vec()),
            profile: ProfileName::Ci,
            backing: Backing::Memory,
        })
        .unwrap_or_else(|refusal| panic!("{refusal}"));
        vault
            .store_alias(
                &session,
                AliasSeed::from_bytes([0x22; 32]),
                "PSK_PERSON_1",
                b"Ahmet Yilmaz",
                NOW,
            )
            .unwrap_or_else(|refusal| panic!("{refusal}"));

        // A snapshot that does **not** hold the alias the vault does.
        let snapshot = Snapshot::frozen(1, ["PSK_LOC_1".to_owned()]);
        let mut lookup = SessionLookup::new(&mut vault, &snapshot, session, NOW);
        assert_eq!(
            lookup.value_for("PSK_PERSON_1"),
            None,
            "the vault answered about a string this conversation's frozen set does not hold"
        );

        // And the control: with the alias in the set, the same vault answers.
        let held = Snapshot::frozen(1, ["PSK_PERSON_1".to_owned()]);
        let mut lookup = SessionLookup::new(&mut vault, &held, session, NOW);
        assert_eq!(
            lookup.value_for("PSK_PERSON_1"),
            Some("Ahmet Yilmaz".to_owned())
        );
    }

    /// "I cannot read this record" is not "this conversation never had one".
    ///
    /// Everything the request path files is a JSON string's bytes
    /// (`request_path.rs`: `original.as_bytes()`), so a record that opens into
    /// something that is not UTF-8 did not come out the way it went in. Answering
    /// that with `None` put it in the same bucket as an expired session: the alias
    /// went back raw, `masking_unresolved` counted it, and a record whose
    /// plaintext disagrees with everything that can be written into it was
    /// reported as an ordinary miss.
    #[test]
    fn a_record_that_opens_into_something_that_is_not_text_is_not_counted_as_a_miss() {
        use crate::vault::{AliasSeed, Backing, OpenRequest, Passphrase, ProfileName, Vault};

        const NOW: u64 = 1_700_000_000_000;
        let session = SessionId::from_bytes([0x5c; 16]);
        let mut vault = Vault::open(&OpenRequest {
            passphrase: &Passphrase::new(b"an operator's passphrase".to_vec()),
            profile: ProfileName::Ci,
            backing: Backing::Memory,
        })
        .unwrap_or_else(|refusal| panic!("{refusal}"));
        // A lone continuation byte: no encoder produces it and no JSON string can
        // hold it, which is what makes it a record that cannot have been filed by
        // the request path.
        vault
            .store_alias(
                &session,
                AliasSeed::from_bytes([0x33; 32]),
                "PSK_PERSON_1",
                &[0xff, 0xfe, 0x80],
                NOW,
            )
            .unwrap_or_else(|refusal| panic!("{refusal}"));

        let snapshot = snapshot(&["PSK_PERSON_1"]);
        let mut lookup = SessionLookup::new(&mut vault, &snapshot, session, NOW);
        assert_eq!(lookup.value_for("PSK_PERSON_1"), None);
        assert_eq!(
            lookup.tampered(),
            1,
            "a record whose plaintext is not the text that was filed was reported as \
             an ordinary unresolved alias"
        );

        // The control, on the same vault: an ordinary miss stays a miss and does
        // not raise the security counter, or the distinction would be lost the
        // other way round.
        let mut lookup = SessionLookup::new(&mut vault, &snapshot, session, NOW + 1);
        assert_eq!(lookup.value_for("PSK_PERSON_2"), None);
        assert_eq!(lookup.tampered(), 0);
    }

    #[test]
    fn an_empty_snapshot_changes_nothing() {
        let snapshot = Snapshot::empty();
        let mut table = Table::of(&[("PSK_PERSON_1", "Ahmet")]);
        let (text, stats) = restore_text(&snapshot, &mut table, "PSK_PERSON_1");
        assert_eq!(text, "PSK_PERSON_1");
        assert_eq!(stats.aliases_seen_in_response, 0);
    }
}
