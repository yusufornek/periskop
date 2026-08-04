//! The session model: what a masked conversation remembers, and for how long.
//!
//! `proxy/spec.md` section 5 is the shape this implements. A session is the unit
//! of consistency and the unit of forgetting at the same time: the same value has
//! to mask to the same alias for as long as the conversation lasts, and the
//! mapping has to be gone afterwards.
//!
//! # Nothing here reaches a disk
//!
//! `memory` is the default backend and ADR-007 is explicit about why: persistence
//! means the map from alias back to a real person lives on a disk, which is a new
//! pile of exactly the data this product exists to keep from spreading. So this
//! module holds records in process memory, and the process is where they end.
//! `tests/vault_touches_no_files.rs` checks that twice over: it watches the
//! filesystem across a whole vault lifetime, and it reads this crate's own source
//! for the name of any filesystem API. The `file` backend is a later task and will
//! have to lift that boundary deliberately.
//!
//! # Two ways to lose a mapping, and neither is silent
//!
//! A session that has filled up refuses the request with 429 rather than dropping
//! the alias it could not store. A session that has expired answers a restore with
//! [`Restored::Unresolved`], which carries a reason and no value: the alias
//! travels back to the user unchanged and the run reports `masking_unresolved`
//! (threat model R5). Inventing a plausible value would be the one behaviour worse
//! than either.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fmt;

use super::error::VaultError;
use super::record::{AliasSeed, SealedRecord};
use super::secret::{random_bytes, SecretValue, SessionKey};

/// Bytes of a session identifier: 128 random bits (ADR-007).
pub const SESSION_ID_BYTES: usize = 16;

/// Default alias ceiling per session (`proxy/spec.md` section 5).
pub const DEFAULT_ALIAS_CEILING: usize = 10_000;

/// Default time to live, from last use: 24 hours (`proxy/spec.md` section 5).
pub const DEFAULT_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// A session identifier.
///
/// Also the HKDF salt the session key is expanded under, which is what makes two
/// sessions produce unrelated aliases for the same value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId([u8; SESSION_ID_BYTES]);

impl SessionId {
    /// Draws a new identifier from the operating system's entropy source.
    pub fn generate() -> Result<Self, VaultError> {
        Ok(Self(random_bytes()?))
    }

    pub const fn from_bytes(bytes: [u8; SESSION_ID_BYTES]) -> Self {
        Self(bytes)
    }

    pub(super) fn as_bytes(&self) -> &[u8; SESSION_ID_BYTES] {
        &self.0
    }
}

/// The two numbers a session lives by.
///
/// Configurable in the spec, and the defaults are the spec's. They are carried as
/// data rather than read from constants at each use so that a test can move time
/// without waiting for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionLimits {
    /// Aliases one session may hold before requests are refused.
    pub alias_ceiling: usize,
    /// Milliseconds of inactivity after which a session is forgotten.
    pub ttl_ms: u64,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            alias_ceiling: DEFAULT_ALIAS_CEILING,
            ttl_ms: DEFAULT_TTL_MS,
        }
    }
}

/// One record inside a session: the alias that was published, and the sealed
/// original it stands for.
#[derive(Clone, Debug)]
struct AliasRecord {
    alias: String,
    sealed: SealedRecord,
}

/// A masked conversation's memory.
///
/// `date_delta` and the per type counters that `proxy/spec.md` section 5 also
/// lists are not here. Both belong to alias generation, which is a later wave, and
/// a field nothing writes is a field nothing tests.
pub struct Session {
    key: SessionKey,
    created_at_ms: u64,
    last_used_at_ms: u64,
    /// seed to the alias and its sealed original.
    aliases: BTreeMap<AliasSeed, AliasRecord>,
    /// The way back: what the model wrote, to the record that explains it.
    reverse: BTreeMap<String, AliasSeed>,
}

/// Counts and times, never content.
///
/// A session holds published aliases and sealed originals, and `proxy/spec.md`
/// section 9 keeps both out of every log level. A derived `Debug` would carry them
/// into the first `{:?}` a future maintainer reaches for.
impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("aliases", &self.aliases.len())
            .field("created_at_ms", &self.created_at_ms)
            .field("last_used_at_ms", &self.last_used_at_ms)
            .finish()
    }
}

impl Session {
    pub(super) fn new(key: SessionKey, now_ms: u64) -> Self {
        Self {
            key,
            created_at_ms: now_ms,
            last_used_at_ms: now_ms,
            aliases: BTreeMap::new(),
            reverse: BTreeMap::new(),
        }
    }

    /// The key alias derivation runs under, `K_session` in ADR-007.
    ///
    /// Held by the session rather than derived per call so that the derivation
    /// happens once per conversation, and exposed because the alias layer is its
    /// caller.
    pub fn session_key(&self) -> &SessionKey {
        &self.key
    }

    pub fn alias_count(&self) -> usize {
        self.aliases.len()
    }

    fn is_expired(&self, now_ms: u64, ttl_ms: u64) -> bool {
        // Saturating, so a clock that moved backwards reads as "not expired"
        // rather than wrapping into a session that is suddenly ancient.
        now_ms.saturating_sub(self.last_used_at_ms) > ttl_ms
    }

    fn touch(&mut self, now_ms: u64) {
        // Monotonic in this session's own record: a late request carrying an
        // earlier timestamp may not shorten the life of a live session.
        self.last_used_at_ms = self.last_used_at_ms.max(now_ms);
    }

    /// Files one record, refusing rather than dropping it.
    pub(super) fn insert(
        &mut self,
        seed: AliasSeed,
        alias: &str,
        sealed: SealedRecord,
        ceiling: usize,
    ) -> Result<(), VaultError> {
        if let Some(existing) = self.aliases.get(&seed) {
            // The same value masked again inside one conversation. Same seed,
            // same record, and it may not consume a second slot: a long
            // conversation about one customer would otherwise walk into the
            // ceiling for no reason.
            if existing.alias == alias {
                return Ok(());
            }
            // Same value, two different aliases. Only a broken generator produces
            // that, and keeping either one would make the earlier turns of the
            // conversation unreadable.
            return Err(VaultError::AliasCollision);
        }

        // Two different values that rendered to the same alias string. The
        // generator is supposed to make that impossible, and the type preserving
        // generators work in small output spaces where it is merely unlikely. The
        // refusal is loud on purpose: the alternative is a restore that hands the
        // user a different entity's value under an alias they were shown.
        if let Some(bound) = self.reverse.get(alias) {
            if bound != &seed {
                return Err(VaultError::AliasCollision);
            }
        }

        if self.aliases.len() >= ceiling {
            return Err(VaultError::AliasCeilingReached { ceiling });
        }

        self.reverse.insert(alias.to_owned(), seed);
        self.aliases.insert(
            seed,
            AliasRecord {
                alias: alias.to_owned(),
                sealed,
            },
        );
        Ok(())
    }

    /// Finds what an alias in a model's answer refers to.
    pub(super) fn sealed_for_alias(&self, alias: &str) -> Option<(AliasSeed, &SealedRecord)> {
        let seed = self.reverse.get(alias)?;
        let record = self.aliases.get(seed)?;
        Some((*seed, &record.sealed))
    }

    /// Exchanges two records' sealed bodies in place.
    ///
    /// Test only, and it exists because nothing in the shipped code can do this.
    /// Rewriting a sealed body is what an attacker with write access to a vault
    /// file does, and the AAD binding in [`super::record`] is the defence; a
    /// defence with no attack against it is a claim rather than a guarantee.
    #[cfg(test)]
    pub(super) fn swap_sealed_bodies(&mut self, first: &AliasSeed, second: &AliasSeed) -> bool {
        let (Some(a), Some(b)) = (
            self.aliases.get(first).map(|record| record.sealed.clone()),
            self.aliases.get(second).map(|record| record.sealed.clone()),
        ) else {
            return false;
        };

        let mut replace = |seed: &AliasSeed, sealed: SealedRecord| {
            if let Some(record) = self.aliases.get_mut(seed) {
                record.sealed = sealed;
            }
        };
        replace(first, b);
        replace(second, a);
        true
    }
}

/// What a lookup found.
///
/// Expiry and absence are separate answers. An operator whose restores stopped
/// working needs to know whether the conversation outlived its time to live or
/// was never here, and collapsing the two would hide the one setting that
/// explains it.
pub(super) enum Lookup<'a> {
    Active(&'a mut Session),
    Expired,
    Unknown,
}

/// The same three states, without borrowing anything.
enum Presence {
    Live,
    Expired,
    Unknown,
}

/// Every live session in this process.
#[derive(Debug)]
pub(super) struct SessionStore {
    sessions: BTreeMap<SessionId, Session>,
    limits: SessionLimits,
}

impl SessionStore {
    pub(super) fn new(limits: SessionLimits) -> Self {
        Self {
            sessions: BTreeMap::new(),
            limits,
        }
    }

    pub(super) fn limits(&self) -> &SessionLimits {
        &self.limits
    }

    pub(super) fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Returns the named session, creating it if this is its first request.
    ///
    /// The key is built by the caller's closure and only when a session is
    /// actually new, so an ordinary request does not repeat the derivation. An
    /// expired session is dropped first: reusing an identifier gets a new
    /// conversation, not a resurrected one.
    pub(super) fn ensure(
        &mut self,
        id: &SessionId,
        now_ms: u64,
        key: impl FnOnce() -> Result<SessionKey, VaultError>,
    ) -> Result<&mut Session, VaultError> {
        // Expiry is decided in one place, and this is a call to that place. An
        // expired session is forgotten here, so reusing an identifier starts a new
        // conversation rather than resurrecting an old one.
        self.refresh(id, now_ms);

        match self.sessions.entry(*id) {
            Entry::Occupied(live) => Ok(live.into_mut()),
            // The key is derived here and only here: an ordinary request into an
            // ongoing conversation does not repeat it.
            Entry::Vacant(slot) => Ok(slot.insert(Session::new(key()?, now_ms))),
        }
    }

    /// One session, for the fault injection the swap test needs. Test only.
    #[cfg(test)]
    pub(super) fn session_mut(&mut self, id: &SessionId) -> Option<&mut Session> {
        self.sessions.get_mut(id)
    }

    /// Finds a live session, forgetting it if its time is up.
    pub(super) fn lookup(&mut self, id: &SessionId, now_ms: u64) -> Lookup<'_> {
        match self.refresh(id, now_ms) {
            Presence::Unknown => Lookup::Unknown,
            Presence::Expired => Lookup::Expired,
            Presence::Live => match self.sessions.get_mut(id) {
                Some(session) => Lookup::Active(session),
                // Unreachable: `refresh` just found it and this method holds the
                // only mutable borrow. Written as a value rather than an
                // unreachable!(), because a panic in the vault is an outage.
                None => Lookup::Unknown,
            },
        }
    }

    /// Applies the time to live, and says what was there.
    ///
    /// The one place a session is aged: it either loses a session whose time is
    /// up or moves a live session's deadline. Separated from [`Self::lookup`] so
    /// that a caller who wants the effect without the borrow can have it.
    fn refresh(&mut self, id: &SessionId, now_ms: u64) -> Presence {
        let expired = match self.sessions.get(id) {
            None => return Presence::Unknown,
            Some(session) => session.is_expired(now_ms, self.limits.ttl_ms),
        };

        if expired {
            // Removed here, which clears the session key with it. The mapping
            // being gone is the point of a time to live, not a side effect of it.
            self.sessions.remove(id);
            return Presence::Expired;
        }

        if let Some(session) = self.sessions.get_mut(id) {
            session.touch(now_ms);
        }
        Presence::Live
    }

    /// Forgets every session whose time is up.
    ///
    /// Access alone is not enough to keep a vault clean: a conversation nobody
    /// returns to would otherwise sit in memory until the process ended, which is
    /// the opposite of what a time to live is for. The request path calls this on
    /// a timer.
    pub(super) fn purge_expired(&mut self, now_ms: u64) -> usize {
        let before = self.sessions.len();
        let ttl_ms = self.limits.ttl_ms;
        self.sessions
            .retain(|_, session| !session.is_expired(now_ms, ttl_ms));
        before - self.sessions.len()
    }
}

/// Why a lookup could not be resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnresolvedReason {
    /// The session outlived its time to live and was forgotten.
    SessionExpired,
    /// No such session in this process. A restart is the ordinary cause, and the
    /// event dictionary spells it `vault_memory_restart`.
    SessionUnknown,
    /// The session is live and never published this alias. A model that garbled
    /// an alias it was given lands here (threat model R5).
    AliasUnknown,
}

/// The answer to a restore.
///
/// [`Restored::Unresolved`] carries a reason and no value, and that is a
/// deliberate property of the type: there is no shape of this enum that lets a
/// caller hand back something plausible. The alias goes back to the user exactly
/// as the model wrote it and the run reports `masking_unresolved`.
#[derive(Debug)]
pub enum Restored {
    Value(SecretValue),
    Unresolved(UnresolvedReason),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::vault::record::ALIAS_SEED_BYTES;
    use crate::vault::{MasterKey, Storage, Vault};

    const SESSION: SessionId = SessionId::from_bytes([0x77; SESSION_ID_BYTES]);
    const NOW: u64 = 1_700_000_000_000;
    const VALUE: &[u8] = b"Ahmet Yilmaz";

    fn seed(byte: u8) -> AliasSeed {
        AliasSeed::from_bytes([byte; ALIAS_SEED_BYTES])
    }

    fn vault_with(limits: SessionLimits) -> Vault {
        Vault::from_master_key(MasterKey::from_bytes([0x44; 32]), limits).unwrap()
    }

    fn vault() -> Vault {
        vault_with(SessionLimits::default())
    }

    #[test]
    fn the_default_limits_are_the_ones_the_spec_names() {
        let limits = SessionLimits::default();
        assert_eq!(limits.alias_ceiling, 10_000);
        assert_eq!(limits.ttl_ms, 24 * 60 * 60 * 1000);
    }

    #[test]
    fn the_default_storage_is_memory() {
        assert_eq!(Storage::default(), Storage::Memory);
        assert_eq!(vault().storage(), Storage::Memory);
    }

    #[test]
    fn an_alias_restores_to_its_value_inside_the_time_to_live() {
        let mut vault = vault();
        vault
            .store_alias(&SESSION, seed(1), "PSK_PERSON_1", VALUE, NOW)
            .unwrap();

        match vault
            .restore(&SESSION, "PSK_PERSON_1", NOW + 1_000)
            .unwrap()
        {
            Restored::Value(value) => assert_eq!(value.expose(), VALUE),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn storing_one_value_twice_does_not_consume_two_slots() {
        let mut vault = vault();
        for _ in 0..5 {
            vault
                .store_alias(&SESSION, seed(1), "PSK_PERSON_1", VALUE, NOW)
                .unwrap();
        }
        assert_eq!(vault.open_session(&SESSION, NOW).unwrap().alias_count(), 1);
    }

    /// Spec section 10's last row: the ceiling is a 429, and the request is
    /// refused rather than the alias being dropped.
    #[test]
    fn the_alias_ceiling_refuses_with_429_instead_of_losing_the_value() {
        let mut vault = vault_with(SessionLimits {
            alias_ceiling: 2,
            ..SessionLimits::default()
        });

        vault
            .store_alias(&SESSION, seed(1), "PSK_PERSON_1", VALUE, NOW)
            .unwrap();
        vault
            .store_alias(&SESSION, seed(2), "PSK_PERSON_2", b"Ayse Demir", NOW)
            .unwrap();

        let refusal = vault
            .store_alias(&SESSION, seed(3), "PSK_PERSON_3", b"Mehmet Kaya", NOW)
            .unwrap_err();
        assert_eq!(refusal, VaultError::AliasCeilingReached { ceiling: 2 });
        assert_eq!(refusal.http_status(), 429);

        // Refused, not half done: the value that could not be stored did not
        // leave a record behind, and the two that fit are untouched.
        let stored = vault.open_session(&SESSION, NOW).unwrap().alias_count();
        assert_eq!(stored, 2);
        assert!(matches!(
            vault.restore(&SESSION, "PSK_PERSON_3", NOW).unwrap(),
            Restored::Unresolved(UnresolvedReason::AliasUnknown)
        ));
    }

    #[test]
    fn a_value_already_stored_still_resolves_once_the_ceiling_is_reached() {
        // A conversation that hit the ceiling has to keep working for the aliases
        // it already published, or the model's earlier turns become unreadable.
        let mut vault = vault_with(SessionLimits {
            alias_ceiling: 1,
            ..SessionLimits::default()
        });
        vault
            .store_alias(&SESSION, seed(1), "PSK_PERSON_1", VALUE, NOW)
            .unwrap();
        assert!(vault
            .store_alias(&SESSION, seed(2), "PSK_PERSON_2", b"Ayse Demir", NOW)
            .is_err());

        match vault.restore(&SESSION, "PSK_PERSON_1", NOW).unwrap() {
            Restored::Value(value) => assert_eq!(value.expose(), VALUE),
            other => panic!("{other:?}"),
        }
    }

    /// The time to live is a promise to forget, and this is the shape of keeping
    /// it: no value, a reason, and nothing invented.
    #[test]
    fn an_expired_session_resolves_to_masking_unresolved_and_invents_nothing() {
        let mut vault = vault();
        vault
            .store_alias(&SESSION, seed(1), "PSK_PERSON_1", VALUE, NOW)
            .unwrap();

        let after_ttl = NOW + DEFAULT_TTL_MS + 1;
        let answer = vault.restore(&SESSION, "PSK_PERSON_1", after_ttl).unwrap();

        match answer {
            Restored::Unresolved(reason) => {
                assert_eq!(reason, UnresolvedReason::SessionExpired)
            }
            Restored::Value(_) => panic!("an expired session handed back a value"),
        }

        // And the mapping is gone rather than merely hidden: the same alias, at
        // the same instant, is now simply unknown.
        assert!(matches!(
            vault.restore(&SESSION, "PSK_PERSON_1", after_ttl).unwrap(),
            Restored::Unresolved(UnresolvedReason::SessionUnknown)
        ));
    }

    #[test]
    fn an_expired_session_identifier_reused_starts_empty() {
        let mut vault = vault();
        vault
            .store_alias(&SESSION, seed(1), "PSK_PERSON_1", VALUE, NOW)
            .unwrap();

        let after_ttl = NOW + DEFAULT_TTL_MS + 1;
        assert_eq!(
            vault
                .open_session(&SESSION, after_ttl)
                .unwrap()
                .alias_count(),
            0
        );
    }

    #[test]
    fn an_unknown_session_and_an_unknown_alias_are_told_apart() {
        let mut vault = vault();
        vault
            .store_alias(&SESSION, seed(1), "PSK_PERSON_1", VALUE, NOW)
            .unwrap();

        assert!(matches!(
            vault.restore(&SESSION, "PSK_PERSON_9", NOW).unwrap(),
            Restored::Unresolved(UnresolvedReason::AliasUnknown)
        ));
        let elsewhere = SessionId::from_bytes([0x99; SESSION_ID_BYTES]);
        assert!(matches!(
            vault.restore(&elsewhere, "PSK_PERSON_1", NOW).unwrap(),
            Restored::Unresolved(UnresolvedReason::SessionUnknown)
        ));
    }

    #[test]
    fn the_time_to_live_runs_from_the_last_use() {
        let mut vault = vault();
        vault
            .store_alias(&SESSION, seed(1), "PSK_PERSON_1", VALUE, NOW)
            .unwrap();

        // Used shortly before it would have expired.
        let late = NOW + DEFAULT_TTL_MS - 1;
        assert!(matches!(
            vault.restore(&SESSION, "PSK_PERSON_1", late).unwrap(),
            Restored::Value(_)
        ));

        // The clock moves another almost-whole time to live, and the session is
        // still alive because the use above moved its deadline.
        let later = late + DEFAULT_TTL_MS - 1;
        assert!(matches!(
            vault.restore(&SESSION, "PSK_PERSON_1", later).unwrap(),
            Restored::Value(_)
        ));
    }

    #[test]
    fn purging_forgets_expired_sessions_and_keeps_live_ones() {
        let mut vault = vault();
        let old = SessionId::from_bytes([0x01; SESSION_ID_BYTES]);
        let fresh = SessionId::from_bytes([0x02; SESSION_ID_BYTES]);

        vault
            .store_alias(&old, seed(1), "PSK_PERSON_1", VALUE, NOW)
            .unwrap();
        let later = NOW + DEFAULT_TTL_MS;
        vault
            .store_alias(&fresh, seed(2), "PSK_PERSON_2", b"Ayse Demir", later)
            .unwrap();

        assert_eq!(vault.session_count(), 2);
        assert_eq!(vault.purge_expired(later + 1), 1);
        assert_eq!(vault.session_count(), 1);
        assert!(matches!(
            vault.restore(&fresh, "PSK_PERSON_2", later + 1).unwrap(),
            Restored::Value(_)
        ));
    }

    #[test]
    fn two_generated_session_identifiers_differ() {
        assert_ne!(
            SessionId::generate().unwrap(),
            SessionId::generate().unwrap()
        );
    }

    #[test]
    fn a_session_carries_the_key_alias_derivation_runs_under() {
        let mut vault = vault();
        let session = vault.open_session(&SESSION, NOW).unwrap();
        let rendered = format!("{:?}", session.session_key());
        // Present, and unprintable. The alias layer is its only reader.
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn two_values_that_render_to_one_alias_are_refused_rather_than_confused() {
        let mut vault = vault();
        vault
            .store_alias(&SESSION, seed(1), "PSK_PERSON_1", VALUE, NOW)
            .unwrap();

        // A generator collision: a different value, the same published alias. The
        // restore path would otherwise hand one user the other user's data.
        let refusal = vault
            .store_alias(&SESSION, seed(2), "PSK_PERSON_1", b"Ayse Demir", NOW)
            .unwrap_err();
        assert_eq!(refusal, VaultError::AliasCollision);
        assert_eq!(refusal.http_status(), 503);
    }

    // The other half of task 70's claim, that the default configuration writes
    // nothing to disk, lives in `tests/vault_touches_no_files.rs`. It is there
    // rather than here for a reason worth keeping: that test watches the
    // filesystem and reads this crate's own sources for filesystem calls, and a
    // scan with no exceptions is only possible while no vault module, test module
    // included, names one.
}
