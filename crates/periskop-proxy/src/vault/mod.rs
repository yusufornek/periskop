//! The masking vault: local, encrypted, in this process (ADR-007).
//!
//! Everything the proxy learns about a real person passes through here, and
//! nothing else in the product may read it: the MCP server, the CLI and report
//! generation see aliases and never originals (ADR-005). CLAUDE.md forbids a
//! default configuration that writes the vault outside this process, so `memory`
//! is the default backend and the disk is not involved at all.
//!
//! # The shape of the thing
//!
//! ```text
//! passphrase --Argon2id--> K_master --HKDF--> K_record   (records are sealed under this)
//!                                   --HKDF--> K_session  (alias derivation runs under this)
//! ```
//!
//! [`Vault`] is the facade over four modules that each own one idea: [`key`]
//! derives, [`record`] seals, [`session`] remembers and forgets, [`error`] says
//! what the caller answers.
//!
//! # Fail closed, everywhere
//!
//! Every refusal in this module is a refusal. There is no path that carries on
//! with an unmasked value, a partially decrypted record or an invented one; the
//! caller gets a 503 or a 429 and the request stops (`proxy/spec.md` section 10).
//! The cost is written down rather than worked around: when the vault is
//! unreachable, access to the model stops too.

// Private by default, as CLAUDE.md's visibility rule asks: the public API of this
// crate is the list of re-exports below, decided item by item, rather than every
// module that happens to exist. `pub(crate)` rather than fully private because
// `alias` derives seeds against `record`'s widths, and because the two boundary
// tests read these modules by path.
pub(crate) mod chain;
pub(crate) mod compaction;
pub(crate) mod error;
pub(crate) mod file;
pub(crate) mod key;
pub(crate) mod layout;
pub(crate) mod record;
pub(crate) mod secret;
pub(crate) mod session;
pub(crate) mod status;

use std::fmt;
use std::path::Path;

pub use compaction::Compacted;
pub use error::{Integrity, VaultError, VaultField};
pub use file::{CounterFloor, VaultFile};
pub use key::{ClaimedKdfParameters, KdfProfile, ProfileName, Salt, VaultNote};
pub use record::{AliasSeed, RecordCounters, RecordType, SealedRecord, ALIAS_SEED_BYTES};
pub use secret::{MasterKey, Passphrase, SecretValue, SessionKey};
pub use session::{Restored, Session, SessionId, SessionLimits, UnresolvedReason};
pub use status::{VaultState, VaultStatus};

use key::note_for;
use layout::Frame;
use record::RecordIdentity;
use secret::RecordKey;
use session::{Inserted, Lookup, SessionStore};

/// Where the vault keeps its records.
///
/// `memory` is the default: `proxy/spec.md` section 9 makes it the normal case and
/// persistence the exception somebody has to ask for, and CLAUDE.md's first
/// prohibition is a default configuration that writes the vault outside this
/// process. `file` exists because a proxy that restarts otherwise breaks every
/// conversation it was masking, and that cost has to be payable by an operator who
/// decides it is worth it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Storage {
    /// Process memory, for the lifetime of the process. Nothing is written
    /// anywhere, and a restart loses the mappings: that cost is declared as
    /// `masking_unresolved` rather than hidden.
    #[default]
    Memory,
    /// A `vault.psk` file, encrypted per record and chained (ADR-007, SB-9).
    File,
}

impl Storage {
    /// The `backend` value `GET /admin/vault/status` reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::File => "file",
        }
    }
}

/// Where a vault being opened should keep its records.
///
/// Separate from [`Storage`] because opening a file needs two things the status
/// projection must never carry: where the file is, and what this caller already
/// knows about how far the vault had got.
pub enum Backing<'a> {
    /// The default. Nothing reaches a disk.
    Memory,
    /// `vault.psk` at `path`, created if it is not there.
    File {
        path: &'a Path,
        /// The lowest record counter this caller will accept. See
        /// [`CounterFloor`]: a rollback is only visible against a value that did
        /// not come out of the file being checked.
        floor: CounterFloor,
    },
}

/// What opening a vault needs.
///
/// A passphrase, a profile and a backing. ADR-016 section 4 struck the operating
/// system keyring from F4, so there is no passwordless path here to configure; the
/// loss is recorded in KG-020 rather than quietly filled by a key file somebody
/// leaves at mode 644.
pub struct OpenRequest<'a> {
    pub passphrase: &'a Passphrase,
    pub profile: ProfileName,
    pub backing: Backing<'a>,
}

/// The vault.
pub struct Vault {
    master: MasterKey,
    record_key: RecordKey,
    storage: Storage,
    file: Option<VaultFile>,
    sessions: SessionStore,
    counters: RecordCounters,
    notes: Vec<VaultNote>,
    /// Whether sessions read out of a file are still waiting for a clock.
    ///
    /// A vault file records when each session was last used, but opening one
    /// happens before any request supplies a "now", so [`session::SessionStore::load`]
    /// cannot apply the time to live and deliberately does not try. Something has
    /// to, though: without this flag a restart resurrects every expired
    /// conversation, keeps its session key in memory for the life of the process
    /// and counts it in `/admin/vault/status`. The first call that carries a clock
    /// sweeps, and the flag is what makes that happen once rather than never.
    awaiting_first_clock: bool,
    /// The most recent "now" any caller has handed this vault.
    ///
    /// The vault reads no clock of its own, on purpose: every answer it gives is
    /// a function of what it was told, which is what keeps it testable and its
    /// output diffable. [`Vault::status`] needs a time anyway, because a record
    /// whose session has outlived its time to live is not a record this vault can
    /// resolve, and counting it in `entries_count` reports a mapping the very
    /// next lookup would refuse. So the clock is remembered where it arrives
    /// rather than invented where it is needed.
    ///
    /// `None` until the first request carries one. A vault that has never been
    /// told what time it is cannot say which of the sessions it read off a disk
    /// are still alive, so it reports what it holds rather than guessing, and the
    /// sweep happens the moment a clock does arrive.
    last_clock_ms: Option<u64>,
}

/// Says what the vault is doing and nothing about what it holds.
///
/// Written by hand because the derived form would print session records, and
/// `proxy/spec.md` section 9 puts vault content outside every log level.
impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("storage", &self.storage)
            .field("sessions", &self.sessions.len())
            .field("record_tamper", &self.counters.record_tamper())
            .finish()
    }
}

impl Vault {
    /// Derives the keys and opens the vault.
    ///
    /// In `memory` mode the Argon2id salt is drawn fresh: nothing survives the
    /// process, so there is no previous salt to agree with and a new one every
    /// time is strictly better than a stored one. In `file` mode the salt and the
    /// parameters come out of the header, are bounded before anything is derived,
    /// and are then authenticated by the header tag they derive the key for.
    pub fn open(request: &OpenRequest<'_>) -> Result<Self, VaultError> {
        match request.backing {
            Backing::Memory => Self::open_in_memory(request),
            Backing::File { path, floor } => Self::open_on_file(request, path, floor),
        }
    }

    fn open_in_memory(request: &OpenRequest<'_>) -> Result<Self, VaultError> {
        let profile = KdfProfile::named(request.profile);
        let master = key::derive_master_key(&profile, request.passphrase, &Salt::generate()?)?;

        let mut vault = Self::from_master_key(master, SessionLimits::default())?;
        vault.notes.extend(note_for(&profile));
        Ok(vault)
    }

    /// Opens a vault whose records live in `vault.psk`.
    ///
    /// Every refusal from here is fail closed and none of them repairs anything:
    /// the three integrity violations, a header from another layout, and a file the
    /// operating system would not hand over all leave the bytes exactly as they
    /// were (`proxy/spec.md` section 10, ADR-007 section 3).
    fn open_on_file(
        request: &OpenRequest<'_>,
        path: &Path,
        floor: CounterFloor,
    ) -> Result<Self, VaultError> {
        let loaded = file::open(path, request.passphrase, request.profile, floor)?;
        let effective = loaded.effective_profile();
        let mut vault = Self::from_master_key(loaded.master, SessionLimits::default())?;
        vault.storage = Storage::File;

        // The note follows the parameters the vault is *actually* protected by,
        // which in file mode is what the header says rather than what this run
        // asked for. An operator who typed `--vault-profile default` at a vault
        // created under `ci` is running at the reduced strength either way, and
        // the difference between the two may not be invisible (README principle 4).
        vault.notes.extend(note_for(&effective));
        vault.load_frames(&loaded.frames)?;
        // Only when there was something to load. A vault opened on a file that did
        // not exist yet holds nothing, and arming the sweep for it would be a flag
        // set for a state that cannot occur.
        vault.awaiting_first_clock = !loaded.frames.is_empty();
        vault.file = Some(loaded.file);
        Ok(vault)
    }

    /// Applies the time to live to sessions that were read off a disk.
    ///
    /// Called by every entry point that carries a clock. Sessions restored from a
    /// file arrive with the deadline they had when they were written; if the file
    /// sat on the disk over a weekend, most of them are already over it, and each
    /// one that survives holds a session key. Sweeping at the first clock rather
    /// than at open is what lets the vault be loaded before any request exists
    /// without the time to live becoming optional.
    fn sweep_sessions_loaded_from_a_file(&mut self, now_ms: u64) {
        // Every entry point that carries a clock passes through here, which makes
        // it the one place the vault learns what time it is. Kept monotone so a
        // late request carrying an earlier stamp cannot walk the reading back and
        // resurrect a session in the status projection.
        self.last_clock_ms = Some(self.last_clock_ms.map_or(now_ms, |seen| seen.max(now_ms)));
        if !self.awaiting_first_clock {
            return;
        }
        // Cleared before the sweep, not after: the sweep is a one off, and a
        // panic inside it must not leave the flag armed for every later call.
        self.awaiting_first_clock = false;
        self.sessions.purge_expired(now_ms);
    }

    fn load_frames(&mut self, frames: &[Frame]) -> Result<(), VaultError> {
        let master = &self.master;
        for frame in frames {
            self.sessions.load(
                &frame.session,
                frame.stored_at_ms,
                frame.alias_seed,
                &frame.alias,
                frame.sealed.clone(),
                || key::derive_session_key(master, &frame.session),
            )?;
        }
        Ok(())
    }

    /// Opens a vault around a key that has already been derived.
    ///
    /// The seam [`Vault::open`] itself uses, and the one the tests in this crate
    /// use so that they exercise the vault rather than Argon2id's memory
    /// parameter.
    pub(crate) fn from_master_key(
        master: MasterKey,
        limits: SessionLimits,
    ) -> Result<Self, VaultError> {
        let record_key = key::derive_record_key(&master)?;
        Ok(Self {
            master,
            record_key,
            storage: Storage::default(),
            file: None,
            sessions: SessionStore::new(limits),
            counters: RecordCounters::default(),
            notes: Vec::new(),
            awaiting_first_clock: false,
            last_clock_ms: None,
        })
    }

    pub fn storage(&self) -> Storage {
        self.storage
    }

    /// What `GET /admin/vault/status` answers for this vault.
    ///
    /// An open vault always reports `integrity: ok`, because a vault whose chain
    /// did not close never became a `Vault` at all: the three violations are
    /// errors out of [`Vault::open`], and their value is read off the refusal with
    /// [`VaultError::integrity`].
    ///
    /// `entries_count` is what this vault can still resolve, not what it is still
    /// holding. Expiry is applied by a sweep and a sweep needs a clock, so
    /// between two requests the store keeps sessions whose time to live has
    /// already run out; counting those reported mappings that the next lookup
    /// answers `masking_unresolved` for, and after a restart from a file it
    /// reported a whole day of conversations that were over before the process
    /// started. The count is taken against the last clock a caller supplied
    /// instead, which is the newest time this vault is entitled to believe.
    pub fn status(&self) -> VaultStatus {
        VaultStatus::new(
            VaultState::Unsealed,
            self.storage,
            self.file.as_ref().map(|file| file.path()),
            Integrity::Ok,
            self.resolvable_record_count(),
        )
    }

    /// Records a lookup could still return, as of the last clock this vault saw.
    ///
    /// Without a clock there is nothing to apply, and the honest answer is what
    /// the store holds: a vault opened on a file and asked for its status before
    /// any request has arrived does not know which of those sessions survived,
    /// and reporting zero would be as invented as reporting all of them. That
    /// window closes at the first request, which sweeps.
    fn resolvable_record_count(&self) -> usize {
        match self.last_clock_ms {
            Some(now_ms) => self.sessions.record_count_at(now_ms),
            None => self.sessions.record_count(),
        }
    }

    /// The record counter a caller should pass as [`CounterFloor`] next time.
    ///
    /// `None` in `memory` mode, where there is no file to roll back.
    pub fn record_counter(&self) -> Option<u64> {
        self.file.as_ref().map(|file| file.record_counter())
    }

    /// What the operator has to be told about this vault.
    ///
    /// Empty for a vault opened at the shipped strength. The command line prints
    /// whatever is here, so a note that is produced is a note that is seen.
    pub fn notes(&self) -> &[VaultNote] {
        &self.notes
    }

    pub fn limits(&self) -> &SessionLimits {
        self.sessions.limits()
    }

    /// The counters a `ProxyEvent` reports (`schemas/proxy-event.schema.json`).
    pub fn counters(&self) -> &RecordCounters {
        &self.counters
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Returns the named session, starting it if this is its first request.
    ///
    /// The session key is derived once, here, and the alias layer reads it from
    /// the session it is handed.
    pub fn open_session(
        &mut self,
        session: &SessionId,
        now_ms: u64,
    ) -> Result<&Session, VaultError> {
        self.sweep_sessions_loaded_from_a_file(now_ms);
        let master = &self.master;
        self.sessions
            .ensure(session, now_ms, || key::derive_session_key(master, session))
            .map(|entry| &*entry)
    }

    /// Seals one original value under the alias that replaced it.
    ///
    /// Sealing happens before the session is touched, so a session that cannot
    /// take the record is not left with a slot that has nothing in it.
    ///
    /// In `file` mode the record reaches the disk before this returns, and if it
    /// cannot, the in memory copy is taken back out. The alternative, keeping a
    /// record memory has and the file does not, would answer this conversation
    /// correctly and lose it at the next restart without anything having reported
    /// a failure.
    pub fn store_alias(
        &mut self,
        session: &SessionId,
        seed: AliasSeed,
        alias: &str,
        value: &[u8],
        now_ms: u64,
    ) -> Result<(), VaultError> {
        self.sweep_sessions_loaded_from_a_file(now_ms);
        let sealed = record::seal(
            &self.record_key,
            &RecordIdentity {
                record_type: RecordType::Alias,
                session,
                alias_seed: &seed,
            },
            value,
        )?;

        let ceiling = self.sessions.limits().alias_ceiling;
        let master = &self.master;
        let stored = self
            .sessions
            .ensure(session, now_ms, || key::derive_session_key(master, session))?
            .insert(seed, alias, sealed.clone(), ceiling)?;

        let (Inserted::Stored, Some(file)) = (stored, self.file.as_mut()) else {
            // Either nothing new was filed, or there is no disk to file it on.
            return Ok(());
        };

        let frame = Frame {
            stored_at_ms: now_ms,
            session: *session,
            alias_seed: seed,
            alias: alias.to_owned(),
            sealed,
        };
        if let Err(refusal) = file.append(&frame) {
            if let Some(live) = self.sessions.session_mut(session) {
                live.forget(&seed, alias);
            }
            return Err(refusal);
        }
        Ok(())
    }

    /// Rewrites the vault file so that it holds only what is still live.
    ///
    /// The two halves are one operation on purpose: expiry decides what a session
    /// is worth keeping, and the file is the copy that outlives the process. A
    /// purge that did not reach the disk would forget a mapping until the next
    /// restart brought it back.
    ///
    /// `None` in `memory` mode, where purging is the whole of it.
    pub fn compact(&mut self, now_ms: u64) -> Result<Option<Compacted>, VaultError> {
        self.purge_expired(now_ms);
        if self.file.is_none() {
            return Ok(None);
        }

        let frames = self.live_frames();
        let Some(file) = self.file.as_mut() else {
            return Ok(None);
        };
        compaction::compact(file, &frames).map(Some)
    }

    /// The live sessions as frames, in the order compaction writes them.
    fn live_frames(&self) -> Vec<Frame> {
        let mut frames = Vec::new();
        for (id, session) in self.sessions.iter() {
            for (seed, alias, sealed) in session.records() {
                frames.push(Frame {
                    // The session's own deadline rather than each record's, so
                    // that a conversation kept alive by reads is written back with
                    // the life it actually has.
                    stored_at_ms: session.last_used_at_ms(),
                    session: *id,
                    alias_seed: seed,
                    alias: alias.to_owned(),
                    sealed: sealed.clone(),
                });
            }
        }
        frames
    }

    /// Looks up what an alias in a model's answer stands for.
    ///
    /// A lookup, not a computation: aliases are one way, and the only route back
    /// is this table (`proxy/spec.md` section 6.2). Three of the four answers
    /// carry no value, and none of the four carries a guess.
    pub fn restore(
        &mut self,
        session: &SessionId,
        alias: &str,
        now_ms: u64,
    ) -> Result<Restored, VaultError> {
        self.sweep_sessions_loaded_from_a_file(now_ms);
        let mut tampered = false;

        let answer = match self.sessions.lookup(session, now_ms) {
            Lookup::Unknown => Ok(Restored::Unresolved(UnresolvedReason::SessionUnknown)),
            Lookup::Expired => Ok(Restored::Unresolved(UnresolvedReason::SessionExpired)),
            Lookup::Active(live) => match live.sealed_for_alias(alias) {
                None => Ok(Restored::Unresolved(UnresolvedReason::AliasUnknown)),
                Some((seed, sealed)) => {
                    let identity = RecordIdentity {
                        record_type: RecordType::Alias,
                        session,
                        alias_seed: &seed,
                    };
                    match record::unseal(&self.record_key, &identity, sealed) {
                        Ok(value) => Ok(Restored::Value(value)),
                        Err(refusal) => {
                            // Counted below rather than here so that the count
                            // cannot be skipped by an early return added later.
                            tampered = true;
                            Err(refusal)
                        }
                    }
                }
            },
        };

        if tampered {
            self.counters.count_tamper();
        }
        answer
    }

    /// Forgets every session whose time to live has run out.
    ///
    /// Returns how many were forgotten, because a sweep that reports nothing is a
    /// sweep nobody can tell ran.
    pub fn purge_expired(&mut self, now_ms: u64) -> usize {
        // The one place the flag is cleared without its own sweep mattering: this
        // call is the sweep.
        self.awaiting_first_clock = false;
        self.last_clock_ms = Some(self.last_clock_ms.map_or(now_ms, |seen| seen.max(now_ms)));
        self.sessions.purge_expired(now_ms)
    }

    /// Replaces the session limits on an open vault.
    ///
    /// `proxy/spec.md` section 5 says both numbers are configurable, and this is
    /// where an operator's choice lands: [`Vault::open`] takes the defaults
    /// because a vault has to be openable before anything has been configured.
    /// Applied to an empty store only, which is the shape of a vault that has just
    /// been opened; lowering the ceiling under a session that is already over it
    /// would refuse a conversation that was legal when it started.
    pub fn with_limits(mut self, limits: SessionLimits) -> Self {
        self.sessions.set_limits(limits);
        self
    }

    /// An in memory vault with limits a test chose, around a key that was not
    /// derived.
    ///
    /// Test only, and crate visible so that the request path's tests can drive the
    /// alias ceiling without spending Argon2id on every case. The production
    /// entry point is [`Vault::open`], which is the only one that takes a
    /// passphrase.
    #[cfg(test)]
    pub(crate) fn in_memory_with_limits(limits: SessionLimits) -> Result<Self, VaultError> {
        Self::from_master_key(MasterKey::from_bytes([0x3c; 32]), limits)
    }

    /// Exchanges two records' sealed bodies, as an attacker with write access to
    /// a vault file would. Test only; see [`session::Session::swap_sealed_bodies`].
    #[cfg(test)]
    pub(crate) fn swap_sealed_bodies_for_test(
        &mut self,
        session: &SessionId,
        first: &AliasSeed,
        second: &AliasSeed,
    ) -> bool {
        self.sessions
            .session_mut(session)
            .is_some_and(|live| live.swap_sealed_bodies(first, second))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn passphrase() -> Passphrase {
        Passphrase::new(b"the operator typed this".to_vec())
    }

    /// Every `Vault::open` in this module goes through here.
    ///
    /// One place takes the permit, so no two Argon2id derivations in this test
    /// binary run beside each other; see [`key::one_derivation_at_a_time`]. The
    /// three tests below opened vaults without it, which is how four derivations
    /// came to be able to run at once under `--test-threads=4` on a machine with
    /// sixteen gigabytes: the permit existed, it was taken by the `file` and
    /// `key` suites, and the facade's own tests were the hole in it.
    fn open_here(request: &OpenRequest<'_>) -> Result<Vault, VaultError> {
        let _permit = key::one_derivation_at_a_time();
        Vault::open(request)
    }

    #[test]
    fn a_vault_opened_under_the_reduced_profile_carries_its_note() {
        let vault = open_here(&OpenRequest {
            passphrase: &passphrase(),
            profile: ProfileName::Ci,
            backing: Backing::Memory,
        })
        .unwrap();

        assert_eq!(vault.notes().len(), 1);
        assert!(vault.notes()[0].to_string().contains("64 MiB"));
        assert_eq!(vault.storage(), Storage::Memory);
        // Nothing to roll back, because nothing was written down.
        assert_eq!(vault.record_counter(), None);
    }

    #[test]
    fn a_vault_cannot_be_opened_without_a_passphrase() {
        let refusal = open_here(&OpenRequest {
            passphrase: &Passphrase::new(Vec::new()),
            profile: ProfileName::Ci,
            backing: Backing::Memory,
        })
        .unwrap_err();

        assert_eq!(refusal, VaultError::PassphraseMissing);
        assert_eq!(refusal.http_status(), 503);
    }

    #[test]
    fn a_memory_vault_reports_the_memory_backend_and_no_path() {
        let vault = open_here(&OpenRequest {
            passphrase: &passphrase(),
            profile: ProfileName::Ci,
            backing: Backing::Memory,
        })
        .unwrap();

        let json = vault.status().to_json();
        assert!(json.contains("\"backend\":\"memory\""), "{json}");
        assert!(json.contains("\"integrity\":\"ok\""), "{json}");
        // `proxy-api.md`'s normative table: the path is only meaningful in `file`
        // mode and is `null` here. This assertion used to pin the opposite, that
        // the field was absent, which made the divergence from the contract a
        // property the suite defended.
        assert!(json.contains("\"path\":null"), "{json}");
    }

    #[test]
    fn compacting_a_memory_vault_purges_and_reports_no_file_work() {
        let mut vault = open_here(&OpenRequest {
            passphrase: &passphrase(),
            profile: ProfileName::Ci,
            backing: Backing::Memory,
        })
        .unwrap();
        let session = SessionId::from_bytes([0x33; 16]);
        vault
            .store_alias(
                &session,
                AliasSeed::from_bytes([1u8; 32]),
                "PSK_PERSON_1",
                b"Ahmet Yilmaz",
                1_700_000_000_000,
            )
            .unwrap();

        let after_ttl = 1_700_000_000_000 + vault.limits().ttl_ms + 1;
        assert_eq!(vault.compact(after_ttl).unwrap(), None);
        assert_eq!(vault.session_count(), 0);
    }

    /// `entries_count` is what a lookup could still return, not what the store
    /// happens to be holding.
    ///
    /// The two diverge whenever a session outlives its time to live without
    /// anything having swept it, which is every moment between two requests and
    /// the whole gap between a restart and the first one. The second
    /// conversation below carries the clock that makes the first one over; the
    /// first session is still in the store, and `/admin/vault/status` used to
    /// count its record as a mapping this vault could resolve.
    #[test]
    fn the_status_count_leaves_out_records_a_lookup_would_no_longer_resolve() {
        let mut vault =
            Vault::from_master_key(MasterKey::from_bytes([0x5a; 32]), SessionLimits::default())
                .unwrap();
        let started = 1_700_000_000_000;
        let ended = SessionId::from_bytes([0x44; 16]);
        let live = SessionId::from_bytes([0x55; 16]);

        vault
            .store_alias(
                &ended,
                AliasSeed::from_bytes([1u8; 32]),
                "PSK_PERSON_1",
                b"Ahmet Yilmaz",
                started,
            )
            .unwrap();
        assert!(vault.status().to_json().contains("\"entries_count\":1"));

        let after_ttl = started + vault.limits().ttl_ms + 1;
        vault
            .store_alias(
                &live,
                AliasSeed::from_bytes([2u8; 32]),
                "PSK_PERSON_2",
                b"Ayse Demir",
                after_ttl,
            )
            .unwrap();

        // The expired session is still there: nothing touched it, and a
        // projection may not change what the vault holds in order to answer.
        assert_eq!(vault.session_count(), 2);
        let json = vault.status().to_json();
        assert!(json.contains("\"entries_count\":1"), "{json}");

        // And the count agrees with the answer the endpoint's own vault gives:
        // the record it left out is the one that no longer resolves.
        assert!(matches!(
            vault.restore(&ended, "PSK_PERSON_1", after_ttl).unwrap(),
            Restored::Unresolved(UnresolvedReason::SessionExpired)
        ));
        assert!(matches!(
            vault.restore(&live, "PSK_PERSON_2", after_ttl).unwrap(),
            Restored::Value(_)
        ));
    }

    #[test]
    fn the_debug_rendering_says_what_the_vault_is_doing_and_not_what_it_holds() {
        let mut vault =
            Vault::from_master_key(MasterKey::from_bytes([9u8; 32]), SessionLimits::default())
                .unwrap();
        let session = SessionId::from_bytes([1u8; 16]);
        vault
            .store_alias(
                &session,
                AliasSeed::from_bytes([2u8; 32]),
                "PSK_PERSON_1",
                b"Ahmet Yilmaz",
                0,
            )
            .unwrap();

        let rendered = format!("{vault:?}");
        assert!(rendered.contains("Memory"), "{rendered}");
        assert!(!rendered.contains("Ahmet"), "{rendered}");
        assert!(!rendered.contains("PSK_PERSON_1"), "{rendered}");
    }

    // The `file` backend's tests live in `tests/vault_file_backend.rs` rather than
    // here, and the reason is the boundary in `tests/vault_touches_no_files.rs`:
    // that scan reads every vault module, test modules included, and only two of
    // them may name a filesystem call. Keeping this facade off that list is what
    // makes the list short enough to be worth reading.
}
