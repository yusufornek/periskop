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

pub mod chain;
pub mod compaction;
pub mod error;
pub mod file;
pub mod key;
pub mod layout;
pub mod record;
pub mod secret;
pub mod session;
pub mod status;

use std::fmt;
use std::path::Path;

pub use compaction::Compacted;
pub use error::{Integrity, VaultError, VaultField};
pub use file::{CounterFloor, VaultFile};
pub use key::{ClaimedKdfParameters, KdfProfile, ProfileName, Salt, VaultNote};
pub use record::{AliasSeed, RecordCounters, RecordType, SealedRecord};
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
        vault.file = Some(loaded.file);
        Ok(vault)
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
    pub fn status(&self) -> VaultStatus {
        VaultStatus::new(
            VaultState::Unsealed,
            self.storage,
            self.file.as_ref().map(|file| file.path()),
            Integrity::Ok,
            self.sessions.record_count(),
        )
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
        self.sessions.purge_expired(now_ms)
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

    #[test]
    fn a_vault_opened_under_the_reduced_profile_carries_its_note() {
        let vault = Vault::open(&OpenRequest {
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
        let refusal = Vault::open(&OpenRequest {
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
        let vault = Vault::open(&OpenRequest {
            passphrase: &passphrase(),
            profile: ProfileName::Ci,
            backing: Backing::Memory,
        })
        .unwrap();

        let json = vault.status().to_json();
        assert!(json.contains("\"backend\":\"memory\""), "{json}");
        assert!(json.contains("\"integrity\":\"ok\""), "{json}");
        // `proxy-api.md`: the path is only meaningful in `file` mode.
        assert!(!json.contains("path"), "{json}");
    }

    #[test]
    fn compacting_a_memory_vault_purges_and_reports_no_file_work() {
        let mut vault = Vault::open(&OpenRequest {
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
