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

pub mod error;
pub mod key;
pub mod record;
pub mod secret;
pub mod session;

use std::fmt;

pub use error::VaultError;
pub use key::{ClaimedKdfParameters, KdfProfile, ProfileName, Salt, VaultNote};
pub use record::{AliasSeed, RecordCounters, RecordType, SealedRecord};
pub use secret::{MasterKey, Passphrase, SecretValue, SessionKey};
pub use session::{Restored, Session, SessionId, SessionLimits, UnresolvedReason};

use record::RecordIdentity;
use secret::RecordKey;
use session::{Lookup, SessionStore};

/// Where the vault keeps its records.
///
/// One value, and it is the default: `proxy/spec.md` section 9 makes `memory` the
/// normal case and persistence the exception somebody has to ask for. The `file`
/// backend arrives in its own task, and the source scan in
/// `tests/vault_touches_no_files.rs` is what makes adding it a decision rather
/// than an edit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Storage {
    /// Process memory, for the lifetime of the process. Nothing is written
    /// anywhere, and a restart loses the mappings: that cost is declared as
    /// `masking_unresolved` rather than hidden.
    #[default]
    Memory,
}

/// What opening a vault needs.
///
/// A passphrase and a profile, and nothing else. ADR-016 section 4 struck the
/// operating system keyring from F4, so there is no passwordless path here to
/// configure; the loss is recorded in KG-020 rather than quietly filled by a key
/// file somebody leaves at mode 644.
pub struct OpenRequest<'a> {
    pub passphrase: &'a Passphrase,
    pub profile: ProfileName,
}

/// The vault.
pub struct Vault {
    master: MasterKey,
    record_key: RecordKey,
    storage: Storage,
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
    /// Derives the keys and opens an empty vault.
    ///
    /// The Argon2id salt is drawn fresh here. In `memory` mode nothing survives
    /// the process, so there is no previous salt to agree with, and a new one
    /// every time is strictly better than a stored one.
    pub fn open(request: &OpenRequest<'_>) -> Result<Self, VaultError> {
        let profile = KdfProfile::named(request.profile);
        let master = key::derive_master_key(&profile, request.passphrase, &Salt::generate()?)?;

        let mut vault = Self::from_master_key(master, SessionLimits::default())?;
        // The reduced profile is a fact about how well this vault is protected,
        // so it leaves the opening with a note attached rather than in a comment
        // somebody reads later.
        vault.notes.extend(request.profile.note());
        Ok(vault)
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
            sessions: SessionStore::new(limits),
            counters: RecordCounters::default(),
            notes: Vec::new(),
        })
    }

    pub fn storage(&self) -> Storage {
        self.storage
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
        self.sessions
            .ensure(session, now_ms, || key::derive_session_key(master, session))?
            .insert(seed, alias, sealed, ceiling)
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
        })
        .unwrap();

        assert_eq!(vault.notes().len(), 1);
        assert!(vault.notes()[0].to_string().contains("ci"));
        assert_eq!(vault.storage(), Storage::Memory);
    }

    #[test]
    fn a_vault_cannot_be_opened_without_a_passphrase() {
        let refusal = Vault::open(&OpenRequest {
            passphrase: &Passphrase::new(Vec::new()),
            profile: ProfileName::Ci,
        })
        .unwrap_err();

        assert_eq!(refusal, VaultError::PassphraseMissing);
        assert_eq!(refusal.http_status(), 503);
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
}
