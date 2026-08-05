//! What the vault refuses to do, and what the caller answers with.
//!
//! The status codes are part of the error rather than a mapping table somewhere
//! up the stack. `proxy/spec.md` section 10 makes fail closed the base rule: the
//! proxy does not pass data it could not mask, and a vault failure is therefore a
//! refusal rather than a degraded mode. Putting the status here means the request
//! path cannot invent a fourth answer, and the answers are pinned by tests in
//! this crate before an HTTP surface exists to give them.
//!
//! No variant carries a value from the vault. An error message is a log line and
//! a response body; personal data reaches neither (spec section 9, "Günlük
//! disiplini").

use std::fmt;

use thiserror::Error;

/// Everything the vault can refuse, and why.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultError {
    /// The vault was asked to open on nothing.
    #[error("the vault passphrase is empty; the vault stays sealed")]
    PassphraseMissing,

    /// A claimed Argon2id parameter is outside the hard bounds.
    ///
    /// Carries the numbers because they came from the caller or from a file
    /// header, and an operator who mistyped a profile needs to see which bound
    /// they crossed. Parameters are not secret; the passphrase they would have
    /// been used on is, and it is not here.
    #[error(
        "Argon2id {parameter} of {claimed} is outside the allowed range {floor}..={ceiling}; the vault stays sealed"
    )]
    KdfParameterOutOfRange {
        parameter: &'static str,
        claimed: u32,
        floor: u32,
        ceiling: u32,
    },

    /// Argon2id or HKDF refused the inputs it was handed.
    ///
    /// Deliberately opaque: the inputs are the passphrase and the salt, and an
    /// error that explains which one was wrong explains it to whoever is guessing.
    #[error("the vault key could not be derived; the vault stays sealed")]
    KeyDerivationFailed,

    /// The record cipher refused, with the key already derived and in hand.
    ///
    /// Deliberately not [`VaultError::KeyDerivationFailed`], which is what this
    /// used to be reported as. By the time a seal can fail the derivation has
    /// already succeeded, so the only remaining causes are an output buffer that
    /// could not be produced or a length invariant inside the cipher. An operator
    /// who reads "the vault key could not be derived" retypes and re-enters a
    /// passphrase that is the one part of the system already known to work, and a
    /// refusal that names the wrong remedy is slower to resolve than one that
    /// names none. Carries the stage rather than the value: what was being sealed
    /// is a plaintext and never appears here.
    #[error(
        "the vault could not run its record cipher while {stage}; the key was already in hand, so this is a buffer or memory failure; the vault stays sealed"
    )]
    SealFailed { stage: &'static str },

    /// The operating system would not give us random bytes.
    ///
    /// A refusal rather than a fallback. A nonce from a weaker source is the one
    /// failure this cipher choice was made to rule out (ADR-007, D-14).
    #[error("the operating system entropy source is unavailable; the vault stays sealed")]
    EntropyUnavailable,

    /// A record did not authenticate under the identity it was opened with.
    ///
    /// This is D-10 finding 37's regression lock. A record whose sealed body was
    /// swapped with another record's decrypts to somebody else's personal data,
    /// and the AAD binding turns that from a silent substitution into this error.
    /// The value is never handed to the caller, not even partially.
    #[error("a vault record failed authentication; it was not sealed under this identity")]
    RecordTamper,

    /// Two different values inside one session claim the same alias string, or
    /// one value claims two.
    ///
    /// Only a defective alias generator produces either, and the type preserving
    /// generators work in output spaces small enough that it is possible rather
    /// than impossible. The refusal is loud because the alternative is silent and
    /// worse: a restore that hands the user a different entity's value under an
    /// alias they were shown, which is D-10 finding 37 arriving through the front
    /// door instead of through a tampered file.
    #[error("this session already published this alias for a different value")]
    AliasCollision,

    /// The session hit its alias ceiling.
    ///
    /// Named with the limit, because "too many" without a number is a bug report
    /// nobody can act on (spec section 10: 429 plus which limit was crossed).
    #[error("this session already holds its ceiling of {ceiling} aliases")]
    AliasCeilingReached { ceiling: usize },

    /// The vault file did not survive its integrity check.
    ///
    /// One error for the three shapes of the same attack, because they end the
    /// same way: `proxy/spec.md` section 10 answers all three with 503, the vault
    /// stays sealed and **no recovery is attempted**. The distinction is carried
    /// in [`Integrity`] rather than in three error variants so that the value
    /// `GET /admin/vault/status` reports and the value the refusal carries cannot
    /// drift apart.
    #[error("the vault file failed its integrity check ({integrity}); the vault stays sealed and is not repaired")]
    IntegrityFailed { integrity: Integrity },

    /// The bytes on disk are not a `vault.psk` this build can read at all.
    ///
    /// Separate from [`VaultError::IntegrityFailed`] on purpose: a truncated or
    /// corrupt header is not one of the three integrity violations the contract
    /// enumerates, and reporting it as one would put a value in
    /// `/admin/vault/status` that did not happen. Both refuse with 503.
    #[error(
        "the vault file is not readable: the {field} field is malformed; the vault stays sealed"
    )]
    VaultFileMalformed { field: VaultField },

    /// The file is well formed but declares something this build does not
    /// implement.
    #[error(
        "the vault file declares an unsupported {field} ({found}); the vault stays sealed rather than guessing"
    )]
    VaultFileUnsupported { field: VaultField, found: u32 },

    /// The operating system refused a read, a write or a rename.
    ///
    /// Carries what was being attempted and the operating system's own category,
    /// and never the path: a path is not secret but it is noise in a log line, and
    /// the caller knows which vault it asked for.
    #[error("the vault file could not be {operation}: {cause}; the vault stays sealed")]
    VaultFileUnavailable {
        operation: &'static str,
        cause: String,
    },
}

/// Which of the three violations ADR-007 section 3 and 4 name.
///
/// The values are the ones `proxy-api.md` fixes for `GET /admin/vault/status`, and
/// this enum is their only definition in this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Integrity {
    /// Nothing is wrong, which is the only value a `memory` vault ever reports.
    Ok,
    /// The chain over the records does not end where the header says it does: a
    /// record was removed, edited, reordered, truncated away or appended.
    ChainMismatch,
    /// The file's record counter is below one this process has already seen, which
    /// is what restoring an older copy of the vault looks like.
    CounterRollback,
    /// The header did not authenticate under the key its own parameters derive,
    /// which is what weakening the Argon2id parameters looks like.
    HeaderMacFailed,
}

impl Integrity {
    /// The wire value (`proxy-api.md`, `GET /admin/vault/status`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::ChainMismatch => "chain_mismatch",
            Self::CounterRollback => "counter_rollback",
            Self::HeaderMacFailed => "header_mac_failed",
        }
    }
}

impl fmt::Display for Integrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which field of the file format was wrong.
///
/// Named rather than numbered because the message reaches an operator looking at
/// a vault that will not open, and "byte 10" is not something they can act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultField {
    Magic,
    LayoutVersion,
    KdfAlgorithm,
    Aead,
    HeaderLength,
    HeaderReserved,
    FrameVersion,
    FrameLength,
    FrameReserved,
    RecordType,
    AliasLength,
    Alias,
    BodyLength,
}

impl fmt::Display for VaultField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Magic => "magic",
            Self::LayoutVersion => "layout version",
            Self::KdfAlgorithm => "key derivation algorithm",
            Self::Aead => "aead",
            Self::HeaderLength => "header length",
            Self::HeaderReserved => "header reserved",
            Self::FrameVersion => "frame version",
            Self::FrameLength => "frame length",
            Self::FrameReserved => "frame reserved",
            Self::RecordType => "record type",
            Self::AliasLength => "alias length",
            Self::Alias => "alias",
            Self::BodyLength => "sealed body length",
        })
    }
}

impl VaultError {
    /// The status the request path answers with (`proxy/spec.md` section 10).
    ///
    /// Two answers and no third. 503 is the fail closed refusal: the vault is not
    /// usable, so no request is. 429 is the one case that is about this caller
    /// rather than the vault, and it is deliberately not 503: a session that has
    /// filled up is a client that should slow down or start a new session, not a
    /// server that has broken.
    ///
    /// There is no 200 path out of this type. Silent data loss is the failure
    /// mode this whole component exists to make impossible, so an error that
    /// could be answered with a success would be the bug.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::AliasCeilingReached { .. } => 429,
            Self::PassphraseMissing
            | Self::KdfParameterOutOfRange { .. }
            | Self::KeyDerivationFailed
            | Self::SealFailed { .. }
            | Self::EntropyUnavailable
            | Self::RecordTamper
            | Self::AliasCollision
            | Self::IntegrityFailed { .. }
            | Self::VaultFileMalformed { .. }
            | Self::VaultFileUnsupported { .. }
            | Self::VaultFileUnavailable { .. } => 503,
        }
    }

    /// The value `GET /admin/vault/status` reports after this refusal.
    ///
    /// `None` for every failure that is not one of the three the contract
    /// enumerates. A truncated header is a real failure and it is still not a
    /// `chain_mismatch`; answering with one would put a fact in the operator's
    /// dashboard that did not happen.
    pub fn integrity(&self) -> Option<Integrity> {
        match self {
            Self::IntegrityFailed { integrity } => Some(*integrity),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_vault_failure_answers_503_except_the_alias_ceiling() {
        // Spec section 10, row by row. Written as an explicit list rather than a
        // property so that a new variant has to be added here on purpose.
        assert_eq!(VaultError::PassphraseMissing.http_status(), 503);
        assert_eq!(VaultError::KeyDerivationFailed.http_status(), 503);
        assert_eq!(
            VaultError::SealFailed { stage: "sealing" }.http_status(),
            503
        );
        assert_eq!(VaultError::EntropyUnavailable.http_status(), 503);
        assert_eq!(VaultError::RecordTamper.http_status(), 503);
        assert_eq!(VaultError::AliasCollision.http_status(), 503);
        assert_eq!(
            VaultError::KdfParameterOutOfRange {
                parameter: "memory",
                claimed: 1,
                floor: 2,
                ceiling: 3,
            }
            .http_status(),
            503
        );
        assert_eq!(
            VaultError::AliasCeilingReached { ceiling: 10_000 }.http_status(),
            429
        );
    }

    #[test]
    fn the_alias_ceiling_refusal_says_which_limit_was_crossed() {
        let rendered = VaultError::AliasCeilingReached { ceiling: 10_000 }.to_string();
        assert!(rendered.contains("10000"), "{rendered}");
    }

    /// Spec section 10's integrity row: all three violations are 503.
    #[test]
    fn all_three_integrity_violations_answer_503_and_name_themselves() {
        for integrity in [
            Integrity::ChainMismatch,
            Integrity::CounterRollback,
            Integrity::HeaderMacFailed,
        ] {
            let refusal = VaultError::IntegrityFailed { integrity };
            assert_eq!(refusal.http_status(), 503, "{integrity:?}");
            assert_eq!(refusal.integrity(), Some(integrity));
            let rendered = refusal.to_string();
            assert!(rendered.contains(integrity.as_str()), "{rendered}");
            // The refusal has to say that nothing was repaired, because a vault
            // that opened halfway is more dangerous than one that did not open.
            assert!(rendered.contains("not repaired"), "{rendered}");
        }
    }

    /// The four values `proxy-api.md` fixes for the status endpoint, spelled the
    /// way the contract spells them.
    #[test]
    fn the_integrity_vocabulary_is_the_contract_vocabulary() {
        assert_eq!(Integrity::Ok.as_str(), "ok");
        assert_eq!(Integrity::ChainMismatch.as_str(), "chain_mismatch");
        assert_eq!(Integrity::CounterRollback.as_str(), "counter_rollback");
        assert_eq!(Integrity::HeaderMacFailed.as_str(), "header_mac_failed");
    }

    /// A file problem that is not one of the three has no integrity value.
    #[test]
    fn a_malformed_file_is_503_but_is_not_one_of_the_three_violations() {
        let refusal = VaultError::VaultFileMalformed {
            field: VaultField::Magic,
        };
        assert_eq!(refusal.http_status(), 503);
        assert_eq!(refusal.integrity(), None);
        assert!(refusal.to_string().contains("magic"));

        let unsupported = VaultError::VaultFileUnsupported {
            field: VaultField::LayoutVersion,
            found: 2000,
        };
        assert_eq!(unsupported.http_status(), 503);
        assert_eq!(unsupported.integrity(), None);
    }

    /// The two refusals an operator must not confuse, side by side.
    ///
    /// One of them means "the passphrase or the profile is wrong"; the other means
    /// "the key was fine and the machine could not finish the work". They were the
    /// same variant once, and the first sentence an operator read pointed at the
    /// only component that had already proved itself healthy.
    #[test]
    fn a_seal_failure_and_a_derivation_failure_name_different_remedies() {
        let derivation = VaultError::KeyDerivationFailed.to_string();
        let seal = VaultError::SealFailed {
            stage: "sealing a record body",
        };

        assert_eq!(seal.integrity(), None);
        let rendered = seal.to_string();
        assert_ne!(rendered, derivation);
        assert!(rendered.contains("sealing a record body"), "{rendered}");
        assert!(rendered.contains("buffer or memory"), "{rendered}");
        // The words that send an operator to the passphrase belong to the other
        // refusal and to nothing else.
        assert!(!rendered.contains("could not be derived"), "{rendered}");
        assert!(!rendered.contains("passphrase"), "{rendered}");
    }

    #[test]
    fn a_file_that_cannot_be_read_says_what_was_being_attempted() {
        let refusal = VaultError::VaultFileUnavailable {
            operation: "opened",
            cause: "permission denied".to_owned(),
        };
        assert_eq!(refusal.http_status(), 503);
        let rendered = refusal.to_string();
        assert!(rendered.contains("opened"), "{rendered}");
        assert!(rendered.contains("permission denied"), "{rendered}");
    }
}
