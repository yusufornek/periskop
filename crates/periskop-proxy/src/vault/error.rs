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
            | Self::EntropyUnavailable
            | Self::RecordTamper
            | Self::AliasCollision => 503,
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
}
