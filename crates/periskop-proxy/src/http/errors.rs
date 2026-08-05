//! The closed error vocabulary, and the fail closed matrix that maps onto it.
//!
//! `proxy-api.md` fixes ten values for `x-periskop-error` and the HTTP status each
//! one carries; `proxy/spec.md` section 10 is the same decision written as a table
//! of situations. Neither is reproduced by hand at a call site: a refusal is
//! constructed as one of these variants, and the status and the header value are
//! read off it. That is what keeps "a vault failure is 503, a quota is 429" from
//! being a rule each handler remembers separately.
//!
//! The two values are deliberately not free text. `proxy-api.md`'s writing rule
//! (K-09 generalised) says a header value drawn from a closed vocabulary is
//! `snake_case` and identical to the enum it came from, so the enum is the source
//! and [`ProxyError::as_str`] is the only renderer.

use std::fmt;

use crate::vault::VaultError;

/// Every value `x-periskop-error` may carry.
///
/// A refusal that is not one of these has no header value, which is the point: a
/// client branching on this header must be able to write a total match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProxyError {
    /// The vault could not be opened, was never opened, or access to it was lost.
    VaultUnavailable,
    /// Chain MAC, record counter or header MAC verification failed.
    VaultIntegrityFailed,
    /// A record's AAD or tag did not verify.
    VaultRecordTamper,
    /// The policy would not load, or its `policy_hash` did not agree.
    PolicyUnloadable,
    /// Alias derivation collided and the counter ladder found no free name.
    AliasCollisionUnresolved,
    /// This session's alias ceiling was reached.
    AliasLimitExceeded,
    /// An entity was found under `mode = "block"`.
    EntityBlocked,
    /// The request body would not parse.
    BodyUnparsable,
    /// An endpoint or a field this build does not implement.
    EndpointUnsupported,
    /// `tool_call_policy = "reject"` and a structured argument was present.
    ToolArgumentsRejected,
}

impl ProxyError {
    /// The whole vocabulary, so that a test can assert over it rather than over a
    /// list somebody retyped.
    pub const ALL: [Self; 10] = [
        Self::VaultUnavailable,
        Self::VaultIntegrityFailed,
        Self::VaultRecordTamper,
        Self::PolicyUnloadable,
        Self::AliasCollisionUnresolved,
        Self::AliasLimitExceeded,
        Self::EntityBlocked,
        Self::BodyUnparsable,
        Self::EndpointUnsupported,
        Self::ToolArgumentsRejected,
    ];

    /// The `x-periskop-error` value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VaultUnavailable => "vault_unavailable",
            Self::VaultIntegrityFailed => "vault_integrity_failed",
            Self::VaultRecordTamper => "vault_record_tamper",
            Self::PolicyUnloadable => "policy_unloadable",
            Self::AliasCollisionUnresolved => "alias_collision_unresolved",
            Self::AliasLimitExceeded => "alias_limit_exceeded",
            Self::EntityBlocked => "entity_blocked",
            Self::BodyUnparsable => "body_unparsable",
            Self::EndpointUnsupported => "endpoint_unsupported",
            Self::ToolArgumentsRejected => "tool_arguments_rejected",
        }
    }

    /// The status `proxy-api.md`'s table gives this value.
    ///
    /// 429 belongs to the alias ceiling and to nothing else. Section 10 spends a
    /// paragraph on why: a ceiling is a quota, the vault is intact and retrying is
    /// the caller's correct move, while every vault failure means stop and look.
    /// One status for both would erase that difference, and a retried integrity
    /// violation is a security event nobody sees.
    pub const fn status(self) -> u16 {
        match self {
            Self::AliasLimitExceeded => 429,
            Self::VaultUnavailable
            | Self::VaultIntegrityFailed
            | Self::VaultRecordTamper
            | Self::PolicyUnloadable
            | Self::AliasCollisionUnresolved => 503,
            Self::EntityBlocked
            | Self::BodyUnparsable
            | Self::EndpointUnsupported
            | Self::ToolArgumentsRejected => 400,
        }
    }
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The vault's refusals, translated once.
///
/// Written here rather than beside the vault so that the vault stays a library
/// with no opinion about HTTP, and so that the mapping is a single readable match
/// instead of a status number chosen at each of a dozen call sites.
impl From<&VaultError> for ProxyError {
    fn from(refusal: &VaultError) -> Self {
        match refusal {
            VaultError::AliasCeilingReached { .. } => Self::AliasLimitExceeded,
            VaultError::AliasCollision => Self::AliasCollisionUnresolved,
            VaultError::RecordTamper => Self::VaultRecordTamper,
            VaultError::IntegrityFailed { .. } => Self::VaultIntegrityFailed,
            // Everything else a vault can refuse with means the vault cannot be
            // used: no passphrase, no entropy, parameters out of range, a cipher
            // that could not produce a sealed body, a file that will not open or
            // does not have this layout. All of them are "stop and fix the
            // environment", which is what `vault_unavailable` tells a caller, and
            // it is the row `proxy/spec.md` section 10 puts them in. A corrupt
            // file belongs here rather than under `vault_integrity_failed`: that
            // value's row says "durdur ve incele" and is reserved for the three
            // violations section 9 enumerates.
            _ => Self::VaultUnavailable,
        }
    }
}

/// A refusal, and the one sentence that says which field caused it.
///
/// The detail never reaches a header. `proxy-api.md`'s last line about these
/// headers is that they carry counters, identifiers and closed vocabulary values
/// and never the masked value or its original; a field **name** is neither, so it
/// travels in the body where section 10's "400 + hangi alanın desteklenmediği"
/// can be satisfied without widening what a header may hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    error: ProxyError,
    detail: String,
}

impl Refusal {
    pub fn new(error: ProxyError, detail: impl Into<String>) -> Self {
        Self {
            error,
            detail: detail.into(),
        }
    }

    /// A refusal with nothing more to say than its own name.
    pub fn bare(error: ProxyError) -> Self {
        Self::new(error, error.as_str())
    }

    pub const fn error(&self) -> ProxyError {
        self.error
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }

    pub const fn status(&self) -> u16 {
        self.error.status()
    }

    /// The response body: the closed value, and the field that caused it.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"error\":\"{}\",\"detail\":{}}}",
            self.error.as_str(),
            super::json::quote(&self.detail)
        )
    }
}

impl From<VaultError> for Refusal {
    fn from(refusal: VaultError) -> Self {
        let error = ProxyError::from(&refusal);
        // The vault's own message, which `vault/error.rs` writes without any record
        // content in it. `tests/vault_no_plaintext.rs` scans every refusal message
        // for planted values, so this is a surface that gate already covers.
        Self::new(error, refusal.to_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Every value in `proxy-api.md`'s closed dictionary, with the status the
    /// table gives it, transcribed once here so that a change to the enum has to
    /// disagree with the contract out loud.
    const CONTRACT: &[(&str, u16)] = &[
        ("vault_unavailable", 503),
        ("vault_integrity_failed", 503),
        ("vault_record_tamper", 503),
        ("policy_unloadable", 503),
        ("alias_collision_unresolved", 503),
        ("alias_limit_exceeded", 429),
        ("entity_blocked", 400),
        ("body_unparsable", 400),
        ("endpoint_unsupported", 400),
        ("tool_arguments_rejected", 400),
    ];

    #[test]
    fn the_vocabulary_is_the_contract_s_and_holds_no_eleventh_value() {
        let mine: Vec<(&str, u16)> = ProxyError::ALL
            .into_iter()
            .map(|error| (error.as_str(), error.status()))
            .collect();
        assert_eq!(mine, CONTRACT);
    }

    #[test]
    fn every_value_is_snake_case_as_the_writing_rule_requires() {
        // K-09 generalised: the header name is kebab, the value is snake, and the
        // value is identical to the enum it came from. `vault-unavailable` shipped
        // once in an older revision of the contract and a client branching on it
        // matched in one version and silently did not in the next.
        for error in ProxyError::ALL {
            let value = error.as_str();
            assert!(
                value
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
                "{value} is not snake_case"
            );
            assert!(!value.contains('-'), "{value} carries a kebab separator");
        }
    }

    #[test]
    fn only_the_alias_ceiling_is_a_quota() {
        // Section 10's rule in one assertion: 429 belongs to the ceiling and to
        // nothing else, and every vault failure is 503.
        let quotas: Vec<ProxyError> = ProxyError::ALL
            .into_iter()
            .filter(|error| error.status() == 429)
            .collect();
        assert_eq!(quotas, vec![ProxyError::AliasLimitExceeded]);
    }

    #[test]
    fn a_vault_refusal_keeps_the_class_the_vault_gave_it() {
        let cases = [
            (
                VaultError::AliasCeilingReached { ceiling: 10_000 },
                ProxyError::AliasLimitExceeded,
                429,
            ),
            (
                VaultError::AliasCollision,
                ProxyError::AliasCollisionUnresolved,
                503,
            ),
            (VaultError::RecordTamper, ProxyError::VaultRecordTamper, 503),
            (
                VaultError::IntegrityFailed {
                    integrity: crate::vault::Integrity::CounterRollback,
                },
                ProxyError::VaultIntegrityFailed,
                503,
            ),
            (
                VaultError::PassphraseMissing,
                ProxyError::VaultUnavailable,
                503,
            ),
            (
                VaultError::EntropyUnavailable,
                ProxyError::VaultUnavailable,
                503,
            ),
            // A cipher that could not seal, and a file whose frames do not parse.
            // Both are outages rather than intrusions, and neither may borrow
            // `vault_integrity_failed`, whose row instructs an operator to stop
            // and investigate a break-in.
            (
                VaultError::SealFailed {
                    stage: "sealing a record body",
                },
                ProxyError::VaultUnavailable,
                503,
            ),
            (
                VaultError::VaultFileMalformed {
                    field: crate::vault::VaultField::FrameLength,
                },
                ProxyError::VaultUnavailable,
                503,
            ),
        ];

        for (refusal, expected, status) in cases {
            // The vault's own status and the proxy's have to agree, or the same
            // failure would be a quota on one side and an outage on the other.
            assert_eq!(refusal.http_status(), status, "{refusal:?}");
            let translated = Refusal::from(refusal);
            assert_eq!(translated.error(), expected);
            assert_eq!(translated.status(), status);
        }
    }

    #[test]
    fn the_body_says_which_field_and_the_value_stays_closed() {
        let refusal = Refusal::new(ProxyError::EndpointUnsupported, "body field \"audio\"");
        let json = refusal.to_json();
        assert!(
            json.contains("\"error\":\"endpoint_unsupported\""),
            "{json}"
        );
        // Escaped, because the detail names a field an operator or a client chose.
        assert!(
            json.contains(r#""detail":"body field \"audio\"""#),
            "{json}"
        );
    }
}
