//! What one request is allowed to leave behind.
//!
//! `proxy/spec.md` section 9 puts vault content outside **every** log level and
//! allows four fields at `TRACE`. This type is the whole of what a request writes,
//! and it is a type rather than a format string because task 85's criterion is
//! that the caller's API key appears at **no log level**. A format string is a
//! promise somebody keeps; a struct whose every field is a counter, an opaque
//! handle or a value from a closed vocabulary is a promise the compiler keeps.
//!
//! There is no logging framework here and this does not add one: adding a
//! dependency named in `tests/vault_no_plaintext.rs`'s guard list would fail that
//! gate on purpose, so that whoever adds a real logger extends the byte sweep in
//! the same change. What this produces is the line such a logger would emit, and
//! the sweep reads it.

use crate::detect::{DegradedReason, MaskingProfile};

use super::errors::ProxyError;
use super::session::Origin;

/// One request, as a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestRecord {
    /// Which endpoint, from the route table's own names.
    pub endpoint: &'static str,
    /// Which upstream, or none for a local endpoint.
    pub provider: Option<&'static str>,
    /// Which of `proxy/spec.md` section 2.4's three steps answered.
    pub session_origin: Origin,
    /// The opaque alias scope. Not the client's session name and not the vault's
    /// key material: the same handle `x-periskop-alias-scope` carries.
    pub alias_scope: String,
    /// Which policy generation decided this request.
    pub policy_id: String,
    /// Which layers actually ran.
    pub masking_profile: MaskingProfile,
    /// Distinct aliases minted or reused.
    pub masked_entities: u32,
    /// What this request admits it did not look for.
    pub degraded: Vec<DegradedReason>,
    /// The status the client was given.
    pub status: u16,
    /// The status the provider gave, when there was one.
    pub upstream_status: Option<u16>,
    /// The closed error value, when the request was refused.
    pub error: Option<ProxyError>,
    /// Milliseconds this proxy added.
    pub added_latency_ms: u64,
}

impl RequestRecord {
    /// Every key a log line can carry, in the order [`Self::to_line`] writes them.
    ///
    /// The same closed set device as `VaultStatus::FIELDS`, and here it is the
    /// enforcement rather than the documentation: a field added to the renderer
    /// without being added here fails `a_log_line_carries_these_keys_and_no_other`,
    /// which is the review this list exists to force.
    pub const FIELDS: &'static [&'static str] = &[
        "endpoint",
        "provider",
        "session_origin",
        "alias_scope",
        "policy_id",
        "masking_profile",
        "masked_entities",
        "degraded",
        "status",
        "upstream_status",
        "error",
        "added_latency_ms",
    ];

    /// The line.
    ///
    /// `key=value` pairs, space separated, deterministic. No request body, no
    /// header, no alias string and no original value has a field to travel in.
    pub fn to_line(&self) -> String {
        let mut degraded: Vec<&'static str> =
            self.degraded.iter().map(|reason| reason.as_str()).collect();
        degraded.sort_unstable();
        degraded.dedup();

        [
            format!("endpoint={}", self.endpoint),
            format!("provider={}", self.provider.unwrap_or("-")),
            format!("session_origin={}", self.session_origin.as_str()),
            format!("alias_scope={}", self.alias_scope),
            format!("policy_id={}", self.policy_id),
            format!("masking_profile={}", self.masking_profile.as_str()),
            format!("masked_entities={}", self.masked_entities),
            format!(
                "degraded={}",
                if degraded.is_empty() {
                    "-".to_owned()
                } else {
                    degraded.join(",")
                }
            ),
            format!("status={}", self.status),
            format!(
                "upstream_status={}",
                self.upstream_status
                    .map_or_else(|| "-".to_owned(), |status| status.to_string())
            ),
            format!("error={}", self.error.map_or("-", |error| error.as_str())),
            format!("added_latency_ms={}", self.added_latency_ms),
        ]
        .join(" ")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn record() -> RequestRecord {
        RequestRecord {
            endpoint: "chat_completions",
            provider: Some("openai"),
            session_origin: Origin::ClientHeader,
            alias_scope: "9f2c4a10bb730e5188a4d7c6e0f21a34".to_owned(),
            policy_id: "org-default".to_owned(),
            masking_profile: MaskingProfile::PatternDictionary,
            masked_entities: 4,
            degraded: vec![DegradedReason::NerDisabled],
            status: 200,
            upstream_status: Some(200),
            error: None,
            added_latency_ms: 7,
        }
    }

    #[test]
    fn a_log_line_carries_these_keys_and_no_other() {
        let line = record().to_line();
        let keys: Vec<&str> = line
            .split(' ')
            .filter_map(|pair| pair.split_once('=').map(|(key, _)| key))
            .collect();
        assert_eq!(keys, RequestRecord::FIELDS);
    }

    #[test]
    fn every_value_is_a_number_a_handle_or_a_closed_vocabulary_value() {
        // The claim in one assertion: no field holds free text. The alias scope
        // and the policy identifier are the only non-numeric, non-enum values, and
        // both are identifiers rather than content.
        for pair in record().to_line().split(' ') {
            let (_, value) = pair.split_once('=').unwrap_or_default();
            assert!(
                value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_,+.".contains(c)),
                "a log field carries something that is not an identifier: {pair}"
            );
        }
    }

    #[test]
    fn a_refusal_records_its_closed_value_and_no_detail() {
        let refused = RequestRecord {
            status: 503,
            upstream_status: None,
            error: Some(ProxyError::VaultUnavailable),
            masked_entities: 0,
            ..record()
        };
        let line = refused.to_line();
        assert!(line.contains("error=vault_unavailable"), "{line}");
        assert!(line.contains("upstream_status=-"), "{line}");
        // The detail sentence names a field and sometimes a path; it goes in the
        // response body, where a client that has to fix the request reads it, and
        // not into a line that gets aggregated.
        assert!(!line.contains("detail"), "{line}");
    }

    #[test]
    fn the_same_request_renders_the_same_line_whatever_order_reasons_arrived_in() {
        let one = RequestRecord {
            degraded: vec![
                DegradedReason::CodeBlockSkipped,
                DegradedReason::NerDisabled,
            ],
            ..record()
        };
        let other = RequestRecord {
            degraded: vec![
                DegradedReason::NerDisabled,
                DegradedReason::CodeBlockSkipped,
                DegradedReason::NerDisabled,
            ],
            ..record()
        };
        assert_eq!(one.to_line(), other.to_line());
    }
}
