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
use super::event::Measurement;
use super::session::Origin;
use super::stream::{Measured, Warning};

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
    /// What the response side measured: counters only, and the same counters
    /// `proxy-events.md` names. No alias string and no value has a field here,
    /// which is why this whole struct can be written to a log line.
    pub measured: Measured,
    /// What the **request** side measured: per type counts and two phase
    /// durations, for the event record.
    ///
    /// Not on the line, and that is the split rather than an oversight. A line is
    /// flat, one key per field, and these are nested aggregates; folding them in
    /// would turn `to_line` into a place somebody could add a per type map. What
    /// reads this is [`super::event::ProxyEvent`], and the byte sweep searches
    /// both surfaces.
    pub measurement: Measurement,
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
        "stream_chunks",
        "hold_timeout_flush",
        "partial_alias_flushed",
        "aliases_seen_in_response",
        "aliases_restored",
        "aliases_leaked",
        "warn",
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
            format!("stream_chunks={}", self.measured.stream.chunks),
            format!(
                "hold_timeout_flush={}",
                self.measured.stream.hold_timeout_flush
            ),
            format!(
                "partial_alias_flushed={}",
                self.measured.stream.partial_alias_flushed
            ),
            format!(
                "aliases_seen_in_response={}",
                self.measured.restore.aliases_seen_in_response
            ),
            format!(
                "aliases_restored={}",
                self.measured.restore.aliases_restored
            ),
            format!("aliases_leaked={}", self.measured.restore.aliases_leaked),
            format!("warn={}", render_warnings(&self.measured.warnings())),
        ]
        .join(" ")
    }

    /// The counters that crossed the line `proxy-events.md` draws under them.
    ///
    /// A WARN is not a log level here, it is a named counter that went above
    /// zero, and it is on the line so that a run cannot be read as clean when it
    /// was not.
    pub fn warnings(&self) -> Vec<Warning> {
        self.measured.warnings()
    }
}

fn render_warnings(warnings: &[Warning]) -> String {
    if warnings.is_empty() {
        return "-".to_owned();
    }
    warnings
        .iter()
        .map(|warning| warning.as_str())
        .collect::<Vec<&str>>()
        .join(",")
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
            measured: Measured::default(),
            measurement: Measurement::default(),
        }
    }

    #[test]
    fn a_warning_counter_is_on_the_line_and_a_clean_run_says_so() {
        // Task 92 and 93 both require a WARN that is not silent. The line is the
        // surface it appears on, and a run with nothing wrong has to be readable
        // as such or the marker means nothing.
        assert!(
            record().to_line().contains("warn=-"),
            "{}",
            record().to_line()
        );

        let mut measured = Measured::default();
        measured.stream.partial_alias_flushed = 1;
        measured.restore.aliases_leaked = 2;
        let noisy = RequestRecord {
            measured,
            ..record()
        };
        assert!(
            noisy
                .to_line()
                .contains("warn=partial_alias_flushed,aliases_leaked"),
            "{}",
            noisy.to_line()
        );
        assert_eq!(
            noisy.warnings(),
            vec![Warning::PartialAliasFlushed, Warning::AliasesLeaked]
        );
        assert!(
            noisy.to_line().contains("aliases_leaked=2"),
            "{}",
            noisy.to_line()
        );
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
