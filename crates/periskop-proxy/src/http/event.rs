//! `ProxyEvent`: the deterministic measurement record for one request and
//! response pair.
//!
//! # The one constraint, and where it is enforced
//!
//! `proxy-events.md` opens with it: **this record carries no value.** Not the
//! text a user wrote, not the alias that replaced it, not a prompt fragment and
//! not a byte of vault content. Types, counts, ladder rungs and durations, and
//! nothing else. `proxy-api.md` says the same thing about the headers this record
//! feeds: they carry "sayaç, kimlik ve kapalı sözlük değeri".
//!
//! That constraint is enforced in three places rather than by review, and this
//! module is only the first of them:
//!
//! 1. **Here.** [`ProxyEvent`] is built field by field from a literal list. There
//!    is no `Serialize` derive, so "what this record holds" cannot drift into
//!    "whatever the struct happens to hold today", and the two types it is built
//!    from ([`MaskedType`], [`AllowedType`]) have no field a string of user text
//!    could travel in.
//! 2. **The schema.** `schemas/proxy-event.schema.json` is
//!    `additionalProperties: false` at every level, so a field that carried a
//!    value would be rejected by a validator rather than by a reader.
//!    `tests/proxy_event.rs` checks the produced record against that file rather
//!    than against a copy of it.
//! 3. **The byte sweep.** `tests/vault_no_plaintext.rs` renders this record for a
//!    request whose body was full of planted values and searches every byte of it
//!    for each one, in both Argon2id profiles.
//!
//! # Local, and with no code path out
//!
//! `proxy-events.md`: "Olay kayıtları hiçbir koşulda dışarı gönderilmez." The
//! enforcement is structural. Three files under `src/` name this type in code:
//! this one, [`super::gateway`], which builds it and keeps it, and the module
//! tree that re-exports it. It has no method that takes an
//! [`super::upstream::Upstream`] or builds a [`super::upstream::Call`], and
//! `tests/proxy_event.rs` fails the moment a fourth source file learns its name.
//! Whoever wires it into something that sends has to widen that list in the same
//! commit, which is the change that has to be read rather than merged.
//!
//! # No wall clock
//!
//! The body carries no timestamp (`proxy-events.md`, "Determinizm"), durations
//! are whole milliseconds, and every duration is read off the gateway's injected
//! clock. A run with a fixed clock therefore produces a byte identical record for
//! a byte identical request, which is what makes the determinism claim a test
//! rather than an intention.

use serde_json::{json, Value};

use crate::alias::mint::AliasStats;
use crate::alias::AliasStyle;
use crate::detect::{DegradedReason, DetectionLayer, MaskingProfile};

use super::request_path::{AllowedType, MaskedType};
use super::stream::hold_timeout::StreamStats;
use super::stream::restore::RestoreStats;

/// `MAJOR.MINOR`, as ADR-006 fixes it. Three segment semver is not used.
pub const SCHEMA_VERSION: &str = "1.0";

/// What the masking pass measured, beyond the counters the log line carries.
///
/// Separate from [`super::observe::RequestRecord`] rather than folded into it:
/// the record is a **line**, one flat key per field, and these are nested
/// aggregates. Keeping them apart is what stops somebody adding a per type map
/// to a log line by accident.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Measurement {
    /// Occurrences replaced, per type.
    pub masked: Vec<MaskedType>,
    /// Occurrences that crossed unmasked because a rule said so, per type.
    pub allowed: Vec<AllowedType>,
    /// Distinct aliases this request produced, with their rungs.
    pub aliases: AliasStats,
    /// `latency_ms.detect`.
    pub detect_ms: u64,
    /// `latency_ms.alias`.
    pub alias_ms: u64,
}

/// Everything one event record is built from.
///
/// A struct rather than eleven arguments, and borrowed rather than owned, so that
/// building the record cannot clone a body by accident.
pub struct Parts<'a> {
    pub session_scope: &'a str,
    pub policy_version: &'a str,
    pub policy_hash: &'a str,
    pub ruleset_hash: String,
    pub masking_profile: MaskingProfile,
    pub alias_style: AliasStyle,
    pub measurement: &'a Measurement,
    pub stream: StreamStats,
    pub restore: RestoreStats,
    pub record_tamper: u32,
    pub degraded: &'a [DegradedReason],
    /// The whole of what this proxy added, end to end (`latency_ms.total`).
    pub total_ms: u64,
}

/// One request and response pair, measured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyEvent {
    schema_version: &'static str,
    session_scope: String,
    policy_version: String,
    policy_hash: String,
    ruleset_hash: String,
    masking_profile: MaskingProfile,
    alias_style: AliasStyle,
    masked: Vec<MaskedType>,
    allowed: Vec<AllowedType>,
    detect_ms: u64,
    alias_ms: u64,
    total_ms: u64,
    stream: StreamStats,
    aliases: AliasStats,
    restore: RestoreStats,
    record_tamper: u32,
    degraded: Vec<DegradedReason>,
}

impl ProxyEvent {
    /// Builds the record, or refuses to.
    ///
    /// `None` when the request never reached a conversation: an administrative
    /// endpoint, a route that did not resolve, a body that would not parse. Those
    /// are requests and they are not request **and response pairs** in the sense
    /// this record measures, and the schema says so in the one field they cannot
    /// fill: `session_scope` has `minLength: 1`, because a measurement that
    /// cannot name the conversation it belongs to cannot be compared with any
    /// other measurement.
    ///
    /// Refused here rather than at the call site so that no caller can decide to
    /// write a placeholder. Nothing is lost by the refusal: every request,
    /// including these, still leaves a [`super::observe::RequestRecord`].
    pub fn of(parts: &Parts<'_>) -> Option<Self> {
        if parts.session_scope.is_empty() {
            return None;
        }
        let mut degraded: Vec<DegradedReason> = parts.degraded.to_vec();
        degraded.sort_unstable();
        degraded.dedup();

        Some(Self {
            schema_version: SCHEMA_VERSION,
            session_scope: parts.session_scope.to_owned(),
            policy_version: parts.policy_version.to_owned(),
            policy_hash: parts.policy_hash.to_owned(),
            ruleset_hash: parts.ruleset_hash.clone(),
            masking_profile: parts.masking_profile,
            alias_style: parts.alias_style,
            masked: parts.measurement.masked.clone(),
            allowed: parts.measurement.allowed.clone(),
            detect_ms: parts.measurement.detect_ms,
            alias_ms: parts.measurement.alias_ms,
            total_ms: parts.total_ms,
            stream: parts.stream,
            aliases: parts.measurement.aliases.clone(),
            restore: parts.restore,
            record_tamper: parts.record_tamper,
            degraded,
        })
    }

    /// The counters `proxy-events.md` draws a WARN under.
    ///
    /// The same four the contract's table names, plus the two the response path
    /// already reports through [`super::stream::Warning`]. Exposed so a caller
    /// cannot read a run as clean by looking at the wrong field.
    pub fn warnings(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.stream.partial_alias_flushed > 0 {
            out.push("partial_alias_flushed");
        }
        if self.restore.aliases_leaked > 0 {
            out.push("aliases_leaked");
        }
        if self.record_tamper > 0 {
            out.push("vault_record_tamper");
        }
        if self.aliases.alias_pool_exhausted > 0 {
            out.push("alias_pool_exhausted");
        }
        out
    }

    /// The record as the JSON document the schema describes.
    ///
    /// Key order is ASCII, not insertion order: `report-schema.md`'s
    /// deterministic serialisation rule 1 forbids the library default, and
    /// `serde_json`'s map is a `BTreeMap`, so the ordering is a property of the
    /// type rather than of the code below.
    pub fn to_value(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "session_scope": self.session_scope,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "ruleset_hash": self.ruleset_hash,
            "masking_profile": self.masking_profile.as_str(),
            "alias_style": self.alias_style.as_str(),
            "entities_masked": self
                .masked
                .iter()
                .map(|entry| json!({
                    "type": entry.entity.tag(),
                    "count": entry.count,
                    "layer": entry.layer.as_str(),
                    "confidence_bucket": confidence_bucket(entry.layer),
                }))
                .collect::<Vec<Value>>(),
            "entities_allowed": self
                .allowed
                .iter()
                .map(|entry| json!({
                    "type": entry.entity.tag(),
                    "count": entry.count,
                    "rule_scope": entry.rule_scope,
                }))
                .collect::<Vec<Value>>(),
            // Empty, and empty is the honest answer rather than an omission. The
            // list holds NER candidates that fell below the threshold, and F4's
            // scope boundary 1 forbids the layer's code path outright, so there
            // is no scorer, no threshold and nothing that fell under one.
            // `degraded_reasons[]` carries `ner_disabled` on every request, which
            // is where a reader learns why this is empty.
            "unmasked_candidates": Vec::<Value>::new(),
            "latency_ms": {
                "detect": self.detect_ms,
                "alias": self.alias_ms,
                "stream_hold_total": self.stream.hold_total_ms,
                "total": self.total_ms,
                // `derived_date_scan` is deliberately absent rather than zero.
                // The schema makes it optional for this exact reason: it is
                // populated only under `date_policy = "shift"`, which this build
                // refuses to load, and a zero would read as a scan that ran and
                // found nothing.
            },
            "stream_stats": {
                "chunks": self.stream.chunks,
                "hold_events": self.stream.hold_events,
                "hold_timeout_flush": self.stream.hold_timeout_flush,
                "hold_timeout_flush_depth_max": self.stream.hold_timeout_flush_depth_max,
                "partial_alias_flushed": self.stream.partial_alias_flushed,
                "max_buffer_bytes": self.stream.max_buffer_bytes,
                "l_max_static": self.stream.l_max_static,
                "l_max_session": self.stream.l_max_session,
            },
            "alias_stats": {
                "by_type": self
                    .aliases
                    .by_type
                    .iter()
                    .map(|(entity, stat)| {
                        (
                            entity.tag().to_owned(),
                            json!({
                                "count": stat.count,
                                "ladder_rung": stat.ladder_rung.as_str(),
                            }),
                        )
                    })
                    .collect::<serde_json::Map<String, Value>>(),
                "alias_pool_exhausted": self.aliases.alias_pool_exhausted,
                "alias_length_class_capped": self.aliases.alias_length_class_capped,
            },
            "restore_stats": {
                "aliases_seen_in_response": self.restore.aliases_seen_in_response,
                "aliases_restored": self.restore.aliases_restored,
                "aliases_leaked": self.restore.aliases_leaked,
            },
            // Always zero in this build, and zero is right here where it would be
            // wrong for `derived_date_scan`: the field counts dates the restore
            // table could not account for, and with `shift` unimplemented there
            // are none. The schema requires the field, so the honest value is the
            // count, not an omission.
            "derived_dates_seen": 0,
            "vault_record_tamper": self.record_tamper,
            "degraded_reasons": self
                .degraded
                .iter()
                .map(|reason| reason.as_str())
                .collect::<Vec<&str>>(),
        })
    }

    /// The record as a document on disk: two space indent, one trailing newline.
    ///
    /// `report-schema.md` deterministic serialisation rule 5.
    pub fn to_json(&self) -> String {
        let mut out = serde_json::to_string_pretty(&self.to_value())
            // A `Value` built from numbers and strings a line above. There is no
            // input that makes this fail, and an `unwrap` here would be a panic in
            // production code, which this crate denies.
            .unwrap_or_else(|_| self.to_value().to_string());
        out.push('\n');
        out
    }
}

/// Which confidence bucket a layer's finding falls in.
///
/// Total by construction, and two of the three arms are the same answer for the
/// same reason: layer A decides with a regular expression plus a published check
/// digit rule, and layer B with an exact entry in a list somebody wrote. Neither
/// produces a score, so neither has anything to bucket, and `deterministic` is
/// the bucket `proxy-event.schema.json` provides for exactly that.
const fn confidence_bucket(layer: DetectionLayer) -> &'static str {
    match layer {
        DetectionLayer::Pattern | DetectionLayer::Dictionary => "deterministic",
        // Unreachable in this build rather than unlikely:
        // `detect::owning_layer` maps every registered type to A or B, and
        // `detection.ner.enabled = true` refuses to load. `low` is the most
        // conservative of the three scored buckets, so if the layer ever does
        // run, a caller that forgot to bucket its score under-claims rather than
        // over-claims. `the_statistical_layer_owns_no_type_in_this_build` is what
        // keeps the branch honest.
        DetectionLayer::Ner => "low",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::alias::mint::TypeStat;
    use crate::alias::{EntityType, LadderRung};
    use crate::detect::owning_layer;

    use super::*;

    fn measurement() -> Measurement {
        let mut aliases = AliasStats::default();
        aliases.fold(EntityType::Iban, LadderRung::Invalid);
        Measurement {
            masked: vec![MaskedType {
                entity: EntityType::Iban,
                count: 2,
                layer: DetectionLayer::Pattern,
            }],
            allowed: vec![AllowedType {
                entity: EntityType::Date,
                count: 4,
                rule_scope: "messages[*].content".to_owned(),
            }],
            aliases,
            detect_ms: 6,
            alias_ms: 12,
        }
    }

    const POLICY_HASH: &str = "3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a";

    fn parts<'a>(measurement: &'a Measurement, degraded: &'a [DegradedReason]) -> Parts<'a> {
        Parts {
            session_scope: "9f2c4a10bb730e5188a4d7c6e0f21a34",
            policy_version: "2026.08.1",
            policy_hash: POLICY_HASH,
            ruleset_hash: "b3".repeat(32),
            masking_profile: MaskingProfile::PatternDictionary,
            alias_style: AliasStyle::TypePreserving,
            measurement,
            stream: StreamStats {
                l_max_static: 128,
                l_max_session: 42,
                ..StreamStats::default()
            },
            restore: RestoreStats::default(),
            record_tamper: 0,
            degraded,
            total_ms: 88,
        }
    }

    #[test]
    fn a_record_with_no_conversation_to_name_is_not_written() {
        // The mutation this catches: filling `session_scope` with a placeholder
        // so that an administrative request produces a record too. The record
        // would validate against nothing the schema forbids and it would be a
        // measurement of a conversation that did not happen.
        let measurement = Measurement::default();
        let anonymous = Parts {
            session_scope: "",
            ..parts(&measurement, &[])
        };
        assert!(ProxyEvent::of(&anonymous).is_none());
        assert!(ProxyEvent::of(&parts(&measurement, &[])).is_some());
    }

    #[test]
    fn the_same_request_twice_produces_the_same_bytes() {
        let measurement = measurement();
        let reasons = [DegradedReason::NerDisabled];
        let one = ProxyEvent::of(&parts(&measurement, &reasons)).unwrap();
        let other = ProxyEvent::of(&parts(&measurement, &reasons)).unwrap();
        assert_eq!(one.to_json(), other.to_json());

        // And the order the reasons arrived in does not reach the bytes.
        let shuffled = [
            DegradedReason::CodeBlockSkipped,
            DegradedReason::NerDisabled,
            DegradedReason::CodeBlockSkipped,
        ];
        let sorted = [
            DegradedReason::NerDisabled,
            DegradedReason::CodeBlockSkipped,
        ];
        assert_eq!(
            ProxyEvent::of(&parts(&measurement, &shuffled))
                .unwrap()
                .to_json(),
            ProxyEvent::of(&parts(&measurement, &sorted))
                .unwrap()
                .to_json()
        );
    }

    #[test]
    fn the_body_carries_no_wall_clock_and_every_duration_is_a_whole_millisecond() {
        let measurement = measurement();
        let event = ProxyEvent::of(&parts(&measurement, &[])).unwrap();
        let document = event.to_value();

        for forbidden in ["generated_at", "timestamp", "time", "host", "started_at"] {
            assert!(
                document.get(forbidden).is_none(),
                "the body carries {forbidden}: {document}"
            );
        }
        let latency = &document["latency_ms"];
        for key in ["detect", "alias", "stream_hold_total", "total"] {
            assert!(
                latency[key].is_u64(),
                "{key} is not a whole millisecond: {latency}"
            );
        }
        // The optional field stays absent rather than becoming a zero somebody
        // reads as a scan that ran.
        assert!(latency.get("derived_date_scan").is_none(), "{latency}");
    }

    #[test]
    fn the_derived_date_counter_is_a_zero_and_the_derived_date_timing_is_an_absence() {
        // The pair is the point, and getting it backwards is the mistake the
        // schema's own description warns about. `derived_dates_seen` is a count
        // of a thing that did not happen, so zero is true. `derived_date_scan` is
        // the duration of a scan that never ran, so zero would be a lie and the
        // field is left out.
        let measurement = measurement();
        let document = ProxyEvent::of(&parts(&measurement, &[]))
            .unwrap()
            .to_value();
        assert_eq!(document["derived_dates_seen"], 0);
        assert!(document["latency_ms"].get("derived_date_scan").is_none());
    }

    #[test]
    fn the_allowed_entities_carry_the_expression_and_never_the_text() {
        let measurement = measurement();
        let document = ProxyEvent::of(&parts(&measurement, &[]))
            .unwrap()
            .to_value();
        let allowed = &document["entities_allowed"][0];
        assert_eq!(allowed["type"], "DATE");
        assert_eq!(allowed["count"], 4);
        assert_eq!(allowed["rule_scope"], "messages[*].content");
        assert_eq!(
            allowed.as_object().unwrap().len(),
            3,
            "a fourth field appeared on an allowance: {allowed}"
        );
    }

    #[test]
    fn a_reused_alias_counts_as_an_occurrence_and_not_as_a_second_alias() {
        // `entities_masked[].count` and `alias_stats.by_type[].count` answer two
        // different questions, and a run where they are made equal has lost one
        // of them: two occurrences of one IBAN is two masked entities and one
        // alias.
        let measurement = measurement();
        let document = ProxyEvent::of(&parts(&measurement, &[]))
            .unwrap()
            .to_value();
        assert_eq!(document["entities_masked"][0]["count"], 2);
        assert_eq!(document["alias_stats"]["by_type"]["IBAN"]["count"], 1);
        assert_eq!(
            document["alias_stats"]["by_type"]["IBAN"]["ladder_rung"],
            "I"
        );
    }

    #[test]
    fn every_warning_counter_the_contract_names_is_reported() {
        let mut measurement = measurement();
        measurement.aliases = AliasStats {
            by_type: [(
                EntityType::CreditCard,
                TypeStat {
                    count: 1,
                    ladder_rung: LadderRung::Invalid,
                },
            )]
            .into_iter()
            .collect(),
            alias_pool_exhausted: 3,
            alias_length_class_capped: 0,
        };
        let noisy = Parts {
            stream: StreamStats {
                partial_alias_flushed: 1,
                l_max_static: 128,
                l_max_session: 42,
                ..StreamStats::default()
            },
            restore: RestoreStats {
                aliases_seen_in_response: 2,
                aliases_restored: 1,
                aliases_leaked: 1,
            },
            record_tamper: 2,
            ..parts(&measurement, &[])
        };
        assert_eq!(
            ProxyEvent::of(&noisy).unwrap().warnings(),
            vec![
                "partial_alias_flushed",
                "aliases_leaked",
                "vault_record_tamper",
                "alias_pool_exhausted",
            ]
        );
        // And a clean run says nothing, or the marker means nothing.
        let quiet = Measurement::default();
        assert!(ProxyEvent::of(&parts(&quiet, &[]))
            .unwrap()
            .warnings()
            .is_empty());
    }

    #[test]
    fn the_statistical_layer_owns_no_type_in_this_build() {
        // What keeps `confidence_bucket`'s third arm unreachable rather than
        // merely unlikely. If a type is ever handed to layer C, this fails and
        // whoever did it has to decide what its score buckets to.
        for entity in EntityType::ALL {
            assert_ne!(
                owning_layer(entity),
                DetectionLayer::Ner,
                "{} is owned by a layer this build does not run",
                entity.tag()
            );
        }
        assert_eq!(confidence_bucket(DetectionLayer::Pattern), "deterministic");
        assert_eq!(
            confidence_bucket(DetectionLayer::Dictionary),
            "deterministic"
        );
    }
}
