//! The three legged declaration, and the rule that one leg missing means refuse.
//!
//! `proxy-api.md`'s tool-call decision is a trade: structured arguments and the
//! Responses surface reach the provider **unmasked**, because masking a
//! `{"limit": 50}` without knowing the schema turns a correct call into a
//! confidently wrong one, and refusing outright pushes an organisation into taking
//! the proxy out of the path. The trade holds on one condition, stated as a
//! sentence: "geçiş vardır ama sessiz geçiş yoktur", and the declaration is made in
//! three places at once.
//!
//! 1. the response header `x-periskop-degraded`,
//! 2. `ProxyEvent.degraded_reasons[]`,
//! 3. a finding, `kind = "unmasked_passthrough"`.
//!
//! "Üçünden biri üretilemiyorsa istek **reddedilir**." That is why this is a type
//! with a fallible constructor rather than three lines at a call site: the request
//! path cannot forward an unmasked body without holding one of these, and one of
//! these cannot exist with a leg missing.
//!
//! # The leg that was here and was not produced
//!
//! For a whole phase the third leg was a struct built in this file, returned by an
//! accessor, and **called by nothing under `src/`**. So the header was written, the
//! event carried the reason, and the finding was constructed and dropped on the
//! floor of the same expression that made it. The contract's condition held for two
//! legs and was vacuous for the third, which is worse than an unimplemented leg
//! because the fallible constructor made it look enforced.
//!
//! Two changes close it and they are separate on purpose. The finding is now a
//! **document** ([`Finding::to_value`]), so there is something a caller can keep
//! and a reader can read; and its producibility is a property of the data
//! ([`Subject`]) rather than a third boolean, because a boolean is a caller's claim
//! about a leg and the contract asks whether the leg can be *produced*. What keeps
//! it produced is `http::gateway`: it files every declared gap where
//! `Gateway::findings` can return it, and a test drives a real tool-call request
//! and asserts all three.

use serde_json::{json, Value};

use crate::detect::DegradedReason;

use super::errors::{ProxyError, Refusal};

/// `finding.schema.json`'s own version, as ADR-006 fixes it: `MAJOR.MINOR`.
const FINDING_SCHEMA_VERSION: &str = "1.2";

/// The version of the two rules below.
///
/// Three segment, because `finding.schema.json` requires it of `rule_version` and
/// of nothing else in this crate.
const RULE_VERSION: &str = "1.0.0";

/// The finding a passed-through gap produces (`findings-schema.md`).
///
/// Every field is a value from a closed vocabulary, an identifier, or a hash of
/// one. There is no field a prompt fragment, an alias or an argument value could
/// travel in, which is the same constraint [`super::event::ProxyEvent`] is built
/// under and for the same reason: this record is written where the thing it is
/// about is not allowed to go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub kind: &'static str,
    pub component: &'static str,
    pub rule_id: &'static str,
    /// The provider this exchange was bound for, in `finding.schema.json`'s
    /// spelling.
    provider_ref: String,
    /// `refs[0].ref_id`: the exchange this finding hangs off, `px_` and sixteen
    /// hex characters.
    exchange: String,
    /// The JSON path of the gap, which is a **field name** and never its
    /// contents.
    at: &'static str,
}

impl Finding {
    /// `refs[0].ref_id`.
    pub fn exchange(&self) -> &str {
        &self.exchange
    }

    /// `finding_id`: `fnd_` and sixteen hex characters.
    ///
    /// Content addressed over the four inputs `finding.schema.json` names (kind,
    /// source, primary ref and the rule identifier) and over nothing else, so the
    /// same gap in the same conversation is the same finding on every run. There
    /// is no wall clock in the inputs, which is what keeps a re-run byte
    /// identical. The primary ref carries the whole of the condition: see
    /// `Subject::exchange` for the one session origin under which a conversation
    /// cannot be the same one twice.
    pub fn id(&self) -> String {
        format!(
            "fnd_{}",
            short_hash(&[self.kind, SOURCE, &self.exchange, self.rule_id])
        )
    }

    /// The record as the document `finding.schema.json` describes.
    pub fn to_value(&self) -> Value {
        json!({
            "schema_version": FINDING_SCHEMA_VERSION,
            "finding_id": self.id(),
            "kind": self.kind,
            // The proxy watched an application make this call, which is what
            // `observed-app` means. Not `observed-wire`: this is the request
            // itself, not a packet somebody reassembled.
            "source": SOURCE,
            // Never `suspect`. Nothing was guessed at: the request carried
            // structured arguments or hit an endpoint with no masking, and the
            // proxy forwarded it unmasked on purpose.
            "confidence": "confirmed",
            "provider_ref": self.provider_ref,
            "egress_kind": "llm_chat",
            "detector_severity": "high",
            "refs": [{ "ref_type": "proxy_exchange", "ref_id": self.exchange }],
            "evidence": [{
                "evidence_type": "proxy_exchange",
                // The exchange and the path inside it. A path is a field name, so
                // it is the one thing here that describes the gap's location
                // without carrying what was in it.
                "ref": format!("{}#{}", self.exchange, self.at),
            }],
            "detector": {
                "component": self.component,
                "rule_id": self.rule_id,
                "rule_version": RULE_VERSION,
                "rule_hash": long_hash(&[self.rule_id, RULE_VERSION]),
            },
            "location": { "component": self.component },
            // The gap is declared, so nothing about coverage is unresolved: the
            // proxy knows exactly what crossed and says so.
            "coverage_impact": "none",
            "data_sources": [{
                "source": SOURCE,
                "detector_id": format!("proxy/{}", self.provider_ref),
            }],
        })
    }
}

/// `Finding.source` for everything this component produces.
const SOURCE: &str = "observed-app";

/// Sixteen hex characters of blake3 over the parts, joined by a byte no part
/// contains.
///
/// The separator is what stops two different part lists hashing the same: without
/// it `["ab", "c"]` and `["a", "bc"]` are one input.
fn short_hash(parts: &[&str]) -> String {
    let digest = digest_of(parts);
    digest.chars().take(16).collect()
}

/// Sixty four hex characters of the same digest, which is what
/// `finding.schema.json` requires of `rule_hash`.
fn long_hash(parts: &[&str]) -> String {
    digest_of(parts)
}

fn digest_of(parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(&[0x1f]);
    }
    hasher.finalize().to_hex().to_string()
}

/// What the finding hangs off: the conversation and the provider.
///
/// Borrowed rather than owned so that building a declaration cannot clone
/// anything by accident, and named as a type rather than passed as two strings so
/// that swapping the two at a call site does not compile.
#[derive(Clone, Copy, Debug)]
pub struct Subject<'a> {
    /// The opaque alias scope, which is the handle the client already holds. Not
    /// the session identifier, whose bytes are the vault's HKDF salt.
    pub scope: &'a str,
    /// The provider this request was routed to.
    pub provider: &'a str,
}

impl Subject<'_> {
    /// Whether a finding can be built from this subject at all.
    ///
    /// The third leg's availability is a property of the data rather than a
    /// boolean a caller passes in, which is deliberate: a boolean is a claim, and
    /// the contract's condition is that the finding can actually be **produced**.
    /// `finding.schema.json` requires `provider_ref` to match `[a-z0-9][a-z0-9-]*`
    /// and `refs` to hold at least one entity, and neither can be invented from a
    /// request whose provider or conversation is unnamed.
    fn is_nameable(&self) -> bool {
        !self.scope.is_empty()
            && self.provider.chars().enumerate().all(|(at, character)| {
                character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || (at > 0 && character == '-')
            })
            && !self.provider.is_empty()
    }

    /// `px_` and sixteen hex characters, derived rather than counted.
    ///
    /// Derived from the alias scope and the rule, never from a counter or a
    /// clock: both of those make a re-run produce different bytes, which
    /// `proxy-events.md`'s determinism rule forbids of everything this component
    /// writes. The cost is that two exchanges in one conversation that hit the
    /// same rule share a reference.
    ///
    /// **The stability is exactly as good as the alias scope's, and the scope has
    /// a case where it is fresh every time.** `session::Binding::identify` derives the
    /// scope from the client's session header, or failing that from a
    /// conversation fingerprint in the body, or failing both from
    /// `Origin::Ephemeral`, which is random per request. A re-run therefore
    /// reproduces this reference byte for byte for the first two origins and
    /// cannot for the third, because under it there is no "same conversation" to
    /// reproduce: two identical requests with no session header and no anchor are
    /// two conversations by construction. Saying "stable across a re-run of the
    /// same request" without that condition was an overclaim, and an auditor who
    /// diffed two runs of an unanchored request would have found the difference
    /// and had nothing to read that predicted it.
    fn exchange(&self, rule_id: &str) -> String {
        format!("px_{}", short_hash(&[self.scope, self.provider, rule_id]))
    }
}

/// What is being declared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gap {
    /// Structured tool-call or tool-result arguments in an otherwise masked body.
    ToolArguments,
    /// A whole endpoint with no masking (Responses, Assistants).
    UnsupportedEndpoint,
}

impl Gap {
    const fn reason(self) -> DegradedReason {
        match self {
            Self::ToolArguments => DegradedReason::ToolArgumentsUnmasked,
            Self::UnsupportedEndpoint => DegradedReason::EndpointUnsupportedPassthrough,
        }
    }

    const fn rule_id(self) -> &'static str {
        match self {
            Self::ToolArguments => "proxy.tool-call.unmasked-arguments",
            Self::UnsupportedEndpoint => "proxy.endpoint.unsupported-passthrough",
        }
    }

    /// Where in the exchange the gap is, as a path.
    ///
    /// A path names a field and never its contents, which is what lets the
    /// evidence reference say **where** without saying what.
    const fn at(self) -> &'static str {
        match self {
            Self::ToolArguments => "tool_call.arguments",
            Self::UnsupportedEndpoint => "body",
        }
    }
}

/// A gap that has been declared in all three places.
///
/// Holding one is the permission to forward an unmasked body. There is no
/// constructor that skips a leg.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declared {
    gap: Gap,
    reason: DegradedReason,
    finding: Finding,
}

impl Declared {
    /// Builds the declaration, or refuses.
    ///
    /// `header_available` and `event_available` are what the caller knows about
    /// its own two legs: a response that has already been committed cannot take a
    /// header, and a request with no event record cannot carry a reason. Passing
    /// `false` for either is what turns the trade off and the request into a
    /// refusal, which is the contract's own condition rather than an extra one.
    ///
    /// The third leg is `subject`, and it is data rather than a third boolean on
    /// purpose. It used to be neither: the finding was built unconditionally, was
    /// returned by an accessor **nothing in `src/` called**, and the request went
    /// upstream anyway. So the contract's "üçünden biri üretilemiyorsa istek
    /// reddedilir" held for two legs and was vacuous for the third, which is the
    /// worst of the three states: the type looked like it enforced the rule.
    /// [`Subject::is_nameable`] is now the condition, and it asks what the schema
    /// asks.
    pub fn make(
        gap: Gap,
        header_available: bool,
        event_available: bool,
        subject: Subject<'_>,
    ) -> Result<Self, Refusal> {
        let missing = if !header_available {
            Some("the response header x-periskop-degraded")
        } else if !event_available {
            Some("the event record's degraded_reasons[]")
        } else if !subject.is_nameable() {
            Some("the unmasked_passthrough finding, which has no conversation or provider to name")
        } else {
            None
        };
        if let Some(missing) = missing {
            return Err(Refusal::new(
                ProxyError::ToolArgumentsRejected,
                format!(
                    "an unmasked passthrough ({}) could not be declared in all three \
                     places, so it is refused instead: {missing} could not be produced, \
                     and a gap that cannot be declared is the one thing the pass-through \
                     decision does not permit",
                    gap.rule_id()
                ),
            ));
        }
        Ok(Self {
            gap,
            reason: gap.reason(),
            finding: Finding {
                kind: "unmasked_passthrough",
                component: "proxy",
                rule_id: gap.rule_id(),
                provider_ref: subject.provider.to_owned(),
                exchange: subject.exchange(gap.rule_id()),
                at: gap.at(),
            },
        })
    }

    pub const fn reason(&self) -> DegradedReason {
        self.reason
    }

    /// The third leg.
    ///
    /// `#[must_use]` is not decoration here: an accessor whose result is dropped
    /// is exactly how this leg went missing for a whole phase.
    #[must_use]
    pub const fn finding(&self) -> &Finding {
        &self.finding
    }

    pub const fn gap(&self) -> Gap {
        self.gap
    }
}

/// The refusal `tool_call_policy = "reject"` produces.
pub fn rejected() -> Refusal {
    Refusal::new(
        ProxyError::ToolArgumentsRejected,
        "the policy sets tool_call_policy = \"reject\" and this request carries \
         structured tool-call arguments",
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const SCOPE: &str = "9f2c4a10bb730e5188a4d7c6e0f21a34";

    fn subject() -> Subject<'static> {
        Subject {
            scope: SCOPE,
            provider: "anthropic",
        }
    }

    #[test]
    fn a_declared_gap_carries_all_three_legs() {
        let declared = Declared::make(Gap::ToolArguments, true, true, subject()).unwrap();
        assert_eq!(declared.reason(), DegradedReason::ToolArgumentsUnmasked);
        assert_eq!(declared.reason().as_str(), "tool_arguments_unmasked");
        let finding = declared.finding();
        assert_eq!(finding.kind, "unmasked_passthrough");
        assert_eq!(finding.component, "proxy");
        assert_eq!(finding.rule_id, "proxy.tool-call.unmasked-arguments");
    }

    #[test]
    fn the_endpoint_level_gap_is_counted_apart_from_the_field_level_one() {
        // `proxy-events.md` is explicit that these two may not stand in for each
        // other: one is a field inside a masked request, the other is a whole
        // endpoint where no layer ran, and they are measured separately.
        let field = Declared::make(Gap::ToolArguments, true, true, subject()).unwrap();
        let endpoint = Declared::make(Gap::UnsupportedEndpoint, true, true, subject()).unwrap();
        assert_ne!(field.reason(), endpoint.reason());
        assert_ne!(field.finding().rule_id, endpoint.finding().rule_id);
        // And two rules in one conversation are two findings, or a report would
        // fold a field level gap and an endpoint level one into one row.
        assert_ne!(field.finding().id(), endpoint.finding().id());
        assert_ne!(field.finding().exchange(), endpoint.finding().exchange());
        assert_eq!(
            endpoint.reason().as_str(),
            "endpoint_unsupported_passthrough"
        );
    }

    #[test]
    fn a_leg_that_cannot_be_produced_turns_the_pass_through_into_a_refusal() {
        let nameless = [
            Subject {
                scope: "",
                provider: "openai",
            },
            Subject {
                scope: SCOPE,
                provider: "",
            },
            // `finding.schema.json` fixes `provider_ref` to `[a-z0-9][a-z0-9-]*`,
            // so a name that would not validate is a finding that cannot be
            // written, not one that is written badly.
            Subject {
                scope: SCOPE,
                provider: "OpenAI",
            },
            Subject {
                scope: SCOPE,
                provider: "-openai",
            },
        ];
        let cases = [(false, true), (true, false), (false, false)]
            .map(|(header, event)| (header, event, subject()))
            .into_iter()
            .chain(nameless.map(|subject| (true, true, subject)));

        for (header, event, subject) in cases {
            let refusal = Declared::make(Gap::ToolArguments, header, event, subject)
                .expect_err("a gap was passed through undeclared");
            assert_eq!(refusal.error(), ProxyError::ToolArgumentsRejected);
            assert_eq!(refusal.status(), 400);
        }
    }

    /// The finding is a document, and the document is what the contract asks for.
    ///
    /// Transcribed against `finding.schema.json`'s required list rather than
    /// derived from the struct, so that a field dropped from the renderer fails
    /// here instead of at whatever reads the report.
    #[test]
    fn the_finding_is_the_document_the_schema_requires() {
        let declared = Declared::make(Gap::ToolArguments, true, true, subject()).unwrap();
        let document = declared.finding().to_value();

        for required in [
            "schema_version",
            "finding_id",
            "kind",
            "source",
            "confidence",
            "provider_ref",
            "refs",
            "evidence",
            "detector",
        ] {
            assert!(
                document.get(required).is_some(),
                "{required} is missing: {document:#}"
            );
        }
        assert_eq!(document["kind"], "unmasked_passthrough");
        assert_eq!(document["source"], "observed-app");
        assert_eq!(document["confidence"], "confirmed");
        assert_eq!(document["provider_ref"], "anthropic");
        assert_eq!(document["detector"]["component"], "proxy");
        assert_eq!(document["detector"]["rule_version"], "1.0.0");

        // The three identity patterns, checked as patterns rather than as one
        // remembered example.
        let id = document["finding_id"].as_str().unwrap_or_default();
        assert!(id.starts_with("fnd_") && id.len() == 20, "{id}");
        let exchange = document["refs"][0]["ref_id"].as_str().unwrap_or_default();
        assert!(
            exchange.starts_with("px_") && exchange.len() == 19,
            "{exchange}"
        );
        let hash = document["detector"]["rule_hash"]
            .as_str()
            .unwrap_or_default();
        assert_eq!(hash.len(), 64);
        for id in [
            id.get(4..).unwrap_or_default(),
            exchange.get(3..).unwrap_or_default(),
            hash,
        ] {
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "{id}"
            );
        }
    }

    /// `report-schema.md`'s determinism rule, applied to this record too.
    #[test]
    fn the_same_gap_in_the_same_conversation_is_the_same_finding_twice() {
        let once = Declared::make(Gap::ToolArguments, true, true, subject()).unwrap();
        let twice = Declared::make(Gap::ToolArguments, true, true, subject()).unwrap();
        assert_eq!(once.finding().to_value(), twice.finding().to_value());

        // And a different conversation is a different finding, or two
        // organisations' gaps would collapse into one row.
        let elsewhere = Declared::make(
            Gap::ToolArguments,
            true,
            true,
            Subject {
                scope: "0000000000000000000000000000ffff",
                provider: "anthropic",
            },
        )
        .unwrap();
        assert_ne!(once.finding().id(), elsewhere.finding().id());
    }

    /// The one thing this record may never hold.
    #[test]
    fn no_field_of_the_finding_can_carry_what_crossed_unmasked() {
        // The evidence reference is the field a value would most plausibly be
        // put in, so it is the one asserted about: a path names a field, and a
        // field name is not its contents.
        let declared = Declared::make(Gap::ToolArguments, true, true, subject()).unwrap();
        let rendered = declared.finding().to_value().to_string();
        assert!(rendered.contains("tool_call.arguments"), "{rendered}");
        // Every character in the document is an identifier character. A prompt
        // fragment or an argument value would not survive this.
        let document = declared.finding().to_value();
        assert!(strings_of(&document).iter().all(|value| value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./#".contains(c))));
    }

    fn strings_of(value: &Value) -> Vec<String> {
        match value {
            Value::String(text) => vec![text.clone()],
            Value::Array(items) => items.iter().flat_map(strings_of).collect(),
            Value::Object(fields) => fields.values().flat_map(strings_of).collect(),
            _ => Vec::new(),
        }
    }

    #[test]
    fn the_reject_policy_refuses_with_the_contract_s_own_value() {
        let refusal = rejected();
        assert_eq!(refusal.error(), ProxyError::ToolArgumentsRejected);
        assert_eq!(refusal.status(), 400);
    }
}
