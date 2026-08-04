//! The egress event type.
//!
//! Mirrors `schemas/egress-event.schema.json`. The schema is the contract; this
//! is the in memory shape that serializes to it. Fields are added to the schema
//! first and only then here, so the two cannot drift in the direction that
//! matters.
//!
//! Where a declared egress point says the code *can* reach a provider, an event
//! says it *did*. The difference is what makes the record worth defending: it
//! describes a call that carried real data, so the record itself must carry the
//! shape of that data and never the data. A tool that exists to stop content
//! leaving must not become the thing that copies it. That rule is not left to
//! the discretion of eight separate hook implementations; it is checked here, on
//! the way in ([`EgressEvent::validate`]).
//!
//! Nor is the record's identity. It is derived from the call shape by a
//! derivation the schema calls normative, and [`EgressEvent::validate`]
//! recomputes it rather than accepting the one the hook wrote. Identity is the
//! deduplication key, so a hook that derives it differently does not produce a
//! wrong label: it makes two calls into one record, or one call into two, and it
//! does so without anything downstream noticing.

use serde::{Deserialize, Serialize};

use periskop_core::ids::{short_hash, EgressEventId};

/// Schema version this build writes.
pub const SCHEMA_VERSION: &str = "1.0";

/// Domain tag for the event identity space.
///
/// Keeps event identities apart from point and flow identities that might
/// otherwise be derived from the same host and path strings.
const ID_DOMAIN_TAG: &str = "ee/v1";

/// Marks a field path that carries a value rather than a shape.
///
/// A normalised path names structure: `messages[].content`. The moment one
/// reads `user=ahmet@firma.com`, the record has copied a piece of the payload it
/// was only supposed to describe.
const VALUE_MARKER: char = '=';

/// A record that the contract rejects, and why.
///
/// Every variant names a specific invariant the schema states. There is no
/// catch-all: a collector that cannot say what was wrong with a record produces
/// a coverage entry nobody can act on.
#[derive(Debug, thiserror::Error)]
pub enum EventError {
    /// A field path carries payload content.
    ///
    /// The most serious of these, because the record is not merely invalid: it
    /// is a leak that has already happened once, into a file on disk.
    #[error("a payload field path carries a value, not a shape")]
    RawContentInFieldPath,

    #[error("operation is not normalised to lower case")]
    MalformedOperation,

    #[error("provider_ref is not a valid classifier name")]
    MalformedProviderRef,

    /// Call site hints are joined against a scan of a project tree, so a path
    /// that only resolves on the machine that produced it is not a hint. It is
    /// noise that also happens to name somebody's home directory.
    #[error("call site path is absolute")]
    AbsoluteCallSitePath,

    #[error("event identity is not the ee_ form the contract fixes")]
    MalformedEventId {
        #[source]
        source: periskop_core::Error,
    },

    /// The identity does not follow from the fields it claims to name.
    ///
    /// Well formed and still wrong, which is the dangerous shape. Identity is
    /// the deduplication key, so an identity that does not follow from the call
    /// shape either merges two different calls into one record or splits one
    /// call into two observations, and both happen without a single line
    /// appearing in a coverage statement.
    #[error("event identity does not follow from the call shape it names")]
    EventIdMismatch,
}

impl EventError {
    /// A fixed, content free label for this rejection.
    ///
    /// Deliberately not the `Display` text and never the offending value. A
    /// diagnostic that quotes the field path it rejected would copy the very
    /// content the check exists to keep out of the record, one layer further
    /// down where nobody is looking for it.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::RawContentInFieldPath => "raw_content_in_field_path",
            Self::MalformedOperation => "malformed_operation",
            Self::MalformedProviderRef => "malformed_provider_ref",
            Self::AbsoluteCallSitePath => "absolute_call_site_path",
            Self::MalformedEventId { .. } => "malformed_event_id",
            Self::EventIdMismatch => "event_id_mismatch",
        }
    }
}

/// Language of the process the hook sat in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Python,
    Javascript,
    Typescript,
}

/// Which layer the hook sat at.
///
/// An `SdkWrapper` observation is stronger evidence than an `HttpClient` one:
/// the latter cannot tell a provider call from any other request without
/// looking at the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mechanism {
    SdkWrapper,
    HttpClient,
    RawSocket,
}

/// Why a record is less complete than a full one.
///
/// Present so a thin event is read as thin, rather than as evidence of a small
/// call that never happened that way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradedReason {
    StreamingBodyNotMeasured,
    PayloadTraversalTruncated,
    TargetNotResolved,
    CallSiteUnavailable,
    SamplingApplied,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Process {
    pub language: Language,
    /// Interpreter and version, for example `cpython/3.12`.
    pub runtime: String,
    /// Best effort name of what is running. Never an absolute path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Library {
    /// Package the call went through, for example `openai` or `httpx`.
    pub module: String,
    pub mechanism: Mechanism,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Destination host, recorded as written, since a scan needs to compare it
    /// against what the code declared.
    pub host_id: String,
    /// The schema bounds this at 65535, so the type does the bounding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Request path with identifiers removed, so two calls to one endpoint
    /// compare equal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_template: Option<String>,
    /// Classified provider, or `unknown`. Never omitted to hide an unclassified
    /// destination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_ref: Option<String>,
}

/// Structure of what was sent.
///
/// Content is not recorded and cannot be recovered from these fields.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadShape {
    /// Normalised field paths, sorted. Dynamic keys are replaced by a
    /// placeholder before they get here, because a key carries data as readily
    /// as a value: a map keyed by customer email would otherwise copy those
    /// addresses into the record.
    pub field_paths: Vec<String>,
    /// Approximate size. An estimate rather than a measurement, since
    /// materialising a streaming body to measure it would change the behaviour
    /// of the program under observation.
    pub byte_size_estimate: u64,
    /// Depth at which traversal stopped, so a shallow record is not mistaken
    /// for a small payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_depth: Option<u32>,
}

/// Best effort link back to source. Advisory only: reconciliation joins on the
/// call shape, not on this.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallSiteHint {
    /// Relative to the project root. Absolute paths are rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

/// One call that actually happened, as recorded by a runtime hook.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressEvent {
    pub schema_version: String,
    pub egress_event_id: String,
    pub process: Process,
    pub library: Library,
    /// Method or endpoint that was invoked, normalised to lower case.
    pub operation: String,
    pub target: Target,
    pub payload_shape: PayloadShape,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_site_hint: Option<CallSiteHint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded_reasons: Option<Vec<DegradedReason>>,
}

/// Derives an event identity from the call shape.
///
/// Only the four fields that answer *which call is this* take part. No clock
/// value and no counter, which is what lets the same call, recorded twice in two
/// processes or in two runs, collapse to one identity instead of inflating a
/// count. The reasoning is the one `periskop_core::ids` gives for keeping line
/// numbers out of a finding identity: an identity that moves on its own produces
/// a report that differs from itself, and a diff that lights up on nothing is a
/// diff nobody reads.
///
/// An absent path template hashes as the empty string. The field count is fixed
/// at four, so the separator still keeps the boundaries unambiguous, and a
/// request path is never legitimately empty for the collision to matter.
pub fn derive_egress_event_id(
    module: &str,
    operation: &str,
    host_id: &str,
    path_template: Option<&str>,
) -> Result<EgressEventId, periskop_core::Error> {
    let hash = short_hash(
        ID_DOMAIN_TAG,
        &[module, operation, host_id, path_template.unwrap_or("")],
    );
    EgressEventId::from_short_hash(&hash)
}

impl EgressEvent {
    /// Builds an event, deriving the identity from the fields the contract names.
    ///
    /// The identity is not accepted as an argument. Letting a caller supply one
    /// would let two spellings of the same call into the pipeline, and the
    /// duplicate would surface as two observations of one thing.
    pub fn new(
        process: Process,
        library: Library,
        operation: impl Into<String>,
        target: Target,
        payload_shape: PayloadShape,
    ) -> Result<Self, EventError> {
        let operation = operation.into();
        let id = derive_egress_event_id(
            &library.module,
            &operation,
            &target.host_id,
            target.path_template.as_deref(),
        )
        .map_err(|source| EventError::MalformedEventId { source })?;

        let event = Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            egress_event_id: id.to_string(),
            process,
            library,
            operation,
            target,
            payload_shape,
            call_site_hint: None,
            degraded_reasons: None,
        };
        event.validate()?;
        Ok(event)
    }

    /// Attaches the hint that lets reconciliation offer a source location.
    ///
    /// Fallible where the other builders are not, because this is the one field
    /// that can carry a filesystem path. A builder that can put an invalid
    /// record into the pipeline and report success is not worth having.
    pub fn with_call_site_hint(mut self, hint: CallSiteHint) -> Result<Self, EventError> {
        self.call_site_hint = Some(hint);
        self.validate()?;
        Ok(self)
    }

    /// Records why this event is thinner than a complete one.
    ///
    /// Sorted and deduplicated on the way in: the order in which a hook noticed
    /// two degradations is an accident of its control flow, and letting it reach
    /// the record would make two identical observations serialize differently.
    /// An empty list is stored as absent, since both say the same thing and a
    /// reader should not have to know that.
    pub fn with_degraded_reasons(mut self, mut reasons: Vec<DegradedReason>) -> Self {
        reasons.sort();
        reasons.dedup();
        self.degraded_reasons = if reasons.is_empty() {
            None
        } else {
            Some(reasons)
        };
        self
    }

    pub fn id(&self) -> &str {
        &self.egress_event_id
    }

    /// Checks the invariants the schema states as rejections.
    ///
    /// Run on construction and again on every record read back from disk. The
    /// second run is the one that earns its keep: the hook that wrote the file
    /// ran inside somebody else's process, in a language this crate does not
    /// compile, and a collector that trusts that writer would let one hook bug
    /// turn periskop into the leak it exists to find.
    pub fn validate(&self) -> Result<(), EventError> {
        EgressEventId::parse(&self.egress_event_id)
            .map_err(|source| EventError::MalformedEventId { source })?;

        if !is_normalised_operation(&self.operation) {
            return Err(EventError::MalformedOperation);
        }

        if let Some(provider_ref) = &self.target.provider_ref {
            if !is_provider_ref(provider_ref) {
                return Err(EventError::MalformedProviderRef);
            }
        }

        if self
            .payload_shape
            .field_paths
            .iter()
            .any(|path| path.contains(VALUE_MARKER))
        {
            return Err(EventError::RawContentInFieldPath);
        }

        if let Some(path) = self.call_site_hint.as_ref().and_then(|h| h.path.as_deref()) {
            if is_absolute_path(path) {
                return Err(EventError::AbsoluteCallSitePath);
            }
        }

        // Last of the checks, deliberately. A record that also carries content
        // must be rejected for the content: that rejection names a leak, this
        // one names a hook bug, and the leak is the one an operator has to see
        // first.
        //
        // The derivation is normative in the schema, which is what makes
        // recomputing it here a check rather than an opinion. Accepting an
        // identity because it has the right shape would trust the arithmetic of
        // a program in another language: a hook that hashed the port instead of
        // the path template would give every endpoint on one host the same
        // identity, and deduplication would delete the difference without
        // counting it.
        let derived = derive_egress_event_id(
            &self.library.module,
            &self.operation,
            &self.target.host_id,
            self.target.path_template.as_deref(),
        )
        .map_err(|source| EventError::MalformedEventId { source })?;
        if derived.as_str() != self.egress_event_id {
            return Err(EventError::EventIdMismatch);
        }

        Ok(())
    }
}

/// Schema pattern `^[a-z][a-z0-9_.]*$`.
fn is_normalised_operation(value: &str) -> bool {
    let mut chars = value.chars();
    if !matches!(chars.next(), Some(c) if c.is_ascii_lowercase()) {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
}

/// Schema pattern `^[a-z0-9][a-z0-9-]*$`.
fn is_provider_ref(value: &str) -> bool {
    let mut chars = value.chars();
    if !matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit()) {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Whether a hint path is rooted, for any platform.
///
/// This cannot defer to `std::path`, because the process that wrote the record
/// is not the process reading it and need not have been running the same
/// operating system. A Windows drive path read on Linux is still a path that
/// leaks a machine layout into a report meant to be diffable anywhere.
fn is_absolute_path(path: &str) -> bool {
    if path.starts_with('/') || path.starts_with('\\') {
        return true;
    }
    let mut chars = path.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some(drive), Some(':')) if drive.is_ascii_alphabetic()
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The contract example from `schemas/examples/egress-event.valid.json`,
    /// with the identity corrected.
    ///
    /// The example carries `ee_5b18c30af7924de6`, which is not what the
    /// derivation the schema calls normative produces for these fields. The
    /// example was written by hand before any implementation existed, and the
    /// mismatch went unnoticed for as long as nothing recomputed the identity.
    /// This crate cannot edit `schemas/`, so the correction is filed as a
    /// contract request in `hub/memory/interfaces.md`; the value below is what
    /// all three implementations of the derivation agree on.
    const CONTRACT_EXAMPLE: &str = r#"{
      "schema_version": "1.0",
      "egress_event_id": "ee_3dfe316616cd47b4",
      "process": {
        "language": "python",
        "runtime": "cpython/3.12",
        "entrypoint_hint": "billing-worker"
      },
      "library": { "module": "openai", "mechanism": "sdk_wrapper" },
      "operation": "chat.completions.create",
      "target": {
        "host_id": "api.openai.com",
        "port": 443,
        "path_template": "/v1/chat/completions",
        "provider_ref": "openai"
      },
      "payload_shape": {
        "field_paths": ["messages[].content", "messages[].role", "model"],
        "byte_size_estimate": 2048,
        "truncated_depth": 0
      },
      "call_site_hint": { "path": "services/customer.py", "symbol": "summarize" }
    }"#;

    fn sample_with(host_id: &str, operation: &str) -> EgressEvent {
        EgressEvent::new(
            Process {
                language: Language::Python,
                runtime: "cpython/3.12".to_owned(),
                entrypoint_hint: Some("billing-worker".to_owned()),
            },
            Library {
                module: "openai".to_owned(),
                mechanism: Mechanism::SdkWrapper,
            },
            operation,
            Target {
                host_id: host_id.to_owned(),
                port: Some(443),
                path_template: Some("/v1/chat/completions".to_owned()),
                provider_ref: Some("openai".to_owned()),
            },
            PayloadShape {
                field_paths: vec!["messages[].content".to_owned(), "model".to_owned()],
                byte_size_estimate: 2048,
                truncated_depth: Some(0),
            },
        )
        .unwrap()
    }

    fn sample() -> EgressEvent {
        sample_with("api.openai.com", "chat.completions.create")
    }

    fn keys_of(value: &serde_json::Value, into: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    into.push(key.clone());
                    keys_of(child, into);
                }
            }
            serde_json::Value::Array(items) => {
                for child in items {
                    keys_of(child, into);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn serialized_shape_uses_the_contract_spellings() {
        let json = serde_json::to_value(sample()).unwrap();
        assert_eq!(json["process"]["language"], "python");
        assert_eq!(json["library"]["mechanism"], "sdk_wrapper");
        assert_eq!(json["schema_version"], SCHEMA_VERSION);
        // Optional fields that were never set must be absent, not null: the
        // schema forbids unknown shapes and a null would fail validation.
        assert!(json.get("call_site_hint").is_none());
        assert!(json.get("degraded_reasons").is_none());
    }

    #[test]
    fn the_contract_example_round_trips() {
        let event: EgressEvent = serde_json::from_str(CONTRACT_EXAMPLE).unwrap();
        event.validate().unwrap();
        assert_eq!(event.target.port, Some(443));
        assert_eq!(event.process.language, Language::Python);
        let reserialized = serde_json::to_value(&event).unwrap();
        let original: serde_json::Value = serde_json::from_str(CONTRACT_EXAMPLE).unwrap();
        assert_eq!(reserialized, original);
    }

    #[test]
    fn identity_is_stable_across_calls() {
        assert_eq!(sample().egress_event_id, sample().egress_event_id);
    }

    #[test]
    fn identity_ignores_everything_but_the_call_shape() {
        // Two processes make the same call a day apart, one of them degraded and
        // sending twice as much. It is still the same call, and the report says
        // so once.
        let plain = sample();
        let mut loaded = sample();
        loaded.payload_shape.byte_size_estimate = 999_999;
        loaded.payload_shape.truncated_depth = Some(6);
        loaded.process.entrypoint_hint = Some("nightly-batch".to_owned());
        let loaded = loaded
            .with_degraded_reasons(vec![DegradedReason::SamplingApplied])
            .with_call_site_hint(CallSiteHint {
                path: Some("services/other.py".to_owned()),
                symbol: None,
            })
            .unwrap();

        assert_eq!(plain.egress_event_id, loaded.egress_event_id);
    }

    #[test]
    fn no_field_in_the_record_carries_a_clock() {
        // The runtime-hooks spec sketches an earlier event shape with a
        // monotonic timestamp on every call. The schema, which is the contract,
        // dropped it, and this asserts the type followed: a report that carries
        // wall clock or counter values cannot be diffed against yesterday's.
        let json = serde_json::to_value(sample()).unwrap();
        let mut keys = Vec::new();
        keys_of(&json, &mut keys);
        for key in keys {
            for banned in ["timestamp", "_at", "clock", "epoch", "monotonic"] {
                assert!(!key.contains(banned), "{key} carries a clock value");
            }
        }
    }

    #[test]
    fn identity_follows_the_target_and_the_operation() {
        let base = sample();
        assert_ne!(
            base.egress_event_id,
            sample_with("api.anthropic.com", "chat.completions.create").egress_event_id
        );
        assert_ne!(
            base.egress_event_id,
            sample_with("api.openai.com", "embeddings.create").egress_event_id
        );
    }

    #[test]
    fn a_field_path_carrying_a_value_is_rejected() {
        let mut event = sample();
        event.payload_shape.field_paths = vec![
            "messages[].content".to_owned(),
            "customers.ahmet@firma.com=acme".to_owned(),
        ];
        assert!(matches!(
            event.validate(),
            Err(EventError::RawContentInFieldPath)
        ));
    }

    #[test]
    fn a_rejection_never_repeats_the_value_it_rejected() {
        // The whole point of the check is that the string must not be copied
        // anywhere. A diagnostic that quotes it merely moves the leak.
        let mut event = sample();
        event.payload_shape.field_paths = vec!["email=ahmet@firma.com".to_owned()];
        let error = event.validate().unwrap_err();
        assert_eq!(error.reason(), "raw_content_in_field_path");
        assert!(!error.reason().contains("ahmet"));
        assert!(!error.to_string().contains("ahmet"));
    }

    #[test]
    fn an_absolute_call_site_path_is_rejected_on_any_platform() {
        for path in ["/Users/someone/app/services/customer.py", "C:\\app\\svc.py"] {
            let hint = CallSiteHint {
                path: Some(path.to_owned()),
                symbol: None,
            };
            assert!(matches!(
                sample().with_call_site_hint(hint),
                Err(EventError::AbsoluteCallSitePath)
            ));
        }
    }

    #[test]
    fn a_relative_call_site_path_is_accepted() {
        let hint = CallSiteHint {
            path: Some("services/customer.py".to_owned()),
            symbol: Some("summarize".to_owned()),
        };
        assert!(sample().with_call_site_hint(hint).is_ok());
    }

    #[test]
    fn an_operation_that_is_not_normalised_is_rejected() {
        let mut event = sample();
        event.operation = "chat.Completions.Create".to_owned();
        assert!(matches!(
            event.validate(),
            Err(EventError::MalformedOperation)
        ));
    }

    #[test]
    fn a_record_with_an_unknown_field_is_not_accepted() {
        // The schema sets additionalProperties to false. Quietly accepting an
        // extra field would let a hook ship a channel this build never
        // validates, which is how content gets in through a side door.
        let with_extra = CONTRACT_EXAMPLE.replace(
            "\"operation\":",
            "\"prompt_text\": \"hello\",\n      \"operation\":",
        );
        assert!(serde_json::from_str::<EgressEvent>(&with_extra).is_err());
    }

    #[test]
    fn degraded_reasons_are_ordered_and_an_empty_list_is_absent() {
        let event = sample().with_degraded_reasons(vec![
            DegradedReason::SamplingApplied,
            DegradedReason::TargetNotResolved,
            DegradedReason::SamplingApplied,
        ]);
        assert_eq!(
            event.degraded_reasons,
            Some(vec![
                DegradedReason::TargetNotResolved,
                DegradedReason::SamplingApplied,
            ])
        );
        assert!(sample()
            .with_degraded_reasons(Vec::new())
            .degraded_reasons
            .is_none());
    }

    #[test]
    fn an_identity_read_back_is_re_derived_and_not_taken_on_trust() {
        // The record was written by a hook in another language, running inside
        // somebody else's process. The derivation is normative in the schema
        // precisely so that this comparison is possible, and a collector that
        // only checked the ee_ shape would accept an identity a hook invented.
        let event: EgressEvent = serde_json::from_str(CONTRACT_EXAMPLE).unwrap();
        let derived = derive_egress_event_id(
            &event.library.module,
            &event.operation,
            &event.target.host_id,
            event.target.path_template.as_deref(),
        )
        .unwrap();

        assert!(event.validate().is_ok());
        assert_eq!(event.egress_event_id, derived.to_string());
    }

    #[test]
    fn an_identity_that_does_not_follow_from_the_call_shape_is_rejected() {
        // The failure this check exists for. A hook derives the identity from
        // the port instead of the path template, so two endpoints on one host
        // collapse to one identity. Deduplication then deletes the embeddings
        // call, and without this rejection nothing counts the deletion: the
        // report says the call never happened.
        let chat = sample_with("api.openai.com", "chat.completions.create");
        let mut embeddings = sample_with("api.openai.com", "embeddings.create");
        embeddings.egress_event_id = chat.egress_event_id.clone();

        assert!(matches!(
            embeddings.validate(),
            Err(EventError::EventIdMismatch)
        ));
        // The rejection is countable: the collector turns this label into a
        // dropped event with a location, rather than a silent merge.
        assert_eq!(
            embeddings.validate().unwrap_err().reason(),
            "event_id_mismatch"
        );
    }

    #[test]
    fn a_rejected_identity_never_repeats_the_record() {
        // Same rule as the field path check: a diagnostic that quotes what it
        // rejected moves the leak instead of stopping it.
        let mut event = sample();
        event.target.host_id = "internal-gateway.acme.test".to_owned();
        let error = event.validate().unwrap_err();
        assert!(!error.to_string().contains("acme"));
        assert!(!error.reason().contains("acme"));
    }

    #[test]
    fn a_malformed_identity_is_rejected() {
        let mut event = sample();
        event.egress_event_id = "ee_NOTHEX".to_owned();
        assert!(matches!(
            event.validate(),
            Err(EventError::MalformedEventId { .. })
        ));
    }
}
