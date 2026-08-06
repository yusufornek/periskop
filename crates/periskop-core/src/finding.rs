//! The finding type.
//!
//! Mirrors `schemas/finding.schema.json`. The schema is the contract; this is the
//! in memory shape that serializes to it. Fields are added to the schema first and
//! only then here, so the two cannot drift in the direction that matters.
//!
//! Two properties are enforced by construction rather than by review. A finding
//! always carries at least one piece of evidence, because an assertion without
//! evidence is the thing this product exists to argue against. And nothing in the
//! body carries a timestamp, a hostname or an absolute path, because any of those
//! would make two runs over the same tree produce different bytes.

use serde::{Deserialize, Serialize};

/// How a finding was arrived at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Source {
    #[serde(rename = "declared")]
    Declared,
    #[serde(rename = "observed-app")]
    ObservedApp,
    #[serde(rename = "observed-wire")]
    ObservedWire,
    #[serde(rename = "reconciled")]
    Reconciled,
}

impl Source {
    /// The spelling the contract fixes, and the one the identity is derived from.
    ///
    /// One function rather than a `match` at each use site. The finding identity
    /// hashes this string, so a second hand written copy that fell out of step
    /// with the serde name would keep emitting the old spelling into the hash
    /// while the JSON carried the new one. Findings would then stop matching
    /// across versions with nothing in the report to show why.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::ObservedApp => "observed-app",
            Self::ObservedWire => "observed-wire",
            Self::Reconciled => "reconciled",
        }
    }
}

/// What kind of claim this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    DeclaredEgressPoint,
    ObservedEgressCall,
    ObservedNetworkFlow,
    UnclassifiedEgress,
    /// Content crossed the boundary without masking and the proxy is saying so.
    ///
    /// The only kind no scan can produce. It is a statement about a request the
    /// proxy forwarded, and it exists because `proxy-api.md` allows the pass
    /// through and forbids it being silent.
    UnmaskedPassthrough,
    UnmatchedWireTraffic,
    DormantEgressPoint,
    TargetDrift,
    VolumeAnomaly,
}

impl Kind {
    /// The source this kind is required to carry.
    ///
    /// The pairing is fixed by the schema, so deriving it here removes the chance
    /// of writing a combination the validator would reject.
    pub fn required_source(self) -> Source {
        match self {
            Self::DeclaredEgressPoint => Source::Declared,
            Self::ObservedEgressCall => Source::ObservedApp,
            Self::ObservedNetworkFlow | Self::UnclassifiedEgress => Source::ObservedWire,
            // The proxy watched an application make the call, which is what
            // `observed-app` means. Not `observed-wire`: this is the request
            // itself, not a packet somebody reassembled.
            Self::UnmaskedPassthrough => Source::ObservedApp,
            Self::UnmatchedWireTraffic
            | Self::DormantEgressPoint
            | Self::TargetDrift
            | Self::VolumeAnomaly => Source::Reconciled,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeclaredEgressPoint => "declared_egress_point",
            Self::ObservedEgressCall => "observed_egress_call",
            Self::ObservedNetworkFlow => "observed_network_flow",
            Self::UnclassifiedEgress => "unclassified_egress",
            Self::UnmaskedPassthrough => "unmasked_passthrough",
            Self::UnmatchedWireTraffic => "unmatched_wire_traffic",
            Self::DormantEgressPoint => "dormant_egress_point",
            Self::TargetDrift => "target_drift",
            Self::VolumeAnomaly => "volume_anomaly",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Confirmed,
    Suspect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefType {
    EgressPoint,
    EgressEvent,
    Flow,
    /// One request and its response as the proxy saw them.
    ProxyExchange,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EntityRef {
    pub ref_type: RefType,
    pub ref_id: String,
}

impl EntityRef {
    /// Rejects a reference whose identity does not match the type it declares.
    ///
    /// The schema pins each reference type to its own prefix, but nothing
    /// validates a report against the schema while it is being built, so a
    /// mismatch used to travel all the way into the finding identity and out to
    /// disk. The only place it would have surfaced is an external validator run
    /// against sample files rather than against real output.
    pub fn validate(&self) -> crate::Result<()> {
        match self.ref_type {
            RefType::EgressPoint => crate::ids::EgressPointId::parse(&self.ref_id).map(drop),
            RefType::EgressEvent => crate::ids::EgressEventId::parse(&self.ref_id).map(drop),
            RefType::Flow => crate::ids::FlowId::parse(&self.ref_id).map(drop),
            RefType::ProxyExchange => crate::ids::ProxyExchangeId::parse(&self.ref_id).map(drop),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    AstNode,
    SdkCallTrace,
    HttpHeader,
    Sni,
    DnsQuery,
    PcapFlow,
    ReconciliationJoin,
    /// The exchange itself, referenced as `<exchange id>#<path>`. The path is a
    /// field name, so it locates the gap without carrying what was in it.
    ProxyExchange,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_type: EvidenceType,
    pub r#ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Component {
    StaticScanner,
    RuntimeHooks,
    NetworkSensor,
    Reconciliation,
    Proxy,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Detector {
    pub component: Component,
    pub rule_id: String,
    pub rule_version: String,
    pub rule_hash: String,
}

/// Byte span in a file. Display only, and never part of an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Span {
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Location {
    pub component: Component,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span: Option<Span>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageImpact {
    UnresolvedTarget,
    UnlinkedEvent,
    UnhookedProcess,
    DegradedAttribution,
    None,
}

/// The destination a finding names, in the form the reconciliation join reads.
///
/// This block exists because the join compares a destination and an operation,
/// and until now neither had a home in the contract. A scanner reads both while
/// matching a rule and used to drop both on the way out, so `target_drift` was
/// derivable in a unit test and unproducible in the pipeline: the component ran,
/// and nothing ever fed it.
///
/// Two fields and no more. `data-model.md` §1 gives `Target` a scheme, a path
/// template and a model as well, and those describe the request rather than the
/// destination. A field no reader consumes is a field every producer fills in by
/// guessing, so the contract gains them in the release that gains their reader.
///
/// Deliberately not folded into [`Location`]. That block is display only by its
/// own contract note and no field of it enters an identity or a decision; a join
/// key living there would read as decorative to anyone who trusted the note.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeclaredTarget {
    /// Host as the source wrote it, minus scheme, credentials and path. Case is
    /// preserved: the report shows what a reader will find in the file, and the
    /// join is what folds case away before comparing.
    pub host: String,
    /// Absent when the value named no port. Not defaulted to 443: a destination
    /// whose port was never written is a different fact from one written as 443,
    /// and only the second is evidence of anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

impl DeclaredTarget {
    /// Reduces a destination as written in source to host and port.
    ///
    /// Accepts what a rule can hand over: a bare host, a host with a port, or a
    /// whole URL, because one rule reads a literal endpoint and another reads a
    /// client's base url. Returns `None` when there is no host in the value,
    /// which is a different fact from an empty host and must not be stored as
    /// one.
    ///
    /// Credentials are dropped rather than carried. A base url written with a
    /// token in it is ordinary, and a report that copied it would publish the
    /// secret it was deployed to protect.
    pub fn parse(written: &str, port_hint: Option<u16>) -> Option<Self> {
        let value = written.trim();
        let after_scheme = match value.find("://") {
            Some(index) => &value[index + 3..],
            None => value,
        };
        let authority = after_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or(after_scheme);
        let authority = match authority.rfind('@') {
            Some(index) => &authority[index + 1..],
            None => authority,
        };

        let (host, port) = split_port(authority);
        let host = host.trim_end_matches('.');
        if host.is_empty() {
            return None;
        }
        Some(Self {
            host: host.to_owned(),
            port: port.or(port_hint),
        })
    }
}

/// Splits a trailing `:port`, leaving a bracketed address intact.
///
/// An address written without brackets has more than one colon and no port at
/// all; reading its last group as one would invent a destination nobody wrote.
fn split_port(authority: &str) -> (&str, Option<u16>) {
    if let Some(end) = authority
        .strip_prefix('[')
        .and_then(|_| authority.find(']'))
    {
        let port = authority[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok());
        return (&authority[1..end], port);
    }
    if authority.matches(':').count() > 1 {
        return (authority, None);
    }
    match authority.rsplit_once(':') {
        // An unparsable port is not a port. Dropping the segment would let
        // `host:not-a-number` compare equal to `host`, so the value keeps its
        // shape and simply fails to match anything.
        Some((host, port)) => match port.parse() {
            Ok(port) => (host, Some(port)),
            Err(_) => (authority, None),
        },
        None => (authority, None),
    }
}

/// One evidence backed claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub schema_version: String,
    pub finding_id: String,
    pub kind: Kind,
    pub source: Source,
    pub confidence: Confidence,
    pub provider_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress_kind: Option<String>,
    /// Where this finding says the call goes. Absent when nothing established a
    /// destination, which is the honest result and not an empty host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_target: Option<DeclaredTarget>,
    /// Method or endpoint invoked, in the spelling the event contract fixes:
    /// lower case, dot separated. Absent when nothing named one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    pub refs: Vec<EntityRef>,
    pub evidence: Vec<Evidence>,
    pub detector: Detector,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage_impact: Option<CoverageImpact>,
}

/// Schema version this build writes.
///
/// Every step so far has been MINOR, so a reader of any earlier one keeps
/// working and simply learns nothing new. 1.1 added `declared_target` and
/// `operation`, both optional. 1.2 widened four closed vocabularies for the
/// proxy's finding: `unmasked_passthrough`, the `proxy` component, and
/// `proxy_exchange` as both a reference and an evidence type. 1.3 turned a
/// sentence that had been normative since 1.0 into a constraint the validator
/// applies, by rejecting an absolute `location.path`.
///
/// This constant sat at `1.1` while the schema was at `1.3`, which is the one
/// drift a version field cannot survive: the engine stamped its output with a
/// version that no longer described it, and a consumer reading the version
/// before validating would have refused a document that was in fact correct.
/// `schema_agreement` at the bottom of this file is what now compares the two
/// rather than a reviewer.
pub const SCHEMA_VERSION: &str = "1.3";

impl Finding {
    /// Builds a finding, deriving the identity from the fields the contract names.
    ///
    /// The source is taken from the kind rather than accepted as an argument.
    /// Passing them separately would allow a combination the schema rejects, and
    /// the failure would surface at validation time instead of here.
    pub fn new(
        kind: Kind,
        confidence: Confidence,
        provider_ref: impl Into<String>,
        primary_ref: EntityRef,
        evidence: Evidence,
        detector: Detector,
    ) -> crate::Result<Self> {
        let source = kind.required_source();
        primary_ref.validate()?;
        let finding_id = crate::ids::derive_finding_id(
            kind.as_str(),
            source.as_str(),
            &primary_ref.ref_id,
            &detector.rule_id,
        )?;

        Ok(Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            finding_id: finding_id.to_string(),
            kind,
            source,
            confidence,
            provider_ref: provider_ref.into(),
            egress_kind: None,
            declared_target: None,
            operation: None,
            refs: vec![primary_ref],
            evidence: vec![evidence],
            detector,
            location: None,
            coverage_impact: None,
        })
    }

    pub fn with_egress_kind(mut self, egress_kind: impl Into<String>) -> Self {
        self.egress_kind = Some(egress_kind.into());
        self
    }

    /// States the destination this finding names.
    pub fn with_declared_target(mut self, target: DeclaredTarget) -> Self {
        self.declared_target = Some(target);
        self
    }

    /// States the operation this finding names, normalising the spelling.
    ///
    /// Lower cased here rather than at each call site, because the runtime side
    /// of the join is lower case by contract and a producer that forgot would
    /// leave the two sides unable to match on a difference of case alone.
    pub fn with_operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = Some(operation.into().to_ascii_lowercase());
        self
    }

    pub fn with_location(mut self, location: Location) -> Self {
        self.location = Some(location);
        self
    }

    pub fn with_coverage_impact(mut self, impact: CoverageImpact) -> Self {
        self.coverage_impact = Some(impact);
        self
    }

    pub fn id(&self) -> &str {
        &self.finding_id
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample(kind: Kind, rule_id: &str) -> Finding {
        Finding::new(
            kind,
            Confidence::Confirmed,
            "openai",
            EntityRef {
                ref_type: RefType::EgressPoint,
                ref_id: "ep_3f0a91c7d4e28b56".to_owned(),
            },
            Evidence {
                evidence_type: EvidenceType::AstNode,
                r#ref: "call@a.py".to_owned(),
                hash: None,
            },
            Detector {
                component: Component::StaticScanner,
                rule_id: rule_id.to_owned(),
                rule_version: "1.0.0".to_owned(),
                rule_hash: "0".repeat(64),
            },
        )
        .unwrap()
    }

    #[test]
    fn source_follows_from_kind() {
        assert_eq!(
            sample(Kind::DeclaredEgressPoint, "r").source,
            Source::Declared
        );
        assert_eq!(sample(Kind::TargetDrift, "r").source, Source::Reconciled);
    }

    #[test]
    fn identity_is_stable_for_identical_inputs() {
        let a = sample(Kind::DeclaredEgressPoint, "python.static.x");
        let b = sample(Kind::DeclaredEgressPoint, "python.static.x");
        assert_eq!(a.finding_id, b.finding_id);
    }

    #[test]
    fn identity_changes_when_the_rule_changes() {
        let a = sample(Kind::DeclaredEgressPoint, "python.static.x");
        let b = sample(Kind::DeclaredEgressPoint, "python.static.y");
        assert_ne!(a.finding_id, b.finding_id);
    }

    #[test]
    fn location_does_not_take_part_in_the_identity() {
        // The invariant the whole product rests on: editing a file above a call
        // must not turn one finding into a different finding.
        let plain = sample(Kind::DeclaredEgressPoint, "r");
        let moved = sample(Kind::DeclaredEgressPoint, "r").with_location(Location {
            component: Component::StaticScanner,
            path: Some("a.py".to_owned()),
            span: Some(Span {
                start_line: 900,
                start_col: 1,
                end_line: 901,
                end_col: 2,
            }),
            symbol: None,
        });
        assert_eq!(plain.finding_id, moved.finding_id);
    }

    #[test]
    fn serialized_shape_uses_the_contract_spellings() {
        let json = serde_json::to_value(sample(Kind::DeclaredEgressPoint, "r")).unwrap();
        assert_eq!(json["source"], "declared");
        assert_eq!(json["kind"], "declared_egress_point");
        assert_eq!(json["detector"]["component"], "static-scanner");
        // Optional fields that were never set must be absent, not null: the schema
        // forbids unknown shapes and a null would fail validation.
        assert!(json.get("egress_kind").is_none());
        assert!(json.get("location").is_none());
        assert!(json.get("declared_target").is_none());
        assert!(json.get("operation").is_none());
    }

    #[test]
    fn a_destination_and_an_operation_survive_into_the_serialized_shape() {
        // The two fields the reconciliation join compares. Before they existed
        // the scanner read both and neither reached its output, so the join had
        // nothing on the code side and target_drift could not be produced by the
        // pipeline at all.
        let json = serde_json::to_value(
            sample(Kind::DeclaredEgressPoint, "r")
                .with_declared_target(
                    DeclaredTarget::parse("https://api.openai.com/v1", None).unwrap(),
                )
                .with_operation("Chat.Completions.Create"),
        )
        .unwrap();

        assert_eq!(json["declared_target"]["host"], "api.openai.com");
        assert!(json["declared_target"].get("port").is_none());
        assert_eq!(json["operation"], "chat.completions.create");
    }

    #[test]
    fn neither_new_field_takes_part_in_the_identity() {
        // Same invariant location already has. A base url edited in a config
        // must not turn one finding into a different finding, or every report
        // after a gateway move would read as a page of new problems.
        let plain = sample(Kind::DeclaredEgressPoint, "r");
        let targeted = sample(Kind::DeclaredEgressPoint, "r")
            .with_declared_target(DeclaredTarget::parse("llm-gateway.internal:8443", None).unwrap())
            .with_operation("chat.completions.create");
        assert_eq!(plain.finding_id, targeted.finding_id);
    }

    #[test]
    fn a_destination_is_reduced_the_way_both_sides_can_compare_it() {
        let cases = [
            ("https://api.openai.com/v1/chat", "api.openai.com", None),
            ("api.openai.com.", "api.openai.com", None),
            ("http://gw.internal:8443/v1", "gw.internal", Some(8443)),
            ("[2001:db8::1]:8443", "2001:db8::1", Some(8443)),
            // More than one colon and no brackets is an address, not a port.
            ("2001:db8::1", "2001:db8::1", None),
        ];
        for (written, host, port) in cases {
            let target = DeclaredTarget::parse(written, None).unwrap();
            assert_eq!(target.host, host, "{written}");
            assert_eq!(target.port, port, "{written}");
        }
    }

    #[test]
    fn credentials_never_survive_into_a_declared_target() {
        // A base url with a token in it is ordinary code. Copying it into a
        // report would publish the secret the tool exists to keep in place.
        let target = DeclaredTarget::parse("https://user:s3cret@api.openai.com/v1", None).unwrap();
        assert_eq!(target.host, "api.openai.com");
        assert!(!serde_json::to_string(&target).unwrap().contains("s3cret"));
    }

    #[test]
    fn a_value_with_no_host_yields_nothing_rather_than_an_empty_target() {
        for empty in ["", "   ", "https://", "/v1/chat"] {
            assert!(DeclaredTarget::parse(empty, None).is_none(), "{empty:?}");
        }
    }

    #[test]
    fn a_port_hint_fills_in_only_what_the_value_did_not_say() {
        assert_eq!(
            DeclaredTarget::parse("api.openai.com", Some(8443))
                .unwrap()
                .port,
            Some(8443)
        );
        assert_eq!(
            DeclaredTarget::parse("api.openai.com:9000", Some(8443))
                .unwrap()
                .port,
            Some(9000)
        );
    }

    #[test]
    fn every_source_serializes_to_the_string_the_identity_uses() {
        // The bug this pins: the identity used to be derived from a second hand
        // written copy of these four spellings. Renaming one on the serde side
        // would have changed the JSON while the hash kept the old value, and the
        // existing shape test only ever looked at `declared`.
        for source in [
            Source::Declared,
            Source::ObservedApp,
            Source::ObservedWire,
            Source::Reconciled,
        ] {
            let json = serde_json::to_value(source).unwrap();
            assert_eq!(json, serde_json::Value::String(source.as_str().to_owned()));
        }
    }

    #[test]
    fn a_reference_id_that_contradicts_its_type_is_refused() {
        // An egress point identity under a flow reference passed straight through
        // and became part of the finding identity, so the report carried an
        // identifier the contract forbids and nothing in the run noticed.
        let build = |ref_type: RefType, ref_id: &str| {
            Finding::new(
                Kind::DeclaredEgressPoint,
                Confidence::Confirmed,
                "openai",
                EntityRef {
                    ref_type,
                    ref_id: ref_id.to_owned(),
                },
                Evidence {
                    evidence_type: EvidenceType::AstNode,
                    r#ref: "call@a.py".to_owned(),
                    hash: None,
                },
                Detector {
                    component: Component::StaticScanner,
                    rule_id: "python.static.x".to_owned(),
                    rule_version: "1.0.0".to_owned(),
                    rule_hash: "0".repeat(64),
                },
            )
        };

        assert!(build(RefType::Flow, "ep_3f0a91c7d4e28b56").is_err());
        assert!(build(RefType::EgressPoint, "ep_QQ").is_err());
        assert!(build(RefType::EgressPoint, "ep_3f0a91c7d4e28b56").is_ok());
        assert!(build(RefType::Flow, "fl_3f0a91c7d4e28b56").is_ok());
    }

    #[test]
    fn observed_wire_kinds_share_one_source() {
        assert_eq!(
            Kind::UnclassifiedEgress.required_source(),
            Kind::ObservedNetworkFlow.required_source()
        );
    }
}

/// Holds the Rust enums to the schema file rather than to a second hand copy.
///
/// Four closed vocabularies live twice: once in `schemas/finding.schema.json`,
/// which is the contract, and once here, which is what actually emits. Nothing
/// compared them, and they drifted: the schema gained the proxy's four values in
/// 1.2 while this file stayed at 1.1, so the engine declared a version the
/// schema no longer described and the proxy's own finding could not be
/// expressed by the type every other component builds.
///
/// Reading the schema at test time rather than restating it is the point. A
/// restated list passes on the day both copies change together, which is the one
/// change that cannot break, and stays silent on the day only one does.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod schema_agreement {
    use super::*;

    fn schema() -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/finding.schema.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        serde_json::from_str(&text).expect("finding.schema.json is not valid JSON")
    }

    /// The values a `"enum"` at `pointer` lists, sorted.
    fn schema_values(pointer: &str) -> Vec<String> {
        let document = schema();
        let node = document
            .pointer(pointer)
            .unwrap_or_else(|| panic!("{pointer} is not in finding.schema.json"));
        let mut values: Vec<String> = node
            .as_array()
            .unwrap_or_else(|| panic!("{pointer} is not an array"))
            .iter()
            .map(|v| v.as_str().expect("enum value is not a string").to_owned())
            .collect();
        values.sort();
        values
    }

    fn emitted<T: Serialize>(values: &[T]) -> Vec<String> {
        let mut out: Vec<String> = values
            .iter()
            .map(|v| {
                serde_json::to_value(v)
                    .expect("value does not serialize")
                    .as_str()
                    .expect("value does not serialize to a string")
                    .to_owned()
            })
            .collect();
        out.sort();
        out
    }

    #[test]
    fn every_kind_the_schema_lists_is_a_kind_this_build_can_emit() {
        assert_eq!(
            emitted(&[
                Kind::DeclaredEgressPoint,
                Kind::ObservedEgressCall,
                Kind::ObservedNetworkFlow,
                Kind::UnclassifiedEgress,
                Kind::UnmaskedPassthrough,
                Kind::UnmatchedWireTraffic,
                Kind::DormantEgressPoint,
                Kind::TargetDrift,
                Kind::VolumeAnomaly,
            ]),
            schema_values("/properties/kind/enum")
        );
    }

    #[test]
    fn the_component_lists_agree() {
        let expected = emitted(&[
            Component::StaticScanner,
            Component::RuntimeHooks,
            Component::NetworkSensor,
            Component::Reconciliation,
            Component::Proxy,
        ]);
        assert_eq!(
            expected,
            schema_values("/properties/detector/properties/component/enum")
        );
        // Two places in the schema spell the same vocabulary, and a finding
        // carries both. A component accepted as a detector and refused as a
        // location would be a finding no producer could write.
        assert_eq!(
            expected,
            schema_values("/properties/location/properties/component/enum")
        );
    }

    #[test]
    fn the_reference_and_evidence_lists_agree() {
        assert_eq!(
            emitted(&[
                RefType::EgressPoint,
                RefType::EgressEvent,
                RefType::Flow,
                RefType::ProxyExchange,
            ]),
            schema_values("/properties/refs/items/properties/ref_type/enum")
        );
        assert_eq!(
            emitted(&[
                EvidenceType::AstNode,
                EvidenceType::SdkCallTrace,
                EvidenceType::HttpHeader,
                EvidenceType::Sni,
                EvidenceType::DnsQuery,
                EvidenceType::PcapFlow,
                EvidenceType::ReconciliationJoin,
                EvidenceType::ProxyExchange,
            ]),
            schema_values("/properties/evidence/items/properties/evidence_type/enum")
        );
    }

    #[test]
    fn every_reference_type_has_an_identity_this_build_can_parse() {
        // The pattern the schema pins on `ref_id`, read back as the set of
        // prefixes. A reference type whose identity nothing can parse would be
        // refused by `EntityRef::validate` at the moment a producer built it.
        let document = schema();
        let pattern = document
            .pointer("/properties/refs/items/properties/ref_id/pattern")
            .and_then(serde_json::Value::as_str)
            .expect("refs.ref_id has no pattern");
        for prefix in ["ep", "ee", "fl", "px"] {
            assert!(
                pattern.contains(prefix),
                "the schema pattern {pattern:?} does not admit {prefix}_"
            );
        }
    }

    #[test]
    fn the_version_this_build_emits_is_the_one_the_schema_examples_carry() {
        // `schema_version` is a free `MAJOR.MINOR` string in the schema, so no
        // enum pins it. The examples do: they are what the validator checks and
        // what a reader copies, so a build emitting a different version is a
        // build whose output does not match its own documentation.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/examples/finding.valid.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let example: serde_json::Value = serde_json::from_str(&text).expect("example is not JSON");
        assert_eq!(example["schema_version"].as_str(), Some(SCHEMA_VERSION));
    }
}
