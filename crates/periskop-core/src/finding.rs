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

/// What kind of claim this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    DeclaredEgressPoint,
    ObservedEgressCall,
    ObservedNetworkFlow,
    UnclassifiedEgress,
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
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EntityRef {
    pub ref_type: RefType,
    pub ref_id: String,
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
    pub refs: Vec<EntityRef>,
    pub evidence: Vec<Evidence>,
    pub detector: Detector,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage_impact: Option<CoverageImpact>,
}

/// Schema version this build writes.
pub const SCHEMA_VERSION: &str = "1.0";

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
        let source_str = match source {
            Source::Declared => "declared",
            Source::ObservedApp => "observed-app",
            Source::ObservedWire => "observed-wire",
            Source::Reconciled => "reconciled",
        };
        let finding_id = crate::ids::derive_finding_id(
            kind.as_str(),
            source_str,
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
    }

    #[test]
    fn observed_wire_kinds_share_one_source() {
        assert_eq!(
            Kind::UnclassifiedEgress.required_source(),
            Kind::ObservedNetworkFlow.required_source()
        );
    }
}
