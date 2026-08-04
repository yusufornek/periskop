//! The code side of the join.
//!
//! A declared egress point is what the static scanner found: a place in the
//! source that can reach a provider. The scanner reports it as a `Finding`, and
//! everything this type needs now comes out of that finding.
//!
//! It did not always. The two fields the join compares on, the destination the
//! code names and the operation it invokes, had no home in the finding contract:
//! the scanner read both while matching a rule and neither survived into its
//! output, so a caller had to state them from somewhere else or leave them
//! empty. In a real run nobody could, which meant `target_drift` was derivable
//! in a unit test and unproducible in the pipeline. Contract version 1.1 gives
//! both a home (`declared_target`, `operation`) and
//! [`DeclaredPoint::from_finding`] reads them.
//!
//! The two builders below survive because a caller may know something the
//! finding does not, for instance a destination read from a lockfile or a
//! deployment manifest. They state, they never guess: a point that receives no
//! target has nothing for the join to compare, which is the honest result.

use periskop_core::finding::{Confidence, Finding, Kind, RefType};
use periskop_core::ids::EgressPointId;

use crate::error::{ReconcileError, Result};
use crate::target::TargetId;

/// One place in the code that can reach a provider.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeclaredPoint {
    egress_point_id: String,
    provider_ref: String,
    confidence: Confidence,
    egress_kind: Option<String>,
    /// Relative to the repository root, for display only.
    path: Option<String>,
    /// Absent when the scanner could not pin the destination down, and absent
    /// too when the caller had nothing to hand over. The two are one case here
    /// on purpose: in both, nothing was established about where this call goes,
    /// and a claim that it drifted would rest on the same absent knowledge.
    target: Option<TargetId>,
    /// Absent when nothing named the operation. The join then falls to a weaker
    /// key rather than treating "unknown" as a value that can match.
    operation: Option<String>,
}

impl DeclaredPoint {
    /// Reads the contract backed half out of a scanner finding.
    ///
    /// Rejects a finding of any other kind. The alternative, accepting it and
    /// letting the join sort it out, would put an observation on the code side,
    /// where nothing can match it and the report would say a call that did
    /// happen is a call that never ran.
    pub fn from_finding(finding: &Finding) -> Result<Self> {
        if finding.kind != Kind::DeclaredEgressPoint {
            return Err(ReconcileError::NotDeclared {
                kind: finding.kind.as_str(),
            });
        }

        let reference = finding
            .refs
            .iter()
            .find(|r| r.ref_type == RefType::EgressPoint)
            .ok_or(ReconcileError::NoEgressPointRef)?;
        let egress_point_id = EgressPointId::parse(&reference.ref_id)
            .map_err(|source| ReconcileError::MalformedEgressPointId { source })?;

        let path = match finding.location.as_ref().and_then(|l| l.path.as_deref()) {
            Some(path) if is_absolute_path(path) => {
                return Err(ReconcileError::AbsoluteLocationPath)
            }
            Some(path) => Some(path.to_owned()),
            None => None,
        };

        // A destination the contract accepted but this side cannot read is an
        // error rather than an absence. The schema requires a non empty host, so
        // the only way to arrive here is a malformed finding, and quietly
        // treating it as "no destination" would turn a broken producer into a
        // code point that simply never drifts.
        let target = match &finding.declared_target {
            Some(declared) => Some(
                TargetId::parse(&declared.host, declared.port)
                    .ok_or(ReconcileError::UnreadableTarget)?,
            ),
            None => None,
        };

        Ok(Self {
            egress_point_id: egress_point_id.to_string(),
            provider_ref: finding.provider_ref.clone(),
            confidence: finding.confidence,
            egress_kind: finding.egress_kind.clone(),
            path,
            target,
            operation: finding
                .operation
                .as_ref()
                .map(|operation| operation.to_ascii_lowercase()),
        })
    }

    /// States the destination the code names.
    ///
    /// Fallible, because a value that names no host is not a destination and
    /// storing it as one would let the join compare against an empty string.
    pub fn with_target(mut self, written: &str, port: Option<u16>) -> Result<Self> {
        self.target = Some(TargetId::parse(written, port).ok_or(ReconcileError::UnreadableTarget)?);
        Ok(self)
    }

    /// States the operation the code invokes, in the spelling the event contract
    /// fixes: lower case, dot separated.
    pub fn with_operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = Some(operation.into().to_ascii_lowercase());
        self
    }

    pub fn egress_point_id(&self) -> &str {
        &self.egress_point_id
    }

    pub fn provider_ref(&self) -> &str {
        &self.provider_ref
    }

    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    pub fn egress_kind(&self) -> Option<&str> {
        self.egress_kind.as_deref()
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn target(&self) -> Option<&TargetId> {
        self.target.as_ref()
    }

    pub fn operation(&self) -> Option<&str> {
        self.operation.as_deref()
    }
}

/// Whether a path is rooted, for any platform.
///
/// Cannot defer to `std::path`: a report may be read on an operating system
/// other than the one that produced it, and a Windows drive path read on Linux
/// still leaks a machine layout into output that is meant to be diffable
/// anywhere.
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
pub(crate) mod tests {
    use super::*;
    use periskop_core::finding::{
        Component, DeclaredTarget, Detector, EntityRef, Evidence, EvidenceType, Location,
    };

    /// A scanner finding shaped exactly as `detect.rs` builds one.
    pub(crate) fn declared_finding(egress_point_id: &str, provider: &str) -> Finding {
        Finding::new(
            Kind::DeclaredEgressPoint,
            Confidence::Confirmed,
            provider,
            EntityRef {
                ref_type: RefType::EgressPoint,
                ref_id: egress_point_id.to_owned(),
            },
            Evidence {
                evidence_type: EvidenceType::AstNode,
                r#ref: "call@services/customer.py".to_owned(),
                hash: None,
            },
            Detector {
                component: Component::StaticScanner,
                rule_id: "python.static.openai-chat-completions".to_owned(),
                rule_version: "1.0.0".to_owned(),
                rule_hash: "0".repeat(64),
            },
        )
        .unwrap()
        .with_egress_kind("llm_chat")
        .with_location(Location {
            component: Component::StaticScanner,
            path: Some("services/customer.py".to_owned()),
            span: None,
            symbol: None,
        })
    }

    /// A declared point with a resolved destination and a named operation.
    pub(crate) fn point(egress_point_id: &str, host: &str, operation: &str) -> DeclaredPoint {
        point_without_operation(egress_point_id, host).with_operation(operation)
    }

    /// A declared point as the scanner produces one today: a destination the
    /// caller could resolve, and no operation for the join to compare.
    pub(crate) fn point_without_operation(egress_point_id: &str, host: &str) -> DeclaredPoint {
        DeclaredPoint::from_finding(&declared_finding(egress_point_id, "openai"))
            .unwrap()
            .with_target(host, None)
            .unwrap()
    }

    /// A declared point the scanner could not pin a destination for.
    pub(crate) fn unresolved_point(egress_point_id: &str, provider: &str) -> DeclaredPoint {
        DeclaredPoint::from_finding(&declared_finding(egress_point_id, provider)).unwrap()
    }

    #[test]
    fn a_scanner_finding_yields_the_fields_the_contract_carries() {
        let point = DeclaredPoint::from_finding(&declared_finding("ep_3f0a91c7d4e28b56", "openai"))
            .unwrap();

        assert_eq!(point.egress_point_id(), "ep_3f0a91c7d4e28b56");
        assert_eq!(point.provider_ref(), "openai");
        assert_eq!(point.egress_kind(), Some("llm_chat"));
        assert_eq!(point.path(), Some("services/customer.py"));
        // The scanner could not read a destination for this one, so the finding
        // states none and none is invented here.
        assert!(point.target().is_none());
        assert!(point.operation().is_none());
    }

    #[test]
    fn both_join_keys_are_read_out_of_the_finding_rather_than_supplied_by_the_caller() {
        // The bloker this closes. Both values used to be dropped on the way out
        // of the scanner, so the only way a point ever had them was a caller
        // stating them, and in a real run no caller could.
        let finding = declared_finding("ep_3f0a91c7d4e28b56", "openai")
            .with_declared_target(DeclaredTarget::parse("https://api.openai.com/v1", None).unwrap())
            .with_operation("chat.completions.create");
        let point = DeclaredPoint::from_finding(&finding).unwrap();

        assert_eq!(point.target().map(TargetId::host), Some("api.openai.com"));
        assert_eq!(point.operation(), Some("chat.completions.create"));
    }

    #[test]
    fn a_declared_target_the_contract_should_have_refused_is_an_error_not_an_absence() {
        // Reading a malformed host as "no destination" would turn a broken
        // producer into a code point that simply never drifts, which is the
        // quietest possible way to lose the finding.
        let mut finding = declared_finding("ep_3f0a91c7d4e28b56", "openai");
        finding.declared_target = Some(DeclaredTarget {
            host: String::new(),
            port: None,
        });
        assert!(matches!(
            DeclaredPoint::from_finding(&finding),
            Err(ReconcileError::UnreadableTarget)
        ));
    }

    #[test]
    fn an_observation_is_not_accepted_as_a_declared_point() {
        let observed = Finding::new(
            Kind::ObservedEgressCall,
            Confidence::Confirmed,
            "openai",
            EntityRef {
                ref_type: RefType::EgressEvent,
                ref_id: "ee_5b18c30af7924de6".to_owned(),
            },
            Evidence {
                evidence_type: EvidenceType::SdkCallTrace,
                r#ref: "hook".to_owned(),
                hash: None,
            },
            Detector {
                component: Component::RuntimeHooks,
                rule_id: "python.runtime.openai".to_owned(),
                rule_version: "1.0.0".to_owned(),
                rule_hash: "0".repeat(64),
            },
        )
        .unwrap();

        assert!(matches!(
            DeclaredPoint::from_finding(&observed),
            Err(ReconcileError::NotDeclared {
                kind: "observed_egress_call"
            })
        ));
    }

    #[test]
    fn an_absolute_location_path_is_refused() {
        for path in ["/Users/someone/app/services/customer.py", "C:\\app\\svc.py"] {
            let finding =
                declared_finding("ep_3f0a91c7d4e28b56", "openai").with_location(Location {
                    component: Component::StaticScanner,
                    path: Some(path.to_owned()),
                    span: None,
                    symbol: None,
                });
            assert!(matches!(
                DeclaredPoint::from_finding(&finding),
                Err(ReconcileError::AbsoluteLocationPath)
            ));
        }
    }

    #[test]
    fn a_target_that_names_no_host_is_refused_rather_than_stored_empty() {
        let finding = declared_finding("ep_3f0a91c7d4e28b56", "openai");
        let point = DeclaredPoint::from_finding(&finding).unwrap();
        assert!(matches!(
            point.with_target("https://", None),
            Err(ReconcileError::UnreadableTarget)
        ));
    }

    #[test]
    fn an_operation_is_stored_in_the_spelling_the_event_contract_fixes() {
        let finding = declared_finding("ep_3f0a91c7d4e28b56", "openai");
        let point = DeclaredPoint::from_finding(&finding).unwrap();
        assert_eq!(
            point.with_operation("Chat.Completions.Create").operation(),
            Some("chat.completions.create")
        );
    }
}
