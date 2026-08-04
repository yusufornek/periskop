//! `target_drift`: the code names one destination and the call reached another.
//!
//! The causes range from ordinary to serious and the finding does not choose
//! between them: an environment variable pointing at a gateway, a regional
//! endpoint, a proxy in the path, a misconfiguration, or a redirection nobody
//! intended. What they have in common is that reading the source would not have
//! revealed any of them, which is the whole reason two sources are being
//! compared.
//!
//! One case is explicitly not a drift. When the scanner could not resolve the
//! destination, the code declared nothing to drift from, and reporting one would
//! turn a gap in static analysis into a claim about the system. What that case
//! produces instead is an enrichment: the observation supplies the destination
//! the scanner could not read, and the run says so where the coverage statement
//! can pick it up.

use std::collections::BTreeSet;

use periskop_core::finding::{Confidence, Evidence, Finding, Kind};

use crate::declared::DeclaredPoint;
use crate::emit;
use crate::join::{J2Match, JoinResult};
use crate::outcome::ResolvedTarget;
use crate::settings::ReconcileSettings;
use crate::target::TargetId;

pub(crate) const RULE_ID: &str = "any.reconciled.target-drift";

/// How the destination that was reached differs from the one that was written.
///
/// Named because the reader acts on the difference: a regional subdomain is a
/// deployment question, a bare address is a question about what resolved it, and
/// another provider entirely is a question about where the data went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DriftKind {
    /// The call reached an address rather than a name.
    AddressLiteral,
    /// The same host on a different port.
    Port,
    /// One name sits under the other.
    Subdomain,
    /// An unrelated host.
    Host,
}

impl DriftKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::AddressLiteral => "address_literal",
            Self::Port => "port",
            Self::Subdomain => "subdomain",
            Self::Host => "host",
        }
    }

    fn of(declared: &TargetId, observed: &TargetId) -> Self {
        if observed.is_address_literal() && !declared.is_address_literal() {
            return Self::AddressLiteral;
        }
        if declared.host() == observed.host() {
            return Self::Port;
        }
        if declared.shares_name_with(observed) {
            return Self::Subdomain;
        }
        Self::Host
    }
}

#[derive(Debug, Default)]
pub(crate) struct Derived {
    pub findings: Vec<Finding>,
    /// Destinations an observation supplied for a point the scanner could not
    /// resolve. Not findings: nothing is wrong, something became known.
    pub resolved_targets: Vec<ResolvedTarget>,
    pub faults: Vec<String>,
}

/// Derives one finding per code point whose calls went somewhere else.
///
/// One finding per point rather than one per call. The identity of a derived
/// finding is anchored on the code point, so a point reaching three unexpected
/// destinations is one claim with three pieces of evidence; emitting three
/// findings would give them one identity between them and the report would keep
/// whichever survived deduplication.
pub(crate) fn derive(
    points: &[DeclaredPoint],
    join: &JoinResult,
    settings: &ReconcileSettings,
) -> Derived {
    let mut derived = Derived::default();

    for point in points {
        match point.target() {
            Some(declared) => drift_for(point, declared, join, settings, &mut derived),
            None => collect_resolved(point, join, &mut derived),
        }
    }

    derived.resolved_targets.sort();
    derived.resolved_targets.dedup();
    derived
}

fn drift_for(
    point: &DeclaredPoint,
    declared: &TargetId,
    join: &JoinResult,
    settings: &ReconcileSettings,
    derived: &mut Derived,
) {
    let drifting: Vec<&J2Match> = join
        .matches_for(point.egress_point_id())
        .filter(|m| m.observed_target.as_ref().is_some_and(|t| t != declared))
        .collect();
    if drifting.is_empty() {
        return;
    }

    // Deduplicated by destination: a point called a thousand times through one
    // gateway is one drift, and §6 of the spec asks for exactly that collapse.
    let mut details: BTreeSet<String> = BTreeSet::new();
    let mut event_ids: BTreeSet<String> = BTreeSet::new();
    let mut confirmed = false;
    for matched in &drifting {
        event_ids.insert(matched.egress_event_id.clone());
        confirmed |= matched.tier.is_confirmed();
        if let Some(observed) = &matched.observed_target {
            details.insert(format!(
                "J2:{} declared={declared} observed={observed} drift={}",
                matched.tier.as_str(),
                DriftKind::of(declared, observed).as_str()
            ));
        }
    }

    let evidence: Vec<Evidence> = details.into_iter().map(emit::join_evidence).collect();
    // Every finding is built with one piece of evidence and the rest are
    // attached afterwards. The set above is already ordered, so which one leads
    // does not depend on anything the sources controlled.
    let Some((lead, rest)) = evidence.split_first() else {
        derived.faults.push(format!(
            "target drift derivation found no comparable destination for {}",
            point.egress_point_id()
        ));
        return;
    };

    let confidence = if confirmed {
        Confidence::Confirmed
    } else {
        // Only the provider classification tied the two sides together, and a
        // call to the same provider is not evidence that it came from this line.
        Confidence::Suspect
    };

    match emit::derived_finding(
        Kind::TargetDrift,
        confidence,
        point.provider_ref(),
        point.egress_point_id(),
        lead.clone(),
        settings,
        RULE_ID,
    ) {
        Ok(finding) => {
            let mut finding = finding
                .with_location(emit::code_location(point.path()))
                .with_coverage_impact(periskop_core::finding::CoverageImpact::None);
            if let Some(kind) = point.egress_kind() {
                finding = finding.with_egress_kind(kind);
            }
            emit::attach_evidence(&mut finding, rest.to_vec());
            emit::attach_event_refs(&mut finding, &event_ids.into_iter().collect::<Vec<_>>());
            derived.findings.push(finding);
        }
        Err(error) => derived.faults.push(format!(
            "target drift derivation could not build a finding for {}: {error}",
            point.egress_point_id()
        )),
    }
}

/// Records the destinations observation supplied for an unresolved point.
fn collect_resolved(point: &DeclaredPoint, join: &JoinResult, derived: &mut Derived) {
    for matched in join.matches_for(point.egress_point_id()) {
        if let Some(observed) = &matched.observed_target {
            derived.resolved_targets.push(ResolvedTarget {
                egress_point_id: point.egress_point_id().to_owned(),
                observed_target: observed.clone(),
            });
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::declared::tests::{point, point_without_operation, unresolved_point};
    use crate::join::{join, tests::event};
    use periskop_runtime_collector::EgressEvent;

    const EP: &str = "ep_3f0a91c7d4e28b56";

    fn derive_with(points: &[DeclaredPoint], events: &[EgressEvent]) -> Derived {
        let result = join(points, events);
        derive(points, &result, &ReconcileSettings::default())
    }

    fn evidence_of(derived: &Derived) -> String {
        derived.findings[0]
            .evidence
            .iter()
            .map(|e| e.r#ref.clone())
            .collect::<Vec<_>>()
            .join(" | ")
    }

    #[test]
    fn a_call_that_went_elsewhere_is_reported_against_the_code_that_declared_it() {
        let points = [point(EP, "api.openai.com", "chat.completions.create")];
        let events = [event(
            "openai",
            "chat.completions.create",
            "llm-gateway.internal",
            "unknown",
        )];
        let derived = derive_with(&points, &events);

        assert_eq!(derived.findings.len(), 1);
        assert_eq!(derived.findings[0].kind, Kind::TargetDrift);
        assert_eq!(derived.findings[0].confidence, Confidence::Confirmed);
        let evidence = evidence_of(&derived);
        assert!(evidence.contains("declared=api.openai.com"), "{evidence}");
        assert!(
            evidence.contains("observed=llm-gateway.internal"),
            "{evidence}"
        );
        assert!(evidence.contains("drift=host"), "{evidence}");
    }

    #[test]
    fn a_call_that_went_where_the_code_said_produces_nothing() {
        let points = [point(EP, "api.openai.com", "chat.completions.create")];
        let events = [event(
            "openai",
            "chat.completions.create",
            "api.openai.com",
            "openai",
        )];
        assert!(derive_with(&points, &events).findings.is_empty());
    }

    #[test]
    fn a_spelling_difference_is_not_a_drift() {
        // The normalisation earning its keep: a trailing dot, an upper case
        // letter and an explicit default port are the same destination.
        let points = [point(EP, "api.openai.com", "chat.completions.create")];
        let events = [event(
            "openai",
            "chat.completions.create",
            "API.OpenAI.com.",
            "openai",
        )];
        assert!(derive_with(&points, &events).findings.is_empty());
    }

    #[test]
    fn the_kind_of_difference_is_named() {
        let cases = [
            ("eu.api.openai.com", "drift=subdomain"),
            ("10.2.3.4", "drift=address_literal"),
            ("api.anthropic.com", "drift=host"),
        ];
        for (observed, expected) in cases {
            let points = [point(EP, "api.openai.com", "chat.completions.create")];
            let events = [event(
                "openai",
                "chat.completions.create",
                observed,
                "openai",
            )];
            let derived = derive_with(&points, &events);
            assert!(evidence_of(&derived).contains(expected), "{observed}");
        }
    }

    #[test]
    fn an_unresolved_declaration_is_enriched_rather_than_accused() {
        // The scanner could not read the destination. Reporting a drift here
        // would turn a gap in static analysis into a claim about the code.
        let points = [unresolved_point(EP, "openai")];
        let events = [event(
            "openai",
            "chat.completions.create",
            "api.openai.com",
            "openai",
        )];
        let derived = derive_with(&points, &events);

        assert!(derived.findings.is_empty());
        assert_eq!(derived.resolved_targets.len(), 1);
        assert_eq!(
            derived.resolved_targets[0].observed_target.host(),
            "api.openai.com"
        );
    }

    #[test]
    fn a_provider_level_tie_can_only_produce_a_suspected_drift() {
        // Nothing links the call to this line except that both name the same
        // provider. The finding stays, and it stays suspect.
        let points = [point(EP, "api.openai.com", "chat.completions.create")];
        let events = [event(
            "openai",
            "embeddings.create",
            "eu.api.openai.com",
            "openai",
        )];
        let derived = derive_with(&points, &events);

        assert_eq!(derived.findings[0].confidence, Confidence::Suspect);
    }

    #[test]
    fn one_point_reaching_several_destinations_stays_one_finding() {
        let points = [point_without_operation(EP, "api.openai.com")];
        let events = [
            event(
                "openai",
                "chat.completions.create",
                "eu.api.openai.com",
                "openai",
            ),
            event("openai", "embeddings.create", "us.api.openai.com", "openai"),
        ];
        let derived = derive_with(&points, &events);

        assert_eq!(derived.findings.len(), 1);
        assert_eq!(derived.findings[0].evidence.len(), 2);
        // Both observations are referenced, and the code point still leads.
        assert_eq!(derived.findings[0].refs.len(), 3);
        assert_eq!(
            derived.findings[0].refs[0].ref_type,
            periskop_core::finding::RefType::EgressPoint
        );
    }

    #[test]
    fn the_finding_does_not_depend_on_the_order_the_calls_arrived_in() {
        let points = [point_without_operation(EP, "api.openai.com")];
        let one = event(
            "openai",
            "chat.completions.create",
            "eu.api.openai.com",
            "openai",
        );
        let other = event("openai", "embeddings.create", "us.api.openai.com", "openai");

        let forward = derive_with(&points, &[one.clone(), other.clone()]);
        let backward = derive_with(&points, &[other, one]);

        assert_eq!(forward.findings, backward.findings);
    }
}
