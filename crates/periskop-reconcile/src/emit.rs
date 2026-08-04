//! Turning a join result into a finding the contract accepts.
//!
//! Two properties are enforced here rather than at each deriver. A derived
//! finding always carries the join that produced it as evidence, because a claim
//! assembled from two sources is worth exactly what the link between them is
//! worth and a reader has to be able to see which rung it rested on. And the
//! references stay ordered by type, because the contract derives the identity
//! from the first one: a finding that grew a second reference must not thereby
//! become a different finding.

use periskop_core::finding::{
    Component, Confidence, Detector, EntityRef, Evidence, EvidenceType, Finding, Kind, Location,
    RefType,
};

use crate::settings::ReconcileSettings;

/// Version of the derivation rules in this crate.
///
/// Separate from the finding schema version and from the algorithm version: this
/// one moves when a rule changes what it emits for inputs it already handled.
pub(crate) const RULE_VERSION: &str = "1.0.0";

/// Domain tag for reconciliation rule digests.
const RULE_HASH_DOMAIN: &str = "rr/v1";

/// Field separator for hash inputs.
///
/// The same byte and the same reasoning as `periskop_core::ids`: without it the
/// inputs `("ab", "c")` and `("a", "bc")` would digest identically. The core
/// helper is not reused because it truncates to eight bytes, while `rule_hash`
/// is a full digest by contract.
const FIELD_SEPARATOR: u8 = 0x1f;

/// The detector block a derived finding carries.
///
/// `rule_hash` covers the thresholds as well as the rule, because a threshold
/// change alters which findings the rule produces. Two reports whose rules
/// differ only in configuration would otherwise be indistinguishable at the one
/// place a reader looks to ask what produced a claim.
///
/// **No threshold is an input to the identity**, which is derived from the kind,
/// the source, the primary reference and the rule id. What that sentence does
/// not mean, and used to be read as meaning, is that a finding keeps its
/// identity across a threshold change. It does for the kinds anchored on a code
/// point: an egress point is what it is whatever the dormancy window says. It
/// does not for the two kinds anchored on traffic, and the mechanism is worth
/// stating rather than discovering. Their primary reference is the episode
/// anchor, the lowest flow identity in the conversation ([`crate::wire`]), and
/// `effective_join_tolerance_ms` is what decides which connections make up one
/// conversation. Widen it and two bursts merge; the merged conversation is
/// anchored on the earlier of the two anchors and the later finding is gone.
///
/// The claim was corrected rather than the behaviour, and the reason is that the
/// alternative reading is false. A finding that survived a regrouping with its
/// identity intact would assert a continuity that did not happen: two bursts an
/// hour apart and one hour long conversation are different facts about the
/// machine, not one fact under two settings. Every anchor that would be stable
/// across tolerances collapses that difference, either by anchoring on the
/// destination, which merges conversations one report is supposed to keep apart,
/// or by ignoring the grouping, which is what the tolerance exists to do. So the
/// tolerance is reported in the evidence of every finding it shaped, and a
/// reader comparing two reports across a tolerance change is told to read them
/// as two groupings rather than as one set of findings that moved.
///
/// A separate limit sits underneath this one and is not this crate's to fix: a
/// flow identity carries the ephemeral source port, so the same repeated
/// connection is a new identity on every run and the two traffic anchored kinds
/// cannot be followed across runs at all. That belongs to the flow identity
/// contract and is filed against its owner.
pub(crate) fn detector(rule_id: &str, settings: &ReconcileSettings) -> Detector {
    // Every threshold that can change what a rule emits, including the one that
    // is usually absent: a run with no volume band and a run with a very wide
    // one produce the same findings and are not the same configuration.
    let band = settings.volume_band().map_or_else(
        || "none".to_owned(),
        |band| format!("{}..{}", band.min_basis_points(), band.max_basis_points()),
    );
    Detector {
        component: Component::Reconciliation,
        rule_id: rule_id.to_owned(),
        rule_version: RULE_VERSION.to_owned(),
        rule_hash: full_hash(
            RULE_HASH_DOMAIN,
            &[
                rule_id,
                RULE_VERSION,
                settings.algorithm_version(),
                &settings.min_dormant_window_ms().to_string(),
                &settings.effective_join_tolerance_ms().to_string(),
                &band,
            ],
        ),
    }
}

/// Evidence naming the join that produced a derived finding.
pub(crate) fn join_evidence(detail: String) -> Evidence {
    Evidence {
        evidence_type: EvidenceType::ReconciliationJoin,
        r#ref: detail,
        hash: None,
    }
}

/// Builds a derived finding anchored on a code point.
///
/// The egress point is the primary reference for every kind this build derives,
/// which is what makes a finding about one place in the code stay one finding no
/// matter how many observations it was assembled from.
pub(crate) fn derived_finding(
    kind: Kind,
    confidence: Confidence,
    provider_ref: &str,
    egress_point_id: &str,
    evidence: Evidence,
    settings: &ReconcileSettings,
    rule_id: &str,
) -> periskop_core::Result<Finding> {
    derived_finding_anchored(
        kind,
        confidence,
        provider_ref,
        EntityRef {
            ref_type: RefType::EgressPoint,
            ref_id: egress_point_id.to_owned(),
        },
        evidence,
        settings,
        rule_id,
    )
}

/// Builds a derived finding anchored on whatever entity it is about.
///
/// The two wire kinds are about a connection rather than a line of code, and a
/// code point is exactly what they do not have: `unmatched_wire_traffic` exists
/// because no code explains the traffic. Anchoring them on the flow is what
/// gives them a stable identity of their own instead of borrowing one.
pub(crate) fn derived_finding_anchored(
    kind: Kind,
    confidence: Confidence,
    provider_ref: &str,
    primary_ref: EntityRef,
    evidence: Evidence,
    settings: &ReconcileSettings,
    rule_id: &str,
) -> periskop_core::Result<Finding> {
    Finding::new(
        kind,
        confidence,
        provider_ref,
        primary_ref,
        evidence,
        detector(rule_id, settings),
    )
}

/// The primary reference of a finding about observed traffic.
pub(crate) fn flow_ref(flow_id: &str) -> EntityRef {
    EntityRef {
        ref_type: RefType::Flow,
        ref_id: flow_id.to_owned(),
    }
}

/// Records where in the source the point sits.
///
/// The component is the static scanner rather than reconciliation: the contract
/// reads this block in the vocabulary of the component whose coordinates it
/// uses, and a path with no span is a scanner coordinate. Which component
/// produced the finding is stated in `detector`, and the two questions are not
/// the same one.
pub(crate) fn code_location(path: Option<&str>) -> Location {
    Location {
        component: Component::StaticScanner,
        path: path.map(str::to_owned),
        span: None,
        symbol: None,
    }
}

/// Adds the observations a finding rests on, keeping the reference order fixed.
pub(crate) fn attach_event_refs(finding: &mut Finding, egress_event_ids: &[String]) {
    attach_refs(finding, RefType::EgressEvent, egress_event_ids);
}

/// Adds the connections a finding rests on.
pub(crate) fn attach_flow_refs(finding: &mut Finding, flow_ids: &[String]) {
    attach_refs(finding, RefType::Flow, flow_ids);
}

/// The ordering rule both of the above share.
///
/// Written once because the property it keeps is not obvious: the contract
/// derives the identity from the first reference, so a finding that grew a
/// second one must not thereby become a different finding. Two copies of this
/// loop would be two chances to sort one of them differently.
fn attach_refs(finding: &mut Finding, ref_type: RefType, ids: &[String]) {
    for id in ids {
        finding.refs.push(EntityRef {
            ref_type,
            ref_id: id.clone(),
        });
    }
    finding.refs.sort();
    finding.refs.dedup();
}

/// Adds further evidence, ordered so that two runs write the same bytes.
pub(crate) fn attach_evidence(finding: &mut Finding, evidence: Vec<Evidence>) {
    finding.evidence.extend(evidence);
    finding.evidence.sort();
    finding.evidence.dedup();
}

fn full_hash(domain_tag: &str, fields: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain_tag.as_bytes());
    for field in fields {
        hasher.update(&[FIELD_SEPARATOR]);
        hasher.update(field.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const EP: &str = "ep_3f0a91c7d4e28b56";
    const RULE: &str = "any.reconciled.dormant-egress-point";

    fn finding(settings: &ReconcileSettings) -> Finding {
        derived_finding(
            Kind::DormantEgressPoint,
            Confidence::Confirmed,
            "openai",
            EP,
            join_evidence("J2:none".to_owned()),
            settings,
            RULE,
        )
        .unwrap()
    }

    #[test]
    fn a_derived_finding_carries_the_source_the_contract_binds_to_its_kind() {
        let built = finding(&ReconcileSettings::default());
        assert_eq!(built.source, periskop_core::finding::Source::Reconciled);
        assert_eq!(built.detector.component, Component::Reconciliation);
        assert_eq!(built.detector.rule_hash.len(), 64);
    }

    #[test]
    fn a_threshold_change_moves_the_rule_hash_and_not_a_code_point_identity() {
        // The report has to show that the rules were configured differently.
        // What it must not show is a different finding for the same place in the
        // code: an egress point is what it is whatever the window says.
        //
        // The claim is deliberately stated for the kinds anchored on a code
        // point only. The two anchored on traffic are grouped by a threshold,
        // and the test below this one is where that is pinned.
        let default = finding(&ReconcileSettings::default());
        let strict = finding(&ReconcileSettings::default().with_min_dormant_window_ms(7_200_000));

        assert_ne!(default.detector.rule_hash, strict.detector.rule_hash);
        assert_eq!(default.finding_id, strict.finding_id);
    }

    #[test]
    fn every_threshold_this_build_has_reaches_the_rule_digest() {
        // The digest is what tells two reports apart when only the configuration
        // moved, so a threshold missing from it would let two differently
        // configured runs claim the same detector. Each one is moved on its own,
        // because a digest covering two of three would pass a test that changed
        // all three at once.
        let base = ReconcileSettings::default();
        let hash_of = |settings: &ReconcileSettings| detector(RULE, settings).rule_hash;

        assert_ne!(
            hash_of(&base),
            hash_of(&base.clone().with_min_dormant_window_ms(7_200_000))
        );
        assert_ne!(
            hash_of(&base),
            hash_of(&base.clone().with_join_tolerance_ms(30_000))
        );
        assert_ne!(
            hash_of(&base),
            hash_of(
                &base.clone().with_volume_band(
                    crate::settings::VolumeBand::declared(5_000, 30_000).unwrap()
                )
            )
        );
    }

    #[test]
    fn attaching_observations_leaves_the_identity_where_it_was() {
        let mut built = finding(&ReconcileSettings::default());
        let before = built.finding_id.clone();
        attach_event_refs(
            &mut built,
            &[
                "ee_5b18c30af7924de6".to_owned(),
                "ee_0000000000000001".to_owned(),
            ],
        );

        assert_eq!(built.finding_id, before);
        // The egress point stays at the head, which is where the identity is
        // read from.
        assert_eq!(built.refs[0].ref_type, RefType::EgressPoint);
        assert_eq!(built.refs.len(), 3);
    }

    #[test]
    fn attached_references_and_evidence_are_ordered_and_deduplicated() {
        let mut built = finding(&ReconcileSettings::default());
        attach_event_refs(
            &mut built,
            &[
                "ee_5b18c30af7924de6".to_owned(),
                "ee_5b18c30af7924de6".to_owned(),
            ],
        );
        attach_evidence(
            &mut built,
            vec![
                join_evidence("J2:target_only".to_owned()),
                join_evidence("J2:none".to_owned()),
            ],
        );

        assert_eq!(built.refs.len(), 2);
        assert_eq!(built.evidence.len(), 2);
        let mut sorted = built.evidence.clone();
        sorted.sort();
        assert_eq!(built.evidence, sorted);
    }

    #[test]
    fn a_field_boundary_in_the_rule_digest_is_not_ambiguous() {
        assert_ne!(
            full_hash("rr/v1", &["ab", "c"]),
            full_hash("rr/v1", &["a", "bc"])
        );
    }
}
