//! `dormant_egress_point`: a call site nothing was seen to use.
//!
//! The finding says one thing only: during a window of a stated length, no
//! observed call could be attributed to this point in the code. It does not say
//! the code is dead. `reconciliation/spec.md` §5.2 keeps both readings open on
//! purpose, because "nobody calls this any more" and "nothing triggered it today"
//! are indistinguishable from the outside and the second is the more common one.
//!
//! Which is why the window reaches the evidence of every finding this module
//! emits, and why a window too short to support the reading at all produces no
//! findings rather than weak ones. That decision is not taken here: it is taken
//! in [`crate::capability`], before anything is derived, so the reason a report
//! has no dormant findings is written down instead of inferred from their
//! absence.
//!
//! The other half of the same discipline is which links may silence a finding,
//! and getting it wrong cost this module every finding it was built to produce.
//! Asking the join whether a point matched anything at all let the weakest rung
//! answer: one observed call to a vendor tied itself to every call site naming
//! that vendor, so a repository with forty OpenAI call sites and one working
//! call reported none of them dormant, and nothing in the report said why. A
//! link is read here as silence only when it places the call at the point,
//! which is [`MatchTier::attributes_a_call`]. A weaker link does not silence
//! the finding; it weakens it, and it is named in the evidence so a reader can
//! see what the run had.

use periskop_core::finding::{Confidence, Finding, Kind};

use crate::declared::DeclaredPoint;
use crate::emit;
use crate::join::{JoinResult, MatchTier};
use crate::settings::ReconcileSettings;
use crate::window::ObservationWindow;

pub(crate) const RULE_ID: &str = "any.reconciled.dormant-egress-point";

/// What one derivation pass produced.
#[derive(Debug, Default)]
pub(crate) struct Derived {
    pub findings: Vec<Finding>,
    /// The engine contradicting itself. Travels to the report diagnostics rather
    /// than to a coverage counter, and never disappears into a discarded result.
    pub faults: Vec<String>,
}

/// Derives one finding per code point no observation reached.
pub(crate) fn derive(
    points: &[DeclaredPoint],
    join: &JoinResult,
    window: ObservationWindow,
    observed_calls: usize,
    settings: &ReconcileSettings,
) -> Derived {
    let mut derived = Derived::default();

    for point in points {
        let attribution = join.strongest_tier_for(point.egress_point_id());
        if attribution.is_some_and(MatchTier::attributes_a_call) {
            continue;
        }

        // The rung the run reached, which past this line is either nothing or
        // the provider. Writing `none` for a provider level tie would state the
        // claim more firmly than the run can defend, and a reader deciding
        // whether to act on a suspected dormancy needs to know that traffic to
        // that vendor was seen.
        let rung = attribution.map_or("none", MatchTier::as_str);
        let evidence = emit::join_evidence(format!(
            "J2:{rung} observation_window_ms={} observed_calls={observed_calls} unlinked_events={}",
            window.duration_ms(),
            join.unlinked_events()
        ));

        match emit::derived_finding(
            Kind::DormantEgressPoint,
            confidence_for(point, join, attribution),
            point.provider_ref(),
            point.egress_point_id(),
            evidence,
            settings,
            RULE_ID,
        ) {
            Ok(finding) => {
                let finding = finding
                    .with_location(emit::code_location(point.path()))
                    .with_coverage_impact(periskop_core::finding::CoverageImpact::None);
                let finding = match point.egress_kind() {
                    Some(kind) => finding.with_egress_kind(kind),
                    None => finding,
                };
                derived.findings.push(finding);
            }
            // A point that reached this far already carries a contract shaped
            // identity, so this is the engine disagreeing with itself rather
            // than bad input. Either way it is named: swallowing it would drop a
            // code point out of the report with nothing to show it was there.
            Err(error) => derived.faults.push(format!(
                "dormant derivation could not build a finding for {}: {error}",
                point.egress_point_id()
            )),
        }
    }

    derived
}

/// How firmly the absence may be stated.
///
/// Three things weaken it and all three are about attribution rather than about
/// the code. A point whose destination was never resolved offers the join almost
/// nothing to match on, so its absence may be an absence of evidence. A run that
/// failed to attribute some of the calls it did observe cannot be sure that none
/// of them belonged here. And a point tied to observed traffic by the provider
/// alone has the same doubt in a sharper form: a call to that vendor was seen
/// and something made it, so this may be the line that did.
///
/// The third is the compromise this module rests on and it is a deliberate one.
/// Suppressing the finding on a provider level tie loses every dormant finding
/// a real repository could produce; stating it as confirmed would claim a line
/// never ran while holding evidence that a call it could have made was
/// observed. Reporting it at `suspect` keeps both halves: the reader is told,
/// and told how much the claim is worth. The residual false positive is
/// catalogued in `docs/05-quality/known-gaps.md` rather than left for a user to
/// discover.
fn confidence_for(
    point: &DeclaredPoint,
    join: &JoinResult,
    attribution: Option<MatchTier>,
) -> Confidence {
    let unattributed_traffic = join.unlinked_events() > 0 || attribution.is_some();
    if point.target().is_some() && !unattributed_traffic {
        Confidence::Confirmed
    } else {
        Confidence::Suspect
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::declared::tests::{point, point_without_operation, unresolved_point};
    use crate::join::{join, tests::event};

    const EP: &str = "ep_3f0a91c7d4e28b56";
    const OTHER_EP: &str = "ep_0000000000000001";
    const LONG_WINDOW: ObservationWindow = ObservationWindow::of_ms(3_600_000);

    /// The shape of a repository that uses one vendor from many places: the
    /// client is built with the library default, so the scanner reads no
    /// destination, and each site invokes a different operation.
    fn many_points_for_one_provider(count: usize) -> Vec<DeclaredPoint> {
        (0..count)
            .map(|index| {
                unresolved_point(&format!("ep_{index:016x}"), "openai")
                    .with_operation(format!("operation.{index}"))
            })
            .collect()
    }

    fn derive_with(
        points: &[DeclaredPoint],
        events: &[periskop_runtime_collector::EgressEvent],
    ) -> Derived {
        let result = join(points, events);
        derive(
            points,
            &result,
            LONG_WINDOW,
            events.len(),
            &ReconcileSettings::default(),
        )
    }

    #[test]
    fn a_point_no_call_reached_is_reported_once() {
        let points = [point(EP, "api.openai.com", "chat.completions.create")];
        let derived = derive_with(&points, &[]);

        assert_eq!(derived.findings.len(), 1);
        assert_eq!(derived.findings[0].kind, Kind::DormantEgressPoint);
        assert_eq!(derived.findings[0].confidence, Confidence::Confirmed);
        assert!(derived.faults.is_empty());
    }

    #[test]
    fn a_point_a_call_reached_produces_nothing() {
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
    fn one_working_call_does_not_vouch_for_every_other_site_using_the_same_vendor() {
        // The defect this test exists for, in the shape it takes in a real
        // repository: forty call sites, one vendor, one call observed. Every
        // pair agrees on the provider and on nothing else, and a run that read
        // a provider level tie as execution reported none of the untouched
        // thirty nine, produced no finding, no suppression and no counter, and
        // so said nothing at all while appearing to have looked.
        let points = many_points_for_one_provider(40);
        let events = [event("openai", "operation.7", "api.openai.com", "openai")];
        let derived = derive_with(&points, &events);

        assert_eq!(
            derived.findings.len(),
            39,
            "the one point the call is attributable to is silenced and no other: {:?}",
            derived.faults
        );
        // Not one of them may be stated firmly: a call to this vendor was seen
        // and any of these lines could have made it.
        assert!(derived
            .findings
            .iter()
            .all(|finding| finding.confidence == Confidence::Suspect));
        // And the reader is told which rung produced that doubt.
        assert!(derived.findings[0].evidence[0]
            .r#ref
            .starts_with("J2:provider_only "));
        assert!(derived.faults.is_empty());
    }

    #[test]
    fn a_vendor_nothing_was_seen_to_reach_is_reported_more_firmly_than_one_that_was() {
        // The pair that shows the weakening is the provider tie and not the
        // window: same point, same window, one run with a call to its vendor
        // and one without.
        let points = [point(EP, "api.openai.com", "chat.completions.create")];
        let untied = derive_with(&points, &[]);
        let tied = derive_with(
            &points,
            &[event(
                "openai",
                "embeddings.create",
                "eu.api.openai.com",
                "openai",
            )],
        );

        assert_eq!(untied.findings[0].confidence, Confidence::Confirmed);
        assert_eq!(tied.findings.len(), 1);
        assert_eq!(tied.findings[0].confidence, Confidence::Suspect);
    }

    #[test]
    fn a_point_reached_only_through_the_transport_layer_is_not_dormant() {
        // The escape this crate is built to avoid: a Node hook records the same
        // request under another module and another operation, and a join that
        // could not unite them would report working code as never executed.
        let points = [point_without_operation(EP, "api.openai.com")];
        let events = [event("node:https", "post", "api.openai.com", "openai")];
        assert!(derive_with(&points, &events).findings.is_empty());
    }

    #[test]
    fn the_window_the_claim_rests_on_is_in_the_evidence() {
        let points = [point(EP, "api.openai.com", "chat.completions.create")];
        let derived = derive_with(&points, &[]);
        let evidence = &derived.findings[0].evidence[0].r#ref;

        // A duration and two counts. No stamp, so the same observations
        // reconciled tomorrow produce the same bytes.
        assert_eq!(
            evidence,
            "J2:none observation_window_ms=3600000 observed_calls=0 unlinked_events=0"
        );
    }

    #[test]
    fn a_point_with_no_resolved_destination_is_only_ever_suspected_dormant() {
        let points = [unresolved_point(EP, "openai")];
        let derived = derive_with(&points, &[]);
        assert_eq!(derived.findings[0].confidence, Confidence::Suspect);
    }

    #[test]
    fn an_unattributed_call_weakens_every_absence_in_the_run() {
        // Something did leave the process and nothing could say where from. That
        // is exactly the case where "this point never ran" may be wrong.
        let points = [point(EP, "api.openai.com", "chat.completions.create")];
        let events = [event(
            "anthropic",
            "messages.create",
            "api.anthropic.com",
            "anthropic",
        )];
        let derived = derive_with(&points, &events);

        assert_eq!(derived.findings.len(), 1);
        assert_eq!(derived.findings[0].confidence, Confidence::Suspect);
    }

    #[test]
    fn findings_do_not_depend_on_the_order_the_points_arrived_in() {
        let one = point(EP, "api.openai.com", "chat.completions.create");
        let other = point(OTHER_EP, "api.anthropic.com", "messages.create");

        let forward = derive_with(&[one.clone(), other.clone()], &[]);
        let backward = derive_with(&[other, one], &[]);

        let ids = |derived: &Derived| {
            let mut ids: Vec<String> = derived
                .findings
                .iter()
                .map(|f| f.finding_id.clone())
                .collect();
            ids.sort();
            ids
        };
        assert_eq!(ids(&forward), ids(&backward));
        assert_eq!(forward.findings.len(), 2);
    }
}
