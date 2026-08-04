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

use periskop_core::finding::{Confidence, Finding, Kind};

use crate::declared::DeclaredPoint;
use crate::emit;
use crate::join::JoinResult;
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
        if join.is_matched(point.egress_point_id()) {
            continue;
        }

        let evidence = emit::join_evidence(format!(
            "J2:none observation_window_ms={} observed_calls={observed_calls} unlinked_events={}",
            window.duration_ms(),
            join.unlinked_events()
        ));

        match emit::derived_finding(
            Kind::DormantEgressPoint,
            confidence_for(point, join),
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
/// Two things weaken it and both are about attribution rather than about the
/// code. A point whose destination was never resolved offers the join almost
/// nothing to match on, so its absence may be an absence of evidence. And a run
/// that failed to attribute some of the calls it did observe cannot be sure that
/// none of them belonged here.
fn confidence_for(point: &DeclaredPoint, join: &JoinResult) -> Confidence {
    if point.target().is_some() && join.unlinked_events() == 0 {
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
