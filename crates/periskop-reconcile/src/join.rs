//! J2: the code side against the runtime side.
//!
//! The trap this module is built around is a real one and it is not obvious. The
//! same call is seen by hooks sitting at different layers, and each layer names
//! itself: a Python hook wrapping the SDK records `library.module = "openai"` and
//! `operation = "chat.completions.create"`, while a Node hook wrapping the
//! transport records `library.module = "node:https"` and `operation = "post"` for
//! the very same request. A join keyed on the module would split one call into
//! two unrelated observations, attribute neither to the code, and then report the
//! code that made it as never having run. So the module takes no part in the key
//! at all, and the operation only takes part when both sides name one.
//!
//! What is left is a ladder. Each rung rests on weaker evidence than the one
//! above it and says so, because a derived finding may never be stated more
//! confidently than the join that produced it. The rungs are mutually exclusive
//! by construction, so a pair of records lands on exactly one and the result does
//! not depend on the order the records arrived in.

use std::collections::BTreeSet;

use serde::Serialize;

use periskop_runtime_collector::event::{DegradedReason, EgressEvent};

use crate::declared::DeclaredPoint;
use crate::target::TargetId;

/// The word a source writes when it could not tell.
///
/// The contract requires the value to be written rather than omitted, so that an
/// unclassified provider or an unreadable destination cannot be hidden behind a
/// missing key. It is a sentinel and never a value, and both fields that carry
/// it are guarded here for the same reason: letting two of them join would take
/// that honesty and turn it into a match between any two unknown things, and
/// letting one of them stand as a destination would turn "I could not see where
/// this went" into "it went somewhere else".
const UNRESOLVED: &str = "unknown";

/// How a code point and an observed call were tied together.
///
/// Declared strongest first, and the derived ordering is that strength ordering:
/// it decides which rung a pair keeps when the same pair is offered twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchTier {
    /// Both sides name the same operation and the same destination.
    OperationAndTarget,
    /// The same operation reached a different destination. This is the rung a
    /// target drift is established on.
    OperationOnly,
    /// The same destination, with no operation on the code side to compare. This
    /// is the rung that unites two hooks sitting at different layers.
    TargetOnly,
    /// Only the provider classification agrees. Never enough to state anything
    /// as confirmed: a call to the same provider is not evidence that it came
    /// from this line of code.
    ProviderOnly,
}

impl MatchTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OperationAndTarget => "operation_and_target",
            Self::OperationOnly => "operation_only",
            Self::TargetOnly => "target_only",
            Self::ProviderOnly => "provider_only",
        }
    }

    /// Whether a claim resting on this rung may be stated as confirmed.
    pub fn is_confirmed(self) -> bool {
        !matches!(self, Self::ProviderOnly)
    }

    /// Whether this rung is evidence that the code point ran.
    ///
    /// A different question from [`Self::is_confirmed`], and they are written
    /// separately because a build answered them with one predicate and stopped
    /// producing dormancy findings in every repository that made a single
    /// working call. How well two records agree is not the same claim as where
    /// the call came from, and a rung added later may well answer the two
    /// differently, so the match below is exhaustive rather than delegating.
    ///
    /// Rung by rung. `OperationAndTarget` names both keys and needs no
    /// argument. `OperationOnly` says the operation this point invokes was
    /// invoked and reached somewhere else, which is the rung a target drift is
    /// established on: one run may not call a point drifting and never executed
    /// at the same time. `TargetOnly` is the rung that unites two hooks sitting
    /// at different layers, and refusing it would reopen the exact trap this
    /// module was built around and report working code as never executed.
    ///
    /// `ProviderOnly` is refused, and that refusal is the point of the method.
    /// It says only that some call reached the same vendor, which every call
    /// site for that vendor in the repository has in common; reading it as
    /// execution lets one observed call vouch for forty untouched ones. What it
    /// does establish is that traffic this point could have produced was seen,
    /// so the absence is stated less firmly rather than not stated at all.
    pub fn attributes_a_call(self) -> bool {
        match self {
            Self::OperationAndTarget | Self::OperationOnly | Self::TargetOnly => true,
            Self::ProviderOnly => false,
        }
    }
}

/// One code point tied to one observed call.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct J2Match {
    pub egress_point_id: String,
    pub egress_event_id: String,
    pub tier: MatchTier,
    /// The destination the call actually reached, when the record named one.
    pub observed_target: Option<TargetId>,
}

/// Everything the join established, and everything it could not.
///
/// Only [`join`] builds one and both fields are private, which is what lets
/// [`JoinResult::matches_for`] rely on `matches` being ordered by code point:
/// the ordering is a property of the constructor rather than a hope about the
/// caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JoinResult {
    matches: Vec<J2Match>,
    /// Observed calls that reached no code point.
    ///
    /// A count and a list of identities, never a finding. Failing to attribute
    /// an observation is a loss of coverage rather than a fact about the system
    /// under observation (K-10), and promoting it to a finding would inflate
    /// both the finding count and the false positive rate with the tool's own
    /// blind spots.
    unlinked_event_ids: Vec<String>,
}

impl JoinResult {
    pub fn matches(&self) -> &[J2Match] {
        &self.matches
    }

    pub fn unlinked_event_ids(&self) -> &[String] {
        &self.unlinked_event_ids
    }

    pub fn unlinked_events(&self) -> u64 {
        self.unlinked_event_ids.len() as u64
    }

    /// Every match established for one code point.
    ///
    /// Found by search rather than by scanning the whole list, because both
    /// derivers call this once per code point and the list grows with the
    /// product of the two sources. A repository with thousands of call sites
    /// paid for that scan twice per site, and the weakest rung ties nearly
    /// every pair, so the scan was the run rather than a detail of it.
    pub fn matches_for<'a>(
        &'a self,
        egress_point_id: &'a str,
    ) -> impl Iterator<Item = &'a J2Match> {
        let first = self
            .matches
            .partition_point(|m| m.egress_point_id.as_str() < egress_point_id);
        self.matches[first..]
            .iter()
            .take_while(move |m| m.egress_point_id == egress_point_id)
    }

    /// The strongest rung any observation reached for one code point.
    ///
    /// `None` when nothing was tied to the point at all. [`MatchTier`] orders
    /// itself by strength, so the strongest is the minimum.
    ///
    /// This replaced an `is_matched` predicate, and removing that name is part
    /// of the fix rather than tidying: a caller asking whether a point matched
    /// reads the answer as whether it ran, and the weakest rung answers yes to
    /// the first while saying nothing about the second. A caller now receives
    /// the rung and has to decide, which is the decision
    /// [`MatchTier::attributes_a_call`] states once for everybody.
    pub fn strongest_tier_for(&self, egress_point_id: &str) -> Option<MatchTier> {
        self.matches_for(egress_point_id).map(|m| m.tier).min()
    }
}

/// The comparable form of one observed call.
///
/// Built once per event rather than once per pair, so that a destination is
/// normalised the same way no matter how many code points it is compared with.
struct EventKey<'e> {
    egress_event_id: &'e str,
    operation: &'e str,
    target: Option<TargetId>,
    provider_ref: Option<&'e str>,
}

impl<'e> EventKey<'e> {
    fn of(event: &'e EgressEvent) -> Self {
        Self {
            egress_event_id: &event.egress_event_id,
            operation: &event.operation,
            target: observed_target(event),
            provider_ref: event
                .target
                .provider_ref
                .as_deref()
                .filter(|p| *p != UNRESOLVED),
        }
    }
}

/// The destination an observation established, when it established one.
///
/// A hook that could not read where a call went still has to write the field,
/// so the absence arrives as a word rather than as a missing key, and it says
/// why in `degraded_reasons`. Both are read, because a hook may state one
/// without the other and either one alone is the hook saying it did not see.
///
/// Accepting the sentinel as a destination is the most expensive mistake this
/// crate can make, and it is not a hypothetical one. The word compares unequal
/// to every real host, so a point declaring `api.openai.com` would drift
/// against it on whichever rung the pair reached, and the report would state on
/// confirmed evidence that a call went somewhere else when nothing was seen to
/// go anywhere. Not knowing where a call went is a gap in observation: the run
/// counts the call, still attributes it through the operation if it can, and
/// never accuses the code with it.
fn observed_target(event: &EgressEvent) -> Option<TargetId> {
    if event.target.host_id.trim().eq_ignore_ascii_case(UNRESOLVED) {
        return None;
    }
    let unresolved = event
        .degraded_reasons
        .as_ref()
        .is_some_and(|reasons| reasons.contains(&DegradedReason::TargetNotResolved));
    if unresolved {
        return None;
    }
    TargetId::parse(&event.target.host_id, event.target.port)
}

/// Ties observed calls to the code points that could have made them.
///
/// Every pair is considered, and each one lands on the single rung that applies
/// to it. A code point is not withdrawn from the ladder once it matches: the same
/// point legitimately matches one call through its operation and another through
/// its destination, which is what happens when two hooks at different layers
/// record the same request.
///
/// The declared cost is the product of the two source sizes, and it is declared
/// rather than optimised away because indexing would not remove it: the weakest
/// rung ties a call to every code point naming its vendor, so in the shape this
/// crate has to survive, a repository using one provider from everywhere, the
/// candidate set for each point is every observation regardless of how it is
/// looked up. What indexing does buy is spent above, on the two lookups that
/// were quadratic in the output rather than in the input, and no budget for the
/// remaining product has been measured. Until one is, that is a stated gap
/// rather than a claim that the shape is fine.
pub fn join(points: &[DeclaredPoint], events: &[EgressEvent]) -> JoinResult {
    let keys: Vec<EventKey<'_>> = events.iter().map(EventKey::of).collect();

    let mut matches: Vec<J2Match> = Vec::new();
    for point in points {
        for key in &keys {
            if let Some(tier) = tier_for(point, key) {
                matches.push(J2Match {
                    egress_point_id: point.egress_point_id().to_owned(),
                    egress_event_id: key.egress_event_id.to_owned(),
                    tier,
                    observed_target: key.target.clone(),
                });
            }
        }
    }

    // Sorted before deduplication so that the strongest rung survives for a pair
    // offered twice, and so that the output does not depend on the order the
    // sources handed their records over in.
    matches.sort();
    matches.dedup_by(|a, b| {
        a.egress_point_id == b.egress_point_id && a.egress_event_id == b.egress_event_id
    });

    // Set membership rather than a scan per event. The scan was quadratic in
    // the product of two numbers that both grow with the repository, and the
    // weakest rung ties nearly every pair, so on a real monorepo the answer to
    // "which observations reached nothing" cost more than the join itself.
    let linked: BTreeSet<&str> = matches.iter().map(|m| m.egress_event_id.as_str()).collect();
    let mut unlinked_event_ids: Vec<String> = keys
        .iter()
        .filter(|key| !linked.contains(key.egress_event_id))
        .map(|key| key.egress_event_id.to_owned())
        .collect();
    unlinked_event_ids.sort();
    unlinked_event_ids.dedup();

    JoinResult {
        matches,
        unlinked_event_ids,
    }
}

/// The single rung a pair lands on, if any.
fn tier_for(point: &DeclaredPoint, key: &EventKey<'_>) -> Option<MatchTier> {
    let operation_agrees = point.operation() == Some(key.operation);
    let target_agrees = match (point.target(), key.target.as_ref()) {
        (Some(declared), Some(observed)) => declared == observed,
        _ => false,
    };

    match (operation_agrees, target_agrees) {
        (true, true) => Some(MatchTier::OperationAndTarget),
        (true, false) => Some(MatchTier::OperationOnly),
        (false, true) => Some(MatchTier::TargetOnly),
        (false, false) => provider_agrees(point, key).then_some(MatchTier::ProviderOnly),
    }
}

fn provider_agrees(point: &DeclaredPoint, key: &EventKey<'_>) -> bool {
    point.provider_ref() != UNRESOLVED && key.provider_ref == Some(point.provider_ref())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;
    use crate::declared::tests::{point, point_without_operation, unresolved_point};
    use periskop_runtime_collector::event::{
        DegradedReason, Language, Library, Mechanism, PayloadShape, Process, Target,
    };

    /// An event as a hook records one, at whichever layer it sits.
    pub(crate) fn event(module: &str, operation: &str, host: &str, provider: &str) -> EgressEvent {
        EgressEvent::new(
            Process {
                language: Language::Python,
                runtime: "cpython/3.12".to_owned(),
                entrypoint_hint: None,
            },
            Library {
                module: module.to_owned(),
                mechanism: Mechanism::SdkWrapper,
            },
            operation,
            Target {
                host_id: host.to_owned(),
                port: Some(443),
                path_template: Some("/v1/chat/completions".to_owned()),
                provider_ref: Some(provider.to_owned()),
            },
            PayloadShape {
                field_paths: vec!["messages[].content".to_owned()],
                byte_size_estimate: 512,
                truncated_depth: None,
            },
        )
        .unwrap()
    }

    /// A call a hook watched without being able to read where it went.
    ///
    /// Spelled the way the contract makes a hook spell it: the sentinel in the
    /// host field, because the field may not be omitted, and the reason beside
    /// it. `fetch(someUrlObject)` in the Node hook is exactly this record.
    pub(crate) fn event_with_unresolved_target(operation: &str, provider: &str) -> EgressEvent {
        event("node:https", operation, UNRESOLVED, provider)
            .with_degraded_reasons(vec![DegradedReason::TargetNotResolved])
    }

    const EP: &str = "ep_3f0a91c7d4e28b56";

    #[test]
    fn a_destination_the_hook_could_not_read_is_not_a_destination() {
        // The sentinel compares unequal to every real host, so accepting it
        // would put "the call went elsewhere" on the strength of an observation
        // that saw nowhere. The operation still ties the two together, which is
        // the honest half of what the record established.
        let result = join(
            &[point(EP, "api.openai.com", "chat.completions.create")],
            &[event_with_unresolved_target(
                "chat.completions.create",
                "openai",
            )],
        );

        assert_eq!(result.matches().len(), 1);
        assert_eq!(result.matches()[0].tier, MatchTier::OperationOnly);
        assert_eq!(result.matches()[0].observed_target, None);
    }

    #[test]
    fn a_stated_reason_withdraws_a_destination_the_record_still_carries() {
        // The two halves of the same statement, and a hook may write either one
        // without the other. Here the host field looks readable and the record
        // says the value was not resolved, so the value is not used.
        let degraded = event(
            "node:https",
            "chat.completions.create",
            "api.openai.com",
            "openai",
        )
        .with_degraded_reasons(vec![DegradedReason::TargetNotResolved]);
        let result = join(
            &[point(EP, "api.openai.com", "chat.completions.create")],
            &[degraded],
        );

        assert_eq!(result.matches()[0].tier, MatchTier::OperationOnly);
        assert_eq!(result.matches()[0].observed_target, None);
    }

    #[test]
    fn the_weakest_rung_is_not_evidence_that_a_point_ran() {
        // The rule the whole ladder exists to keep, stated where a caller can
        // read it: agreeing on the vendor is not agreeing on the call site.
        assert!(MatchTier::OperationAndTarget.attributes_a_call());
        assert!(MatchTier::OperationOnly.attributes_a_call());
        assert!(MatchTier::TargetOnly.attributes_a_call());
        assert!(!MatchTier::ProviderOnly.attributes_a_call());
    }

    #[test]
    fn every_match_for_a_point_is_found_even_when_other_points_surround_it() {
        // The lookup searches an ordered list instead of scanning it, so it is
        // worth pinning that it finds the whole run and stops at its end. A
        // point sorting between two others is the case that would break if the
        // ordering assumption ever stopped holding.
        let points = [
            point("ep_0000000000000001", "api.openai.com", "images.generate"),
            point(EP, "api.openai.com", "chat.completions.create"),
            point("ep_ffffffffffffffff", "api.openai.com", "embeddings.create"),
        ];
        let events = [
            event(
                "openai",
                "chat.completions.create",
                "api.openai.com",
                "openai",
            ),
            event("node:https", "post", "api.openai.com", "openai"),
        ];
        let result = join(&points, &events);

        assert_eq!(result.matches_for(EP).count(), 2);
        assert_eq!(result.matches().len(), 6);
        assert!(result
            .matches_for(EP)
            .all(|m| m.egress_point_id.as_str() == EP));
    }

    #[test]
    fn a_point_reports_the_strongest_rung_it_reached_and_not_merely_that_it_reached_one() {
        let points = [point(EP, "api.openai.com", "chat.completions.create")];
        let events = [
            event("openai", "embeddings.create", "eu.api.openai.com", "openai"),
            event(
                "openai",
                "chat.completions.create",
                "api.openai.com",
                "openai",
            ),
        ];
        let result = join(&points, &events);

        assert_eq!(
            result.strongest_tier_for(EP),
            Some(MatchTier::OperationAndTarget)
        );
        assert_eq!(result.strongest_tier_for("ep_0000000000000001"), None);
    }

    #[test]
    fn agreement_on_both_keys_is_the_strongest_rung() {
        let result = join(
            &[point(EP, "api.openai.com", "chat.completions.create")],
            &[event(
                "openai",
                "chat.completions.create",
                "api.openai.com",
                "openai",
            )],
        );
        assert_eq!(result.matches().len(), 1);
        assert_eq!(result.matches()[0].tier, MatchTier::OperationAndTarget);
        assert_eq!(result.unlinked_events(), 0);
    }

    #[test]
    fn the_same_operation_at_another_destination_still_matches() {
        let result = join(
            &[point(EP, "api.openai.com", "chat.completions.create")],
            &[event(
                "openai",
                "chat.completions.create",
                "llm-gateway.internal",
                "unknown",
            )],
        );
        assert_eq!(result.matches()[0].tier, MatchTier::OperationOnly);
    }

    #[test]
    fn two_hooks_at_different_layers_reach_the_same_code_point() {
        // The trap: one request, two records, two different modules and two
        // different operations. Only the destination is common to both, and a
        // join that leaned on the module would leave the transport record
        // unattributed and the code point looking dormant.
        let sdk = event(
            "openai",
            "chat.completions.create",
            "api.openai.com",
            "openai",
        );
        let transport = event("node:https", "post", "api.openai.com", "openai");
        let result = join(
            &[point(EP, "api.openai.com", "chat.completions.create")],
            &[sdk.clone(), transport.clone()],
        );

        assert_eq!(result.matches().len(), 2);
        assert_eq!(result.unlinked_events(), 0);
        let tiers: Vec<MatchTier> = result.matches().iter().map(|m| m.tier).collect();
        assert!(tiers.contains(&MatchTier::OperationAndTarget));
        assert!(tiers.contains(&MatchTier::TargetOnly));
    }

    #[test]
    fn a_point_with_no_operation_still_reaches_its_calls_through_the_destination() {
        // A rule that names a destination but no method, and a hook that names
        // both: the destination is the only key the two have in common.
        let result = join(
            &[point_without_operation(EP, "api.openai.com")],
            &[event(
                "openai",
                "chat.completions.create",
                "api.openai.com",
                "openai",
            )],
        );
        assert_eq!(result.matches()[0].tier, MatchTier::TargetOnly);
    }

    #[test]
    fn provider_agreement_alone_is_the_weakest_rung() {
        let result = join(
            &[point(EP, "api.openai.com", "chat.completions.create")],
            &[event(
                "openai",
                "embeddings.create",
                "eu.api.openai.com",
                "openai",
            )],
        );
        assert_eq!(result.matches()[0].tier, MatchTier::ProviderOnly);
        assert!(!MatchTier::ProviderOnly.is_confirmed());
    }

    #[test]
    fn two_unclassified_destinations_do_not_join() {
        // Both sides say "unknown". Reading that as agreement would tie every
        // unclassified call to every unclassified code point.
        let unknown_point = unresolved_point(EP, "unknown");
        let result = join(
            &[unknown_point],
            &[event("httpx", "post", "some.host.example", "unknown")],
        );
        assert!(result.matches().is_empty());
        assert_eq!(result.unlinked_events(), 1);
    }

    #[test]
    fn an_observation_that_reaches_no_code_point_is_counted_not_reported() {
        let result = join(
            &[point(EP, "api.openai.com", "chat.completions.create")],
            &[event(
                "anthropic",
                "messages.create",
                "api.anthropic.com",
                "anthropic",
            )],
        );
        assert!(result.matches().is_empty());
        assert_eq!(result.unlinked_events(), 1);
        assert_eq!(result.unlinked_event_ids().len(), 1);
    }

    #[test]
    fn the_result_does_not_depend_on_the_order_the_records_arrived_in() {
        let points = [
            point(EP, "api.openai.com", "chat.completions.create"),
            point(
                "ep_0000000000000001",
                "api.anthropic.com",
                "messages.create",
            ),
        ];
        let events = [
            event(
                "openai",
                "chat.completions.create",
                "api.openai.com",
                "openai",
            ),
            event(
                "anthropic",
                "messages.create",
                "api.anthropic.com",
                "anthropic",
            ),
        ];

        let forward = join(&points, &events);
        let reversed_points = [points[1].clone(), points[0].clone()];
        let reversed_events = [events[1].clone(), events[0].clone()];
        let backward = join(&reversed_points, &reversed_events);

        assert_eq!(forward, backward);
    }

    #[test]
    fn the_same_pair_offered_twice_keeps_its_strongest_rung() {
        let one = event(
            "openai",
            "chat.completions.create",
            "api.openai.com",
            "openai",
        );
        let result = join(
            &[point(EP, "api.openai.com", "chat.completions.create")],
            &[one.clone(), one],
        );
        assert_eq!(result.matches().len(), 1);
        assert_eq!(result.matches()[0].tier, MatchTier::OperationAndTarget);
    }
}
