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

use serde::Serialize;

use periskop_runtime_collector::event::EgressEvent;

use crate::declared::DeclaredPoint;
use crate::target::TargetId;

/// A provider classification that matches nothing, including itself.
///
/// The contract requires the value to be written rather than omitted, so that an
/// unclassified destination cannot be hidden. Letting two of them join would take
/// that honesty and turn it into a match between any two unclassified things.
const UNCLASSIFIED_PROVIDER: &str = "unknown";

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
    pub fn matches_for<'a>(
        &'a self,
        egress_point_id: &'a str,
    ) -> impl Iterator<Item = &'a J2Match> {
        self.matches
            .iter()
            .filter(move |m| m.egress_point_id == egress_point_id)
    }

    pub fn is_matched(&self, egress_point_id: &str) -> bool {
        self.matches_for(egress_point_id).next().is_some()
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
            target: TargetId::parse(&event.target.host_id, event.target.port),
            provider_ref: event
                .target
                .provider_ref
                .as_deref()
                .filter(|p| *p != UNCLASSIFIED_PROVIDER),
        }
    }
}

/// Ties observed calls to the code points that could have made them.
///
/// Every pair is considered, and each one lands on the single rung that applies
/// to it. A code point is not withdrawn from the ladder once it matches: the same
/// point legitimately matches one call through its operation and another through
/// its destination, which is what happens when two hooks at different layers
/// record the same request.
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

    let mut unlinked_event_ids: Vec<String> = keys
        .iter()
        .filter(|key| {
            !matches
                .iter()
                .any(|m| m.egress_event_id == key.egress_event_id)
        })
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
    point.provider_ref() != UNCLASSIFIED_PROVIDER && key.provider_ref == Some(point.provider_ref())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;
    use crate::declared::tests::{point, point_without_operation, unresolved_point};
    use periskop_runtime_collector::event::{
        Language, Library, Mechanism, PayloadShape, Process, Target,
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

    const EP: &str = "ep_3f0a91c7d4e28b56";

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
        // The shape the scanner produces today: the finding contract carries no
        // operation, so the destination is the only key left.
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
