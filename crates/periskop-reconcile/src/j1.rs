//! J1: what left the machine, against what the application said it sent.
//!
//! `data-model.md` §3 states the key as three parts, a process identity, a
//! destination and an overlapping time window, and this module applies the ones
//! each side can state. Today that is the destination, and the reason is worth
//! being exact about rather than leaving to be discovered from behaviour.
//!
//! A flow states all three. An `EgressEvent` states one: the event contract
//! carries no process identity and, by design, no clock value at all, so neither
//! the process key nor the time constraint has a second side to be compared
//! against. Two answers were possible and only one of them is honest. Treating
//! the missing keys as agreement would let a call from one process vouch for
//! traffic from another; treating them as disagreement would leave every flow
//! unmatched and turn the product's headline finding into noise on any machine
//! running more than one program. So the pair is matched on the key both sides
//! carry, and every match says which keys it rested on, in the evidence of the
//! finding it produced. A reader is never left believing a match was time
//! constrained when nothing timed it. The contract gap is filed against its
//! owner in `hub/memory/interfaces.md` rather than papered over here.
//!
//! The time tolerance is not idle in the meantime. It decides where one
//! conversation ends and the next begins ([`crate::wire::episodes`]), which
//! decides how many findings a burst of connections produces, and its effective
//! value travels into the evidence with everything else.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use periskop_runtime_collector::event::EgressEvent;

use crate::target::TargetId;
use crate::wire::WireEpisode;

/// The word a source writes when it could not tell.
///
/// Guarded here for the reason [`crate::join`] guards it: letting two of them
/// join would turn an honest "I could not read this" into a match between any
/// two unknown things.
const UNRESOLVED: &str = "unknown";

/// How much a J1 link is worth.
///
/// The two values are the contract's, minus the third: `none` is not a quality,
/// it is the absence of a link, and it is represented by a flow appearing in
/// [`J1Result::unmatched_episode_ids`] instead of by a value nobody can attach
/// evidence to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchQuality {
    /// One candidate, a destination both sides named, and a process the kernel
    /// attributed rather than a socket table inferred.
    Exact,
    /// Everything else that still matched: more than one call could have
    /// travelled over this connection, or the destination was only an address,
    /// or the owning process was inferred. A finding resting on this rung is
    /// stated as suspected.
    Ambiguous,
}

impl MatchQuality {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Ambiguous => "ambiguous",
        }
    }
}

/// One connection tied to one observed call.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct J1Match {
    pub flow_id: String,
    pub egress_event_id: String,
    pub quality: MatchQuality,
}

/// Everything J1 established, and every connection it could not explain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct J1Result {
    matches: Vec<J1Match>,
    /// Episodes no observed call could be tied to. The candidates for the
    /// product's headline finding, and nothing more than candidates: whether one
    /// becomes a finding is decided by the bucket it sits in and by whether any
    /// code explains it.
    unmatched_episode_ids: BTreeSet<String>,
}

impl J1Result {
    pub fn matches(&self) -> &[J1Match] {
        &self.matches
    }

    pub fn is_unmatched(&self, flow_id: &str) -> bool {
        self.unmatched_episode_ids.contains(flow_id)
    }

    /// Every call tied to one connection, strongest quality first.
    pub fn matches_for<'a>(&'a self, flow_id: &'a str) -> impl Iterator<Item = &'a J1Match> {
        self.matches.iter().filter(move |m| m.flow_id == flow_id)
    }

    /// The best quality any call reached for one connection.
    pub fn quality_for(&self, flow_id: &str) -> Option<MatchQuality> {
        self.matches_for(flow_id).map(|m| m.quality).min()
    }
}

/// The comparable form of one observed call.
///
/// Built once per event rather than once per pair, so a destination is
/// normalised the same way however many connections it is compared with.
struct CallKey<'e> {
    egress_event_id: &'e str,
    target: Option<TargetId>,
}

impl<'e> CallKey<'e> {
    fn of(event: &'e EgressEvent) -> Self {
        Self {
            egress_event_id: &event.egress_event_id,
            // Deliberately the same reading [`crate::join`] applies: a host
            // field holding the sentinel is a hook saying it did not see, and
            // accepting it as a destination would tie every unreadable call to
            // every connection.
            target: (!event.target.host_id.trim().eq_ignore_ascii_case(UNRESOLVED))
                .then(|| TargetId::parse(&event.target.host_id, event.target.port))
                .flatten(),
        }
    }
}

/// Ties observed calls to the connections that could have carried them.
///
/// The relationship is one to many in both directions and the model says so:
/// one connection carries many calls under keep alive, and one call can be
/// retried over two connections. Neither side is withdrawn once it matches.
pub(crate) fn join(episodes: &[WireEpisode], events: &[EgressEvent]) -> J1Result {
    let keys: Vec<CallKey<'_>> = events.iter().map(CallKey::of).collect();
    // Indexed rather than scanned once per episode. The scan was quadratic in
    // two numbers that both grow with the run, and on a busy machine the answer
    // to "which connections reached nothing" cost more than the join itself.
    let mut by_target: BTreeMap<&TargetId, Vec<&CallKey<'_>>> = BTreeMap::new();
    for key in &keys {
        if let Some(target) = key.target.as_ref() {
            by_target.entry(target).or_default().push(key);
        }
    }
    // One call recorded twice is one call. Counting the copy as a second
    // candidate would make a link ambiguous, and every finding resting on it
    // suspected, because a stream was replayed or a directory read twice.
    for candidates in by_target.values_mut() {
        candidates.sort_by_key(|key| key.egress_event_id);
        candidates.dedup_by_key(|key| key.egress_event_id);
    }

    let mut matches: Vec<J1Match> = Vec::new();
    let mut unmatched_episode_ids: BTreeSet<String> = BTreeSet::new();

    for episode in episodes {
        let Some(candidates) = by_target.get(&episode.target) else {
            unmatched_episode_ids.insert(episode.flow_id.clone());
            continue;
        };

        let quality = quality_of(episode, candidates.len());
        for candidate in candidates {
            matches.push(J1Match {
                flow_id: episode.flow_id.clone(),
                egress_event_id: candidate.egress_event_id.to_owned(),
                quality,
            });
        }
    }

    // Ordered before deduplication so the strongest quality survives a pair
    // offered twice, and so the output does not depend on the order either
    // source handed its records over in.
    matches.sort();
    matches.dedup_by(|a, b| a.flow_id == b.flow_id && a.egress_event_id == b.egress_event_id);

    J1Result {
        matches,
        unmatched_episode_ids,
    }
}

/// How much a link to this connection is worth.
///
/// Three things weaken it and each one is a way of not knowing which call this
/// was. More than one candidate means any of them could have travelled here,
/// which is the contract's `ambiguous` exactly. An address with no name means
/// the destination was matched on what the kernel saw rather than on what
/// either side called it. And an inferred process is a socket table snapshot
/// agreeing with a connection key, which is a guess about ownership.
fn quality_of(episode: &WireEpisode, candidates: usize) -> MatchQuality {
    let kernel_attributed = matches!(
        episode.attribution,
        periskop_network_sensor::flow::ProcessAttribution::KernelAttributed
    );
    if candidates == 1 && episode.named && kernel_attributed {
        MatchQuality::Exact
    } else {
        MatchQuality::Ambiguous
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;
    use crate::wire::episodes;
    use crate::wire::tests::{flow, named_flow, opaque_flow, TOLERANCE_MS};
    use periskop_network_sensor::flow::ProcessAttribution;
    use periskop_network_sensor::scope::FlowScope;

    const BUCKET: u64 = 1_785_834_000;

    fn joined(flows: &[periskop_network_sensor::Flow], events: &[EgressEvent]) -> J1Result {
        let (episodes, _) = episodes(flows, TOLERANCE_MS);
        join(&episodes, events)
    }

    fn first_episode_id(flows: &[periskop_network_sensor::Flow]) -> String {
        episodes(flows, TOLERANCE_MS).0[0].flow_id.clone()
    }

    #[test]
    fn a_call_to_the_destination_a_connection_reached_is_tied_to_it() {
        let flows = [flow("api.openai.com", BUCKET, FlowScope::InScope)];
        let events = [crate::join::tests::event(
            "openai",
            "chat.completions.create",
            "api.openai.com",
            "openai",
        )];
        let result = joined(&flows, &events);

        assert_eq!(result.matches().len(), 1);
        assert_eq!(result.matches()[0].quality, MatchQuality::Exact);
        assert!(!result.is_unmatched(&first_episode_id(&flows)));
    }

    #[test]
    fn a_connection_no_call_explains_is_reported_as_unmatched() {
        // The candidate for the product's headline finding: data left the
        // machine and no watched application says it sent any.
        let flows = [flow("api.openai.com", BUCKET, FlowScope::InScope)];
        let events = [crate::join::tests::event(
            "anthropic",
            "messages.create",
            "api.anthropic.com",
            "anthropic",
        )];
        let result = joined(&flows, &events);

        assert!(result.matches().is_empty());
        assert!(result.is_unmatched(&first_episode_id(&flows)));
    }

    #[test]
    fn more_than_one_candidate_call_makes_the_link_ambiguous() {
        // The contract's own word for it: any of the calls could have travelled
        // over this connection, so nothing derived from the link may be stated
        // as certain.
        let flows = [flow("api.openai.com", BUCKET, FlowScope::InScope)];
        let events = [
            crate::join::tests::event(
                "openai",
                "chat.completions.create",
                "api.openai.com",
                "openai",
            ),
            crate::join::tests::event("openai", "embeddings.create", "api.openai.com", "openai"),
        ];
        let result = joined(&flows, &events);

        assert_eq!(result.matches().len(), 2);
        assert_eq!(
            result.quality_for(&first_episode_id(&flows)),
            Some(MatchQuality::Ambiguous)
        );
    }

    #[test]
    fn a_destination_only_an_address_named_never_reaches_the_exact_rung() {
        let flows = [opaque_flow("104.18.7.9", BUCKET, FlowScope::InScope)];
        let events = [crate::join::tests::event(
            "requests",
            "http.post",
            "104.18.7.9",
            "unknown",
        )];
        let result = joined(&flows, &events);

        assert_eq!(result.matches().len(), 1);
        assert_eq!(result.matches()[0].quality, MatchQuality::Ambiguous);
    }

    #[test]
    fn an_inferred_owner_never_reaches_the_exact_rung_either() {
        // A socket table snapshot agreeing with a connection key is a guess
        // about who owned it, and a guess may not produce a certain claim.
        let mut inferred = flow("api.openai.com", BUCKET, FlowScope::InScope);
        inferred.process_attribution = ProcessAttribution::Inferred;
        let events = [crate::join::tests::event(
            "openai",
            "chat.completions.create",
            "api.openai.com",
            "openai",
        )];
        let result = joined(&[inferred], &events);

        assert_eq!(result.matches()[0].quality, MatchQuality::Ambiguous);
    }

    #[test]
    fn a_call_whose_destination_the_hook_could_not_read_ties_to_nothing() {
        // The sentinel is not a host. Reading it as one would tie every
        // unobservable call to every connection and silence the finding this
        // whole phase exists to produce.
        let flows = [flow("api.openai.com", BUCKET, FlowScope::InScope)];
        let events = [crate::join::tests::event_with_unresolved_target(
            "chat.completions.create",
            "openai",
        )];
        let result = joined(&flows, &events);

        assert!(result.matches().is_empty());
        assert!(result.is_unmatched(&first_episode_id(&flows)));
    }

    #[test]
    fn the_result_does_not_depend_on_the_order_either_source_arrived_in() {
        let flows = [
            flow("api.openai.com", BUCKET, FlowScope::InScope),
            named_flow(
                "api.anthropic.com",
                "anthropic",
                BUCKET,
                FlowScope::InScope,
                54_999,
            ),
        ];
        let one = crate::join::tests::event(
            "openai",
            "chat.completions.create",
            "api.openai.com",
            "openai",
        );
        let other = crate::join::tests::event(
            "anthropic",
            "messages.create",
            "api.anthropic.com",
            "anthropic",
        );

        let forward = joined(&flows, &[one.clone(), other.clone()]);
        let backward = joined(
            &[flows[1].clone(), flows[0].clone()],
            &[other, one.clone(), one],
        );
        assert_eq!(forward, backward);
        assert_eq!(forward.matches().len(), 2);
    }

    #[test]
    fn a_run_with_no_calls_at_all_leaves_every_connection_unmatched() {
        // The two source shape: a sensor and a scan, no hooks. Every connection
        // is unexplained by an application, which is true and is exactly why the
        // finding derived from it is not stated as certain.
        let flows = [flow("api.openai.com", BUCKET, FlowScope::InScope)];
        let result = joined(&flows, &[]);

        assert!(result.matches().is_empty());
        assert!(result.is_unmatched(&first_episode_id(&flows)));
    }
}
