//! The four buckets every observed flow falls into.
//!
//! Only `in_scope` can produce an unmatched traffic finding. The other three
//! never enter false positive accounting, and that is exactly why they are
//! dangerous: a bucket that keeps flows out of the count and then disappears
//! from the report is a silent swallow, which is the failure the counting was
//! introduced to prevent. So this module makes both halves structural. A flow
//! cannot exist without a bucket, and a tally cannot be rendered without all
//! four counters ([`ScopeTally::counters`]), including the zeros.
//!
//! The classification order is fixed and stated, because the order is where the
//! honesty lives: a flow nobody could attribute must not be quietly filed as
//! somebody else's traffic.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::flow::ProcessAttribution;
use crate::observation::Observation;

/// Which bucket a flow falls into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowScope {
    /// The process is attributable to the codebase under scan.
    InScope,
    /// Attributed, but not to the codebase under scan: the developer's own AI
    /// tooling, a browser, an operating system service.
    OutOfScopeProcess,
    /// A declared allow list entry.
    KnownBenign,
    /// Nobody could be attributed. A high rate here is not a defect, it is a
    /// measured gap in visibility.
    Undetermined,
}

impl FlowScope {
    /// Every bucket, in report order.
    ///
    /// The list is public and fixed so a renderer cannot iterate over "the
    /// buckets that had something in them". A bucket that vanishes when it is
    /// empty takes its zero with it, and a zero is the answer to a question a
    /// reader asked.
    pub const ALL: [FlowScope; 4] = [
        Self::InScope,
        Self::OutOfScopeProcess,
        Self::KnownBenign,
        Self::Undetermined,
    ];

    /// The contract spelling. Exhaustive by construction: adding a variant
    /// stops the build here rather than silently widening the enum.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InScope => "in_scope",
            Self::OutOfScopeProcess => "out_of_scope_process",
            Self::KnownBenign => "known_benign",
            Self::Undetermined => "undetermined",
        }
    }

    /// Whether reconciliation may raise an unmatched traffic finding from this
    /// bucket.
    ///
    /// One bucket, by contract. The three that answer `false` still appear in
    /// the report; not counting them and not showing them are different things.
    pub fn counts_toward_findings(self) -> bool {
        matches!(self, Self::InScope)
    }
}

/// What the operator declared about the machine being watched.
///
/// There is no `Default`, on purpose. An empty policy is a legitimate state,
/// but it is one where nothing can be attributed to the codebase and every
/// attributed flow lands in `out_of_scope_process`. That has to be a decision
/// somebody made and can read back, not what happens when a caller forgets to
/// pass anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopePolicy {
    codebase_processes: BTreeSet<String>,
    declared_benign_hosts: BTreeSet<String>,
}

impl ScopePolicy {
    /// Declares which processes belong to the codebase under scan.
    ///
    /// Entries are matched against [`crate::flow::ProcessRecord::scope_key`]:
    /// the executable path when there is one, the short kernel name otherwise.
    pub fn for_codebase<I, S>(processes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            codebase_processes: processes.into_iter().map(Into::into).collect(),
            declared_benign_hosts: BTreeSet::new(),
        }
    }

    /// Adds a destination the operator declared benign.
    ///
    /// Exact host match only. A pattern language here would make the allow list
    /// able to swallow more than the operator wrote down, and the allow list is
    /// already the entry in this policy that most easily turns into an escape
    /// hatch.
    pub fn with_declared_benign_host(mut self, host: impl Into<String>) -> Self {
        self.declared_benign_hosts.insert(host.into());
        self
    }

    /// Places one observation in a bucket.
    ///
    /// The order is the argument:
    ///
    /// 1. Nothing was attributed, so nothing can be claimed about ownership.
    ///    `undetermined`.
    /// 2. A process was attributed but carries no name to match. A pid names a
    ///    process, not a codebase, so this is still `undetermined` rather than
    ///    somebody else's traffic: filing it as out of scope would remove it
    ///    from finding generation on the strength of a fact nobody has.
    /// 3. The destination is on the declared allow list. `known_benign` wins
    ///    over `in_scope`, otherwise the allow list would have no effect on the
    ///    only bucket that produces findings, which is the bucket the operator
    ///    was declaring against.
    /// 4. The process is in the declared codebase. `in_scope`.
    /// 5. Anything left is attributed and not ours. `out_of_scope_process`.
    pub fn classify(&self, observation: &Observation) -> FlowScope {
        if observation.process_attribution == ProcessAttribution::Unattributed {
            return FlowScope::Undetermined;
        }

        let Some(process) = observation.process.as_ref() else {
            // Attribution says a process was identified and no record came
            // with it. The record is contradictory and will be rejected when it
            // is built; the bucket says what is true in the meantime.
            return FlowScope::Undetermined;
        };
        let Some(scope_key) = process.scope_key() else {
            return FlowScope::Undetermined;
        };

        if observation
            .resolved_host
            .as_deref()
            .is_some_and(|host| self.declared_benign_hosts.contains(host))
        {
            return FlowScope::KnownBenign;
        }

        if self.codebase_processes.contains(scope_key) {
            FlowScope::InScope
        } else {
            FlowScope::OutOfScopeProcess
        }
    }
}

/// How many flows landed in each bucket.
///
/// Feeds `out_of_scope_flows`, `known_benign_flows` and `unattributed_flows` in
/// the coverage statement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScopeTally {
    in_scope: u64,
    out_of_scope_process: u64,
    known_benign: u64,
    undetermined: u64,
}

impl ScopeTally {
    /// Counts one flow. Exhaustive, so a new bucket cannot be added without a
    /// counter to hold it.
    pub fn record(&mut self, scope: FlowScope) {
        let counter = match scope {
            FlowScope::InScope => &mut self.in_scope,
            FlowScope::OutOfScopeProcess => &mut self.out_of_scope_process,
            FlowScope::KnownBenign => &mut self.known_benign,
            FlowScope::Undetermined => &mut self.undetermined,
        };
        *counter = counter.saturating_add(1);
    }

    pub fn count(&self, scope: FlowScope) -> u64 {
        match scope {
            FlowScope::InScope => self.in_scope,
            FlowScope::OutOfScopeProcess => self.out_of_scope_process,
            FlowScope::KnownBenign => self.known_benign,
            FlowScope::Undetermined => self.undetermined,
        }
    }

    /// All four counters, always, including the zeros.
    ///
    /// A renderer that wants to show buckets has to take the whole array; there
    /// is no accessor that hands back only the non empty ones.
    pub fn counters(&self) -> [(FlowScope, u64); FlowScope::ALL.len()] {
        FlowScope::ALL.map(|scope| (scope, self.count(scope)))
    }

    pub fn total(&self) -> u64 {
        self.counters().iter().map(|(_, count)| count).sum()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::flow::tests::{five_tuple, process};
    use crate::flow::{ProcessRecord, ResolvedHostSource, SniSource};

    fn policy() -> ScopePolicy {
        ScopePolicy::for_codebase(["/srv/app/venv/bin/python3"])
            .with_declared_benign_host("telemetry.internal")
    }

    fn observation() -> Observation {
        Observation::new("h_1", 1, five_tuple(), SniSource::ClientHello)
    }

    fn app_process() -> ProcessRecord {
        ProcessRecord {
            exe: Some("/srv/app/venv/bin/python3".to_owned()),
            ..process()
        }
    }

    #[test]
    fn a_flow_nobody_could_attribute_is_undetermined() {
        assert_eq!(policy().classify(&observation()), FlowScope::Undetermined);
    }

    #[test]
    fn a_process_from_the_codebase_is_in_scope() {
        let observed = observation().kernel_attributed(app_process());
        assert_eq!(policy().classify(&observed), FlowScope::InScope);
    }

    #[test]
    fn a_process_outside_the_codebase_is_out_of_scope_and_not_hidden() {
        // The developer's own editor assistant, on the same machine, talking to
        // the same provider. It is not a finding and it is not invisible.
        let editor = ProcessRecord {
            exe: Some("/Applications/Editor.app/Contents/MacOS/Editor".to_owned()),
            ..process()
        };
        let observed = observation().kernel_attributed(editor);
        assert_eq!(policy().classify(&observed), FlowScope::OutOfScopeProcess);
    }

    #[test]
    fn a_declared_benign_destination_wins_over_the_codebase() {
        // Otherwise the allow list would only ever apply to traffic that was
        // never going to produce a finding anyway.
        let observed = observation()
            .kernel_attributed(app_process())
            .resolved("telemetry.internal", ResolvedHostSource::Dns);
        assert_eq!(policy().classify(&observed), FlowScope::KnownBenign);
    }

    #[test]
    fn the_allow_list_matches_the_host_exactly() {
        let observed = observation()
            .kernel_attributed(app_process())
            .resolved("evil.telemetry.internal", ResolvedHostSource::Dns);
        assert_eq!(policy().classify(&observed), FlowScope::InScope);
    }

    #[test]
    fn an_attributed_process_with_no_name_stays_undetermined() {
        // A pid names a process, not a codebase. Filing this as out of scope
        // would drop it out of finding generation on a fact nobody has.
        let nameless = ProcessRecord {
            pid: 4821,
            pid_start_time: None,
            comm: None,
            exe: None,
            cmdline_hash: None,
        };
        let observed = observation().inferred(nameless);
        assert_eq!(policy().classify(&observed), FlowScope::Undetermined);
    }

    #[test]
    fn an_unattributed_flow_to_a_declared_host_is_still_undetermined() {
        // The allow list says a destination is fine for a declared sender. With
        // no sender established there is nothing to apply it to, and calling
        // the flow benign would be a judgement nobody can back.
        let observed = observation().resolved("telemetry.internal", ResolvedHostSource::Dns);
        assert_eq!(policy().classify(&observed), FlowScope::Undetermined);
    }

    #[test]
    fn an_inferred_process_is_bucketed_like_an_attributed_one() {
        // A probabilistic match is still an attribution; the record says which
        // kind it was, and the bucket does not have to repeat it.
        let observed = observation().inferred(app_process());
        assert_eq!(policy().classify(&observed), FlowScope::InScope);
    }

    #[test]
    fn an_empty_policy_attributes_nothing_to_the_codebase() {
        let empty = ScopePolicy::for_codebase(Vec::<String>::new());
        let observed = observation().kernel_attributed(app_process());
        assert_eq!(empty.classify(&observed), FlowScope::OutOfScopeProcess);
    }

    #[test]
    fn only_one_bucket_feeds_finding_generation() {
        assert!(FlowScope::InScope.counts_toward_findings());
        for quiet in [
            FlowScope::OutOfScopeProcess,
            FlowScope::KnownBenign,
            FlowScope::Undetermined,
        ] {
            assert!(!quiet.counts_toward_findings());
        }
    }

    #[test]
    fn every_bucket_is_reported_even_when_it_is_empty() {
        // The silent swallow this whole module exists to prevent: three buckets
        // that keep flows out of the count and then disappear from the report.
        let mut tally = ScopeTally::default();
        tally.record(FlowScope::InScope);

        let counters = tally.counters();
        assert_eq!(counters.len(), FlowScope::ALL.len());
        for scope in FlowScope::ALL {
            assert!(
                counters.iter().any(|(bucket, _)| *bucket == scope),
                "{scope:?} dropped out of the report"
            );
        }
        assert_eq!(tally.count(FlowScope::KnownBenign), 0);
        assert_eq!(tally.total(), 1);
    }

    #[test]
    fn the_bucket_list_cannot_shrink_without_the_build_noticing() {
        assert_eq!(FlowScope::ALL.len(), 4);
        let distinct: BTreeSet<&str> = FlowScope::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(distinct.len(), FlowScope::ALL.len());
    }

    #[test]
    fn counts_land_in_the_bucket_they_were_recorded_under() {
        let mut tally = ScopeTally::default();
        for scope in [
            FlowScope::KnownBenign,
            FlowScope::KnownBenign,
            FlowScope::Undetermined,
        ] {
            tally.record(scope);
        }
        assert_eq!(tally.count(FlowScope::KnownBenign), 2);
        assert_eq!(tally.count(FlowScope::Undetermined), 1);
        assert_eq!(tally.count(FlowScope::InScope), 0);
        assert_eq!(tally.total(), 3);
    }
}
