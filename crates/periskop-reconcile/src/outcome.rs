//! What one reconciliation pass established, and what it could not.
//!
//! Four of the fields carry no findings at all, and they are the reason this type
//! exists rather than a bare `Vec<Finding>`. A reader who is handed only findings
//! cannot tell a run that looked and found nothing from a run that never looked,
//! and every question about the second kind is answered here: which sources fed
//! the run, which derived kinds were suppressed and why, how long anything was
//! watched for, and which thresholds decided it.

use serde::Serialize;

use periskop_core::finding::Finding;
use periskop_report::coverage::ReconciliationMode;

use crate::capability::Suppression;
use crate::j1::J1Match;
use crate::join::J2Match;
use crate::settings::ReconcileSettings;
use crate::target::TargetId;
use crate::wire::WireCoverage;

/// A destination an observation supplied for a code point the scan could not
/// resolve.
///
/// Not a finding. Nothing is wrong when this appears; something the static side
/// could not read has become known, and the coverage statement can drop the
/// point from its unresolved list on the strength of it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ResolvedTarget {
    pub egress_point_id: String,
    pub observed_target: TargetId,
}

/// The result of reconciling whatever sources the run had.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReconcileOutcome {
    /// Derived findings, ordered by identity and deduplicated.
    pub findings: Vec<Finding>,
    /// Derived kinds this run did not produce, with a reason for each.
    pub suppressed: Vec<Suppression>,
    /// Destinations observation filled in for the static side.
    pub resolved_targets: Vec<ResolvedTarget>,
    /// Observed calls that reached no code point.
    ///
    /// A coverage counter, never a finding (K-10). Feeds
    /// `coverage.unlinked_events`.
    pub unlinked_events: u64,
    /// Observed calls whose destination the hook could not read.
    ///
    /// A coverage counter for the same reason as the one above and a different
    /// gap: those calls reached no code point, these named nowhere at all, so
    /// they could take no part in the join against the wire. Feeds
    /// `coverage.unresolved_event_targets`. While it is above zero, no
    /// unexplained traffic claim in the run is stated as certain, and reading a
    /// report without it would leave that downgrade unexplained.
    pub unresolved_event_targets: u64,
    /// Which sources fed this run, in the vocabulary the coverage statement uses.
    pub reconciliation_mode: ReconciliationMode,
    /// Feeds `coverage.observation_window_ms`. A duration, not a stamp.
    pub observation_window_ms: u64,
    /// Every link the join established, strongest rung first for a given pair.
    ///
    /// Carried because a derived finding is only as good as the link under it,
    /// and the explain surface has to be able to show that link rather than
    /// assert it.
    pub matches: Vec<J2Match>,
    /// The same, for the join between the wire and the observed calls.
    pub j1_matches: Vec<J1Match>,
    /// What the network sensor saw, in the counters the coverage statement
    /// carries.
    ///
    /// `None` when no sensor fed the run, and that is not the same as five
    /// zeros: a report that wrote zeros would say the sensor watched and found
    /// nothing. Three of the five count flows that produce no finding, and they
    /// are written whenever there was a sensor at all, because a bucket that
    /// keeps traffic out of the count and then vanishes from the report is a
    /// silent swallow (K-15).
    pub wire: Option<WireCoverage>,
    /// The thresholds and algorithm version this result was produced with.
    pub settings: ReconcileSettings,
    /// The engine disagreeing with itself. Belongs in the report diagnostics
    /// block, not in the coverage counters: a rule that failed is a different
    /// thing from something the run could not see.
    pub faults: Vec<String>,
    /// Where a rule ran, produced nothing, and the nothing means something.
    ///
    /// Neither findings nor faults. A rung that silenced an accusation and a
    /// comparison no measurement allowed are both cases where a reader who sees
    /// an empty finding list would otherwise conclude the run was clean.
    /// `reconciliation/spec.md` §6 states the rule these lines exist for: no
    /// class stays out of the report. They travel as report diagnostics, sorted
    /// and deduplicated like the faults beside them.
    pub silences: Vec<String>,
}
