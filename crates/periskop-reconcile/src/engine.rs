//! One pass: sources in, findings and a statement of the gaps out.
//!
//! The order of the four steps is the argument this component makes. Capability
//! is decided first, from the sources alone, so that no deriver is ever in a
//! position to produce a finding its inputs cannot support. Then the join runs
//! once, and both derivers read the same links, which is what keeps a point from
//! being called dormant by one rule while another reports where its calls went.
//!
//! Nothing here returns a `Result`. A missing source, a window too short to
//! conclude from and a kind this build cannot derive are answers, not failures,
//! and an error return would throw away what the run did establish in order to
//! report what it did not. The same reasoning the collector states for damaged
//! event files applies one layer up.

use crate::capability::{Capabilities, DerivedKind};
use crate::dormant;
use crate::drift;
use crate::join;
use crate::outcome::ReconcileOutcome;
use crate::settings::ReconcileSettings;
use crate::sources::Sources;
use crate::window::ObservationWindow;

/// Everything one pass needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileInputs {
    pub sources: Sources,
    /// How long the observation sources were watching. `NONE` for a run with no
    /// observation at all, which is not the same as a very short one.
    pub window: ObservationWindow,
    pub settings: ReconcileSettings,
}

impl ReconcileInputs {
    /// Inputs with the declared thresholds.
    pub fn new(sources: Sources, window: ObservationWindow) -> Self {
        Self {
            sources,
            window,
            settings: ReconcileSettings::default(),
        }
    }

    pub fn with_settings(mut self, settings: ReconcileSettings) -> Self {
        self.settings = settings;
        self
    }
}

/// Reconciles what the code declares against what was observed.
pub fn reconcile(inputs: &ReconcileInputs) -> ReconcileOutcome {
    let points = inputs.sources.declared_points();
    let events = inputs.sources.events();

    let capabilities = Capabilities::of(&inputs.sources, inputs.window, &inputs.settings);
    let links = join::join(points, events);

    let mut findings = Vec::new();
    let mut resolved_targets = Vec::new();
    let mut faults = Vec::new();

    if capabilities.allows(DerivedKind::DormantEgressPoint) {
        let derived = dormant::derive(
            points,
            &links,
            inputs.window,
            events.len(),
            &inputs.settings,
        );
        findings.extend(derived.findings);
        faults.extend(derived.faults);
    }

    if capabilities.allows(DerivedKind::TargetDrift) {
        let derived = drift::derive(points, &links, &inputs.settings);
        findings.extend(derived.findings);
        resolved_targets.extend(derived.resolved_targets);
        faults.extend(derived.faults);
    }

    // Ordering is applied here rather than at serialization, so a caller that
    // writes the result straight out cannot leak the order the derivers ran in.
    findings.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
    let before_collapse = findings.len();
    findings.dedup_by(|a, b| a.finding_id == b.finding_id);
    // Deduplication here should never have anything to do: one point cannot be
    // both never executed and reaching another destination, so the two derivers
    // cannot produce one identity between them. If they ever do, which record
    // survives depends on the order they ran in, and the loss is named rather
    // than left to be inferred from a count nobody keeps.
    if findings.len() < before_collapse {
        faults.push(format!(
            "{} derived findings collapsed onto an identity another finding already held",
            before_collapse - findings.len()
        ));
    }
    resolved_targets.sort();
    resolved_targets.dedup();
    faults.sort();
    faults.dedup();

    ReconcileOutcome {
        findings,
        suppressed: capabilities.suppressed().to_vec(),
        resolved_targets,
        unlinked_events: links.unlinked_events(),
        reconciliation_mode: inputs.sources.reconciliation_mode(),
        observation_window_ms: inputs.window.duration_ms(),
        matches: links.matches().to_vec(),
        settings: inputs.settings.clone(),
        faults,
    }
}
