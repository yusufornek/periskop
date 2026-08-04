//! Which derived findings this run is entitled to produce.
//!
//! The product's central claim is that three sources disagreeing is worth more
//! than any one of them alone. The claim only holds if a report never implies it
//! had a source it did not have. So the four derived kinds are not written as
//! four functions that happen to check their inputs; they are written as a table
//! of what each one needs, evaluated before anything is derived, and every kind
//! the run cannot produce is named in the result together with the reason.
//!
//! The suppression list is the load bearing part. Silence would be indexed the
//! same way by a reader whether a kind found nothing or was never attempted, and
//! `reconciliation/spec.md` §7 is explicit that a missing source is never
//! compensated for quietly.

use serde::Serialize;

use periskop_core::finding::Kind;

use crate::settings::ReconcileSettings;
use crate::sources::Sources;
use crate::window::ObservationWindow;

/// The four findings no single source can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedKind {
    UnmatchedWireTraffic,
    DormantEgressPoint,
    TargetDrift,
    VolumeAnomaly,
}

impl DerivedKind {
    pub const ALL: [Self; 4] = [
        Self::UnmatchedWireTraffic,
        Self::DormantEgressPoint,
        Self::TargetDrift,
        Self::VolumeAnomaly,
    ];

    /// The finding kind this maps to in the contract vocabulary.
    ///
    /// Taken from the shared enum rather than spelled again here, so a rename in
    /// the contract cannot leave this crate reporting a suppression for a kind
    /// name that no longer exists.
    pub fn kind(self) -> Kind {
        match self {
            Self::UnmatchedWireTraffic => Kind::UnmatchedWireTraffic,
            Self::DormantEgressPoint => Kind::DormantEgressPoint,
            Self::TargetDrift => Kind::TargetDrift,
            Self::VolumeAnomaly => Kind::VolumeAnomaly,
        }
    }
}

/// Why a derived kind was not produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionReason {
    /// No static scan fed the run, so there is no code side to compare against.
    DeclaredSourceAbsent,
    /// No hook was installed. Without it every egress point looks unexecuted,
    /// which is the compensation §7 forbids.
    RuntimeSourceAbsent,
    /// No network sensor ran. This is the one that keeps a two source run from
    /// making a three source claim.
    WireSourceAbsent,
    /// The window was too short for an absence to mean anything.
    ObservationWindowTooShort,
    /// No policy declared the band an observed volume is compared against.
    ///
    /// The one threshold this crate refuses to invent. Any constant would be
    /// wrong for most workloads while looking authoritative in every report, so
    /// a run without a declared band derives nothing and says why.
    VolumeBandNotDeclared,
}

/// One derived kind that will not appear in this report, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Suppression {
    pub kind: DerivedKind,
    pub reason: SuppressionReason,
}

/// Everything this run may and may not derive.
///
/// Deliberately has no `Default`. An empty suppression list means every derived
/// kind is allowed, which is the one value that must never be reachable by
/// accident: it is what a run with no sources at all would have to claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    suppressed: Vec<Suppression>,
}

impl Capabilities {
    /// Evaluates the table against what the run actually has.
    pub fn of(sources: &Sources, window: ObservationWindow, settings: &ReconcileSettings) -> Self {
        let mut suppressed = Vec::new();
        let mut suppress = |kind: DerivedKind, reason: SuppressionReason| {
            suppressed.push(Suppression { kind, reason });
        };

        // Every derived kind rests on the code side; without it there is nothing
        // to compare an observation with.
        if !sources.has_declared() {
            for kind in DerivedKind::ALL {
                suppress(kind, SuppressionReason::DeclaredSourceAbsent);
            }
        }

        if !sources.has_runtime() {
            for kind in [
                DerivedKind::DormantEgressPoint,
                DerivedKind::TargetDrift,
                DerivedKind::VolumeAnomaly,
            ] {
                suppress(kind, SuppressionReason::RuntimeSourceAbsent);
            }
        }

        if !sources.has_wire() {
            for kind in [
                DerivedKind::UnmatchedWireTraffic,
                DerivedKind::VolumeAnomaly,
            ] {
                suppress(kind, SuppressionReason::WireSourceAbsent);
            }
        }

        if !window.covers(settings.min_dormant_window_ms()) {
            suppress(
                DerivedKind::DormantEgressPoint,
                SuppressionReason::ObservationWindowTooShort,
            );
        }

        // The threshold this crate will not invent. Without a declared band
        // there is nothing to compare an observed volume against, and a run that
        // silently used a made up one would produce findings nobody could
        // review beforehand.
        if settings.volume_band().is_none() {
            suppress(
                DerivedKind::VolumeAnomaly,
                SuppressionReason::VolumeBandNotDeclared,
            );
        }

        suppressed.sort();
        suppressed.dedup();
        Self { suppressed }
    }

    /// Whether a kind may be derived at all.
    pub fn allows(&self, kind: DerivedKind) -> bool {
        !self.suppressed.iter().any(|s| s.kind == kind)
    }

    /// Sorted, one entry per reason a kind is missing.
    pub fn suppressed(&self) -> &[Suppression] {
        &self.suppressed
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::sources::{DeclaredSource, RuntimeSource, WireSource};

    fn sources(declared: bool, runtime: bool, wire: WireSource) -> Sources {
        Sources::new(
            if declared {
                DeclaredSource::Present(Vec::new())
            } else {
                DeclaredSource::Absent
            },
            if runtime {
                RuntimeSource::Present(Vec::new())
            } else {
                RuntimeSource::Absent
            },
            wire,
        )
    }

    fn reasons_for(capabilities: &Capabilities, kind: DerivedKind) -> Vec<SuppressionReason> {
        capabilities
            .suppressed()
            .iter()
            .filter(|s| s.kind == kind)
            .map(|s| s.reason)
            .collect()
    }

    #[test]
    fn wire_traffic_is_never_derivable_without_a_sensor() {
        // The claim this whole crate must not make: two sources cannot say
        // anything about traffic that has no code behind it.
        let capabilities = Capabilities::of(
            &sources(true, true, WireSource::Absent),
            ObservationWindow::of_ms(3_600_000),
            &ReconcileSettings::default(),
        );

        assert!(!capabilities.allows(DerivedKind::UnmatchedWireTraffic));
        assert!(
            reasons_for(&capabilities, DerivedKind::UnmatchedWireTraffic)
                .contains(&SuppressionReason::WireSourceAbsent)
        );
    }

    #[test]
    fn a_sensor_that_fed_the_run_unlocks_the_kind_that_needs_it() {
        // The other half of the same rule, and the milestone this phase closes.
        // The suppression above is not a permanent property of the build: it is
        // a statement about a run that had no wire source, and a run that has
        // one is entitled to the claim.
        let capabilities = Capabilities::of(
            &sources(true, true, WireSource::Present(Vec::new())),
            ObservationWindow::of_ms(3_600_000),
            &ReconcileSettings::default(),
        );

        assert!(capabilities.allows(DerivedKind::UnmatchedWireTraffic));
        assert!(reasons_for(&capabilities, DerivedKind::UnmatchedWireTraffic).is_empty());
    }

    #[test]
    fn a_volume_claim_needs_a_band_somebody_declared() {
        // The threshold comes from policy or the finding does not exist. There
        // is no default, because a default here would be a number this crate
        // made up and every report would carry it as though it meant something.
        let no_band = Capabilities::of(
            &sources(true, true, WireSource::Present(Vec::new())),
            ObservationWindow::of_ms(3_600_000),
            &ReconcileSettings::default(),
        );
        assert!(!no_band.allows(DerivedKind::VolumeAnomaly));
        assert_eq!(
            reasons_for(&no_band, DerivedKind::VolumeAnomaly),
            [SuppressionReason::VolumeBandNotDeclared]
        );

        let declared = Capabilities::of(
            &sources(true, true, WireSource::Present(Vec::new())),
            ObservationWindow::of_ms(3_600_000),
            &ReconcileSettings::default().with_volume_band(
                crate::settings::VolumeBand::declared(5_000, 30_000).expect("a band"),
            ),
        );
        assert!(declared.allows(DerivedKind::VolumeAnomaly));
    }

    #[test]
    fn a_short_window_suppresses_only_the_claim_that_depends_on_it() {
        let capabilities = Capabilities::of(
            &sources(true, true, WireSource::Absent),
            ObservationWindow::of_ms(60_000),
            &ReconcileSettings::default(),
        );

        assert!(!capabilities.allows(DerivedKind::DormantEgressPoint));
        assert_eq!(
            reasons_for(&capabilities, DerivedKind::DormantEgressPoint),
            [SuppressionReason::ObservationWindowTooShort]
        );
        // A drift is a statement about a call that did happen, so the length of
        // the window has nothing to say about it.
        assert!(capabilities.allows(DerivedKind::TargetDrift));
    }

    #[test]
    fn every_reason_a_kind_is_missing_is_listed_not_just_the_first() {
        let capabilities = Capabilities::of(
            &sources(false, false, WireSource::Absent),
            ObservationWindow::NONE,
            &ReconcileSettings::default(),
        );

        assert_eq!(
            reasons_for(&capabilities, DerivedKind::DormantEgressPoint),
            [
                SuppressionReason::DeclaredSourceAbsent,
                SuppressionReason::RuntimeSourceAbsent,
                SuppressionReason::ObservationWindowTooShort,
            ]
        );
    }

    #[test]
    fn a_run_with_every_source_and_every_threshold_may_derive_all_four() {
        let capabilities = Capabilities::of(
            &sources(true, true, WireSource::Present(Vec::new())),
            ObservationWindow::of_ms(3_600_000),
            &ReconcileSettings::default().with_volume_band(
                crate::settings::VolumeBand::declared(5_000, 30_000).expect("a band"),
            ),
        );

        for kind in DerivedKind::ALL {
            assert!(capabilities.allows(kind), "{kind:?} was suppressed");
        }
        assert!(capabilities.suppressed().is_empty());
    }

    #[test]
    fn the_derived_kind_names_are_the_contract_names() {
        // Two vocabularies for one set of names is how a suppression ends up
        // naming a finding kind that no longer exists.
        for kind in DerivedKind::ALL {
            let serialized = serde_json::to_string(&kind).expect("kind serializes");
            assert_eq!(serialized, format!("\"{}\"", kind.kind().as_str()));
        }
    }
}
