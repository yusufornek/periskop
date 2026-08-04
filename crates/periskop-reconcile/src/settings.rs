//! The thresholds a run was decided with.
//!
//! Held as data and written into the result, because they change which findings
//! exist. A reader comparing two reports has to be able to see that the second
//! one produced fewer dormant findings because the threshold moved rather than
//! because the code did, and a threshold that is invisible until it fires cannot
//! be reviewed beforehand.

use serde::Serialize;

/// Version of the matching and derivation rules in this build.
///
/// Moves whenever a change would make the same inputs produce different
/// findings. Two reports from different versions are still comparable, but the
/// difference between them is not only the code.
pub const ALGORITHM_VERSION: &str = "1.0.0";

/// Shortest window a `dormant_egress_point` finding may be derived from.
///
/// Ten minutes, and the number is a declared default rather than a measurement.
/// The reasoning is the one `reconciliation/spec.md` open question 4 states: a
/// five minute session produces dormant findings that are close to meaningless,
/// because a code path that did not run in five minutes has told nobody anything
/// about whether it is dead. The threshold sits above that, and the alternative
/// of emitting the findings at zero severity was rejected: a finding in a report
/// is a claim, and "this code never runs" is not a claim a short window can
/// support at any severity.
pub const DEFAULT_MIN_DORMANT_WINDOW_MS: u64 = 600_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReconcileSettings {
    algorithm_version: &'static str,
    min_dormant_window_ms: u64,
}

impl Default for ReconcileSettings {
    fn default() -> Self {
        Self {
            algorithm_version: ALGORITHM_VERSION,
            min_dormant_window_ms: DEFAULT_MIN_DORMANT_WINDOW_MS,
        }
    }
}

impl ReconcileSettings {
    /// Replaces the shortest window a dormant finding may be derived from.
    ///
    /// Zero is refused. A zero threshold would let a run with no observation at
    /// all report every egress point in the code as never executed, which is the
    /// exact false claim the threshold exists to prevent, so the floor is one
    /// millisecond and the caller is told what it got.
    pub fn with_min_dormant_window_ms(mut self, minimum_ms: u64) -> Self {
        self.min_dormant_window_ms = minimum_ms.max(1);
        self
    }

    pub fn algorithm_version(&self) -> &'static str {
        self.algorithm_version
    }

    pub fn min_dormant_window_ms(&self) -> u64 {
        self.min_dormant_window_ms
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_default_threshold_is_above_the_window_the_spec_calls_meaningless() {
        let settings = ReconcileSettings::default();
        assert!(settings.min_dormant_window_ms() > 300_000);
        assert_eq!(settings.algorithm_version(), ALGORITHM_VERSION);
    }

    #[test]
    fn a_zero_threshold_is_refused_rather_than_honoured() {
        // Honouring it would make a run that watched nothing report every egress
        // point in the repository as dead code.
        assert_eq!(
            ReconcileSettings::default()
                .with_min_dormant_window_ms(0)
                .min_dormant_window_ms(),
            1
        );
    }

    #[test]
    fn the_settings_reach_the_output_they_decided() {
        let json =
            serde_json::to_value(ReconcileSettings::default().with_min_dormant_window_ms(60))
                .expect("settings serialize");
        assert_eq!(json["min_dormant_window_ms"], 60);
        assert_eq!(json["algorithm_version"], ALGORITHM_VERSION);
    }
}
