//! The thresholds a run was decided with.
//!
//! Held as data and written into the result, because they change which findings
//! exist. A reader comparing two reports has to be able to see that the second
//! one produced fewer dormant findings because the threshold moved rather than
//! because the code did, and a threshold that is invisible until it fires cannot
//! be reviewed beforehand.
//!
//! One of them is deliberately absent by default. The volume band decides what
//! counts as an unexpected amount of data, and there is no honest number for it
//! that this crate could pick: a batch job and a chat endpoint disagree by three
//! orders of magnitude. So it is `None` until a policy states it, and the kind
//! that needs it is reported as suppressed rather than derived against an
//! invented default.

use serde::Serialize;

use crate::error::{ReconcileError, Result};

/// Version of the matching and derivation rules in this build.
///
/// Moves whenever a change would make the same inputs produce different
/// findings. Two reports from different versions are still comparable, but the
/// difference between them is not only the code.
///
/// 1.1.0 is the version at which the wire source became an input the run reads
/// rather than only counts: the same declared points and the same events now
/// produce the same findings, and a run that also carries flows produces two
/// kinds it could not produce before.
pub const ALGORITHM_VERSION: &str = "1.1.0";

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

/// The J1 time tolerance, delta in `data-model.md` §3.
///
/// 250 ms, which is the allowance the contract states for clock skew between
/// two sources and for the delay between a call being made and a connection
/// being recorded.
pub const DEFAULT_JOIN_TOLERANCE_MS: u64 = 250;

/// Width of the bucket a flow's start time is rounded to.
///
/// One second, fixed by `flow-schema.md`: the raw stamp is deliberately not
/// carried, because it would put wall clock into an identity that has to
/// compare equal across runs. The consequence for J1 is worth stating rather
/// than discovering, and it is why [`ReconcileSettings::effective_join_tolerance_ms`]
/// exists: comparing two bucketed starts at a 250 ms tolerance would be
/// comparing at a precision neither record has, and the answer would depend on
/// which side of a bucket boundary a connection happened to fall on.
pub const FLOW_START_BUCKET_WIDTH_MS: u64 = 1_000;

/// The range a matched flow's outbound volume is expected to fall in.
///
/// Expressed in basis points of what the observed calls declared they were
/// sending, so the whole comparison is integer arithmetic. A ratio held as a
/// float would make the same two reports differ between platforms, which
/// `reconciliation/spec.md` §8 rule 6 rules out.
///
/// The band is two sided on purpose. Too many bytes on the wire for the payload
/// the application declared is the case everybody thinks of; too few is the
/// more interesting one, because it says the application believes it sent
/// something the wire never carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct VolumeBand {
    min_basis_points: u64,
    max_basis_points: u64,
}

impl VolumeBand {
    /// States the band a policy declared.
    ///
    /// Fallible rather than clamping. A band whose upper edge sits below its
    /// lower one admits nothing at all, so every matched flow would be an
    /// anomaly; silently reordering the two would produce a working band nobody
    /// wrote and hide the typo that produced it.
    pub fn declared(min_basis_points: u64, max_basis_points: u64) -> Result<Self> {
        if max_basis_points < min_basis_points {
            return Err(ReconcileError::InvertedVolumeBand);
        }
        Ok(Self {
            min_basis_points,
            max_basis_points,
        })
    }

    pub fn min_basis_points(self) -> u64 {
        self.min_basis_points
    }

    pub fn max_basis_points(self) -> u64 {
        self.max_basis_points
    }

    /// The lowest volume this band admits for a declared payload total.
    ///
    /// Rounded down, and the upper edge is rounded up, so rounding can only ever
    /// widen the band. A finding raised because an integer division lost a byte
    /// would be an artefact of the arithmetic rather than a fact about the run.
    pub fn low(self, expected_bytes: u64) -> u64 {
        scale_down(expected_bytes, self.min_basis_points)
    }

    /// The highest volume this band admits for a declared payload total.
    pub fn high(self, expected_bytes: u64) -> u64 {
        scale_up(expected_bytes, self.max_basis_points)
    }

    /// Whether an observed volume sits inside the band.
    pub fn admits(self, observed_bytes: u64, expected_bytes: u64) -> bool {
        observed_bytes >= self.low(expected_bytes) && observed_bytes <= self.high(expected_bytes)
    }
}

/// `value * basis_points / 10_000`, rounded down, in a width that cannot wrap.
fn scale_down(value: u64, basis_points: u64) -> u64 {
    let scaled = u128::from(value) * u128::from(basis_points) / 10_000;
    u64::try_from(scaled).unwrap_or(u64::MAX)
}

/// The same product rounded up.
fn scale_up(value: u64, basis_points: u64) -> u64 {
    let product = u128::from(value) * u128::from(basis_points);
    let scaled = product.div_ceil(10_000);
    u64::try_from(scaled).unwrap_or(u64::MAX)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReconcileSettings {
    algorithm_version: &'static str,
    min_dormant_window_ms: u64,
    join_tolerance_ms: u64,
    /// Absent until a policy states one, and the kind that needs it is then
    /// suppressed with that reason. There is no default that would be true of
    /// any workload.
    #[serde(skip_serializing_if = "Option::is_none")]
    volume_band: Option<VolumeBand>,
}

impl Default for ReconcileSettings {
    fn default() -> Self {
        Self {
            algorithm_version: ALGORITHM_VERSION,
            min_dormant_window_ms: DEFAULT_MIN_DORMANT_WINDOW_MS,
            join_tolerance_ms: DEFAULT_JOIN_TOLERANCE_MS,
            volume_band: None,
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

    /// Replaces the J1 time tolerance.
    ///
    /// Zero is accepted here, unlike the dormancy threshold, because it is a
    /// meaningful instruction: compare the two sides at whatever precision the
    /// records carry and allow nothing on top. What it cannot do is make the
    /// comparison finer than the records are, which is
    /// [`Self::effective_join_tolerance_ms`].
    pub fn with_join_tolerance_ms(mut self, tolerance_ms: u64) -> Self {
        self.join_tolerance_ms = tolerance_ms;
        self
    }

    /// States the band a matched flow's volume is expected to fall in.
    pub fn with_volume_band(mut self, band: VolumeBand) -> Self {
        self.volume_band = Some(band);
        self
    }

    pub fn algorithm_version(&self) -> &'static str {
        self.algorithm_version
    }

    pub fn min_dormant_window_ms(&self) -> u64 {
        self.min_dormant_window_ms
    }

    /// The tolerance as declared.
    pub fn join_tolerance_ms(&self) -> u64 {
        self.join_tolerance_ms
    }

    /// The tolerance the comparison actually runs at.
    ///
    /// Never finer than the bucket a flow's start time is rounded to. Two
    /// connections a fifth of a second apart are written with the same bucket,
    /// so a 250 ms tolerance applied to them would separate or unite them
    /// according to where the bucket boundary fell rather than according to what
    /// happened. Widening to the bucket width is the honest reading of records
    /// that were rounded before this crate ever saw them, and the value that
    /// decided a run travels in the evidence of the findings it produced.
    pub fn effective_join_tolerance_ms(&self) -> u64 {
        self.join_tolerance_ms.max(FLOW_START_BUCKET_WIDTH_MS)
    }

    pub fn volume_band(&self) -> Option<VolumeBand> {
        self.volume_band
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
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
        let json = serde_json::to_value(
            ReconcileSettings::default()
                .with_min_dormant_window_ms(60)
                .with_join_tolerance_ms(500)
                .with_volume_band(VolumeBand::declared(5_000, 30_000).unwrap()),
        )
        .expect("settings serialize");
        assert_eq!(json["min_dormant_window_ms"], 60);
        assert_eq!(json["join_tolerance_ms"], 500);
        assert_eq!(json["volume_band"]["max_basis_points"], 30_000);
        assert_eq!(json["algorithm_version"], ALGORITHM_VERSION);
    }

    #[test]
    fn a_run_with_no_declared_band_writes_no_band_at_all() {
        // Not a zero band and not a default one. The field's absence is what a
        // reader has to see, because it is the reason a kind is missing.
        let json = serde_json::to_value(ReconcileSettings::default()).expect("settings serialize");
        assert!(json.get("volume_band").is_none(), "{json}");
        assert_eq!(ReconcileSettings::default().volume_band(), None);
    }

    #[test]
    fn the_comparison_never_runs_finer_than_the_records_were_written() {
        // The declared tolerance is below the bucket a flow start is rounded to,
        // so honouring it literally would decide a match on where a bucket
        // boundary fell.
        let settings = ReconcileSettings::default();
        assert_eq!(settings.join_tolerance_ms(), DEFAULT_JOIN_TOLERANCE_MS);
        assert_eq!(
            settings.effective_join_tolerance_ms(),
            FLOW_START_BUCKET_WIDTH_MS
        );
        // A tolerance above the bucket width is honoured as stated.
        assert_eq!(
            settings
                .with_join_tolerance_ms(30_000)
                .effective_join_tolerance_ms(),
            30_000
        );
    }

    #[test]
    fn an_inverted_band_is_refused_rather_than_reordered() {
        // It admits nothing, so every matched flow would be an anomaly, and
        // swapping the edges would hide the typo behind a band nobody wrote.
        assert!(matches!(
            VolumeBand::declared(30_000, 5_000),
            Err(ReconcileError::InvertedVolumeBand)
        ));
        assert!(VolumeBand::declared(10_000, 10_000).is_ok());
    }

    #[test]
    fn rounding_widens_the_band_and_never_narrows_it() {
        // Half a basis point either way must not be the reason a report gains a
        // finding.
        let band = VolumeBand::declared(9_999, 10_001).unwrap();
        assert_eq!(band.low(3), 2);
        assert_eq!(band.high(3), 4);
        assert!(band.admits(3, 3));
    }

    #[test]
    fn a_volume_far_outside_the_band_is_not_admitted() {
        let band = VolumeBand::declared(5_000, 30_000).unwrap();
        assert!(band.admits(1_500, 1_000), "three times is inside 300%");
        assert!(!band.admits(3_001, 1_000), "just over three times is not");
        assert!(!band.admits(499, 1_000), "under half is not either");
    }

    #[test]
    fn a_band_over_an_enormous_payload_does_not_wrap() {
        // The arithmetic is done in a wider type, so a payload near the top of
        // the range saturates rather than folding round to a small number and
        // admitting everything.
        let band = VolumeBand::declared(10_000, 20_000).unwrap();
        assert_eq!(band.high(u64::MAX), u64::MAX);
        assert!(band.admits(u64::MAX, u64::MAX));
    }
}
