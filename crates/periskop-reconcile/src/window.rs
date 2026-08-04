//! How long anything was watched for.
//!
//! A duration, never two timestamps. The window is what every claim about
//! something *not* happening rests on, so it has to reach the evidence of those
//! findings; a wall clock value that reached the evidence would make the same
//! observations reconcile differently tomorrow, which is the one property the
//! report may not have.

use serde::Serialize;

/// The stretch of time the runtime and network sources were watching for.
///
/// No `Default`, on purpose. A window that defaults to zero would let a caller
/// omit the one value every claim about something not happening rests on, and
/// the omission would read in the report as a run that observed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ObservationWindow {
    duration_ms: u64,
}

impl ObservationWindow {
    /// A run where nothing was watched.
    ///
    /// Zero is a real value here rather than a missing one: it is what a static
    /// only scan honestly observed, and it is also what makes every claim about
    /// something not happening unsupportable.
    pub const NONE: Self = Self { duration_ms: 0 };

    pub const fn of_ms(duration_ms: u64) -> Self {
        Self { duration_ms }
    }

    pub const fn duration_ms(self) -> u64 {
        self.duration_ms
    }

    /// Whether the window is long enough for a declared threshold.
    pub const fn covers(self, minimum_ms: u64) -> bool {
        self.duration_ms >= minimum_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_with_no_observation_covers_no_threshold() {
        assert_eq!(ObservationWindow::NONE.duration_ms(), 0);
        assert!(!ObservationWindow::NONE.covers(1));
        // A zero threshold is met by a zero window, which is why no threshold in
        // this crate is allowed to be zero.
        assert!(ObservationWindow::NONE.covers(0));
    }

    #[test]
    fn a_window_exactly_at_the_threshold_covers_it() {
        assert!(ObservationWindow::of_ms(600_000).covers(600_000));
        assert!(!ObservationWindow::of_ms(599_999).covers(600_000));
    }
}
