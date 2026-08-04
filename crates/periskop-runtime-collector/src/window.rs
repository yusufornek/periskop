//! How long the hooks were watching, as their own accounting states it.
//!
//! A duration, never two stamps. `schemas/egress-event.schema.json` carries no
//! clock value on purpose, because `egress_event_id` is derived from the call
//! shape and a stamp in the body would give one call two identities; the window
//! is not a property of a call anyway, it is a property of the collection. So it
//! travels in the status sidecar each hook already writes, and this module is
//! what turns a directory of those sidecars into one statement about the run.
//!
//! Two facts are kept apart here and everything downstream depends on it. Zero
//! is a measurement: the process was watched for no time at all, which is what a
//! process that ran with the hook switched off honestly observed. Absent is not
//! a measurement: something was watching and cannot say for how long, which is
//! what a crashed hook leaves behind. A reader that collapses the two turns an
//! unknown into a number, and `dormant_egress_point` is derived from exactly
//! that number.

/// The window one process reported, or a whole run's after folding.
///
/// No `Default` deriving a measured value: the only default that can be safe is
/// the one that claims nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObservedWindow {
    /// Nothing that was read stated a duration this run may rely on.
    #[default]
    Unmeasured,
    /// Watched for at least this many milliseconds.
    ///
    /// A lower bound rather than a total, because a hook rewrites its sidecar as
    /// it flushes: a process still running, or one that died between two
    /// flushes, leaves the window it had reached and not the one it finished
    /// with. Understating the window can only suppress a claim, never inflate
    /// one, which is the direction this product errs in.
    Measured(u64),
}

impl ObservedWindow {
    /// The duration, when one was measured.
    pub const fn duration_ms(self) -> Option<u64> {
        match self {
            Self::Unmeasured => None,
            Self::Measured(duration_ms) => Some(duration_ms),
        }
    }
}

/// Folds the per process windows of one directory into the run's window.
///
/// The rule is the shortest window, and it is normative: see
/// `docs/04-contracts/hook-status-schema.md`. A dormancy claim is universally
/// quantified over processes, so its strength is bounded by the least watched
/// one. Taking the longest would let an hour long web server vouch for a fifty
/// millisecond batch job that may well be where the untouched code lives, and a
/// union cannot be computed at all without the wall clock stamps this product
/// refuses to record.
///
/// One unmeasured process makes the whole fold unmeasured. The smallest of a set
/// containing an unknown is unknown; writing the shortest of the rest instead
/// would be answering a question the run cannot answer.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct WindowFold {
    /// `None` until a process has been folded in.
    ///
    /// Kept apart from `Some(Unmeasured)` because they are different runs: no
    /// process reported anything at all, versus a process that reported and
    /// could not say. Both resolve to the same answer, and merging them here
    /// would make the first process folded in win over every later one.
    state: Option<ObservedWindow>,
}

impl WindowFold {
    pub(crate) fn add(&mut self, window: ObservedWindow) {
        self.state = Some(match self.state {
            None => window,
            Some(current) => shortest(current, window),
        });
    }

    pub(crate) fn resolve(self) -> ObservedWindow {
        self.state.unwrap_or(ObservedWindow::Unmeasured)
    }
}

fn shortest(one: ObservedWindow, other: ObservedWindow) -> ObservedWindow {
    match (one, other) {
        (ObservedWindow::Measured(one), ObservedWindow::Measured(other)) => {
            ObservedWindow::Measured(one.min(other))
        }
        _ => ObservedWindow::Unmeasured,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fold(windows: &[ObservedWindow]) -> ObservedWindow {
        let mut fold = WindowFold::default();
        for window in windows {
            fold.add(*window);
        }
        fold.resolve()
    }

    #[test]
    fn a_run_that_read_no_process_measured_nothing() {
        assert_eq!(fold(&[]), ObservedWindow::Unmeasured);
        assert_eq!(ObservedWindow::Unmeasured.duration_ms(), None);
    }

    #[test]
    fn the_least_watched_process_decides_the_run() {
        // The long lived process may not speak for the short lived one: the code
        // that never ran may be exactly the code only the short one could reach.
        assert_eq!(
            fold(&[
                ObservedWindow::Measured(3_600_000),
                ObservedWindow::Measured(50),
                ObservedWindow::Measured(600_000),
            ]),
            ObservedWindow::Measured(50)
        );
    }

    #[test]
    fn one_process_that_could_not_say_makes_the_run_unable_to_say() {
        // The smallest of a set holding an unknown is unknown. Reporting the
        // shortest of the rest would answer a question the run cannot answer.
        assert_eq!(
            fold(&[
                ObservedWindow::Measured(600_000),
                ObservedWindow::Unmeasured,
                ObservedWindow::Measured(900_000),
            ]),
            ObservedWindow::Unmeasured
        );
    }

    #[test]
    fn a_measured_zero_is_a_measurement_and_survives_as_one() {
        // A process that ran with the hook switched off watched for no time at
        // all. That is a fact about the run, and it has to reach the fold as a
        // number rather than as an absence, or a directory of hooked and
        // unhooked processes would look uniformly instrumented.
        assert_eq!(
            fold(&[
                ObservedWindow::Measured(600_000),
                ObservedWindow::Measured(0)
            ]),
            ObservedWindow::Measured(0)
        );
        assert_eq!(ObservedWindow::Measured(0).duration_ms(), Some(0));
    }

    #[test]
    fn folding_does_not_depend_on_the_order_the_processes_were_read_in() {
        // Two runs over one directory have to produce the same report, and the
        // filesystem does not promise an order.
        let windows = [
            ObservedWindow::Measured(900_000),
            ObservedWindow::Measured(120),
            ObservedWindow::Measured(600_000),
        ];
        let mut reversed = windows;
        reversed.reverse();
        assert_eq!(fold(&windows), fold(&reversed));
    }
}
