//! Which of the three detection sources fed this run.
//!
//! The distinction every type here exists to preserve: a source that ran and saw
//! nothing is not a source that did not run. An empty event list means the hooks
//! were installed and the program made no calls. An absent runtime source means
//! nobody was watching. Inferring the second from the first is how a tool ends up
//! reporting an entire codebase as dead, and it is why presence is stated by the
//! caller rather than guessed from a length.
//!
//! The same distinction decides `reconciliation_mode`, the coverage field that
//! tells a reader how much of the product's central claim this particular report
//! is entitled to make. Two sources cannot produce a three source conclusion, and
//! the mode is what stops a report from implying otherwise.

use periskop_network_sensor::Flow;
use periskop_report::coverage::ReconciliationMode;
use periskop_runtime_collector::event::EgressEvent;

use crate::declared::DeclaredPoint;

/// Whether the static scanner fed this run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclaredSource {
    /// No scan was performed, or its result was not handed over.
    Absent,
    /// A scan ran. An empty list means it found no egress points.
    Present(Vec<DeclaredPoint>),
}

/// Whether the runtime hooks fed this run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeSource {
    /// No hook was installed, or the event directory could not be read.
    Absent,
    /// Hooks reported. An empty list means they observed no calls, which is an
    /// observation and not a gap.
    Present(Vec<EgressEvent>),
}

/// Whether a network sensor fed this run.
///
/// The third source, and the one the product's central claim rests on: a
/// connection that left the machine can be seen here and nowhere else.
///
/// Presence is stated by the caller for the same reason it is on the other two.
/// An empty flow list means the sensor watched and the machine stayed quiet,
/// which is an observation; an absent sensor means nobody was watching the wire,
/// and it is what stops `reconciliation_mode` from ever reading `full`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireSource {
    /// No sensor ran, or its records were not handed over.
    Absent,
    /// A sensor reported. An empty list means it observed no connections.
    Present(Vec<Flow>),
}

/// What this run had to work with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sources {
    declared: DeclaredSource,
    runtime: RuntimeSource,
    wire: WireSource,
}

impl Sources {
    pub fn new(declared: DeclaredSource, runtime: RuntimeSource, wire: WireSource) -> Self {
        Self {
            declared,
            runtime,
            wire,
        }
    }

    /// The coverage value naming which sources fed reconciliation.
    ///
    /// The enum is closed at four values and every one of them assumes a static
    /// source, so a run without one has no spelling of its own. It is reported as
    /// the observation sources it did have, and the absent code side is stated
    /// where it can be acted on instead: every derived kind that needs the
    /// declared source is listed as suppressed with that reason. A reader is
    /// therefore never left inferring the code side from a mode value that cannot
    /// express it. The gap is filed against the contract owner rather than
    /// papered over with a fifth value invented here.
    pub fn reconciliation_mode(&self) -> ReconciliationMode {
        match (self.has_runtime(), self.has_wire()) {
            (true, true) => ReconciliationMode::Full,
            (true, false) => ReconciliationMode::StaticPlusRuntime,
            (false, true) => ReconciliationMode::StaticPlusWire,
            (false, false) => ReconciliationMode::StaticOnly,
        }
    }

    pub fn declared_points(&self) -> &[DeclaredPoint] {
        match &self.declared {
            DeclaredSource::Absent => &[],
            DeclaredSource::Present(points) => points,
        }
    }

    pub fn events(&self) -> &[EgressEvent] {
        match &self.runtime {
            RuntimeSource::Absent => &[],
            RuntimeSource::Present(events) => events,
        }
    }

    pub fn flows(&self) -> &[Flow] {
        match &self.wire {
            WireSource::Absent => &[],
            WireSource::Present(flows) => flows,
        }
    }

    pub fn has_declared(&self) -> bool {
        matches!(self.declared, DeclaredSource::Present(_))
    }

    pub fn has_runtime(&self) -> bool {
        matches!(self.runtime, RuntimeSource::Present(_))
    }

    pub fn has_wire(&self) -> bool {
        matches!(self.wire, WireSource::Present(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn the_mode_names_the_observation_sources_that_fed_the_run() {
        assert_eq!(
            sources(true, false, WireSource::Absent).reconciliation_mode(),
            ReconciliationMode::StaticOnly
        );
        assert_eq!(
            sources(true, true, WireSource::Absent).reconciliation_mode(),
            ReconciliationMode::StaticPlusRuntime
        );
        assert_eq!(
            sources(true, false, WireSource::Present(Vec::new())).reconciliation_mode(),
            ReconciliationMode::StaticPlusWire
        );
        assert_eq!(
            sources(true, true, WireSource::Present(Vec::new())).reconciliation_mode(),
            ReconciliationMode::Full
        );
    }

    #[test]
    fn a_sensor_that_saw_nothing_is_not_an_absent_sensor_either() {
        // The same distinction as the runtime source, on the source the
        // product's central claim rests on. `full` says the wire was watched,
        // and only a caller can say whether it was.
        let watched = sources(true, true, WireSource::Present(Vec::new()));
        let unwatched = sources(true, true, WireSource::Absent);

        assert!(watched.flows().is_empty());
        assert!(unwatched.flows().is_empty());
        assert!(watched.has_wire());
        assert!(!unwatched.has_wire());
        assert_eq!(watched.reconciliation_mode(), ReconciliationMode::Full);
        assert_eq!(
            unwatched.reconciliation_mode(),
            ReconciliationMode::StaticPlusRuntime
        );
    }

    #[test]
    fn a_source_that_saw_nothing_is_not_an_absent_source() {
        // The whole reason presence is an input. Both runs below observed no
        // calls; only one of them was watching.
        let watched = sources(true, true, WireSource::Absent);
        let unwatched = sources(true, false, WireSource::Absent);

        assert!(watched.events().is_empty());
        assert!(unwatched.events().is_empty());
        assert!(watched.has_runtime());
        assert!(!unwatched.has_runtime());
        assert_ne!(
            watched.reconciliation_mode(),
            unwatched.reconciliation_mode()
        );
    }

    #[test]
    fn an_absent_code_side_still_reports_the_observation_sources_it_had() {
        // The enum cannot spell "no static source". What it must not do is claim
        // a source that was not there, so the runtime source it did have is what
        // the mode names.
        assert_eq!(
            sources(false, true, WireSource::Absent).reconciliation_mode(),
            ReconciliationMode::StaticPlusRuntime
        );
        assert!(!sources(false, true, WireSource::Absent).has_declared());
    }
}
