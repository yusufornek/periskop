//! The coverage statement as it appears in a report.
//!
//! Every field is required, including the ones that are usually zero. The schema
//! enforces that, and this type mirrors it, because the gap between an absent
//! field and a zero is the easiest place for an honest looking report to stop
//! being honest.

use serde::{Deserialize, Serialize};

use periskop_core::coverage::UnparsedReason;

/// Re-exported from the core vocabulary. The scanner produces these and the
/// report only carries them, so the types live where the producer can reach them.
pub use periskop_core::coverage::{
    CoverageLanguage, RuleSetSource, UnresolvedReason, UnresolvedTarget,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnparsedFile {
    pub path: String,
    pub reason: UnparsedReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStatus {
    Instrumented,
    /// A mechanism exists but was not opted into.
    NotInstrumented,
    Degraded,
    /// No mechanism is defined for this language at all.
    Unsupported,
}

/// Hook status for one language.
///
/// The language is an enum rather than a string because the schema closes the
/// list at ten. A free string compiled and serialized happily and only failed in
/// an external validator, which in this build runs over sample files rather than
/// over real output, so a misspelling would have shipped.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RuntimeCoverage {
    pub language: CoverageLanguage,
    pub status: RuntimeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_mechanism: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorPlatformClass {
    LinuxEbpf,
    MacosPcap,
    WindowsPcapEtw,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsObservation {
    Available,
    UnavailableEncryptedDns,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationMode {
    Full,
    StaticOnly,
    StaticPlusRuntime,
    StaticPlusWire,
}

impl ReconciliationMode {
    /// The spelling the contract uses, for a surface that prints rather than
    /// serializes. Without it a renderer reaches for `{:?}` and the terminal
    /// starts naming the same value differently from the JSON beside it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::StaticOnly => "static_only",
            Self::StaticPlusRuntime => "static_plus_runtime",
            Self::StaticPlusWire => "static_plus_wire",
        }
    }
}

/// What the scan could not see, in numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageStatement {
    pub parsed_files: u64,
    pub unparsed_files: Vec<UnparsedFile>,
    pub unresolved_targets: Vec<UnresolvedTarget>,
    pub undetected_libraries: Vec<String>,
    pub runtime_coverage: Vec<RuntimeCoverage>,
    pub unrecognized_clients: u64,
    pub unhooked_processes: u64,
    pub dropped_events: u64,
    pub unlinked_events: u64,
    /// Observed calls whose destination the hook could not read.
    ///
    /// Different from `unlinked_events`, which counts calls that reached no code
    /// point: these named no destination at all, so nothing could be compared
    /// against the traffic that left the machine. The number is what keeps a
    /// downgraded traffic claim readable, since a call that went nowhere nameable
    /// is a standing candidate explanation for any connection in the run.
    pub unresolved_event_targets: u64,
    pub unattributed_flows: u64,
    pub unclassified_flows: u64,
    /// Flows attributed to the codebase under scan, and the only bucket derived
    /// findings come from (K-15).
    ///
    /// The denominator the other three buckets are read against. Without it a
    /// reader sees "412 out of scope" and cannot tell 412 of 450 from 412 of
    /// 40000, which are opposite conclusions about the same machine, and the
    /// attribution accuracy gate K-15 states cannot be checked from the report
    /// at all.
    pub in_scope_flows: u64,
    pub out_of_scope_flows: u64,
    pub known_benign_flows: u64,
    pub sensor_platform_class: SensorPlatformClass,
    pub dns_observation: DnsObservation,
    pub observation_window_ms: u64,
    pub reconciliation_mode: ReconciliationMode,
    /// Which detector set decided this run: the one shipped in the binary, or a
    /// directory the caller named.
    ///
    /// The one field here that is not a count of something unseen, and it belongs
    /// beside them because it says what "seen" was measured against. A reader told
    /// a tree is clean has to be able to ask "clean according to what", and
    /// `rule_set_hash` answers with the content of the rules rather than with
    /// where they came from. A narrow rule set produces a cleaner report, and
    /// making that kind of false cleanliness visible is the whole product.
    ///
    /// The run announces this on stderr as well, but stderr is not archived and
    /// the report is.
    pub rule_set_source: RuleSetSource,
}

impl CoverageStatement {
    /// A statement for a run with no runtime or network observation.
    ///
    /// The zeros are not placeholders. A static only scan genuinely observed no
    /// flows and hooked no processes, and saying so is different from leaving the
    /// fields out and letting a reader assume.
    ///
    /// What this is not is a report ready statement. `runtime_coverage` starts
    /// empty and the caller fills it from the languages the scan actually saw; an
    /// empty list would say nothing at all about any language, which is the
    /// silence the field exists to break.
    ///
    /// The rule set source is an argument rather than a default for the reason
    /// the whole field exists. Defaulting it to `Embedded` would make a caller who
    /// forgot it claim the shipped detectors produced the run, which is the exact
    /// false statement the field was added to prevent, and the caller would never
    /// see a compiler error telling them so.
    pub fn static_only(rule_set_source: RuleSetSource) -> Self {
        Self {
            parsed_files: 0,
            unparsed_files: Vec::new(),
            unresolved_targets: Vec::new(),
            undetected_libraries: Vec::new(),
            runtime_coverage: Vec::new(),
            unrecognized_clients: 0,
            unhooked_processes: 0,
            dropped_events: 0,
            unlinked_events: 0,
            unresolved_event_targets: 0,
            unattributed_flows: 0,
            unclassified_flows: 0,
            in_scope_flows: 0,
            out_of_scope_flows: 0,
            known_benign_flows: 0,
            sensor_platform_class: SensorPlatformClass::None,
            dns_observation: DnsObservation::Available,
            observation_window_ms: 0,
            reconciliation_mode: ReconciliationMode::StaticOnly,
            rule_set_source,
        }
    }

    /// Applies the ordering the contract fixes.
    ///
    /// Sorting happens when the statement is built rather than when it is written,
    /// so a caller that forgets to sort cannot leak filesystem or thread order
    /// into a report that is supposed to be reproducible.
    pub fn normalize(&mut self) {
        self.unparsed_files.sort();
        self.unparsed_files.dedup();
        self.unresolved_targets.sort();
        self.unresolved_targets.dedup();
        self.undetected_libraries.sort();
        self.undetected_libraries.dedup();
        self.runtime_coverage.sort();
        self.runtime_coverage.dedup();
    }

    /// Share of the code surface that could not be read, in basis points.
    pub fn unparsed_ratio_basis_points(&self) -> u64 {
        let counting = self
            .unparsed_files
            .iter()
            .filter(|f| f.reason.counts_toward_ratio())
            .count() as u64;
        periskop_core::coverage::unparsed_ratio_basis_points(self.parsed_files, counting)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_reconciliation_mode_is_printed_in_the_words_the_contract_uses() {
        // Same reason as the diagnostic vocabulary in `report.rs`: a summary
        // that prints `StaticPlusRuntime` and a JSON that says
        // `static_plus_runtime` describe one run in two languages.
        for mode in [
            ReconciliationMode::Full,
            ReconciliationMode::StaticOnly,
            ReconciliationMode::StaticPlusRuntime,
            ReconciliationMode::StaticPlusWire,
        ] {
            assert_eq!(
                serde_json::to_string(&mode).expect("mode serializes"),
                format!("\"{}\"", mode.as_str()),
                "{mode:?}"
            );
        }
    }

    #[test]
    fn static_only_run_declares_no_observation() {
        let c = CoverageStatement::static_only(RuleSetSource::Embedded);
        assert_eq!(c.sensor_platform_class, SensorPlatformClass::None);
        assert_eq!(c.observation_window_ms, 0);
        assert_eq!(c.reconciliation_mode, ReconciliationMode::StaticOnly);
    }

    #[test]
    fn normalize_sorts_and_deduplicates() {
        let mut c = CoverageStatement::static_only(RuleSetSource::Embedded);
        c.undetected_libraries = vec!["zeta".into(), "alpha".into(), "zeta".into()];
        c.normalize();
        assert_eq!(c.undetected_libraries, ["alpha", "zeta"]);
    }

    #[test]
    fn binary_files_do_not_move_the_ratio() {
        let mut c = CoverageStatement::static_only(RuleSetSource::Embedded);
        c.parsed_files = 10;
        c.unparsed_files = vec![UnparsedFile {
            path: "logo.png".into(),
            reason: UnparsedReason::SkippedBinary,
        }];
        assert_eq!(c.unparsed_ratio_basis_points(), 0);
    }

    #[test]
    fn an_unreadable_source_file_does_move_it() {
        let mut c = CoverageStatement::static_only(RuleSetSource::Embedded);
        c.parsed_files = 9;
        c.unparsed_files = vec![UnparsedFile {
            path: "broken.py".into(),
            reason: UnparsedReason::ParseError,
        }];
        assert_eq!(c.unparsed_ratio_basis_points(), 1000);
    }
}
