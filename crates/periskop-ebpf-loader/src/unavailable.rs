//! Why the loader did not start, in the words a report already uses.
//!
//! These four causes are the same four `periskop-network-sensor` declares, spelled
//! with the same labels, and that duplication is deliberate. The sensor cannot
//! be a dependency of this crate without putting the two in a cycle, so the
//! vocabulary is restated here and the agreement between the two lists is held
//! by an assertion on the sensor's side rather than by a shared type. A reader
//! counting occurrences of `missing_capability` across a fleet has to get the
//! same string whichever crate produced it.
//!
//! What must never happen is a fifth cause appearing here. The set is closed
//! because it is a reporting vocabulary: a new value would reach a coverage
//! statement that has no schema entry for it, and the remedy column an operator
//! reads would be blank.

/// Why this build is not observing.
///
/// Every variant is a distinct condition with a distinct remedy. Merging any two
/// would send an operator to fix the wrong thing, which costs more than saying
/// nothing would have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, thiserror::Error)]
pub enum LoaderUnavailable {
    /// Not Linux. There is no remedy in v1: ADR-008's pcap path for macOS and
    /// Windows is a v2 line, and this build would be claiming an observation no
    /// code in the workspace performs.
    #[error("this build observes nothing on this platform")]
    UnsupportedPlatform,
    /// Neither `CAP_BPF` with `CAP_PERFMON` nor root. Remedy: grant the two
    /// capabilities, which is less authority than root and enough.
    #[error("neither the capabilities nor root")]
    MissingCapability,
    /// The kernel cannot host the programs, for instance with no BTF exposed.
    /// Remedy: a newer kernel. Granting capabilities would not help, so this
    /// must not arrive wearing the permission label.
    #[error("the kernel cannot host the programs")]
    KernelUnsupported,
    /// Everything was in place and this build carries no program object to
    /// load. Remedy: build the loader (ADR-014 §4).
    #[error("the privileges were there and this build carries no program object")]
    LoaderNotBuilt,
}

impl LoaderUnavailable {
    /// The fixed label a coverage statement carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::MissingCapability => "missing_capability",
            Self::KernelUnsupported => "kernel_unsupported",
            Self::LoaderNotBuilt => "loader_not_built",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every cause this crate can report, in one place, so a test that has to
    /// cover the whole vocabulary cannot quietly cover part of it.
    const EVERY_CAUSE: [LoaderUnavailable; 4] = [
        LoaderUnavailable::UnsupportedPlatform,
        LoaderUnavailable::MissingCapability,
        LoaderUnavailable::KernelUnsupported,
        LoaderUnavailable::LoaderNotBuilt,
    ];

    #[test]
    fn every_cause_has_a_distinct_label_a_reader_can_count() {
        // Two causes sharing a label would make a fleet wide count of
        // "missing_capability" silently include machines whose kernel was the
        // problem, and the capability grant those machines got would not help.
        let labels: std::collections::BTreeSet<&str> =
            EVERY_CAUSE.iter().map(|cause| cause.as_str()).collect();
        assert_eq!(labels.len(), EVERY_CAUSE.len());
    }

    #[test]
    fn the_labels_are_the_snake_case_the_coverage_statement_expects() {
        // Pinned rather than derived, because a rename in this crate would
        // otherwise silently change what every report in the field says.
        assert_eq!(
            EVERY_CAUSE.map(LoaderUnavailable::as_str),
            [
                "unsupported_platform",
                "missing_capability",
                "kernel_unsupported",
                "loader_not_built",
            ]
        );
    }

    #[test]
    fn a_cause_explains_itself_when_printed() {
        // A loader failure can reach a log line before it reaches a report, and
        // an enum name alone tells an operator nothing about the remedy.
        for cause in EVERY_CAUSE {
            assert!(!cause.to_string().is_empty());
        }
    }
}
