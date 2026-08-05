//! The coverage statement: what the scan could not see.
//!
//! A finding is an assertion backed by evidence. A blind spot is not an assertion,
//! so it is never reported as one. It is counted here instead, and the report
//! schema makes the block mandatory, which means a run cannot quietly omit it.
//!
//! Engine, rule and schema errors do not belong in this structure. They travel in
//! the report diagnostics block, because mixing them into coverage counters would
//! make any policy threshold over those counters meaningless.

use serde::{Deserialize, Serialize};

/// Why a file did not make it into the parsed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnparsedReason {
    /// Not a code surface at all. The only reason excluded from the unparsed ratio.
    SkippedBinary,
    SkippedTooLarge,
    UnknownLanguage,
    /// Language recognised, no grammar bound. This is where a phase boundary
    /// becomes visible to the user instead of disappearing.
    NoGrammar,
    ParseError,
    PartialParse,
    ParseTimeout,
    IoError,
}

impl UnparsedReason {
    /// Whether this reason counts toward the unparsed ratio.
    ///
    /// Binary files are excluded on purpose. Counting them would turn the ratio
    /// into a function of how many images a repository happens to contain: adding
    /// a hundred screenshots would cross a policy threshold without a single line
    /// of code becoming less visible.
    pub fn counts_toward_ratio(self) -> bool {
        !matches!(self, Self::SkippedBinary)
    }
}

/// Why a target a finding points at could not be pinned down.
///
/// Lives here rather than next to the report types because the scanner produces
/// these and the report only carries them. A vocabulary owned by the consumer
/// would force the producer to describe its own blind spots in someone else's
/// words, which is how the field ended up unwritten in the first place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnresolvedReason {
    DynamicExpression,
    EnvVar,
    ConfigIndirection,
    UnsupportedPattern,
}

/// An egress point whose destination the scan could not determine.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnresolvedTarget {
    pub egress_point_id: String,
    pub reason: UnresolvedReason,
}

/// The languages the coverage vocabulary knows about.
///
/// Closed on purpose, and closed here rather than only in the schema. The status
/// of a language is the one place a reader learns that a hook does not exist for
/// it, so a spelling the validator rejects would take that statement out of the
/// report entirely and leave silence in its place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageLanguage {
    Python,
    Typescript,
    Javascript,
    Java,
    Csharp,
    Go,
    Rust,
    Kotlin,
    Ruby,
    Php,
}

impl CoverageLanguage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Typescript => "typescript",
            Self::Javascript => "javascript",
            Self::Java => "java",
            Self::Csharp => "csharp",
            Self::Go => "go",
            Self::Rust => "rust",
            Self::Kotlin => "kotlin",
            Self::Ruby => "ruby",
            Self::Php => "php",
        }
    }
}

/// Where the detectors that decided a run came from.
///
/// Two values and no third, because a run reads exactly one of two rule sets: the
/// one compiled into the binary, or a directory the caller named. Implicit
/// discovery was removed, so there is no "wherever it was found" to name.
///
/// Lives in the coverage vocabulary rather than beside the scanner's own source
/// type for the reason [`UnresolvedReason`] gives: the scanner produces the value
/// and the report only carries it. It belongs to coverage because it answers the
/// question the rest of the block answers. Every other field says what the run
/// could not see; this one says which detectors decided what counted as seen.
/// `rule_set_hash` already pins the content of the rule set and says nothing
/// about its origin, and to somebody reading an archived report, scanned with the
/// detectors we ship is not the same claim as scanned with a local directory that
/// may never have been under version control.
///
/// **No path is ever carried here.** An absolute path differs between machines
/// and would put the build machine into a document that has to compare equal
/// across them. Same rule that keeps paths out of `finding_id` and derives
/// `scan_root_id` from a directory name rather than from where it sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleSetSource {
    /// The set compiled in at build time.
    Embedded,
    /// A directory the caller named, which replaces the embedded set entirely.
    Directory,
}

impl RuleSetSource {
    /// The spelling the contract fixes, for surfaces that print rather than
    /// serialize. Same reason [`CoverageLanguage::as_str`] exists: one word per
    /// fact, so a terminal and the JSON beside it cannot disagree.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Embedded => "embedded",
            Self::Directory => "directory",
        }
    }
}

/// Denominator in basis points, so the ratio stays integer arithmetic end to end.
const BASIS_POINTS: u64 = 10_000;

/// Share of the code surface that could not be read, in basis points.
///
/// Integer only, and rounded up. Rounding down would let a small but real gap
/// display as zero, which is exactly the kind of quiet omission the coverage block
/// exists to prevent. Rounding up can at worst trip a threshold early.
///
/// A run with nothing to scan yields zero rather than an error: the ratio is
/// undefined there and must not trip anything. That situation is already visible
/// as `parsed_files = 0`.
///
/// The multiplication widens to `u128` before it is divided. Saturating in `u64`
/// would have pulled the ratio *down*: a numerator large enough to clamp at
/// `u64::MAX` divided by an equally large total came out near zero, so the one
/// case where nothing at all was read would have printed as full coverage. The
/// invariant that has to hold is that the ratio is never understated.
pub fn unparsed_ratio_basis_points(parsed_files: u64, unparsed_counting: u64) -> u64 {
    let total = u128::from(parsed_files) + u128::from(unparsed_counting);
    if total == 0 {
        return 0;
    }
    // Ceiling division, integer arithmetic throughout. No step produces a float.
    let ratio = (u128::from(unparsed_counting) * u128::from(BASIS_POINTS)).div_ceil(total);
    // The quotient cannot exceed the denominator scale, but the clamp states the
    // range the contract fixes instead of leaving it to be re-derived.
    ratio.min(u128::from(BASIS_POINTS)) as u64
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn binary_files_stay_out_of_the_ratio() {
        assert!(!UnparsedReason::SkippedBinary.counts_toward_ratio());
        for reason in [
            UnparsedReason::SkippedTooLarge,
            UnparsedReason::UnknownLanguage,
            UnparsedReason::NoGrammar,
            UnparsedReason::ParseError,
            UnparsedReason::PartialParse,
            UnparsedReason::ParseTimeout,
            UnparsedReason::IoError,
        ] {
            assert!(reason.counts_toward_ratio(), "{reason:?} must count");
        }
    }

    #[test]
    fn a_rule_set_source_is_written_in_the_words_the_contract_uses() {
        // The enum is closed at two values by contract, and the spelling is what
        // an archived report is read by. A printed word that differs from the
        // serialized one would give a reader two vocabularies for one fact.
        for source in [RuleSetSource::Embedded, RuleSetSource::Directory] {
            assert_eq!(
                serde_json::to_string(&source).expect("the source serializes"),
                format!("\"{}\"", source.as_str()),
                "{source:?}"
            );
        }
    }

    #[test]
    fn empty_scan_does_not_trip_a_threshold() {
        assert_eq!(unparsed_ratio_basis_points(0, 0), 0);
    }

    #[test]
    fn full_coverage_is_zero() {
        assert_eq!(unparsed_ratio_basis_points(100, 0), 0);
    }

    #[test]
    fn nothing_readable_is_the_whole_range() {
        assert_eq!(unparsed_ratio_basis_points(0, 7), BASIS_POINTS);
    }

    #[test]
    fn a_single_missed_file_never_reads_as_zero() {
        // One file out of a very large tree is far below one basis point. Rounding
        // down would print 0 and hide a real gap; rounding up keeps it visible.
        let ratio = unparsed_ratio_basis_points(999_999, 1);
        assert_eq!(ratio, 1);
    }

    #[test]
    fn ratio_matches_the_documented_example() {
        // 2 unreadable out of 10 considered is 20 percent, which is 2000 basis points.
        assert_eq!(unparsed_ratio_basis_points(8, 2), 2000);
    }

    #[test]
    fn ratio_never_exceeds_the_full_range() {
        for parsed in [0u64, 1, 97, 1_000_000] {
            for unparsed in [0u64, 1, 5, 1_000_000] {
                assert!(unparsed_ratio_basis_points(parsed, unparsed) <= BASIS_POINTS);
            }
        }
    }

    #[test]
    fn a_count_too_large_for_the_multiplication_still_reads_as_a_full_gap() {
        // The bug this pins: the numerator used to saturate in u64, so a file
        // count past 1.8e15 clamped and then divided down to a handful of basis
        // points. A run that read nothing at all reported as almost fully
        // covered, which is the one direction this number may never move in.
        let counted = u64::MAX / 4;
        assert_eq!(unparsed_ratio_basis_points(0, counted), BASIS_POINTS);
        assert_eq!(unparsed_ratio_basis_points(counted, counted), 5_000);
    }

    #[test]
    fn coverage_language_spelling_matches_the_contract() {
        // The schema fixes a closed list of ten. A value outside it serializes
        // fine in Rust and is rejected by the validator, which would take the
        // runtime status of that language out of the report altogether.
        let spellings: Vec<&str> = [
            CoverageLanguage::Python,
            CoverageLanguage::Typescript,
            CoverageLanguage::Javascript,
            CoverageLanguage::Java,
            CoverageLanguage::Csharp,
            CoverageLanguage::Go,
            CoverageLanguage::Rust,
            CoverageLanguage::Kotlin,
            CoverageLanguage::Ruby,
            CoverageLanguage::Php,
        ]
        .into_iter()
        .map(CoverageLanguage::as_str)
        .collect();
        assert_eq!(
            spellings,
            [
                "python",
                "typescript",
                "javascript",
                "java",
                "csharp",
                "go",
                "rust",
                "kotlin",
                "ruby",
                "php"
            ]
        );
        for language in [CoverageLanguage::Python, CoverageLanguage::Csharp] {
            let json = serde_json::to_string(&language).expect("enum serializes");
            assert_eq!(json, format!("\"{}\"", language.as_str()));
        }
    }

    #[test]
    fn unresolved_reasons_use_the_contract_spellings() {
        let json = serde_json::to_string(&UnresolvedTarget {
            egress_point_id: "ep_0000000000000001".to_owned(),
            reason: UnresolvedReason::EnvVar,
        })
        .expect("target serializes");
        assert!(json.contains("\"env_var\""), "{json}");
    }
}
