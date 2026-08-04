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
pub fn unparsed_ratio_basis_points(parsed_files: u64, unparsed_counting: u64) -> u64 {
    let total = parsed_files.saturating_add(unparsed_counting);
    if total == 0 {
        return 0;
    }
    // Ceiling division, integer arithmetic throughout. No step produces a float.
    unparsed_counting
        .saturating_mul(BASIS_POINTS)
        .div_ceil(total)
}

#[cfg(test)]
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
}
