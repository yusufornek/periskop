//! Deterministic report construction.
//!
//! The same tree and the same rule set must serialize to the same bytes. Ordering
//! is applied when the report is built rather than when it is written, so a
//! parallel scan order can never leak into the output.

pub mod coverage;
pub mod report;
pub mod serialize;

pub use coverage::CoverageStatement;
pub use report::{Envelope, PolicyRef, ReportBuilder, RuleHit, ScanReport, Verdict, VerdictOrder};
pub use serialize::{body_hash, to_canonical_json};
