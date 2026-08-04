//! Deterministic report construction.
//!
//! The same tree and the same rule set must serialize to the same bytes. Ordering
//! is applied when the report is built rather than when it is written, so a
//! parallel scan order can never leak into the output.

#![doc(html_no_source)]
