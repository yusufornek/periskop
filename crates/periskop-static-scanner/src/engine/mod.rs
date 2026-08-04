//! The detection engine.
//!
//! Rules describe what to look for; this is what does the looking. The split
//! keeps library knowledge out of the code and inside data files, so support for
//! a new provider is a rule plus fixtures rather than a patch here.

pub mod bindings;
pub mod detect;

pub use bindings::BindingTable;
pub use detect::{detect, FileFindings};
