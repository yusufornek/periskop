//! Shared domain types for periskop.
//!
//! This crate holds what every other crate needs to agree on: identity formats,
//! the error type, and the vocabulary the JSON contracts use. It depends on no
//! other crate in the workspace. The dependency arrow always points inward, so
//! nothing here may reach out to the scanner, the CLI or the report builder.

pub mod coverage;
pub mod error;
pub mod finding;
pub mod ids;

pub use error::{Error, Result};
pub use finding::{Confidence, Finding, Kind, Source};
