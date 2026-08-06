//! The `Flow` record: one connection the sensor watched leave the machine.
//!
//! Mirrors `schemas/flow.schema.json`. The schema is the contract; the types
//! below are the in memory shape that serializes to it.
//!
//! **Why this is three files and not one.** The split is by the question each
//! file answers, not by size:
//!
//! - [`vocabulary`] answers *which words a record may use*. Closed value sets,
//!   meaningful without a record around them, and what most of the rest of the
//!   crate is actually written against.
//! - [`record`] answers *what a record is and how one is built*. The fields, the
//!   one door an observation comes through, and the setters.
//! - [`validate`] answers *which records the contract rejects, and why*. It runs
//!   on construction and again on read back, and its rejection vocabulary is a
//!   contract surface of its own.
//!
//! The three used to be one file, and the cost was not the length: the value
//! sets could not be read without scrolling past the invariants, and a change to
//! one subject arrived in a diff touching all three. Nothing moved across the
//! module boundary in the split, so every path a consumer already imports still
//! resolves through the re-exports below.

mod record;
mod validate;
mod vocabulary;

#[cfg(test)]
pub(crate) mod fixtures;

pub use record::{FiveTuple, Flow, ProcessRecord, SCHEMA_VERSION};
pub use validate::FlowError;
pub use vocabulary::{
    Classification, DegradedReason, Mechanism, ProcessAttribution, Proto, ProviderConfidence,
    ResolvedHostSource, SniSource, UNKNOWN_PROVIDER,
};
