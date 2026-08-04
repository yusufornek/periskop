//! Collects the egress events the runtime hooks recorded.
//!
//! The hooks themselves are language native and live outside this workspace: a
//! Python import hook, a Node preload module, a JVM agent. What they share is a
//! single output contract, `schemas/egress-event.schema.json`, and a transport
//! chosen for what it does when things go wrong. Each process appends JSON Lines
//! to its own file and never coordinates with another process, because the
//! alternative would put periskop in a position to stall the application it is
//! observing.
//!
//! This crate is the reading half of that contract. It turns a directory of
//! half written, possibly damaged files into a deduplicated, ordered set of
//! events, and an honest statement of what could not be read. It knows nothing
//! about findings or reconciliation; the dependency arrow points inward, to
//! `periskop-core` and no further.

pub mod collector;
pub mod event;
pub mod status;
pub mod window;

pub use collector::{collect, CollectionResult};
pub use event::{EgressEvent, EventError};
pub use window::ObservedWindow;
