//! Reconciliation: what the code says, against what actually ran.
//!
//! This is the component the product's argument rests on. The static scanner
//! says what the code can reach, the runtime hooks say what it did reach, and a
//! network sensor says what left the machine. Each of the three is useful; the
//! value is in the places where they do not agree, and finding those places is
//! all this crate does. It classifies nothing, applies no policy and blocks
//! nothing.
//!
//! Two rules shape every type here, and both exist because the failure they
//! prevent is the kind nobody notices.
//!
//! The first: a claim may never be stronger than the evidence under it. The join
//! is a ladder of progressively weaker keys, each rung is recorded on the finding
//! it produced, and a rung that only agrees on the provider can never yield a
//! confirmed anything. The second: a source that did not run is never
//! compensated for. Every derived kind declares what it needs, the run states
//! which kinds it could not produce and why, and the one kind that needs a
//! network sensor cannot be produced by a build that has none. Two sources
//! making a three source claim would discredit the product's central argument
//! more thoroughly than missing the finding would.
//!
//! What this build derives is `dormant_egress_point` and `target_drift`. The two
//! that need the wire, `unmatched_wire_traffic` and `volume_anomaly`, are listed
//! as suppressed with a reason rather than left as silence.

pub mod capability;
pub mod declared;
mod dormant;
mod drift;
mod emit;
pub mod engine;
pub mod error;
pub mod join;
pub mod outcome;
pub mod settings;
pub mod sources;
pub mod target;
pub mod window;

pub use declared::DeclaredPoint;
pub use engine::{reconcile, ReconcileInputs};
pub use error::{ReconcileError, Result};
pub use outcome::ReconcileOutcome;
pub use sources::{DeclaredSource, RuntimeSource, Sources, WireSource};
pub use window::ObservationWindow;
