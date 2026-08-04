//! The network sensor: what left the machine.
//!
//! Of periskop's three detection sources this is the one that cannot be
//! stepped around. Reading code can miss an opaque wrapper, a runtime hook can
//! miss an uninstrumented process, but data leaving the machine has to pass
//! through a socket. That is the claim, and it is a narrow one: the sensor
//! answers *how much*, *where to*, *when* and *whose*. It does not answer
//! *what*, and no field in this crate ever will (ADR-008, `Flow`).
//!
//! Three properties are structural here rather than documented, because each
//! one is a place where a report could quietly become dishonest:
//!
//! - **Every flow carries a bucket.** [`flow::Flow`] cannot be built without
//!   one, and three of the four buckets produce no findings while still being
//!   counted. A bucket that keeps flows out of the count and then vanishes from
//!   the report is a silent swallow.
//! - **No sensor and a silent sensor say different things.**
//!   [`sensor::SensorOutcome::coverage_platform_class`] is `none` whenever
//!   nothing was observed, and the reason is always stated.
//! - **A denied sensor cannot fail a scan.** [`sensor::observe`] returns an
//!   outcome, never an error.
//!
//! The kernel side is behind [`source::FlowSource`]. This build ships the seam
//! and a loader that reports it is not built yet.

pub mod flow;
pub mod identity;
pub mod observation;
pub mod platform;
pub mod privilege;
pub mod scope;
pub mod sensor;
pub mod source;

pub use flow::{Flow, FlowError, Mechanism};
pub use observation::Observation;
pub use platform::SensorPlatformClass;
pub use privilege::{Privileges, SensorUnavailable};
pub use scope::{FlowScope, ScopePolicy, ScopeTally};
pub use sensor::{observe, SensorOutcome, SensorState};
pub use source::FlowSource;
