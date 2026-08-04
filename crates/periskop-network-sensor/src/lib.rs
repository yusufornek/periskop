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
//! The kernel side is behind [`kernel::KernelEvents`], and the line is drawn as
//! far towards the kernel as it will go. Which programs to attach, how a
//! packet event joins onto a process event, what a DNS answer means, what a
//! ClientHello means, which name wins when the two disagree and what the record
//! then says are all on this side of it and all tested here. Opening the kernel
//! objects is the only thing on the far side, because it is the only thing that
//! cannot run in continuous integration (ADR-014).

pub mod assemble;
pub mod flow;
pub mod identity;
pub mod kernel;
pub mod observation;
pub mod parse;
pub mod platform;
pub mod privilege;
pub mod resolve;
pub mod scope;
pub mod sensor;
pub mod source;

pub use assemble::FlowAssembler;
pub use flow::{Flow, FlowError, Mechanism};
pub use kernel::{FlowKey, KernelEvent, KernelEvents};
pub use observation::Observation;
pub use platform::SensorPlatformClass;
pub use privilege::{Privileges, SensorUnavailable};
pub use resolve::DnsObservation;
pub use scope::{FlowScope, ScopePolicy, ScopeTally};
pub use sensor::{observe, SensorOutcome, SensorState};
pub use source::{EbpfFlowSource, FlowSource, SourceCoverage};
