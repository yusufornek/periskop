//! The boundary between this crate and a kernel.
//!
//! Everything below this module is ordinary Rust over ordinary data: keys,
//! events, a plan. Everything a kernel is actually needed for is behind
//! [`KernelEvents`], which has exactly two methods. That line is drawn here
//! rather than left implicit for a reason that is about honesty rather than
//! tidiness: the eBPF programs cannot run in continuous integration, so any
//! logic on the kernel side of the line is logic that ships untested. The line
//! is placed so that almost nothing is on that side.
//!
//! What is on the far side: opening kernel objects and reading the ring buffer.
//! What is on this side: which programs to attach, how events join into flows,
//! what a DNS answer means, what a handshake means, which name wins, what the
//! record says. All of it runs on the machine you are reading this on.

pub mod attach;
pub mod event;
pub mod key;
pub mod loader;

pub use attach::{plan, AttachPlan, Program};
pub use event::{
    CloseEvent, ConnectEvent, KernelBatch, KernelEvent, KernelProcess, PayloadEvent, PayloadFacts,
    PollState, VolumeEvent,
};
pub use key::FlowKey;
pub use loader::PlatformKernel;

use crate::privilege::SensorUnavailable;

/// A source of kernel events.
///
/// Deliberately not a stream of flows. An implementation reports what a hook
/// saw; deciding what that means about a connection is the assembler's job, and
/// keeping the two apart is what stops a loader from being the place where a
/// record's meaning is decided.
pub trait KernelEvents {
    /// Loads and attaches the planned programs, or says why it cannot.
    ///
    /// The plan is passed in rather than built here, so an implementation
    /// cannot decide for itself to attach a program the grant did not allow.
    fn attach(&mut self, plan: &AttachPlan) -> Result<(), SensorUnavailable>;

    /// Reads whatever the ring buffer holds, along with what it lost.
    ///
    /// The batch states whether anything was attached when the read happened.
    /// An implementation that has loaded nothing answers
    /// [`PollState::NotAttached`], and it must: an empty batch from an
    /// unattached kernel and an empty batch from a quiet machine are the two
    /// facts this whole product exists to keep apart, and only the second is a
    /// measurement.
    fn poll(&mut self) -> KernelBatch;
}
