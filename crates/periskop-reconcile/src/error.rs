//! What this crate refuses, and why.
//!
//! Every variant names one invariant the contracts state. There is no catch-all:
//! a reconciliation that cannot say why it rejected an input hands the caller a
//! failure nobody can act on, which is the shape of problem this product exists
//! to argue against.
//!
//! Note what is *not* an error here. A source that did not run, an observation
//! window too short to conclude anything from, and a finding kind this build
//! cannot derive are all ordinary outcomes and travel in the result
//! ([`crate::outcome::ReconcileOutcome`]) rather than as failures. Reconciliation
//! answers with what it could establish and a statement of what it could not.

pub type Result<T> = std::result::Result<T, ReconcileError>;

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    /// A finding of some other kind was offered as a declared egress point.
    ///
    /// Silently accepting it would put an observation on the code side of the
    /// join, where it would then fail to match itself and be reported as code
    /// that never ran.
    #[error("a finding of kind {kind} is not a declared egress point")]
    NotDeclared { kind: &'static str },

    /// The join is keyed on egress point identity, so a declared finding without
    /// one cannot take part in it at all.
    #[error("a declared finding carries no egress point reference")]
    NoEgressPointRef,

    #[error("an egress point identity is not the ep_ form the contract fixes")]
    MalformedEgressPointId {
        #[source]
        source: periskop_core::Error,
    },

    /// A path that only resolves on the machine that produced it makes the
    /// report differ between two machines that saw the same thing.
    #[error("a declared location path is absolute")]
    AbsoluteLocationPath,

    #[error("a declared target names no host")]
    UnreadableTarget,
}
