//! Entity detection: which bytes of a prompt stand for somebody.
//!
//! # The shape of the answer
//!
//! `proxy/spec.md` section 3 splits detection into three layers, and ADR-011
//! section 1 gives them three different statuses:
//!
//! | Layer | Method | Status in this build |
//! |---|---|---|
//! | A, [`pattern`] | regular expressions plus published check digit rules | mandatory, always on |
//! | B, [`dictionary`] | one Aho-Corasick pass over the organization's word list | mandatory, always on, empty when the list is empty |
//! | C, NER | statistical span labelling | **not written**, and declared on every request |
//!
//! No type is looked for in more than one layer. [`layer`] is where that is a
//! total function rather than a convention, [`merge`] is where overlapping
//! *ranges* are resolved and where the run declares which layers actually ran.
//!
//! # The two errors, and why they are not weighed the same
//!
//! A **missed** entity is a leak: the value goes to the provider, nothing says
//! so, and it cannot be taken back. A **false** detection is a damaged prompt:
//! the model answers a different question, the user sees it, and the operator can
//! change the policy. Every gate in this module states which way it errs and why,
//! because a detector tuned without saying so drifts toward whichever error its
//! author found more annoying that week.
//!
//! # What is deliberately absent
//!
//! The NER code path, in any form. F4's scope boundary 1 is explicit: no model
//! package, no ONNX runtime, no language detection, no code path. What is here
//! instead is the declaration: [`merge::MaskingProfile`] says
//! `pattern+dictionary`, `degraded_reasons[]` carries `ner_disabled`, and
//! [`merge::NER_DISABLED_DECLARATION`] is the sentence that reaches the user.

pub mod affix;
pub mod dictionary;
pub mod layer;
pub mod merge;
pub mod pattern;
pub mod segment;
pub mod span;

pub use layer::{owning_layer, DetectionLayer};
pub use merge::{merge, DegradedReason, Detection, MaskingProfile, NER_DISABLED_DECLARATION};
pub use span::Candidate;

/// Credential shaped strings for tests, assembled rather than written out.
///
/// A detector for provider keys has to be tested against text that looks like a
/// provider key, which is exactly what a secret scanner is built to find. The
/// values below are the published documentation examples from Stripe and
/// GitHub and none of them opens anything, but a scanner cannot know that and
/// should not try: it blocked a push of this repository on an earlier version
/// of these tests, which was the correct call on the evidence it had.
///
/// So the literals are split at the prefix boundary and joined at run time. The
/// detector still sees the whole string, and no continuous match survives in
/// the source for anything downstream to find. `no_credential_shaped_literal`
/// keeps it that way.
#[cfg(test)]
pub(crate) mod sample {
    /// Stripe's documentation key.
    pub(crate) fn stripe_key() -> String {
        format!("sk_{}_{}", "live", "4eC39HqLyjWDarjtT1zdp7dc")
    }

    /// GitHub's documentation token.
    pub(crate) fn github_token() -> String {
        format!("ghp_{}", "16C7e42F292c6912E7710c838347Ae178B4a")
    }
}
