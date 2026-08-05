//! `policy.toml`: what an operator writes down, and what happens when it cannot
//! be honoured.
//!
//! # Fail closed, and what that means here
//!
//! `proxy-policy.md` section 7 lists nine ways a policy fails to load, and eight
//! of them stop the process from accepting a request. The ninth, a key that is
//! provably ineffective, is ignored **and reported**. There is no tenth
//! behaviour and in particular there is no "log it and use the default": a rule
//! that is silently dropped is a value the operator believes is masked, already
//! on its way out.
//!
//! Section 7.1 added the class that is easiest to get wrong: a value that the
//! **contract** defines and that **this build** did not write. `date_policy =
//! "shift"` and `detection.ner.enabled = true` are the two of them today. Both
//! refuse to load, with a message distinguishable from a typo, because the
//! operator's next move differs: fix the spelling, or use a different build.
//!
//! # What lives where
//!
//! - [`load`]: parsing, the canonical JSON projection, `policy_hash`, and every
//!   row of the section 7 table.
//! - [`scope`]: field scoped rules, "narrowest scope wins", the JSON key rule,
//!   and which detection layers run inside a fenced code block.
//! - [`error`]: the failures, one variant per reason an operator would act on
//!   differently.

pub mod error;
pub mod load;
pub mod scope;

pub use error::{PolicyError, PolicyWarning, POLICY_UNLOADABLE};
pub use load::{CodeBlockPolicy, DatePolicy, HoldTimeout, Policy, ToolCallPolicy};
pub use scope::{decide, resolve, Decision, Mode, Rule, Scope, Step};
