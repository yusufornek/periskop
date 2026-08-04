//! Alias generation: what the model sees in place of a real person's data.
//!
//! # The one rule this module exists to keep
//!
//! ADR-010 section 5 calls it P-0 and puts it above every other design goal in
//! this component:
//!
//! > No alias generator may produce a value that could be **allocated** to a real
//! > person, company or account. The burden of proof is on the generator.
//!
//! The reason is not squeamishness. Masking that turns one person's data into
//! something a downstream system will accept as another person's data has not
//! prevented a leak, it has moved the harm to somebody who was never asked. A
//! valid looking IBAN that fails to be restored is shown to the user, and a model
//! that writes it into a payment instruction sends money to a stranger's account.
//!
//! So the aliases here are deliberately **not** believable as records. They are
//! believable as *shapes*: the country code of an IBAN survives, a card is still
//! sixteen digits, a host is still a host. What does not survive is validity.
//!
//! # The ladder (ADR-010 section 5.1)
//!
//! Every type walks the same three steps and stops at the first one it can prove,
//! and the step it may enter at is fixed at compile time:
//!
//! | Rung | Meaning | The invariant CI enforces |
//! |---|---|---|
//! | `R` | A published reserved or fiction range, cited in [`catalog`] | the alias lies inside that range |
//! | `I` | The shape is kept and the type's own validator is deliberately failed | the validator rejects the alias |
//! | `O` | Type preservation is switched off: `PSK_<TAG>_<16 hex>` | the alias starts with `PSK_` |
//!
//! A fourth class sits beside them rather than inside them: `L`, a counted label
//! (`PERSON_1`). No value is drawn from the type's value space at all, so there is
//! nothing to allocate.
//!
//! [`LadderRung::Opaque`] is not a failure. It is P-0 being applied: what cannot
//! be proved is not produced.
//!
//! # What each module owns
//!
//! - [`limits`]: the `L_type_max` table and `L_MAX_STATIC`, the only place a
//!   length ceiling is written down.
//! - [`catalog`]: the rule file. Every documented range carries the publication it
//!   comes from, and a range with no citation cannot be constructed.
//! - [`checksum`]: the total validation functions rung `I` has to fail.
//! - [`rung_l`], [`rung_r`], [`rung_i`], [`card`], [`phone`], [`opaque`]: the
//!   generators, one module per rung, plus the two types whose generator walks
//!   more than one rung.
//! - [`derive`]: `alias_seed = HMAC(K_session, type || 0x00 || normalize(value))`,
//!   the type specific `normalize`, and the deterministic byte stream a generator
//!   draws from.
//! - [`mint`]: the session's own memory: which alias belongs to which seed, which
//!   alias strings are already spoken for, and the counters an event reports.
//!
//! # What is not here
//!
//! Detection (which bytes are an IBAN), the request path and restoration. This
//! module turns a value that has already been found into a string, and remembers
//! nothing about where it was found.

pub mod card;
pub mod catalog;
pub mod checksum;
pub mod derive;
pub mod entity;
pub mod error;
pub mod limits;
pub mod mint;
pub mod opaque;
pub mod phone;
pub mod rung_i;
pub mod rung_l;
pub mod rung_r;

pub use derive::AliasKey;
pub use entity::{AliasStyle, EntityType, LadderRung, Minting};
pub use error::AliasError;
pub use limits::{l_max_static, l_type_max, L_MAX_STATIC};
pub use mint::{AliasStats, Minted, Minter, TypeStat, UrlHostAlias};
