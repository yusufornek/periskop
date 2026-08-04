//! What alias generation refuses to do, and why each refusal is a refusal.
//!
//! Every variant here stops a request. None of them carries the value that
//! caused it: the whole point of this component is that personal data does not
//! reach a log line, and an error message is a log line waiting to happen
//! (`proxy/spec.md` section 9). What they carry is the entity type and a count,
//! which is enough to find the generator at fault and nothing more.

use thiserror::Error;

use super::entity::EntityType;

/// A refusal from the alias layer.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AliasError {
    /// This type mints no alias in this phase.
    ///
    /// `DATE` is the only one. Date shifting is off by default and unimplemented
    /// in F4 (ADR-010 section 7), so a caller asking for a date alias has
    /// misread the policy: the answer to a date is `allow` or `block`, not a
    /// substitute value.
    #[error("{entity} mints no alias in this build; date policy decides allow or block")]
    NotMinted { entity: EntityType },

    /// A URL was handed to the general entry point.
    ///
    /// A URL is never aliased whole (ADR-010 section 2): only its host component
    /// is, and the caller has to know which bytes to replace. `mint_url_host` is
    /// the way in.
    #[error("URL is aliased through its host component only; use mint_url_host")]
    UrlMintsViaHost,

    /// A URL with nothing that could be a host in it.
    #[error("no host component was found in the URL")]
    HostNotFound,

    /// A value with nothing in it after normalisation.
    ///
    /// Refused rather than aliased, because an alias for the empty string would
    /// be restored into every empty string in the response.
    #[error("{entity} value is empty after normalisation")]
    EmptyValue { entity: EntityType },

    /// The counter walk could not find a free alias string.
    ///
    /// Reached only when a small output space is nearly full, which is what the
    /// per session alias ceiling exists to keep from happening. Refusing is the
    /// only safe answer: reusing an alias would make one alias mean two people.
    #[error("{entity} alias still collided after {attempts} attempts")]
    CollisionUnresolved { entity: EntityType, attempts: u32 },

    /// A generator produced a string longer than its type's ceiling.
    ///
    /// This is a bug in a generator rather than a bad input, and it is caught at
    /// run time as well as in tests because the streaming state machine's hold
    /// depends on the ceiling being true. An alias longer than `L_type_max` is an
    /// alias that can be flushed in two halves.
    #[error("{entity} alias is {bytes} bytes, over its {ceiling} byte ceiling")]
    LengthCeilingExceeded {
        entity: EntityType,
        bytes: usize,
        ceiling: usize,
    },

    /// The session key was refused by HMAC.
    ///
    /// Unreachable in practice: HMAC accepts a key of any length and this one is
    /// a fixed 32 bytes. It exists so that the impossible path is a refusal
    /// rather than a panic, which is the same choice the vault made.
    #[error("the session key could not be used for alias derivation")]
    KeyUnusable,
}
