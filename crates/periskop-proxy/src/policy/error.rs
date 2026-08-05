//! Why a policy did not load, in the shapes `proxy-policy.md` section 7 names.
//!
//! # Every variant here stops startup, except one
//!
//! Section 7's closing sentence is the whole design: "Sessizce yok sayılan tek
//! durum, **etkisiz** olduğu ispatlanabilen anahtardır; geri kalan her hata
//! açılışı durdurur." A rule that is dropped quietly is a value the operator
//! believes is masked and that is on its way to a provider.
//!
//! # Why "recognised but not implemented" is its own variant
//!
//! Section 7.1 (SB-7) added a class that did not exist before: a value that is
//! **valid in the contract** and **not written in this build**. `date_policy =
//! "shift"` and `detection.ner.enabled = true` are both of them. Falling back to
//! the default would be the worst available outcome: the operator asked for date
//! shifting and got dates sent as they are, or asked for name detection and got
//! a `pattern+dictionary` run, and in both cases believes otherwise.
//!
//! The message has to be **distinguishable** from an unrecognised value, because
//! the operator's next move differs: an unrecognised value is a typo to fix, an
//! unimplemented one needs a different build or a different mode. That is why
//! [`PolicyError::RecognisedButUnimplemented`] carries the key, the value and the
//! scope boundary that explains it, rather than being folded into
//! [`PolicyError::UnknownValue`].

use crate::detect::affix::AffixError;
use crate::detect::dictionary::DictionaryError;

/// The `x-periskop-error` value every load failure carries
/// (`proxy-policy.md` section 7).
///
/// One value for every row of the table on purpose: the header says a policy
/// could not be loaded, and the detail is in the message, which does not cross
/// the network.
pub const POLICY_UNLOADABLE: &str = "policy_unloadable";

/// Why a policy file did not become a [`super::Policy`].
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The file is not TOML, or not the shape the schema describes.
    #[error("policy is not readable as TOML: {detail}")]
    Unparseable { detail: String },

    /// A key nothing in this contract defines.
    ///
    /// Section 7 row 2. Ignoring it is forbidden: an operator who misspells
    /// `code_block_policy` gets the default and never learns it.
    #[error("policy names unknown key '{key}'; a key nobody recognises is a rule nothing applies")]
    UnknownKey { key: String },

    /// A key that names a real concept the policy does not get to set.
    ///
    /// `masking_profile` is the one that matters: `proxy-policy.md` section 4.1
    /// derives it from `detection.ner.enabled`, and the reason is that the same
    /// fact settable in two places drifts, after which the report declares a
    /// profile the run did not have. Distinguished from [`Self::UnknownKey`]
    /// because an operator writing this key is not making a typo, and the fix is
    /// to delete the line rather than correct it.
    #[error(
        "policy key '{key}' is derived and not writable; it follows from the keys it is \
         computed from, and a second place to set it is a second answer to the same question"
    )]
    DerivedKeyIsNotWritable { key: String },

    /// A type identifier outside the closed set.
    #[error("policy rule {index} names unknown entity type '{tag}'")]
    UnknownEntityType { index: usize, tag: String },

    /// A value outside a key's enum.
    #[error("policy key '{key}' has unknown value '{value}'; expected one of {expected}")]
    UnknownValue {
        key: String,
        value: String,
        expected: &'static str,
    },

    /// A value this contract defines and this build does not implement.
    ///
    /// Distinguishable from [`Self::UnknownValue`] by type and by wording, and
    /// the test that proves the two are distinguishable is in `policy::load`.
    #[error(
        "policy key '{key}' asks for '{value}', which this contract defines but this build \
         does not implement ({boundary}); it is refused rather than silently replaced by \
         '{would_have_been}', because getting '{would_have_been}' while believing '{value}' \
         is unmasked data the operator thinks is masked"
    )]
    RecognisedButUnimplemented {
        key: &'static str,
        value: String,
        /// Which scope boundary of `milestones.md` F4 removed it.
        boundary: &'static str,
        /// What a silent fallback would have produced. Named so the message says
        /// what was refused as well as what was asked for.
        would_have_been: &'static str,
    },

    /// `stream.l_max_session` above the compile time ceiling.
    #[error(
        "stream.l_max_session = {asked} exceeds L_MAX_STATIC = {ceiling}; the lookahead window \
         is a correctness bound, not a tuning knob"
    )]
    LookaheadAboveCeiling { asked: usize, ceiling: usize },

    /// The word list could not be read and `dictionary.required = true`.
    ///
    /// The field is `list` and not `source`, because `thiserror` reads a field
    /// called `source` as the underlying error rather than as a name.
    #[error("dictionary '{list}' is required and could not be read: {detail}")]
    DictionaryUnreadable { list: String, detail: String },

    /// The word list was read and is not valid.
    #[error("dictionary '{list}' is invalid: {detail}")]
    DictionaryInvalid {
        list: String,
        detail: DictionaryError,
    },

    /// A language is listed in `affix_rules.languages` with no rule directory.
    #[error("{0}")]
    AffixRules(#[from] AffixError),

    /// The declared `policy_hash` is not the hash of the body.
    ///
    /// Section 6: the proxy accepts no request in this state, and does not fall
    /// back to a previously loaded policy at run time.
    #[error(
        "policy_hash mismatch: the file declares {declared} and its canonical body hashes to \
         {computed}; no request is accepted under an unverified policy"
    )]
    HashMismatch { declared: String, computed: String },

    /// `policy_hash` is present and is not 64 hex characters.
    #[error("policy_hash '{declared}' is not 64 lower case hex characters")]
    HashMalformed { declared: String },

    /// `policy_id` or `policy_version` is empty.
    #[error("policy field '{field}' must not be empty")]
    EmptyIdentity { field: &'static str },
}

impl PolicyError {
    /// The header value this failure reports as.
    pub const fn header_value(&self) -> &'static str {
        POLICY_UNLOADABLE
    }

    /// Whether this is the "recognised, not implemented" class of section 7.1.
    ///
    /// Exposed so a caller can tell an operator to change build rather than to
    /// fix a typo, and so the distinguishability test does not read the message
    /// text.
    pub const fn is_unimplemented_value(&self) -> bool {
        matches!(self, Self::RecognisedButUnimplemented { .. })
    }
}

/// A key that has no effect and is safe to ignore, reported rather than dropped.
///
/// Section 7's one non-fatal row: `derived_date_action` given while
/// `date_policy != "shift"`. Ignoring it silently would be the same mistake in
/// miniature, so it comes back as a warning the caller has to carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyWarning {
    pub key: &'static str,
    pub detail: String,
}
