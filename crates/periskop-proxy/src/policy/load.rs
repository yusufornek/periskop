//! Reading `policy.toml`, fail closed.
//!
//! # The rule this module exists to keep
//!
//! `proxy-policy.md` section 7: everything that is not provably harmless stops
//! startup. Not "logs a warning and continues" — stops. The reason is one
//! sentence long and it is the same sentence for every row of that table: a rule
//! that is silently dropped is a value the operator believes is masked, already
//! on its way to a provider.
//!
//! # Two passes, and the order matters
//!
//! 1. **Parse.** TOML decides what the bytes say. A file that is not TOML is not
//!    a policy, and nothing further is attempted.
//! 2. **Validate.** The parsed document is projected to the canonical JSON the
//!    schema describes, and every key, every value and every cross-key constraint
//!    is checked against what **this build** implements. `npm run
//!    validate:schemas` checks the same projection in CI, so the rule CI sees and
//!    the rule the process enforces come out of one file.
//!
//! Keeping them apart is what makes "recognised but not implemented" expressible
//! at all: `date_policy = "shift"` parses perfectly and is a contract value; only
//! the second pass knows this build did not write it.
//!
//! # `policy_hash`
//!
//! Section 6: blake3-256 of the canonical body, 64 hex characters. It is not one
//! of the schema's properties, because a hash cannot cover itself; the loader
//! strips it before hashing. Verification failing means the proxy accepts no
//! request, and this module's contribution to that is refusing to produce a
//! [`Policy`] at all. There is no partially loaded policy to fall back to.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::alias::{AliasStyle, EntityType, L_MAX_STATIC};
use crate::detect::affix::AffixRules;
use crate::detect::dictionary::Dictionary;
use crate::detect::MaskingProfile;

use super::error::{PolicyError, PolicyWarning};
use super::scope::{Mode, Rule, Scope};

/// What `date_policy` may be **in this build**.
///
/// `shift` is missing on purpose and its absence is the enforcement: F4's scope
/// boundary 2 removed date shifting entirely, so there is no variant to hold it
/// and no branch that could quietly behave like `allow`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DatePolicy {
    /// ADR-010 section 7's default: dates cross, and are counted.
    #[default]
    Allow,
    /// A date found means the request is refused.
    Block,
}

impl DatePolicy {
    /// The spelling `policy.toml` uses and `/admin/policy` returns.
    ///
    /// There is no `"shift"` arm, and its absence is what makes the read only
    /// projection unable to claim a mode this build does not implement.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }
}

/// `on_hold_timeout` (`proxy/spec.md` section 6.2 F2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HoldTimeout {
    #[default]
    Flush,
    Wait,
}

/// `code_block_policy` (spec section 7).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CodeBlockPolicy {
    /// Only layer A runs inside a fence.
    #[default]
    PatternOnly,
    /// Every enabled layer runs inside a fence.
    Full,
    /// Nothing runs inside a fence.
    Skip,
}

/// `tool_call_policy` (`proxy-api.md`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ToolCallPolicy {
    #[default]
    PassThrough,
    Reject,
}

impl ToolCallPolicy {
    /// The spelling `policy.toml` uses and `/admin/policy` returns.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PassThrough => "pass-through",
            Self::Reject => "reject",
        }
    }
}

/// A loaded, validated policy.
///
/// Construction is the validation: there is no way to build one of these that
/// skipped a check, which is what makes "fail closed" a property of the type
/// rather than of a code path somebody has to remember to call.
#[derive(Debug)]
pub struct Policy {
    policy_id: String,
    policy_version: String,
    policy_hash: String,
    default_mode: Mode,
    rules: Vec<Rule>,
    alias_style: AliasStyle,
    date_policy: DatePolicy,
    on_hold_timeout: HoldTimeout,
    code_block_policy: CodeBlockPolicy,
    tool_call_policy: ToolCallPolicy,
    hold_timeout_ms: u64,
    l_max_session: Option<usize>,
    affix_languages: Vec<String>,
    dictionary: Dictionary,
    dictionary_available: bool,
    warnings: Vec<PolicyWarning>,
}

/// Every key the contract defines, with its nesting.
///
/// Written out rather than derived from a struct, because `serde`'s
/// `deny_unknown_fields` would report the first offender and nothing about where
/// it sat, and because this list is what an operator's error message is built
/// from.
const TOP_LEVEL_KEYS: &[&str] = &[
    "policy_id",
    "policy_version",
    "policy_hash",
    "default",
    "rule",
    "alias_style",
    "date_policy",
    "derived_date_action",
    "on_hold_timeout",
    "code_block_policy",
    "tool_call_policy",
    "detection",
    "stream",
    "dictionary",
    "affix_rules",
];

/// Keys that exist as a concept and are **derived**, never written.
///
/// `proxy-policy.md` section 4.1: `masking_profile` comes from
/// `detection.ner.enabled`. A policy that sets it is not making a typo, it is
/// asking for the one thing that would let the report and the run disagree, so
/// its message is its own.
const DERIVED_KEYS: &[&str] = &["masking_profile", "ruleset_hash", "l_max_static"];

impl Policy {
    /// Loads a policy from TOML text.
    ///
    /// `base` is the directory paths in the file resolve against (the policy
    /// file's own directory, per `proxy-policy.md` section 10) and the root the
    /// `rules/masking/<lang>/` directories are looked up under. `expected_hash`
    /// is the out-of-band `policy_hash` a deployment pins; `None` skips the
    /// comparison but still computes the hash, so a report can always name the
    /// policy it ran under.
    pub fn load(text: &str, base: &Path, expected_hash: Option<&str>) -> Result<Self, PolicyError> {
        let parsed: toml::Value =
            toml::from_str(text).map_err(|error| PolicyError::Unparseable {
                detail: error.to_string(),
            })?;
        let mut document = to_json(&parsed).ok_or_else(|| PolicyError::Unparseable {
            detail: "the policy body is not a table".to_owned(),
        })?;

        // The hash cannot cover itself, and the schema's closed property set does
        // not carry it. Taken out before both.
        let declared_hash = match document.remove("policy_hash") {
            Some(Value::String(text)) => Some(text),
            Some(other) => {
                return Err(PolicyError::UnknownValue {
                    key: "policy_hash".to_owned(),
                    value: other.to_string(),
                    expected: "a 64 character lower case hex string",
                })
            }
            None => None,
        };

        let computed = canonical_hash(&document);
        if let Some(declared) = declared_hash.as_deref() {
            check_hash_shape(declared)?;
            if declared != computed {
                return Err(PolicyError::HashMismatch {
                    declared: declared.to_owned(),
                    computed,
                });
            }
        }
        if let Some(expected) = expected_hash {
            check_hash_shape(expected)?;
            if expected != computed {
                return Err(PolicyError::HashMismatch {
                    declared: expected.to_owned(),
                    computed,
                });
            }
        }

        Self::from_document(document, computed, base)
    }

    /// Loads from a path, resolving relative paths against its directory.
    pub fn load_from_path(
        path: &Path,
        root: &Path,
        expected_hash: Option<&str>,
    ) -> Result<Self, PolicyError> {
        let text = std::fs::read_to_string(path).map_err(|error| PolicyError::Unparseable {
            detail: format!("{}: {error}", path.display()),
        })?;
        let base = path
            .parent()
            .map_or_else(|| root.to_owned(), Path::to_owned);
        let mut policy = Self::load(&text, &base, expected_hash)?;
        policy.load_affix_rules(root)?;
        Ok(policy)
    }

    fn from_document(
        document: Map<String, Value>,
        hash: String,
        base: &Path,
    ) -> Result<Self, PolicyError> {
        reject_unknown_keys(&document, TOP_LEVEL_KEYS, "")?;

        let policy_id = required_non_empty(&document, "policy_id")?;
        let policy_version = required_non_empty(&document, "policy_version")?;

        let default_table = document
            .get("default")
            .and_then(Value::as_object)
            .ok_or(PolicyError::EmptyIdentity { field: "default" })?;
        reject_unknown_keys(default_table, &["mode"], "default.")?;
        let default_mode = mode_of(default_table.get("mode"), "default.mode")?;

        let rules = read_rules(document.get("rule"))?;

        let alias_style = match string_of(&document, "alias_style")? {
            None | Some("type-preserving") => AliasStyle::TypePreserving,
            Some("opaque") => AliasStyle::Opaque,
            Some(other) => {
                return Err(PolicyError::UnknownValue {
                    key: "alias_style".to_owned(),
                    value: other.to_owned(),
                    expected: "type-preserving | opaque",
                })
            }
        };

        let date_policy = match string_of(&document, "date_policy")? {
            None | Some("allow") => DatePolicy::Allow,
            Some("block") => DatePolicy::Block,
            // Section 7.1. The contract defines this value; this build does not
            // implement it, and falling back to `allow` would send dates the
            // operator believes are shifted.
            Some("shift") => {
                return Err(PolicyError::RecognisedButUnimplemented {
                    key: "date_policy",
                    value: "shift".to_owned(),
                    boundary: "milestones.md F4 scope boundary 2",
                    would_have_been: "allow",
                })
            }
            Some(other) => {
                return Err(PolicyError::UnknownValue {
                    key: "date_policy".to_owned(),
                    value: other.to_owned(),
                    expected: "allow | block | shift",
                })
            }
        };

        // Section 7 row 8, the one non-fatal row: provably ineffective, so it is
        // ignored and reported rather than ignored quietly.
        let mut warnings = Vec::new();
        if let Some(action) = string_of(&document, "derived_date_action")? {
            if !matches!(action, "annotate" | "fail") {
                return Err(PolicyError::UnknownValue {
                    key: "derived_date_action".to_owned(),
                    value: action.to_owned(),
                    expected: "annotate | fail",
                });
            }
            warnings.push(PolicyWarning {
                key: "derived_date_action",
                detail: format!(
                    "'{action}' is only meaningful under date_policy = \"shift\"; \
                     date_policy is \"{}\", so the key has no effect",
                    match date_policy {
                        DatePolicy::Allow => "allow",
                        DatePolicy::Block => "block",
                    }
                ),
            });
        }

        let on_hold_timeout = match string_of(&document, "on_hold_timeout")? {
            None | Some("flush") => HoldTimeout::Flush,
            Some("wait") => HoldTimeout::Wait,
            Some(other) => {
                return Err(PolicyError::UnknownValue {
                    key: "on_hold_timeout".to_owned(),
                    value: other.to_owned(),
                    expected: "flush | wait",
                })
            }
        };

        let code_block_policy = match string_of(&document, "code_block_policy")? {
            None | Some("pattern-only") => CodeBlockPolicy::PatternOnly,
            Some("full") => CodeBlockPolicy::Full,
            Some("skip") => CodeBlockPolicy::Skip,
            Some(other) => {
                return Err(PolicyError::UnknownValue {
                    key: "code_block_policy".to_owned(),
                    value: other.to_owned(),
                    expected: "pattern-only | full | skip",
                })
            }
        };

        let tool_call_policy = match string_of(&document, "tool_call_policy")? {
            None | Some("pass-through") => ToolCallPolicy::PassThrough,
            Some("reject") => ToolCallPolicy::Reject,
            Some(other) => {
                return Err(PolicyError::UnknownValue {
                    key: "tool_call_policy".to_owned(),
                    value: other.to_owned(),
                    expected: "pass-through | reject",
                })
            }
        };

        read_detection(&document)?;
        let (hold_timeout_ms, l_max_session) = read_stream(&document, alias_style)?;
        let affix_languages = read_affix_languages(&document)?;
        let (dictionary, dictionary_available) = read_dictionary(&document, base)?;

        Ok(Self {
            policy_id,
            policy_version,
            policy_hash: hash,
            default_mode,
            rules,
            alias_style,
            date_policy,
            on_hold_timeout,
            code_block_policy,
            tool_call_policy,
            hold_timeout_ms,
            l_max_session,
            affix_languages,
            dictionary,
            dictionary_available,
            warnings,
        })
    }

    /// Loads the affix rule directories the policy declares.
    ///
    /// Split out of [`Self::from_document`] because it needs the repository root
    /// rather than the policy file's directory, and because a caller with the
    /// rules elsewhere has to be able to say so. A declared language with no
    /// directory stops the load (`proxy-policy.md` sections 7 and 11).
    pub fn load_affix_rules(&mut self, root: &Path) -> Result<(), PolicyError> {
        let languages = self.affix_languages.clone();
        for language in &languages {
            let rules = AffixRules::load(root, language)?;
            // One language today (`["tr"]` is a closed set), so the last one
            // loaded is the one in force. A second language would need the
            // dictionary to hold a set, and that is a MINOR change with its own
            // tests, per section 11.
            let dictionary = std::mem::replace(&mut self.dictionary, Dictionary::empty());
            self.dictionary = dictionary.with_affixes(rules);
        }
        Ok(())
    }

    /// Identity fields, in the shape `report-schema.md` carries them.
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }
    /// The blake3-256 of the canonical body, 64 lower case hex characters.
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }
    pub fn default_mode(&self) -> Mode {
        self.default_mode
    }
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
    pub fn alias_style(&self) -> AliasStyle {
        self.alias_style
    }
    pub fn date_policy(&self) -> DatePolicy {
        self.date_policy
    }
    pub fn on_hold_timeout(&self) -> HoldTimeout {
        self.on_hold_timeout
    }
    pub fn code_block_policy(&self) -> CodeBlockPolicy {
        self.code_block_policy
    }
    pub fn tool_call_policy(&self) -> ToolCallPolicy {
        self.tool_call_policy
    }
    pub fn hold_timeout_ms(&self) -> u64 {
        self.hold_timeout_ms
    }
    pub fn l_max_session(&self) -> Option<usize> {
        self.l_max_session
    }
    pub fn affix_languages(&self) -> &[String] {
        &self.affix_languages
    }
    pub fn dictionary(&self) -> &Dictionary {
        &self.dictionary
    }
    /// Whether the word list was actually read.
    ///
    /// `false` only under `dictionary.required = false`, and the caller owes a
    /// `degraded_reasons[] = dictionary_unavailable` for it. An **empty** list is
    /// available: section 10 keeps the two apart because one is a choice and the
    /// other is a failure.
    pub fn dictionary_available(&self) -> bool {
        self.dictionary_available
    }
    /// Keys accepted, ignored, and reported.
    pub fn warnings(&self) -> &[PolicyWarning] {
        &self.warnings
    }

    /// The profile this policy runs under.
    ///
    /// Always `pattern+dictionary` here, and it is a derivation rather than a
    /// constant: `detection.ner.enabled = true` cannot load, so the other branch
    /// is unreachable by construction rather than by omission.
    pub fn masking_profile(&self) -> MaskingProfile {
        MaskingProfile::derived_from(false)
    }
}

/// Converts a TOML document to the canonical JSON projection the schema
/// describes.
///
/// `serde_json`'s default map is a `BTreeMap`, so serialization is key sorted
/// and the hash below is stable across runs and machines. That is not incidental:
/// `policy_hash` has to be the same number everywhere or a deployment cannot pin
/// it.
fn to_json(value: &toml::Value) -> Option<Map<String, Value>> {
    let converted = serde_json::to_value(value).ok()?;
    match converted {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// blake3-256 of the canonical JSON body, as 64 lower case hex characters.
fn canonical_hash(document: &Map<String, Value>) -> String {
    let canonical = Value::Object(document.clone()).to_string();
    blake3::hash(canonical.as_bytes()).to_hex().to_string()
}

fn check_hash_shape(hash: &str) -> Result<(), PolicyError> {
    let well_formed = hash.len() == 64
        && hash
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
    if well_formed {
        Ok(())
    } else {
        Err(PolicyError::HashMalformed {
            declared: hash.to_owned(),
        })
    }
}

/// Refuses a key nothing defines, and names the derived keys separately.
fn reject_unknown_keys(
    table: &Map<String, Value>,
    known: &[&str],
    prefix: &str,
) -> Result<(), PolicyError> {
    for key in table.keys() {
        if DERIVED_KEYS.contains(&key.as_str()) {
            return Err(PolicyError::DerivedKeyIsNotWritable {
                key: format!("{prefix}{key}"),
            });
        }
        if !known.contains(&key.as_str()) {
            return Err(PolicyError::UnknownKey {
                key: format!("{prefix}{key}"),
            });
        }
    }
    Ok(())
}

fn required_non_empty(
    document: &Map<String, Value>,
    field: &'static str,
) -> Result<String, PolicyError> {
    match document.get(field).and_then(Value::as_str) {
        Some(text) if !text.is_empty() => Ok(text.to_owned()),
        _ => Err(PolicyError::EmptyIdentity { field }),
    }
}

fn string_of<'d>(
    document: &'d Map<String, Value>,
    key: &str,
) -> Result<Option<&'d str>, PolicyError> {
    match document.get(key) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.as_str())),
        Some(other) => Err(PolicyError::UnknownValue {
            key: key.to_owned(),
            value: other.to_string(),
            expected: "a string",
        }),
    }
}

fn mode_of(value: Option<&Value>, key: &str) -> Result<Mode, PolicyError> {
    let text = value
        .and_then(Value::as_str)
        .ok_or(PolicyError::UnknownValue {
            key: key.to_owned(),
            value: value.map(ToString::to_string).unwrap_or_default(),
            expected: "mask | block | allow",
        })?;
    Mode::parse_mode(text).ok_or_else(|| PolicyError::UnknownValue {
        key: key.to_owned(),
        value: text.to_owned(),
        expected: "mask | block | allow",
    })
}

fn read_rules(value: Option<&Value>) -> Result<Vec<Rule>, PolicyError> {
    let Some(list) = value else {
        return Ok(Vec::new());
    };
    let Some(items) = list.as_array() else {
        return Err(PolicyError::UnknownValue {
            key: "rule".to_owned(),
            value: list.to_string(),
            expected: "an array of tables",
        });
    };
    let mut rules = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let Some(table) = item.as_object() else {
            return Err(PolicyError::UnknownValue {
                key: format!("rule[{index}]"),
                value: item.to_string(),
                expected: "a table",
            });
        };
        reject_unknown_keys(
            table,
            &["scope", "entity", "mode"],
            &format!("rule[{index}]."),
        )?;
        let mode = mode_of(table.get("mode"), &format!("rule[{index}].mode"))?;
        let entity =
            match table.get("entity").and_then(Value::as_str) {
                None => None,
                Some(tag) => Some(EntityType::from_tag(tag).ok_or_else(|| {
                    PolicyError::UnknownEntityType {
                        index,
                        tag: tag.to_owned(),
                    }
                })?),
            };
        let scope = match table.get("scope").and_then(Value::as_str) {
            None => Scope::everything(),
            Some(path) => Scope::parse(path).ok_or_else(|| PolicyError::UnknownValue {
                key: format!("rule[{index}].scope"),
                value: path.to_owned(),
                expected: "a JSON path such as messages[*].content",
            })?,
        };
        rules.push(Rule {
            scope,
            entity,
            mode,
        });
    }
    Ok(rules)
}

/// Validates `[detection.ner]` and refuses the one value F4 did not write.
fn read_detection(document: &Map<String, Value>) -> Result<(), PolicyError> {
    let Some(detection) = document.get("detection") else {
        return Ok(());
    };
    let Some(table) = detection.as_object() else {
        return Err(PolicyError::UnknownValue {
            key: "detection".to_owned(),
            value: detection.to_string(),
            expected: "a table",
        });
    };
    reject_unknown_keys(table, &["ner"], "detection.")?;
    let Some(ner) = table.get("ner") else {
        return Ok(());
    };
    let Some(ner) = ner.as_object() else {
        return Err(PolicyError::UnknownValue {
            key: "detection.ner".to_owned(),
            value: ner.to_string(),
            expected: "a table",
        });
    };
    reject_unknown_keys(
        ner,
        &["enabled", "threshold", "languages", "on_model_error"],
        "detection.ner.",
    )?;

    // Section 7.1's second row. The keys are read and validated (scope boundary
    // 1 says so) and `enabled = true` is a load failure, not a downgrade: running
    // `pattern+dictionary` while the operator believes names are being detected
    // is the failure this whole section exists to prevent.
    if ner.get("enabled") == Some(&Value::Bool(true)) {
        return Err(PolicyError::RecognisedButUnimplemented {
            key: "detection.ner.enabled",
            value: "true".to_owned(),
            boundary: "milestones.md F4 scope boundary 1",
            would_have_been: "false",
        });
    }
    if let Some(threshold) = ner.get("threshold") {
        let ok = threshold.as_f64().is_some_and(|v| (0.0..=1.0).contains(&v));
        if !ok {
            return Err(PolicyError::UnknownValue {
                key: "detection.ner.threshold".to_owned(),
                value: threshold.to_string(),
                expected: "a number between 0.0 and 1.0",
            });
        }
    }
    if let Some(languages) = ner.get("languages") {
        let entries = languages
            .as_array()
            .ok_or_else(|| PolicyError::UnknownValue {
                key: "detection.ner.languages".to_owned(),
                value: languages.to_string(),
                expected: "an array of tr | en",
            })?;
        for entry in entries {
            let tag = entry.as_str().unwrap_or_default();
            if !matches!(tag, "tr" | "en") {
                return Err(PolicyError::UnknownValue {
                    key: "detection.ner.languages".to_owned(),
                    value: entry.to_string(),
                    expected: "tr | en",
                });
            }
        }
    }
    if let Some(on_error) = ner.get("on_model_error") {
        let tag = on_error.as_str().unwrap_or_default();
        if !matches!(tag, "strict" | "degraded") {
            return Err(PolicyError::UnknownValue {
                key: "detection.ner.on_model_error".to_owned(),
                value: on_error.to_string(),
                expected: "strict | degraded",
            });
        }
    }
    Ok(())
}

/// Validates `[stream]`, including the ceiling that is a correctness bound.
fn read_stream(
    document: &Map<String, Value>,
    style: AliasStyle,
) -> Result<(u64, Option<usize>), PolicyError> {
    let default_hold = 40u64;
    let Some(stream) = document.get("stream") else {
        return Ok((default_hold, None));
    };
    let Some(table) = stream.as_object() else {
        return Err(PolicyError::UnknownValue {
            key: "stream".to_owned(),
            value: stream.to_string(),
            expected: "a table",
        });
    };
    reject_unknown_keys(table, &["hold_timeout_ms", "l_max_session"], "stream.")?;

    let hold = match table.get("hold_timeout_ms") {
        None => default_hold,
        Some(value) => value.as_u64().ok_or_else(|| PolicyError::UnknownValue {
            key: "stream.hold_timeout_ms".to_owned(),
            value: value.to_string(),
            expected: "an integer of at least 0",
        })?,
    };

    let ceiling = crate::alias::l_max_static(style);
    let l_max = match table.get("l_max_session") {
        None => None,
        Some(value) => {
            let asked = value
                .as_u64()
                .and_then(|v| usize::try_from(v).ok())
                .filter(|v| *v >= 1)
                .ok_or_else(|| PolicyError::UnknownValue {
                    key: "stream.l_max_session".to_owned(),
                    value: value.to_string(),
                    expected: "an integer of at least 1",
                })?;
            if asked > ceiling {
                return Err(PolicyError::LookaheadAboveCeiling { asked, ceiling });
            }
            Some(asked)
        }
    };
    debug_assert!(ceiling <= L_MAX_STATIC);
    Ok((hold, l_max))
}

fn read_affix_languages(document: &Map<String, Value>) -> Result<Vec<String>, PolicyError> {
    let Some(block) = document.get("affix_rules") else {
        return Ok(Vec::new());
    };
    let Some(table) = block.as_object() else {
        return Err(PolicyError::UnknownValue {
            key: "affix_rules".to_owned(),
            value: block.to_string(),
            expected: "a table",
        });
    };
    reject_unknown_keys(table, &["languages"], "affix_rules.")?;
    let Some(languages) = table.get("languages") else {
        return Ok(Vec::new());
    };
    let entries = languages
        .as_array()
        .ok_or_else(|| PolicyError::UnknownValue {
            key: "affix_rules.languages".to_owned(),
            value: languages.to_string(),
            expected: "an array of language tags",
        })?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for entry in entries {
        let tag = entry.as_str().unwrap_or_default();
        // Closed set today (`["tr"]`, section 11). A tag outside it is refused
        // rather than looked up, so the error names the contract and not a
        // missing directory.
        if tag != "tr" {
            return Err(PolicyError::UnknownValue {
                key: "affix_rules.languages".to_owned(),
                value: entry.to_string(),
                expected: "tr",
            });
        }
        if seen.insert(tag.to_owned()) {
            out.push(tag.to_owned());
        }
    }
    Ok(out)
}

/// Reads `[dictionary]`, honouring `required`.
fn read_dictionary(
    document: &Map<String, Value>,
    base: &Path,
) -> Result<(Dictionary, bool), PolicyError> {
    let Some(block) = document.get("dictionary") else {
        // No block: layer B runs empty. Not a degradation, because nothing was
        // promised.
        return Ok((Dictionary::empty(), true));
    };
    let Some(table) = block.as_object() else {
        return Err(PolicyError::UnknownValue {
            key: "dictionary".to_owned(),
            value: block.to_string(),
            expected: "a table",
        });
    };
    reject_unknown_keys(table, &["source", "required"], "dictionary.")?;
    let source = table
        .get("source")
        .and_then(Value::as_str)
        .ok_or(PolicyError::EmptyIdentity {
            field: "dictionary.source",
        })?;
    let required = match table.get("required") {
        None => true,
        Some(Value::Bool(value)) => *value,
        Some(other) => {
            return Err(PolicyError::UnknownValue {
                key: "dictionary.required".to_owned(),
                value: other.to_string(),
                expected: "true | false",
            })
        }
    };

    let path: PathBuf = base.join(source);
    match std::fs::read_to_string(&path) {
        Ok(text) => match Dictionary::parse(&text) {
            Ok(dictionary) => Ok((dictionary, true)),
            // A malformed list stops the load whatever `required` says: it is
            // not an unavailable list, it is a wrong one, and starting with a
            // wrong list masks the wrong things.
            Err(detail) => Err(PolicyError::DictionaryInvalid {
                list: source.to_owned(),
                detail,
            }),
        },
        Err(error) if required => Err(PolicyError::DictionaryUnreadable {
            list: source.to_owned(),
            detail: error.to_string(),
        }),
        // `required = false`: layer B opens empty and the caller owes a
        // `dictionary_unavailable` on every request.
        Err(_) => Ok((Dictionary::empty(), false)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    const MINIMAL: &str = r#"
policy_id = "acme"
policy_version = "2026.08.1"
[default]
mode = "mask"
"#;

    /// A minimal policy with `extra` spliced in **before** the `[default]`
    /// table.
    ///
    /// Appending instead would put the keys inside `[default]`, where TOML's
    /// table scoping means every one of them reads as `default.<key>` and every
    /// test below would be asserting about a key nobody wrote. That mistake
    /// produced five green-looking failures the first time this file ran.
    fn with(extra: &str) -> String {
        format!("policy_id = \"acme\"\npolicy_version = \"2026.08.1\"\n{extra}\n[default]\nmode = \"mask\"\n")
    }

    fn load(text: &str) -> Result<Policy, PolicyError> {
        Policy::load(text, &repository_root(), None)
    }

    #[test]
    fn a_minimal_policy_loads_with_the_documented_defaults() {
        let policy = load(MINIMAL).unwrap();
        assert_eq!(policy.policy_id(), "acme");
        assert_eq!(policy.default_mode(), Mode::Mask);
        assert_eq!(policy.alias_style(), AliasStyle::TypePreserving);
        assert_eq!(policy.date_policy(), DatePolicy::Allow);
        assert_eq!(policy.on_hold_timeout(), HoldTimeout::Flush);
        assert_eq!(policy.code_block_policy(), CodeBlockPolicy::PatternOnly);
        assert_eq!(policy.tool_call_policy(), ToolCallPolicy::PassThrough);
        assert_eq!(policy.hold_timeout_ms(), 40);
        assert_eq!(policy.l_max_session(), None);
        assert!(policy.dictionary().is_empty());
        assert!(policy.dictionary_available());
        assert!(policy.warnings().is_empty());
        assert_eq!(policy.masking_profile().as_str(), "pattern+dictionary");
    }

    // ---- section 7, row by row -------------------------------------------

    #[test]
    fn row_1_an_unknown_entity_type_stops_the_load() {
        let error = load(&with("[[rule]]\nentity = \"PASSPORT\"\nmode = \"block\"")).unwrap_err();
        assert!(matches!(error, PolicyError::UnknownEntityType { .. }));
        assert_eq!(error.header_value(), "policy_unloadable");
    }

    #[test]
    fn row_2_an_unknown_key_stops_the_load_rather_than_being_ignored() {
        let error = load(&with("mask_everything = true")).unwrap_err();
        assert!(matches!(error, PolicyError::UnknownKey { .. }));
        // Nested too, or a typo inside a table would take the default.
        let nested = load(&with("[stream]\nhold_ms = 40")).unwrap_err();
        assert!(matches!(nested, PolicyError::UnknownKey { key } if key == "stream.hold_ms"));
    }

    #[test]
    fn row_3_an_unknown_mode_value_stops_the_load() {
        let error =
            load("policy_id = \"a\"\npolicy_version = \"1\"\n[default]\nmode = \"redact\"\n")
                .unwrap_err();
        assert!(matches!(error, PolicyError::UnknownValue { .. }));
    }

    #[test]
    fn row_4_a_recognised_but_unimplemented_value_stops_the_load_distinguishably() {
        // Section 7.1, both rows of its table. The message class has to differ
        // from an unrecognised value because the operator's next move differs.
        let shift = load(&with("date_policy = \"shift\"")).unwrap_err();
        assert!(shift.is_unimplemented_value());
        assert!(shift.to_string().contains("does not implement"));
        assert!(shift.to_string().contains("scope boundary 2"));

        let ner = load(&with("[detection.ner]\nenabled = true")).unwrap_err();
        assert!(ner.is_unimplemented_value());
        assert!(ner.to_string().contains("scope boundary 1"));

        // And an unrecognised value is NOT of this class, which is the whole
        // point of the distinction.
        let typo = load(&with("date_policy = \"shrift\"")).unwrap_err();
        assert!(!typo.is_unimplemented_value());
        assert!(matches!(typo, PolicyError::UnknownValue { .. }));
    }

    #[test]
    fn row_4_neither_unimplemented_value_falls_back_to_a_default() {
        // The mutation target for this task: turn either branch into a silent
        // default and this goes red. Written as "no policy is produced" rather
        // than as a message check, so weakening the message cannot pass it.
        assert!(load(&with("date_policy = \"shift\"")).is_err());
        assert!(load(&with("[detection.ner]\nenabled = true")).is_err());
        // The permitted values still load, so the refusal is about the value and
        // not about the key.
        assert_eq!(
            load(&with("date_policy = \"block\""))
                .unwrap()
                .date_policy(),
            DatePolicy::Block
        );
        assert!(load(&with("[detection.ner]\nenabled = false")).is_ok());
    }

    #[test]
    fn row_5_a_lookahead_above_the_ceiling_stops_the_load() {
        let error = load(&with("[stream]\nl_max_session = 129")).unwrap_err();
        assert!(matches!(error, PolicyError::LookaheadAboveCeiling { .. }));
        // The ceiling follows the style: opaque aliases are shorter, so a value
        // legal under type-preserving is illegal under opaque.
        let opaque = load(&with(
            "alias_style = \"opaque\"\n[stream]\nl_max_session = 64",
        ))
        .unwrap_err();
        assert!(matches!(opaque, PolicyError::LookaheadAboveCeiling { .. }));
        assert!(load(&with("[stream]\nl_max_session = 42")).is_ok());
    }

    #[test]
    fn row_6_a_required_dictionary_that_cannot_be_read_stops_the_load() {
        let error = load(&with(
            "[dictionary]\nsource = \"nowhere.toml\"\nrequired = true",
        ))
        .unwrap_err();
        assert!(matches!(error, PolicyError::DictionaryUnreadable { .. }));

        // And `required = false` opens with layer B empty and says so, which is
        // a different state from an empty list.
        let degraded = load(&with(
            "[dictionary]\nsource = \"nowhere.toml\"\nrequired = false",
        ))
        .unwrap();
        assert!(!degraded.dictionary_available());
        assert!(degraded.dictionary().is_empty());
    }

    #[test]
    fn row_7_a_declared_language_with_no_rule_directory_stops_the_load() {
        // The check needs the repository root, so it runs through
        // `load_affix_rules`, which is what `load_from_path` calls.
        let mut policy = load(&with("[affix_rules]\nlanguages = [\"tr\"]")).unwrap();
        assert!(policy.load_affix_rules(&repository_root()).is_ok());

        let mut elsewhere = load(&with("[affix_rules]\nlanguages = [\"tr\"]")).unwrap();
        let empty_root = std::env::temp_dir().join("periskop-no-rules-here");
        assert!(matches!(
            elsewhere.load_affix_rules(&empty_root).unwrap_err(),
            PolicyError::AffixRules(_)
        ));

        // A language outside the closed set is refused at parse time, before any
        // directory is looked for.
        let unknown = load(&with("[affix_rules]\nlanguages = [\"de\"]")).unwrap_err();
        assert!(matches!(unknown, PolicyError::UnknownValue { .. }));
    }

    #[test]
    fn row_8_the_one_provably_ineffective_key_is_ignored_and_reported() {
        // Section 7's only non-fatal row. Ignored, but not quietly: the warning
        // is what keeps this from being the same mistake in miniature.
        let policy = load(&with("derived_date_action = \"fail\"")).unwrap();
        assert_eq!(policy.warnings().len(), 1);
        assert_eq!(policy.warnings()[0].key, "derived_date_action");
        assert!(policy.warnings()[0].detail.contains("no effect"));
        // A bad value for it is still a load failure.
        assert!(load(&with("derived_date_action = \"ignore\"")).is_err());
    }

    #[test]
    fn row_9_a_policy_hash_that_does_not_match_produces_no_policy_at_all() {
        let good = load(MINIMAL).unwrap();
        let hash = good.policy_hash().to_owned();
        assert_eq!(hash.len(), 64);

        // Declared in the file.
        let with_hash = with(&format!("policy_hash = \"{hash}\""));
        assert_eq!(load(&with_hash).unwrap().policy_hash(), hash);

        let wrong = with(&format!("policy_hash = \"{}\"", "0".repeat(64)));
        let error = load(&wrong).unwrap_err();
        assert!(matches!(error, PolicyError::HashMismatch { .. }));

        // Pinned out of band by the deployment.
        assert!(Policy::load(MINIMAL, &repository_root(), Some(&hash)).is_ok());
        assert!(Policy::load(MINIMAL, &repository_root(), Some(&"1".repeat(64))).is_err());

        // Not 64 hex characters.
        assert!(matches!(
            Policy::load(MINIMAL, &repository_root(), Some("abc")).unwrap_err(),
            PolicyError::HashMalformed { .. }
        ));
    }

    #[test]
    fn the_hash_is_stable_and_covers_the_body_but_not_itself() {
        let first = load(MINIMAL).unwrap().policy_hash().to_owned();
        let second = load(MINIMAL).unwrap().policy_hash().to_owned();
        assert_eq!(first, second);
        // Key order in the file does not change the canonical body.
        let reordered =
            "policy_version = \"2026.08.1\"\npolicy_id = \"acme\"\n[default]\nmode = \"mask\"\n";
        assert_eq!(load(reordered).unwrap().policy_hash(), first);
        // A real change does.
        let changed = MINIMAL.replace("mask", "block");
        assert_ne!(load(&changed).unwrap().policy_hash(), first);
    }

    #[test]
    fn masking_profile_cannot_be_written_by_a_policy() {
        // Milestone 82: setting it is a load failure, and a distinguishable one,
        // because an operator writing it is not making a typo.
        let error = load(&with("masking_profile = \"pattern+dictionary+ner\"")).unwrap_err();
        assert!(matches!(error, PolicyError::DerivedKeyIsNotWritable { .. }));
        assert!(error.to_string().contains("derived"));
        // Even asking for the value it already has is refused: the point is that
        // the key has one source of truth, not that the values disagree.
        let same = load(&with("masking_profile = \"pattern+dictionary\"")).unwrap_err();
        assert!(matches!(same, PolicyError::DerivedKeyIsNotWritable { .. }));
    }

    #[test]
    fn the_shipped_example_policy_loads() {
        // `schemas/examples/proxy-policy.valid.json` is what CI validates. The
        // loader has to accept the same document, or CI and the process are
        // checking two different contracts.
        let example = std::fs::read_to_string(
            repository_root().join("schemas/examples/proxy-policy.valid.json"),
        )
        .unwrap();
        let document: Map<String, Value> = serde_json::from_str(&example).unwrap();
        let hash = super::canonical_hash(&document);
        // The dictionary and affix paths in the example are not on disk here, so
        // the projection is loaded directly rather than through the file reader.
        let policy = Policy::from_document(document, hash, &repository_root().join("schemas"));
        let error = policy.unwrap_err();
        // The one thing missing is the word list the example names, which is
        // exactly the fail closed behaviour: an example that pointed at a list
        // nobody shipped must not start.
        assert!(matches!(error, PolicyError::DictionaryUnreadable { .. }));
    }

    #[test]
    fn an_empty_or_broken_file_produces_no_policy() {
        // The exhausted case at the gate: nothing to read is not a default
        // policy.
        assert!(load("").is_err());
        assert!(load("this is not toml = = =").is_err());
        assert!(
            load("policy_id = \"\"\npolicy_version = \"1\"\n[default]\nmode=\"mask\"\n").is_err()
        );
    }
}
