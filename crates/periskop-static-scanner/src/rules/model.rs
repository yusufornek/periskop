//! The shape of a detector rule.
//!
//! Rules are data, not code. Adding support for a library means writing a TOML
//! file and three fixtures, which keeps the contributor bar at "can read a query"
//! rather than "can write Rust".
//!
//! The primitives here are deliberately few. A rule can match a syntax pattern,
//! constrain a binding, pull out a handful of fields and say how confident the
//! result is. It cannot express cross module data flow, and it is not meant to:
//! that limit is catalogued rather than papered over.

use std::collections::BTreeMap;

use serde::Deserialize;

/// One rule file, covering one library for one language.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    pub schema_version: String,
    pub language: String,
    pub provider: String,
    pub rule_id: String,
    pub rule_version: String,

    /// Patterns that make this rule fire. A rule with no patterns can never
    /// produce a finding, so the loader rejects it rather than letting a silent
    /// no-op sit in the rule set.
    #[serde(rename = "match")]
    pub matches: Vec<MatchSpec>,

    /// Modules this rule accounts for beyond what its bindings name.
    ///
    /// A rule that keys on a destination rather than on a client object has no
    /// binding, so nothing else would mark the HTTP libraries it covers as
    /// handled. Without this they would be reported as libraries with no
    /// detector, which is the opposite of true.
    #[serde(default)]
    pub covers_modules: Vec<String>,

    #[serde(default)]
    pub extract: BTreeMap<String, ExtractSpec>,

    pub classify: ClassifySpec,

    /// blake3 of the rule file as written. Filled in by the loader, never read
    /// from the file itself, so a rule cannot claim a hash it does not have.
    /// Carried into every finding so a report can be traced to the exact rule
    /// text that produced it.
    #[serde(skip)]
    pub rule_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchSpec {
    /// What kind of syntax this pattern targets. Reported with the finding so a
    /// reader can tell an import match from a call match.
    pub kind: MatchKind,

    /// A tree-sitter query in the grammar's own node names.
    pub query: String,

    /// Constrains the receiver capture to a known import.
    ///
    /// Without this a query matching `x.chat.completions.create()` would fire on
    /// any object that happens to expose that path. With it, the match is tied to
    /// a symbol the file actually imported.
    #[serde(default)]
    pub binding: Option<BindingSpec>,

    #[serde(default)]
    pub method: Option<MethodSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    Call,
    Import,
    /// A raw HTTP call whose destination is a provider endpoint.
    HttpRequest,
}

impl MatchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Import => "import",
            Self::HttpRequest => "http_request",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingSpec {
    pub capture: String,
    pub resolves_to: ResolvesTo,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvesTo {
    pub module: String,
    #[serde(default)]
    pub symbol_path: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MethodSpec {
    pub capture: String,
    pub one_of: Vec<String>,
}

/// A field lifted out of the match and carried into the report.
///
/// Failing to resolve one is not a failure of the rule. The finding is still
/// produced, the field is marked unresolved, and the coverage statement gains a
/// line. Dropping the finding instead would hide a real egress because one
/// detail was dynamic.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractSpec {
    pub from: String,
    #[serde(default)]
    pub keyword: Option<String>,
    #[serde(default)]
    pub constructor_keyword: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassifySpec {
    /// Functional class of the egress. Deliberately an open string in v1: the
    /// vocabulary has one known member, and a single member enum would break on
    /// the day a second appears.
    pub egress_kind: String,

    pub default_confidence: Confidence,

    /// Conditions that lower confidence rather than suppressing the finding.
    #[serde(default)]
    pub downgrade: Vec<DowngradeSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Confirmed,
    Suspect,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Suspect => "suspect",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DowngradeSpec {
    /// Condition expressed as `<field>.unresolved`.
    pub when: String,
    pub to: Confidence,
    /// Note added to the coverage statement when this downgrade fires, so the
    /// reason a finding is only suspected stays visible.
    #[serde(default)]
    pub coverage_note: Option<String>,
}
