//! The workspace error type.
//!
//! Every variant names a condition a caller can act on. There is deliberately no
//! catch-all `Other(String)`: a scanner that cannot say why it failed produces a
//! coverage entry that nobody can interpret, which is the failure mode this
//! product exists to prevent.

use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{path} could not be parsed: {detail}")]
    Parse { path: PathBuf, detail: String },

    #[error("rule file {path} is invalid at line {line}: {detail}")]
    RuleSyntax {
        path: PathBuf,
        line: usize,
        detail: String,
    },

    /// A query that fails to compile is a defect in the rule, not in the input.
    /// It must surface with the rule that caused it, because a rule set is only
    /// useful if a broken entry can be traced back to a file a human wrote.
    #[error("rule {rule_id} did not compile: {detail}")]
    RuleCompile { rule_id: String, detail: String },

    #[error("{what} is not a valid {kind} identifier")]
    MalformedId { kind: &'static str, what: String },

    #[error("unsupported schema version {found}, this build understands {supported}")]
    SchemaVersion { found: String, supported: String },
}
