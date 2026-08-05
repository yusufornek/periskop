//! Declarative detector rules.
//!
//! A rule says what to look for; the engine is a general matcher that knows
//! nothing about any particular library. That split is what lets a new provider
//! arrive as a TOML file and three fixtures instead of a Rust patch.

pub mod compiler;
pub mod embedded;
pub mod loader;
pub mod model;
pub mod source;

pub use compiler::{compile, CompileError, CompiledRules, PatternOrigin};
pub use embedded::{embedded_rule_files, load_embedded, EmbeddedRuleFile};
pub use loader::{load_directory, load_rule_file, parse_rule, RuleLoadError};
pub use model::{Confidence, MatchKind, RuleFile};
pub use source::RuleSource;
