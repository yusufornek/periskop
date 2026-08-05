//! Static scanner.
//!
//! Parses source files with tree-sitter and matches declarative rules against the
//! syntax tree. Text matching is deliberately absent: a rule that fires on a string
//! inside a comment produces a claim the evidence does not support.

pub mod discovery;
pub mod engine;
pub mod language;
pub mod parser;
pub mod rules;

pub use discovery::{discover, DiscoveredFile, Discovery, DiscoveryOptions, SkippedFile};
pub use language::Language;
pub use parser::{parse, parse_as, ParseFailure, ParsedFile};
pub use rules::{compile, load_directory, load_embedded, CompiledRules, RuleFile, RuleSource};
