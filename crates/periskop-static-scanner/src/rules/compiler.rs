//! Compiling a language's rules into one query.
//!
//! tree-sitter can hold many patterns in a single query and report which pattern
//! matched. Compiling per rule and running each query over every file would walk
//! the tree once per rule; compiling once and walking once is the difference
//! between linear and quadratic behaviour as the rule set grows.
//!
//! The compile step is also where a broken query is caught. A query that does not
//! compile is a defect in a file someone wrote, so the error names that file and
//! the rule rather than reporting a generic engine failure.

use crate::language::Language;
use crate::rules::model::{MatchKind, RuleFile};

/// Where a pattern in the combined query came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternOrigin {
    pub rule_id: String,
    pub provider: String,
    pub match_index: usize,
    pub kind: MatchKind,
}

/// All rules for one language, compiled into a single multi-pattern query.
#[derive(Debug)]
pub struct CompiledRules {
    language: Language,
    query: tree_sitter::Query,
    /// Indexed by tree-sitter pattern index, so a match can be traced back to the
    /// rule that produced it.
    origins: Vec<PatternOrigin>,
}

impl CompiledRules {
    pub fn language(&self) -> Language {
        self.language
    }

    pub fn query(&self) -> &tree_sitter::Query {
        &self.query
    }

    pub fn pattern_count(&self) -> usize {
        self.origins.len()
    }

    pub fn origin(&self, pattern_index: usize) -> Option<&PatternOrigin> {
        self.origins.get(pattern_index)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    /// A query that will not compile. Named with the rule so the fix is obvious.
    #[error("rule {rule_id}, match {match_index}: query did not compile: {detail}")]
    Query {
        rule_id: String,
        match_index: usize,
        detail: String,
    },

    /// A capture the rule refers to does not exist in its own query. This passes
    /// query compilation and then silently never matches, so it is checked here.
    #[error("rule {rule_id}, match {match_index}: query has no capture named @{capture}")]
    MissingCapture {
        rule_id: String,
        match_index: usize,
        capture: String,
    },
}

/// Rule id used when the failure belongs to the joined query rather than a rule.
const COMBINED: &str = "<combined>";

/// The result of compiling a rule family without stopping at the first defect.
///
/// Both halves matter. The patterns that did compile are what the scan can still
/// run; the errors are what the report has to declare. Returning only one of them
/// is how a broken rule turns into a clean looking result.
#[derive(Debug)]
pub struct PartialCompile {
    /// The patterns that compiled, or `None` when the joined query itself failed.
    /// `None` always arrives with at least one error.
    pub compiled: Option<CompiledRules>,
    /// Every rule that did not compile, in rule order.
    pub errors: Vec<CompileError>,
}

/// Compiles every rule for one language, keeping going past a broken rule.
///
/// One malformed query used to disable the whole family, because compilation
/// stopped at the first error. A family of five rules where one no longer
/// compiles is still four working detectors, and running four declared detectors
/// is better than running none silently. The caller is expected to report the
/// errors; the scan must not present a partial rule set as a complete one.
pub fn compile_partial(language: Language, rules: &[RuleFile]) -> PartialCompile {
    let grammar = language.grammar();
    let mut sources = Vec::new();
    let mut origins = Vec::new();
    let mut errors = Vec::new();

    for rule in rules {
        for (match_index, spec) in rule.matches.iter().enumerate() {
            // Compiling each pattern on its own first means the error points at
            // one rule. A combined query would only report an offset into a blob
            // of concatenated text, which no contributor can act on.
            let single = match tree_sitter::Query::new(&grammar, &spec.query) {
                Ok(single) => single,
                Err(e) => {
                    errors.push(CompileError::Query {
                        rule_id: rule.rule_id.clone(),
                        match_index,
                        detail: e.to_string(),
                    });
                    continue;
                }
            };

            let capture_names = single.capture_names();
            let missing = |name: &str| -> Option<CompileError> {
                if capture_names.contains(&name) {
                    None
                } else {
                    Some(CompileError::MissingCapture {
                        rule_id: rule.rule_id.clone(),
                        match_index,
                        capture: name.to_owned(),
                    })
                }
            };
            let mut absent = Vec::new();
            if let Some(binding) = &spec.binding {
                absent.extend(missing(&binding.capture));
            }
            if let Some(method) = &spec.method {
                absent.extend(missing(&method.capture));
            }
            if !absent.is_empty() {
                errors.append(&mut absent);
                continue;
            }

            sources.push(spec.query.clone());
            origins.push(PatternOrigin {
                rule_id: rule.rule_id.clone(),
                provider: rule.provider.clone(),
                match_index,
                kind: spec.kind,
            });
        }
    }

    let combined = sources.join("\n");
    match tree_sitter::Query::new(&grammar, &combined) {
        Ok(query) => PartialCompile {
            compiled: Some(CompiledRules {
                language,
                query,
                origins,
            }),
            errors,
        },
        Err(e) => {
            errors.push(CompileError::Query {
                rule_id: COMBINED.to_owned(),
                match_index: 0,
                detail: e.to_string(),
            });
            PartialCompile {
                compiled: None,
                errors,
            }
        }
    }
}

/// Compiles every rule for one language into a single query, all or nothing.
///
/// Kept for callers that want a rule set only when it is whole, such as the rule
/// lint, where any defect has to fail the build. A scan uses [`compile_partial`]
/// instead, because dropping four working detectors over one broken rule is a
/// loss of coverage nobody asked for.
pub fn compile(language: Language, rules: &[RuleFile]) -> Result<CompiledRules, CompileError> {
    let outcome = compile_partial(language, rules);
    match outcome.errors.into_iter().next() {
        // The first error is the one to fix first. Callers that need the whole
        // list call compile_partial.
        Some(first) => Err(first),
        None => outcome.compiled.ok_or(CompileError::Query {
            rule_id: COMBINED.to_owned(),
            match_index: 0,
            detail: "the rule set produced no query".to_owned(),
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::rules::loader::parse_rule;
    use std::path::Path;

    fn rule(rule_name: &str, query: &str, extra: &str) -> RuleFile {
        let text = format!(
            r#"
schema_version = "1.0"
language = "python"
provider = "openai"
rule_id = "python.static.{rule_name}"
rule_version = "1.0.0"

[[match]]
kind = "call"
query = '''{query}'''
{extra}

[classify]
egress_kind = "llm_chat"
default_confidence = "confirmed"
"#
        );
        parse_rule(Path::new("rules/python/test.toml"), &text).unwrap()
    }

    #[test]
    fn combines_patterns_and_keeps_their_origin() {
        let rules = vec![
            rule("first", "(call) @call", ""),
            rule("second", "(import_statement) @import", ""),
        ];
        let compiled = compile(Language::Python, &rules).unwrap();

        assert_eq!(compiled.pattern_count(), 2);
        assert_eq!(compiled.query().pattern_count(), 2);
        assert_eq!(compiled.origin(0).unwrap().rule_id, "python.static.first");
        assert_eq!(compiled.origin(1).unwrap().rule_id, "python.static.second");
    }

    #[test]
    fn a_broken_query_names_the_rule_that_owns_it() {
        // The acceptance criterion for the lint step: the message has to lead a
        // contributor to one file, not to the engine.
        let rules = vec![rule("broken", "(this_node_does_not_exist) @x", "")];
        let err = compile(Language::Python, &rules).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("python.static.broken"), "{rendered}");
    }

    #[test]
    fn a_capture_the_rule_relies_on_must_exist() {
        // The query compiles, but the binding points at a capture that is not in
        // it. Without this check the rule would load, compile and never fire.
        let rules = vec![rule(
            "mismatched",
            "(call) @call",
            "[match.binding]\ncapture = \"recv\"\nresolves_to = { module = \"openai\" }",
        )];
        let err = compile(Language::Python, &rules).unwrap_err();
        assert!(err.to_string().contains("recv"), "{err}");
    }

    #[test]
    fn empty_rule_set_compiles_to_an_empty_query() {
        let compiled = compile(Language::Python, &[]).unwrap();
        assert_eq!(compiled.pattern_count(), 0);
    }

    #[test]
    fn one_broken_rule_does_not_disable_the_rest_of_the_family() {
        // The error class this test catches: a single unusable query silently
        // taking every other detector for that language with it, so the scan runs
        // with no rules and reports nothing rather than reporting less.
        let rules = vec![
            rule("good", "(call) @call", ""),
            rule("broken", "(this_node_does_not_exist) @x", ""),
            rule("also-good", "(import_statement) @import", ""),
        ];
        let outcome = compile_partial(Language::Python, &rules);

        let compiled = outcome.compiled.unwrap();
        assert_eq!(compiled.pattern_count(), 2);
        assert_eq!(outcome.errors.len(), 1);
        assert!(
            outcome.errors[0]
                .to_string()
                .contains("python.static.broken"),
            "{}",
            outcome.errors[0]
        );
    }

    #[test]
    fn every_broken_rule_is_reported_not_only_the_first() {
        // Stopping at the first error hides the rest until the contributor fixes
        // one and runs again, which turns one round of feedback into several.
        let rules = vec![
            rule("first-broken", "(no_such_node) @x", ""),
            rule("second-broken", "(also_no_such_node) @y", ""),
        ];
        let outcome = compile_partial(Language::Python, &rules);
        assert_eq!(outcome.errors.len(), 2, "{:?}", outcome.errors);
        assert_eq!(outcome.compiled.unwrap().pattern_count(), 0);
    }

    #[test]
    fn each_language_compiles_against_its_own_grammar() {
        // A query valid for Python is not automatically valid for TypeScript.
        // Compiling per language is what keeps that mistake from reaching a scan.
        let python_only = vec![rule("py", "(import_from_statement) @i", "")];
        assert!(compile(Language::Python, &python_only).is_ok());
        assert!(compile(Language::TypeScript, &python_only).is_err());
    }
}
