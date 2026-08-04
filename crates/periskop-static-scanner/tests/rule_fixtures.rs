#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! Each rule family is exercised against real source.
//!
//! Compiling a query proves it is syntactically valid. It does not prove the query
//! describes the code anyone actually writes, and a rule that compiles but never
//! matches is worse than no rule: it reads as coverage while providing none.
//!
//! Every positive fixture must produce at least one match. Negative fixtures are
//! handled with more care: at this layer a rule that relies on a binding is only a
//! pre-filter, so over-matching there is expected and the test says so explicitly
//! rather than being loosened until it passes.
//!
//! Evasion fixtures are real egress the scanner cannot see. They are expected to
//! match nothing, and the value of keeping them is that the limit stays written
//! down where a reader will find it.

use std::path::{Path, PathBuf};

use periskop_static_scanner::language::Language;
use periskop_static_scanner::parser::parse_as;
use periskop_static_scanner::rules::{compile, load_directory, CompiledRules};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture_dir(language: &str, group: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(language)
        .join(group)
}

fn python_rules() -> CompiledRules {
    let (rules, errors) = load_directory(&repo_root().join("rules"));
    assert!(errors.is_empty(), "rule load failed: {errors:?}");
    let python: Vec<_> = rules
        .into_iter()
        .filter(|r| r.language == "python")
        .collect();
    assert!(!python.is_empty(), "no python rules found");
    match compile(Language::Python, &python) {
        Ok(compiled) => compiled,
        Err(e) => panic!("python rules did not compile: {e}"),
    }
}

/// Rule identifiers that matched, one entry per distinct rule.
fn matching_rules(compiled: &CompiledRules, source: &str) -> Vec<String> {
    let parsed = match parse_as("fixture.py", source, Language::Python) {
        Ok(parsed) => parsed,
        Err(e) => panic!("fixture did not parse: {e}"),
    };

    let mut cursor = tree_sitter::QueryCursor::new();
    let mut hits: Vec<String> = Vec::new();

    let mut matches = cursor.matches(
        compiled.query(),
        parsed.root_node(),
        parsed.source().as_bytes(),
    );
    while let Some(m) = streaming_next(&mut matches) {
        if let Some(origin) = compiled.origin(m.pattern_index) {
            if !hits.contains(&origin.rule_id) {
                hits.push(origin.rule_id.clone());
            }
        }
    }
    hits.sort();
    hits
}

/// tree-sitter 0.25 returns a streaming iterator rather than a plain one.
fn streaming_next<
    't,
    T: streaming_iterator::StreamingIterator<Item = tree_sitter::QueryMatch<'t, 't>>,
>(
    it: &mut T,
) -> Option<&tree_sitter::QueryMatch<'t, 't>> {
    it.next()
}

fn read_fixtures(group: &str) -> Vec<(String, String)> {
    let dir = fixture_dir("python", group);
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) => panic!("cannot read {}: {e}", dir.display()),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "py") {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<unnamed>")
                .to_owned();
            match std::fs::read_to_string(&path) {
                Ok(text) => out.push((name, text)),
                Err(e) => panic!("cannot read {}: {e}", path.display()),
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(!out.is_empty(), "no fixtures under {}", dir.display());
    out
}

#[test]
fn every_positive_fixture_matches_a_rule() {
    let compiled = python_rules();
    for (name, source) in read_fixtures("positive") {
        let hits = matching_rules(&compiled, &source);
        assert!(
            !hits.is_empty(),
            "{name} is a positive fixture but matched no rule"
        );
    }
}

#[test]
fn a_query_alone_does_not_decide_a_finding() {
    // Worth stating plainly, because the result looks like a failure and is not.
    //
    // A rule with a binding constraint deliberately keeps its query broad. The
    // query asks "is this a call to a method with this name", and a great many
    // unrelated objects have a method called create. What narrows it is the
    // binding: the receiver has to resolve to a symbol the file imported from the
    // provider package.
    //
    // Bindings are applied by the detector engine, not by tree-sitter. So at this
    // layer a bound rule is a pre-filter and is expected to over-match. Asserting
    // otherwise here would either be wrong or would push the constraint into the
    // query, where it cannot follow an import.
    //
    // The real negative assertion, with bindings applied, belongs to the engine.
    let compiled = python_rules();
    let unbound_over_matches: Vec<(String, Vec<String>)> = read_fixtures("negative")
        .into_iter()
        .map(|(name, source)| (name, matching_rules(&compiled, &source)))
        .filter(|(_, hits)| !hits.is_empty())
        .collect();

    for (name, hits) in &unbound_over_matches {
        for rule_id in hits {
            assert!(
                rule_is_bound(rule_id),
                "{name} matched {rule_id}, which has no binding constraint to \
                 narrow it later. An unbound rule that fires on a negative \
                 fixture is a false positive with nothing left to catch it."
            );
        }
    }
}

/// Whether a rule leans on a binding constraint to reach its final verdict.
fn rule_is_bound(rule_id: &str) -> bool {
    let (rules, _) = load_directory(&repo_root().join("rules"));
    rules
        .iter()
        .find(|r| r.rule_id == rule_id)
        .is_some_and(|r| r.matches.iter().any(|m| m.binding.is_some()))
}

#[test]
fn evasion_fixtures_document_what_is_not_seen() {
    // These are real egress calls. The scanner does not see them, and the test
    // records that rather than hiding it. If one of them ever starts matching,
    // this failing test is the prompt to move it out of the gap catalogue.
    let compiled = python_rules();
    for (name, source) in read_fixtures("evasion") {
        let hits = matching_rules(&compiled, &source);
        assert!(
            hits.is_empty(),
            "{name} now matches {hits:?}; the known gap entry needs updating"
        );
    }
}

#[test]
fn each_rule_family_is_covered_by_a_fixture() {
    // Guards against a rule set growing past its fixtures. A rule with nothing
    // exercising it can rot into a pattern that no longer matches anything, and
    // nothing would report that.
    let compiled = python_rules();
    let mut covered: Vec<String> = Vec::new();
    for (_, source) in read_fixtures("positive") {
        for rule_id in matching_rules(&compiled, &source) {
            if !covered.contains(&rule_id) {
                covered.push(rule_id);
            }
        }
    }

    let mut declared: Vec<String> = (0..compiled.pattern_count())
        .filter_map(|i| compiled.origin(i).map(|o| o.rule_id.clone()))
        .collect();
    declared.sort();
    declared.dedup();

    let uncovered: Vec<_> = declared
        .iter()
        .filter(|id| !covered.contains(id))
        .cloned()
        .collect();

    assert!(
        uncovered.is_empty(),
        "these rules have no positive fixture: {uncovered:?}"
    );
}
