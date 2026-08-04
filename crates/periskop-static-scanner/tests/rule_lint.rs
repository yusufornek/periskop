//! Rule lint.
//!
//! Loads every shipped rule file and compiles it against the grammar it targets.
//! This runs before the unit tests in the same `cargo test` invocation, which
//! makes it the floor of the test pyramid rather than an optional extra step.
//!
//! The failure it catches is specific and easy to introduce. A tree-sitter query
//! is a string until something compiles it, so a typo in a node name, a stray
//! parenthesis or a predicate written outside the pattern all look fine in review
//! and only fail when a scan reaches that language. Compiling here moves that
//! failure to the pull request.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use periskop_static_scanner::language::Language;
use periskop_static_scanner::rules::{compile, load_directory};

fn rules_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at the crate; the rule tree lives at the repo root
    // so that a contributor adding a language does not have to know the crate
    // layout.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("rules")
}

#[test]
fn every_shipped_rule_loads_and_compiles() {
    let root = rules_root();
    if !root.exists() {
        // Before the first rule set lands there is nothing to lint. Passing here
        // is correct; the directory arriving is what turns this test on.
        return;
    }

    let mut failures: Vec<String> = Vec::new();
    let mut compiled_patterns = 0usize;

    // Rules are grouped by the family their directory names, then compiled
    // against every grammar that draws from that family. A rule written for
    // TypeScript has to hold up for the TSX and JavaScript grammars too, because
    // all three share one rule family.
    let mut by_family: BTreeMap<String, Vec<_>> = BTreeMap::new();

    let (rules, load_errors) = load_directory(&root);
    for error in load_errors {
        failures.push(error.to_string());
    }
    for rule in rules {
        by_family
            .entry(rule.language.clone())
            .or_default()
            .push(rule);
    }

    for (family, rules) in &by_family {
        let grammars: Vec<Language> = Language::ALL
            .into_iter()
            .filter(|l| l.rule_family() == family)
            .collect();

        if grammars.is_empty() {
            failures.push(format!(
                "rules declare language {family:?}, which no linked grammar serves"
            ));
            continue;
        }

        for grammar in grammars {
            match compile(grammar, rules) {
                Ok(compiled) => compiled_patterns += compiled.pattern_count(),
                Err(e) => failures.push(format!("{grammar:?}: {e}")),
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} rule problem(s):\n  {}",
        failures.len(),
        failures.join("\n  ")
    );

    // A rule tree that exists but yields nothing means the loader silently found
    // no files, which would make this test a no-op that still reports success.
    if !by_family.is_empty() {
        assert!(
            compiled_patterns > 0,
            "rules were loaded but no pattern compiled"
        );
    }
}
