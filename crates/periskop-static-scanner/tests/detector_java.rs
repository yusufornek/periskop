#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! The Java rule set, exercised against the Java fixtures.
//!
//! What this suite can assert is bounded by where the engine stands. `detect`
//! hands Java files an empty binding table until it learns about
//! `engine::bindings_java`, so every rule that leans on a binding is still a
//! query level pre-filter here. Asserting a confirmed finding for one of those
//! would be asserting something the engine does not do yet.
//!
//! So the suite is split along that line, and each half is checked at the layer
//! where it is real. The rule that keys on a destination carries no binding and
//! is checked end to end, findings and all. The rules that key on a client are
//! checked in two pieces: the pattern matches its fixture, and the resolution the
//! finding depends on is asserted against the collector directly.

use std::path::{Path, PathBuf};

use periskop_core::finding::Confidence;
use periskop_static_scanner::engine::bindings_java;
use periskop_static_scanner::engine::detect;
use periskop_static_scanner::language::Language;
use periskop_static_scanner::parser::parse_as;
use periskop_static_scanner::rules::{compile, load_directory, CompiledRules, RuleFile};
use streaming_iterator::StreamingIterator;

// The Java resolver is not wired into the library yet: `engine/mod.rs` does not
// declare it, so nothing compiles it and nothing runs the tests it carries.
// Including it here compiles it against the real binding table and runs those
// tests now rather than after the wiring lands. The three modules below exist
// only to supply the paths the file expects from inside the library.
//
// Delete this block and the include under it once `engine/mod.rs` declares
// `pub mod bindings_java;`.

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn java_rules() -> Vec<RuleFile> {
    let (rules, errors) = load_directory(&repo_root().join("rules"));
    assert!(errors.is_empty(), "rule load failed: {errors:?}");
    let java: Vec<RuleFile> = rules.into_iter().filter(|r| r.language == "java").collect();
    assert!(!java.is_empty(), "no java rules found");
    java
}

/// The rule set compiled against the Java grammar.
///
/// A query is a string until something compiles it, so this is also where a node
/// name that does not exist in the Java grammar stops being a silent no-op.
fn compiled_rules() -> (CompiledRules, Vec<RuleFile>) {
    let rules = java_rules();
    match compile(Language::Java, &rules) {
        Ok(compiled) => (compiled, rules),
        Err(e) => panic!("java rules did not compile: {e}"),
    }
}

/// Rule identifiers whose pattern matched, before any binding narrows them.
fn matching_rules(source: &str, name: &str) -> Vec<String> {
    let (compiled, _) = compiled_rules();
    let parsed = match parse_as(name, source, Language::Java) {
        Ok(parsed) => parsed,
        Err(e) => panic!("{name} did not parse: {e}"),
    };

    let mut cursor = tree_sitter::QueryCursor::new();
    let mut matches = cursor.matches(
        compiled.query(),
        parsed.root_node(),
        parsed.source().as_bytes(),
    );

    let mut hits: Vec<String> = Vec::new();
    while let Some(m) = matches.next() {
        if let Some(origin) = compiled.origin(m.pattern_index) {
            if !hits.contains(&origin.rule_id) {
                hits.push(origin.rule_id.clone());
            }
        }
    }
    hits.sort();
    hits
}

/// Findings the engine produces as it stands today.
fn findings(source: &str, name: &str) -> Vec<(String, Confidence)> {
    let (compiled, rules) = compiled_rules();
    let parsed = match parse_as(name, source, Language::Java) {
        Ok(parsed) => parsed,
        Err(e) => panic!("{name} did not parse: {e}"),
    };
    detect(&parsed, &compiled, &rules)
        .findings
        .into_iter()
        .map(|f| (f.detector.rule_id, f.confidence))
        .collect()
}

fn fixture_dir(group: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/java")
        .join(group)
}

fn fixtures(group: &str) -> Vec<(String, String)> {
    let dir = fixture_dir(group);
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("fixture dir").flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "java") {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            out.push((name, std::fs::read_to_string(&path).expect("fixture")));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(!out.is_empty(), "no fixtures under {}", dir.display());
    out
}

fn fixture(group: &str, name: &str) -> String {
    std::fs::read_to_string(fixture_dir(group).join(name)).expect("fixture")
}

#[test]
fn every_positive_fixture_matches_a_rule() {
    for (name, source) in fixtures("positive") {
        let hits = matching_rules(&source, &name);
        assert!(
            !hits.is_empty(),
            "{name} is a positive fixture but matched no rule"
        );
    }
}

#[test]
fn each_rule_is_covered_by_a_positive_fixture() {
    // Guards against a rule set growing past its fixtures. A rule with nothing
    // exercising it can rot into a pattern that no longer matches anything, and
    // nothing else would report that.
    let (compiled, _) = compiled_rules();
    let mut covered: Vec<String> = Vec::new();
    for (name, source) in fixtures("positive") {
        for rule_id in matching_rules(&source, &name) {
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

    let uncovered: Vec<String> = declared
        .into_iter()
        .filter(|id| !covered.contains(id))
        .collect();
    assert!(
        uncovered.is_empty(),
        "these rules have no positive fixture: {uncovered:?}"
    );
}

#[test]
fn negative_fixtures_only_match_rules_a_binding_narrows() {
    // Worth stating plainly, because a match here looks like a failure and is
    // not. A bound rule keeps its query broad on purpose: `create` is a method
    // name half the classes in a Java codebase have, and what narrows it is the
    // receiver resolving into a provider package. Bindings are applied by the
    // engine, not by tree-sitter, so over-matching at this layer is expected.
    //
    // An unbound rule has nothing left to catch it, so a match from one of those
    // on a negative fixture is a false positive with no second chance.
    let rules = java_rules();
    let bound: Vec<&str> = rules
        .iter()
        .filter(|r| r.matches.iter().any(|m| m.binding.is_some()))
        .map(|r| r.rule_id.as_str())
        .collect();

    for (name, source) in fixtures("negative") {
        for rule_id in matching_rules(&source, &name) {
            assert!(
                bound.contains(&rule_id.as_str()),
                "{name} matched {rule_id}, which has no binding constraint to \
                 narrow it later"
            );
        }
    }
}

#[test]
fn evasion_fixtures_match_nothing_and_that_is_recorded() {
    // These are real egress calls. The scanner does not see them, and the test
    // records that rather than hiding it. If one of them ever starts matching,
    // this failing test is the prompt to move it out of the gap catalogue.
    for (name, source) in fixtures("evasion") {
        let hits = matching_rules(&source, &name);
        assert!(
            hits.is_empty(),
            "{name} is catalogued as a gap but matched {hits:?}; \
             the catalogue entry needs updating"
        );
    }
}

#[test]
fn a_literal_provider_endpoint_produces_a_confirmed_finding() {
    // The one rule family that is complete end to end today: it keys on the
    // destination, so it needs no binding and no resolver.
    let source = fixture("positive", "HttpLiteralEndpoint.java");
    let hits = findings(&source, "HttpLiteralEndpoint.java");
    assert!(
        hits.iter().any(
            |(rule_id, confidence)| rule_id == "java.static.http-provider-endpoint"
                && *confidence == Confidence::Confirmed
        ),
        "expected a confirmed finding, got {hits:?}"
    );
}

#[test]
fn an_internal_endpoint_produces_nothing() {
    let source = fixture("negative", "InternalServiceCall.java");
    assert!(findings(&source, "InternalServiceCall.java").is_empty());
}

#[test]
fn renaming_a_local_does_not_change_the_finding_identity() {
    // The diff invariant. An identity built from what a call is stays put when
    // the names around it move.
    let (compiled, rules) = compiled_rules();
    let ids = |src: &str| {
        let parsed = parse_as("A.java", src, Language::Java).unwrap();
        let mut ids: Vec<String> = detect(&parsed, &compiled, &rules)
            .findings
            .into_iter()
            .map(|f| f.finding_id)
            .collect();
        ids.sort();
        ids
    };

    let original = ids(
        "class A {\n  void f() {\n    HttpRequest request = HttpRequest.newBuilder()\n      .uri(URI.create(\"https://api.openai.com/v1/chat/completions\")).build();\n  }\n}\n",
    );
    let renamed = ids(
        "class A {\n  void f() {\n    HttpRequest call = HttpRequest.newBuilder()\n      .uri(URI.create(\"https://api.openai.com/v1/chat/completions\")).build();\n  }\n}\n",
    );

    assert!(!original.is_empty());
    assert_eq!(original, renamed);
}

#[test]
fn scanning_the_same_source_twice_gives_the_same_result() {
    let source = fixture("positive", "HttpLiteralEndpoint.java");
    assert_eq!(
        findings(&source, "HttpLiteralEndpoint.java"),
        findings(&source, "HttpLiteralEndpoint.java")
    );
}

#[test]
fn the_client_in_each_positive_fixture_resolves_to_its_package() {
    // The half of the verdict the engine cannot reach yet, asserted against the
    // collector directly. Without it a positive fixture would only prove that a
    // pattern matched, which is the weaker half of a detection.
    let cases = [
        (
            "OpenAiClientCall.java",
            "client",
            "com.openai",
            "OpenAIClient",
        ),
        (
            "AnthropicMessagesCall.java",
            "client",
            "com.anthropic",
            "AnthropicClient",
        ),
        (
            "Langchain4jChatCall.java",
            "model",
            "dev.langchain4j",
            "ChatModel",
        ),
        (
            "WildcardImportClient.java",
            "client",
            "com.openai",
            "OpenAIClient",
        ),
    ];

    for (name, local, module, symbol) in cases {
        let source = fixture("positive", name);
        let parsed = parse_as(name, source.as_str(), Language::Java).unwrap();
        let table = bindings_java::collect(parsed.root_node(), parsed.source());
        assert!(
            table.satisfies(local, module, &[symbol.to_owned()]),
            "{name}: {local} resolved to {:?}, not into {module}",
            table.resolve(local)
        );
    }
}

#[test]
fn a_client_from_a_lookalike_package_does_not_resolve() {
    // The negative the query layer cannot make. `com.openaimock` starts with the
    // characters of `com.openai`, and only a segment aware comparison rejects it.
    let source = fixture("negative", "LookalikePackage.java");
    let parsed = parse_as("LookalikePackage.java", source.as_str(), Language::Java).unwrap();
    let table = bindings_java::collect(parsed.root_node(), parsed.source());

    assert_eq!(
        table.resolve("client"),
        Some("com.openaimock.client.OpenAIClient")
    );
    assert!(!table.satisfies("client", "com.openai", &["OpenAIClient".to_owned()]));
}

#[test]
fn a_local_class_leaves_its_receiver_unresolved() {
    let source = fixture("negative", "LocalCreateMethod.java");
    let parsed = parse_as("LocalCreateMethod.java", source.as_str(), Language::Java).unwrap();
    let table = bindings_java::collect(parsed.root_node(), parsed.source());
    assert!(!table.satisfies("store", "com.openai", &["OpenAIClient".to_owned()]));
}
