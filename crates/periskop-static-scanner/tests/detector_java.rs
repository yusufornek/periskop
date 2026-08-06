#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! End to end detection over the Java fixtures.
//!
//! This suite used to stop one layer short, and the gap it left cost a phase.
//! `detect` was not resolving Java receivers, so the bound rules were checked in
//! two pieces here instead: the pattern was asserted to match its fixture, and
//! the resolution was asserted against `bindings_java::collect` directly. Both
//! halves passed. The path between them did not exist, three of the five
//! positive fixtures produced no finding at all, and nothing in this file was
//! looking at the thing a user actually gets (defect AK-001).
//!
//! So every claim below now travels through `detect`. The unit level assertions
//! are kept, because a chain of two green tests either side of a broken join is
//! only misleading when nobody checks the join; once the join is checked, the
//! narrower tests are what say which half broke.

use std::path::{Path, PathBuf};

use periskop_core::finding::Confidence;
use periskop_static_scanner::engine::bindings_java;
use periskop_static_scanner::engine::{detect, FileFindings};
use periskop_static_scanner::language::Language;
use periskop_static_scanner::parser::parse_as;
use periskop_static_scanner::rules::{compile, load_directory, CompiledRules, RuleFile};
use streaming_iterator::StreamingIterator;

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

/// Everything one scan of one file produced: findings, coverage and faults.
fn scan(source: &str, name: &str) -> FileFindings {
    let (compiled, rules) = compiled_rules();
    let parsed = match parse_as(name, source, Language::Java) {
        Ok(parsed) => parsed,
        Err(e) => panic!("{name} did not parse: {e}"),
    };
    detect(&parsed, &compiled, &rules)
}

/// Findings the engine produces, reduced to the pair each assertion needs.
fn findings(source: &str, name: &str) -> Vec<(String, Confidence)> {
    scan(source, name)
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

/// The confidence each positive fixture is expected to come back with.
///
/// Named per fixture rather than asserted in bulk, because they do not agree. A
/// rule whose distinguishing condition is a regular expression over the text of a
/// URL cannot claim a structural fact, so it reports `suspect` by design.
/// Loosening the assertion to "some finding exists" would let that pass and would
/// stop watching the fixtures that must stay confirmed.
const EXPECTED_CONFIDENCE: &[(&str, Confidence)] = &[
    ("AnthropicMessagesCall.java", Confidence::Confirmed),
    ("HttpLiteralEndpoint.java", Confidence::Suspect),
    ("Langchain4jChatCall.java", Confidence::Confirmed),
    ("OpenAiClientCall.java", Confidence::Confirmed),
    ("WildcardImportClient.java", Confidence::Confirmed),
];

#[test]
fn every_fixture_parses_cleanly() {
    // Without this the negative and evasion assertions could pass for the wrong
    // reason: a fixture with a syntax error parses into error nodes, matches
    // nothing, and looks exactly like a correctly rejected file.
    for group in ["positive", "negative", "evasion"] {
        for (name, source) in fixtures(group) {
            let parsed = match parse_as(&name, source, Language::Java) {
                Ok(p) => p,
                Err(e) => panic!("{name} did not parse: {e}"),
            };
            assert!(
                !parsed.is_partial(),
                "{name} has {} unparsed region(s)",
                parsed.error_node_count()
            );
        }
    }
}

#[test]
fn every_positive_fixture_produces_the_confidence_it_is_listed_with() {
    // The assertion AK-001 would have failed. Three of these five fixtures came
    // back empty while every other test in this file was green.
    for (name, source) in fixtures("positive") {
        let hits = findings(&source, &name);
        assert!(!hits.is_empty(), "{name} produced no finding");
        let Some((_, expected)) = EXPECTED_CONFIDENCE.iter().find(|(f, _)| *f == name) else {
            panic!(
                "{name} is a positive fixture with no entry in EXPECTED_CONFIDENCE; \
                 a new fixture states what it expects rather than inheriting it"
            );
        };
        let unexpected: Vec<&(String, Confidence)> =
            hits.iter().filter(|(_, c)| c != expected).collect();
        assert!(
            unexpected.is_empty(),
            "{name} is listed as {expected:?} but also produced {unexpected:?}"
        );
    }
}

#[test]
fn every_listed_fixture_still_exists() {
    // Stops the table above from outliving the files it describes, which would
    // leave a fixture silently unasserted.
    let present: Vec<String> = fixtures("positive").into_iter().map(|(n, _)| n).collect();
    let missing: Vec<&str> = EXPECTED_CONFIDENCE
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| !present.iter().any(|p| p == name))
        .collect();
    assert!(missing.is_empty(), "listed but absent: {missing:?}");
}

#[test]
fn every_java_rule_has_a_positive_fixture_that_reaches_a_finding() {
    // Coverage measured in findings rather than in query matches. The weaker
    // version of this test passed throughout the AK-001 period, because a rule
    // whose pattern matches and whose match is then dropped looks covered.
    let rules = java_rules();
    let mut fired: Vec<String> = Vec::new();
    for (name, source) in fixtures("positive") {
        for (rule_id, _) in findings(&source, &name) {
            if !fired.contains(&rule_id) {
                fired.push(rule_id);
            }
        }
    }

    let uncovered: Vec<&str> = rules
        .iter()
        .map(|r| r.rule_id.as_str())
        .filter(|id| !fired.iter().any(|f| f == id))
        .collect();
    assert!(
        uncovered.is_empty(),
        "these java rules produce no finding on any positive fixture: {uncovered:?}"
    );
}

#[test]
fn a_chained_receiver_resolves_end_to_end() {
    // The regression test for AK-001 itself, written against the shape that
    // broke rather than against a fixture that happens to contain it.
    // `client.chat().completions().create(params)` reaches `root_identifier` as a
    // `method_invocation`, which used to fall through to `None`.
    let source = "import com.openai.client.OpenAIClient;\n\
                  class T {\n  private final OpenAIClient client = null;\n\
                  \n  Object f(Object params) {\n    \
                  return client.chat().completions().create(params);\n  }\n}\n";
    let result = scan(source, "T.java");
    let ids: Vec<&str> = result
        .findings
        .iter()
        .map(|f| f.detector.rule_id.as_str())
        .collect();
    assert!(
        ids.contains(&"java.static.openai-client-call"),
        "a chained receiver produced {ids:?}"
    );
}

#[test]
fn negative_fixtures_produce_nothing() {
    // The check the query layer cannot make. A local type with a `create` method
    // matches the pattern and is dropped here, because its receiver does not
    // resolve into any provider package.
    for (name, source) in fixtures("negative") {
        let hits = findings(&source, &name);
        assert!(hits.is_empty(), "{name} produced {hits:?}");
    }
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
fn evasion_fixtures_produce_nothing_and_that_is_recorded() {
    // These are real egress calls. The scanner does not see them, and the test
    // records that rather than hiding it. If one of them ever starts producing a
    // finding, this failing test is the prompt to move it out of the catalogue.
    for (name, source) in fixtures("evasion") {
        let hits = findings(&source, &name);
        assert!(
            hits.is_empty(),
            "{name} is catalogued as a gap but produced {hits:?}; \
             the catalogue entry needs updating"
        );
    }
}

#[test]
fn a_receiver_the_engine_cannot_resolve_reaches_the_diagnostics() {
    // The property AK-001 was actually about. Resolving Java receivers closed one
    // fixture family; the failure class stays open forever, because a receiver
    // shape no resolver walks will always exist. What must never happen again is
    // the engine dropping such a match without saying so.
    //
    // `client()` is a bare method call, so the chain bottoms out at a node with
    // no object and no type. The rule matched, the binding could not be checked,
    // and the only honest output is no finding plus a diagnostic naming the rule.
    let source = "class T {\n  Object f(Object params) {\n    \
                  return client().messages().create(params);\n  }\n}\n";
    let result = scan(source, "T.java");

    assert!(
        result.findings.is_empty(),
        "an unresolvable receiver must not become a finding: {:?}",
        result.findings
    );
    assert!(
        result.engine_faults.iter().any(|fault| {
            fault.contains("java.static.anthropic-messages-call")
                && fault.contains("dropped without being judged")
        }),
        "the dropped match left no trace: {:?}",
        result.engine_faults
    );
}

#[test]
fn every_engine_fault_over_the_corpus_is_one_this_suite_accounts_for() {
    // A diagnostics channel nobody reads is the same as no diagnostics channel,
    // so the corpus is scanned for faults and each one has to be a class this
    // file has looked at. The single class accounted for today is a declared
    // downgrade the engine cannot evaluate: `base_url` sits on the constructor,
    // and `constructor_arguments` indexes only the Python and TypeScript
    // vocabularies, so for Java it reports "not evaluable" rather than guessing.
    // That is a limitation stated out loud, not a dropped match.
    //
    // A fault of any other class fails here rather than sitting unread in a
    // report, which is what makes the previous test more than a one-off.
    for group in ["positive", "negative", "evasion"] {
        for (name, source) in fixtures(group) {
            for fault in scan(&source, &name).engine_faults {
                assert!(
                    fault.contains("downgrades on"),
                    "{name} produced an unaccounted engine fault: {fault:?}"
                );
            }
        }
    }
}

#[test]
fn a_literal_provider_endpoint_produces_a_suspected_finding() {
    // Suspect rather than confirmed. The call shape comes from the syntax tree,
    // but the claim that the destination belongs to a provider comes from
    // matching the text of a string literal, and a text match cannot support a
    // structural assertion.
    let source = fixture("positive", "HttpLiteralEndpoint.java");
    let hits = findings(&source, "HttpLiteralEndpoint.java");
    assert!(
        hits.iter().any(
            |(rule_id, confidence)| rule_id == "java.static.http-literal-endpoint"
                && *confidence == Confidence::Suspect
        ),
        "expected a suspected finding, got {hits:?}"
    );
}

#[test]
fn renaming_a_local_does_not_change_the_finding_identity() {
    // The diff invariant. An identity built from what a call is stays put when
    // the names around it move.
    let ids = |src: &str| {
        let mut ids: Vec<String> = scan(src, "A.java")
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
fn renaming_a_client_field_does_not_change_the_finding_identity() {
    // The same invariant on the path the fix opened, because that path is new and
    // an identity built from a receiver name would look correct until somebody
    // renamed a field.
    let ids = |receiver: &str| {
        let source = format!(
            "import com.openai.client.OpenAIClient;\n\
             class A {{\n  private final OpenAIClient {receiver} = null;\n\
             \n  Object f(Object params) {{\n    \
             return {receiver}.chat().completions().create(params);\n  }}\n}}\n"
        );
        let mut ids: Vec<String> = scan(&source, "A.java")
            .findings
            .into_iter()
            .map(|f| f.finding_id)
            .collect();
        ids.sort();
        ids
    };

    let original = ids("client");
    assert!(!original.is_empty());
    assert_eq!(original, ids("openAi"));
}

#[test]
fn scanning_the_same_source_twice_gives_the_same_result() {
    let source = fixture("positive", "OpenAiClientCall.java");
    assert_eq!(
        findings(&source, "OpenAiClientCall.java"),
        findings(&source, "OpenAiClientCall.java")
    );
}

#[test]
fn the_client_in_each_positive_fixture_resolves_to_its_package() {
    // Kept below the end to end assertions rather than instead of them. When one
    // of those goes red, this says whether the resolver or the engine around it
    // is the half that broke.
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

#[test]
fn an_unknown_import_is_reported_as_unclaimed() {
    // "We have no detector for this" and "there is nothing here" are different
    // statements, and only the first one is true.
    let source = "import com.acme.privatellm.PrivateClient;\n\
                  class T {\n  private final PrivateClient client = null;\n}\n";
    assert!(scan(source, "T.java")
        .unclaimed_imports
        .contains(&"com.acme.privatellm".to_owned()));
}
