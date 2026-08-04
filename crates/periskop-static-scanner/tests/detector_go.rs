#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! End to end detection over the Go fixtures.
//!
//! Same three obligations as the other languages: a positive fixture must yield a
//! confirmed finding, a negative one must yield nothing, and an evasion fixture
//! must yield nothing and is expected to.
//!
//! Go puts more weight on the last two than Python or TypeScript do. The package
//! name a call is written against is derived rather than read, so a resolver that
//! guessed loosely would turn any repository whose name ends in `-go` into a
//! provider SDK; and interface dispatch, which is ordinary Go style rather than an
//! evasion technique, is invisible here by construction.

use std::path::{Path, PathBuf};

use periskop_core::finding::Confidence;
use periskop_static_scanner::engine::{detect, FileFindings};
use periskop_static_scanner::language::Language;
use periskop_static_scanner::parser::parse_as;
use periskop_static_scanner::rules::{compile, load_directory, CompiledRules, RuleFile};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn go_rules() -> (CompiledRules, Vec<RuleFile>) {
    let (rules, errors) = load_directory(&repo_root().join("rules"));
    assert!(errors.is_empty(), "rule load failed: {errors:?}");
    let go: Vec<RuleFile> = rules.into_iter().filter(|r| r.language == "go").collect();
    assert!(!go.is_empty(), "no go rules found");
    let compiled = match compile(Language::Go, &go) {
        Ok(c) => c,
        Err(e) => panic!("rules did not compile: {e}"),
    };
    (compiled, go)
}

/// Everything one scan of one file produced: findings, coverage and faults.
fn scan_all(source: &str, name: &str) -> FileFindings {
    let (compiled, rules) = go_rules();
    let parsed = match parse_as(name, source, Language::Go) {
        Ok(p) => p,
        Err(e) => panic!("{name} did not parse: {e}"),
    };
    detect(&parsed, &compiled, &rules)
}

fn scan(source: &str, name: &str) -> Vec<(String, Confidence)> {
    scan_all(source, name)
        .findings
        .into_iter()
        .map(|f| (f.detector.rule_id, f.confidence))
        .collect()
}

fn fixtures(group: &str) -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/go")
        .join(group);
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("fixture dir").flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "go") {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            out.push((name, std::fs::read_to_string(&path).expect("fixture")));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(!out.is_empty(), "no fixtures under {}", dir.display());
    out
}

#[test]
fn every_fixture_parses_cleanly() {
    // Without this the negative and evasion assertions could pass for the wrong
    // reason: a fixture with a syntax error parses into error nodes, matches
    // nothing, and looks exactly like a correctly rejected file.
    for group in ["positive", "negative", "evasion"] {
        for (name, source) in fixtures(group) {
            let parsed = match parse_as(&name, source, Language::Go) {
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

/// The confidence each positive fixture is expected to come back with.
///
/// Named per fixture rather than asserted in bulk, because they no longer agree.
/// A rule whose distinguishing condition is a regular expression over the text of
/// a URL cannot claim a structural fact, so it reports `suspect` and its fixture
/// comes back weaker by design. Loosening the assertion to "some finding exists"
/// would let that pass and would stop watching the fixtures that must stay
/// confirmed, so both statements are kept.
const EXPECTED_CONFIDENCE: &[(&str, Confidence)] = &[
    ("http_literal_post.go", Confidence::Suspect),
    ("http_new_request.go", Confidence::Suspect),
    ("openai_go_chat.go", Confidence::Confirmed),
    ("openai_go_responses.go", Confidence::Confirmed),
    ("sashabaranov_chat.go", Confidence::Confirmed),
];

#[test]
fn every_positive_fixture_produces_the_confidence_it_is_listed_with() {
    for (name, source) in fixtures("positive") {
        let hits = scan(&source, &name);
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
fn every_go_rule_has_a_positive_fixture() {
    // A rule with nothing exercising it can rot into a pattern that no longer
    // matches anything, and nothing else in the suite would report that.
    let (_, rules) = go_rules();
    let mut fired: Vec<String> = Vec::new();
    for (name, source) in fixtures("positive") {
        for (rule_id, _) in scan(&source, &name) {
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
        "these go rules have no positive fixture: {uncovered:?}"
    );
}

#[test]
fn negative_fixtures_produce_nothing() {
    // The check the query layer could not make. A local type with a
    // CreateChatCompletion method matches the pattern and is dropped here,
    // because its receiver does not resolve to any provider module.
    for (name, source) in fixtures("negative") {
        let hits = scan(&source, &name);
        assert!(hits.is_empty(), "{name} produced {hits:?}");
    }
}

#[test]
fn evasion_fixtures_produce_nothing_and_that_is_recorded() {
    for (name, source) in fixtures("evasion") {
        let hits = scan(&source, &name);
        assert!(
            hits.is_empty(),
            "{name} is catalogued as a gap but produced {hits:?}; \
             the catalogue entry needs updating"
        );
    }
}

#[test]
fn a_client_from_a_lookalike_module_is_not_reported() {
    // The derived package name is `openai` for both paths, which is exactly why
    // the name cannot be the thing that decides.
    let source = "package main\n\nimport \"github.com/acme/openai-go\"\n\nfunc f(ctx, params any) {\n\tclient := openai.NewClient()\n\tclient.Chat.Completions.New(ctx, params)\n}\n";
    assert!(scan(source, "lookalike.go").is_empty());
}

#[test]
fn a_bare_http_post_to_an_internal_host_is_not_reported() {
    let source = "package main\n\nimport \"net/http\"\n\nfunc f(body any) {\n\thttp.Post(\"https://billing.internal.example/v1/enrich\", \"application/json\", body)\n}\n";
    assert!(scan(source, "internal.go").is_empty());
}

#[test]
fn an_aliased_standard_library_import_still_resolves() {
    // The receiver is resolved rather than compared to the name `http`, so an
    // alias does not hide the call.
    let source = "package main\n\nimport nethttp \"net/http\"\n\nfunc f(body any) {\n\tnethttp.Post(\"https://api.openai.com/v1/chat/completions\", \"application/json\", body)\n}\n";
    let hits = scan(source, "aliased.go");
    assert_eq!(hits.len(), 1, "{hits:?}");
    // Suspect rather than confirmed: the receiver is resolved structurally, which
    // is what this test is about, but the provider claim still rests on matching
    // the text of the URL.
    assert_eq!(hits[0].1, Confidence::Suspect);
}

#[test]
fn renaming_the_client_does_not_change_the_finding_identity() {
    // The diff invariant, checked end to end rather than only at the id helper.
    let (compiled, rules) = go_rules();
    let ids = |src: &str| {
        let parsed = parse_as("a.go", src, Language::Go).unwrap();
        let mut ids: Vec<String> = detect(&parsed, &compiled, &rules)
            .findings
            .into_iter()
            .map(|f| f.finding_id)
            .collect();
        ids.sort();
        ids
    };

    let original = ids("package main\n\nimport \"github.com/sashabaranov/go-openai\"\n\nfunc f(ctx, req any) {\n\tclient := openai.NewClient(\"token\")\n\tclient.CreateChatCompletion(ctx, req)\n}\n");
    let renamed = ids("package main\n\nimport \"github.com/sashabaranov/go-openai\"\n\nfunc f(ctx, req any) {\n\tsession := openai.NewClient(\"token\")\n\tsession.CreateChatCompletion(ctx, req)\n}\n");

    assert!(!original.is_empty());
    assert_eq!(original, renamed);
}

#[test]
fn scanning_the_same_source_twice_gives_the_same_result() {
    let source = "package main\n\nimport \"github.com/openai/openai-go\"\n\nfunc f(ctx, params any) {\n\tclient := openai.NewClient()\n\tclient.Responses.New(ctx, params)\n}\n";
    assert_eq!(scan(source, "a.go"), scan(source, "a.go"));
}

#[test]
fn an_unknown_import_is_reported_as_unclaimed() {
    // "We have no detector for this" and "there is nothing here" are different
    // statements, and only the first one is true.
    let source = "package main\n\nimport \"github.com/acme/private-llm-go\"\n";
    assert!(scan_all(source, "a.go")
        .unclaimed_imports
        .contains(&"github.com/acme/private-llm-go".to_owned()));
}

#[test]
fn every_engine_fault_over_the_corpus_is_one_this_suite_accounts_for() {
    // A diagnostics channel nobody reads is the same as no diagnostics channel.
    // The engine records a fault whenever it disagrees with itself, and until
    // this test existed the Go suite never looked at one.
    //
    // The single class accounted for today is a declared downgrade the engine
    // cannot evaluate: `base_url` sits on the constructor, and
    // `constructor_arguments` indexes only the Python and TypeScript
    // vocabularies, so for Go it reports "not evaluable" rather than guessing a
    // destination. That is a limitation stated out loud, not a lost match.
    //
    // Anything else fails here. In particular a fault saying a match was dropped
    // without being judged is defect AK-001 reappearing in Go, and the point of
    // the assertion is that it would be read rather than buried in a report.
    for group in ["positive", "negative", "evasion"] {
        for (name, source) in fixtures(group) {
            for fault in scan_all(&source, &name).engine_faults {
                assert!(
                    fault.contains("downgrades on"),
                    "{name} produced an unaccounted engine fault: {fault:?}"
                );
            }
        }
    }
}

#[test]
fn every_go_binding_capture_is_pinned_to_an_identifier() {
    // Why Go was untouched by AK-001, written down so it stays a decision rather
    // than a coincidence. The Java rules capture the receiver as `object: (_)`,
    // which hands the engine whatever shape the source had; the Go rules pin
    // theirs to `(identifier)`, so the receiver the engine has to walk back to a
    // name is already a name.
    //
    // The engine no longer loses a match either way: an unwalkable receiver
    // leaves an `INTERNAL` diagnostic now. But a rule loosened to `(_)` moves the
    // whole family onto that path, which is a deliberate change and should not be
    // possible to make by accident.
    let (_, rules) = go_rules();
    for rule in &rules {
        for (index, spec) in rule.matches.iter().enumerate() {
            let Some(binding) = &spec.binding else {
                continue;
            };
            let pinned = format!("(identifier) @{}", binding.capture);
            assert!(
                spec.query.contains(&pinned),
                "{} [[match]] {index} binds @{} to a receiver its query does not \
                 pin to an identifier; the engine path that shape takes is the one \
                 defect AK-001 lived on",
                rule.rule_id,
                binding.capture
            );
        }
    }
}
