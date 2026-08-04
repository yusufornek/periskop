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
use periskop_static_scanner::engine::detect;
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

fn scan(source: &str, name: &str) -> Vec<(String, Confidence)> {
    let (compiled, rules) = go_rules();
    let parsed = match parse_as(name, source, Language::Go) {
        Ok(p) => p,
        Err(e) => panic!("{name} did not parse: {e}"),
    };
    let result = detect(&parsed, &compiled, &rules);
    result
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

#[test]
fn positive_fixtures_produce_confirmed_findings() {
    for (name, source) in fixtures("positive") {
        let hits = scan(&source, &name);
        assert!(!hits.is_empty(), "{name} produced no finding");
        assert!(
            hits.iter().any(|(_, c)| *c == Confidence::Confirmed),
            "{name} produced only weak findings: {hits:?}"
        );
    }
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
    assert_eq!(hits[0].1, Confidence::Confirmed);
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
    let (compiled, rules) = go_rules();
    let source = "package main\n\nimport \"github.com/acme/private-llm-go\"\n";
    let parsed = parse_as("a.go", source, Language::Go).unwrap();
    let result = detect(&parsed, &compiled, &rules);
    assert!(result
        .unclaimed_imports
        .contains(&"github.com/acme/private-llm-go".to_owned()));
}
