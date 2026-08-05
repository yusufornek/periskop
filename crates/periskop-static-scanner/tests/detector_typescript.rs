#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! End to end detection over the TypeScript, TSX and JavaScript fixtures.
//!
//! The three grammars share one rule family, so the same rules are exercised
//! against all of them. A rule that holds for `.ts` and quietly stops matching in
//! `.tsx` is a gap nobody would notice from the TypeScript tests alone, which is
//! why the fixture set spans every extension the family claims to cover.
//!
//! Positive fixtures must yield a finding at the confidence they are listed with,
//! which is not the same as "confirmed" for all of them.

use std::path::{Path, PathBuf};

use periskop_core::finding::Confidence;
use periskop_static_scanner::engine::detect;
use periskop_static_scanner::language::Language;
use periskop_static_scanner::parser::parse_as;
use periskop_static_scanner::rules::{compile, load_directory, RuleFile};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn family_rules() -> Vec<RuleFile> {
    let (rules, errors) = load_directory(&repo_root().join("rules"));
    assert!(errors.is_empty(), "rule load failed: {errors:?}");
    let family: Vec<RuleFile> = rules
        .into_iter()
        .filter(|r| r.language == "typescript")
        .collect();
    assert!(!family.is_empty(), "no typescript rules found");
    family
}

fn scan(source: &str, name: &str, language: Language) -> Vec<(String, Confidence)> {
    let rules = family_rules();
    let compiled = match compile(language, &rules) {
        Ok(c) => c,
        Err(e) => panic!("rules did not compile for {language:?}: {e}"),
    };
    let parsed = match parse_as(name, source, language) {
        Ok(p) => p,
        Err(e) => panic!("{name} did not parse: {e}"),
    };
    detect(&parsed, &compiled, &rules)
        .findings
        .into_iter()
        .map(|f| (f.detector.rule_id, f.confidence))
        .collect()
}

/// Fixtures, each paired with the grammar its extension selects.
fn fixtures(group: &str) -> Vec<(String, String, Language)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/typescript")
        .join(group);
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("fixture dir").flatten() {
        let path = entry.path();
        let Some(language) = Language::from_path(&path) else {
            continue;
        };
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        out.push((
            name,
            std::fs::read_to_string(&path).expect("fixture"),
            language,
        ));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(!out.is_empty(), "no fixtures under {}", dir.display());
    out
}

/// The confidence each positive fixture is expected to come back with.
///
/// Named per fixture rather than asserted in bulk, because the fixtures no longer
/// agree. A rule whose distinguishing condition is a regular expression over the
/// text of a string literal cannot claim a structural fact, so it reports
/// `suspect` and the fixture exercising it comes back weaker by design. A blanket
/// "every positive fixture is confirmed" would have to be loosened to a "some
/// finding exists" check to let that pass, and loosening it would stop watching
/// the fixtures that must stay confirmed. This table keeps both statements.
const EXPECTED_CONFIDENCE: &[(&str, Confidence)] = &[
    ("anthropic_messages.ts", Confidence::Confirmed),
    // Same rule and the same reason as `fetch_literal.ts`: matched on the text of
    // a URL. Listed separately because the host it exercises is the one the
    // TypeScript alternation was missing, and a fixture folded into the other
    // entry would stop naming what it guards.
    ("fetch_bedrock.ts", Confidence::Suspect),
    // Matched on the text of a URL, so the provider claim is a text coincidence
    // away from being wrong.
    ("fetch_literal.ts", Confidence::Suspect),
    ("openai_client.ts", Confidence::Confirmed),
    // The client held in a class field: resolved through the binding table, so
    // this is a structural fact and stays confirmed.
    ("openai_client_field.ts", Confidence::Confirmed),
    ("openai_require.js", Confidence::Confirmed),
    ("openai_view.tsx", Confidence::Confirmed),
];

#[test]
fn every_positive_fixture_produces_the_confidence_it_is_listed_with() {
    for (name, source, language) in fixtures("positive") {
        let hits = scan(&source, &name, language);
        assert!(!hits.is_empty(), "{name} produced no finding");
        let Some((_, expected)) = EXPECTED_CONFIDENCE.iter().find(|(f, _)| *f == name) else {
            panic!(
                "{name} is a positive fixture with no entry in EXPECTED_CONFIDENCE; \
                 a new fixture states what it expects rather than inheriting it"
            );
        };
        // Every finding, not merely one of them. "At least one is confirmed" was
        // what let a weaker finding hide behind a stronger one from another rule;
        // naming the whole set is what makes the http fixture's downgrade visible
        // here instead of only in the benchmark.
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
    let present: Vec<String> = fixtures("positive")
        .into_iter()
        .map(|(n, _, _)| n)
        .collect();
    let missing: Vec<&str> = EXPECTED_CONFIDENCE
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| !present.iter().any(|p| p == name))
        .collect();
    assert!(missing.is_empty(), "listed but absent: {missing:?}");
}

#[test]
fn a_client_kept_in_a_class_field_is_reported() {
    // The shape most application code uses. Both spellings of the field reach the
    // same call site, so both are checked; before this neither resolved, and a
    // file making plain OpenAI calls reported no egress at all.
    let property = "import OpenAI from 'openai';\n\
                    class S {\n  private client = new OpenAI();\n\
                    \x20 run() { return this.client.chat.completions.create({}); }\n}\n";
    let constructor = "import OpenAI from 'openai';\n\
                       class S {\n  private client: OpenAI;\n\
                       \x20 constructor() { this.client = new OpenAI(); }\n\
                       \x20 run() { return this.client.chat.completions.create({}); }\n}\n";
    for (label, source) in [("property", property), ("constructor", constructor)] {
        let hits = scan(source, "field.ts", Language::TypeScript);
        assert!(
            hits.iter().any(|(rule_id, confidence)| rule_id
                == "typescript.static.openai-client-call"
                && *confidence == Confidence::Confirmed),
            "the {label} spelling produced {hits:?}"
        );
    }
}

#[test]
fn a_field_holding_an_unrelated_class_is_not_reported() {
    // The other half of the field case. Tracking fields must not turn every
    // `this.<name>.create(...)` in a codebase into a provider finding.
    let source = "class Store { create(f: unknown) { return f; } }\n\
                  class Repo {\n  private client = new Store();\n\
                  \x20 run(f: unknown) { return this.client.create(f); }\n}\n";
    assert!(scan(source, "field_negative.ts", Language::TypeScript).is_empty());
}

#[test]
fn negative_fixtures_produce_nothing() {
    for (name, source, language) in fixtures("negative") {
        let hits = scan(&source, &name, language);
        assert!(hits.is_empty(), "{name} produced {hits:?}");
    }
}

#[test]
fn evasion_fixtures_produce_nothing_and_that_is_recorded() {
    for (name, source, language) in fixtures("evasion") {
        let hits = scan(&source, &name, language);
        assert!(
            hits.is_empty(),
            "{name} is catalogued as a gap but produced {hits:?}"
        );
    }
}

#[test]
fn the_same_rules_hold_across_every_grammar_in_the_family() {
    // One source, three grammars. TSX and JavaScript both accept this text, and
    // the rule family claims all three, so all three must agree.
    let source = "import OpenAI from 'openai';\nconst c = new OpenAI();\nc.chat.completions.create({ model: 'gpt-4' });\n";
    for language in [Language::TypeScript, Language::Tsx, Language::JavaScript] {
        let hits = scan(source, "shared.ts", language);
        assert!(
            !hits.is_empty(),
            "no finding under {language:?}, though the family covers it"
        );
    }
}

#[test]
fn require_style_imports_resolve_like_module_imports() {
    let source =
        "const OpenAI = require('openai');\nconst c = new OpenAI();\nc.chat.completions.create({});\n";
    assert!(!scan(source, "cjs.js", Language::JavaScript).is_empty());
}

#[test]
fn a_lookalike_package_is_not_reported() {
    let source =
        "import OpenAI from 'openai-mock';\nconst c = new OpenAI();\nc.chat.completions.create({});\n";
    assert!(scan(source, "mock.ts", Language::TypeScript).is_empty());
}

#[test]
fn renaming_the_client_does_not_change_the_finding_identity() {
    let rules = family_rules();
    let compiled = compile(Language::TypeScript, &rules).unwrap();
    let ids = |src: &str| {
        let parsed = parse_as("a.ts", src, Language::TypeScript).unwrap();
        let mut ids: Vec<String> = detect(&parsed, &compiled, &rules)
            .findings
            .into_iter()
            .map(|f| f.finding_id)
            .collect();
        ids.sort();
        ids
    };

    let original =
        ids("import OpenAI from 'openai';\nconst client = new OpenAI();\nclient.chat.completions.create({});\n");
    let renamed =
        ids("import OpenAI from 'openai';\nconst session = new OpenAI();\nsession.chat.completions.create({});\n");

    assert!(!original.is_empty());
    assert_eq!(original, renamed);
}
