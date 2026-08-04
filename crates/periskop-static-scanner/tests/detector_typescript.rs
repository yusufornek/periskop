#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! End to end detection over the TypeScript, TSX and JavaScript fixtures.
//!
//! The three grammars share one rule family, so the same rules are exercised
//! against all of them. A rule that holds for `.ts` and quietly stops matching in
//! `.tsx` is a gap nobody would notice from the TypeScript tests alone, which is
//! why the fixture set spans every extension the family claims to cover.

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

#[test]
fn positive_fixtures_produce_confirmed_findings() {
    for (name, source, language) in fixtures("positive") {
        let hits = scan(&source, &name, language);
        assert!(!hits.is_empty(), "{name} produced no finding");
        assert!(
            hits.iter().any(|(_, c)| *c == Confidence::Confirmed),
            "{name} produced only weak findings: {hits:?}"
        );
    }
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
