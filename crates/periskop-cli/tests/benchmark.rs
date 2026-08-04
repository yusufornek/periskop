#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! Detection benchmark.
//!
//! Scores the rule set against a labeled corpus and writes the numbers to
//! `target/benchmark.json`. Two things about how it scores are worth stating,
//! because both would be easy to get wrong in a way that flatters the result.
//!
//! Recall is measured per file, not per call site. Resolving every call site in
//! a project needs a symbol table the scanner does not build, so a call site
//! score would be measuring a capability the tool does not claim. The file unit
//! answers the question a reader actually has: did the scan notice this file
//! sends data to a provider. A suspected finding counts as noticing. Scoring
//! only confirmed findings would mark a rule as failing on the day it correctly
//! lowered its own confidence, which is the opposite of the incentive wanted.
//!
//! A miss that is already in the gap catalogue is reported separately from one
//! that is not. The first is a known limit; the second is a regression. Adding
//! them together would let a catalogued gap hide a genuine loss of coverage.
//!
//! Catalogued gaps stay in the denominator of the recall figure. Removing them
//! made the number a tautology: the run already fails on any uncatalogued miss,
//! so once that assertion passed, recall was one hundred percent by arithmetic
//! and could not have come out otherwise. Counted in, the figure measures what
//! share of known egress this rule set actually finds, and it moves when the
//! catalogue grows.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use periskop_static_scanner::engine::detect;
use periskop_static_scanner::language::Language;
use periskop_static_scanner::parser::parse_as;
use periskop_static_scanner::rules::{compile, load_directory, RuleFile};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// One scored language.
#[derive(Debug, serde::Serialize)]
struct LanguageScore {
    language: String,
    /// Files labeled as containing egress.
    positives: usize,
    /// Labeled files where at least one confirmed finding was produced.
    detected: usize,
    /// Files labeled as clean where a finding was produced anyway.
    false_positives: usize,
    /// Labeled files with no finding, and whether the gap is catalogued.
    missed_catalogued: Vec<String>,
    missed_uncatalogued: Vec<String>,
    recall_file_unit_basis_points: u64,
}

#[derive(Debug, serde::Serialize)]
struct BenchmarkResult {
    corpus: String,
    languages: Vec<LanguageScore>,
    /// Recorded so a reader can tell a strong result from a small sample.
    sample_note: String,
}

fn rules_for(language: Language) -> (Vec<RuleFile>, periskop_static_scanner::CompiledRules) {
    let (all, errors) = load_directory(&repo_root().join("rules"));
    assert!(errors.is_empty(), "rule load failed: {errors:?}");
    let family: Vec<RuleFile> = all
        .into_iter()
        .filter(|r| r.language == language.rule_family())
        .collect();
    let compiled = match compile(language, &family) {
        Ok(c) => c,
        Err(e) => panic!("rules did not compile: {e}"),
    };
    (family, compiled)
}

/// Files under a fixture group, with the grammar their extension selects.
fn group(language_dir: &str, group: &str) -> Vec<(String, String, Language)> {
    let dir = repo_root()
        .join("crates/periskop-static-scanner/fixtures")
        .join(language_dir)
        .join(group);
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("fixture group").flatten() {
        let path = entry.path();
        let Some(language) = Language::from_path(&path) else {
            continue;
        };
        out.push((
            path.file_name().unwrap().to_string_lossy().into_owned(),
            std::fs::read_to_string(&path).expect("fixture"),
            language,
        ));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn has_finding(source: &str, name: &str, language: Language) -> bool {
    let (family, compiled) = rules_for(language);
    let Ok(parsed) = parse_as(name, source, language) else {
        return false;
    };
    !detect(&parsed, &compiled, &family).findings.is_empty()
}

/// The marker an evasion fixture carries in its own header.
const GAP_MARKER: &str = "Known gap";

/// Gaps the project has written down. A miss listed here is expected.
///
/// Read out of the fixtures rather than held as a list in this file. The list
/// used to sit here with a comment claiming a new evasion fixture was catalogued
/// the moment it was added; the code did the opposite, and adding one turned the
/// benchmark red until somebody found the array in a Rust test and edited it.
/// A fixture now declares its own status, which is the only place a contributor
/// is already looking.
fn catalogued_gaps(language_dir: &str) -> BTreeSet<String> {
    group(language_dir, "evasion")
        .into_iter()
        .filter(|(_, source, _)| source.contains(GAP_MARKER))
        .map(|(name, _, _)| name)
        .collect()
}

fn score(language_dir: &str) -> LanguageScore {
    let catalogued = catalogued_gaps(language_dir);
    let mut detected = 0usize;
    let mut missed_catalogued = Vec::new();
    let mut missed_uncatalogued = Vec::new();

    // Positive and evasion fixtures both contain egress. The difference is
    // whether the scanner is expected to see it.
    let mut positives = 0usize;
    for (name, source, language) in group(language_dir, "positive")
        .into_iter()
        .chain(group(language_dir, "evasion"))
    {
        positives += 1;
        if has_finding(&source, &name, language) {
            detected += 1;
        } else if catalogued.contains(&name) {
            missed_catalogued.push(name);
        } else {
            missed_uncatalogued.push(name);
        }
    }

    let mut false_positives = 0usize;
    for (name, source, language) in group(language_dir, "negative") {
        if has_finding(&source, &name, language) {
            false_positives += 1;
            missed_uncatalogued.push(format!("false positive: {name}"));
        }
    }

    let recall = if positives == 0 {
        0
    } else {
        (detected as u64 * 10_000) / positives as u64
    };

    LanguageScore {
        language: language_dir.to_owned(),
        positives,
        detected,
        false_positives,
        missed_catalogued,
        missed_uncatalogued,
        recall_file_unit_basis_points: recall,
    }
}

/// The share of labeled egress the rule set is expected to find.
///
/// Not one hundred percent, and that is the point. The corpus deliberately
/// contains fixtures the scanner cannot see, so a perfect score would mean the
/// catalogue had been emptied rather than the rules improved. The floor is set
/// below the current figure with room for one more catalogued gap per language,
/// so adding a gap is a decision rather than a build failure, and losing a
/// detector is still a red test.
const RECALL_FLOOR_BASIS_POINTS: u64 = 6_500;

#[test]
fn detection_benchmark() {
    let languages: Vec<LanguageScore> = ["python", "typescript"].into_iter().map(score).collect();

    let result = BenchmarkResult {
        corpus: "fixtures".to_owned(),
        sample_note: "Bootstrap corpus only. Fixtures are written by the same people who write \
                      the rules, so this measures whether the rules do what their authors \
                      intended, not whether that intent matches how libraries are used in \
                      practice. See test-corpus/README.md."
            .to_owned(),
        languages,
    };

    let out = repo_root().join("target/benchmark.json");
    if let Some(parent) = out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&out, serde_json::to_string_pretty(&result).unwrap());

    // Every uncatalogued miss fails the run. A gap is either written down or it
    // is a regression; there is no third state where it is merely tolerated.
    let mut problems: BTreeMap<&str, &Vec<String>> = BTreeMap::new();
    for language in &result.languages {
        if !language.missed_uncatalogued.is_empty() {
            problems.insert(language.language.as_str(), &language.missed_uncatalogued);
        }
    }
    assert!(
        problems.is_empty(),
        "uncatalogued misses or false positives: {problems:?}"
    );

    for language in &result.languages {
        assert!(
            language.recall_file_unit_basis_points >= RECALL_FLOOR_BASIS_POINTS,
            "{} recall is {} basis points, below the declared floor of \
             {RECALL_FLOOR_BASIS_POINTS}",
            language.language,
            language.recall_file_unit_basis_points
        );
        assert!(
            !language.missed_catalogued.is_empty(),
            "{} has no catalogued gap left, so the recall figure is measuring an \
             empty catalogue rather than the rules",
            language.language
        );
    }
}
