#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! Every copy of the provider table says the same thing.
//!
//! The table lives in `schemas/providers.json` and in six hand written copies:
//! one `http-literal-endpoint.toml` per language family, and one host classifier
//! per runtime hook. The copies are not an accident waiting to be removed. A hook
//! runs inside somebody else's process, where this repository is not on disk and
//! reading a file per request is work the performance budget does not have; and a
//! tree-sitter query is compiled from a literal string that no loader
//! interpolates. What the copies must not be is *independent*, and until this
//! file existed they were.
//!
//! The drift was real, not hypothetical. The TypeScript alternation ended at
//! `openai.azure.com` while Python, Go and Java carried a fifth alternative for
//! AWS Bedrock, so `fetch("https://bedrock-runtime.<region>.amazonaws.com/…")`
//! produced no finding in a TypeScript codebase and a `suspect` finding in a
//! Python one. Nothing went red: `rule_lint` compiles queries without comparing
//! them, the benchmark had no Bedrock fixture, and a raw fetch imports no module,
//! so the call did not even reach `undetected_libraries`. Neither a finding nor
//! an admission, which is the worst outcome this product can produce.
//!
//! So this test is the gate that was missing. It reads the one file and proves
//! each copy still derives from it, in both directions: an entry added to the
//! table and forgotten in a copy fails here, and so does an entry a copy carries
//! that the table does not.
//!
//! Kept as an integration test rather than a unit test for the same reason
//! `embedded_rules.rs` is: the thing under test is the repository, not this
//! crate.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use periskop_static_scanner::rules::load_directory;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// One row of the table, in the shape the copies have to spell it.
struct Entry {
    /// `exact`, `suffix` or `pattern`. Named rather than inferred, because the
    /// three are consulted in that order and a row that moved between them would
    /// change what a host classifies as.
    kind: &'static str,
    /// The host, suffix or anchored pattern, exactly as a hook must write it.
    value: String,
    provider_ref: String,
    /// How the static rules spell this host, or `None` when the static rules do
    /// not target it.
    static_url_pattern: Option<String>,
}

/// The table, read from the single file that owns it.
///
/// Parsed by hand rather than through serde so that this test depends on nothing
/// the product does not already ship. The parse is strict: a row missing a field
/// panics rather than being skipped, because a silently skipped row is exactly
/// the hole this gate exists to close.
fn table() -> Vec<Entry> {
    let path = repo_root().join("schemas/providers.json");
    let text = read(&path);
    let value: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()));

    let mut out = Vec::new();
    for (array, kind, key) in [
        ("exact_hosts", "exact", "host"),
        ("suffix_hosts", "suffix", "suffix"),
        ("pattern_hosts", "pattern", "pattern"),
    ] {
        let rows = value[array]
            .as_array()
            .unwrap_or_else(|| panic!("{} has no {array} array", path.display()));
        assert!(!rows.is_empty(), "{array} is empty in {}", path.display());
        for row in rows {
            let field = |name: &str| -> String {
                row[name]
                    .as_str()
                    .unwrap_or_else(|| panic!("{array} row {row} has no string {name}"))
                    .to_owned()
            };
            out.push(Entry {
                kind,
                value: field(key),
                provider_ref: field("provider_ref"),
                static_url_pattern: row["static_url_pattern"].as_str().map(str::to_owned),
            });
        }
    }
    out
}

/// The alternation every language family's rule has to carry, in file order.
///
/// Order is part of the claim rather than an artefact. Comparing sets would let
/// two rule files that list the same hosts in different orders both pass, and the
/// two would then produce different `rule_hash` values for what a reader is told
/// is the same detector.
fn expected_alternation() -> Vec<String> {
    let alternation: Vec<String> = table()
        .into_iter()
        .filter_map(|e| e.static_url_pattern)
        .collect();
    assert!(
        alternation.len() > 1,
        "schemas/providers.json yielded {} static url pattern(s); a table this \
         small means the parse found nothing rather than that the product \
         targets one host",
        alternation.len()
    );
    alternation
}

/// Every `#match? @url "(…)"` alternation in a rule file, one entry per query.
///
/// The rule file carries the tree-sitter *string literal* spelling, in which
/// every backslash is doubled because tree-sitter unescapes the literal before
/// handing the text to its regex engine. Undoubling here is what lets the
/// comparison happen in one spelling instead of storing both.
fn alternations_in(rule_text: &str) -> Vec<Vec<String>> {
    const OPEN: &str = "(#match? @url \"(";
    const CLOSE: &str = ")\")";

    let mut out = Vec::new();
    let mut rest = rule_text;
    while let Some(at) = rest.find(OPEN) {
        let after = &rest[at + OPEN.len()..];
        let Some(end) = after.find(CLOSE) else {
            panic!("an @url predicate opens and never closes");
        };
        out.push(
            after[..end]
                .split('|')
                .map(|alternative| alternative.replace("\\\\", "\\"))
                .collect(),
        );
        rest = &after[end..];
    }
    out
}

/// Language families that ship detector rules, read from the tree rather than
/// listed here, so a family added tomorrow joins this gate without an edit.
fn rule_families() -> BTreeSet<String> {
    let (rules, errors) = load_directory(&repo_root().join("rules"));
    assert!(errors.is_empty(), "rule load failed: {errors:?}");
    let families: BTreeSet<String> = rules.into_iter().map(|r| r.language).collect();
    assert!(!families.is_empty(), "no rule family was loaded");
    families
}

#[test]
fn every_language_family_ships_the_http_endpoint_rule() {
    // The protection for a language added later. Without this, a new family could
    // arrive with SDK rules only, carry no host alternation at all, and pass the
    // identity check below vacuously: there would be nothing to compare. A family
    // that cannot see a raw HTTP call to a provider is a family with a hole in it,
    // and the hole would be invisible.
    let missing: Vec<String> = rule_families()
        .into_iter()
        .filter(|family| {
            !repo_root()
                .join("rules")
                .join(family)
                .join("http-literal-endpoint.toml")
                .exists()
        })
        .collect();
    assert!(
        missing.is_empty(),
        "these rule families ship no http-literal-endpoint.toml, so raw HTTP \
         calls to a provider are invisible in them: {missing:?}"
    );
}

#[test]
fn every_language_family_matches_the_same_provider_hosts() {
    // The identity claim. A destination is a fact about the network, not about
    // the language that addressed it, so the set of hosts the scanner recognises
    // cannot legitimately differ between families. SDK coverage may and does
    // differ; this does not.
    let expected = expected_alternation();
    let mut checked = 0usize;
    let mut problems: Vec<String> = Vec::new();

    for family in rule_families() {
        let path = repo_root()
            .join("rules")
            .join(&family)
            .join("http-literal-endpoint.toml");
        let found = alternations_in(&read(&path));
        assert!(
            !found.is_empty(),
            "{} declares no @url predicate, so this file's copy of the table \
             could not be compared at all",
            path.display()
        );

        for (index, alternation) in found.iter().enumerate() {
            checked += 1;
            if alternation != &expected {
                let missing: Vec<&String> = expected
                    .iter()
                    .filter(|h| !alternation.contains(h))
                    .collect();
                let extra: Vec<&String> = alternation
                    .iter()
                    .filter(|h| !expected.contains(h))
                    .collect();
                problems.push(format!(
                    "{} query {index}: missing {missing:?}, unexpected {extra:?}",
                    path.display()
                ));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "{} rule copies disagree with schemas/providers.json:\n  {}",
        problems.len(),
        problems.join("\n  ")
    );
    // A walk that compared nothing is not a walk that passed.
    assert!(checked > 0, "no @url alternation was compared");
}

#[test]
fn both_runtime_hooks_carry_the_table_the_file_declares() {
    // The other three copies. The hooks are already pinned to each other by
    // `hooks/python/tests/hook-parity-vectors.json`, which keeps them equal but
    // says nothing about whether the pair still agrees with the table the static
    // scanner reads. Two hooks that drift together are a reconciliation that
    // compares a declared provider against an observed one and disagrees with
    // itself.
    let node = read(&repo_root().join("hooks/node/src/provider-ref.ts"));
    let python = read(&repo_root().join("hooks/python/periskop_hook/target.py"));

    let mut missing: Vec<String> = Vec::new();
    for entry in table() {
        let (node_line, python_line) = match entry.kind {
            "exact" => (
                format!("[\"{}\", \"{}\"]", entry.value, entry.provider_ref),
                format!("\"{}\": \"{}\"", entry.value, entry.provider_ref),
            ),
            "suffix" => (
                format!("[\"{}\", \"{}\"]", entry.value, entry.provider_ref),
                format!("(\"{}\", \"{}\")", entry.value, entry.provider_ref),
            ),
            "pattern" => (
                format!("[/{}/, \"{}\"]", entry.value, entry.provider_ref),
                format!(
                    "(re.compile(r\"{}\"), \"{}\")",
                    entry.value, entry.provider_ref
                ),
            ),
            other => panic!("unknown entry kind {other}"),
        };
        if !node.contains(&node_line) {
            missing.push(format!("hooks/node/src/provider-ref.ts: {node_line}"));
        }
        if !python.contains(&python_line) {
            missing.push(format!(
                "hooks/python/periskop_hook/target.py: {python_line}"
            ));
        }
    }

    assert!(
        missing.is_empty(),
        "{} table row(s) declared in schemas/providers.json and absent from a \
         hook:\n  {}",
        missing.len(),
        missing.join("\n  ")
    );
}

#[test]
fn no_hook_classifies_a_host_the_table_does_not_declare() {
    // The direction the containment check above cannot see. A provider added to a
    // hook and never written down would classify traffic under a name the report
    // vocabulary does not know, and the row would be invisible to every other
    // copy of the table.
    let declared: BTreeSet<String> = table().into_iter().map(|e| e.provider_ref).collect();

    for (path, quoted) in [
        ("hooks/node/src/provider-ref.ts", "\", \""),
        ("hooks/python/periskop_hook/target.py", "\": \""),
    ] {
        let text = read(&repo_root().join(path));
        let undeclared: Vec<String> = text
            .lines()
            .filter_map(|line| line.split_once(quoted))
            .filter_map(|(_, tail)| tail.split('"').next())
            .filter(|value| !declared.contains(*value))
            .map(str::to_owned)
            .collect();
        assert!(
            undeclared.is_empty(),
            "{path} classifies hosts as {undeclared:?}, which schemas/providers.json \
             does not declare"
        );
    }
}
