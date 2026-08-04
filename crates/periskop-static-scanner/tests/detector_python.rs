#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! End to end detection over the Python fixtures.
//!
//! This is the regression suite the rule set is held to. Every fixture group
//! carries a different obligation, and the three together are what the project
//! calls a complete test case for a detector.
//!
//! Positive fixtures must yield a finding at the confidence they are listed with,
//! which is not the same as "confirmed" for all of them. Negative fixtures must
//! yield none, and this is the layer where that assertion becomes meaningful,
//! because bindings are applied here rather than in the query. Evasion fixtures
//! must yield nothing and are expected to: they record the limits of static
//! analysis in a form that fails loudly if the limits ever move.

use std::path::{Path, PathBuf};

use periskop_core::finding::Confidence;
use periskop_static_scanner::engine::detect;
use periskop_static_scanner::language::Language;
use periskop_static_scanner::parser::parse_as;
use periskop_static_scanner::rules::{compile, load_directory, CompiledRules, RuleFile};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn python_rules() -> (CompiledRules, Vec<RuleFile>) {
    let (rules, errors) = load_directory(&repo_root().join("rules"));
    assert!(errors.is_empty(), "rule load failed: {errors:?}");
    let python: Vec<RuleFile> = rules
        .into_iter()
        .filter(|r| r.language == "python")
        .collect();
    let compiled = match compile(Language::Python, &python) {
        Ok(c) => c,
        Err(e) => panic!("rules did not compile: {e}"),
    };
    (compiled, python)
}

fn scan(source: &str, name: &str) -> Vec<(String, Confidence)> {
    let (compiled, rules) = python_rules();
    let parsed = match parse_as(name, source, Language::Python) {
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
        .join("fixtures/python")
        .join(group);
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("fixture dir").flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "py") {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            out.push((name, std::fs::read_to_string(&path).expect("fixture")));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    // An empty group would let every assertion below pass without running once.
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
    ("anthropic_messages.py", Confidence::Confirmed),
    ("google_genai.py", Confidence::Confirmed),
    // Matched on the text of a URL, so the provider claim is a text coincidence
    // away from being wrong.
    ("http_literal.py", Confidence::Suspect),
    ("openai_client.py", Confidence::Confirmed),
    // The client held in an instance field: resolved through the binding table,
    // so this is a structural fact and stays confirmed.
    ("openai_client_field.py", Confidence::Confirmed),
    ("openai_legacy.py", Confidence::Confirmed),
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
    let present: Vec<String> = fixtures("positive").into_iter().map(|(n, _)| n).collect();
    let missing: Vec<&str> = EXPECTED_CONFIDENCE
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| !present.iter().any(|p| p == name))
        .collect();
    assert!(missing.is_empty(), "listed but absent: {missing:?}");
}

#[test]
fn a_client_kept_in_an_instance_field_is_reported() {
    // The shape most Python classes use. It resolved to nothing before, so a file
    // making plain OpenAI calls through a field reported no egress at all: not a
    // weaker finding, no finding, and no coverage entry either.
    let source = "from openai import OpenAI\n\
                  class Summarizer:\n\
                  \x20   def __init__(self):\n\
                  \x20       self.client = OpenAI()\n\
                  \x20   def run(self, text):\n\
                  \x20       return self.client.chat.completions.create(model='x', messages=text)\n";
    let hits = scan(source, "field.py");
    assert!(
        hits.iter().any(
            |(rule_id, confidence)| rule_id == "python.static.openai-client-call"
                && *confidence == Confidence::Confirmed
        ),
        "expected a confirmed finding for the field held client, got {hits:?}"
    );
}

#[test]
fn a_field_holding_an_unrelated_class_is_not_reported() {
    // The other half of the field case. Tracking fields must not turn every
    // `self.<name>.create(...)` in a codebase into a provider finding.
    let source = "class Store:\n\
                  \x20   def create(self, **fields):\n\
                  \x20       return fields\n\
                  class Repo:\n\
                  \x20   def __init__(self):\n\
                  \x20       self.client = Store()\n\
                  \x20   def run(self, text):\n\
                  \x20       return self.client.create(payload=text)\n";
    assert!(scan(source, "field_negative.py").is_empty());
}

#[test]
fn negative_fixtures_produce_nothing() {
    // The check the query layer could not make. A local class with a create
    // method matches the pattern and is dropped here, because its receiver does
    // not resolve to any provider package.
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
fn a_client_from_a_lookalike_package_is_not_reported() {
    let source = "from openai_helper import OpenAI\nclient = OpenAI()\nclient.chat.completions.create(model='x')\n";
    assert!(scan(source, "lookalike.py").is_empty());
}

#[test]
fn renaming_the_client_does_not_change_the_finding_identity() {
    // The diff invariant, checked end to end rather than only at the id helper.
    let (compiled, rules) = python_rules();
    let ids = |src: &str| {
        let parsed = parse_as("a.py", src, Language::Python).unwrap();
        let mut ids: Vec<String> = detect(&parsed, &compiled, &rules)
            .findings
            .into_iter()
            .map(|f| f.finding_id)
            .collect();
        ids.sort();
        ids
    };

    let original = ids(
        "from openai import OpenAI\nclient = OpenAI()\nclient.chat.completions.create(model='x')\n",
    );
    let renamed = ids("from openai import OpenAI\nsession = OpenAI()\nsession.chat.completions.create(model='x')\n");

    assert!(!original.is_empty());
    assert_eq!(original, renamed);
}

#[test]
fn adding_a_line_above_the_call_does_not_change_the_identity() {
    let (compiled, rules) = python_rules();
    let ids = |src: &str| {
        let parsed = parse_as("a.py", src, Language::Python).unwrap();
        let mut ids: Vec<String> = detect(&parsed, &compiled, &rules)
            .findings
            .into_iter()
            .map(|f| f.finding_id)
            .collect();
        ids.sort();
        ids
    };

    let base =
        "from openai import OpenAI\nclient = OpenAI()\nclient.chat.completions.create(model='x')\n";
    let shifted = format!("# a new comment\n{base}");

    assert_eq!(ids(base), ids(&shifted));
}

/// Two calls to the same method, one in each of two functions.
const TWO_SCOPES: &str = "from openai import OpenAI\n\
                          client = OpenAI()\n\
                          def send_profile():\n\
                          \x20   client.chat.completions.create(model='x')\n\
                          def send_payment():\n\
                          \x20   client.chat.completions.create(model='x')\n";

/// Two calls to the same method inside one function.
const ONE_SCOPE: &str = "from openai import OpenAI\n\
                         client = OpenAI()\n\
                         def send_both():\n\
                         \x20   client.chat.completions.create(model='x')\n\
                         \x20   client.chat.completions.create(model='x')\n";

fn identities(source: &str) -> Vec<String> {
    let (compiled, rules) = python_rules();
    let parsed = match parse_as("svc.py", source, Language::Python) {
        Ok(p) => p,
        Err(e) => panic!("svc.py did not parse: {e}"),
    };
    let mut ids: Vec<String> = detect(&parsed, &compiled, &rules)
        .findings
        .into_iter()
        .map(|f| f.finding_id)
        .collect();
    ids.sort();
    ids
}

#[test]
fn two_call_sites_in_one_file_get_two_identities() {
    // The first half of the identity contract. The README promises every call
    // site is reported. Before this, both calls hashed to the same egress point,
    // deduplication dropped the second, and the dropped call reached no list and
    // no counter: a file sending payment data on line 200 was invisible because
    // line 10 sent profile data through the same method.
    let ids = identities(TWO_SCOPES);
    assert_eq!(
        ids.len(),
        2,
        "expected one finding per call site, got {ids:?}"
    );
    assert_ne!(ids[0], ids[1]);
}

#[test]
fn two_call_sites_in_one_scope_get_two_identities() {
    // The harder half of the same case: the enclosing symbol cannot separate
    // these, so the occurrence number has to.
    let ids = identities(ONE_SCOPE);
    assert_eq!(
        ids.len(),
        2,
        "expected one finding per call site, got {ids:?}"
    );
    assert_ne!(ids[0], ids[1]);
}

#[test]
fn adding_a_line_above_two_call_sites_changes_no_identity() {
    // The second half of the identity contract, and the reason the discriminator
    // is a scope and an occurrence rather than a line number. Both invariants have
    // to hold together: separating call sites is worthless if it costs the diff.
    for source in [TWO_SCOPES, ONE_SCOPE] {
        let shifted = format!("# a new comment\n{source}");
        assert_eq!(identities(source), identities(&shifted));
    }
}

#[test]
fn renaming_the_enclosing_function_is_the_only_thing_that_moves_its_call() {
    // The cost of scoping identities, stated rather than discovered later. A call
    // moved into a renamed function is a different call site by this rule, while
    // every call in every other scope keeps its identity.
    let renamed = TWO_SCOPES.replace("send_profile", "send_profile_v2");
    let before = identities(TWO_SCOPES);
    let after = identities(&renamed);

    assert_eq!(before.len(), after.len());
    let unchanged = before.iter().filter(|id| after.contains(id)).count();
    assert_eq!(unchanged, 1, "only the renamed scope should move");
}

#[test]
fn scanning_the_same_source_twice_gives_the_same_result() {
    let source = "from anthropic import Anthropic\nc = Anthropic()\nc.messages.create(model='m')\n";
    assert_eq!(scan(source, "a.py"), scan(source, "a.py"));
}

#[test]
fn an_unknown_import_is_reported_as_unclaimed() {
    // "We have no detector for this" and "there is nothing here" are different
    // statements, and only the first one is true.
    let (compiled, rules) = python_rules();
    let parsed = parse_as("a.py", "import some_private_ai_sdk\n", Language::Python).unwrap();
    let result = detect(&parsed, &compiled, &rules);
    assert!(result
        .unclaimed_imports
        .contains(&"some_private_ai_sdk".to_owned()));
}
