#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! Detection benchmark over the four rule families v1 ships (milestone 47).
//!
//! Scores the rule set against the fixture corpus and writes the numbers to
//! `target/benchmark.json`. Four properties of how it scores are worth stating,
//! because each of them would be easy to get wrong in a direction that flatters
//! the result.
//!
//! **Recall is measured per file, not per call site.** Resolving every call site
//! in a project needs a project wide symbol table the scanner does not build, so
//! a call site score would be measuring a capability the tool does not claim
//! (`docs/05-quality/benchmarks.md` section (a), "measurement unit"). The file
//! unit answers the question a reader actually has: did the scan notice that
//! this file sends data to a provider.
//!
//! **Which confidence level counts is written down rather than assumed.** Once
//! the HTTP rules were corrected to report `suspect` instead of `confirmed`,
//! "detected" stopped being one number. `benchmarks.md` defines the gate metric
//! as the share of labeled files carrying at least one *confirmed* finding, so
//! that figure is reported under a name with `confirmed` in it. The looser
//! figure, any finding at all, is reported next to it under its own name and is
//! never a gate. A single field called "recall" that quietly counted suspects
//! would let a rule set which had given up on every claim it makes still score
//! full marks, and the day a rule correctly lowered its own confidence would
//! look like the day nothing changed.
//!
//! **A cell below the minimum sample reports no score at all.** `benchmarks.md`
//! rule 3 is binding: a cell that does not meet the minimum sample reports the
//! words "insufficient sample" instead of a number, and does not enter the gate
//! arithmetic. Zero would be a lie in one direction and the ratio over eight
//! fixtures would be a lie in the other. The regression assertions below do not
//! depend on that ratio, so a small corpus costs the release gate and keeps the
//! safety net.
//!
//! **A miss lands in one of three buckets, and they are never added up.** A
//! catalogued gap is a declared limit of the approach. An open defect is a bug
//! with an owner, counted against recall and named in the output until somebody
//! closes it. Anything else is a regression and fails the run. Collapsing the
//! three would let a declared limit hide a bug, or a bug hide a regression.
//!
//! Catalogued gaps stay in the denominator. Removing them made the number a
//! tautology: the run already fails on any uncatalogued miss, so once that
//! assertion passed, recall was one hundred percent by arithmetic and could not
//! have come out otherwise. Counted in, the figure measures what share of known
//! egress this rule set actually finds, and it moves when the catalogue grows.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use periskop_core::finding::Confidence;
use periskop_static_scanner::engine::detect;
use periskop_static_scanner::language::Language;
use periskop_static_scanner::parser::parse_as;
use periskop_static_scanner::rules::{compile, load_directory, CompiledRules, RuleFile};

/// Fixture groups, which are also the labels.
///
/// A file's group is its label. `positive` and `evasion` both contain egress and
/// both count towards the sample; the difference between them is only whether
/// the scanner is expected to see it.
const POSITIVE: &str = "positive";
const EVASION: &str = "evasion";
const NEGATIVE: &str = "negative";

/// The rule families v1 covers, and therefore the cells this benchmark owes a
/// reader. F2 adds `go` and `java` to the two F1 shipped with.
const CORPUS_LANGUAGES: [&str; 4] = ["go", "java", "python", "typescript"];

/// Sample floor below which a cell may not report a rate.
///
/// From `benchmarks.md` section (a), "targets": at least one hundred labeled
/// egress points per cell. In this corpus a fixture file carries one labeled
/// egress point, so the labeled file count is the sample size. The bootstrap
/// fixtures are roughly an order of magnitude short of this, which is the
/// intended reading rather than a defect to route around: the number that closes
/// F2's benchmark gate comes from the labeled corpus in `test-corpus/`, and
/// until that exists every cell here says so out loud.
const MINIMUM_LABELED_EGRESS_POINTS: usize = 100;

/// The share of labeled egress a scored cell is expected to find.
///
/// Not one hundred percent, and that is the point. The corpus deliberately
/// contains fixtures the scanner cannot see, so a perfect score would mean the
/// catalogue had been emptied rather than the rules improved. Applied only to
/// cells that meet [`MINIMUM_LABELED_EGRESS_POINTS`]; a rate computed over eight
/// files is not a release gate whatever its value.
const RECALL_FLOOR_BASIS_POINTS: u64 = 6_500;

/// Labeled fixtures currently lost to an open defect, with the defect named.
///
/// This is deliberately not the gap catalogue and deliberately not a tolerated
/// miss. A catalogued gap says "no rule can see this"; an entry here says "a
/// rule should have seen this and a bug stopped it", which is a different claim
/// and belongs in a different column of the report. Both lower recall, because
/// the reader's question is what the tool finds, not why it did not.
///
/// The list can only shrink. `every_open_defect_is_still_open` fails when an
/// entry starts being detected, so fixing the defect forces the entry out
/// instead of leaving a stale exemption behind that would mask the next
/// regression on the same fixture.
///
/// Empty, and that is the intended resting state rather than an oversight. The
/// three `java` entries this array held were the receiver chain defect AK-001:
/// `bindings.rs::root_identifier` knew no Java node kinds, so `detect.rs`
/// dropped a matched rule on a `?` and the file came back clean. Both halves are
/// fixed (Java receivers resolve, and a match the engine cannot evaluate now
/// leaves an `INTERNAL` diagnostic), so the entries are gone and the fixtures are
/// back under the ordinary regression assertions.
const OPEN_DEFECTS: [(&str, &str, &str); 0] = [];

fn open_defects(language_dir: &str) -> BTreeSet<String> {
    OPEN_DEFECTS
        .iter()
        .filter(|(language, _, _)| *language == language_dir)
        .map(|(_, fixture, _)| (*fixture).to_owned())
        .collect()
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// One fixture file, with the grammar its extension selects.
struct Fixture {
    name: String,
    source: String,
    language: Language,
}

/// The compiled rule set, loaded once for the whole run.
///
/// This used to be loaded and compiled once per fixture file, which made the
/// benchmark's cost quadratic in the size of the corpus. The corpus is the thing
/// that is supposed to grow, so the cost of growing it belongs at zero.
struct RuleSet {
    families: BTreeMap<Language, (Vec<RuleFile>, CompiledRules)>,
}

impl RuleSet {
    fn load() -> Self {
        let (all, errors) = load_directory(&repo_root().join("rules"));
        assert!(errors.is_empty(), "rule load failed: {errors:?}");

        let mut families = BTreeMap::new();
        for language in Language::ALL {
            let family: Vec<RuleFile> = all
                .iter()
                .filter(|r| r.language == language.rule_family())
                .cloned()
                .collect();
            let compiled = match compile(language, &family) {
                Ok(compiled) => compiled,
                Err(error) => panic!("{} rules did not compile: {error}", language.as_str()),
            };
            families.insert(language, (family, compiled));
        }
        Self { families }
    }

    fn family(&self, language: Language) -> &(Vec<RuleFile>, CompiledRules) {
        self.families
            .get(&language)
            .unwrap_or_else(|| panic!("no rule family compiled for {}", language.as_str()))
    }
}

/// Files under one fixture group, in a fixed order.
fn group(language_dir: &str, group: &str) -> Vec<Fixture> {
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
        out.push(Fixture {
            name: path.file_name().unwrap().to_string_lossy().into_owned(),
            source: std::fs::read_to_string(&path).expect("fixture"),
            language,
        });
    }
    // read_dir hands back whatever order the filesystem keeps, and the report is
    // supposed to compare equal between two machines that scored the same corpus.
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The strongest claim the rule set made about one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Detection {
    Confirmed,
    Suspect,
    Nothing,
    /// The grammar could not read the file. Not a miss: a miss is a rule that
    /// looked and found nothing, and this is a scan that never happened. Scoring
    /// it as a miss would blame the rule set for a parser problem, and scoring it
    /// as a detection would be worse.
    Unparsable,
}

fn classify(fixture: &Fixture, rules: &RuleSet) -> Detection {
    let (family, compiled) = rules.family(fixture.language);
    let Ok(parsed) = parse_as(&fixture.name, &fixture.source, fixture.language) else {
        return Detection::Unparsable;
    };
    let findings = detect(&parsed, compiled, family).findings;
    if findings
        .iter()
        .any(|f| f.confidence == Confidence::Confirmed)
    {
        Detection::Confirmed
    } else if findings.is_empty() {
        Detection::Nothing
    } else {
        Detection::Suspect
    }
}

/// Whether a cell is allowed to report a rate at all.
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum SampleStatus {
    /// Meets [`MINIMUM_LABELED_EGRESS_POINTS`]; the rates are release gates.
    Scored,
    /// Below it. Rates are reported as null, and the cell is out of the gate
    /// arithmetic entirely (`benchmarks.md`, "targets are read like this", rule 3).
    InsufficientSample,
}

/// Gaps the project has written down, read out of the corpus layout.
///
/// A file under `evasion/` is the declaration. The directory name is the label
/// and `docs/05-quality/known-gaps.md` carries the prose; nothing here reads the
/// file contents. This list used to be a Rust array in this file, and then a
/// marker string every fixture header had to repeat. Both had the same effect:
/// adding an evasion fixture turned the benchmark red until somebody found the
/// rule buried in a test and satisfied it, so contributors stopped adding them.
/// A corpus nobody dares extend measures less every release, which costs more
/// than the discipline the marker was buying.
fn catalogued_gaps(language_dir: &str) -> BTreeSet<String> {
    group(language_dir, EVASION)
        .into_iter()
        .map(|fixture| fixture.name)
        .collect()
}

/// One scored language.
#[derive(Debug, serde::Serialize)]
struct LanguageScore {
    language: String,
    /// Files labeled as containing egress: the sample this cell is measured on.
    labeled_egress_points: usize,
    sample_status: SampleStatus,
    /// Labeled files carrying at least one `confirmed` finding.
    detected_confirmed: usize,
    /// Labeled files whose strongest finding is `suspect`. Reported apart from
    /// the confirmed count because the HTTP rules report `suspect` by design:
    /// the destination is read out of a string literal, and a text match is not
    /// allowed to reach the confirmed list.
    detected_suspect_only: usize,
    /// Files labeled clean that produced a finding anyway.
    false_positives: usize,
    /// Labeled files with no finding, in the three buckets a miss can fall into.
    missed_catalogued: Vec<String>,
    /// Misses a rule was supposed to catch, held open against a named defect.
    /// Every entry here is a bug somebody owns, not a limit of the approach.
    missed_to_open_defect: Vec<String>,
    missed_uncatalogued: Vec<String>,
    /// `benchmarks.md` gate metric: confirmed findings only. Null below the
    /// minimum sample, because a rate over eight files is not a measurement.
    recall_file_unit_confirmed_basis_points: Option<u64>,
    /// Confirmed or suspect. Reported, never a gate.
    detection_rate_any_confidence_basis_points: Option<u64>,
}

fn score(language_dir: &str, rules: &RuleSet) -> LanguageScore {
    let catalogued = catalogued_gaps(language_dir);
    let defects = open_defects(language_dir);

    let mut labeled = 0usize;
    let mut detected_confirmed = 0usize;
    let mut detected_suspect_only = 0usize;
    let mut missed_catalogued = Vec::new();
    let mut missed_to_open_defect = Vec::new();
    let mut missed_uncatalogued = Vec::new();

    for fixture in group(language_dir, POSITIVE)
        .into_iter()
        .chain(group(language_dir, EVASION))
    {
        labeled += 1;
        match classify(&fixture, rules) {
            Detection::Confirmed => detected_confirmed += 1,
            Detection::Suspect => detected_suspect_only += 1,
            Detection::Unparsable => {
                missed_uncatalogued.push(format!("unparsable: {}", fixture.name));
            }
            Detection::Nothing if catalogued.contains(&fixture.name) => {
                missed_catalogued.push(fixture.name);
            }
            Detection::Nothing if defects.contains(&fixture.name) => {
                missed_to_open_defect.push(fixture.name);
            }
            Detection::Nothing => missed_uncatalogued.push(fixture.name),
        }
    }

    let mut false_positives = 0usize;
    for fixture in group(language_dir, NEGATIVE) {
        match classify(&fixture, rules) {
            Detection::Confirmed | Detection::Suspect => {
                false_positives += 1;
                missed_uncatalogued.push(format!("false positive: {}", fixture.name));
            }
            Detection::Unparsable => {
                missed_uncatalogued.push(format!("unparsable: {}", fixture.name));
            }
            Detection::Nothing => {}
        }
    }
    missed_uncatalogued.sort();

    let sample_status = if labeled >= MINIMUM_LABELED_EGRESS_POINTS {
        SampleStatus::Scored
    } else {
        SampleStatus::InsufficientSample
    };
    let rate = |detected: usize| {
        if sample_status == SampleStatus::InsufficientSample || labeled == 0 {
            None
        } else {
            Some((detected as u64 * 10_000) / labeled as u64)
        }
    };

    LanguageScore {
        language: language_dir.to_owned(),
        labeled_egress_points: labeled,
        recall_file_unit_confirmed_basis_points: rate(detected_confirmed),
        detection_rate_any_confidence_basis_points: rate(
            detected_confirmed + detected_suspect_only,
        ),
        sample_status,
        detected_confirmed,
        detected_suspect_only,
        false_positives,
        missed_catalogued,
        missed_to_open_defect,
        missed_uncatalogued,
    }
}

#[derive(Debug, serde::Serialize)]
struct BenchmarkResult {
    corpus: String,
    minimum_labeled_egress_points: usize,
    /// Says in the output itself which confidence level each rate counts, so a
    /// number lifted out of this file into a release note carries its own
    /// definition with it.
    confidence_counted: BTreeMap<&'static str, &'static str>,
    /// The defects the `missed_to_open_defect` entries point at, spelled out in
    /// the artefact so a reader of the numbers does not have to open a test to
    /// learn why a cell is down.
    open_defects: BTreeMap<String, &'static str>,
    languages: Vec<LanguageScore>,
    /// Recorded so a reader can tell a strong result from a small sample.
    sample_note: String,
}

fn confidence_legend() -> BTreeMap<&'static str, &'static str> {
    let mut legend = BTreeMap::new();
    legend.insert(
        "recall_file_unit_confirmed_basis_points",
        "confirmed only. A labeled file counts as detected when at least one \
         finding on it is confirmed. This is the metric benchmarks.md makes the \
         phase gate.",
    );
    legend.insert(
        "detection_rate_any_confidence_basis_points",
        "confirmed or suspect. A labeled file counts as detected when any \
         finding was produced. Reported and tracked, never a gate: the HTTP \
         rules report suspect by design, because they read the destination out \
         of a string literal and a text match may not reach the confirmed list.",
    );
    legend
}

#[test]
fn detection_benchmark() {
    let rules = RuleSet::load();
    let languages: Vec<LanguageScore> = CORPUS_LANGUAGES
        .iter()
        .map(|language| score(language, &rules))
        .collect();

    let result = BenchmarkResult {
        corpus: "fixtures".to_owned(),
        minimum_labeled_egress_points: MINIMUM_LABELED_EGRESS_POINTS,
        confidence_counted: confidence_legend(),
        open_defects: OPEN_DEFECTS
            .iter()
            .map(|(language, fixture, defect)| (format!("{language}/{fixture}"), *defect))
            .collect(),
        sample_note: "Bootstrap corpus only, and every cell is below the minimum \
                      sample. Fixtures are written by the same people who write \
                      the rules, so this measures whether the rules do what their \
                      authors intended, not whether that intent matches how \
                      libraries are used in practice. See test-corpus/README.md."
            .to_owned(),
        languages,
    };

    let out = repo_root().join("target/benchmark.json");
    if let Some(parent) = out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&out, serde_json::to_string_pretty(&result).unwrap());

    // Every uncatalogued miss fails the run, whatever the sample size. A gap is
    // either written down or it is a regression; there is no third state where
    // it is merely tolerated. This assertion, not the recall rate, is what keeps
    // a broken detector from passing while the corpus is still small.
    let mut problems: BTreeMap<&str, &Vec<String>> = BTreeMap::new();
    for language in &result.languages {
        if !language.missed_uncatalogued.is_empty() {
            problems.insert(language.language.as_str(), &language.missed_uncatalogued);
        }
    }
    assert!(
        problems.is_empty(),
        "uncatalogued misses, false positives or unparsable fixtures: {problems:?}"
    );

    for language in &result.languages {
        assert!(
            !language.missed_catalogued.is_empty(),
            "{} has no catalogued gap left, so its cell is measuring an empty \
             catalogue rather than the rules",
            language.language
        );

        match language.sample_status {
            // benchmarks.md rule 3, enforced rather than described: a cell under
            // the minimum sample reports the words and no number. Emitting a
            // rate here is how "8 of 8 fixtures" becomes "100 percent recall" in
            // somebody's release note.
            SampleStatus::InsufficientSample => assert!(
                language.recall_file_unit_confirmed_basis_points.is_none()
                    && language
                        .detection_rate_any_confidence_basis_points
                        .is_none(),
                "{} is below the minimum sample and must report no rate",
                language.language
            ),
            SampleStatus::Scored => {
                let recall = language
                    .recall_file_unit_confirmed_basis_points
                    .expect("a scored cell reports its gate metric");
                assert!(
                    recall >= RECALL_FLOOR_BASIS_POINTS,
                    "{} confirmed recall is {recall} basis points, below the \
                     declared floor of {RECALL_FLOOR_BASIS_POINTS}",
                    language.language
                );
            }
        }
    }
}

/// Every entry in the defect register is still a miss, and every miss held open
/// against a defect is in the register.
///
/// The error class this catches: an exemption outliving the bug it was written
/// for. Once the engine learns to resolve a Java receiver chain, these three
/// fixtures start producing findings, and an entry left behind would go on
/// excusing them, so the next regression on the same file would be scored as a
/// known problem and nothing would go red. Deleting the entry is the last step
/// of the fix, and this test is what makes that step compulsory.
#[test]
fn every_open_defect_is_still_open() {
    let rules = RuleSet::load();
    for language_dir in CORPUS_LANGUAGES {
        let registered = open_defects(language_dir);
        let observed: BTreeSet<String> = score(language_dir, &rules)
            .missed_to_open_defect
            .into_iter()
            .collect();
        assert_eq!(
            observed, registered,
            "{language_dir}: the open defect register and what is actually missed \
             have diverged. A fixture that is detected again must lose its entry; \
             a fixture named in the register must exist and still be missed."
        );
    }
}

/// Every rule family in the repository has a cell in the benchmark.
///
/// The error class this catches: a phase adds a language, ships rules and
/// fixtures for it, and leaves the benchmark scoring the old set. Nothing goes
/// red, the report still says "corpus: fixtures", and the new family is simply
/// unmeasured. That is exactly what happened to go and java between F1 and F2.
#[test]
fn every_rule_family_has_a_benchmark_cell() {
    let mut families: Vec<String> = std::fs::read_dir(repo_root().join("rules"))
        .expect("rules directory")
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        // `rules/masking/` is not a detector rule family. It holds the proxy's
        // affix rules for detection layer B, in a different rule language read
        // by a different loader (`proxy-policy.md` section 11), and it has no
        // corpus, no recall and nothing this benchmark could score. The name is
        // written out rather than inferred, for the same reason the loader
        // writes it out: a directory skipped because it "looked wrong" is how a
        // real language stops being measured.
        .filter(|name| name != "masking")
        .collect();
    families.sort();

    let scored: Vec<String> = CORPUS_LANGUAGES.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(
        families, scored,
        "a rule family without a benchmark cell is a language nobody is measuring"
    );
}
