#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
//! **Milestone 96, F4 exit criterion 6 (partial).** The masking quality
//! benchmark's **runner**, section (b) of `docs/05-quality/benchmarks.md`.
//!
//! # This file produces a runner, not a number
//!
//! The measurement it exists for cannot run here, and that is a property of the
//! measurement rather than a gap in this file. Section (b) compares two runs of
//! the same prompt: one **masked** through periskop, and one **raw**, which sends
//! unmasked personal data to a real model provider. That second run is the exact
//! thing this product exists to prevent, it costs money at a provider, and
//! CLAUDE.md forbids periskop from being an egress source. So it never runs in
//! continuous integration, and the numbers in a release note come from an
//! operator's own recorded session with a funded key.
//!
//! What runs here is everything around the number:
//!
//! | Half | Runs where |
//! |---|---|
//! | the consent gate, the funded key check, the sample floor, the corpus rule | everywhere, as ordinary tests over a total function |
//! | the mechanical half: masking, alias generation, restoration, the counters | everywhere, against a stub upstream, offline |
//! | the scored half: raw run, masked run, degradation | an operator's machine, with a key and a pinned model snapshot, and nowhere else |
//!
//! # The three ways this runner refuses
//!
//! Each one exists because the alternative is worse than not measuring.
//!
//! 1. **No consent flag, no live run.** `benchmarks.md`'s data rule: the task set
//!    is synthetic, running it against real organisational data is forbidden, and
//!    the runner "`--i-understand-synthetic-only` bayrağı olmadan çalışmaz". The
//!    warning goes to standard output whether or not the flag is there, because
//!    somebody reading it is how the flag gets thought about.
//! 2. **No funded key or no pinned model snapshot, no scores.** Not an empty
//!    result: an empty result is indistinguishable from a run that measured
//!    perfect fidelity. The artefact says which of the two was missing.
//! 3. **Fewer than five repetitions, no score at all.** `benchmarks.md` binding
//!    rule 3, and the reason is in rule 3 of the same section: language models are
//!    not deterministic at `temperature = 0`, so a mean over four runs is a
//!    number about scheduling. The cell reports "insufficient sample" instead.
//!
//! # What is deliberately not a field
//!
//! **Checksum and validator pass rates.** K-16 and P-0: no generator may produce
//! a value that could be allocated to a real person, so an `IBAN` alias is
//! parseable and deliberately invalid. An early draft of `benchmarks.md` assumed
//! the opposite and carried "downstream validators do not break" as an
//! acceptance criterion. That assumption is void, and a runner with a
//! `checksum_pass_rate` field would quietly reintroduce it as a target somebody
//! optimises toward. `no_field_measures_whether_an_alias_passes_a_validator` is
//! what keeps it out.
//!
//! # The report shape
//!
//! `benchmarks.md` section (b) fixes it, and F3's `target/reconcile-benchmark.json`
//! fixes the honesty conventions: every unearned field is `null`, every `null` has
//! a reason in `not_measured`, and numbers a regression net may read but a release
//! note may not live under a name that says so.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{json, Value};

use periskop_proxy::http::gateway::{Clock, Gateway, Incoming};
use periskop_proxy::http::headers::{HeaderList, SESSION_HEADER};
use periskop_proxy::http::upstream::{Answer, Call, Pending, Unreachable, Upstream};
use periskop_proxy::http::AllowList;
use periskop_proxy::policy::Policy;
use periskop_proxy::vault::{Backing, OpenRequest, Passphrase, ProfileName, Vault};

/// The operator's consent that the data in this run is synthetic.
///
/// `benchmarks.md` writes it as `--i-understand-synthetic-only`. This runner is a
/// test binary, whose own argument list belongs to the harness, so the flag is an
/// environment variable that carries the flag's name. The awkwardness is not a
/// cost worth optimising away: a switch somebody has to look up is a switch
/// somebody thinks about.
const CONSENT: &str = "PERISKOP_I_UNDERSTAND_SYNTHETIC_ONLY";
/// The funded provider key. Read only to decide whether a live run is possible;
/// never rendered, never logged, and never written to the artefact.
const API_KEY: &str = "PERISKOP_BENCHMARK_API_KEY";
/// The pinned model snapshot both runs use. A comparison across two snapshots is
/// not a comparison (`benchmarks.md` section (b) point 2).
const MODEL_SNAPSHOT: &str = "PERISKOP_BENCHMARK_MODEL_SNAPSHOT";
/// Repetitions per task.
const REPETITIONS: &str = "PERISKOP_BENCHMARK_N";
/// A corpus the operator supplied instead of the built in one.
const CORPUS: &str = "PERISKOP_BENCHMARK_CORPUS";

/// `benchmarks.md` section (b) point 3.
const MINIMUM_REPETITIONS: usize = 5;

/// What the runner prints before it does anything.
const SYNTHETIC_ONLY_WARNING: &str = "\
  periskop masking quality benchmark, benchmarks.md section (b).\n  \
  THE RAW HALF OF THIS BENCHMARK SENDS UNMASKED DATA TO A REAL MODEL PROVIDER.\n  \
  That is the opposite of what this product does, and it is the only way to\n  \
  measure what masking costs. Run it with synthetic data and with nothing else.\n  \
  Running it against real organisational data is forbidden (benchmarks.md, data\n  \
  rule). Set PERISKOP_I_UNDERSTAND_SYNTHETIC_ONLY=1 to say that the data in this\n  \
  run is invented.";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// What the operator asked for.
///
/// A struct rather than five reads of the environment, so the decision below is a
/// total function of its input and can be tested without a process wide variable
/// that other tests in this binary would race on.
#[derive(Clone, Debug, Default)]
struct Requested {
    consent: bool,
    has_funded_key: bool,
    model_snapshot: Option<String>,
    repetitions: usize,
    /// An operator supplied corpus, and whether it declares itself synthetic.
    corpus: Option<Corpus>,
}

#[derive(Clone, Debug)]
struct Corpus {
    path: String,
    declares_synthetic_only: bool,
}

/// Why a live run did not happen, or that it can.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Readiness {
    Refused { code: &'static str, reason: String },
    Ready { model_snapshot: String, n: usize },
}

/// The decision, in the order the reasons matter.
///
/// Consent first, because it is about the data rather than about the run: a
/// corpus of real customer records must not be read even to count it. The corpus
/// declaration second, for the same reason. Then the two things without which
/// there are no scores, then the sample floor.
fn readiness(requested: &Requested) -> Readiness {
    if !requested.consent {
        return Readiness::Refused {
            code: "consent_absent",
            reason: format!(
                "{CONSENT} is not set. The raw half of this benchmark sends unmasked data to a \
                 real provider, so it does not start until somebody says the data is synthetic. \
                 benchmarks.md, data rule: running this against real organisational data is \
                 forbidden"
            ),
        };
    }
    if let Some(corpus) = &requested.corpus {
        if !corpus.declares_synthetic_only {
            return Readiness::Refused {
                code: "corpus_not_declared_synthetic",
                reason: format!(
                    "the corpus at {} does not declare `synthetic_only = true`. The consent flag \
                     says the operator understands the rule; the declaration says this particular \
                     file follows it, and one is not the other",
                    corpus.path
                ),
            };
        }
    }
    if !requested.has_funded_key {
        return Readiness::Refused {
            code: "funded_key_absent",
            reason: format!(
                "{API_KEY} is not set. The raw and masked runs both go to a real provider and \
                 both cost money; with no key there is nothing to score. This is reported rather \
                 than returned as an empty result, because an empty result reads the same as a \
                 run that measured no degradation at all"
            ),
        };
    }
    let Some(snapshot) = requested
        .model_snapshot
        .as_deref()
        .filter(|snapshot| !snapshot.is_empty())
    else {
        return Readiness::Refused {
            code: "model_snapshot_absent",
            reason: format!(
                "{MODEL_SNAPSHOT} is not set. benchmarks.md section (b) point 2: both runs use one \
                 pinned model snapshot and masking is the only variable. A comparison across two \
                 snapshots measures the provider's release notes"
            ),
        };
    };
    if requested.repetitions < MINIMUM_REPETITIONS {
        return Readiness::Refused {
            code: "insufficient_sample",
            reason: format!(
                "{REPETITIONS} is {}, and benchmarks.md section (b) point 3 requires at least \
                 {MINIMUM_REPETITIONS}. Language models are not deterministic at temperature \
                 zero, so a mean over fewer runs is a number about scheduling. The cell reports \
                 insufficient sample rather than a score",
                requested.repetitions
            ),
        };
    }
    Readiness::Ready {
        model_snapshot: snapshot.to_owned(),
        n: requested.repetitions,
    }
}

fn requested_from_environment() -> Requested {
    Requested {
        consent: std::env::var_os(CONSENT).is_some_and(|value| !value.is_empty()),
        // Presence only. The value is a credential and this process has no reason
        // to hold it: `proxy/spec.md` section 2.3 says periskop does not store,
        // mint or log a key, and an artefact writer that had one in scope is one
        // refactor away from printing it.
        has_funded_key: std::env::var_os(API_KEY).is_some_and(|value| !value.is_empty()),
        model_snapshot: std::env::var(MODEL_SNAPSHOT).ok(),
        repetitions: std::env::var(REPETITIONS)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        corpus: std::env::var(CORPUS).ok().map(|path| Corpus {
            declares_synthetic_only: std::fs::read_to_string(&path)
                .is_ok_and(|text| text.contains("synthetic_only = true")),
            path,
        }),
    }
}

// ---------------------------------------------------------------------------
// The task set
// ---------------------------------------------------------------------------

/// One of `benchmarks.md` section (b)'s four task classes.
struct TaskClass {
    name: &'static str,
    /// The primary metric the live run would score. Named here so the artefact
    /// says what is missing rather than only that something is.
    primary_metric: &'static str,
    /// The masking policy this class runs under.
    policy: &'static str,
    /// The prompts. Synthetic, invented here, and the only data this file has.
    prompts: Vec<String>,
    /// A note the artefact carries for the class.
    note: &'static str,
}

/// Synthetic values, assembled at run time for the reason
/// `tests/no_credential_literals.rs` gives.
fn iban() -> String {
    format!("TR{}", "330006100519786457841326")
}

fn phone() -> String {
    format!("+90 {} {} {}", "532", "000", "4455")
}

fn card() -> String {
    format!("{} {} {} {}", "4111", "1111", "1111", "1111")
}

fn task_classes() -> Vec<TaskClass> {
    vec![
        TaskClass {
            name: "structured_extraction",
            primary_metric: "field by field exact match rate",
            policy: "",
            prompts: vec![
                format!(
                    "Fatura metnini JSON'a cevir. Hesap {}, telefon {}, eposta \
                     zeynep.kucukates@ornek-firma-a.invalid, tutar 1240 TL.",
                    iban(),
                    phone()
                ),
                format!(
                    "Su odeme kaydini alanlarina ayir: kart {}, iletisim \
                     mert.ayhanoglu@ornek-firma-b.invalid, tarih 2026-03-11.",
                    card()
                ),
            ],
            note: "the cleanest signal in the set: the effect of masking is visible field by \
                   field",
        },
        TaskClass {
            name: "free_text_summary",
            primary_metric: "entity aware check: whether the masked entities are restored \
                             correctly in the summary",
            policy: "",
            prompts: vec![
                format!(
                    "Su destek kaydini ozetle. Musteri {} numarasindan aradi, iade talebi \
                     acti, hesabi {} olarak verdi.",
                    phone(),
                    iban()
                ),
                "Su gorusmeyi ozetle: kullanici selin.bayraktaroglu@ornek-firma-c.invalid \
                 adresinden yazdi ve faturasinin iki kez kesildigini soyledi."
                    .to_owned(),
            ],
            note: "ROUGE-L is informative only: n-gram overlap falls on aliased text for \
                   reasons that have nothing to do with masking quality (D-10 finding 48)",
        },
        TaskClass {
            name: "multi_turn_dialogue",
            primary_metric: "task completion rate",
            policy: "",
            prompts: vec![
                format!(
                    "Merhaba, {} numarali hattimla ilgili bir sorun var.",
                    phone()
                ),
                format!(
                    "Evet, iade {} hesabina yapilsin. Onceki mesajimdaki numarayi da teyit et.",
                    iban()
                ),
                "Tesekkurler, ozet gecer misin?".to_owned(),
            ],
            note: "the turns share one session on purpose: this class also measures whether \
                   restoration stays consistent across a conversation",
        },
        TaskClass {
            name: "code_assistance",
            primary_metric: "unit test pass rate",
            // `benchmarks.md`: this class runs **only** under
            // `code_block_policy = "full"`. Under the default `pattern-only` there
            // is almost no masking inside a fenced block, so the class would
            // measure noise (D-10 finding 48).
            policy: "code_block_policy = \"full\"",
            prompts: vec![format!(
                "Su fonksiyondaki hatayi bul:\n```python\ndef pay(account):\n    \
                 return charge(\"{}\", account)\n```",
                iban()
            )],
            note: "runs only under code_block_policy = full; under the default there is almost \
                   nothing masked inside a fence and the class measures noise",
        },
    ]
}

// ---------------------------------------------------------------------------
// The mechanical half
// ---------------------------------------------------------------------------

/// A provider that answers with the masked text it was given.
///
/// Not a model, and the artefact says so: what it measures is the part of the
/// pipeline that has no model in it. The round trip through it is real, though —
/// real masking, a real vault write, a real frozen automaton and real
/// restoration.
struct EchoesWhatItWasSent;

impl Upstream for EchoesWhatItWasSent {
    fn send(&self, call: Call) -> Pending<'_> {
        let document: Value = serde_json::from_slice(&call.body).unwrap_or(Value::Null);
        let text = document["messages"]
            .as_array()
            .and_then(|messages| messages.last())
            .and_then(|message| message["content"].as_str())
            .unwrap_or_default()
            .to_owned();
        let answer = Answer::whole(
            200,
            HeaderList::new().with("content-type", "application/json"),
            json!({
                "choices": [{"index": 0, "message": {"role": "assistant", "content": text}}]
            })
            .to_string()
            .into_bytes(),
        );
        Box::pin(async move { Ok::<Answer, Unreachable>(answer) })
    }
}

/// What one task class's offline run established.
#[derive(Debug, Default)]
struct Mechanical {
    inputs: usize,
    masked_entities: u64,
    by_type: BTreeMap<String, u64>,
    ladder_rungs: BTreeMap<String, u64>,
    alias_pool_exhausted: u64,
    aliases_seen: u64,
    aliases_restored_exact: u64,
    aliases_leaked: u64,
    /// Every planted value came back out of the round trip.
    values_recovered: usize,
}

fn run_offline(class: &TaskClass) -> Mechanical {
    // No rule about dates. The corpus has an invoice with a date on it, and a
    // benchmark that had to write a rule to survive its own corpus would be
    // measuring a configuration nobody deploys: `date_policy` defaults to
    // `allow` (`proxy-policy.md` section 4, K-18), so the default policy is what
    // this runs under. The rule that used to be here was a workaround for a
    // defect in the request path, and it is gone with the defect.
    let policy = Policy::load(
        &format!(
            "policy_id = \"benchmark\"\npolicy_version = \"1\"\n{}\n\
             [default]\nmode = \"mask\"\n",
            class.policy
        ),
        Path::new("."),
        None,
    )
    .unwrap_or_else(|refusal| panic!("{refusal}"));
    let vault = Vault::open(&OpenRequest {
        passphrase: &Passphrase::new(b"the operator typed this".to_vec()),
        profile: ProfileName::Ci,
        backing: Backing::Memory,
    })
    .unwrap_or_else(|refusal| panic!("{refusal}"));
    let gateway = Gateway::new(
        policy,
        vault,
        Arc::new(EchoesWhatItWasSent) as Arc<dyn Upstream>,
        AllowList::shipped(),
        Clock::Fixed(1_700_000_000_000),
    )
    .unwrap_or_else(|refusal| panic!("{}", refusal.detail()));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut measured = Mechanical::default();
    let mut answers = Vec::new();
    for (turn, prompt) in class.prompts.iter().enumerate() {
        measured.inputs += 1;
        let response = runtime.block_on(
            gateway.handle(Incoming {
                method: "POST".to_owned(),
                path: "/v1/chat/completions".to_owned(),
                query: None,
                headers: HeaderList::new()
                    // The multi turn class keeps one session so that restoration
                    // across turns is exercised; the others get a session per turn.
                    .with(
                        SESSION_HEADER,
                        if class.name == "multi_turn_dialogue" {
                            class.name.to_owned()
                        } else {
                            format!("{}-{turn}", class.name)
                        },
                    ),
                body: json!({
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": prompt}]
                })
                .to_string()
                .into_bytes(),
            }),
        );
        answers.push(String::from_utf8_lossy(&response.body).into_owned());
    }

    for event in gateway.events() {
        let document: Value = serde_json::from_str(&event.to_json()).unwrap();
        for entry in document["entities_masked"].as_array().into_iter().flatten() {
            let count = entry["count"].as_u64().unwrap_or(0);
            measured.masked_entities += count;
            *measured
                .by_type
                .entry(entry["type"].as_str().unwrap_or("?").to_owned())
                .or_insert(0) += count;
        }
        for (_, stat) in document["alias_stats"]["by_type"]
            .as_object()
            .into_iter()
            .flatten()
        {
            *measured
                .ladder_rungs
                .entry(stat["ladder_rung"].as_str().unwrap_or("?").to_owned())
                .or_insert(0) += stat["count"].as_u64().unwrap_or(0);
        }
        measured.alias_pool_exhausted += document["alias_stats"]["alias_pool_exhausted"]
            .as_u64()
            .unwrap_or(0);
        measured.aliases_seen += document["restore_stats"]["aliases_seen_in_response"]
            .as_u64()
            .unwrap_or(0);
        measured.aliases_restored_exact += document["restore_stats"]["aliases_restored"]
            .as_u64()
            .unwrap_or(0);
        measured.aliases_leaked += document["restore_stats"]["aliases_leaked"]
            .as_u64()
            .unwrap_or(0);
    }

    // The round trip claim: what the client got back holds the values the client
    // sent. Counted rather than asserted here so the artefact can carry it.
    for (prompt, answer) in class.prompts.iter().zip(&answers) {
        let planted = planted_in(prompt);
        // Only the inputs that planted something. A turn with nothing in it
        // recovers everything it planted, vacuously, and counting that would let
        // the corpus lift its own recovery rate by adding pleasantries.
        if planted.is_empty() {
            continue;
        }
        if planted.iter().all(|value| answer.contains(value)) {
            measured.values_recovered += 1;
        }
    }
    measured
}

/// Every synthetic value this file plants in a prompt.
///
/// The round trip claim is checked against these: whatever was masked on the way
/// out has to be back, byte for byte, in what the client received.
fn synthetic_values() -> Vec<String> {
    vec![
        iban(),
        phone(),
        card(),
        "zeynep.kucukates@ornek-firma-a.invalid".to_owned(),
        "mert.ayhanoglu@ornek-firma-b.invalid".to_owned(),
        "selin.bayraktaroglu@ornek-firma-c.invalid".to_owned(),
    ]
}

/// The synthetic values one prompt carries.
fn planted_in(prompt: &str) -> Vec<String> {
    synthetic_values()
        .into_iter()
        .filter(|value| prompt.contains(value))
        .collect()
}

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

#[test]
fn the_masking_quality_benchmark_runs_what_it_can_and_declares_what_it_cannot() {
    // Always, and before anything else. Somebody reading this line is how the
    // consent flag gets thought about rather than copied from a wiki page.
    println!("\n{SYNTHETIC_ONLY_WARNING}\n");

    let requested = requested_from_environment();
    let readiness = readiness(&requested);
    if let Readiness::Refused { code, reason } = &readiness {
        println!(
            "  NO LIVE RUN: {code}\n  {reason}\n  The mechanical half below still runs offline \
             against a stub provider. It measures the pipeline, not the model, and it closes no \
             part of F4 exit criterion 6.\n"
        );
    }

    let classes = task_classes();
    let cells: Vec<Value> = classes
        .iter()
        .map(|class| cell(class, &run_offline(class), &readiness))
        .collect();

    let document = artefact(&cells, &readiness, &requested);
    write_artefact(&document);

    // The mechanical claims, which are the ones this run is entitled to make.
    for (class, cell) in classes.iter().zip(&cells) {
        assert!(
            cell["masked_entity_density"].as_f64().unwrap_or(0.0) > 0.0,
            "the {} class masked nothing, so its cell measures an empty detector rather than a \
             pipeline: {cell}",
            class.name
        );
        assert_eq!(
            cell["restore_recovery_rate"]["aliases_leaked"], 0,
            "an alias came back out of the {} class unresolved: {cell}",
            class.name
        );
        assert_eq!(
            cell["round_trip_inputs_fully_recovered"], cell["inputs_with_planted_values"],
            "a synthetic value did not survive the round trip in the {} class: {cell}",
            class.name
        );
    }

    // And the refusals, which are the rest of what it is entitled to say.
    if matches!(readiness, Readiness::Refused { .. }) {
        for cell in &cells {
            for unearned in [
                "raw_score_mean",
                "raw_score_ci95",
                "masked_score_mean",
                "masked_score_ci95",
                "degradation_pct",
                "degradation_ci95",
                "model_snapshot",
            ] {
                assert!(
                    cell[unearned].is_null(),
                    "{unearned} was published by a run that never reached a provider: {cell}"
                );
                assert!(
                    cell["not_measured"][unearned].is_string(),
                    "{unearned} is null with no reason beside it, which reads as an omission \
                     rather than as a refusal: {cell}"
                );
            }
            assert_eq!(cell["n"], 0);
        }
    }
}

/// One task class's row, in `benchmarks.md` section (b)'s field names.
fn cell(class: &TaskClass, measured: &Mechanical, readiness: &Readiness) -> Value {
    let mut not_measured = serde_json::Map::new();
    let (n, model_snapshot) = match readiness {
        Readiness::Ready { model_snapshot, n } => (*n, Some(model_snapshot.clone())),
        Readiness::Refused { code, reason } => {
            for unearned in [
                "raw_score_mean",
                "raw_score_ci95",
                "masked_score_mean",
                "masked_score_ci95",
            ] {
                not_measured.insert(unearned.to_owned(), json!(format!("{code}: {reason}")));
            }
            not_measured.insert(
                "degradation_pct".to_owned(),
                json!("derived from the two scores, neither of which was measured"),
            );
            not_measured.insert(
                "degradation_ci95".to_owned(),
                json!("derived from the two scores, neither of which was measured"),
            );
            not_measured.insert(
                "model_snapshot".to_owned(),
                json!(format!(
                    "no provider was called, so no snapshot answered. {code}: {reason}"
                )),
            );
            (0, None)
        }
    };
    not_measured.insert(
        "restore_recovery_rate.recovered_by_normalised_match".to_owned(),
        json!(
            "this build resolves an alias by exact string lookup and has no normalising \
               matcher, so there is no second recovery path to report. benchmarks.md's extra \
               metric (D-10 finding 32) splits exact from normalised recovery precisely because \
               a model reformatting a format preserving alias is the design's known tension; \
               until the matcher exists, the split is one number and an absence"
        ),
    );

    json!({
        "task_class": class.name,
        "primary_metric": class.primary_metric,
        "note": class.note,
        "masking_profile": "pattern+dictionary",
        "n": n,
        "minimum_sample": MINIMUM_REPETITIONS,
        "meets_minimum_sample": n >= MINIMUM_REPETITIONS,
        "raw_score_mean": Value::Null,
        "raw_score_ci95": Value::Null,
        "masked_score_mean": Value::Null,
        "masked_score_ci95": Value::Null,
        "degradation_pct": Value::Null,
        "degradation_ci95": Value::Null,
        "model_snapshot": model_snapshot,
        // Measured, because it can be: entities masked per input, and the split
        // by type that says which type moves the quality number.
        "masked_entity_density": ratio(measured.masked_entities, measured.inputs as u64),
        "masked_entity_density_by_type": measured
            .by_type
            .iter()
            .map(|(name, count)| (name.clone(), json!(ratio(*count, measured.inputs as u64))))
            .collect::<serde_json::Map<String, Value>>(),
        "ladder_rung_distribution": measured
            .ladder_rungs
            .iter()
            .map(|(rung, count)| (rung.clone(), json!(count)))
            .collect::<serde_json::Map<String, Value>>(),
        // `benchmarks.md` P-0 point 3: a run whose pool ran out is marked, and its
        // quality number never shares a column with one whose pool did not.
        "alias_pool_exhausted": measured.alias_pool_exhausted,
        "alias_pool_exhausted_run": measured.alias_pool_exhausted > 0,
        "restore_recovery_rate": {
            "aliases_seen_in_response": measured.aliases_seen,
            "recovered_by_exact_match": measured.aliases_restored_exact,
            "recovered_by_normalised_match": Value::Null,
            "aliases_leaked": measured.aliases_leaked,
        },
        "inputs": measured.inputs,
        "inputs_with_planted_values": class
            .prompts
            .iter()
            .filter(|prompt| !planted_in(prompt).is_empty())
            .count(),
        "round_trip_inputs_fully_recovered": measured.values_recovered,
        "not_measured": Value::Object(not_measured),
    })
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    ((numerator as f64) / (denominator as f64) * 1000.0).round() / 1000.0
}

fn artefact(cells: &[Value], readiness: &Readiness, requested: &Requested) -> Value {
    let (status, refusal) = match readiness {
        Readiness::Ready { .. } => ("live_run_ready", Value::Null),
        Readiness::Refused { code, reason } => {
            ("mechanical_only", json!({"code": code, "reason": reason}))
        }
    };

    json!({
        "benchmark": "masking quality, benchmarks.md section (b) (milestone 96)",
        "criterion": "roadmap.md F4 exit criterion 6, partial",
        "status": status,
        "live_run_refusal": refusal,
        "masking_profile": "pattern+dictionary",
        "profile_note": "the gate run of this benchmark measures the core profile only. NER is \
                         off by default (K-11) and F4 has no code path for it, so free text \
                         personal names outside the organisation's word list are not masked here \
                         and these results do not generalise to a build with layer C",
        "consent_flag": CONSENT,
        "consent_given": requested.consent,
        "synthetic_only_warning": SYNTHETIC_ONLY_WARNING,
        "cells": cells,
        "what_ran": "the mechanical half: real masking, real alias generation, a real vault \
                     write, a real frozen automaton and real restoration, against a stub \
                     provider that echoes what it was sent",
        "what_did_not_run": "the scored half: the raw run that sends unmasked data to a real \
                             provider, the masked run beside it, and the degradation between \
                             them. It needs a funded key and a pinned model snapshot, it costs \
                             money, and CLAUDE.md forbids periskop from being an egress source, \
                             so it never runs in continuous integration. The numbers in a release \
                             note come from an operator's recorded session",
        "not_a_metric": "checksum and validator pass rates. P-0 (K-16) forbids any generator from \
                         producing a value that could be allocated to a real person, so a format \
                         preserving alias is parseable and deliberately invalid. A pass rate \
                         field would reintroduce the void assumption as a target",
    })
}

fn write_artefact(document: &Value) {
    let out = repo_root().join("target/masking-quality-benchmark.json");
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut rendered = serde_json::to_string_pretty(document).unwrap();
    rendered.push('\n');
    std::fs::write(&out, rendered)
        .unwrap_or_else(|why| panic!("{} could not be written: {why}", out.display()));
}

// ---------------------------------------------------------------------------
// The gate, tested without a process wide variable
// ---------------------------------------------------------------------------

#[test]
fn the_runner_does_not_start_a_live_run_without_the_consent_flag() {
    let refused = readiness(&Requested {
        consent: false,
        has_funded_key: true,
        model_snapshot: Some("gpt-4o-2026-05-01".to_owned()),
        repetitions: 20,
        corpus: None,
    });
    let Readiness::Refused { code, reason } = refused else {
        panic!("a live run started with everything ready except the consent nobody gave");
    };
    assert_eq!(code, "consent_absent");
    assert!(reason.contains(CONSENT), "{reason}");
}

#[test]
fn a_corpus_that_does_not_declare_itself_synthetic_is_refused() {
    // The consent flag and the corpus declaration are two different statements:
    // one says the operator knows the rule, the other says this file follows it.
    // A runner that took the first for the second would let a directory of real
    // support tickets through on the strength of an environment variable set last
    // month.
    let refused = readiness(&Requested {
        consent: true,
        has_funded_key: true,
        model_snapshot: Some("gpt-4o-2026-05-01".to_owned()),
        repetitions: 20,
        corpus: Some(Corpus {
            path: "/tmp/tickets.jsonl".to_owned(),
            declares_synthetic_only: false,
        }),
    });
    let Readiness::Refused { code, .. } = refused else {
        panic!("an undeclared corpus was accepted");
    };
    assert_eq!(code, "corpus_not_declared_synthetic");

    // And a declared one gets through, or the check is a wall rather than a gate.
    assert!(matches!(
        readiness(&Requested {
            corpus: Some(Corpus {
                path: "/tmp/synthetic.jsonl".to_owned(),
                declares_synthetic_only: true,
            }),
            consent: true,
            has_funded_key: true,
            model_snapshot: Some("gpt-4o-2026-05-01".to_owned()),
            repetitions: 20,
        }),
        Readiness::Ready { .. }
    ));
}

#[test]
fn a_run_without_a_funded_key_or_a_pinned_snapshot_says_which_one_was_missing() {
    // Neither may produce a silent empty result: an empty result is
    // indistinguishable in a report from a run that measured no degradation.
    let no_key = readiness(&Requested {
        consent: true,
        has_funded_key: false,
        model_snapshot: Some("gpt-4o-2026-05-01".to_owned()),
        repetitions: 20,
        corpus: None,
    });
    let Readiness::Refused { code, reason } = no_key else {
        panic!("a live run started with no key to pay for it");
    };
    assert_eq!(code, "funded_key_absent");
    assert!(!reason.is_empty());

    let no_snapshot = readiness(&Requested {
        consent: true,
        has_funded_key: true,
        model_snapshot: None,
        repetitions: 20,
        corpus: None,
    });
    let Readiness::Refused { code, reason } = no_snapshot else {
        panic!("a live run started with no pinned snapshot to compare within");
    };
    assert_eq!(code, "model_snapshot_absent");
    assert!(reason.contains(MODEL_SNAPSHOT), "{reason}");

    // An empty string is an absent snapshot, not a snapshot named "".
    assert!(matches!(
        readiness(&Requested {
            consent: true,
            has_funded_key: true,
            model_snapshot: Some(String::new()),
            repetitions: 20,
            corpus: None,
        }),
        Readiness::Refused {
            code: "model_snapshot_absent",
            ..
        }
    ));
}

#[test]
fn fewer_than_five_repetitions_reports_insufficient_sample_and_not_a_score() {
    for repetitions in 0..MINIMUM_REPETITIONS {
        let refused = readiness(&Requested {
            consent: true,
            has_funded_key: true,
            model_snapshot: Some("gpt-4o-2026-05-01".to_owned()),
            repetitions,
            corpus: None,
        });
        let Readiness::Refused { code, .. } = refused else {
            panic!("a score was allowed over {repetitions} repetitions");
        };
        assert_eq!(code, "insufficient_sample");
    }
    assert!(matches!(
        readiness(&Requested {
            consent: true,
            has_funded_key: true,
            model_snapshot: Some("gpt-4o-2026-05-01".to_owned()),
            repetitions: MINIMUM_REPETITIONS,
            corpus: None,
        }),
        Readiness::Ready { .. }
    ));
}

#[test]
fn a_refused_run_reports_every_score_as_null_with_its_reason() {
    // The failure this prevents is a release note built from an artefact whose
    // score fields are zero. Zero degradation and no measurement look identical
    // in a table, and the second is what happened.
    let refused = Readiness::Refused {
        code: "funded_key_absent",
        reason: "nothing paid for a request".to_owned(),
    };
    let classes = task_classes();
    let class = &classes[0];
    let produced = cell(class, &Mechanical::default(), &refused);

    for unearned in [
        "raw_score_mean",
        "masked_score_mean",
        "degradation_pct",
        "model_snapshot",
    ] {
        assert!(produced[unearned].is_null(), "{produced}");
        assert!(produced["not_measured"][unearned].is_string(), "{produced}");
    }
    assert_eq!(produced["n"], 0);
    assert_eq!(produced["meets_minimum_sample"], false);
}

#[test]
fn no_field_measures_whether_an_alias_passes_a_validator() {
    // K-16 and `benchmarks.md` P-0 point 1. The forbidden fields are looked for in
    // the produced document **and** in this file's own source, because the way
    // this comes back is somebody adding a helper called `checksum_pass_rate` and
    // wiring it in later.
    const FORBIDDEN: &[&str] = &[
        "checksum_pass_rate",
        "checksum_valid",
        "validator_pass_rate",
        "validator_pass",
        "passes_checksum",
        "downstream_validator",
    ];

    let classes = task_classes();
    let document = artefact(
        &classes
            .iter()
            .map(|class| {
                cell(
                    class,
                    &Mechanical::default(),
                    &Readiness::Ready {
                        model_snapshot: "gpt-4o-2026-05-01".to_owned(),
                        n: 20,
                    },
                )
            })
            .collect::<Vec<Value>>(),
        &Readiness::Ready {
            model_snapshot: "gpt-4o-2026-05-01".to_owned(),
            n: 20,
        },
        &Requested::default(),
    );
    let rendered = serde_json::to_string(&document).unwrap();
    let source = std::fs::read_to_string(Path::new(file!()))
        .or_else(|_| std::fs::read_to_string(repo_root().join(file!())))
        .expect("this file can read itself");

    for name in FORBIDDEN {
        assert!(
            !rendered.contains(name),
            "the benchmark reports {name}, which P-0 makes meaningless: a format preserving \
             alias is deliberately invalid, so a pass rate is a measurement of nothing that \
             somebody would then optimise"
        );
    }

    // And in the source, because the way this comes back is a helper added now
    // and wired into the report later. The list itself and the prose around it
    // are skipped: a scan that fired on its own declaration would be deleted by
    // the first person who read it.
    let mut offences = Vec::new();
    let mut inside_the_list = false;
    for (number, line) in source.lines().enumerate() {
        let code = line.trim_start();
        if code.starts_with("//") {
            continue;
        }
        if code.starts_with("const FORBIDDEN") {
            inside_the_list = true;
            continue;
        }
        if inside_the_list {
            inside_the_list = !code.starts_with("];");
            continue;
        }
        for name in FORBIDDEN {
            if code.contains(name) {
                offences.push(format!("line {}: {name}", number + 1));
            }
        }
    }
    assert!(
        offences.is_empty(),
        "a validator pass rate is being computed in this runner: {offences:#?}"
    );
    // And the artefact says out loud that it is not a metric, so the absence
    // reads as a decision rather than as an oversight.
    assert!(document["not_a_metric"].is_string());
}

#[test]
fn the_four_task_classes_of_the_contract_are_all_present() {
    let names: Vec<&str> = task_classes().iter().map(|class| class.name).collect();
    assert_eq!(
        names,
        vec![
            "structured_extraction",
            "free_text_summary",
            "multi_turn_dialogue",
            "code_assistance",
        ]
    );
    // The one class with a condition attached, checked rather than remembered.
    let code = task_classes()
        .into_iter()
        .find(|class| class.name == "code_assistance")
        .expect("the class exists");
    assert!(
        code.policy.contains("code_block_policy = \"full\""),
        "the code class ran under the default policy, where a fenced block is barely masked and \
         the class measures noise (benchmarks.md, D-10 finding 48)"
    );
}
