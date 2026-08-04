#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! Reconciliation benchmark (milestone 59): what the attribution actually gets
//! right, and what nothing here is entitled to say.
//!
//! `docs/05-quality/benchmarks.md` section (c) makes two binding decisions about
//! this measurement, and both of them are about refusing a number rather than
//! producing one.
//!
//! **The false positive rate is conditioned on the environment class (K-15).** A
//! developer's laptop runs editor assistants, CLI agents, browsers and package
//! managers, and most of the traffic reaching a model provider from it does not
//! come from the codebase under scan. An unconditional "under five percent" would
//! be met on a CI runner and unmeetable on a laptop, so it is a release gate for
//! O1 and O2 and explicitly not one for O3, where the gate is attribution
//! accuracy instead.
//!
//! **A cell below the minimum sample reports no rate at all.** Two hundred
//! provider directed flows per class, and below that the cell says so instead of
//! printing a ratio nobody should act on.
//!
//! # What this file measures, and what it refuses to
//!
//! Measured, because it can be: **attribution accuracy**. Every flow in the
//! corpus below carries the bucket it belongs in, decided by how it was
//! constructed, and `ScopePolicy::classify` is asked which bucket it would place
//! it in. That is a real measurement of the code that decides whether a finding
//! may be raised at all, and it is the O3 gate metric. **Silent misses** come out
//! of the same comparison and are reported separately, because a flow wrongly
//! filed as somebody else's traffic disappears from the accounting without a
//! trace, which is worse than a wrong accusation somebody can argue with.
//!
//! Refused, because it cannot be measured here: **false positives and every rate
//! derived from them**. `benchmarks.md` defines a false positive as a finding
//! that manual verification found to be wrong, with the source of the flow
//! established from the process, the cgroup, the time and the destination. There
//! is no automated substitute for that. A synthetic corpus scores exactly what it
//! was written to score, so a number computed here would measure the fixture
//! author rather than the tool, and it would look identical in the release notes
//! to one that had been earned.
//!
//! Refused for the same reason: the **environment class**. This corpus was not
//! observed on a machine, so it belongs to no class and no class gate is
//! computed. The release measurement in O1, O2 and O3 is still owed and the
//! output below says so in a field a release check can read, rather than leaving
//! the absence to be noticed.
//!
//! What is left is a regression net over the part that is real, in the report
//! shape `benchmarks.md` fixes, with every unearned field carrying `null` and a
//! reason beside it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use periskop_core::finding::Kind;
use periskop_network_sensor::flow::{FiveTuple, Mechanism, ProcessRecord, Proto, SniSource};
use periskop_network_sensor::observation::Observation;
use periskop_network_sensor::{Flow, FlowScope, ScopePolicy};
use periskop_reconcile::settings::ReconcileSettings;

use periskop_cli::scan;

/// Minimum provider directed flows a cell needs before it may report a rate.
///
/// `benchmarks.md` section (c), "minimum sample". Stated here so the output can
/// say which side of it a measurement fell on rather than leaving the reader to
/// remember the number.
const MINIMUM_LABELED_FLOWS: usize = 200;

/// The O3 gate: the share of flows placed in the right bucket.
///
/// Ninety five percent in basis points. Applied to this corpus as a regression
/// floor rather than as a release gate, because a synthetic corpus cannot close
/// a gate defined over a developer's real machine.
const ATTRIBUTION_ACCURACY_FLOOR_BASIS_POINTS: u64 = 9_500;

/// The executable the corpus treats as the codebase under scan.
const CODEBASE_PROCESS: &str = "/srv/app/venv/bin/python3";
/// A destination the operator declared benign.
const BENIGN_HOST: &str = "telemetry.internal";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// One labeled flow: how it was built, and the bucket it therefore belongs in.
///
/// The label is not a second opinion about the classifier's answer. It is a fact
/// about how the observation was constructed, so a disagreement is the
/// classifier being wrong rather than two graders differing.
struct Labeled {
    case: &'static str,
    observation: Observation,
    truth: FlowScope,
}

fn observation(src_port: u16, dst_ip: &str) -> Observation {
    Observation::new(
        "h_9f2c4a17be0d5386",
        1_785_834_000,
        FiveTuple {
            src_port,
            dst_ip: dst_ip.to_owned(),
            dst_port: 443,
            proto: Proto::Tcp,
        },
        SniSource::ClientHello,
    )
    .with_boot_id("b_3f0a91c7d4e28b56")
    .with_volume(2_048, 8_192)
}

fn process(exe: Option<&str>, comm: Option<&str>) -> ProcessRecord {
    ProcessRecord {
        pid: 4_821,
        pid_start_time: Some(1_785_833_900),
        comm: comm.map(str::to_owned),
        exe: exe.map(str::to_owned),
        cmdline_hash: None,
    }
}

/// The corpus: one case per way the attribution can be right or wrong.
///
/// Small and deliberately so. Its size is reported beside the minimum sample so
/// nobody reads a rate off it, and every case is a distinct behaviour rather
/// than a repetition that would inflate the count without testing anything new.
fn corpus() -> Vec<Labeled> {
    use periskop_network_sensor::flow::ResolvedHostSource::DnsAndSni;

    vec![
        Labeled {
            case: "declared codebase process reaching a provider",
            observation: observation(54_321, "104.18.7.1")
                .resolved("api.openai.com", DnsAndSni)
                .with_provider_ref("openai")
                .kernel_attributed(process(Some(CODEBASE_PROCESS), Some("python3"))),
            truth: FlowScope::InScope,
        },
        Labeled {
            case: "declared codebase process reaching a second provider",
            observation: observation(54_322, "104.18.7.2")
                .resolved("api.anthropic.com", DnsAndSni)
                .with_provider_ref("anthropic")
                .kernel_attributed(process(Some(CODEBASE_PROCESS), Some("python3"))),
            truth: FlowScope::InScope,
        },
        Labeled {
            case: "an editor assistant on the same machine",
            observation: observation(54_323, "104.18.7.3")
                .resolved("api.openai.com", DnsAndSni)
                .with_provider_ref("openai")
                .kernel_attributed(process(
                    Some("/Applications/Editor.app/agent"),
                    Some("agent"),
                )),
            truth: FlowScope::OutOfScopeProcess,
        },
        Labeled {
            case: "a package manager on the same machine",
            observation: observation(54_324, "104.18.7.4")
                .resolved("registry.example", DnsAndSni)
                .kernel_attributed(process(Some("/usr/bin/pkg"), Some("pkg"))),
            truth: FlowScope::OutOfScopeProcess,
        },
        Labeled {
            case: "the codebase reaching a destination the operator declared benign",
            observation: observation(54_325, "10.0.0.9")
                .resolved(BENIGN_HOST, DnsAndSni)
                .kernel_attributed(process(Some(CODEBASE_PROCESS), Some("python3"))),
            truth: FlowScope::KnownBenign,
        },
        Labeled {
            case: "a connection nobody could attribute",
            observation: observation(54_326, "104.18.7.5")
                .resolved("api.openai.com", DnsAndSni)
                .with_provider_ref("openai"),
            truth: FlowScope::Undetermined,
        },
        Labeled {
            case: "a process the kernel named with neither a path nor a short name",
            observation: observation(54_327, "104.18.7.6")
                .resolved("api.openai.com", DnsAndSni)
                .with_provider_ref("openai")
                .kernel_attributed(process(None, None)),
            truth: FlowScope::Undetermined,
        },
        Labeled {
            case: "the codebase process named only by its short name",
            observation: observation(54_328, "104.18.7.7")
                .resolved("api.openai.com", DnsAndSni)
                .with_provider_ref("openai")
                .kernel_attributed(process(None, Some("python3"))),
            // The policy declares an executable path, and this record carries
            // only the short name. Filing it as somebody else's traffic is the
            // right answer: a short name is not evidence of ownership, and
            // guessing would produce the accusation the buckets exist to avoid.
            truth: FlowScope::OutOfScopeProcess,
        },
    ]
}

/// One environment class's cell in the benchmark table.
///
/// The field names are `benchmarks.md`'s, so a release note built from this file
/// and one built from a live measurement line up. Every field that was not
/// measured is `null` and its reason is in `not_measured`.
#[derive(Debug, serde::Serialize)]
struct BenchmarkReport {
    benchmark: &'static str,
    /// O1, O2 or O3, or the honest answer for a corpus nobody observed.
    environment_class: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    window: Option<String>,
    total_llm_flows: usize,
    minimum_sample: usize,
    meets_minimum_sample: bool,
    in_scope_flows: u64,
    out_of_scope_flows: u64,
    known_benign_flows: u64,
    unattributed_flows: u64,
    findings_emitted: usize,
    /// Null, always, in an automated run. A false positive is a finding manual
    /// verification found to be wrong, and there is no automated stand in.
    false_positives: Option<u64>,
    fp_rate: Option<String>,
    fp_rate_ci95: Option<String>,
    /// Measured. The share of flows placed in the bucket they belong in, in
    /// basis points, over the labeled corpus.
    attribution_accuracy_basis_points: u64,
    /// Flows wrongly filed as somebody else's traffic, which disappear from the
    /// accounting with nothing in the report to show they were seen.
    silent_misses: u64,
    /// Flows wrongly filed as the codebase's, which become accusations.
    wrong_in_scope_attributions: u64,
    /// Per case, so a drop names the behaviour that broke rather than a number.
    cases: BTreeMap<&'static str, &'static str>,
    not_measured: BTreeMap<&'static str, &'static str>,
}

fn write_report(report: &BenchmarkReport) {
    let out = repo_root().join("target/reconcile-benchmark.json");
    if let Some(parent) = out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&out, serde_json::to_string_pretty(report).unwrap());
}

struct ScanTree {
    root: PathBuf,
}

impl ScanTree {
    fn new(flows: &[Flow]) -> Self {
        // The counter, not only the process id. Both tests in this file run the
        // measurement and they run in parallel inside one process, so a name
        // built from the pid alone would have them deleting each other's tree.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let ordinal = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "periskop-reconcile-bench-{}-{ordinal}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("project")).unwrap();
        std::fs::create_dir_all(root.join("events")).unwrap();
        std::fs::create_dir_all(root.join("flows")).unwrap();
        // A project with no egress in it, so every finding in the report came
        // from the wire rather than from the code.
        std::fs::write(
            root.join("project/main.py"),
            "def add(left, right):\n    return left + right\n",
        )
        .unwrap();
        let body: String = flows
            .iter()
            .map(|flow| format!("{}\n", serde_json::to_string(flow).unwrap()))
            .collect();
        std::fs::write(root.join("flows/sensor-1.jsonl"), body).unwrap();
        Self { root }
    }

    fn scan(&self) -> scan::ScanOutcome {
        scan::run_with_sources(
            scan::ScanRequest {
                project_root: &self.root.join("project"),
                rules_root: &repo_root().join("rules"),
                tool_version: "0.0.0-test",
                generated_at: "2026-08-04T09:00:00Z".to_owned(),
            },
            scan::ScanSources {
                event_dir: Some(&self.root.join("events")),
                flow_dir: Some(&self.root.join("flows")),
            },
            ReconcileSettings::default(),
        )
    }
}

impl Drop for ScanTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Runs the measurement and returns what it established.
///
/// Both tests below call it rather than one reading a file the other wrote:
/// tests run in parallel, so a shared artefact would make the pair pass or fail
/// on scheduling. The measurement is cheap enough to run twice.
fn measure() -> (BenchmarkReport, scan::ScanOutcome) {
    let policy = ScopePolicy::for_codebase([CODEBASE_PROCESS.to_owned()])
        .with_declared_benign_host(BENIGN_HOST.to_owned());

    let mut cases: BTreeMap<&'static str, &'static str> = BTreeMap::new();
    let mut correct = 0u64;
    let mut silent_misses = 0u64;
    let mut wrong_in_scope = 0u64;
    let mut flows: Vec<Flow> = Vec::new();

    for labeled in corpus() {
        let placed = policy.classify(&labeled.observation);
        if placed == labeled.truth {
            correct += 1;
            cases.insert(labeled.case, labeled.truth.as_str());
        } else {
            cases.insert(labeled.case, "MISPLACED");
            // The two errors are not symmetric and are never added up. A flow
            // wrongly filed as somebody else's traffic vanishes from the
            // accounting; a flow wrongly filed as ours becomes an accusation
            // somebody can argue with.
            if labeled.truth == FlowScope::InScope {
                silent_misses += 1;
            }
            if placed == FlowScope::InScope {
                wrong_in_scope += 1;
            }
        }
        flows.push(
            Flow::from_observation(labeled.observation, placed, Mechanism::Ebpf)
                .expect("a record built from a corpus observation satisfies the contract"),
        );
    }

    let total = flows.len();
    let accuracy_basis_points = correct * 10_000 / total as u64;

    // The pipeline half: the same records through the shipped scan, so the
    // bucket counts in the report are the ones a reader would see.
    let tree = ScanTree::new(&flows);
    let outcome = tree.scan();
    let coverage = &outcome.report.coverage;
    let findings: Vec<_> = outcome
        .report
        .findings
        .iter()
        .chain(outcome.report.suspect_findings.iter())
        .filter(|finding| finding.kind == Kind::UnmatchedWireTraffic)
        .collect();

    let mut not_measured: BTreeMap<&'static str, &'static str> = BTreeMap::new();
    not_measured.insert(
        "false_positives",
        "a false positive is a finding manual verification found to be wrong, established from \
         the process, cgroup, time and destination. There is no automated substitute, and a \
         number computed over a synthetic corpus would measure the fixture author",
    );
    not_measured.insert(
        "fp_rate",
        "derived from false_positives, which was not measured",
    );
    not_measured.insert(
        "fp_rate_ci95",
        "derived from false_positives, which was not measured",
    );
    not_measured.insert(
        "environment_class",
        "this corpus was not observed on a machine, so it belongs to no class and no class gate \
         is computed. The O1 and O2 release gates and the O3 attribution measurement are still \
         owed and need scripted environments and a full working day of live traffic",
    );
    not_measured.insert(
        "window",
        "no observation window: the corpus was constructed rather than watched",
    );

    let report = BenchmarkReport {
        benchmark: "reconciliation (milestone 59)",
        environment_class: "none: synthetic corpus, not an environment measurement",
        window: None,
        total_llm_flows: total,
        minimum_sample: MINIMUM_LABELED_FLOWS,
        meets_minimum_sample: total >= MINIMUM_LABELED_FLOWS,
        in_scope_flows: coverage.in_scope_flows,
        out_of_scope_flows: coverage.out_of_scope_flows,
        known_benign_flows: coverage.known_benign_flows,
        unattributed_flows: coverage.unattributed_flows,
        findings_emitted: findings.len(),
        false_positives: None,
        fp_rate: None,
        fp_rate_ci95: None,
        attribution_accuracy_basis_points: accuracy_basis_points,
        silent_misses,
        wrong_in_scope_attributions: wrong_in_scope,
        cases,
        not_measured,
    };
    (report, outcome)
}

#[test]
fn reconciliation_benchmark_scores_what_it_can_measure_and_declares_what_it_cannot() {
    let (report, outcome) = measure();
    write_report(&report);

    let coverage = &outcome.report.coverage;
    let accuracy_basis_points = report.attribution_accuracy_basis_points;
    let silent_misses = report.silent_misses;
    let wrong_in_scope = report.wrong_in_scope_attributions;
    let total = report.total_llm_flows;

    // The regression net. None of these is the release gate, and the report says
    // so; what they catch is the attribution quietly getting worse between now
    // and the day somebody runs the live measurement.
    assert!(
        accuracy_basis_points >= ATTRIBUTION_ACCURACY_FLOOR_BASIS_POINTS,
        "attribution accuracy fell to {accuracy_basis_points} basis points: {:?}",
        report.cases
    );
    assert_eq!(
        silent_misses, 0,
        "a flow belonging to the codebase was filed as somebody else's traffic, which removes it \
         from the report with nothing to show it was seen: {:?}",
        report.cases
    );
    assert_eq!(wrong_in_scope, 0, "{:?}", report.cases);

    // Only `in_scope` produces the finding, which is milestone 56's acceptance
    // criterion and the reason the false positive rate is defined over that
    // bucket alone.
    assert_eq!(
        report.findings_emitted as u64, coverage.in_scope_flows,
        "the accusation count and the only bucket entitled to produce one disagree: {:?}",
        outcome.report
    );

    // The other three buckets are counted and visible. A bucket that keeps flows
    // out of the accounting and then vanishes from the report is the silent
    // swallow K-15 exists to prevent, and it is what would make the conditioned
    // false positive definition unauditable.
    assert_eq!(
        coverage.in_scope_flows
            + coverage.out_of_scope_flows
            + coverage.known_benign_flows
            + coverage.unattributed_flows,
        total as u64,
        "flows went missing between the sensor and the coverage statement: {:?}",
        coverage
    );
    assert!(coverage.out_of_scope_flows > 0 && coverage.known_benign_flows > 0);
}

#[test]
fn the_benchmark_never_prints_a_false_positive_rate_it_did_not_earn() {
    // The failure this prevents is a release note. A cell reading `fp_rate: 0%`
    // over a synthetic corpus is indistinguishable from one earned on a scripted
    // O1 environment, and it would close a gate nobody measured.
    let (measured, _) = measure();
    let report: serde_json::Value = serde_json::to_value(&measured).unwrap();

    assert!(report["false_positives"].is_null(), "{report}");
    assert!(report["fp_rate"].is_null(), "{report}");
    assert!(report["fp_rate_ci95"].is_null(), "{report}");
    assert!(
        report["not_measured"]["false_positives"].is_string(),
        "{report}"
    );
    assert!(
        report["not_measured"]["environment_class"].is_string(),
        "{report}"
    );
    assert!(
        !measured.meets_minimum_sample,
        "the corpus grew past the minimum sample, which would let a rate be read off it: {report}"
    );
}
