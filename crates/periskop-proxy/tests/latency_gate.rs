#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
//! **Milestone 95, F4 exit criterion 2.** The added latency measurement, and the
//! number this machine is not entitled to publish.
//!
//! # What is measured
//!
//! One p95, end to end, as a **difference**. A real client on loopback, a real
//! stub provider on loopback, and two paths between them: straight to the stub,
//! and through a real `periskop` gateway on a real socket. The added latency is
//! `p95(through the proxy) - p95(straight)`, and every part of the sentence is
//! load bearing:
//!
//! - **A difference**, because `performance-budgets.md` measures against a proxy
//!   free baseline. A machine that is slow answers slowly on both paths and the
//!   difference stays what the proxy costs.
//! - **One p95**, because D-10 finding 30 and `proxy/spec.md` section 6.3 both
//!   forbid adding the sub items up: the sum of the p95s of detection, minting,
//!   the vault write and the response walk is not the p95 of the whole, and it is
//!   always larger. The sub item table in `performance-budgets.md` is
//!   informative, and nothing here computes from it.
//! - **The median of three**, per `perf-budgets.md` section 2.3. One run does not
//!   decide.
//!
//! # What is not measured, and why this file says so loudly
//!
//! `perf-budgets.md` section 4 declares exactly one reference environment,
//! `ci-linux-4vcpu`, and then says the part that matters here: *"Geliştirme
//! makinesinde alınan bir ölçüm bu dosyaya yazılmaz; yerel ölçüm bir sinyaldir,
//! bir kanıt değil."* A development machine is not a reference environment. Two
//! measurements from different machines are not comparable, and a gate that
//! compares them reads noise as a regression and a regression as noise.
//!
//! So this file **measures**, and it **refuses to publish a verdict** unless the
//! run declares itself to be on the reference environment. The number it took is
//! in the artefact under `local_signal`, where the name says what it is not; the
//! budget verdict is `null` with its reason in `not_measured`; and
//! `perf-budgets.json` is not written. That is the same shape F3's reconciliation
//! benchmark used when it left the false positive rate `null` and wrote down why,
//! and it is the shape for the same reason: a number that looks earned and was
//! not is worse than an absent one, because nothing downstream can tell them
//! apart.
//!
//! Declaring the environment is deliberately awkward: `PERISKOP_PERF_ENVIRONMENT_ID`
//! has to be set to the identity in `perf-budgets.md`, and the job that sets it is
//! the job that runs on that hardware. A run that sets it on a laptop is somebody
//! writing a false statement, not somebody forgetting a flag.
//!
//! Setting it is not sufficient, and that is the second half of this file. The run
//! reads the machine's own cores, memory, architecture and operating system and
//! compares them with the declaration; a run that claims the reference environment
//! on a machine that does not match it **fails**, and publishes nothing. An
//! environment variable is a claim, and a claim nothing checks is how a two core
//! runner ends up owning the number a release note quotes.
//!
//! # Where the two numbers come from, and why they are here at all
//!
//! The threshold is `docs/05-quality/performance-budgets.md`'s, which
//! `perf-budgets.md` names as the document that wins on what a budget is. The
//! environment is `perf-budgets.md` section 4's, which owns where a budget is
//! measured. Neither document is published: `.gitignore` excludes `docs/`, so a
//! clone and every CI checkout carry none of it, and a gate that could only read
//! its threshold from there could not run in the one place it has to run. That
//! is not hypothetical, it is the state this file was audited in.
//!
//! So both numbers are carried here as well, and the copies are held to their
//! owners rather than left to drift. On every tree that has the documents, which
//! is every developer machine and every orchestrator run and therefore every tree
//! where a budget is ever edited, `the_carried_numbers_agree_with_the_documents_that_own_them`
//! parses both rows and fails if they disagree. On a tree that has none, it does
//! not skip quietly: it asserts that `docs/` is absent altogether, so a moved
//! document and a published tree cannot be mistaken for each other, and the
//! artefact records which of the two this run was in
//! `budget_source.agreement_with_document_checked`.
//!
//! The remaining gap is named rather than papered over: a published tree has no
//! normative statement of the threshold at all. What closes it is committing
//! `perf-budgets.json`'s `budgets[]` and `reference_environments[]`, which
//! `perf-budgets.md` section 1 already declares and whose schema is published.
//! Until then, relaxing this budget still takes a document edit and an ADR
//! reference (`performance-budgets.md`, "CI'da bütçe aşımı kuralı" item 4), and
//! this file turns red at the moment somebody does one without the other.
//!
//! # The budget rows
//!
//! Four, in `perf-budgets.json`'s own field names so they can be lifted verbatim
//! when a reference run happens. Three of them are `unmeasured`, and the schema
//! makes that a first class state by **forbidding** a `limit` beside it. One of
//! the three is new here: `proxy.added_latency_p95.hold_wait`. Milestone 92
//! requires `on_hold_timeout = "wait"` to appear as a separate line item, because
//! the 150 ms budget does not apply in a mode whose whole design is to stall
//! rather than emit a fragment. The previous wave raised it in
//! `hub/memory/interfaces.md` and recommended a separate `budget_id` over a new
//! schema field, on the grounds that it needs no contract change. This is that
//! row.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use periskop_proxy::http::gateway::{Clock, Gateway};
use periskop_proxy::http::listen::{Exposure, ListenAddress};
use periskop_proxy::http::route::Provider;
use periskop_proxy::http::serve::Listener;
use periskop_proxy::http::upstream::{RustlsUpstream, Upstream};
use periskop_proxy::http::AllowList;
use periskop_proxy::policy::Policy;
use periskop_proxy::vault::{Backing, OpenRequest, Passphrase, ProfileName, Vault};

/// How a run says which environment it is on.
const ENVIRONMENT_VARIABLE: &str = "PERISKOP_PERF_ENVIRONMENT_ID";

/// What a run that did not say is called.
const UNDECLARED_ENVIRONMENT: &str = "local-undeclared";

/// The document that owns what the budget is.
const BUDGET_DOCUMENT: &str = "docs/05-quality/performance-budgets.md";

/// The document that owns where the budget is measured.
const ENVIRONMENT_DOCUMENT: &str = "docs/06-delivery/perf-budgets.md";

/// Where a passing reference run writes the threshold and measurement file.
const PERF_BUDGETS_JSON: &str = "perf-budgets.json";

/// Requests per phase, per run. Enough that the 95th percentile is a percentile
/// rather than the second worst of a handful.
const SAMPLES_PER_PHASE: usize = 60;

/// Requests thrown away before each phase is timed.
///
/// The connection pool's first request pays a fresh TCP handshake and, against a
/// real provider, a TLS one. `performance-budgets.md` puts that outside the
/// budget in as many words, on the condition that a pool is used at all.
const WARMUP_REQUESTS: usize = 10;

/// Measurement rounds. The verdict is read off the median (`perf-budgets.md`
/// section 2.3).
const ROUNDS: usize = 3;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A document under `docs/`, if this tree has one.
///
/// `Option` and not a panic, and this is the constraint the whole of the next two
/// sections is shaped around: `.gitignore` excludes `docs/`, so a published clone
/// and every CI checkout carry none of it. A gate that read its threshold from
/// there could not run in the one place it has to run, which is exactly the state
/// this file was in when the criterion was audited as never having run.
fn read_document(relative: &str) -> Option<String> {
    std::fs::read_to_string(repo_root().join(relative)).ok()
}

/// Whether this is a tree that carries its internal documents at all.
///
/// A missing document in a tree that has `docs/` is a moved or renamed document,
/// which is a defect. A missing document in a tree that has no `docs/` is a
/// published clone. The two are told apart here rather than by a skip, the same
/// way `periskop-cli`'s command surface test tells them apart.
fn docs_are_present() -> bool {
    repo_root().join("docs").exists()
}

// ---------------------------------------------------------------------------
// The threshold
// ---------------------------------------------------------------------------

/// The binding budget: `performance-budgets.md`, proxy core profile.
///
/// A copy, and the reason it is one is `docs/` being unpublished rather than
/// anything about the number. It is not a copy that can drift: on any tree that
/// carries the document, `the_carried_numbers_agree_with_the_documents_that_own_them`
/// reads the row and fails if the two disagree. That is every developer machine
/// and every orchestrator run, which is where a budget is actually edited. What
/// closes the remaining gap is publishing `perf-budgets.json` with these rows in
/// it, so a published tree has something normative to read; that file is declared
/// in `perf-budgets.md` section 1 and nothing writes it yet except a passing
/// reference run.
const ADDED_LATENCY_BUDGET_MS: f64 = 150.0;

/// The same number as the document states it, or `None` if this tree has no
/// document to state it.
///
/// The row is found by what it says rather than by where it sits, so that adding
/// a component above it does not silently move the check onto another line.
fn budget_ms_in_document() -> Option<f64> {
    let text = read_document(BUDGET_DOCUMENT)?;
    let row = text
        .lines()
        .find(|line| {
            line.starts_with('|')
                && line.contains("çekirdek profil")
                && line.contains("Ek gecikme (p95)")
        })
        .unwrap_or_else(|| {
            panic!(
                "{BUDGET_DOCUMENT} no longer carries a proxy core profile row naming \
                 `Ek gecikme (p95)`, so the number this runner carries agrees with nothing"
            )
        });
    // Cell 3 of `| component | metric | budget | method |`: the leading pipe makes
    // the first split empty, so the budget cell is the fourth piece.
    let cell = row.split('|').nth(3).unwrap_or_else(|| {
        panic!("the proxy core profile row in {BUDGET_DOCUMENT} has no budget column: {row}")
    });
    Some(budget_ms_in(cell).unwrap_or_else(|| {
        panic!(
            "the proxy core profile budget in {BUDGET_DOCUMENT} is no longer written as \
             `**< N ms**`, so it cannot be compared with the number this runner carries: {cell}"
        )
    }))
}

/// `**< 150 ms**` becomes `150.0`.
fn budget_ms_in(cell: &str) -> Option<f64> {
    let (_, after) = cell.split_once("**<")?;
    let (number, _) = after.split_once("ms**")?;
    number.trim().parse().ok()
}

// ---------------------------------------------------------------------------
// The reference environment
// ---------------------------------------------------------------------------

/// The reference environment as `perf-budgets.md` section 4 declares it.
#[derive(PartialEq, Eq, Debug)]
struct Declaration {
    environment_id: String,
    cpu_arch: String,
    cpu_cores: usize,
    memory_mib_min: u64,
    memory_mib_max: u64,
    os_id: String,
    os_version: String,
    vault_profile: String,
}

/// Every key section 4 is required to carry, and the whole of what it may carry.
///
/// Unknown keys are rejected rather than ignored, for the reason
/// `perf-budgets.schema.json` sets `additionalProperties: false`: a row nothing
/// reads looks like a declaration and constrains nothing.
const DECLARED_KEYS: [&str; 8] = [
    "environment_id",
    "cpu_arch",
    "cpu_cores",
    "memory_mib_min",
    "memory_mib_max",
    "os_id",
    "os_version",
    "vault_profile",
];

/// The declaration this runner carries, for the same reason the threshold is
/// carried: a published tree has no `perf-budgets.md` to read it from.
///
/// Every value here is checked twice. Against the document, wherever the document
/// exists, so an edit to section 4 that is not mirrored here turns the gate red on
/// the machine doing the editing. And against the machine, on every run, which is
/// what stops the identity in the workflow from being taken at its word.
fn declaration() -> Declaration {
    Declaration {
        environment_id: "ci-linux-4vcpu".to_owned(),
        cpu_arch: "x86_64".to_owned(),
        cpu_cores: 4,
        memory_mib_min: 15_000,
        memory_mib_max: 16_384,
        os_id: "ubuntu".to_owned(),
        os_version: "24.04".to_owned(),
        vault_profile: "ci".to_owned(),
    }
}

/// The same declaration as section 4 states it, or `None` in a published tree.
fn declaration_in_document() -> Option<Declaration> {
    let text = read_document(ENVIRONMENT_DOCUMENT)?;
    let mut rows: Vec<(String, String)> = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            // Matched on what the section is called rather than on its number, so
            // that inserting a section ahead of it does not point this at another
            // table. If it is renamed, nothing is found and the panic below says so.
            inside = heading.contains("Referans ortam beyanı");
            continue;
        }
        if !inside || !line.starts_with('|') {
            continue;
        }
        let mut cells = line.split('|').skip(1);
        let (Some(key), Some(value)) = (cells.next(), cells.next()) else {
            continue;
        };
        // The header and the separator carry no backticks, so they fall out here
        // without being named. A backticked key is the declaration's own shape.
        let (Some(key), Some(value)) = (backticked(key), backticked(value)) else {
            continue;
        };
        assert!(
            DECLARED_KEYS.contains(&key.as_str()),
            "{ENVIRONMENT_DOCUMENT} section 4 declares `{key}`, which nothing here reads. \
             A declared field the gate ignores constrains nothing"
        );
        rows.push((key, value));
    }

    let field = |name: &str| -> String {
        rows.iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| {
                panic!(
                    "{ENVIRONMENT_DOCUMENT} section 4 no longer declares `{name}`. The gate \
                     refuses to guess it: an environment that is half declared is one whose \
                     measurements are not comparable with anything"
                )
            })
    };
    let number = |name: &str| -> u64 {
        let raw = field(name);
        raw.parse().unwrap_or_else(|why| {
            panic!("{ENVIRONMENT_DOCUMENT} section 4 declares `{name}` as `{raw}`: {why}")
        })
    };

    Some(Declaration {
        environment_id: field("environment_id"),
        cpu_arch: field("cpu_arch"),
        cpu_cores: usize::try_from(number("cpu_cores")).unwrap_or(usize::MAX),
        memory_mib_min: number("memory_mib_min"),
        memory_mib_max: number("memory_mib_max"),
        os_id: field("os_id"),
        os_version: field("os_version"),
        vault_profile: field("vault_profile"),
    })
}

fn backticked(cell: &str) -> Option<String> {
    let trimmed = cell.trim();
    let inner = trimmed.strip_prefix('`')?.strip_suffix('`')?;
    (!inner.is_empty()).then(|| inner.to_owned())
}

// ---------------------------------------------------------------------------
// The machine, as it actually is
// ---------------------------------------------------------------------------

/// What could be read about this machine without adding a dependency to the
/// workspace.
///
/// Every field is optional because a fact that could not be read is not a fact
/// that matched. On the reference environment all of them are readable; anywhere
/// else the absence is what the artefact reports.
struct Runner {
    cpu_model: Option<String>,
    cpu_cores: Option<usize>,
    memory_mib: Option<u64>,
    os_id: Option<String>,
    os_version: Option<String>,
    cpu_arch: &'static str,
}

fn observe_runner() -> Runner {
    Runner {
        // Read at measurement time and never declared, which is what
        // `perf-budgets.md` section 4 requires: on a shared runner the processor
        // model can change between jobs, and writing one into the document would
        // be declaring something nobody measured.
        cpu_model: proc_cpuinfo_field("model name"),
        // Parallelism rather than a core count out of a file: it follows the cgroup
        // limit and the affinity mask, which is what a measurement on a shared
        // runner is actually running on.
        cpu_cores: std::thread::available_parallelism().ok().map(|n| n.get()),
        memory_mib: proc_meminfo_total_mib(),
        os_id: os_release_field("ID"),
        os_version: os_release_field("VERSION_ID"),
        cpu_arch: std::env::consts::ARCH,
    }
}

fn proc_cpuinfo_field(name: &str) -> Option<String> {
    let text = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == name).then(|| value.trim().to_owned())
    })
}

fn proc_meminfo_total_mib() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    text.lines().find_map(|line| {
        let rest = line.strip_prefix("MemTotal:")?;
        let kib: u64 = rest.trim().strip_suffix(" kB")?.trim().parse().ok()?;
        Some(kib / 1024)
    })
}

fn os_release_field(name: &str) -> Option<String> {
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    text.lines().find_map(|line| {
        let value = line.strip_prefix(name)?.strip_prefix('=')?;
        Some(value.trim().trim_matches('"').to_owned())
    })
}

/// Every way this machine is not the machine the declaration describes.
///
/// The list is returned rather than a boolean because the artefact prints it: a
/// run that refused to publish and does not say which fact was wrong sends the
/// next person to read the runner image release notes.
fn mismatches(declared: &Declaration, runner: &Runner) -> Vec<String> {
    let mut found = Vec::new();

    if runner.cpu_arch != declared.cpu_arch {
        found.push(format!(
            "architecture: declared `{}`, built for `{}`",
            declared.cpu_arch, runner.cpu_arch
        ));
    }
    match runner.cpu_cores {
        Some(cores) if cores == declared.cpu_cores => {}
        Some(cores) => found.push(format!(
            "cores: declared {}, this machine offers {cores}",
            declared.cpu_cores
        )),
        None => found.push("cores: this machine would not say how many it offers".to_owned()),
    }
    // A band and not an equality. The kernel reserves part of the installed
    // memory before `MemTotal` is written, so a runner advertised as 16 GiB
    // reports a little under it; an equality here would make the gate red on the
    // very hardware the declaration names, and the usual repair for that is to
    // widen the check until it stops meaning anything.
    match runner.memory_mib {
        Some(mib) if mib >= declared.memory_mib_min && mib <= declared.memory_mib_max => {}
        Some(mib) => found.push(format!(
            "memory: declared between {} and {} MiB, this machine reports {mib} MiB",
            declared.memory_mib_min, declared.memory_mib_max
        )),
        None => {
            found.push("memory: /proc/meminfo carried no MemTotal this run could read".to_owned())
        }
    }
    match runner.os_id.as_deref() {
        Some(id) if id == declared.os_id => {}
        Some(id) => found.push(format!(
            "operating system: declared `{}`, this machine says `{id}`",
            declared.os_id
        )),
        None => found.push("operating system: /etc/os-release carried no ID".to_owned()),
    }
    // Prefix rather than equality: the runner image reports a point release
    // (`24.04.4`) against a declared series (`24.04`), and the budget belongs to
    // the series. A point release that moved the series would fail this.
    match runner.os_version.as_deref() {
        Some(version) if version.starts_with(&declared.os_version) => {}
        Some(version) => found.push(format!(
            "operating system version: declared `{}`, this machine says `{version}`",
            declared.os_version
        )),
        None => {
            found.push("operating system version: /etc/os-release carried no VERSION_ID".to_owned())
        }
    }

    found
}

// ---------------------------------------------------------------------------
// The budget table
// ---------------------------------------------------------------------------

/// One `budgets[]` row, in `perf-budgets.schema.json`'s field names.
struct Budget {
    budget_id: &'static str,
    metric: &'static str,
    unit: &'static str,
    comparison: Option<&'static str>,
    limit: Option<f64>,
    masking_profile: &'static str,
    status: &'static str,
    source: &'static str,
}

fn budgets() -> Vec<Budget> {
    vec![
        Budget {
            budget_id: "proxy.added_latency_p95",
            metric: "added latency, p95, end to end, against a proxy free baseline",
            unit: "ms",
            comparison: Some("at_most"),
            // One place in this runner holds this number, and it is checked
            // against the document that owns it wherever that document exists.
            limit: Some(ADDED_LATENCY_BUDGET_MS),
            masking_profile: "pattern+dictionary",
            status: "binding",
            source: "docs/05-quality/performance-budgets.md, proxy core profile",
        },
        Budget {
            budget_id: "proxy.added_latency_p95.hold_wait",
            metric: "added latency, p95, under on_hold_timeout = wait",
            unit: "ms",
            comparison: None,
            limit: None,
            masking_profile: "pattern+dictionary",
            status: "unmeasured",
            source: "docs/06-delivery/milestones.md task 92: the 150 ms budget does not apply in \
                     a mode designed to stall rather than emit a fragment, and the two may not \
                     share a series",
        },
        Budget {
            budget_id: "proxy.added_latency_p95.ner",
            metric: "added latency, p95, with detection layer C enabled",
            unit: "ms",
            comparison: None,
            limit: None,
            masking_profile: "pattern+dictionary+ner",
            status: "unmeasured",
            source: "docs/05-quality/performance-budgets.md, NER profile: no binding budget, and \
                     F4 does not implement the layer",
        },
        Budget {
            budget_id: "proxy.rss_peak",
            metric: "peak resident set size during the load test",
            unit: "mib",
            comparison: None,
            limit: None,
            masking_profile: "pattern+dictionary",
            status: "unmeasured",
            source: "docs/05-quality/performance-budgets.md: the proxy memory budget has never \
                     been measured, and an invented ceiling produces design decisions that rest \
                     on it",
        },
    ]
}

impl Budget {
    fn to_value(&self) -> Value {
        let mut row = serde_json::Map::new();
        row.insert("budget_id".to_owned(), json!(self.budget_id));
        row.insert("component".to_owned(), json!("proxy"));
        row.insert("metric".to_owned(), json!(self.metric));
        row.insert("unit".to_owned(), json!(self.unit));
        row.insert("masking_profile".to_owned(), json!(self.masking_profile));
        row.insert("status".to_owned(), json!(self.status));
        row.insert("source".to_owned(), json!(self.source));
        if let Some(comparison) = self.comparison {
            row.insert("comparison".to_owned(), json!(comparison));
        }
        // Present only for a binding budget, and absent rather than null for an
        // unmeasured one: `perf-budgets.schema.json` rejects `limit` beside
        // `status: "unmeasured"`, which is the rule that stops a guess becoming a
        // threshold three weeks later.
        if let Some(limit) = self.limit {
            row.insert("limit".to_owned(), json!(limit));
        }
        Value::Object(row)
    }
}

/// Which side of a budget a value falls on.
///
/// One threshold and no warning band: `milestones.md` task 95 says a measurement
/// over one hundred percent of the budget fails, and that there is no
/// intermediate band. A band is where a number that broke the budget goes to be
/// discussed instead of fixed.
fn verdict(comparison: &str, limit: f64, value: f64) -> &'static str {
    let within = match comparison {
        "at_most" => value <= limit,
        "at_least" => value >= limit,
        // A comparison this build does not implement cannot be read as a pass.
        _ => false,
    };
    if within {
        "pass"
    } else {
        "fail"
    }
}

// ---------------------------------------------------------------------------
// The measurement
// ---------------------------------------------------------------------------

/// What one round measured, in microseconds.
#[derive(Clone, Copy, Debug)]
struct Round {
    baseline_p95_us: u64,
    proxied_p95_us: u64,
}

impl Round {
    /// The added latency: one p95 minus one p95, never a sum of parts.
    fn added_ms(self) -> f64 {
        let added = self.proxied_p95_us.saturating_sub(self.baseline_p95_us);
        (added as f64) / 1000.0
    }
}

/// The 95th percentile, nearest rank.
fn p95(samples: &mut [u64]) -> u64 {
    assert!(!samples.is_empty(), "a percentile over no samples");
    samples.sort_unstable();
    // Nearest rank: ceil(0.95 * n), one indexed, which for n = 60 is the 57th
    // slowest. Named rather than interpolated so two runs of this file compute
    // the same thing as each other and as anybody reading it.
    let rank = ((samples.len() as f64) * 0.95).ceil().max(1.0) as usize;
    samples[rank - 1]
}

fn median(values: &mut [f64]) -> f64 {
    assert!(!values.is_empty());
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    values[values.len() / 2]
}

/// The prompt every request carries.
///
/// Synthetic, and shaped so the masking path has real work: three entity types
/// layer A claims, with their check digits, in eight hundred odd bytes of
/// surrounding prose. A prompt with nothing to mask would measure an empty
/// detector.
fn prompt() -> String {
    let iban = format!("TR{}", "330006100519786457841326");
    let phone = format!("+90 {} {} {}", "532", "000", "4455");
    let filler = "Musteri kaydini inceleyip odemenin neden gecikti\u{011f}ini acikla. ".repeat(12);
    format!(
        "{filler}Fatura hesabi {iban}, iletisim {phone}, eposta \
         zeynep.kucukates@ornek-firma-a.invalid. Ozet cikar."
    )
}

fn body(stream: bool) -> Vec<u8> {
    json!({
        "model": "gpt-4o",
        "stream": stream,
        "messages": [{"role": "user", "content": prompt()}]
    })
    .to_string()
    .into_bytes()
}

/// A loopback provider that answers with the text it was sent.
///
/// Echoing rather than answering from a script is what makes the two paths
/// comparable: the stub does the same work for the baseline client and for the
/// proxy, so the difference between them is the proxy and not the fixture.
async fn stub() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 8192];
                loop {
                    let Ok(read) = socket.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                    let Some(head) = find(&buffer, b"\r\n\r\n") else {
                        continue;
                    };
                    let head_end = head + 4;
                    let headers = String::from_utf8_lossy(&buffer[..head]).into_owned();
                    let length = content_length(&headers).unwrap_or(0);
                    if buffer.len() < head_end + length {
                        continue;
                    }
                    let request = buffer[head_end..head_end + length].to_vec();
                    let answer = echo(&request);
                    if socket.write_all(&answer).await.is_err() {
                        return;
                    }
                    let _flushed = socket.flush().await;
                    buffer.drain(..head_end + length);
                }
            });
        }
    });
    address
}

/// The stub's answer: the text it was given, in the provider's own shape.
fn echo(request: &[u8]) -> Vec<u8> {
    let document: Value = serde_json::from_slice(request).unwrap_or(Value::Null);
    let text = document["messages"][0]["content"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let streaming = document["stream"].as_bool().unwrap_or(false);

    let (content_type, body) = if streaming {
        // Cut every few bytes, which is what puts the response state machine to
        // work: the cuts land inside aliases, so the buffer holds and releases
        // rather than forwarding one perfect chunk.
        let mut out = String::new();
        let mut at = 0usize;
        while at < text.len() {
            let mut end = (at + 7).min(text.len());
            while !text.is_char_boundary(end) {
                end += 1;
            }
            let piece = json!({
                "choices": [{"index": 0, "delta": {"content": &text[at..end]}}]
            });
            out.push_str(&format!("data: {piece}\n\n"));
            at = end;
        }
        out.push_str("data: [DONE]\n\n");
        ("text/event-stream", out)
    } else {
        (
            "application/json",
            json!({
                "id": "chatcmpl-stub",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": text}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
            })
            .to_string(),
        )
    };

    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// The proxy: a real gateway on a real loopback socket.
async fn proxy(stub: SocketAddr) -> (SocketAddr, Arc<Gateway>) {
    let policy = Policy::load(
        "policy_id = \"perf\"\npolicy_version = \"1\"\n[default]\nmode = \"mask\"\n",
        Path::new("."),
        None,
    )
    .unwrap_or_else(|refusal| panic!("{refusal}"));
    let vault = Vault::open(&OpenRequest {
        passphrase: &Passphrase::new(b"the operator typed this".to_vec()),
        // The reduced profile, which is what `perf-budgets.md` section 2.1 says
        // continuous integration uses and what the reference environment
        // declaration names. Argon2id runs once at open and is outside every
        // sample below, but the two profiles are still different environments and
        // the artefact records which one this was.
        profile: ProfileName::Ci,
        backing: Backing::Memory,
    })
    .unwrap_or_else(|refusal| panic!("{refusal}"));

    let upstream = Arc::new(RustlsUpstream::new().unwrap_or_else(|why| panic!("{}", why.why)));
    let gateway = Gateway::new(
        policy,
        vault,
        upstream as Arc<dyn Upstream>,
        AllowList::of(["127.0.0.1"]),
        // The system clock, because this run is a measurement. Every other test
        // in this crate pins it; here the pinned clock would report zero for
        // every duration, which is the one thing a latency measurement cannot do.
        Clock::System,
    )
    .unwrap_or_else(|refusal| panic!("{}", refusal.detail()))
    .with_base(Provider::OpenAi, &format!("http://{stub}"))
    .unwrap_or_else(|refusal| panic!("{}", refusal.detail()));

    let gateway = Arc::new(gateway);
    let listener = Listener::bind(
        ListenAddress::checked("127.0.0.1:0".parse().unwrap(), Exposure::LoopbackOnly).unwrap(),
    )
    .await
    .unwrap();
    let address = listener.address();
    let serving = Arc::clone(&gateway);
    tokio::spawn(async move {
        let _served = listener.serve(serving).await;
    });
    (address, gateway)
}

/// One request, timed from the first byte written to the last byte read.
///
/// A blocking client on purpose: it is the shape of a caller, and a client whose
/// own scheduler could delay a read would be measuring tokio rather than the
/// proxy.
fn one_request(address: SocketAddr, payload: &[u8], session: &str) -> u64 {
    let started = Instant::now();
    let mut socket = TcpStream::connect(address).expect("the endpoint is listening");
    socket.set_nodelay(true).expect("nodelay");
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nhost: {address}\r\ncontent-type: application/json\r\n\
         authorization: Bearer not-a-real-key\r\nx-periskop-session: {session}\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n",
        payload.len()
    );
    socket.write_all(request.as_bytes()).expect("request head");
    socket.write_all(payload).expect("request body");
    socket.flush().expect("flush");

    // Read exactly the answer, rather than to end of file. Both endpoints send a
    // `content-length`, and waiting for the close instead would time the peer's
    // socket teardown into every sample: the stub keeps its connection open, so
    // the baseline would have hung and the proxied path would have been charged
    // a close the baseline never paid.
    let mut answer = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut expected: Option<usize> = None;
    loop {
        let read = socket.read(&mut chunk).expect("the answer");
        assert!(read > 0, "the peer closed before the answer was complete");
        answer.extend_from_slice(&chunk[..read]);
        if expected.is_none() {
            if let Some(head) = find(&answer, b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&answer[..head]).into_owned();
                expected = Some(head + 4 + content_length(&headers).unwrap_or(0));
            }
        }
        if expected.is_some_and(|whole| answer.len() >= whole) {
            break;
        }
    }
    let elapsed = started.elapsed();

    assert!(
        answer.starts_with(b"HTTP/1.1 200"),
        "a request in the measurement did not succeed: {}",
        String::from_utf8_lossy(&answer[..answer.len().min(200)])
    );
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}

fn phase(address: SocketAddr, payload: &[u8], session: &str) -> Vec<u64> {
    for _ in 0..WARMUP_REQUESTS {
        one_request(address, payload, session);
    }
    (0..SAMPLES_PER_PHASE)
        .map(|_| one_request(address, payload, session))
        .collect()
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

#[test]
fn the_added_latency_is_measured_and_is_published_only_where_it_is_comparable() {
    let reference = declaration();
    let budget_ms = ADDED_LATENCY_BUDGET_MS;
    let declared = std::env::var(ENVIRONMENT_VARIABLE)
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| UNDECLARED_ENVIRONMENT.to_owned());

    // Two separate questions, and collapsing them is the failure this replaced.
    // The first is what the run claims; the second is whether the machine bears
    // the claim out. Only a run where both hold may publish a number.
    let claims_reference = declared == reference.environment_id;
    let runner = observe_runner();
    let mismatches = mismatches(&reference, &runner);
    let on_reference_hardware = claims_reference && mismatches.is_empty();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (stub_address, proxy_address, gateway) = runtime.block_on(async {
        let stub_address = stub().await;
        let (proxy_address, gateway) = proxy(stub_address).await;
        (stub_address, proxy_address, gateway)
    });

    let buffered = body(false);
    let streamed = body(true);
    let mut rounds = Vec::new();
    for round in 0..ROUNDS {
        let session = format!("perf-round-{round}");
        let mut baseline = phase(stub_address, &buffered, &session);
        let mut proxied = phase(proxy_address, &buffered, &session);
        rounds.push(Round {
            baseline_p95_us: p95(&mut baseline),
            proxied_p95_us: p95(&mut proxied),
        });
    }

    // A streamed round as well. It is **not** part of the budget: the core
    // profile budget is written for a non streaming request
    // (`performance-budgets.md`, proxy core profile row), and the hold buffer's
    // own line item is the `unmeasured` row above. It runs so that the assertion
    // below is about a response path that actually held bytes, rather than about
    // a state machine that never started.
    let streaming_session = "perf-streaming";
    let mut streaming_baseline = phase(stub_address, &streamed, streaming_session);
    let mut streaming_proxied = phase(proxy_address, &streamed, streaming_session);
    let streaming = Round {
        baseline_p95_us: p95(&mut streaming_baseline),
        proxied_p95_us: p95(&mut streaming_proxied),
    };

    // `milestones.md` task 95: this counter has to be zero in the budget test,
    // and a run where it is not may not have its budget relaxed. It is checked
    // against the event records rather than inferred, and the control beside it
    // is that the stream state machine ran at all.
    let events = gateway.events();
    assert!(
        events.len() >= SAMPLES_PER_PHASE,
        "the proxy measured {} requests, so the assertions below cover almost nothing",
        events.len()
    );
    let mut held = 0u64;
    let mut flushed_fragments = 0u64;
    let mut leaked = 0u64;
    for event in &events {
        let document: Value = serde_json::from_str(&event.to_json()).unwrap();
        held += document["stream_stats"]["hold_events"]
            .as_u64()
            .unwrap_or(0);
        flushed_fragments += document["stream_stats"]["partial_alias_flushed"]
            .as_u64()
            .unwrap_or(0);
        leaked += document["restore_stats"]["aliases_leaked"]
            .as_u64()
            .unwrap_or(0);
    }
    assert!(
        held > 0,
        "no request held a byte, so `partial_alias_flushed == 0` is a fact about a state \
         machine that never ran"
    );
    assert_eq!(
        flushed_fragments, 0,
        "the hold timeout fired off the automaton's root during the measurement, so an unmasked \
         alias fragment may have reached the client. `milestones.md` task 95: the budget is not \
         relaxed to accommodate this"
    );
    assert_eq!(leaked, 0, "an alias in an answer could not be restored");

    let mut added: Vec<f64> = rounds.iter().map(|round| round.added_ms()).collect();
    let mut samples: Vec<f64> = added.iter().map(|value| round(*value)).collect();
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let measured = median(&mut added);
    let outcome = verdict("at_most", budget_ms, measured);

    // Written before the artefact, so that `perf_budgets_json_written` states what
    // happened rather than what was intended. It is written for a failing verdict
    // too: the measurement was comparable, and a series that keeps only the runs
    // that passed cannot show a budget being approached.
    let published = on_reference_hardware;
    if published {
        write_perf_budgets_json(&reference, &runner, &samples, measured, outcome);
    }

    let written = write_artefact(&Artefact {
        reference: &reference,
        runner: &runner,
        declared_environment: &declared,
        on_reference_hardware,
        mismatches: &mismatches,
        rounds: &rounds,
        streaming,
        measured_added_ms: measured,
        samples: &samples,
        budget_ms,
        outcome,
        published,
        requests_per_phase: SAMPLES_PER_PHASE,
    });
    nothing_is_published_that_was_not_earned(&written, on_reference_hardware);

    // The gate itself, applied only where the number means something. On the
    // reference environment this is F4 exit criterion 2; anywhere else it is a
    // signal, and reading a signal as a gate is how a laptop's cache behaviour
    // ends up deciding whether a release ships.
    if on_reference_hardware {
        assert_eq!(
            outcome, "pass",
            "the added p95 latency was {measured:.3} ms against a budget of {budget_ms} ms \
             ({BUDGET_DOCUMENT}, proxy core profile)"
        );
        println!(
            "\n  MEASURED ON `{}`.\n  Added p95 latency {measured:.3} ms against a budget of \
             {budget_ms} ms: {outcome}.\n  Written to {PERF_BUDGETS_JSON} and to \
             target/f4-latency-gate.json.\n",
            reference.environment_id
        );
    } else if claims_reference {
        // A declared environment the machine does not match is a false statement,
        // and the one thing it may not do is pass quietly. The artefact above
        // already carries the reason and a null verdict; this is what keeps the
        // job from going green having measured nothing it was allowed to publish.
        panic!(
            "this run declared `{declared}` and the machine is not that environment, so nothing \
             was published. {ENVIRONMENT_DOCUMENT} section 4 is the declaration; either the job \
             is running somewhere else, or the runner changed under it and section 4 has to be \
             corrected before any number here is comparable again.\n  {}",
            mismatches.join("\n  ")
        );
    } else {
        println!(
            "\n  NOT A MEASUREMENT OF THE REFERENCE ENVIRONMENT.\n  \
             This run declared `{declared}`; every budget number in \
             {ENVIRONMENT_DOCUMENT} belongs to `{}`.\n  \
             The added p95 latency here was {measured:.3} ms. It is a signal, not evidence, it \
             closes no criterion, and it was not written into {PERF_BUDGETS_JSON}.\n  \
             F4 exit criterion 2 stays open until the job on that hardware runs this.\n",
            reference.environment_id
        );
    }
}

#[test]
fn a_measurement_with_no_masking_profile_is_refused() {
    // `performance-budgets.md`: "Profili belirtilmemiş bir proxy gecikme ölçümü
    // geçersizdir". The schema enforces it for anything written to
    // `perf-budgets.json`; this is the same rule one step earlier, so that an
    // unlabelled row cannot be built in the first place.
    for budget in budgets() {
        let row = budget.to_value();
        assert!(
            row["masking_profile"].is_string(),
            "a proxy budget row carries no profile: {row}"
        );
        assert_eq!(row["component"], "proxy");
    }
}

#[test]
fn an_unmeasured_budget_carries_no_limit_and_a_binding_one_carries_both() {
    // The schema rule, checked at the source rather than only at the validator:
    // `status: "unmeasured"` with a `limit` is the shape that turns a guess into
    // a threshold nobody questions three weeks later.
    let mut unmeasured = 0;
    for budget in budgets() {
        let row = budget.to_value();
        match row["status"].as_str() {
            Some("binding") => {
                assert!(row.get("limit").is_some(), "{row}");
                assert!(row.get("comparison").is_some(), "{row}");
            }
            Some("unmeasured") => {
                unmeasured += 1;
                assert!(
                    row.get("limit").is_none(),
                    "an unmeasured budget carries a number: {row}"
                );
            }
            other => panic!("a budget status nothing defines: {other:?}"),
        }
    }
    assert!(
        unmeasured >= 3,
        "the three budgets nobody has measured stopped being declared, which is how an \
         unmeasured budget becomes an invisible one"
    );
    assert!(
        budgets()
            .iter()
            .any(|budget| budget.budget_id == "proxy.added_latency_p95.hold_wait"),
        "the wait mode line item is gone: milestone 92 requires it to be visible as its own row \
         so that a wait mode measurement never lands in the flush mode series"
    );
}

#[test]
fn the_budget_verdict_has_one_threshold_and_no_warning_band() {
    // `milestones.md` task 95: over one hundred percent of the budget fails, and
    // there is no intermediate band. The boundary is the interesting part, so it
    // is the part that is checked.
    assert_eq!(verdict("at_most", 150.0, 149.999), "pass");
    assert_eq!(verdict("at_most", 150.0, 150.0), "pass");
    assert_eq!(verdict("at_most", 150.0, 150.001), "fail");
    assert_eq!(verdict("at_most", 150.0, 400.0), "fail");
    assert_eq!(verdict("at_least", 150.0, 400.0), "pass");
    // A comparison this build does not implement is not a pass. A gate that
    // answered "pass" to a word it did not understand would be a gate anybody
    // could switch off with a typo.
    assert_eq!(verdict("roughly", 150.0, 1.0), "fail");
}

#[test]
fn the_carried_numbers_agree_with_the_documents_that_own_them() {
    // What the runner carries has to be usable as a gate on its own, because in a
    // published tree it is all there is.
    let reference = declaration();
    assert!(!reference.environment_id.is_empty());
    assert!(reference.cpu_cores >= 1);
    assert!(
        reference.memory_mib_min <= reference.memory_mib_max,
        "the declared memory band is empty, so no machine can ever match it"
    );
    // A band and not a wildcard. A declaration wide enough to accept any machine
    // is the same as no declaration, and it would fail open rather than closed.
    assert!(
        reference.memory_mib_max - reference.memory_mib_min <= 4096,
        "the declared memory band spans more than one runner class, so matching it proves \
         nothing about which machine took the number"
    );
    let binding = budgets()
        .into_iter()
        .find(|budget| budget.budget_id == "proxy.added_latency_p95")
        .unwrap_or_else(|| panic!("the binding budget row is gone"));
    assert_eq!(binding.limit, Some(ADDED_LATENCY_BUDGET_MS));

    // And where the owning documents exist, the carried copies have to equal them.
    // This is the half that keeps the copies from being a second source: a budget
    // relaxed in performance-budgets.md or a runner class corrected in
    // perf-budgets.md section 4 turns this red on the machine doing the editing,
    // which is the only machine where either edit happens.
    let Some(documented_budget) = budget_ms_in_document() else {
        // Not a silent skip. `docs/` is unpublished, so its absence is the normal
        // state of a clone and the expected state in CI. What would be a defect is
        // the directory being there with the row missing from it, and that is the
        // case this asserts rather than passes over.
        assert!(
            !docs_are_present(),
            "docs/ is present and {BUDGET_DOCUMENT} does not state the proxy core profile \
             budget, which means the budget moved rather than that this is a published tree"
        );
        return;
    };
    assert_eq!(
        documented_budget, ADDED_LATENCY_BUDGET_MS,
        "{BUDGET_DOCUMENT} states a budget this runner does not carry. The document wins \
         (perf-budgets.md preamble); update the constant and the reason for the change belongs \
         in the document with an ADR beside it"
    );

    let documented_environment = declaration_in_document().unwrap_or_else(|| {
        panic!("{ENVIRONMENT_DOCUMENT} is missing from a tree that carries docs/")
    });
    assert_eq!(
        documented_environment, reference,
        "{ENVIRONMENT_DOCUMENT} section 4 declares an environment this runner does not carry, \
         so the machine check would be comparing against the wrong hardware"
    );
}

#[test]
fn a_machine_that_is_not_the_declared_environment_is_reported_field_by_field() {
    // The check that decides whether a number may be published, exercised without
    // needing the hardware. A runner that differs in every readable respect has to
    // produce a reason per field: one boolean would tell a reader that the machine
    // was wrong and not which part of it, and the repair for that is usually to
    // widen the declaration until it matches.
    let reference = declaration();
    let wrong = Runner {
        cpu_model: Some("a processor".to_owned()),
        cpu_cores: Some(reference.cpu_cores + 1),
        memory_mib: Some(reference.memory_mib_min - 1),
        os_id: Some("not-the-declared-os".to_owned()),
        os_version: Some("0.0".to_owned()),
        cpu_arch: "an-architecture-nothing-builds-for",
    };
    assert_eq!(mismatches(&reference, &wrong).len(), 5);

    let unreadable = Runner {
        cpu_model: None,
        cpu_cores: None,
        memory_mib: None,
        os_id: None,
        os_version: None,
        cpu_arch: "an-architecture-nothing-builds-for",
    };
    // A fact that could not be read is not a fact that matched. The alternative,
    // treating an unreadable field as agreement, is what would let a runner with
    // no /proc publish a number against a budget written for one that has it.
    assert_eq!(mismatches(&reference, &unreadable).len(), 5);
}

#[test]
fn the_percentile_is_the_ninety_fifth_and_not_the_worst() {
    // A p95 implemented as `max` passes every plausible sanity check and reports
    // the slowest request in the run as the typical one. Twenty samples, one
    // outlier: the rank is 19, so the outlier is excluded.
    let mut samples: Vec<u64> = (1..=20).collect();
    samples[19] = 10_000;
    assert_eq!(p95(&mut samples.clone()), 19);
    assert_eq!(p95(&mut [7]), 7);
    assert_eq!(median(&mut [3.0, 1.0, 2.0]), 2.0);
}

// ---------------------------------------------------------------------------
// The artefact
// ---------------------------------------------------------------------------

struct Artefact<'a> {
    reference: &'a Declaration,
    runner: &'a Runner,
    declared_environment: &'a str,
    on_reference_hardware: bool,
    mismatches: &'a [String],
    rounds: &'a [Round],
    streaming: Round,
    measured_added_ms: f64,
    samples: &'a [f64],
    budget_ms: f64,
    outcome: &'static str,
    published: bool,
    requests_per_phase: usize,
}

/// The claim the artefact makes about itself, checked on the bytes that were
/// written.
///
/// The failure this prevents is one line in a release note: "added p95 latency
/// 1 ms". That number was taken on whatever machine ran the test suite, and it is
/// indistinguishable in a document from one earned on the reference environment.
/// So off that hardware three fields have to agree that nothing was earned: the
/// verdict is `null`, the measurement series is empty, and the budget is named in
/// `not_measured` with a reason. A record that carries the number and none of the
/// three is the shape this asserts against.
fn nothing_is_published_that_was_not_earned(document: &Value, on_reference_hardware: bool) {
    assert!(
        document["local_signal"]["added_latency_p95_ms"].is_number(),
        "the artefact carries no measurement at all, so this check is vacuous: {document}"
    );
    if on_reference_hardware {
        // The mirror image, and the half that was missing while the gate never
        // ran: a reference run that leaves the verdict null and the series empty
        // has produced an artefact indistinguishable from a laptop's, and the
        // criterion would stay open with a green job beside it.
        assert!(
            document["budget_verdict"]["verdict"].is_string(),
            "a reference run published no budget verdict: {document}"
        );
        assert!(
            document["measurements"]
                .as_array()
                .is_some_and(|series| !series.is_empty()),
            "a reference run wrote no measurement into the series: {document}"
        );
        assert_eq!(document["measurement_is_comparable"], Value::Bool(true));
        assert_eq!(document["perf_budgets_json_written"], Value::Bool(true));
        assert!(
            document["not_measured"]["proxy.added_latency_p95"].is_null(),
            "the binding budget is listed as not measured by the run that measured it: {document}"
        );
        assert_eq!(document["status"], "measured");
        return;
    }
    assert!(
        document["budget_verdict"].is_null(),
        "a budget verdict was published from a run that is not comparable with the budget: \
         {document}"
    );
    assert_eq!(
        document["measurements"].as_array().map(Vec::len),
        Some(0),
        "a measurement was written into the series from an undeclared environment. \
         perf-budgets.md section 2.3: a measurement with no reference environment is written to \
         no series and is evidence for nothing"
    );
    assert_eq!(document["measurement_is_comparable"], Value::Bool(false));
    assert_eq!(document["perf_budgets_json_written"], Value::Bool(false));
    assert!(
        document["not_measured"]["proxy.added_latency_p95"].is_string(),
        "the binding budget is unpublished with no reason beside it, which reads as an omission \
         rather than as a refusal: {document}"
    );
    assert_eq!(document["status"], "not_measured_on_reference_environment");
}

/// One `measurements[]` row, in `perf-budgets.schema.json`'s field names.
///
/// Built once and written into both files, so that the number a reviewer reads in
/// the job log and the number the series keeps are the same number rather than two
/// roundings of it.
fn measurement_row(environment_id: &str, samples: &[f64], value: f64, outcome: &str) -> Value {
    json!({
        "budget_id": "proxy.added_latency_p95",
        "component": "proxy",
        "environment_id": environment_id,
        "masking_profile": "pattern+dictionary",
        "samples": samples,
        "value": round(value),
        "verdict": outcome,
    })
}

/// The reference environment record, half declared and half measured.
///
/// `cpu_model` comes off the machine because `perf-budgets.md` section 4 refuses
/// to declare it: on a shared runner the model changes between jobs, and a
/// declared model would be a statement nobody checked. Everything else is the
/// declaration, which this run has already confirmed the machine matches.
fn environment_record(reference: &Declaration, runner: &Runner) -> Value {
    json!({
        "environment_id": reference.environment_id,
        "cpu_model": runner.cpu_model.clone().unwrap_or_else(|| "unreadable".to_owned()),
        "cpu_cores": runner.cpu_cores.unwrap_or(0),
        "memory_mib": runner.memory_mib.unwrap_or(0),
        "os": format!(
            "{} {}",
            runner.os_id.clone().unwrap_or_else(|| reference.os_id.clone()),
            runner.os_version.clone().unwrap_or_else(|| reference.os_version.clone())
        ),
        "vault_profile": reference.vault_profile,
    })
}

/// `perf-budgets.json` itself, written only by a run that earned it.
///
/// The whole file rather than an append: the budget rows are derived from the
/// documents on every run, so a stale row cannot survive by being in the file
/// already. The time series this feeds is the artefact store, not this path.
fn write_perf_budgets_json(
    reference: &Declaration,
    runner: &Runner,
    samples: &[f64],
    value: f64,
    outcome: &'static str,
) {
    let document = json!({
        "schema_version": "1.0",
        "reference_environments": [environment_record(reference, runner)],
        "budgets": budgets().iter().map(Budget::to_value).collect::<Vec<Value>>(),
        "measurements": [measurement_row(&reference.environment_id, samples, value, outcome)],
    });

    let out = repo_root().join(PERF_BUDGETS_JSON);
    let mut rendered = serde_json::to_string_pretty(&document).unwrap();
    rendered.push('\n');
    std::fs::write(&out, &rendered)
        .unwrap_or_else(|why| panic!("{} could not be written: {why}", out.display()));
}

fn write_artefact(artefact: &Artefact<'_>) -> Value {
    let samples: Vec<Value> = artefact.samples.iter().map(|value| json!(value)).collect();

    let mut not_measured = serde_json::Map::new();
    if !artefact.on_reference_hardware {
        not_measured.insert(
            "proxy.added_latency_p95".to_owned(),
            json!(format!(
                "measured, and not comparable. Every budget number belongs to the reference \
                 environment `{}` ({ENVIRONMENT_DOCUMENT} section 4), and this run declared `{}`. \
                 A development machine is not a reference environment: perf-budgets.md says a \
                 measurement taken on one is a signal and not evidence, and is not written to \
                 perf-budgets.json. The number this run took is under local_signal, where the name \
                 says what it is not. F4 exit criterion 2 is closed by the job on that hardware \
                 and by nothing here",
                artefact.reference.environment_id, artefact.declared_environment
            )),
        );
    }
    not_measured.insert(
        "proxy.added_latency_p95.hold_wait".to_owned(),
        json!(
            "on_hold_timeout = wait was not exercised as a budget. The mode stalls rather than \
               emitting a fragment, so the 150 ms budget does not apply to it, and the two may \
               not share a budget_id or a time series (milestones.md task 92). The row exists as \
               unmeasured so that a wait mode number has somewhere to go that is not the flush \
               mode series"
        ),
    );
    not_measured.insert(
        "proxy.added_latency_p95.ner".to_owned(),
        json!(
            "detection layer C has no code path in this build (F4 scope boundary 1), so there \
               is nothing to time. performance-budgets.md leaves the NER profile budget open and \
               says the 150 ms figure does not apply to it"
        ),
    );
    not_measured.insert(
        "proxy.rss_peak".to_owned(),
        json!(
            "no resident set size was sampled. Reading peak RSS needs a platform specific call \
               this workspace has no dependency for, and the budget itself has never been set: \
               performance-budgets.md marks it to be measured rather than guessing a ceiling"
        ),
    );
    not_measured.insert(
        "sub_item_breakdown".to_owned(),
        json!(
            "the per stage table in performance-budgets.md is informative and is not measured \
               here. Sub item p95s do not add up to the composite p95 (D-10 finding 30), so \
               publishing them beside the binding number invites the sum"
        ),
    );

    let document = json!({
        "gate": "F4-95",
        "criterion": "roadmap.md F4 exit criterion 2",
        "status": if artefact.on_reference_hardware { "measured" } else { "not_measured_on_reference_environment" },
        "reference_environment_id": artefact.reference.environment_id,
        "declared_environment_id": artefact.declared_environment,
        "measurement_is_comparable": artefact.on_reference_hardware,
        "perf_budgets_json_written": artefact.published,
        // Repo relative and never the path that was written. CLAUDE.md forbids an
        // absolute path in emitted output: it makes the artefact of two identical
        // runs differ by the name of the machine that took them.
        "perf_budgets_json_path": artefact.published.then_some(PERF_BUDGETS_JSON),
        "vault_profile": artefact.reference.vault_profile,
        "masking_profile": "pattern+dictionary",
        "budget_source": {
            "limit_ms": artefact.budget_ms,
            "document": BUDGET_DOCUMENT,
            // Whether this run was able to check the number against its owner.
            // False in a published tree, which is every CI checkout: docs/ is
            // unpublished, so the agreement is asserted where the document is
            // edited rather than where the gate runs. A reader of this artefact
            // is entitled to know which of the two it is looking at.
            "agreement_with_document_checked": docs_are_present(),
        },
        // What the machine turned out to be, printed whether or not it matched.
        // A run that refused to publish and did not say which fact was wrong
        // sends the next reader to the runner image release notes.
        "observed_environment": {
            "cpu_model": artefact.runner.cpu_model,
            "cpu_cores": artefact.runner.cpu_cores,
            "cpu_arch": artefact.runner.cpu_arch,
            "memory_mib": artefact.runner.memory_mib,
            "os_id": artefact.runner.os_id,
            "os_version": artefact.runner.os_version,
        },
        "runner_matches_declaration": artefact.mismatches.is_empty(),
        "runner_mismatches": artefact.mismatches,
        "method": {
            "shape": "p95(through the proxy) - p95(straight to the stub), end to end, one \
                      percentile and never a sum of sub items",
            "requests_per_phase": artefact.requests_per_phase,
            "warmup_requests_per_phase": WARMUP_REQUESTS,
            "rounds": artefact.rounds.len(),
            "verdict_read_from": "the median of the rounds",
            "streaming": "measured separately and excluded from the budget: the core profile \
                          budget is written for a non streaming request",
        },
        "budgets": budgets().iter().map(Budget::to_value).collect::<Vec<Value>>(),
        // Empty, always, off the reference environment. `perf-budgets.md` section
        // 2.3: a measurement with no reference environment is not comparable, is
        // written to no series, and is evidence for nothing.
        "measurements": if artefact.on_reference_hardware {
            vec![measurement_row(
                &artefact.reference.environment_id,
                artefact.samples,
                artefact.measured_added_ms,
                artefact.outcome,
            )]
        } else {
            Vec::<Value>::new()
        },
        "budget_verdict": if artefact.on_reference_hardware {
            json!({
                "budget_id": "proxy.added_latency_p95",
                "comparison": "at_most",
                "limit_ms": artefact.budget_ms,
                "value_ms": round(artefact.measured_added_ms),
                "verdict": artefact.outcome,
            })
        } else {
            Value::Null
        },
        "local_signal": {
            "budget_id": "proxy.added_latency_p95",
            "added_latency_p95_ms": round(artefact.measured_added_ms),
            "samples_ms": samples,
            "buffered_rounds_us": artefact.rounds.iter().map(|r| json!({
                "baseline_p95_us": r.baseline_p95_us,
                "proxied_p95_us": r.proxied_p95_us,
            })).collect::<Vec<Value>>(),
            "streamed_round_us": {
                "baseline_p95_us": artefact.streaming.baseline_p95_us,
                "proxied_p95_us": artefact.streaming.proxied_p95_us,
                "added_latency_p95_ms": round(artefact.streaming.added_ms()),
            },
            "partial_alias_flushed": 0,
            "reading": "a loopback stub, a real socket and a real gateway on whatever machine ran \
                        the test suite. It catches the proxy getting slower between now and the \
                        day the reference job runs, and it closes nothing: two numbers from two \
                        machines are not comparable, and a budget compared across them reads \
                        noise as a regression",
        },
        "not_measured": Value::Object(not_measured),
    });

    let out = repo_root().join("target/f4-latency-gate.json");
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut rendered = serde_json::to_string_pretty(&document).unwrap();
    rendered.push('\n');
    // Not a discarded result: the whole reason this file exists is that a run
    // that measured and a run that published leave the same green line in the
    // output, so a write that failed silently would put the gate back where it
    // was before the artefact was added.
    std::fs::write(&out, &rendered)
        .unwrap_or_else(|why| panic!("{} could not be written: {why}", out.display()));

    // Read back rather than returned from memory: what the check above is about
    // is the document a release note would be built from, and that is the bytes
    // on the disk.
    let written = std::fs::read_to_string(&out)
        .unwrap_or_else(|why| panic!("{} could not be read back: {why}", out.display()));
    serde_json::from_str(&written).unwrap()
}

/// Three decimal places, so the artefact diffs between runs are readable.
fn round(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn content_length(headers: &str) -> Option<usize> {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())?
    })
}
