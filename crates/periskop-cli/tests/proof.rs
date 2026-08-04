#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! The F2 gate (milestone 48): the runtime hook records a call the static
//! scanner cannot see.
//!
//! This is the reason the phase exists. F1 answers "where can this code send
//! data", and its honest answer stops at what the syntax tree holds. A call
//! whose method is reached through `getattr` and whose destination is read out
//! of the environment leaves nothing in the tree to find, so the scanner reports
//! nothing and says so; both are catalogued, as KG-001 and KG-002. F2's claim is
//! that a second source closes that specific hole, and a claim of that shape is
//! either demonstrated on a running program or it is marketing.
//!
//! So the test below runs a small application twice over. The static scan has to
//! come back empty, because a proof that the hook found something the scanner
//! also found would prove nothing. Then the same program runs with the hook
//! installed, and `periskop-runtime-collector` reads back an event naming the
//! host, the path and the library that the call actually used. None of those
//! three strings appears anywhere in the application's source, and the test
//! checks that too, so "the scanner could not have seen it" is a fact about the
//! source rather than an assertion about the scanner.
//!
//! **If this test does not pass, F2 is not closed.** A run that skipped it did
//! not close it either: see `python_interpreter` below for what a skip costs and
//! how continuous integration is meant to forbid one.

use std::path::{Path, PathBuf};
use std::process::Command;

use periskop_runtime_collector::event::{Language, Mechanism};
use periskop_runtime_collector::{collect, EgressEvent};

use periskop_cli::scan;

/// Destination the application reaches, supplied through the environment.
///
/// Held here rather than in the sample source, which is the whole point: the
/// test asserts further down that none of these strings occurs in any file the
/// scanner reads.
const PROVIDER_HOST: &str = "api.openai.com";
const PROVIDER_PATH: &str = "/v1/chat/completions";
const PROVIDER_VERB: &str = "POST";

/// Set this in continuous integration so a machine without python3 fails the
/// gate rather than skipping it.
///
/// The default is the other way round because a developer without a Python
/// interpreter should still be able to run `cargo test`, and a hard failure
/// there teaches people to pass `--skip proof`, which removes the gate for
/// everyone. The choice is between a skip that is loud and recorded, and a
/// failure that gets routed around; this picks the first and gives CI the
/// switch.
const REQUIRE_PROOF: &str = "PERISKOP_REQUIRE_PROOF";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A throwaway directory tree, built by hand.
///
/// Written out rather than pulled in, matching `scan_report.rs`: a test only
/// dependency is still a dependency decision, and this needs a few lines.
struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(name: &str) -> Self {
        // The process id keeps two test runs on one machine from deleting each
        // other's tree, which would show up as a failure with no obvious cause.
        let root =
            std::env::temp_dir().join(format!("periskop-proof-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn write(&self, relative: &str, contents: &str) -> &Self {
        let path = self.root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
        self
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        // Cleanup failure must not mask the assertion that already ran.
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The sample application.
///
/// Deliberately ordinary. Reading a base URL out of the environment is how every
/// deployment that has a staging provider is written, and reaching a method
/// through `getattr` is how a dispatch table works. Neither is an exotic evasion
/// technique, which is the uncomfortable part: this shape is common, and a tool
/// that only reads source walks past it.
const SAMPLE_APP: &str = r#""""Summarises a support ticket through a provider chosen while it runs.

Nothing here names a provider. The verb, the host and the path arrive from the
environment, and the method that sends the request is reached through getattr,
so the syntax tree holds identifiers where a scanner would need literals. The
two gaps this leans on are catalogued as KG-001 and KG-002 in known-gaps.md.
"""

import os

import requests


def summarize(record):
    session = requests.Session()
    request = requests.Request(
        os.environ["LLM_VERB"],
        os.environ["LLM_BASE_URL"] + os.environ["LLM_PATH"],
        record,
    )
    send = getattr(session, os.environ["LLM_SEND_METHOD"])
    return send(request)


if __name__ == "__main__":
    summarize("ticket 4471: the invoice total does not match the order")
"#;

/// Stand in for the `requests` package, cut down to the shape the hook patches.
///
/// Two things it buys. The test installs no third party package, so it measures
/// the hook rather than the machine's site-packages. And it opens no socket: a
/// test that reached a provider would prove the machine had a network and a
/// funded API key, and it would send a request on every `cargo test`, which an
/// observation tool has no business doing.
///
/// What it does not soften is the thing under test. `Session.send` is the funnel
/// the real library routes every helper and every redirect through, and it is
/// the exact attribute `periskop_hook.wrappers.requests_client` patches. At the
/// point the hook observes, this is indistinguishable from the real library.
const SAMPLE_REQUESTS_STUB: &str = r#""""Minimal stand in for the requests package, for the periskop proof test.

Only the surface the hook touches is present: a Session whose send method is the
single funnel, and a request object carrying method, url, headers and body.
"""


class Request(object):
    def __init__(self, method, url, body):
        self.method = method
        self.url = url
        self.body = body
        self.headers = {"content-length": str(len(body))}


class Response(object):
    def __init__(self, status_code):
        self.status_code = status_code


class Session(object):
    def send(self, request):
        # Where the real library would open a socket. What the proof is about is
        # what periskop observed on the way out, not the provider's answer.
        return Response(200)
"#;

/// The interpreter to run the sample with, or the reason there is none.
///
/// A missing interpreter must not look like a passing gate. When there is none
/// the test writes `status: skipped` into `target/f2-proof.json`, prints why,
/// and says in as many words that F2 is not closed by that run. With
/// [`REQUIRE_PROOF`] set it fails instead, which is the setting continuous
/// integration is supposed to use.
fn python_interpreter() -> Result<String, String> {
    for candidate in ["python3", "python"] {
        match Command::new(candidate).arg("--version").output() {
            Ok(output) if output.status.success() => return Ok(candidate.to_owned()),
            Ok(output) => {
                return Err(format!(
                    "{candidate} is on PATH but `{candidate} --version` exited with {}",
                    output.status
                ))
            }
            Err(_) => continue,
        }
    }
    Err("no python3 or python interpreter on PATH".to_owned())
}

/// What this run of the gate established, written next to the benchmark.
///
/// A skipped gate and a passing gate leave the same green line in the test
/// output, so the difference is recorded where a release check can read it.
#[derive(Debug, serde::Serialize)]
struct ProofRecord {
    gate: &'static str,
    status: &'static str,
    reason: String,
    /// Absent on a skipped run, which is how the artefact says the gate was
    /// never exercised rather than exercised and empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<ProofEvidence>,
}

#[derive(Debug, serde::Serialize)]
struct ProofEvidence {
    static_findings: usize,
    static_suspect_findings: usize,
    runtime_events: usize,
    observed_operation: String,
    observed_host: String,
    observed_path_template: String,
    observed_library: String,
}

fn record_outcome(record: &ProofRecord) {
    let out = repo_root().join("target/f2-proof.json");
    if let Some(parent) = out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&out, serde_json::to_string_pretty(record).unwrap());
}

/// Runs the sample under the hook and returns the directory it wrote into.
///
/// Installation is the documented fallback path: `PYTHONPATH` pointing at
/// `hooks/python`, whose `sitecustomize.py` chains onto whatever else claims
/// that name and then installs the hook. The primary path, a `.pth` file, needs
/// a site-packages directory, and `site` only scans `.pth` files in site
/// directories rather than in everything on `PYTHONPATH`; using it here would
/// mean writing into the interpreter the developer runs `cargo test` with. The
/// application is not modified either way (ADR-009), which is the property the
/// gate is about.
fn run_hooked(interpreter: &str, project: &Path, event_dir: &Path) -> std::process::Output {
    Command::new(interpreter)
        .arg("app.py")
        .current_dir(project)
        .env("PYTHONPATH", repo_root().join("hooks/python"))
        // Keeps the run from leaving __pycache__ directories inside the hook
        // source tree, which is a repository the test does not own.
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PERISKOP_EVENT_DIR", event_dir)
        .env("PERISKOP_HOOK_ENTRYPOINT", "proof-app")
        // The destination lives in the environment, not in the source. This is
        // the sample's egress configuration and the reason the scan is blind.
        .env("LLM_VERB", PROVIDER_VERB)
        .env("LLM_BASE_URL", format!("https://{PROVIDER_HOST}"))
        .env("LLM_PATH", PROVIDER_PATH)
        .env("LLM_SEND_METHOD", "send")
        // A developer who has switched the hook off in their shell would
        // otherwise get an empty event directory and a red test with a confusing
        // message, or worse, a green one if the assertions were looser.
        .env_remove("PERISKOP_HOOK")
        .env_remove("PERISKOP_HOOK_OUTPUT")
        .output()
        .expect("the interpreter answered --version, so it can run a script")
}

/// Asserts the destination really is absent from everything the scanner reads.
///
/// Without this the test would only be saying that the scanner produced no
/// finding, which a broken scanner also does. This says the source could not
/// have yielded one.
fn no_source_names(project: &Path, needle: &str) {
    for entry in std::fs::read_dir(project).expect("project").flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("py") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("sample source");
        assert!(
            !source.contains(needle),
            "{} names {needle}, so the static scan was not blind to it and this \
             test would be proving nothing",
            path.display()
        );
    }
}

/// The gate. F2 is not closed while this does not pass.
///
/// Four steps, in the order the claim is made: scan and find nothing, run the
/// program under the hook, read the events back through the collector, and check
/// that what came back is the call the scan missed.
#[test]
fn f2_gate_the_hook_records_a_call_the_static_scanner_cannot_see() {
    let interpreter = match python_interpreter() {
        Ok(interpreter) => interpreter,
        Err(reason) => {
            let required = std::env::var_os(REQUIRE_PROOF).is_some();
            record_outcome(&ProofRecord {
                gate: "F2-48",
                status: "skipped",
                reason: reason.clone(),
                evidence: None,
            });
            assert!(
                !required,
                "{REQUIRE_PROOF} is set and the F2 gate cannot run: {reason}"
            );
            eprintln!(
                "\n  SKIPPED: the F2 end to end proof did not run.\n  \
                 Reason: {reason}\n  \
                 This run does not close F2. Install a python3 interpreter, or set \
                 {REQUIRE_PROOF}=1\n  to make the missing interpreter a failure \
                 instead of a skip.\n"
            );
            return;
        }
    };

    let tree = TempTree::new("runtime-built-call");
    tree.write("project/app.py", SAMPLE_APP)
        .write("project/requests.py", SAMPLE_REQUESTS_STUB);
    let project = tree.path("project");
    let event_dir = tree.path("events");

    // (a) The static scan. Nothing in the source names a provider, so nothing
    //     may be reported: not a confirmed finding and not a suspect one. A
    //     suspect here would mean the scanner had guessed, which the project
    //     forbids more strongly than it forbids missing the call.
    for needle in [PROVIDER_HOST, PROVIDER_PATH, "openai"] {
        no_source_names(&project, needle);
    }
    let outcome = scan::run(scan::ScanRequest {
        project_root: &project,
        rules_root: &repo_root().join("rules"),
        tool_version: "0.0.0-test",
        generated_at: "2026-08-04T09:00:00Z".to_owned(),
    });
    assert!(outcome.rule_errors.is_empty(), "{:?}", outcome.rule_errors);
    assert!(
        outcome.report.findings.is_empty() && outcome.report.suspect_findings.is_empty(),
        "the static scan was supposed to be blind here, so a finding means this \
         test is measuring the wrong sample: {:?} {:?}",
        outcome.report.findings,
        outcome.report.suspect_findings
    );

    // (b) The same program, hooked. A non zero exit would also be a fail-open
    //     failure: the hook is not allowed to break the application it watches.
    let run = run_hooked(&interpreter, &project, &event_dir);
    assert!(
        run.status.success(),
        "the hooked application did not exit cleanly, which breaks the fail-open \
         guarantee before it proves anything.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    // (c) Read the stream back through the collector, the component that owns
    //     the reading half of the event contract.
    let collected = collect(&event_dir);
    assert!(
        collected.malformed.is_empty() && collected.dropped == 0,
        "the hook wrote something the collector could not read: {:?}",
        collected.malformed
    );
    assert_eq!(
        collected.events.len(),
        1,
        "the sample makes exactly one call: {:?}",
        collected.events
    );

    // (d) The event is that call, and not some other traffic the interpreter
    //     happened to produce.
    let event: &EgressEvent = &collected.events[0];
    assert_eq!(event.process.language, Language::Python);
    assert_eq!(
        event.library.module, "requests",
        "the library the sample reached through getattr"
    );
    assert_eq!(
        event.library.mechanism,
        Mechanism::HttpClient,
        "an HTTP client observation, which the schema records as the weaker of \
         the two mechanisms because the layer cannot tell a provider call from \
         any other request without the target"
    );
    assert_eq!(
        event.operation, "http.post",
        "the verb the sample read out of LLM_VERB, normalised"
    );
    assert_eq!(
        event.target.host_id, PROVIDER_HOST,
        "the host the sample read out of LLM_BASE_URL, which appears in no source file"
    );
    assert_eq!(
        event.target.path_template.as_deref(),
        Some(PROVIDER_PATH),
        "the path the sample read out of LLM_PATH"
    );
    assert_eq!(
        event.target.provider_ref.as_deref(),
        Some("openai"),
        "classified from the host, using the same vocabulary the static rules use"
    );

    // The event points back at the exact line the scan walked past, which is
    // what makes the two sources comparable rather than merely both present. The
    // path is relative because an absolute one would put the build machine into
    // output that has to compare equal across machines.
    let call_site = event
        .call_site_hint
        .as_ref()
        .expect("the hook resolved a frame inside the project tree");
    assert_eq!(call_site.path.as_deref(), Some("app.py"));
    assert_eq!(call_site.symbol.as_deref(), Some("summarize"));

    record_outcome(&ProofRecord {
        gate: "F2-48",
        status: "proved",
        reason: "the static scan produced nothing for a runtime built call and \
                 the python hook recorded it"
            .to_owned(),
        evidence: Some(ProofEvidence {
            static_findings: outcome.report.findings.len(),
            static_suspect_findings: outcome.report.suspect_findings.len(),
            runtime_events: collected.events.len(),
            observed_operation: event.operation.clone(),
            observed_host: event.target.host_id.clone(),
            observed_path_template: event.target.path_template.clone().unwrap_or_default(),
            observed_library: event.library.module.clone(),
        }),
    });
}

/// The hook records the shape of the payload and never its content.
///
/// Checked here rather than only in the Python suite because this is the one
/// place a real interpreter, a real call and the Rust side of the contract meet.
/// The sample's ticket text is the kind of string a support desk would send to a
/// provider, and none of it may reach the event stream.
#[test]
fn f2_gate_no_payload_content_reaches_the_event_stream() {
    let Ok(interpreter) = python_interpreter() else {
        // The gate test above is what records and reports a skip; duplicating
        // that here would write the artefact twice with different contents.
        return;
    };

    let tree = TempTree::new("no-content-leak");
    tree.write("project/app.py", SAMPLE_APP)
        .write("project/requests.py", SAMPLE_REQUESTS_STUB);
    let project = tree.path("project");
    let event_dir = tree.path("events");

    let run = run_hooked(&interpreter, &project, &event_dir);
    assert!(run.status.success(), "{:?}", run);

    let mut written = String::new();
    for entry in std::fs::read_dir(&event_dir)
        .expect("event directory")
        .flatten()
    {
        written.push_str(&std::fs::read_to_string(entry.path()).expect("event file"));
    }
    assert!(!written.is_empty(), "the hook wrote nothing to read");

    for secret in ["ticket 4471", "invoice total", "does not match the order"] {
        assert!(
            !written.contains(secret),
            "payload content reached the event stream: {secret}"
        );
    }
}
