#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! The F3 gate (milestone 60): the network sensor records a call that neither
//! the static scanner nor the runtime hook can see.
//!
//! F2 proved that a second source closes the hole reading code leaves. It closed
//! it for one shape of program: one that was instrumented. The hook lives inside
//! an interpreter and patches the HTTP client libraries it knows, so two things
//! stay invisible to it, and both of them are ordinary rather than exotic. A
//! process nobody installed the hook into is one. A call that goes out over a
//! raw socket rather than through a patched library is the other. F3's claim is
//! that data leaving the machine has to pass through a socket whatever the code
//! looked like, and that the third source therefore sees what the first two
//! cannot. A claim of that shape is either demonstrated on a running program or
//! it is marketing.
//!
//! # What is real here, and what is not
//!
//! Real: the application, the child process, the TCP connection, the bytes, the
//! blindness of both other sources. The sample connects to a listener this test
//! opened on the loopback interface, so a real socket is opened, real bytes cross
//! it, and nothing leaves the machine. periskop must not be an egress source, and
//! a test that reached a provider would also be measuring whether the machine had
//! a network and a funded key.
//!
//! Not real: the transport that carries the observation into the sensor. The
//! eBPF loader cannot run here. It needs a Linux kernel with BTF and a process
//! holding `CAP_BPF` and `CAP_PERFMON` (ADR-014), which is neither the macOS
//! machine this repository is developed on nor an unprivileged continuous
//! integration container. So the facts about the connection are measured by the
//! accepting socket, which genuinely observed it, and handed to the sensor
//! through the [`KernelEvents`] seam that a ring buffer would otherwise fill.
//! Everything above that seam is the shipped code: the assembler, the scope
//! policy, the record, the reconciler and the report.
//!
//! That distinction is not left in a comment. `target/f3-proof.json` carries it
//! in `capture` and `caveat`, and the flow record's `mechanism` says `ebpf`
//! because the contract's enum has no value for anything else, which is filed as
//! a contract request in `hub/memory/interfaces.md`. Nobody should be able to
//! read the artefact as proof that eBPF capture works, because this run does not
//! establish that.
//!
//! **If this test does not pass, F3 is not closed.** A run that skipped it did
//! not close it either: `PERISKOP_REQUIRE_PROOF` turns the skip into a failure
//! and continuous integration sets it.

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use periskop_core::finding::{Confidence, Finding, Kind};
use periskop_network_sensor::flow::Proto;
use periskop_network_sensor::kernel::{
    AttachPlan, ConnectEvent, KernelBatch, KernelEvent, KernelEvents, KernelProcess, VolumeEvent,
};
use periskop_network_sensor::privilege::Grant;
use periskop_network_sensor::{
    EbpfFlowSource, Flow, FlowKey, FlowScope, FlowSource, Mechanism, ScopePolicy, SensorUnavailable,
};
use periskop_reconcile::settings::ReconcileSettings;
use periskop_runtime_collector::collect;

use periskop_cli::scan;

/// Set this in continuous integration so a machine without python3 fails the
/// gate rather than skipping it. The same switch the F2 gate uses, and the same
/// reasoning: a developer without an interpreter should still be able to run
/// `cargo test`, because a hard failure there teaches people to pass
/// `--skip proof`, which removes the gate for everybody.
const REQUIRE_PROOF: &str = "PERISKOP_REQUIRE_PROOF";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A throwaway directory tree, built by hand.
///
/// Written out rather than pulled in, matching `proof.rs` and `scan_report.rs`:
/// a test only dependency is still a dependency decision, and this needs a few
/// lines.
struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("periskop-f3-{name}-{}", std::process::id()));
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

    fn dir(&self, relative: &str) -> PathBuf {
        let path = self.root.join(relative);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The sample application.
///
/// Deliberately ordinary, and blind to both of the first two sources for two
/// independent reasons. Nothing in the source names a destination or a transport:
/// the module is reached through `__import__` of a name read from the
/// environment, which is how a pluggable transport layer is written. And the call
/// goes out over a socket rather than through an HTTP client library, which is
/// how anything speaking a binary protocol, a gRPC stub or a vendored SDK
/// eventually sends its bytes. The hook patches libraries; there is no library
/// here to patch.
const SAMPLE_APP: &str = r#""""Ships a support ticket to whatever the deployment configured.

Nothing here names a destination, a transport module or a method. All of them
arrive from the environment, the module is reached through __import__ and the
two calls through getattr, so the syntax tree holds identifiers where a scanner
would need literals. The bytes then leave at the transport layer rather than
through a client library, so there is nothing for a runtime hook to patch
either.
"""

import os


def ship(record):
    transport = __import__(os.environ["LLM_TRANSPORT"])
    open_channel = getattr(transport, os.environ["LLM_OPEN"])
    channel = open_channel((os.environ["LLM_HOST"], int(os.environ["LLM_PORT"])))
    try:
        getattr(channel, os.environ["LLM_SEND"])(record.encode("utf-8"))
    finally:
        channel.close()


if __name__ == "__main__":
    ship("ticket 8812: the renewal quote is missing a line item")
"#;

/// The interpreter to run the sample with, or the reason there is none.
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

/// What the accepting socket genuinely observed about one connection.
///
/// This is the measurement. The peer port, the byte count and the destination
/// are read off a socket that was one end of the connection, not scripted by the
/// test: change the sample's payload and every number here changes with it.
struct AcceptedConnection {
    peer_port: u16,
    bytes_from_peer: u64,
    destination_ip: String,
    destination_port: u16,
    at_epoch_secs: u64,
}

/// Accepts exactly one connection and reports what crossed it.
fn accept_one(listener: &TcpListener) -> AcceptedConnection {
    let local = listener.local_addr().expect("the listener is bound");
    let (mut stream, peer) = listener.accept().expect("the sample connects");
    let mut received = Vec::new();
    read_to_end(&mut stream, &mut received);
    AcceptedConnection {
        peer_port: peer.port(),
        bytes_from_peer: received.len() as u64,
        destination_ip: local.ip().to_string(),
        destination_port: local.port(),
        at_epoch_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or_default(),
    }
}

fn read_to_end(stream: &mut TcpStream, into: &mut Vec<u8>) {
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(read) => into.extend_from_slice(&chunk[..read]),
        }
    }
}

/// The seam a ring buffer would fill, filled by the socket that was there.
///
/// **This is not eBPF and must never be read as eBPF.** It is the transport that
/// carries a measured observation into the sensor on a machine where the loader
/// cannot run. What it hands over is derived entirely from
/// [`AcceptedConnection`]: the pid of the process that really made the call, the
/// port the kernel really gave it, the bytes that really arrived.
struct AcceptedConnectionKernel {
    batches: Vec<KernelBatch>,
}

impl AcceptedConnectionKernel {
    fn of(observed: &AcceptedConnection, pid: u32, comm: &str) -> Self {
        let key = FlowKey {
            // Unknown, and left unknown. The accepting socket cannot see which
            // network namespace the peer was in, and filling it with the test
            // process's own would be inventing attribution.
            netns: None,
            src_ip: "127.0.0.1".parse().expect("loopback parses"),
            src_port: observed.peer_port,
            dst_ip: observed
                .destination_ip
                .parse()
                .expect("the listener's own address parses"),
            dst_port: observed.destination_port,
            proto: Proto::Tcp,
        };
        Self {
            batches: vec![KernelBatch::of(vec![
                KernelEvent::Connect(ConnectEvent {
                    key: key.clone(),
                    t_start_bucket: observed.at_epoch_secs,
                    at_secs: 0,
                    process: KernelProcess {
                        pid,
                        // Not measured. A start time guards against pid reuse
                        // over a long observation, and this test observed one
                        // connection over one second.
                        pid_start_time: None,
                        comm: Some(comm.to_owned()),
                    },
                    pre_existing: false,
                }),
                KernelEvent::Volume(VolumeEvent {
                    key,
                    bytes_out: observed.bytes_from_peer,
                    // Nothing came back: the listener answers nothing, which is
                    // what the sample's protocol does.
                    bytes_in: 0,
                    segments_out: 1,
                }),
            ])],
        }
    }
}

impl KernelEvents for AcceptedConnectionKernel {
    fn attach(&mut self, _plan: &AttachPlan) -> Result<(), SensorUnavailable> {
        Ok(())
    }

    fn poll(&mut self) -> KernelBatch {
        if self.batches.is_empty() {
            return KernelBatch::quiet();
        }
        self.batches.remove(0)
    }

    /// The measured connection carried no payload sample, so no parser was
    /// asked and none refused. Empty is what was counted rather than a default
    /// standing in for a count nobody took.
    fn rejected_samples(&self) -> std::collections::BTreeMap<&'static str, u64> {
        std::collections::BTreeMap::new()
    }
}

/// Turns the measured connection into records, through the shipped sensor.
///
/// Everything from here up is production code: the assembler joins the process
/// event to the volume event, the scope policy places the flow in a bucket, and
/// `Flow::from_observation` enforces every invariant the contract states.
fn sensor_records(observed: &AcceptedConnection, pid: u32, comm: &str) -> Vec<Flow> {
    let mut source = EbpfFlowSource::over(
        AcceptedConnectionKernel::of(observed, pid, comm),
        "h_f3proofhost0001",
    )
    .with_boot_id("b_f3proofboot0001");
    source
        .attach(&Grant {
            tc_available: false,
            elevated_as_root: false,
        })
        .expect("the stand in transport attaches");

    // The process the sample ran as is the codebase under scan, which is what
    // puts the flow in the only bucket that can produce a finding.
    let policy = ScopePolicy::for_codebase([comm.to_owned()]);
    source
        .drain()
        .into_iter()
        .map(|observation| {
            let scope = policy.classify(&observation);
            Flow::from_observation(observation, scope, Mechanism::Ebpf)
                .expect("a record the sensor itself built satisfies its own contract")
        })
        .collect()
}

/// Asserts the destination really is absent from everything the scanner reads.
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

/// Runs the sample, optionally with the hook installed.
///
/// The hooked variant exists to make the second half of the blindness claim an
/// assertion rather than an assumption: the hook is not merely absent here, it is
/// unable to see this call even when it is loaded, because it patches HTTP client
/// libraries and this call goes out over a socket.
fn run_sample(
    interpreter: &str,
    project: &Path,
    event_dir: &Path,
    listener: &TcpListener,
    hooked: bool,
) -> std::process::Child {
    let local = listener.local_addr().expect("the listener is bound");
    let mut command = Command::new(interpreter);
    command
        .arg("app.py")
        .current_dir(project)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PERISKOP_EVENT_DIR", event_dir)
        .env("PERISKOP_HOOK_ENTRYPOINT", "f3-proof-app")
        // The destination and the transport live in the environment, not in the
        // source. This is the sample's egress configuration and the reason the
        // scan is blind.
        .env("LLM_TRANSPORT", "socket")
        .env("LLM_OPEN", "create_connection")
        .env("LLM_SEND", "sendall")
        .env("LLM_HOST", local.ip().to_string())
        .env("LLM_PORT", local.port().to_string())
        .env_remove("PERISKOP_HOOK")
        .env_remove("PERISKOP_HOOK_OUTPUT");
    if hooked {
        command.env("PYTHONPATH", repo_root().join("hooks/python"));
    } else {
        command.env_remove("PYTHONPATH");
    }
    command.spawn().expect("the interpreter runs a script")
}

/// What this run of the gate established, written next to the F2 record.
#[derive(Debug, serde::Serialize)]
struct ProofRecord {
    gate: &'static str,
    status: &'static str,
    reason: String,
    /// How the observation was captured. Never `ebpf`: the loader did not run,
    /// and an artefact that implied it had would be the dishonesty this whole
    /// project is about.
    capture: &'static str,
    /// What this run does not establish, in as many words.
    caveat: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<ProofEvidence>,
}

#[derive(Debug, serde::Serialize)]
struct ProofEvidence {
    static_findings: usize,
    static_suspect_findings: usize,
    /// Events the hook recorded with the process uninstrumented, and again with
    /// the hook loaded. Both are zero, for two independent reasons.
    runtime_events_uninstrumented: usize,
    runtime_events_hooked: usize,
    /// A real child process really connected, and this is what crossed the wire.
    real_child_process: bool,
    bytes_observed_on_the_wire: u64,
    flows_recorded: usize,
    flow_scope: String,
    unmatched_wire_findings: usize,
    finding_confidence: String,
    /// Why the finding is not confirmed. A loopback connection carries no DNS
    /// answer and no handshake, so the destination could not be named, and the
    /// engine refuses to confirm an accusation about a destination nobody could
    /// read. That refusal is correct and is recorded rather than worked around.
    confidence_reason: &'static str,
}

/// Writes the artefact this gate is read through, and fails the test if it
/// cannot.
///
/// The discards this replaces made the artefact worse than absent. A failed
/// write left the previous run's `f3-proof.json` sitting in `target/` while this
/// run reported success, so the file a reader opens to see what was proved would
/// have been the evidence of a run that is no longer the one being described.
/// The stale file is removed before the new one is written, for the same reason:
/// between those two lines there must be no moment where an old artefact could
/// be mistaken for a new one.
fn record_outcome(record: &ProofRecord) {
    let out = repo_root().join("target/f3-proof.json");
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|e| panic!("{} could not be created: {e}", parent.display()));
    }
    match std::fs::remove_file(&out) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!(
            "the artefact of an earlier run at {} could not be removed: {e}",
            out.display()
        ),
    }
    let text = serde_json::to_string_pretty(record).unwrap();
    std::fs::write(&out, text)
        .unwrap_or_else(|e| panic!("{} could not be written: {e}", out.display()));
}

const CAPTURE: &str =
    "accepting_socket_over_a_real_connection, delivered through the KernelEvents seam";
const CAVEAT: &str = "the eBPF loader did not run: it needs a BTF capable Linux kernel and CAP_BPF \
                      with CAP_PERFMON (ADR-014). This run establishes that a call invisible to the \
                      static scanner and to the runtime hook becomes an unmatched_wire_traffic \
                      finding from a sensor record. It does not establish that the eBPF capture \
                      path works.";

fn derived_of_kind(outcome: &scan::ScanOutcome, kind: Kind) -> Vec<&Finding> {
    outcome
        .report
        .findings
        .iter()
        .chain(outcome.report.suspect_findings.iter())
        .filter(|finding| finding.kind == kind)
        .collect()
}

/// The gate. F3 is not closed while this does not pass.
///
/// Five steps, in the order the claim is made: scan the code and find nothing,
/// run the program as a real uninstrumented process, show the hook recorded
/// nothing even when it was loaded, capture the connection at the socket it
/// really crossed, and reconcile all three sources into the finding.
#[test]
fn f3_gate_the_sensor_records_a_call_neither_the_scanner_nor_the_hook_can_see() {
    let interpreter = match python_interpreter() {
        Ok(interpreter) => interpreter,
        Err(reason) => {
            let required = std::env::var_os(REQUIRE_PROOF).is_some();
            record_outcome(&ProofRecord {
                gate: "F3-60",
                status: "skipped",
                reason: reason.clone(),
                capture: CAPTURE,
                caveat: CAVEAT,
                evidence: None,
            });
            assert!(
                !required,
                "{REQUIRE_PROOF} is set and the F3 gate cannot run: {reason}"
            );
            eprintln!(
                "\n  SKIPPED: the F3 end to end proof did not run.\n  \
                 Reason: {reason}\n  \
                 This run does not close F3. Install a python3 interpreter, or set \
                 {REQUIRE_PROOF}=1\n  to make the missing interpreter a failure instead of a \
                 skip.\n"
            );
            return;
        }
    };

    let tree = TempTree::new("socket-egress");
    tree.write("project/app.py", SAMPLE_APP);
    let project = tree.path("project");
    let event_dir = tree.dir("events");
    let flow_dir = tree.dir("flows");

    // (a) The static scan. Nothing in the source names a destination or a
    //     transport, so nothing may be reported: not a confirmed finding and not
    //     a suspect one. A suspect here would mean the scanner had guessed,
    //     which the project forbids more strongly than it forbids missing a call.
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port is free");
    let local = listener.local_addr().unwrap();
    for needle in [
        "socket",
        "create_connection",
        &local.port().to_string(),
        "127.0.0.1",
    ] {
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

    // (b) The program runs as a real, uninstrumented child process and really
    //     connects. The accepting socket is the only thing watching.
    let mut child = run_sample(&interpreter, &project, &event_dir, &listener, false);
    let observed = accept_one(&listener);
    let status = child.wait().expect("the child is reaped");
    assert!(
        status.success(),
        "the sample did not exit cleanly: {status}"
    );
    assert!(
        observed.bytes_from_peer > 0,
        "no bytes crossed the connection, so there is nothing to have observed"
    );

    // (c) The hook saw nothing, for two independent reasons. The process was
    //     never instrumented, and loading the hook does not help: it patches
    //     HTTP client libraries and this call goes out over a socket. The second
    //     run is what turns "we did not install it" into a property of the call.
    let uninstrumented = collect(&event_dir);
    assert!(
        uninstrumented.events.is_empty(),
        "an uninstrumented process produced hook events: {:?}",
        uninstrumented.events
    );

    let hooked_event_dir = tree.dir("events-hooked");
    let mut hooked_child = run_sample(&interpreter, &project, &hooked_event_dir, &listener, true);
    let hooked_observed = accept_one(&listener);
    let hooked_status = hooked_child.wait().expect("the child is reaped");
    assert!(
        hooked_status.success(),
        "the hooked application did not exit cleanly, which breaks the fail-open \
         guarantee before it proves anything: {hooked_status}"
    );
    assert!(hooked_observed.bytes_from_peer > 0);
    let hooked = collect(&hooked_event_dir);
    assert!(
        hooked.events.is_empty(),
        "the hook recorded a raw socket call, so this sample is no longer the one \
         the gate is about: {:?}",
        hooked.events
    );

    // (d) The connection becomes sensor records, through the shipped assembler,
    //     scope policy and record type.
    let flows = sensor_records(&observed, child.id(), &interpreter);
    assert_eq!(flows.len(), 1, "{flows:?}");
    assert_eq!(
        flows[0].flow_scope,
        FlowScope::InScope,
        "the flow has to reach the only bucket that produces a finding"
    );
    assert_eq!(flows[0].bytes_out, Some(observed.bytes_from_peer));
    let body: String = flows
        .iter()
        .map(|flow| format!("{}\n", serde_json::to_string(flow).unwrap()))
        .collect();
    std::fs::write(flow_dir.join("flows.jsonl"), body).unwrap();

    // The record carries no payload. The sample sent a support ticket, and the
    // sensor's whole claim is that it answers where and how much and never what.
    let written = std::fs::read_to_string(flow_dir.join("flows.jsonl")).unwrap();
    for secret in ["ticket 8812", "renewal quote", "missing a line item"] {
        assert!(
            !written.contains(secret),
            "payload content reached a flow record: {secret}"
        );
    }

    // (e) Three sources, one report. The event directory is present and empty,
    //     which is the honest statement that hooks were watching and recorded
    //     nothing, so the run reaches `full` and the traffic is unexplained by
    //     both of the other two sources.
    let reconciled = scan::run_with_sources(
        scan::ScanRequest {
            project_root: &project,
            rules_root: &repo_root().join("rules"),
            tool_version: "0.0.0-test",
            generated_at: "2026-08-04T09:00:00Z".to_owned(),
        },
        scan::ScanSources {
            event_dir: Some(&event_dir),
            flow_dir: Some(&flow_dir),
        },
        ReconcileSettings::default(),
    );

    let unmatched = derived_of_kind(&reconciled, Kind::UnmatchedWireTraffic);
    assert_eq!(
        unmatched.len(),
        1,
        "the sensor's record did not become the finding F3 exists for: {:?}",
        reconciled.report
    );
    // Suspected rather than confirmed, and correctly so. A loopback connection
    // carries no DNS answer and no ClientHello, so the destination could not be
    // named, and the engine refuses to confirm an accusation about a destination
    // nobody could read. Asserting the weaker value is the honest gate: a run
    // that reported `confirmed` here would be claiming knowledge it does not have.
    assert_eq!(unmatched[0].confidence, Confidence::Suspect);
    assert_eq!(
        reconciled.report.coverage.in_scope_flows, 1,
        "the denominator the attribution accuracy gate is computed from"
    );

    record_outcome(&ProofRecord {
        gate: "F3-60",
        status: "proved",
        reason: "a real uninstrumented child process opened a real socket, the static scan and \
                 both hook runs produced nothing, and the sensor record became an \
                 unmatched_wire_traffic finding"
            .to_owned(),
        capture: CAPTURE,
        caveat: CAVEAT,
        evidence: Some(ProofEvidence {
            static_findings: outcome.report.findings.len(),
            static_suspect_findings: outcome.report.suspect_findings.len(),
            runtime_events_uninstrumented: uninstrumented.events.len(),
            runtime_events_hooked: hooked.events.len(),
            real_child_process: true,
            bytes_observed_on_the_wire: observed.bytes_from_peer,
            flows_recorded: flows.len(),
            flow_scope: flows[0].flow_scope.as_str().to_owned(),
            unmatched_wire_findings: unmatched.len(),
            finding_confidence: format!("{:?}", unmatched[0].confidence).to_lowercase(),
            confidence_reason: "the loopback connection carried no DNS answer and no ClientHello, \
                                so the destination could not be named",
        }),
    });
}

/// The other half of the gate: the three quiet buckets are not the finding.
///
/// Milestone 56's acceptance criterion, on a real connection rather than on a
/// fixture. The same traffic, from a process the operator did not declare as the
/// codebase, produces no accusation and still appears in the report. A tool that
/// raised this finding for every connection on a developer's machine would be
/// unusable within a day, and one that hid the flows entirely would be lying by
/// omission.
#[test]
fn f3_gate_traffic_from_a_process_outside_the_codebase_is_counted_and_never_accused() {
    let interpreter = match python_interpreter() {
        Ok(interpreter) => interpreter,
        Err(reason) => {
            // The gate above owns the artefact; writing it here too would leave
            // two records of one run. What is not delegated is the switch: a
            // variable that turned a skip into a failure in one test of this
            // file and left the other silent would cover half the gate while
            // reading like it covered the whole of it.
            assert!(
                std::env::var_os(REQUIRE_PROOF).is_none(),
                "{REQUIRE_PROOF} is set and the F3 gate cannot run: {reason}"
            );
            return;
        }
    };

    let tree = TempTree::new("out-of-scope");
    tree.write("project/app.py", SAMPLE_APP);
    let project = tree.path("project");
    let event_dir = tree.dir("events");
    let flow_dir = tree.dir("flows");

    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port is free");
    let mut child = run_sample(&interpreter, &project, &event_dir, &listener, false);
    let observed = accept_one(&listener);
    assert!(child.wait().expect("the child is reaped").success());

    // The operator declared a different program as the codebase, so this real
    // connection belongs to somebody else's process.
    let mut source = EbpfFlowSource::over(
        AcceptedConnectionKernel::of(&observed, child.id(), &interpreter),
        "h_f3proofhost0001",
    );
    source
        .attach(&Grant {
            tc_available: false,
            elevated_as_root: false,
        })
        .unwrap();
    let policy = ScopePolicy::for_codebase(["some-other-program".to_owned()]);
    let flows: Vec<Flow> = source
        .drain()
        .into_iter()
        .map(|observation| {
            let scope = policy.classify(&observation);
            Flow::from_observation(observation, scope, Mechanism::Ebpf).unwrap()
        })
        .collect();
    assert_eq!(flows[0].flow_scope, FlowScope::OutOfScopeProcess);

    let body: String = flows
        .iter()
        .map(|flow| format!("{}\n", serde_json::to_string(flow).unwrap()))
        .collect();
    std::fs::write(flow_dir.join("flows.jsonl"), body).unwrap();

    let reconciled = scan::run_with_sources(
        scan::ScanRequest {
            project_root: &project,
            rules_root: &repo_root().join("rules"),
            tool_version: "0.0.0-test",
            generated_at: "2026-08-04T09:00:00Z".to_owned(),
        },
        scan::ScanSources {
            event_dir: Some(&event_dir),
            flow_dir: Some(&flow_dir),
        },
        ReconcileSettings::default(),
    );

    assert!(
        derived_of_kind(&reconciled, Kind::UnmatchedWireTraffic).is_empty(),
        "a process outside the declared codebase produced an accusation: {:?}",
        reconciled.report
    );
    // Counted, not hidden. A bucket that keeps traffic out of the accounting and
    // then vanishes from the report is the silent swallow K-15 exists to prevent.
    assert_eq!(reconciled.report.coverage.out_of_scope_flows, 1);
    assert_eq!(reconciled.report.coverage.in_scope_flows, 0);
}
