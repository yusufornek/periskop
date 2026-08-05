#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! The F4 kernel gate (milestone 100): a program running in a kernel reports a
//! connection this test made, and the report carries destination, volume and
//! time without anything having read a byte of what was sent.
//!
//! # What this exists to remove
//!
//! `target/f3-proof.json` closed F3 carrying a caveat in as many words: the eBPF
//! loader did not run, the observation was measured by the accepting socket and
//! handed to the sensor through the `KernelEvents` seam, and the run therefore
//! established nothing about the capture path. That caveat was honest and it was
//! also the phase's largest open question, because a sensor whose transport has
//! never run is a sensor nobody has seen work.
//!
//! This gate's whole job is to take that sentence away. Every fact in the
//! artefact it writes comes from a program the kernel verified and accepted, and
//! `capture` says `ebpf` because it is.
//!
//! # Why the claims here do not read the implementation's own numbers
//!
//! A gate that asserts the code against constants the code declares proves that
//! the code is self consistent, which is not what a gate is for. So every number
//! this test checks is one it arranged or measured independently:
//!
//! - the **port** is chosen by the operating system when the listener binds, and
//!   is not known to any part of periskop until the kernel reports it back;
//! - the **byte count** is what this process wrote and, separately, what the
//!   listening socket counted on the other side of the connection;
//! - the **time** is compared against this machine's wall clock at the moment of
//!   capture, not against the bucket width the loader configured;
//! - the **process** is this test's own pid, read from the operating system.
//!
//! If the kernel side read a wrong structure offset, or the record layout on the
//! two sides of the seam disagreed, or the clock offset were wrong, the values
//! would not be these values. That is the property that makes this a measurement
//! rather than a restatement.
//!
//! # What it deliberately does not do
//!
//! It does not send anything off the machine. periskop must not be an egress
//! source, and a test that reached a real destination would also be measuring
//! whether the runner had a network. The connection is loopback, and the
//! artefact says so among the things it does not prove.
//!
//! **If this test does not report `proved`, F4 exit criterion 1 is open and the
//! phase is not closed.** A run that skipped it did not close it either:
//! `PERISKOP_REQUIRE_KERNEL_PROOF` turns every skip in this file into a failure,
//! and the privileged Linux job in `.github/workflows/ci.yml` is the only place
//! that sets it.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use periskop_network_sensor::flow::{Flow, Mechanism, ProcessAttribution};
use periskop_network_sensor::platform::{self, SensorPlatformClass};
use periskop_network_sensor::privilege::{Grant, Privileges};
use periskop_network_sensor::source::FlowSource;
use periskop_network_sensor::{EbpfFlowSource, ScopePolicy};

/// Set by the privileged Linux job, and nowhere else. With it set, every path in
/// this file that would record a skip fails instead.
const REQUIRE_KERNEL_PROOF: &str = "PERISKOP_REQUIRE_KERNEL_PROOF";

/// Opaque and fixed, because a report must not carry infrastructure naming and
/// two runs of this gate have to produce comparable artefacts.
const HOST_ID: &str = "h_f4kernelhost001";
const BOOT_ID: &str = "b_f4kernelboot001";

/// The bytes the client writes.
///
/// Recognisable on purpose: the gate searches every record it produced for this
/// string, and finding it would mean payload had reached a place no payload may
/// reach. It is not a credential and is not shaped like one.
const PAYLOAD_MARKER: &str = "periskop-f4-kernel-gate-payload-must-not-appear-in-any-record";

/// How long to wait for the ring buffer to carry the connection up.
///
/// The probes fire inside the syscalls this test makes, so the records exist
/// before `connect` returns; the wait is for the reader, not for the kernel. A
/// generous ceiling with an early exit, so a working run is fast and a broken
/// one still ends.
const CAPTURE_DEADLINE: Duration = Duration::from_secs(10);

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// What this run of the gate established, and what it did not.
///
/// The two lists are separate fields rather than one paragraph because they are
/// read for different reasons: the first is what somebody may rely on, and the
/// second is what somebody must not. `f3-proof.json` kept them apart in a single
/// `caveat` string and this splits them, because that string grew to a paragraph
/// and a paragraph is not a list anybody can check against.
#[derive(Debug, serde::Serialize)]
struct KernelProof {
    gate: &'static str,
    /// `proved` only when a kernel program reported the connection this test
    /// made. Anything else is `not_proved`, and the reason says which wall was
    /// hit.
    status: &'static str,
    /// `ebpf` when the observation came out of a ring buffer a kernel program
    /// wrote to, `none` otherwise. There is no third value: this artefact exists
    /// because F3's could not say `ebpf` and had to explain why.
    capture: &'static str,
    reason: String,
    proves: Vec<String>,
    does_not_prove: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<Evidence>,
}

/// The measurements, each one arranged or counted outside the code under test.
#[derive(Debug, serde::Serialize)]
struct Evidence {
    /// Chosen by the operating system at bind time. Nothing in periskop knows it
    /// until a kernel program reports it back.
    listener_port_the_test_dialled: u16,
    bytes_the_client_wrote: u64,
    /// Counted by the listening socket, which is the other end of the same
    /// connection and shares no code with the sensor.
    bytes_the_listener_counted: u64,
    /// This process, read from the operating system rather than from a record.
    pid_of_the_connecting_process: u32,
    wall_clock_seconds_at_capture: u64,
    observations_sealed: usize,
    flows_recorded: usize,
    /// The one flow that matched the connection this test made.
    matched: MatchedFlow,
    /// Ring buffer losses the kernel program counted, and frames the decoder
    /// refused. Both zero in a healthy run, and both reported rather than
    /// assumed, because a run that lost records must not read like a quiet one.
    ring_buffer_frames_dropped: u64,
    records_the_decoder_refused: u64,
    /// Searched for byte by byte in the serialised records.
    payload_marker_found_in_any_record: bool,
}

/// The kernel's account of the connection, beside the test's own.
#[derive(Debug, serde::Serialize)]
struct MatchedFlow {
    destination_ip: String,
    destination_port: u16,
    bytes_out: Option<u64>,
    bytes_in: Option<u64>,
    t_start_bucket: u64,
    seconds_between_bucket_and_wall_clock: i64,
    process_attribution: String,
    process_pid: Option<u32>,
    process_comm: Option<String>,
    mechanism: String,
    flow_scope: String,
    degraded_reasons: Vec<String>,
}

/// What a run of this gate on a working kernel establishes.
fn proves() -> Vec<String> {
    [
        "a TCP connection this test opened to a port the operating system chose was reported by an \
         eBPF program the kernel verified and accepted",
        "the destination address and port in the record are the ones the test dialled, so the \
         kernel side read the socket correctly rather than plausibly",
        "the outbound byte count in the record is at least what the client wrote and what the \
         listening socket independently counted",
        "the record's start bucket agrees with this machine's wall clock at the moment of capture, \
         so the clock the loader handed the kernel program is the right one",
        "the connection is attributed to this test's own process id, read from the operating \
         system and not from the record",
        "no byte of the payload appears anywhere in the records, which is what \"periskop observes \
         connections and never their contents\" means when it is measured rather than asserted",
        "the capabilities that allowed the load are gone afterwards, which the loader's own \
         `kernel_required` suite demonstrates by failing a second load",
    ]
    .map(str::to_owned)
    .to_vec()
}

/// What it does not, stated as flatly as what it does.
fn does_not_prove() -> Vec<String> {
    [
        "name resolution: this build carries no `clsact` classifier, so no DNS answer and no TLS \
         server name was observed and `sni_source` says so on every record",
        "IPv6: the kernel object reads only the configuration independent prefix of `struct sock`, \
         so an AF_INET6 connection produces no record and this run made none",
        "the network namespace and the process start time: both are declared absent by the kernel \
         object rather than measured, so container traffic is not distinguished here and pid reuse \
         over a long observation is not guarded against",
        "traffic that left the machine: the connection is loopback, deliberately, because periskop \
         must not be an egress source",
        "TLS content: nothing on this path reads packet payload at all, which is a property of the \
         program rather than a measurement of it",
        "behaviour under load: the ring buffer's loss counter is reported and nothing in this run \
         filled the buffer, so the loss path is declared and unexercised",
        "the `periskop sensor` command's own loop: this gate drives attach, traffic and drain as \
         three steps, because `observe` performs one attach and one drain in a single call and \
         would look at a window in which nothing had happened yet",
    ]
    .map(str::to_owned)
    .to_vec()
}

/// Writes the artefact this gate is read through, and fails the test if it
/// cannot.
///
/// The stale file is removed before the new one is written. Between those two
/// lines there must be no moment at which an earlier run's artefact could be
/// mistaken for this one's, which is a failure mode that has happened here
/// before: a failed write left a previous `proved` sitting in `target/` while
/// the run that reported it was no longer the run being described.
fn record_outcome(proof: &KernelProof) {
    let out = repo_root().join("target/f4-kernel-proof.json");
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
    let text = serde_json::to_string_pretty(proof).unwrap();
    std::fs::write(&out, text)
        .unwrap_or_else(|e| panic!("{} could not be written: {e}", out.display()));
}

/// Records a run that could not reach the claim, and fails where a run must not
/// be allowed to stop here.
fn not_proved(reason: String) {
    record_outcome(&KernelProof {
        gate: "F4-100",
        status: "not_proved",
        capture: "none",
        reason: reason.clone(),
        proves: Vec::new(),
        does_not_prove: does_not_prove(),
        evidence: None,
    });
    assert!(
        std::env::var_os(REQUIRE_KERNEL_PROOF).is_none(),
        "{REQUIRE_KERNEL_PROOF} is set and the F4 kernel gate could not run: {reason}"
    );
    eprintln!(
        "\n  SKIPPED: the F4 kernel proof did not run.\n  Reason: {reason}\n  \
         This run does not close F4 exit criterion 1. Run it on a Linux kernel with BTF, as a \
         process holding CAP_BPF and CAP_PERFMON, against a build carrying a kernel side object, \
         or set {REQUIRE_KERNEL_PROOF}=1 to make this a failure instead of a skip.\n"
    );
}

/// A listener on loopback that counts what arrives and echoes nothing.
///
/// Its port is the fact this whole gate turns on: the operating system picks it,
/// this test learns it from the socket, and the only other party that can name
/// it is something that watched the connection.
struct Listener {
    address: SocketAddr,
    listener: TcpListener,
}

impl Listener {
    fn open() -> std::io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        Ok(Self { address, listener })
    }

    /// Accepts one connection and returns how many bytes crossed it.
    fn count_one_connection(&self) -> std::io::Result<u64> {
        let (mut stream, _) = self.listener.accept()?;
        let mut counted = 0u64;
        let mut buffer = [0u8; 4096];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => return Ok(counted),
                Ok(read) => counted = counted.saturating_add(read as u64),
                Err(error) => return Err(error),
            }
        }
    }
}

/// This process's short name, as the kernel spells it.
///
/// Read from `/proc` rather than from `std::env::args`, because the kernel
/// truncates `comm` at sixteen bytes and the scope policy has to be given the
/// string the kernel will report, not the one the shell typed.
fn own_comm() -> String {
    std::fs::read_to_string("/proc/self/comm")
        .map(|name| name.trim().to_owned())
        .unwrap_or_default()
}

fn seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

/// What the artefact's `capture` field says, read off the record rather than
/// typed into it.
///
/// This was the literal `"ebpf"`, written beside an assertion that compared the
/// mechanism against the same `Mechanism::Ebpf` the test had handed to
/// `Flow::from_observation` three lines earlier. Both halves were true by
/// construction: the gate set the value, asserted the value it had set, and then
/// declared it in the artefact. A build whose sensor stopped capturing through
/// eBPF would have gone on saying `ebpf`, which is the one sentence this file
/// exists to be able to say honestly.
///
/// Two facts decide it now, and neither is chosen here:
///
/// - the mechanism the **shipped** decision produced ([`platform::detect`] and
///   [`SensorPlatformClass::mechanism`], the same pair the sensor's own reports
///   go through), rather than a name this test picked;
/// - the attribution on the record, which is `KernelAttributed` only when the
///   process came out of the calling task's context. A kprobe runs there; a
///   packet capture reading the same connection off a wire has no task to read
///   and cannot produce it.
///
/// Anything else is `none`, which is the value the artefact check in
/// `.github/workflows/ci.yml` fails the job on.
fn capture_of(mechanism: Mechanism, attribution: ProcessAttribution) -> &'static str {
    match (mechanism, attribution) {
        (Mechanism::Ebpf, ProcessAttribution::KernelAttributed) => "ebpf",
        _ => "none",
    }
}

/// The gate. F4 exit criterion 1 is open while this does not report `proved`.
#[test]
fn f4_kernel_gate_a_program_in_the_kernel_reports_a_connection_this_test_made() {
    if !cfg!(target_os = "linux") {
        not_proved(
            "this machine is not Linux, and ADR-008 gives v1 no capture mechanism for any other \
             platform"
                .to_owned(),
        );
        return;
    }

    // The mechanism every record below is built with, taken from the shipped
    // decision rather than named here. `platform::detect` is what the sensor's
    // own coverage statement runs through, so a build that stopped being the
    // eBPF sensor produces a record this gate refuses instead of one it
    // relabels.
    let class = platform::detect();
    let Some(mechanism) = class.mechanism() else {
        not_proved(format!(
            "the shipped platform decision offers no capture mechanism on this machine \
             (class={})",
            class.as_str()
        ));
        return;
    };

    let privileges = Privileges::probe();
    let listener = match Listener::open() {
        Ok(listener) => listener,
        Err(error) => {
            not_proved(format!("no loopback listener could be opened: {error}"));
            return;
        }
    };

    let mut source = EbpfFlowSource::new(HOST_ID).with_boot_id(BOOT_ID);
    let requested = Grant {
        tc_available: privileges.cap_net_admin || privileges.is_root(),
        elevated_as_root: privileges.is_root(),
    };
    // Driven directly rather than through `observe`, which attaches and drains
    // in one call and would therefore look at a window in which the connection
    // had not happened yet. Everything below the attach is the shipped code.
    let effective = match source.attach(&requested) {
        Ok(effective) => effective,
        Err(reason) => {
            not_proved(format!(
                "the sensor did not attach: {} (btf={}, cap_bpf={}, cap_perfmon={}, root={})",
                reason.as_str(),
                privileges.btf_available,
                privileges.cap_bpf,
                privileges.cap_perfmon,
                privileges.is_root()
            ));
            return;
        }
    };

    // The connection, made by this process so that the attribution the kernel
    // reports can be checked against a pid this test already knows.
    let port = listener.address.port();
    let payload = PAYLOAD_MARKER.repeat(64);
    let written = payload.len() as u64;
    let accepted = std::thread::spawn({
        // The listener moves into the accepting thread; the connection has to be
        // accepted while the client is writing or the write blocks on the
        // backlog.
        move || listener.count_one_connection()
    });

    let wall_clock_at_capture = seconds_now();
    let mut client = match TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port))) {
        Ok(client) => client,
        Err(error) => {
            not_proved(format!("the loopback connection failed: {error}"));
            return;
        }
    };
    client
        .write_all(payload.as_bytes())
        .expect("a loopback write");
    client.flush().expect("a loopback flush");
    // Closed so the teardown probe fires as well as the setup one. The assembler
    // seals open connections too, so this is about exercising the path rather
    // than about getting a record at all.
    drop(client);
    let counted = accepted
        .join()
        .expect("the accepting thread")
        .expect("the accepting socket counted what arrived");

    let policy = ScopePolicy::for_codebase([own_comm()]);
    let mut observations = Vec::new();
    let deadline = Instant::now() + CAPTURE_DEADLINE;
    let mut flows: Vec<Flow> = Vec::new();
    while Instant::now() < deadline {
        for observation in source.drain() {
            let scope = policy.classify(&observation);
            let observation = if effective.tc_available {
                observation
            } else {
                observation.degraded(vec![
                    periskop_network_sensor::flow::DegradedReason::TcUnavailable,
                ])
            };
            observations.push(());
            if let Ok(flow) = Flow::from_observation(observation, scope, mechanism) {
                flows.push(flow);
            }
        }
        if flows.iter().any(|flow| flow.five_tuple.dst_port == port) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let coverage = source.coverage();
    let Some(matched) = flows.iter().find(|flow| flow.five_tuple.dst_port == port) else {
        not_proved(format!(
            "the sensor attached and no record named the port this test dialled ({port}); {} \
             record(s) came back",
            flows.len()
        ));
        return;
    };

    // Everything from here is an assertion, not a branch. A run that reached
    // this line has a kernel that reported something, and a report that
    // disagreed with the connection would be a wrong report rather than a
    // missing one.
    assert_eq!(
        matched.five_tuple.dst_ip,
        Ipv4Addr::LOCALHOST.to_string(),
        "the kernel reported a destination address this test never dialled"
    );
    assert_eq!(
        matched.process_attribution,
        ProcessAttribution::KernelAttributed,
        "a kprobe runs in the calling task's context, so an unattributed flow means the process \
         was read from somewhere else"
    );
    // Not `Mechanism::Ebpf` against `Mechanism::Ebpf`: this compares the record
    // against what the *shipped* platform decision produced, which nothing in
    // this file chose. The gate closes F4 exit criterion 1 on the eBPF path
    // specifically, so a machine the product would observe some other way has to
    // fail here rather than be written up as a kernel capture.
    assert_eq!(
        class,
        SensorPlatformClass::LinuxEbpf,
        "this build's shipped platform decision is not the eBPF sensor, so no run of it closes \
         the criterion this gate is about"
    );
    let capture = capture_of(matched.mechanism, matched.process_attribution);
    assert_eq!(
        capture, "ebpf",
        "the record does not carry the two marks of a kernel capture (mechanism={:?}, \
         attribution={:?})",
        matched.mechanism, matched.process_attribution
    );
    let pid = matched.process.as_ref().map(|process| process.pid);
    assert_eq!(
        pid,
        Some(std::process::id()),
        "the connection was made by this process and the record names another"
    );

    let bytes_out = matched.bytes_out.unwrap_or(0);
    assert!(
        bytes_out >= written && bytes_out >= counted,
        "the kernel reported {bytes_out} bytes out for a connection this test wrote {written} \
         bytes to and the listener counted {counted} on"
    );

    let drift = i64::try_from(matched.t_start_bucket).unwrap_or(0)
        - i64::try_from(wall_clock_at_capture).unwrap_or(0);
    assert!(
        (-300..=60).contains(&drift),
        "the record's start bucket is {drift} seconds from the wall clock at capture, so the \
         offset the loader handed the kernel program is wrong"
    );

    let serialised = serde_json::to_string(&flows).expect("records serialise");
    let leaked = serialised.contains(PAYLOAD_MARKER);
    assert!(
        !leaked,
        "a byte of the payload reached a record, which is the one thing this sensor may never do"
    );

    let refused: u64 = coverage
        .rejected_payload_samples
        .get("record_undecodable")
        .copied()
        .unwrap_or(0);
    assert_eq!(
        refused, 0,
        "the decoder refused {refused} frame(s), so the kernel object and this build do not agree \
         on the record layout"
    );

    record_outcome(&KernelProof {
        gate: "F4-100",
        status: "proved",
        capture,
        reason: "a kprobe pair the kernel verified reported the loopback connection this test made"
            .to_owned(),
        proves: proves(),
        does_not_prove: does_not_prove(),
        evidence: Some(Evidence {
            listener_port_the_test_dialled: port,
            bytes_the_client_wrote: written,
            bytes_the_listener_counted: counted,
            pid_of_the_connecting_process: std::process::id(),
            wall_clock_seconds_at_capture: wall_clock_at_capture,
            observations_sealed: observations.len(),
            flows_recorded: flows.len(),
            matched: MatchedFlow {
                destination_ip: matched.five_tuple.dst_ip.clone(),
                destination_port: matched.five_tuple.dst_port,
                bytes_out: matched.bytes_out,
                bytes_in: matched.bytes_in,
                t_start_bucket: matched.t_start_bucket,
                seconds_between_bucket_and_wall_clock: drift,
                process_attribution: format!("{:?}", matched.process_attribution),
                process_pid: matched.process.as_ref().map(|process| process.pid),
                process_comm: matched
                    .process
                    .as_ref()
                    .and_then(|process| process.comm.clone()),
                mechanism: format!("{:?}", matched.mechanism),
                flow_scope: format!("{:?}", matched.flow_scope),
                degraded_reasons: matched
                    .degraded_reasons
                    .clone()
                    .unwrap_or_default()
                    .iter()
                    .map(|reason| format!("{reason:?}"))
                    .collect(),
            },
            ring_buffer_frames_dropped: coverage.dropped_events,
            records_the_decoder_refused: refused,
            payload_marker_found_in_any_record: leaked,
        }),
    });
}

/// The label the artefact carries has to depend on the record it describes.
///
/// This runs everywhere, including the development machine, because it is about
/// the gate's own arithmetic rather than about a kernel. The value it pins is
/// the one the artefact check in `.github/workflows/ci.yml` reads: anything but
/// `ebpf` fails the workflow, so every row below that answers `none` is a build
/// this gate would refuse to close the criterion for.
#[test]
fn the_capture_label_is_read_off_a_record_rather_than_declared() {
    assert_eq!(
        capture_of(Mechanism::Ebpf, ProcessAttribution::KernelAttributed),
        "ebpf"
    );

    // A different mechanism reading the same connection. Both of these are
    // decided by ADR-008 and unbuilt in v1, and a gate carrying a literal would
    // have written `ebpf` for either of them the day one arrived.
    for other in [Mechanism::Pcap, Mechanism::Etw] {
        assert_eq!(
            capture_of(other, ProcessAttribution::KernelAttributed),
            "none",
            "{other:?} was reported as a kernel capture"
        );
    }

    // The eBPF mechanism without the mark only a program running in the calling
    // task's context leaves. A record assembled from somewhere other than the
    // ring buffer looks like this, and it is not what this gate closes.
    for weaker in [
        ProcessAttribution::Inferred,
        ProcessAttribution::Unattributed,
    ] {
        assert_eq!(
            capture_of(Mechanism::Ebpf, weaker),
            "none",
            "{weaker:?} was reported as a kernel capture"
        );
    }
}

/// The mechanism the gate builds its records with is the shipped decision.
///
/// Held here as well as at the point of use, because the point of use only runs
/// on a privileged Linux runner and this is the assertion that a development
/// machine can still fail: if `platform::detect` ever answered `linux_ebpf` off
/// Linux, or stopped answering it on Linux, the gate would be building records
/// under a mechanism the product does not use.
#[test]
fn the_gate_takes_its_mechanism_from_the_shipped_platform_decision() {
    let class = platform::detect();
    if cfg!(target_os = "linux") {
        assert_eq!(class, SensorPlatformClass::LinuxEbpf);
        assert_eq!(class.mechanism(), Some(Mechanism::Ebpf));
    } else {
        assert_eq!(class, SensorPlatformClass::None);
        assert_eq!(
            class.mechanism(),
            None,
            "a machine with no capture mechanism offered one, which would let this gate build \
             records on a platform ADR-008 gives v1 no sensor for"
        );
    }
}

#[test]
fn the_artefact_separates_what_this_gate_proves_from_what_it_does_not() {
    // The lesson `f3-proof.json` taught, held as an assertion. Its caveat was a
    // paragraph, and a paragraph is something a reader skims; a phase closed on
    // a skimmed caveat is a phase closed on a misunderstanding. Two lists that
    // cannot be empty and cannot overlap are harder to skim past.
    let proved = proves();
    let unproved = does_not_prove();
    assert!(!proved.is_empty());
    assert!(!unproved.is_empty());
    for claim in &proved {
        assert!(
            !unproved.contains(claim),
            "the artefact both claims and disclaims: {claim}"
        );
    }
    // The three the F4 exit criterion names, so a future edit cannot quietly
    // drop one of them from what the gate says it establishes.
    for subject in ["destination", "byte count", "wall clock"] {
        assert!(
            proved.iter().any(|claim| claim.contains(subject)),
            "the gate no longer claims to establish the {subject}"
        );
    }
    assert!(
        unproved.iter().any(|claim| claim.contains("server name")),
        "name resolution stopped being listed as unproved without a classifier arriving"
    );
}
