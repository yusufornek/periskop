//! From packet bytes to a contract record, through the public surface only.
//!
//! The unit tests pin one rule at a time and mostly start from parsed facts.
//! What is checked here is the chain nobody owns on their own: real wire bytes
//! go into the parsers, the facts go into the assembler as the kernel would
//! deliver them, and a `Flow` comes out with a name, a source for that name and
//! an attribution on it.
//!
//! **What is not checked here, and why.** No test in this file loads an eBPF
//! program. Doing that needs a Linux kernel with BTF, `CAP_BPF` and
//! `CAP_PERFMON`, and it needs the loader crate ADR-014 defers. The one test
//! that would need all of that is marked `#[ignore]` at the bottom of this
//! file with its reason spelled out, so it appears in the test list as skipped
//! rather than being quietly absent.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use periskop_network_sensor::flow::{
    Classification, DegradedReason, Flow, Mechanism, ProcessAttribution, Proto, ResolvedHostSource,
    SniSource,
};
use periskop_network_sensor::kernel::event::{
    ConnectEvent, KernelBatch, KernelEvent, KernelProcess, PayloadEvent, PayloadFacts,
};
use periskop_network_sensor::kernel::{AttachPlan, FlowKey, KernelEvents};
use periskop_network_sensor::parse::{dns, tls};
use periskop_network_sensor::privilege::{Grant, Privileges, SensorUnavailable};
use periskop_network_sensor::resolve::DnsObservation;
use periskop_network_sensor::scope::{FlowScope, ScopePolicy};
use periskop_network_sensor::source::{EbpfFlowSource, FlowSource};
use std::net::IpAddr;

const HOST_ID: &str = "h_9f2c4a17be0d5386";
const BOOT_ID: &str = "b_3f0a91c7d4e28b56";
const T_START: u64 = 1_785_834_000;

// ---------------------------------------------------------------- wire fixtures

fn encoded_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(u8::try_from(label.len()).unwrap());
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// A response with one question and one A record, as a resolver writes it.
fn dns_response(question: &str, owner: &str, ip: [u8; 4], ttl: u32) -> Vec<u8> {
    let mut out = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    out.extend_from_slice(&encoded_name(question));
    out.extend_from_slice(&[0, 1, 0, 1]);
    out.extend_from_slice(&encoded_name(owner));
    out.extend_from_slice(&1u16.to_be_bytes()); // A
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&ip);
    out
}

fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
    out.extend_from_slice(data);
    out
}

fn server_name_extension(host: &str) -> Vec<u8> {
    let host = host.as_bytes();
    let mut entry = vec![0x00];
    entry.extend_from_slice(&u16::try_from(host.len()).unwrap().to_be_bytes());
    entry.extend_from_slice(host);
    let mut data = Vec::new();
    data.extend_from_slice(&u16::try_from(entry.len()).unwrap().to_be_bytes());
    data.extend_from_slice(&entry);
    extension(0x0000, &data)
}

fn client_hello(extensions: &[Vec<u8>]) -> Vec<u8> {
    let mut block = Vec::new();
    for ext in extensions {
        block.extend_from_slice(ext);
    }
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&u16::try_from(block.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&block);

    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&u16::try_from(handshake.len()).unwrap().to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn hello_for(host: &str) -> Vec<u8> {
    client_hello(&[server_name_extension(host)])
}

fn ech_hello() -> Vec<u8> {
    client_hello(&[
        server_name_extension("public.cloudflare-ech.com"),
        extension(0xfe0d, &[0x00, 0x01, 0x02]),
    ])
}

// ------------------------------------------------------------------ event shape

fn key(dst_ip: &str, dst_port: u16, src_port: u16) -> FlowKey {
    FlowKey {
        netns: Some(4_026_531_840),
        src_ip: "10.1.2.3".parse::<IpAddr>().unwrap(),
        src_port,
        dst_ip: dst_ip.parse::<IpAddr>().unwrap(),
        dst_port,
        proto: Proto::Tcp,
    }
}

fn connect(flow: &FlowKey, at_secs: u64, exe_comm: &str) -> KernelEvent {
    KernelEvent::Connect(ConnectEvent {
        key: flow.clone(),
        t_start_bucket: T_START,
        at_secs,
        process: KernelProcess {
            pid: 4821,
            pid_start_time: Some(1_785_833_900),
            comm: Some(exe_comm.to_owned()),
        },
        pre_existing: false,
    })
}

/// The tc helper's contribution: bytes in, facts out, nothing in between.
fn dns_payload(flow: &FlowKey, at_secs: u64, message: &[u8]) -> KernelEvent {
    let answers = dns::parse_response(message).expect("the fixture is a well formed response");
    KernelEvent::Payload(PayloadEvent {
        key: flow.clone(),
        t_start_bucket: T_START,
        at_secs,
        facts: PayloadFacts::Dns(answers),
    })
}

fn hello_payload(flow: &FlowKey, at_secs: u64, sample: &[u8]) -> KernelEvent {
    let facts = tls::parse_client_hello(sample).expect("the fixture is a well formed hello");
    KernelEvent::Payload(PayloadEvent {
        key: flow.clone(),
        t_start_bucket: T_START,
        at_secs,
        facts: PayloadFacts::Handshake(facts),
    })
}

/// A kernel that replays one batch and then has nothing more to say.
struct ReplayKernel {
    batch: Option<KernelBatch>,
}

impl ReplayKernel {
    fn of(events: Vec<KernelEvent>) -> Self {
        Self {
            batch: Some(KernelBatch::of(events)),
        }
    }
}

impl KernelEvents for ReplayKernel {
    fn attach(&mut self, _plan: &AttachPlan) -> Result<(), SensorUnavailable> {
        Ok(())
    }

    fn poll(&mut self) -> KernelBatch {
        self.batch.take().unwrap_or_default()
    }

    /// A replay carries only events, so nothing here was ever refused by a
    /// parser. Empty is the measurement, not a stand in for one.
    fn rejected_samples(&self) -> std::collections::BTreeMap<&'static str, u64> {
        std::collections::BTreeMap::new()
    }
}

fn grant() -> Grant {
    Grant {
        tc_available: true,
        elevated_as_root: false,
    }
}

fn policy() -> ScopePolicy {
    ScopePolicy::for_codebase(["python3"])
}

/// Runs the events through the source and turns the observations into records
/// the same way the sensor loop does.
fn records(events: Vec<KernelEvent>) -> Vec<Flow> {
    let mut source = EbpfFlowSource::over(ReplayKernel::of(events), HOST_ID).with_boot_id(BOOT_ID);
    source.attach(&grant()).unwrap();
    let policy = policy();
    source
        .drain()
        .into_iter()
        .map(|observation| {
            let scope = policy.classify(&observation);
            Flow::from_observation(observation, scope, Mechanism::Ebpf).unwrap()
        })
        .collect()
}

fn record_for<'a>(records: &'a [Flow], dst_ip: &str) -> &'a Flow {
    records
        .iter()
        .find(|record| record.five_tuple.dst_ip == dst_ip)
        .expect("no record for that destination")
}

// ----------------------------------------------------------------------- tests

#[test]
fn a_resolved_connection_becomes_a_record_naming_its_destination() {
    // The ordinary case, from resolver bytes to a contract record: a DNS answer
    // is read off the wire, a handshake confirms the name, and the connection is
    // attributed to the process the kernel saw open it.
    let resolver = key("10.0.0.53", 53, 40000);
    let flow = key("104.18.7.1", 443, 54321);
    let records = records(vec![
        dns_payload(
            &resolver,
            1,
            &dns_response("api.openai.com", "api.openai.com", [104, 18, 7, 1], 300),
        ),
        connect(&flow, 2, "python3"),
        hello_payload(&flow, 2, &hello_for("api.openai.com")),
    ]);

    assert_eq!(records.len(), 1);
    let record = record_for(&records, "104.18.7.1");
    assert_eq!(record.resolved_host.as_deref(), Some("api.openai.com"));
    assert_eq!(
        record.resolved_host_source,
        Some(ResolvedHostSource::DnsAndSni)
    );
    assert_eq!(record.sni.as_deref(), Some("api.openai.com"));
    assert_eq!(record.sni_source, SniSource::ClientHello);
    assert_eq!(record.dns_names, Some(vec!["api.openai.com".to_owned()]));
    assert_eq!(
        record.process_attribution,
        ProcessAttribution::KernelAttributed
    );
    assert_eq!(record.flow_scope, FlowScope::InScope);
    assert_eq!(record.mechanism, Mechanism::Ebpf);
    assert_eq!(record.degraded_reasons, None);
    // No signature database ran, so a named destination that matched nothing is
    // a visible warning rather than a blind spot.
    assert_eq!(record.classification, Classification::Unclassified);
    record.validate().unwrap();
}

#[test]
fn a_cdn_answer_and_a_server_name_that_disagree_both_reach_the_record() {
    // Milestone 52's rule, end to end. The handshake wins, the disagreement is
    // declared, and both halves of the evidence are in the record so a reader
    // can check the claim rather than take it.
    let resolver = key("10.0.0.53", 53, 40000);
    let flow = key("104.18.7.1", 443, 54321);
    let records = records(vec![
        dns_payload(
            &resolver,
            1,
            &dns_response("edge.cdn.example", "edge.cdn.example", [104, 18, 7, 1], 300),
        ),
        connect(&flow, 2, "python3"),
        hello_payload(&flow, 2, &hello_for("api.openai.com")),
    ]);

    let record = record_for(&records, "104.18.7.1");
    assert_eq!(record.resolved_host.as_deref(), Some("api.openai.com"));
    assert_eq!(record.resolved_host_source, Some(ResolvedHostSource::Sni));
    assert_eq!(record.dns_names, Some(vec!["edge.cdn.example".to_owned()]));
    assert_eq!(
        record.degraded_reasons,
        Some(vec![DegradedReason::DnsSniMismatch])
    );
    record.validate().unwrap();
}

#[test]
fn an_alias_chain_lets_a_record_carry_the_name_a_human_would_recognise() {
    // The answer files the address under the CDN edge, and the question asked
    // for the service. Both are true and both are recorded, so the handshake
    // agreeing with the service name is not read as a disagreement.
    let mut message = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
    message.extend_from_slice(&encoded_name("api.openai.com"));
    message.extend_from_slice(&[0, 1, 0, 1]);
    message.extend_from_slice(&encoded_name("api.openai.com"));
    message.extend_from_slice(&5u16.to_be_bytes()); // CNAME
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&300u32.to_be_bytes());
    let target = encoded_name("edge.cdn.example");
    message.extend_from_slice(&u16::try_from(target.len()).unwrap().to_be_bytes());
    message.extend_from_slice(&target);
    message.extend_from_slice(&encoded_name("edge.cdn.example"));
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&300u32.to_be_bytes());
    message.extend_from_slice(&4u16.to_be_bytes());
    message.extend_from_slice(&[104, 18, 7, 1]);

    let resolver = key("10.0.0.53", 53, 40000);
    let flow = key("104.18.7.1", 443, 54321);
    let records = records(vec![
        dns_payload(&resolver, 1, &message),
        connect(&flow, 2, "python3"),
        hello_payload(&flow, 2, &hello_for("api.openai.com")),
    ]);

    let record = record_for(&records, "104.18.7.1");
    assert_eq!(
        record.dns_names,
        Some(vec![
            "api.openai.com".to_owned(),
            "edge.cdn.example".to_owned()
        ])
    );
    assert_eq!(
        record.resolved_host_source,
        Some(ResolvedHostSource::DnsAndSni)
    );
    assert_eq!(record.degraded_reasons, None);
}

#[test]
fn an_encrypted_hello_produces_an_opaque_record_that_says_why() {
    // The blind spot that grows over time. The record has to read as opaque and
    // it has to name the reason, or the report understates what it could not
    // see. The public name in the ECH outer hello must not appear anywhere.
    let flow = key("104.18.7.1", 443, 54321);
    let records = records(vec![
        connect(&flow, 1, "python3"),
        hello_payload(&flow, 1, &ech_hello()),
    ]);

    let record = record_for(&records, "104.18.7.1");
    assert_eq!(record.classification, Classification::Opaque);
    assert_eq!(record.resolved_host, None);
    assert_eq!(record.sni, None);
    assert_eq!(record.sni_source, SniSource::EncryptedClientHello);
    assert_eq!(record.degraded_reasons, Some(vec![DegradedReason::Ech]));
    let serialized = serde_json::to_string(record).unwrap();
    assert!(
        !serialized.contains("cloudflare-ech"),
        "the ECH public name reached the record: {serialized}"
    );
    record.validate().unwrap();
}

#[test]
fn a_handshake_no_process_claimed_is_still_reported_without_a_pid() {
    // ADR-008 says an unjoinable packet event is recorded rather than dropped,
    // and that it never gets a process. Both halves matter: dropping it would
    // hide egress, inventing a pid would corrupt attribution.
    let flow = key("104.18.7.1", 443, 54321);
    let records = records(vec![hello_payload(&flow, 1, &hello_for("api.openai.com"))]);

    let record = record_for(&records, "104.18.7.1");
    assert_eq!(record.process_attribution, ProcessAttribution::Unattributed);
    assert!(record.process.is_none());
    assert_eq!(record.flow_scope, FlowScope::Undetermined);
    record.validate().unwrap();
}

#[test]
fn an_encrypted_resolver_is_declared_on_the_run_and_on_the_flow() {
    // DNS over TLS is the one encrypted resolver signal readable without
    // looking at content. A run that lost the map has to say so rather than
    // reporting unresolved destinations with no explanation.
    let dot = key("10.0.0.53", 853, 40000);
    let flow = key("104.18.7.1", 443, 54321);
    let mut source = EbpfFlowSource::over(
        ReplayKernel::of(vec![
            connect(&dot, 1, "systemd-resolve"),
            connect(&flow, 2, "python3"),
        ]),
        HOST_ID,
    )
    .with_boot_id(BOOT_ID);
    source.attach(&grant()).unwrap();

    let observations = source.drain();
    assert_eq!(
        source.coverage().dns_observation,
        DnsObservation::UnavailableEncryptedDns
    );
    let policy = policy();
    let records: Vec<Flow> = observations
        .into_iter()
        .map(|observation| {
            let scope = policy.classify(&observation);
            Flow::from_observation(observation, scope, Mechanism::Ebpf).unwrap()
        })
        .collect();

    let record = record_for(&records, "104.18.7.1");
    assert_eq!(record.classification, Classification::Opaque);
    assert_eq!(
        record.degraded_reasons,
        Some(vec![DegradedReason::EncryptedDns])
    );
}

#[test]
fn the_same_capture_replayed_produces_byte_identical_records() {
    // Determinism is a product property here, not a nicety: reports have to be
    // diffable, and a sensor whose output depended on event ordering would make
    // every report differ from the last one for no reason.
    let resolver = key("10.0.0.53", 53, 40000);
    let first = key("104.18.7.1", 443, 54321);
    let second = key("104.18.7.2", 443, 54322);
    let answer = dns_response("api.openai.com", "api.openai.com", [104, 18, 7, 1], 300);

    let forwards = records(vec![
        dns_payload(&resolver, 1, &answer),
        connect(&first, 2, "python3"),
        hello_payload(&first, 2, &hello_for("api.openai.com")),
        connect(&second, 3, "python3"),
    ]);
    let backwards = records(vec![
        connect(&second, 3, "python3"),
        hello_payload(&first, 2, &hello_for("api.openai.com")),
        connect(&first, 2, "python3"),
        dns_payload(&resolver, 1, &answer),
    ]);

    assert_eq!(forwards.len(), 2);
    assert_eq!(
        serde_json::to_string(&forwards).unwrap(),
        serde_json::to_string(&backwards).unwrap()
    );
}

#[test]
fn a_malformed_packet_is_a_reported_loss_and_never_a_record() {
    // A parser that shrugged would turn an unreadable answer into an empty one,
    // and the classification would degrade with nothing in the report saying so.
    assert!(dns::parse_response(&[0x12, 0x34, 0x81, 0x80, 0, 1]).is_err());
    assert!(tls::parse_client_hello(&hello_for("api.openai.com")[..20]).is_err());

    // And with no payload event at all the connection is still recorded.
    let flow = key("104.18.7.1", 443, 54321);
    let records = records(vec![connect(&flow, 1, "python3")]);
    assert_eq!(records.len(), 1);
    assert_eq!(
        record_for(&records, "104.18.7.1").sni_source,
        SniSource::Absent
    );
}

#[test]
fn a_source_that_cannot_attach_produces_no_records_and_a_stated_reason() {
    // The privilege behaviour this crate will not trade away: the sensor
    // declines, says why, and the scan is expected to carry on.
    //
    // **Which cause is not this test's subject, and pinning it measured the
    // machine instead of the code.** This assertion used to accept
    // `loader_not_built` or `unsupported_platform` and nothing else. Those are
    // the two answers a macOS development machine and a default feature build
    // give; a Linux runner with `--all-features` reaches the real loader and
    // answers whatever that machine actually lacks, which is normally
    // `missing_capability` on an unprivileged container or `kernel_unsupported`
    // where BTF is absent. All four are correct answers about the machine they
    // were produced on, so a test that names two of them fails on a green
    // build and says nothing about this crate.
    //
    // What the name promises is what is asserted: no records, and a cause that
    // was stated rather than defaulted. The vocabulary is checked as a closed
    // set, so this does not degrade into "any answer will do": a cause outside
    // the four, or a fifth appearing without a report being taught to carry it,
    // still fails here.
    let vocabulary = [
        SensorUnavailable::UnsupportedPlatform,
        SensorUnavailable::MissingCapability,
        SensorUnavailable::KernelUnsupported,
        SensorUnavailable::LoaderNotBuilt,
    ];

    let mut source = EbpfFlowSource::new(HOST_ID);
    let refusal = source.attach(&grant()).unwrap_err();

    assert!(
        vocabulary.contains(&refusal),
        "the refusal is outside the sensor's closed vocabulary: {refusal:?}"
    );
    assert!(
        !refusal.as_str().is_empty(),
        "a refusal with no label reaches a report as an empty reason"
    );
    // The label a report carries is the dictionary spelling and not a debug
    // rendering, which is what makes a fleet wide count of one cause mean one
    // thing.
    assert_eq!(
        serde_json::to_value(refusal).unwrap(),
        serde_json::json!(refusal.as_str())
    );
    assert!(
        source.drain().is_empty(),
        "a source that refused to attach handed back observations as if it had looked"
    );
}

/// Loads the real programs against this machine's kernel.
///
/// **Ignored, and here is exactly what it needs.** Three things, none of which
/// hold in continuous integration or on a development machine:
///
/// 1. A Linux kernel 5.8 or newer exposing BTF at `/sys/kernel/btf/vmlinux`.
///    The workspace is developed on macOS, where there is no eBPF at all, and
///    the parse and join logic this milestone delivers is deliberately built so
///    that none of it needs a kernel.
/// 2. `CAP_BPF` and `CAP_PERFMON` on the test process, plus `CAP_NET_ADMIN` for
///    the payload helper. A test runner does not have these, and granting them
///    to one would be a worse trade than skipping a test.
/// 3. A build carrying a kernel side program object, which is what turns
///    `attach` from `loader_not_built` into a real load. That arrived in F4-98
///    (ADR-014 §8), so this test is no longer unpassable everywhere: the
///    privileged Linux job in `.github/workflows/ci.yml` runs it, and it was
///    kept rather than deleted through three milestones precisely so that there
///    would be something to run when the loader landed.
///
/// It also exercises the reduction in `FlowSource::attach`: a privileged machine
/// grants `CAP_NET_ADMIN`, so the grant asks for the payload helper, and a build
/// whose object has no `clsact` classifier has to attach the rest rather than
/// refusing everything (ADR-014 §8.7).
///
/// Run it with `cargo test -p periskop-network-sensor -- --ignored` on a
/// machine that satisfies all three.
#[test]
#[ignore = "needs a BTF capable Linux kernel, CAP_BPF and CAP_PERFMON, and a build carrying a kernel side object"]
fn the_real_loader_attaches_to_this_kernel() {
    let privileges = Privileges::probe();
    let mut source = EbpfFlowSource::new(HOST_ID);
    source
        .attach(&Grant {
            tc_available: privileges.cap_net_admin || privileges.is_root(),
            elevated_as_root: privileges.is_root(),
        })
        .expect("the loader could not attach to this kernel");
    // A machine with traffic on it produces events; a silent one legitimately
    // produces none, so the assertion is on the attach rather than the count.
    let _ = source.drain();
}
