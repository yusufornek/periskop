//! The records the tests of this crate are written against.
//!
//! Shared rather than copied per module, because a fixture copied into two
//! files stops being the same record the moment one copy is edited, and the
//! assertions that looked identical then disagree for a reason nobody can see.
//! The complete record in particular has to stay one object: the key set
//! assertion is only a guarantee about the type if the record it reads carries
//! every optional field.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::flow::record::{FiveTuple, Flow, ProcessRecord};
use crate::flow::vocabulary::{
    DegradedReason, Mechanism, Proto, ProviderConfidence, ResolvedHostSource, SniSource,
};
use crate::observation::Observation;
use crate::scope::FlowScope;

/// The contract itself, read at build time rather than transcribed.
///
/// A transcribed copy drifts the moment the integrator edits the schema,
/// and the test that was supposed to catch the drift is the thing that goes
/// stale.
const SCHEMA: &str = include_str!("../../../../schemas/flow.schema.json");

/// The contract example, byte for byte.
pub(crate) const CONTRACT_EXAMPLE: &str =
    include_str!("../../../../schemas/examples/flow.valid.json");

/// Every degradation reason the vocabulary declares, in declaration order.
///
/// Written out rather than derived, because the two tests that read it are
/// checking the declaration order itself against the contract, and a list
/// generated from the enum could not fail.
pub(crate) const ALL_DEGRADED_REASONS: [DegradedReason; 9] = [
    DegradedReason::ContainerNsUnresolved,
    DegradedReason::DnsSniMismatch,
    DegradedReason::Ech,
    DegradedReason::EncryptedDns,
    DegradedReason::MapOverflow,
    DegradedReason::PidReuseSuspected,
    DegradedReason::PreExistingConnection,
    DegradedReason::SamplingMode,
    DegradedReason::TcUnavailable,
];

#[allow(clippy::unwrap_used)]
pub(crate) fn schema() -> serde_json::Value {
    serde_json::from_str(SCHEMA).unwrap()
}

#[allow(clippy::unwrap_used)]
pub(crate) fn schema_strings(pointer: &str) -> BTreeSet<String> {
    schema()
        .pointer(pointer)
        .and_then(serde_json::Value::as_array)
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect()
}

#[allow(clippy::unwrap_used)]
pub(crate) fn spellings<T: Serialize>(values: &[T]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| {
            serde_json::to_value(value)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

pub(crate) fn keys_of(value: &serde_json::Value) -> BTreeSet<String> {
    value
        .as_object()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default()
}

pub(crate) fn five_tuple() -> FiveTuple {
    FiveTuple {
        src_port: 54321,
        dst_ip: "104.18.7.1".to_owned(),
        dst_port: 443,
        proto: Proto::Tcp,
    }
}

pub(crate) fn process() -> ProcessRecord {
    ProcessRecord {
        pid: 4821,
        pid_start_time: Some(1_785_833_900),
        comm: Some("python3".to_owned()),
        exe: None,
        cmdline_hash: None,
    }
}

/// An observation carrying every optional field the contract allows.
pub(crate) fn full_observation() -> Observation {
    Observation::new(
        "h_9f2c4a17be0d5386",
        1_785_834_000,
        five_tuple(),
        SniSource::ClientHello,
    )
    .with_boot_id("b_3f0a91c7d4e28b56")
    .with_netns("4026531840")
    .with_duration_ms(412)
    .resolved("api.openai.com", ResolvedHostSource::DnsAndSni)
    .with_provider_ref("openai")
    .kernel_attributed(ProcessRecord {
        pid: 4821,
        pid_start_time: Some(1_785_833_900),
        comm: Some("python3".to_owned()),
        exe: Some("/usr/bin/python3".to_owned()),
        cmdline_hash: Some("a".repeat(64)),
    })
    .with_volume(2048, 8192)
    .with_segments_out(9)
    .degraded(vec![DegradedReason::DnsSniMismatch])
}

/// A record carrying every optional field the contract allows.
///
/// The setters are what the packet parsing helper adds after the
/// observation is placed. They are exercised here rather than only in their
/// own tests, because the key set assertion in `record` is only a guarantee if
/// this record is complete.
///
/// `interface` is assigned rather than set through a builder: no capture
/// path in this build produces one, so a setter for it would be a function
/// with a test for its only caller. The field is still written here,
/// because the key set assertion has to cover every key the type can
/// serialize, including the ones only a read back record carries.
#[allow(clippy::unwrap_used)]
pub(crate) fn full_flow() -> Flow {
    let mut flow = Flow::from_observation(full_observation(), FlowScope::InScope, Mechanism::Ebpf)
        .unwrap()
        .with_dns_names(vec!["api.openai.com".to_owned()])
        .with_sni("api.openai.com")
        .unwrap()
        .classified_by(ProviderConfidence::Confirmed, "1.4.0")
        .unwrap();
    flow.interface = Some("utun4".to_owned());
    flow
}
