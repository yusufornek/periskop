//! The record itself: what one observed connection looks like on the wire.
//!
//! Field for field this is `schemas/flow.schema.json`. The schema is the
//! contract; this is the in memory shape that serializes to it. Fields are added
//! to the schema first and only then here, so the two cannot drift in the
//! direction that matters.
//!
//! **There is no field for payload, and the type is what enforces that.** The
//! schema says in a `$comment` that the sensor sees destinations and not
//! contents, but a comment cannot stop a field from being added later. Two
//! things do. `deny_unknown_fields` makes a record carrying a payload key fail
//! to deserialize instead of quietly round tripping through an ignored field.
//! And a test derives the complete set of keys this type can ever serialize and
//! holds it equal to the schema's property list, so a new struct field breaks
//! the build unless the contract gained it first. That is the only door such a
//! field could come through, and it is closed from both sides.

use serde::{Deserialize, Serialize};

use crate::flow::validate::FlowError;
use crate::flow::vocabulary::{
    Classification, DegradedReason, Mechanism, ProcessAttribution, Proto, ProviderConfidence,
    ResolvedHostSource, SniSource,
};
use crate::identity::derive_flow_id;
use crate::observation::Observation;
use crate::scope::FlowScope;

/// Schema version this build writes.
///
/// 1.1 is the version at which `docs/04-contracts/flow-schema.md` and
/// `schemas/flow.schema.json` were reduced to one form. Every field the two
/// halves disagreed about was either added here or removed from the prose with
/// a reason; none was dropped in silence. The step is MINOR because every added
/// field is optional and no existing field changed meaning.
pub const SCHEMA_VERSION: &str = "1.1";

/// The connection key, minus the source address.
///
/// The source address is absent from the contract and therefore from the type.
/// It identifies the machine rather than the connection, and a report that has
/// to compare equal across runs and across machines cannot carry it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FiveTuple {
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: Proto,
}

/// The process a flow was attributed to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessRecord {
    pub pid: u32,
    /// Guards against pid reuse: over a long observation a pid alone can name
    /// two different processes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid_start_time: Option<u64>,
    /// Short name the kernel carries. Present even when the process died before
    /// user space could enrich the record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comm: Option<String>,
    /// The executable, **as a name and never as a path**.
    ///
    /// An observation carries what `/proc/<pid>/exe` resolved to, which is an
    /// absolute path and is what the scope policy matches against. The record
    /// does not: determinism invariant 3 keeps absolute paths out of the body,
    /// and [`Flow::from_observation`] reduces the value to its final component
    /// on the way in. What is kept is the part that says something about the
    /// program rather than about the machine, and it is worth keeping: `comm`
    /// is truncated by the kernel at sixteen bytes, so the two are not the same
    /// string for a program with a longer name.
    ///
    /// Absent means user space could not enrich the record at all, which the
    /// component spec assigns a meaning to; it must not be produced by
    /// redaction, and it is not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// The command line is hashed, never carried: it routinely holds
    /// credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline_hash: Option<String>,
}

impl ProcessRecord {
    /// The name scope classification matches against.
    ///
    /// The real path wins over the short kernel name, because two unrelated
    /// programs can present the same `comm` and only one of them may belong to
    /// the codebase under scan.
    pub fn scope_key(&self) -> Option<&str> {
        self.exe.as_deref().or(self.comm.as_deref())
    }
}

/// One connection the sensor observed leaving the machine.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flow {
    pub schema_version: String,
    pub flow_id: String,
    /// Stable opaque machine id, never a hostname: a report must not carry
    /// infrastructure naming.
    pub host_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    /// Network namespace, so container traffic is not confused with host
    /// traffic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netns: Option<String>,
    /// Observation start, rounded to a fixed bucket. A raw microsecond stamp
    /// would put wall clock into an identity that has to compare equal across
    /// runs.
    pub t_start_bucket: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    pub five_tuple: FiveTuple,
    /// Interface the connection was seen on. A `utun` name is the reason this
    /// is worth carrying: it says the traffic went through a tunnel.
    ///
    /// **No capture path in this build fills it.** The kernel events carry a
    /// namespace and a connection key and no interface index, so the field is
    /// populated only when a record written by a producer that had one is read
    /// back. It had a setter until the setter's only caller turned out to be a
    /// test fixture, which is a field that looks produced and is not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_host_source: Option<ResolvedHostSource>,
    /// Server name as the handshake presented it. Only ever set when
    /// `sni_source` says one was readable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    pub sni_source: SniSource,
    /// Names the observed DNS answers mapped to this destination, ascending.
    /// Carried because `dns_sni_mismatch` states a disagreement, and without
    /// these the record would show only one side of it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_ref: Option<String>,
    /// Derived rather than accepted: it is a reading of what the rest of the
    /// record establishes, and a second party free to write it would be free to
    /// disagree with the evidence sitting next to it.
    pub classification: Classification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_confidence: Option<ProviderConfidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruleset_version: Option<String>,
    pub process_attribution: ProcessAttribution,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessRecord>,
    pub flow_scope: FlowScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub segments_out: Option<u64>,
    pub mechanism: Mechanism,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded_reasons: Option<Vec<DegradedReason>>,
}

impl Flow {
    /// Turns an observation into a contract record.
    ///
    /// The bucket and the mechanism arrive as arguments rather than as fields
    /// of the observation, and that split is the point. A capture mechanism
    /// knows what it saw; it does not know which codebase was under scan, so it
    /// cannot decide the bucket. Routing every record through here is what
    /// makes "every flow carries a bucket" true by construction instead of by
    /// convention.
    ///
    /// The identity is derived, not accepted: letting a caller supply one would
    /// let two spellings of the same connection into the pipeline, and the
    /// duplicate would surface as two observations of one thing.
    /// Reduces an executable path to the name the record may carry.
    ///
    /// Applied here rather than at the capture mechanism because the path is
    /// what the scope policy matches against: the observation needs it, the
    /// record must not have it, and this is the one door between the two. The
    /// bucket the path decided is already in `flow_scope` by the time this
    /// runs, so nothing that used the path loses it.
    fn record_name_of(exe: &str) -> String {
        exe.rsplit(['/', '\\'])
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or(exe)
            .to_owned()
    }

    pub fn from_observation(
        mut observation: Observation,
        flow_scope: FlowScope,
        mechanism: Mechanism,
    ) -> Result<Self, FlowError> {
        let dns_names = std::mem::take(&mut observation.dns_names);
        if let Some(process) = observation.process.as_mut() {
            process.exe = process.exe.as_deref().map(Self::record_name_of);
        }
        let flow_id = derive_flow_id(
            &observation.host_id,
            observation.boot_id.as_deref(),
            &observation.five_tuple,
            observation.t_start_bucket,
        )
        .map_err(|source| FlowError::MalformedFlowId { source })?;

        let mut degraded_reasons = observation.degraded_reasons;
        // The order in which the sensor noticed two degradations is an accident
        // of its control flow. Letting it reach the record would make two
        // identical observations serialize differently.
        degraded_reasons.sort();
        degraded_reasons.dedup();

        let classification = Classification::of(
            observation.resolved_host.as_deref(),
            observation.provider_ref.as_deref(),
        );

        let flow = Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            flow_id: flow_id.to_string(),
            host_id: observation.host_id,
            boot_id: observation.boot_id,
            netns: observation.netns,
            t_start_bucket: observation.t_start_bucket,
            duration_ms: observation.duration_ms,
            five_tuple: observation.five_tuple,
            interface: None,
            resolved_host: observation.resolved_host,
            resolved_host_source: observation.resolved_host_source,
            sni: observation.sni,
            sni_source: observation.sni_source,
            dns_names: None,
            provider_ref: observation.provider_ref,
            classification,
            provider_confidence: None,
            ruleset_version: None,
            process_attribution: observation.process_attribution,
            process: observation.process,
            flow_scope,
            bytes_out: observation.bytes_out,
            bytes_in: observation.bytes_in,
            segments_out: observation.segments_out,
            mechanism,
            // An empty list is stored as absent: both say the same thing, and a
            // reader should not have to know that.
            degraded_reasons: (!degraded_reasons.is_empty()).then_some(degraded_reasons),
        };
        // Routed through the setter so the ordering and the empty list rule
        // live in one place rather than being restated here.
        let flow = flow.with_dns_names(dns_names);
        flow.validate()?;
        Ok(flow)
    }

    pub fn id(&self) -> &str {
        &self.flow_id
    }

    /// Records the names DNS mapped to this destination.
    ///
    /// Sorted and deduplicated here. The order answers arrived in is an accident
    /// of the network, and letting it reach the record would make two identical
    /// observations serialize differently.
    pub fn with_dns_names(mut self, names: Vec<String>) -> Self {
        let mut names = names;
        names.sort();
        names.dedup();
        // An empty list is stored as absent: both say the same thing.
        self.dns_names = (!names.is_empty()).then_some(names);
        self
    }

    /// Records the server name the handshake presented.
    ///
    /// Fallible, because the contract allows a name only where `sni_source` says
    /// one was readable. Storing it anyway would contradict the field that
    /// measures the blind spot, and the contradiction would be read as data.
    pub fn with_sni(mut self, sni: impl Into<String>) -> Result<Self, FlowError> {
        self.sni = Some(sni.into());
        self.validate()?;
        Ok(self)
    }

    /// Records how the provider behind a classified destination was established.
    ///
    /// Fallible for the same reason: both values describe a classification, and
    /// a record that classified nothing has no classification for them to
    /// describe.
    pub fn classified_by(
        mut self,
        confidence: ProviderConfidence,
        ruleset_version: impl Into<String>,
    ) -> Result<Self, FlowError> {
        self.provider_confidence = Some(confidence);
        self.ruleset_version = Some(ruleset_version.into());
        self.validate()?;
        Ok(self)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::flow::fixtures::{
        five_tuple, full_flow, full_observation, keys_of, process, schema, schema_strings,
        CONTRACT_EXAMPLE,
    };

    #[test]
    fn every_field_this_type_can_write_is_named_by_the_contract() {
        // The guarantee that there is no payload field, made structural. A
        // record with every optional field set spells out the complete key set
        // the type can produce, and it has to equal the schema's property list.
        // Adding a field here without adding it to the contract fails, and so
        // does dropping one the contract still requires.
        let written = keys_of(&serde_json::to_value(full_flow()).unwrap());
        let allowed = keys_of(schema().pointer("/properties").unwrap());
        assert_eq!(written, allowed);
    }

    #[test]
    fn the_contract_forbids_the_fields_that_would_carry_content() {
        // Reads the schema rather than the struct, so the check survives a
        // future field being added to either side.
        let allowed = keys_of(schema().pointer("/properties").unwrap());
        for banned in ["payload", "body", "content", "plaintext", "bytes", "sample"] {
            assert!(
                !allowed.contains(banned),
                "the contract grew a {banned} field"
            );
        }
        assert_eq!(schema()["additionalProperties"], serde_json::json!(false));
    }

    #[test]
    fn a_record_carrying_payload_is_rejected_rather_than_ignored() {
        // Well formed JSON, correct field names, and one extra key holding the
        // request body. Serde would drop the extra field silently without
        // deny_unknown_fields, and the record would look clean.
        let leaking = CONTRACT_EXAMPLE.replace(
            "\"host_id\":",
            "\"payload\": \"customer list\",\n  \"host_id\":",
        );
        assert!(serde_json::from_str::<Flow>(&leaking).is_err());
    }

    #[test]
    fn every_required_field_is_present_on_a_minimal_record() {
        let minimal = Flow::from_observation(
            Observation::new("h_1", 1_785_834_000, five_tuple(), SniSource::Absent),
            FlowScope::Undetermined,
            Mechanism::Ebpf,
        )
        .unwrap();
        let written = keys_of(&serde_json::to_value(minimal).unwrap());
        for required in schema_strings("/required") {
            assert!(written.contains(&required), "{required} is missing");
        }
    }

    #[test]
    fn the_contract_example_round_trips() {
        let flow: Flow = serde_json::from_str(CONTRACT_EXAMPLE).unwrap();
        flow.validate().unwrap();
        assert_eq!(flow.five_tuple.dst_port, 443);
        assert_eq!(flow.flow_scope, FlowScope::InScope);
        let reserialized = serde_json::to_value(&flow).unwrap();
        let original: serde_json::Value = serde_json::from_str(CONTRACT_EXAMPLE).unwrap();
        assert_eq!(reserialized, original);
    }

    #[test]
    fn dns_names_are_ordered_and_deduplicated_and_an_empty_list_is_absent() {
        // The order answers arrived in is an accident of the network, and the
        // contract fixes the array as ascending.
        let flow = full_flow().with_dns_names(vec![
            "z.example".to_owned(),
            "a.example".to_owned(),
            "z.example".to_owned(),
        ]);
        assert_eq!(
            flow.dns_names,
            Some(vec!["a.example".to_owned(), "z.example".to_owned()])
        );
        assert!(full_flow().with_dns_names(Vec::new()).dns_names.is_none());
    }

    #[test]
    fn degraded_reasons_are_deduplicated_and_an_empty_list_is_absent() {
        let flow = Flow::from_observation(
            full_observation().degraded(vec![
                DegradedReason::TcUnavailable,
                DegradedReason::Ech,
                DegradedReason::TcUnavailable,
            ]),
            FlowScope::InScope,
            Mechanism::Ebpf,
        )
        .unwrap();
        // The observation already carried one reason of its own, so the record
        // shows all three, sorted and each named once.
        assert_eq!(
            flow.degraded_reasons,
            Some(vec![
                DegradedReason::DnsSniMismatch,
                DegradedReason::Ech,
                DegradedReason::TcUnavailable
            ])
        );

        let plain = Flow::from_observation(
            Observation::new("h_1", 1, five_tuple(), SniSource::Absent),
            FlowScope::Undetermined,
            Mechanism::Ebpf,
        )
        .unwrap();
        assert!(plain.degraded_reasons.is_none());
    }

    #[test]
    fn optional_fields_that_were_never_set_are_absent_rather_than_null() {
        let flow = Flow::from_observation(
            Observation::new("h_1", 1, five_tuple(), SniSource::Absent),
            FlowScope::Undetermined,
            Mechanism::Ebpf,
        )
        .unwrap();
        let json = serde_json::to_value(flow).unwrap();
        for optional in ["boot_id", "netns", "process", "resolved_host", "bytes_out"] {
            assert!(
                json.get(optional).is_none(),
                "{optional} serialized as null"
            );
        }
    }

    #[test]
    fn the_scope_key_prefers_the_real_path_over_the_kernel_name() {
        // Two unrelated programs can present the same comm and only one of them
        // may belong to the codebase under scan.
        let mut record = process();
        assert_eq!(record.scope_key(), Some("python3"));
        record.exe = Some("/srv/app/venv/bin/python3".to_owned());
        assert_eq!(record.scope_key(), Some("/srv/app/venv/bin/python3"));
    }

    #[test]
    fn an_executable_path_never_reaches_the_record_body() {
        // Determinism invariant 3 in the contract, produced rather than
        // described. The observation carries the path, because the scope policy
        // matches against it; the record carries the name, because the same
        // scan run on two machines has to produce reports that differ only on
        // what was observed. A developer's checkout under a home directory
        // would otherwise put that directory into every flow it attributed.
        let observed = Observation::new("h_1", 1, five_tuple(), SniSource::Absent)
            .kernel_attributed(ProcessRecord {
                exe: Some("/Users/someone/checkout/venv/bin/python3".to_owned()),
                ..process()
            });
        let flow = Flow::from_observation(observed, FlowScope::InScope, Mechanism::Ebpf).unwrap();

        let exe = flow
            .process
            .as_ref()
            .and_then(|process| process.exe.as_deref());
        assert_eq!(exe, Some("python3"));
        let json = serde_json::to_string(&flow).unwrap();
        assert!(!json.contains("/Users/someone"), "{json}");
    }

    #[test]
    fn enrichment_that_never_happened_is_not_spelled_like_a_redaction() {
        // The absence of `exe` means user space could not read it, which the
        // component spec assigns a meaning to. Reducing a path to a name must
        // not produce that absence, or a live process and a dead one become
        // indistinguishable in the record.
        let observed = Observation::new("h_1", 1, five_tuple(), SniSource::Absent)
            .kernel_attributed(process());
        let flow = Flow::from_observation(observed, FlowScope::InScope, Mechanism::Ebpf).unwrap();
        assert_eq!(
            flow.process
                .as_ref()
                .and_then(|process| process.exe.as_deref()),
            None
        );
    }
}
