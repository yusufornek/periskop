//! The `Flow` record: one connection the sensor watched leave the machine.
//!
//! Mirrors `schemas/flow.schema.json`. The schema is the contract; this is the
//! in memory shape that serializes to it. Fields are added to the schema first
//! and only then here, so the two cannot drift in the direction that matters.
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

/// Provider identity written when nothing classified the destination.
///
/// Never `null` and never an omitted field: an unresolved destination is a
/// first class result of the reverse list principle, and a reader has to be
/// able to count them.
pub const UNKNOWN_PROVIDER: &str = "unknown";

/// A record the contract rejects, and why.
///
/// Every variant names one invariant. There is no catch all, because a sensor
/// that cannot say what was wrong with an observation produces a coverage entry
/// nobody can act on.
#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    #[error("flow identity is not the fl_ form the contract fixes")]
    MalformedFlowId {
        #[source]
        source: periskop_core::Error,
    },

    #[error("provider_ref is not a valid classifier name")]
    MalformedProviderRef,

    #[error("ruleset_version is not the three segment form the contract fixes")]
    MalformedRulesetVersion,

    /// A server name recorded where the handshake showed none.
    ///
    /// `encrypted_client_hello` and `absent` both mean there was no readable
    /// name. A record carrying one anyway contradicts the field that measures
    /// the blind spot, and the contradiction would be read as data.
    #[error("sni is present although sni_source says no name was readable")]
    SniWithoutClientHello,

    /// `classification` disagrees with what the record actually establishes.
    ///
    /// The three values answer one question, "could the destination be named
    /// and matched", and each has a witness in the record: a classified flow
    /// names a provider, an opaque one names no host at all. A value without its
    /// witness turns the honest coverage axis into a label anyone can write.
    #[error("classification does not agree with what the record establishes")]
    ClassificationWithoutItsWitness,

    /// A provider confidence or a rule set version on an unclassified record.
    ///
    /// Both describe a classification. Carrying them where nothing was
    /// classified attaches a confidence to a claim nobody made.
    #[error("a classification detail is present although nothing was classified")]
    ClassificationDetailWithoutClassification,

    /// `process_attribution` and the presence of `process` disagree.
    ///
    /// The component spec fixes the pairing: an unattributed flow is written
    /// with no `process` object at all, and an attributed one carries it. A
    /// record that says "unattributed" while carrying a pid invites a reader to
    /// treat a guess as kernel truth, which is the one thing attribution exists
    /// to prevent.
    #[error("process_attribution does not agree with the presence of a process")]
    AttributionDisagreesWithProcess,

    /// `resolved_host` and `resolved_host_source` disagree.
    ///
    /// A name without a stated source is a name a reader cannot weigh, and a
    /// source without a name is a claim about nothing.
    #[error("resolved_host does not agree with resolved_host_source")]
    ResolvedHostSourceDisagrees,
}

impl FlowError {
    /// A fixed, content free label for this rejection.
    ///
    /// Deliberately not the `Display` text and never the offending value: the
    /// records this labels are exactly the ones suspected of carrying something
    /// they should not, and a diagnostic that quotes them moves the leak one
    /// layer down where nobody is looking for it.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::MalformedFlowId { .. } => "malformed_flow_id",
            Self::MalformedProviderRef => "malformed_provider_ref",
            Self::MalformedRulesetVersion => "malformed_ruleset_version",
            Self::SniWithoutClientHello => "sni_without_client_hello",
            Self::ClassificationWithoutItsWitness => "classification_without_its_witness",
            Self::ClassificationDetailWithoutClassification => {
                "classification_detail_without_classification"
            }
            Self::AttributionDisagreesWithProcess => "attribution_disagrees_with_process",
            Self::ResolvedHostSourceDisagrees => "resolved_host_source_disagrees",
        }
    }
}

/// Transport protocol of the observed connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// How the handshake presented the server name.
///
/// `EncryptedClientHello` and `Absent` are kept apart on purpose. The first
/// says the name is genuinely unavailable, the second that none was offered;
/// collapsing them would turn a measured blind spot into a shrug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SniSource {
    ClientHello,
    EncryptedClientHello,
    Absent,
}

/// Whether the destination could be named and matched.
///
/// The axis `provider_ref` cannot carry on its own. `Unclassified` and `Opaque`
/// both write `provider_ref = unknown`, and only this field separates "a name
/// was seen and no signature matched it" from "there was never a name to look
/// at". The second is a measured blind spot, and it is the line of the report
/// that matters most.
///
/// Deliberately not the same axis as [`crate::scope::FlowScope`]. One flow can
/// be classified and known benign at once; a single column could not say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Classified,
    Unclassified,
    Opaque,
}

impl Classification {
    /// Reads the axis off the two facts that decide it.
    ///
    /// Derived rather than accepted from a caller. The three values each have a
    /// witness elsewhere in the record, and a caller free to write the value
    /// would be free to write one the record contradicts. Deriving it once here
    /// is also what keeps every consumer from reimplementing the reading
    /// slightly differently.
    fn of(resolved_host: Option<&str>, provider_ref: Option<&str>) -> Self {
        match (resolved_host, provider_ref) {
            (_, Some(provider)) if provider != UNKNOWN_PROVIDER => Self::Classified,
            // A name was seen and no signature matched it. Visible warning, not
            // a blind spot.
            (Some(_), _) => Self::Unclassified,
            // Neither DNS nor SNI produced a name: there was nothing to match.
            (None, _) => Self::Opaque,
        }
    }
}

/// How the provider behind a classified destination was established.
///
/// A signature that matched a host name is a structural fact. A signature that
/// matched an address range is a guess about who owns the range, and the project
/// forbids a guess from reaching the confirmed list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderConfidence {
    Confirmed,
    Suspect,
}

/// Which signal established the destination name.
///
/// Reported because DNS and SNI can disagree, and a reader needs to know which
/// one produced the name in front of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvedHostSource {
    Dns,
    Sni,
    DnsAndSni,
    None,
}

/// How the owning process was determined.
///
/// Kernel context is certain, an inference from a socket table snapshot is not,
/// and a flow nobody could attribute is still reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessAttribution {
    KernelAttributed,
    Inferred,
    Unattributed,
}

/// Which capture mechanism produced the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mechanism {
    Ebpf,
    Pcap,
    Etw,
}

/// Why a record is less complete than a full one.
///
/// Declared in the lexicographic order of their serialized spellings, because
/// the contract fixes that order for the array and a derived `Ord` is what
/// sorts it. A test holds the two together, so inserting a variant in the wrong
/// place fails rather than silently changing report bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradedReason {
    ContainerNsUnresolved,
    DnsSniMismatch,
    Ech,
    EncryptedDns,
    MapOverflow,
    PidReuseSuspected,
    PreExistingConnection,
    SamplingMode,
    TcUnavailable,
}

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
    pub fn from_observation(
        observation: Observation,
        flow_scope: FlowScope,
        mechanism: Mechanism,
    ) -> Result<Self, FlowError> {
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
            sni: None,
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
        flow.validate()?;
        Ok(flow)
    }

    pub fn id(&self) -> &str {
        &self.flow_id
    }

    /// Names the interface the connection was seen on.
    ///
    /// A setter on the record rather than a field of `Observation`, because the
    /// three fields below arrive from parts of the sensor that do not build the
    /// observation: the interface comes from the capture attachment, and the
    /// name and classification detail come from the packet parsing helper, which
    /// by contract carries no process context and therefore cannot be the thing
    /// that constructs a flow.
    pub fn on_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = Some(interface.into());
        self
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

    /// Checks the invariants the contract states as rejections.
    ///
    /// Run on construction and again on every record read back, because a
    /// record read back was written by a build that is not this one.
    pub fn validate(&self) -> Result<(), FlowError> {
        periskop_core::ids::FlowId::parse(&self.flow_id)
            .map_err(|source| FlowError::MalformedFlowId { source })?;

        if let Some(provider_ref) = &self.provider_ref {
            if !is_provider_ref(provider_ref) {
                return Err(FlowError::MalformedProviderRef);
            }
        }

        if self.sni.is_some() && self.sni_source != SniSource::ClientHello {
            return Err(FlowError::SniWithoutClientHello);
        }

        // Each classification value against its witness. Checked on read back as
        // well as on construction, because a record read back was written by a
        // build that is not this one and may have written the label by hand.
        let named_provider = self
            .provider_ref
            .as_deref()
            .is_some_and(|provider| provider != UNKNOWN_PROVIDER);
        let agrees = match self.classification {
            Classification::Classified => named_provider,
            Classification::Unclassified => !named_provider && self.resolved_host.is_some(),
            Classification::Opaque => !named_provider && self.resolved_host.is_none(),
        };
        if !agrees {
            return Err(FlowError::ClassificationWithoutItsWitness);
        }

        let detailed = self.provider_confidence.is_some() || self.ruleset_version.is_some();
        if detailed && self.classification != Classification::Classified {
            return Err(FlowError::ClassificationDetailWithoutClassification);
        }
        if let Some(ruleset_version) = &self.ruleset_version {
            if !is_three_segment_version(ruleset_version) {
                return Err(FlowError::MalformedRulesetVersion);
            }
        }

        let attributed = matches!(
            self.process_attribution,
            ProcessAttribution::KernelAttributed | ProcessAttribution::Inferred
        );
        if attributed != self.process.is_some() {
            return Err(FlowError::AttributionDisagreesWithProcess);
        }

        let named = self.resolved_host.is_some();
        let sourced = !matches!(
            self.resolved_host_source,
            None | Some(ResolvedHostSource::None)
        );
        if named != sourced {
            return Err(FlowError::ResolvedHostSourceDisagrees);
        }

        Ok(())
    }
}

/// Schema pattern `^\d+\.\d+\.\d+$`.
fn is_three_segment_version(value: &str) -> bool {
    let mut segments = value.split('.');
    let three = [segments.next(), segments.next(), segments.next()];
    segments.next().is_none()
        && three.iter().all(|segment| {
            segment.is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// Schema pattern `^[a-z0-9][a-z0-9-]*$`.
fn is_provider_ref(value: &str) -> bool {
    let mut chars = value.chars();
    if !matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit()) {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;
    use crate::observation::Observation;
    use std::collections::BTreeSet;

    /// The contract itself, read at build time rather than transcribed.
    ///
    /// A transcribed copy drifts the moment the integrator edits the schema,
    /// and the test that was supposed to catch the drift is the thing that goes
    /// stale.
    const SCHEMA: &str = include_str!("../../../schemas/flow.schema.json");

    /// The contract example, byte for byte.
    const CONTRACT_EXAMPLE: &str = include_str!("../../../schemas/examples/flow.valid.json");

    fn schema() -> serde_json::Value {
        serde_json::from_str(SCHEMA).unwrap()
    }

    fn schema_strings(pointer: &str) -> BTreeSet<String> {
        schema()
            .pointer(pointer)
            .and_then(serde_json::Value::as_array)
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect()
    }

    fn spellings<T: Serialize>(values: &[T]) -> BTreeSet<String> {
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
    /// The three setters are what the packet parsing helper and the capture
    /// attachment add after the observation is placed. They are exercised here
    /// rather than only in their own tests, because the key set assertion below
    /// is only a guarantee if this record is complete.
    pub(crate) fn full_flow() -> Flow {
        Flow::from_observation(full_observation(), FlowScope::InScope, Mechanism::Ebpf)
            .unwrap()
            .on_interface("utun4")
            .with_dns_names(vec!["api.openai.com".to_owned()])
            .with_sni("api.openai.com")
            .unwrap()
            .classified_by(ProviderConfidence::Confirmed, "1.4.0")
            .unwrap()
    }

    fn keys_of(value: &serde_json::Value) -> BTreeSet<String> {
        value
            .as_object()
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default()
    }

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
    fn an_identity_read_back_is_checked_for_form_and_not_re_derived() {
        // The contract example carries an identity this derivation does not
        // reproduce, and it is still a valid record: holding a read back id to
        // this build's hash would pin every future producer to this build.
        let flow: Flow = serde_json::from_str(CONTRACT_EXAMPLE).unwrap();
        assert!(flow.validate().is_ok());
        assert_ne!(flow.flow_id, full_flow().flow_id);
    }

    #[test]
    fn enum_spellings_match_the_contract() {
        // A misspelled value compiles and serializes happily and only fails in
        // an external validator, which would take the whole record out of the
        // report.
        assert_eq!(
            spellings(&[Proto::Tcp, Proto::Udp]),
            schema_strings("/properties/five_tuple/properties/proto/enum")
        );
        assert_eq!(
            spellings(&[
                SniSource::ClientHello,
                SniSource::EncryptedClientHello,
                SniSource::Absent
            ]),
            schema_strings("/properties/sni_source/enum")
        );
        assert_eq!(
            spellings(&[
                ResolvedHostSource::Dns,
                ResolvedHostSource::Sni,
                ResolvedHostSource::DnsAndSni,
                ResolvedHostSource::None
            ]),
            schema_strings("/properties/resolved_host_source/enum")
        );
        assert_eq!(
            spellings(&[
                ProcessAttribution::KernelAttributed,
                ProcessAttribution::Inferred,
                ProcessAttribution::Unattributed
            ]),
            schema_strings("/properties/process_attribution/enum")
        );
        assert_eq!(
            spellings(&[Mechanism::Ebpf, Mechanism::Pcap, Mechanism::Etw]),
            schema_strings("/properties/mechanism/enum")
        );
        assert_eq!(
            spellings(&ALL_DEGRADED_REASONS),
            schema_strings("/properties/degraded_reasons/items/enum")
        );
        assert_eq!(
            spellings(&FlowScope::ALL),
            schema_strings("/properties/flow_scope/enum")
        );
        assert_eq!(
            spellings(&[
                Classification::Classified,
                Classification::Unclassified,
                Classification::Opaque
            ]),
            schema_strings("/properties/classification/enum")
        );
        assert_eq!(
            spellings(&[ProviderConfidence::Confirmed, ProviderConfidence::Suspect]),
            schema_strings("/properties/provider_confidence/enum")
        );
    }

    #[test]
    fn the_classification_axis_is_read_off_the_record_rather_than_asserted() {
        // The distinction provider_ref cannot carry on its own: both of the last
        // two write unknown, and only this field separates a name nothing
        // matched from no name at all.
        assert_eq!(full_flow().classification, Classification::Classified);

        let named_but_unmatched = Flow::from_observation(
            Observation::new("h_1", 1, five_tuple(), SniSource::ClientHello)
                .resolved("some.host.example", ResolvedHostSource::Sni)
                .with_provider_ref(UNKNOWN_PROVIDER),
            FlowScope::InScope,
            Mechanism::Ebpf,
        )
        .unwrap();
        assert_eq!(
            named_but_unmatched.classification,
            Classification::Unclassified
        );

        let nameless = Flow::from_observation(
            Observation::new("h_1", 1, five_tuple(), SniSource::EncryptedClientHello),
            FlowScope::InScope,
            Mechanism::Ebpf,
        )
        .unwrap();
        assert_eq!(nameless.classification, Classification::Opaque);
    }

    #[test]
    fn a_classification_without_its_witness_is_rejected() {
        // The label is only worth something if it cannot be written by hand over
        // a record that says otherwise.
        let mut relabelled = full_flow();
        relabelled.classification = Classification::Opaque;
        assert_eq!(
            relabelled.validate().unwrap_err().reason(),
            "classification_without_its_witness"
        );
    }

    #[test]
    fn a_name_recorded_where_the_handshake_showed_none_is_rejected() {
        let mut flow = full_flow();
        flow.sni_source = SniSource::EncryptedClientHello;
        assert!(matches!(
            flow.validate(),
            Err(FlowError::SniWithoutClientHello)
        ));

        let opaque = Flow::from_observation(
            Observation::new("h_1", 1, five_tuple(), SniSource::Absent),
            FlowScope::Undetermined,
            Mechanism::Ebpf,
        )
        .unwrap();
        assert!(matches!(
            opaque.with_sni("api.openai.com"),
            Err(FlowError::SniWithoutClientHello)
        ));
    }

    #[test]
    fn classification_detail_cannot_be_attached_to_a_record_that_classified_nothing() {
        let unclassified = Flow::from_observation(
            Observation::new("h_1", 1, five_tuple(), SniSource::ClientHello)
                .resolved("some.host.example", ResolvedHostSource::Sni),
            FlowScope::InScope,
            Mechanism::Ebpf,
        )
        .unwrap();
        assert!(matches!(
            unclassified.classified_by(ProviderConfidence::Suspect, "1.4.0"),
            Err(FlowError::ClassificationDetailWithoutClassification)
        ));
    }

    #[test]
    fn a_malformed_ruleset_version_is_rejected() {
        let mut flow = full_flow();
        flow.ruleset_version = Some("1.4".to_owned());
        assert_eq!(
            flow.validate().unwrap_err().reason(),
            "malformed_ruleset_version"
        );
        flow.ruleset_version = Some("1.4.0".to_owned());
        assert!(flow.validate().is_ok());
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

    const ALL_DEGRADED_REASONS: [DegradedReason; 9] = [
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

    #[test]
    fn degraded_reasons_sort_the_way_the_contract_orders_them() {
        let mut reasons = ALL_DEGRADED_REASONS;
        reasons.reverse();
        reasons.sort();
        let written: Vec<String> = reasons
            .iter()
            .map(|r| {
                serde_json::to_value(r)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        let mut lexicographic = written.clone();
        lexicographic.sort();
        assert_eq!(written, lexicographic);
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
    fn an_unattributed_record_carrying_a_process_is_rejected() {
        // The pairing the component spec fixes. A record that claims nobody
        // could be attributed while carrying a pid invites a reader to read a
        // guess as kernel truth.
        let mut flow = full_flow();
        flow.process_attribution = ProcessAttribution::Unattributed;
        assert_eq!(
            flow.validate().unwrap_err().reason(),
            "attribution_disagrees_with_process"
        );
    }

    #[test]
    fn an_attributed_record_without_a_process_is_rejected() {
        let mut flow = full_flow();
        flow.process = None;
        assert!(matches!(
            flow.validate(),
            Err(FlowError::AttributionDisagreesWithProcess)
        ));
    }

    #[test]
    fn a_resolved_host_without_a_stated_source_is_rejected() {
        let mut flow = full_flow();
        flow.resolved_host_source = None;
        assert!(matches!(
            flow.validate(),
            Err(FlowError::ResolvedHostSourceDisagrees)
        ));

        let mut claiming_none = full_flow();
        claiming_none.resolved_host_source = Some(ResolvedHostSource::None);
        assert!(matches!(
            claiming_none.validate(),
            Err(FlowError::ResolvedHostSourceDisagrees)
        ));
    }

    #[test]
    fn a_source_without_a_host_is_rejected() {
        let mut flow = full_flow();
        flow.resolved_host = None;
        assert!(matches!(
            flow.validate(),
            Err(FlowError::ResolvedHostSourceDisagrees)
        ));
    }

    #[test]
    fn a_malformed_provider_ref_is_rejected() {
        let mut flow = full_flow();
        flow.provider_ref = Some("OpenAI Inc".to_owned());
        assert_eq!(
            flow.validate().unwrap_err().reason(),
            "malformed_provider_ref"
        );
        // The reverse list value is a valid classifier name and stays reportable.
        // It travels with the classification that matches it: a record naming no
        // provider has not classified anything, and the two have to say so
        // together.
        let unknown = Flow::from_observation(
            Observation::new("h_1", 1, five_tuple(), SniSource::ClientHello)
                .resolved("some.host.example", ResolvedHostSource::Sni)
                .with_provider_ref(UNKNOWN_PROVIDER),
            FlowScope::InScope,
            Mechanism::Ebpf,
        )
        .unwrap();
        assert_eq!(unknown.provider_ref.as_deref(), Some(UNKNOWN_PROVIDER));
        assert_eq!(unknown.classification, Classification::Unclassified);
        assert!(unknown.validate().is_ok());
    }

    #[test]
    fn a_malformed_identity_is_rejected() {
        let mut flow = full_flow();
        flow.flow_id = "fl_NOTHEX".to_owned();
        assert!(matches!(
            flow.validate(),
            Err(FlowError::MalformedFlowId { .. })
        ));
    }

    #[test]
    fn a_rejection_never_repeats_the_value_it_rejected() {
        let mut flow = full_flow();
        flow.provider_ref = Some("customer=ahmet@firma.com".to_owned());
        let error = flow.validate().unwrap_err();
        assert!(!error.reason().contains("ahmet"));
        assert!(!error.to_string().contains("ahmet"));
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
}
