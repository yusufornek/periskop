//! The closed word lists a flow record may use.
//!
//! Every type here answers one question: which spellings are allowed in one
//! field. They are closed sets rather than strings because the contract fixes
//! them, and an open string would let a producer write a value no reader knows
//! how to weigh. Nothing here knows the shape of a record; a value set is
//! meaningful on its own and is what the rest of the crate is written against.

use serde::{Deserialize, Serialize};

/// Provider identity written when nothing classified the destination.
///
/// Never `null` and never an omitted field: an unresolved destination is a
/// first class result of the reverse list principle, and a reader has to be
/// able to count them.
pub const UNKNOWN_PROVIDER: &str = "unknown";

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
    pub(super) fn of(resolved_host: Option<&str>, provider_ref: Option<&str>) -> Self {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::flow::fixtures::{
        five_tuple, full_flow, schema_strings, spellings, ALL_DEGRADED_REASONS,
    };
    use crate::flow::Flow;
    use crate::observation::Observation;
    use crate::scope::FlowScope;

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
}
