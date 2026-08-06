//! Which records the contract rejects, and why.
//!
//! Separate from the record because rejection is its own subject. The record
//! says what a flow is; this says which flows a reader may trust, and it runs
//! twice for a reason: once when a record is built here, and again on every
//! record read back, because a record read back was written by a build that is
//! not this one.
//!
//! The rejections are named rather than counted. A sensor that cannot say what
//! was wrong with an observation produces a coverage entry nobody can act on,
//! and a rejection that quotes the offending value moves the suspected leak one
//! layer down where nobody is looking for it. Both of those constraints live
//! here, next to the checks that raise them.

use crate::flow::record::Flow;
use crate::flow::vocabulary::{
    Classification, ProcessAttribution, ResolvedHostSource, SniSource, UNKNOWN_PROVIDER,
};

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

    /// The record carries a filesystem path where it may carry only a name.
    ///
    /// Determinism invariant 3 in `docs/04-contracts/flow-schema.md`: the body
    /// carries no payload, no raw command line, no machine name and no absolute
    /// path. An executable path is the machine's own layout, so two hosts
    /// running the same program produce reports that differ on a line that has
    /// nothing to do with what was observed, and a report meant to be compared
    /// across machines cannot be.
    #[error("a process path reached the record body, which the contract reserves for names")]
    PathInRecordBody,
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
            Self::PathInRecordBody => "path_in_record_body",
        }
    }
}

impl Flow {
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

        // Checked on read back as well as on construction. The producer of a
        // stored record is not necessarily this build, and a path arriving from
        // one is exactly the case the invariant exists for: it would be read
        // straight into a report and make that report incomparable with the
        // same scan run on another machine.
        if self
            .process
            .as_ref()
            .and_then(|process| process.exe.as_deref())
            .is_some_and(carries_a_path)
        {
            return Err(FlowError::PathInRecordBody);
        }

        Ok(())
    }
}

/// Whether a value spells a location on a machine rather than a name.
///
/// A separator is what makes it one, on either platform. The contract names the
/// absolute path, and a separator is the observable form of it: a record that
/// carries `venv/bin/python3` says as much about the machine's layout as one
/// carrying the leading slash.
fn carries_a_path(value: &str) -> bool {
    value.contains('/') || value.contains('\\')
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
mod tests {
    use super::*;
    use crate::flow::fixtures::{five_tuple, full_flow, CONTRACT_EXAMPLE};
    use crate::flow::vocabulary::{Mechanism, ProviderConfidence};
    use crate::observation::Observation;
    use crate::scope::FlowScope;

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
    fn a_stored_record_carrying_a_path_is_rejected_rather_than_reported() {
        // A record written by a build that is not this one. Reading it into a
        // report would carry another machine's layout into this one's output,
        // and the rejection is counted like any other so the shortfall is not
        // silent.
        let mut flow = full_flow();
        if let Some(process) = flow.process.as_mut() {
            process.exe = Some("/srv/app/venv/bin/python3".to_owned());
        }
        assert_eq!(flow.validate().unwrap_err().reason(), "path_in_record_body");
    }
}
