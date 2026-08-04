//! What a capture mechanism saw, before user space placed it.
//!
//! An `Observation` is everything a hook can know on its own: a destination, a
//! volume, and whichever process context the kernel handed over. It is
//! deliberately not a `Flow`. The bucket a flow belongs to
//! ([`crate::scope::FlowScope`]) depends on which codebase is under scan, and a
//! kernel side program has no idea what that is. Keeping the two types apart is
//! what stops a capture path from inventing a bucket, and what makes "every
//! flow carries a bucket someone decided" true by construction.
//!
//! The default attribution is `unattributed` with no process. That is the
//! honest starting point: a mechanism that learned nothing about the owner says
//! so, and the builders below are the only way to claim otherwise.

use crate::flow::{
    DegradedReason, FiveTuple, ProcessAttribution, ProcessRecord, ResolvedHostSource, SniSource,
};

/// One connection as a capture mechanism saw it.
///
/// Fields are public because a mechanism living in another crate has to be able
/// to fill them. The invariants between them are checked when the record is
/// built ([`crate::flow::Flow::validate`]), not assumed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub host_id: String,
    pub boot_id: Option<String>,
    pub netns: Option<String>,
    pub t_start_bucket: u64,
    pub duration_ms: Option<u64>,
    pub five_tuple: FiveTuple,
    pub resolved_host: Option<String>,
    pub resolved_host_source: Option<ResolvedHostSource>,
    /// The server name the handshake presented, as read from the clear text
    /// part of a ClientHello. Only ever set alongside
    /// [`SniSource::ClientHello`]; the record validation rejects the pairing
    /// that would contradict the field measuring the blind spot.
    pub sni: Option<String>,
    pub sni_source: SniSource,
    /// Everything the DNS map said this destination is called. Carried
    /// separately from `resolved_host` because the two can disagree, and a
    /// record declaring a disagreement while showing one side of it is a claim
    /// nobody can check.
    pub dns_names: Vec<String>,
    pub provider_ref: Option<String>,
    pub process_attribution: ProcessAttribution,
    pub process: Option<ProcessRecord>,
    pub bytes_out: Option<u64>,
    pub bytes_in: Option<u64>,
    pub segments_out: Option<u64>,
    pub degraded_reasons: Vec<DegradedReason>,
}

impl Observation {
    /// The four facts a capture mechanism always has.
    ///
    /// `sni_source` is among them because the contract requires it on every
    /// record: "no name was offered" and "the name was encrypted" are different
    /// statements, and a mechanism that could leave the field unset would let
    /// them arrive at the report looking alike.
    pub fn new(
        host_id: impl Into<String>,
        t_start_bucket: u64,
        five_tuple: FiveTuple,
        sni_source: SniSource,
    ) -> Self {
        Self {
            host_id: host_id.into(),
            boot_id: None,
            netns: None,
            t_start_bucket,
            duration_ms: None,
            five_tuple,
            resolved_host: None,
            resolved_host_source: None,
            sni: None,
            sni_source,
            dns_names: Vec::new(),
            provider_ref: None,
            process_attribution: ProcessAttribution::Unattributed,
            process: None,
            bytes_out: None,
            bytes_in: None,
            segments_out: None,
            degraded_reasons: Vec::new(),
        }
    }

    pub fn with_boot_id(mut self, boot_id: impl Into<String>) -> Self {
        self.boot_id = Some(boot_id.into());
        self
    }

    /// Records the network namespace, so container traffic is not read as host
    /// traffic.
    pub fn with_netns(mut self, netns: impl Into<String>) -> Self {
        self.netns = Some(netns.into());
        self
    }

    pub fn with_duration_ms(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    /// Names the destination and says which signal produced the name.
    ///
    /// The two arrive together because a name whose provenance is unstated
    /// cannot be weighed, and DNS and SNI are allowed to disagree.
    pub fn resolved(mut self, host: impl Into<String>, source: ResolvedHostSource) -> Self {
        self.resolved_host = Some(host.into());
        self.resolved_host_source = Some(source);
        self
    }

    /// Records the server name the handshake presented.
    ///
    /// Infallible here and checked at the record: the pairing rule belongs to
    /// the contract, and duplicating it would give two places to change it.
    pub fn with_sni(mut self, sni: impl Into<String>) -> Self {
        self.sni = Some(sni.into());
        self
    }

    /// Records the names DNS mapped to this destination.
    pub fn with_dns_names(mut self, dns_names: Vec<String>) -> Self {
        self.dns_names = dns_names;
        self
    }

    pub fn with_provider_ref(mut self, provider_ref: impl Into<String>) -> Self {
        self.provider_ref = Some(provider_ref.into());
        self
    }

    /// Claims kernel attribution: the hook ran in the calling task's context,
    /// so there was no race and no guess.
    pub fn kernel_attributed(mut self, process: ProcessRecord) -> Self {
        self.process_attribution = ProcessAttribution::KernelAttributed;
        self.process = Some(process);
        self
    }

    /// Claims an inference: a socket table snapshot matched the connection key.
    ///
    /// Separate from [`Self::kernel_attributed`] so a probabilistic match can
    /// never be spelled the same way as a certain one.
    pub fn inferred(mut self, process: ProcessRecord) -> Self {
        self.process_attribution = ProcessAttribution::Inferred;
        self.process = Some(process);
        self
    }

    pub fn with_volume(mut self, bytes_out: u64, bytes_in: u64) -> Self {
        self.bytes_out = Some(bytes_out);
        self.bytes_in = Some(bytes_in);
        self
    }

    pub fn with_segments_out(mut self, segments_out: u64) -> Self {
        self.segments_out = Some(segments_out);
        self
    }

    /// Appends rather than replaces: the sensor adds run level degradations to
    /// whatever the mechanism already reported, and losing either half would
    /// understate what was missed.
    pub fn degraded(mut self, reasons: Vec<DegradedReason>) -> Self {
        self.degraded_reasons.extend(reasons);
        self
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::flow::tests::{five_tuple, process};

    #[test]
    fn a_fresh_observation_claims_no_owner() {
        let observation = Observation::new("h_1", 1, five_tuple(), SniSource::Absent);
        assert_eq!(
            observation.process_attribution,
            ProcessAttribution::Unattributed
        );
        assert!(observation.process.is_none());
    }

    #[test]
    fn the_two_attribution_builders_cannot_be_spelled_alike() {
        let certain = Observation::new("h_1", 1, five_tuple(), SniSource::Absent)
            .kernel_attributed(process());
        let guessed =
            Observation::new("h_1", 1, five_tuple(), SniSource::Absent).inferred(process());
        assert_eq!(
            certain.process_attribution,
            ProcessAttribution::KernelAttributed
        );
        assert_eq!(guessed.process_attribution, ProcessAttribution::Inferred);
    }

    #[test]
    fn degradations_accumulate_instead_of_replacing_each_other() {
        // The mechanism reports what it lost, the sensor adds what the run
        // lost. Keeping only the second would understate the first.
        let observation = Observation::new("h_1", 1, five_tuple(), SniSource::Absent)
            .degraded(vec![DegradedReason::Ech])
            .degraded(vec![DegradedReason::TcUnavailable]);
        assert_eq!(
            observation.degraded_reasons,
            vec![DegradedReason::Ech, DegradedReason::TcUnavailable]
        );
    }

    #[test]
    fn a_name_always_arrives_with_its_source() {
        let observation = Observation::new("h_1", 1, five_tuple(), SniSource::ClientHello)
            .resolved("api.openai.com", ResolvedHostSource::Sni);
        assert_eq!(observation.resolved_host.as_deref(), Some("api.openai.com"));
        assert_eq!(
            observation.resolved_host_source,
            Some(ResolvedHostSource::Sni)
        );
    }
}
