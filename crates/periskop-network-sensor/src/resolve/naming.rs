//! Deciding what a destination is called when two signals disagree.
//!
//! ADR-008 orders the signals and the component spec states the tie break: DNS
//! answers build a map, the ClientHello states a name, and where they disagree
//! **the server name wins**. The reason is not that it is more reliable in
//! general, it is that it is the connection's own statement of where it
//! believes it is going, while the DNS map is a claim about an address that may
//! front any number of services.
//!
//! The disagreement itself is recorded rather than resolved away. A flow whose
//! DNS map and server name point at different hosts carries
//! `dns_sni_mismatch`, and the record carries both sides: `sni` and
//! `dns_names`. On its own the value proves nothing, which the spec says
//! plainly; ordinary CDN setups produce it. It is evidence, and evidence that
//! only shows one side is not evidence.
//!
//! Encrypted ClientHello is where this function is most careful. ADR-008 says
//! that under ECH the sensor is left with an address and nothing else, and the
//! flow is opaque. So a name is not promoted from the DNS map either: the
//! address the client connected to may front many hosts and the one thing that
//! could have said which is exactly the thing that got encrypted. What DNS did
//! say is still written into `dns_names`, because hiding an observation would
//! be worse than declining to conclude from it.

use crate::flow::{DegradedReason, ResolvedHostSource, SniSource};
use crate::parse::tls::ClientHelloFacts;

use super::DnsObservation;

/// What a flow may say about the name of its destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameVerdict {
    pub resolved_host: Option<String>,
    pub resolved_host_source: Option<ResolvedHostSource>,
    /// Only ever set alongside [`SniSource::ClientHello`]; the contract rejects
    /// a record that carries one without the other.
    pub sni: Option<String>,
    pub sni_source: SniSource,
    /// Everything the DNS map said about this address, ascending.
    pub dns_names: Vec<String>,
    pub degraded_reasons: Vec<DegradedReason>,
}

impl Default for NameVerdict {
    /// A verdict that claims nothing. The default sni source is `absent` and
    /// not `encrypted_client_hello`, because the second is a measured blind
    /// spot and must only ever be reached by observing one.
    fn default() -> Self {
        Self {
            resolved_host: None,
            resolved_host_source: None,
            sni: None,
            sni_source: SniSource::Absent,
            dns_names: Vec::new(),
            degraded_reasons: Vec::new(),
        }
    }
}

/// Weighs the two signals and states what the flow may claim.
///
/// `hello` is `None` when no ClientHello was seen for this flow at all, which
/// is the ordinary case for plain TCP, for UDP, and for any connection the
/// `tc` helper could not observe because it was never attached.
pub fn arbitrate(
    hello: Option<&ClientHelloFacts>,
    dns_names: Vec<String>,
    dns_observation: DnsObservation,
) -> NameVerdict {
    let mut verdict = NameVerdict {
        dns_names,
        ..NameVerdict::default()
    };

    match hello {
        Some(ClientHelloFacts::ServerName(name)) => {
            verdict.sni_source = SniSource::ClientHello;
            verdict.sni = Some(name.clone());
            verdict.resolved_host = Some(name.clone());
            verdict.resolved_host_source = Some(if verdict.dns_names.is_empty() {
                ResolvedHostSource::Sni
            } else if verdict.dns_names.iter().any(|known| known == name) {
                ResolvedHostSource::DnsAndSni
            } else {
                // Both signals were readable and they name different hosts.
                verdict
                    .degraded_reasons
                    .push(DegradedReason::DnsSniMismatch);
                ResolvedHostSource::Sni
            });
        }
        Some(ClientHelloFacts::Encrypted) => {
            verdict.sni_source = SniSource::EncryptedClientHello;
            verdict.degraded_reasons.push(DegradedReason::Ech);
            // No resolved host, on purpose. See the module note.
        }
        Some(ClientHelloFacts::NoServerName) | None => {
            verdict.sni_source = SniSource::Absent;
            if let Some(name) = pick_dns_name(&verdict.dns_names) {
                verdict.resolved_host = Some(name);
                verdict.resolved_host_source = Some(ResolvedHostSource::Dns);
            }
        }
    }

    if verdict.dns_names.is_empty() && dns_observation == DnsObservation::UnavailableEncryptedDns {
        // Says why the map contributed nothing here, so a reader does not read
        // an unresolved destination as a quiet network.
        verdict.degraded_reasons.push(DegradedReason::EncryptedDns);
    }

    verdict
}

/// Picks one of several names an address answered to.
///
/// The first in ascending order, which is an arbitrary rule chosen because it
/// is a stable one: the alternative is the order answers happened to arrive in,
/// and that would make two captures of the same traffic serialize differently.
/// Every candidate stays visible in `dns_names`, so nothing is lost by the
/// choice.
fn pick_dns_name(dns_names: &[String]) -> Option<String> {
    dns_names.iter().min().cloned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn names(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn hello(name: &str) -> ClientHelloFacts {
        ClientHelloFacts::ServerName(name.to_owned())
    }

    #[test]
    fn a_server_name_alone_names_the_destination() {
        let verdict = arbitrate(
            Some(&hello("api.openai.com")),
            Vec::new(),
            DnsObservation::Available,
        );
        assert_eq!(verdict.resolved_host.as_deref(), Some("api.openai.com"));
        assert_eq!(verdict.resolved_host_source, Some(ResolvedHostSource::Sni));
        assert_eq!(verdict.sni.as_deref(), Some("api.openai.com"));
        assert_eq!(verdict.sni_source, SniSource::ClientHello);
        assert!(verdict.degraded_reasons.is_empty());
    }

    #[test]
    fn two_signals_that_agree_are_recorded_as_two_signals() {
        // Worth its own value in the contract: a name both signals produced is
        // stronger evidence than one either produced alone.
        let verdict = arbitrate(
            Some(&hello("api.openai.com")),
            names(&["api.openai.com"]),
            DnsObservation::Available,
        );
        assert_eq!(
            verdict.resolved_host_source,
            Some(ResolvedHostSource::DnsAndSni)
        );
        assert!(verdict.degraded_reasons.is_empty());
    }

    #[test]
    fn when_the_two_disagree_the_server_name_wins_and_the_record_says_so() {
        // The milestone's headline rule. Both halves matter: the name that is
        // reported, and the fact that a disagreement existed at all.
        let verdict = arbitrate(
            Some(&hello("api.openai.com")),
            names(&["edge.cdn.example"]),
            DnsObservation::Available,
        );
        assert_eq!(verdict.resolved_host.as_deref(), Some("api.openai.com"));
        assert_eq!(verdict.resolved_host_source, Some(ResolvedHostSource::Sni));
        assert_eq!(
            verdict.degraded_reasons,
            vec![DegradedReason::DnsSniMismatch]
        );
        assert_eq!(verdict.dns_names, names(&["edge.cdn.example"]));
    }

    #[test]
    fn a_disagreement_keeps_both_sides_in_the_record() {
        // A record that declares a mismatch while showing only the winner is a
        // claim a reader cannot check.
        let verdict = arbitrate(
            Some(&hello("api.openai.com")),
            names(&["a.cdn.example", "b.cdn.example"]),
            DnsObservation::Available,
        );
        assert_eq!(verdict.sni.as_deref(), Some("api.openai.com"));
        assert_eq!(verdict.dns_names.len(), 2);
    }

    #[test]
    fn one_matching_name_among_several_is_agreement_and_not_a_mismatch() {
        // A CDN address that answers to many names, one of which is the one the
        // handshake asked for. Flagging that as a disagreement would make the
        // value meaningless through noise.
        let verdict = arbitrate(
            Some(&hello("api.openai.com")),
            names(&["api.openai.com", "edge.cdn.example"]),
            DnsObservation::Available,
        );
        assert_eq!(
            verdict.resolved_host_source,
            Some(ResolvedHostSource::DnsAndSni)
        );
        assert!(verdict.degraded_reasons.is_empty());
    }

    #[test]
    fn under_ech_no_name_is_claimed_and_the_loss_is_declared() {
        // ADR-008: under an encrypted hello the sensor is left with an address.
        // The flow has to read as opaque, which means no resolved host at all.
        let verdict = arbitrate(
            Some(&ClientHelloFacts::Encrypted),
            Vec::new(),
            DnsObservation::Available,
        );
        assert_eq!(verdict.sni_source, SniSource::EncryptedClientHello);
        assert_eq!(verdict.sni, None);
        assert_eq!(verdict.resolved_host, None);
        assert_eq!(verdict.resolved_host_source, None);
        assert!(verdict.degraded_reasons.contains(&DegradedReason::Ech));
    }

    #[test]
    fn under_ech_a_dns_name_is_shown_but_not_promoted_to_the_destination() {
        // The address is fronted; the map cannot say which of the names behind
        // it was reached. Recording the observation without concluding from it
        // is the honest half measure.
        let verdict = arbitrate(
            Some(&ClientHelloFacts::Encrypted),
            names(&["edge.cdn.example"]),
            DnsObservation::Available,
        );
        assert_eq!(verdict.resolved_host, None);
        assert_eq!(verdict.dns_names, names(&["edge.cdn.example"]));
    }

    #[test]
    fn without_a_handshake_the_dns_map_names_the_destination() {
        let verdict = arbitrate(None, names(&["api.openai.com"]), DnsObservation::Available);
        assert_eq!(verdict.resolved_host.as_deref(), Some("api.openai.com"));
        assert_eq!(verdict.resolved_host_source, Some(ResolvedHostSource::Dns));
        assert_eq!(verdict.sni_source, SniSource::Absent);
        assert_eq!(verdict.sni, None);
    }

    #[test]
    fn a_handshake_that_offered_no_name_is_not_an_encrypted_one() {
        let verdict = arbitrate(
            Some(&ClientHelloFacts::NoServerName),
            Vec::new(),
            DnsObservation::Available,
        );
        assert_eq!(verdict.sni_source, SniSource::Absent);
        assert!(!verdict.degraded_reasons.contains(&DegradedReason::Ech));
    }

    #[test]
    fn several_dns_names_and_no_handshake_pick_the_same_one_every_run() {
        // Determinism, not preference. The alternative is arrival order, which
        // would make two captures of one connection differ.
        let forwards = arbitrate(
            None,
            names(&["b.example", "a.example"]),
            DnsObservation::Available,
        );
        let backwards = arbitrate(
            None,
            names(&["a.example", "b.example"]),
            DnsObservation::Available,
        );
        assert_eq!(forwards.resolved_host.as_deref(), Some("a.example"));
        assert_eq!(forwards.resolved_host, backwards.resolved_host);
    }

    #[test]
    fn nothing_readable_at_all_leaves_the_destination_unnamed() {
        // Which the record turns into `opaque`, the line of the report that
        // matters most. It must not be reachable by accident.
        let verdict = arbitrate(None, Vec::new(), DnsObservation::Available);
        assert_eq!(verdict.resolved_host, None);
        assert_eq!(verdict.resolved_host_source, None);
        assert_eq!(verdict.sni_source, SniSource::Absent);
        assert!(verdict.degraded_reasons.is_empty());
    }

    #[test]
    fn an_encrypted_resolver_is_named_as_the_reason_the_map_was_empty() {
        // Otherwise an unresolved destination and a destination nobody looked
        // up read identically.
        let verdict = arbitrate(None, Vec::new(), DnsObservation::UnavailableEncryptedDns);
        assert_eq!(verdict.degraded_reasons, vec![DegradedReason::EncryptedDns]);
    }

    #[test]
    fn an_encrypted_resolver_is_not_blamed_where_dns_did_answer() {
        // Plaintext answers for this address exist, so whatever else the run
        // lost, it did not lose this.
        let verdict = arbitrate(
            None,
            names(&["api.openai.com"]),
            DnsObservation::UnavailableEncryptedDns,
        );
        assert!(!verdict
            .degraded_reasons
            .contains(&DegradedReason::EncryptedDns));
    }

    #[test]
    fn an_encrypted_hello_over_an_encrypted_resolver_declares_both_losses() {
        // The worst case, and the one that grows over time. Both reasons have
        // to survive to the record or the report understates the blind spot.
        let verdict = arbitrate(
            Some(&ClientHelloFacts::Encrypted),
            Vec::new(),
            DnsObservation::UnavailableEncryptedDns,
        );
        assert!(verdict.degraded_reasons.contains(&DegradedReason::Ech));
        assert!(verdict
            .degraded_reasons
            .contains(&DegradedReason::EncryptedDns));
    }
}
