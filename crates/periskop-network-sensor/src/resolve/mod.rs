//! Turning the two payload signals into a name a report can carry.
//!
//! [`cache`] holds what DNS answers established; [`naming`] weighs that against
//! the server name a handshake stated and produces the fields a `Flow` carries.
//! Neither knows about kernels, sockets or privileges, which is what makes the
//! part of this milestone that decides report content testable on any machine.

pub mod cache;
pub mod naming;

use serde::{Deserialize, Serialize};

pub use cache::DnsCache;
pub use naming::{arbitrate, NameVerdict};

/// Whether the name map still holds what it learned about an address.
///
/// Per address rather than per run, which is the difference from
/// [`DnsObservation`]: an encrypted resolver costs the whole run its plaintext
/// answers, while an overflowing map costs the addresses it had to drop and
/// nothing else.
///
/// It exists so that a dropped name and an absent name cannot be spelled the
/// same way. Both leave `names_for` empty, and a flow built on an empty list
/// alone is written `opaque`, which the contract defines as "there was never a
/// name to look at". Saying that about a name this build measured and then
/// threw away is the substitution the product argues against.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum NameMapLoss {
    /// Nothing this map learned about the address has been dropped.
    #[default]
    Intact,
    /// A name the map held for this address was evicted to stay inside the
    /// address budget.
    NamesDropped,
}

/// Whether DNS could be watched at all during a run.
///
/// Declared in the coverage statement rather than per flow, because it is a
/// property of the run: either plaintext resolution was visible or it was not.
/// The component spec calls the loss of DNS visibility the most common
/// practical failure of classification, so a report that did not say which of
/// the two happened would leave its most frequent blind spot unlabelled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsObservation {
    #[default]
    Available,
    UnavailableEncryptedDns,
}

impl DnsObservation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::UnavailableEncryptedDns => "unavailable_encrypted_dns",
        }
    }
}

/// The registered port for DNS over TLS.
///
/// This is the one encrypted resolver signal the sensor can read without
/// looking at content: the port is assigned to DoT and to nothing else, so
/// traffic to it is a structural fact rather than a guess.
///
/// **What this deliberately does not detect.** DNS over HTTPS is
/// indistinguishable from any other HTTPS connection without reading the
/// request, and the sensor does not read requests (ADR-008). Recognising it by
/// a list of resolver host names would be a heuristic match presented as a
/// measurement, which is what this project forbids. So a run whose resolution
/// went over DoH reports `available` while learning nothing, and the flows
/// concerned report themselves as unresolved. That gap is real, and it is
/// listed in the component spec as a known miss rather than papered over here.
pub const DNS_OVER_TLS_PORT: u16 = 853;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const COVERAGE_SCHEMA: &str =
        include_str!("../../../../schemas/coverage-statement.schema.json");

    #[test]
    fn the_two_values_match_the_coverage_contract() {
        // A misspelling here does not degrade gracefully: the validator rejects
        // the statement and the line saying whether DNS was visible disappears.
        let schema: serde_json::Value = serde_json::from_str(COVERAGE_SCHEMA).unwrap();
        let allowed: Vec<&str> = schema
            .pointer("/properties/dns_observation/enum")
            .and_then(serde_json::Value::as_array)
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();

        let written = [
            DnsObservation::Available,
            DnsObservation::UnavailableEncryptedDns,
        ];
        // A subset, and named as one. The contract carries a third value,
        // `not_observed`, which no sensor can write: it is the statement that
        // nothing watched a resolver at all, so it is produced by the absence of
        // this component rather than by anything inside it. Asserting equal
        // lengths, which is what stood here, made a value that exists precisely
        // because the sensor did not run look like a bug in the sensor.
        assert!(written.len() < allowed.len());
        assert!(
            allowed.contains(&"not_observed"),
            "the contract lost the value that says nothing looked: {allowed:?}"
        );
        for value in written {
            assert!(
                allowed.contains(&value.as_str()),
                "{value:?} is not in the contract"
            );
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                serde_json::json!(value.as_str())
            );
        }
    }

    #[test]
    fn the_default_is_the_one_that_claims_no_loss() {
        // A run that never looked must not start out declaring an encrypted
        // resolver it never saw.
        assert_eq!(DnsObservation::default(), DnsObservation::Available);
    }
}
