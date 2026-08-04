//! The `ip -> hostname` map DNS answers build, and the window it holds for.
//!
//! An address on its own says nothing: one Cloudflare address fronts millions
//! of names. The map built here is what turns an observed address back into
//! something a person can act on, and it is the only classification signal that
//! survives when a connection offers no readable server name.
//!
//! Two design points carry the weight.
//!
//! **Time is an observation clock, never a wall clock.** Every method takes the
//! current time as an argument, in seconds since the sensor started looking.
//! Reading the system clock in here would put wall time into the path that
//! decides what a report says, and reports in this project have to compare
//! equal across runs.
//!
//! **The map is bounded and says when it drops something.** A long run on a
//! busy host would otherwise grow without limit against a 50 MB budget. When
//! the bound is reached the soonest expiring entry goes first and a counter
//! records it, because a classification that quietly got worse is the failure
//! mode this product exists to expose.
//!
//! **A dropped name is remembered as a loss, per address.** The counter alone
//! could not do the job it was written for. A connection to an address whose
//! names were evicted looks exactly like a connection to an address nobody ever
//! answered for: both reach [`Self::names_for`] and both get an empty list, and
//! the record that follows says `classification: "opaque"`, which the contract
//! defines as "there was never a name to look at". That is the substitution this
//! product exists to refuse, so the addresses that lost their names are kept
//! ([`DnsCache::name_loss_for`]) and the flow says `map_overflow` instead of
//! claiming a blind spot it does not have.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::parse::dns::DnsMapping;

use super::NameMapLoss;

/// Shortest lifetime a mapping is kept for.
///
/// Providers publish very short lifetimes to steer load, and a mapping that
/// expired before the connection it explains would make the sensor blind to
/// exactly the destinations that rotate fastest.
const MIN_TTL_SECS: u64 = 30;

/// Longest lifetime a mapping is kept for, whatever the answer claimed. An
/// address that has been reassigned would otherwise keep naming the old
/// service, and a wrong name is worse than none.
const MAX_TTL_SECS: u64 = 3_600;

/// Addresses held at once. Fixed rather than configurable: it is a memory
/// budget from the component spec, not a preference.
const MAX_ADDRESSES: usize = 8_192;

/// Names held for one address. A single address legitimately fronts many, and
/// past this point the extra names cost memory without improving the answer.
const MAX_NAMES_PER_ADDRESS: usize = 32;

/// What DNS answers established, for as long as they said it holds.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DnsCache {
    /// Address to name to expiry. Both levels are ordered maps so that two runs
    /// over the same answers produce the same name lists.
    entries: BTreeMap<IpAddr, BTreeMap<String, u64>>,
    answers_recorded: u64,
    evicted: u64,
    /// Addresses this map knew a name for and dropped.
    ///
    /// Bounded by the same address budget as the map itself, and by nothing
    /// else: it holds addresses and no names, so a run that overflows the map
    /// repeatedly cannot make this grow past one address budget. When even this
    /// is full the address is not recorded and [`Self::forgotten_evictions`]
    /// counts it, because a lost loss has to be countable too.
    evicted_addresses: BTreeSet<IpAddr>,
    forgotten_evictions: u64,
}

impl DnsCache {
    /// Records what one response established.
    pub fn observe(&mut self, mappings: &[DnsMapping], now_secs: u64) {
        for mapping in mappings {
            let expires_at = now_secs
                .saturating_add(u64::from(mapping.ttl_secs).clamp(MIN_TTL_SECS, MAX_TTL_SECS));
            let names = self.entries.entry(mapping.ip).or_default();
            if names.len() >= MAX_NAMES_PER_ADDRESS && !names.contains_key(&mapping.name) {
                self.evicted += 1;
                self.record_loss(mapping.ip);
                continue;
            }
            // A repeated answer extends the window rather than shortening it:
            // the mapping was just confirmed.
            names
                .entry(mapping.name.clone())
                .and_modify(|existing| *existing = (*existing).max(expires_at))
                .or_insert(expires_at);
            self.answers_recorded += 1;
        }
        self.expire(now_secs);
        self.enforce_capacity();
    }

    /// Names still in force for an address, ascending.
    pub fn names_for(&self, ip: &IpAddr, now_secs: u64) -> Vec<String> {
        self.entries
            .get(ip)
            .map(|names| {
                names
                    .iter()
                    .filter(|(_, expires_at)| **expires_at > now_secs)
                    .map(|(name, _)| name.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// How many address to name pairs the map has taken in.
    ///
    /// Read by the sensor to tell "DNS was watched and said nothing" apart from
    /// "DNS was never visible", which is the difference between a quiet network
    /// and an encrypted resolver.
    pub fn answers_recorded(&self) -> u64 {
        self.answers_recorded
    }

    /// Mappings dropped because the map was full. A declared loss of
    /// resolution, never a silent one.
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Evictions whose address this map could no longer hold on to.
    ///
    /// Read alongside [`Self::name_loss_for`]: while this is above zero, an
    /// address answering `Intact` may still have lost a name, and the run has
    /// to be able to say so rather than presenting the per address answer as
    /// complete.
    pub fn forgotten_evictions(&self) -> u64 {
        self.forgotten_evictions
    }

    /// Whether a name this map once held for the address was thrown away.
    ///
    /// The whole reason the eviction record exists. Without it a destination
    /// whose name was dropped is reported as one that never had a name, and the
    /// two are the opposite of each other: the first is a budget this build
    /// chose, the second is a property of the traffic.
    pub fn name_loss_for(&self, ip: &IpAddr) -> NameMapLoss {
        if self.evicted_addresses.contains(ip) {
            NameMapLoss::NamesDropped
        } else {
            NameMapLoss::Intact
        }
    }

    /// Remembers that this address lost a name, while there is room to.
    fn record_loss(&mut self, ip: IpAddr) {
        if self.evicted_addresses.len() >= MAX_ADDRESSES && !self.evicted_addresses.contains(&ip) {
            self.forgotten_evictions = self.forgotten_evictions.saturating_add(1);
            return;
        }
        self.evicted_addresses.insert(ip);
    }

    fn expire(&mut self, now_secs: u64) {
        self.entries.retain(|_, names| {
            names.retain(|_, expires_at| *expires_at > now_secs);
            !names.is_empty()
        });
    }

    /// Drops whole addresses, soonest to expire first, until the bound holds.
    ///
    /// Ties break on the address so that two runs that filled the map the same
    /// way drop the same entries.
    fn enforce_capacity(&mut self) {
        if self.entries.len() <= MAX_ADDRESSES {
            return;
        }
        let mut by_expiry: Vec<(u64, IpAddr)> = self
            .entries
            .iter()
            .map(|(ip, names)| (names.values().copied().max().unwrap_or(0), *ip))
            .collect();
        by_expiry.sort_unstable();

        let excess = self.entries.len().saturating_sub(MAX_ADDRESSES);
        for (_, ip) in by_expiry.into_iter().take(excess) {
            if let Some(names) = self.entries.remove(&ip) {
                self.evicted += names.len() as u64;
                // The address, not only the count. A connection to it later in
                // the run has to be able to say the name was dropped rather
                // than reporting that none existed.
                self.record_loss(ip);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn mapping(ip: [u8; 4], name: &str, ttl: u32) -> DnsMapping {
        DnsMapping {
            ip: IpAddr::from(ip),
            name: name.to_owned(),
            ttl_secs: ttl,
        }
    }

    #[test]
    fn a_recorded_answer_names_its_address() {
        let mut cache = DnsCache::default();
        cache.observe(&[mapping([104, 18, 7, 1], "api.openai.com", 300)], 0);
        assert_eq!(
            cache.names_for(&IpAddr::from([104, 18, 7, 1]), 10),
            vec!["api.openai.com"]
        );
    }

    #[test]
    fn an_address_nobody_answered_for_has_no_names_rather_than_a_guess() {
        let cache = DnsCache::default();
        assert!(cache
            .names_for(&IpAddr::from([104, 18, 7, 9]), 0)
            .is_empty());
    }

    #[test]
    fn a_mapping_stops_naming_its_address_once_the_window_closes() {
        // A reassigned address that kept its old name would put a destination
        // in the report that the traffic never went to.
        let mut cache = DnsCache::default();
        cache.observe(&[mapping([104, 18, 7, 1], "api.openai.com", 60)], 0);
        assert!(!cache
            .names_for(&IpAddr::from([104, 18, 7, 1]), 59)
            .is_empty());
        assert!(cache
            .names_for(&IpAddr::from([104, 18, 7, 1]), 61)
            .is_empty());
    }

    #[test]
    fn a_very_short_lifetime_is_lifted_to_the_floor() {
        // Providers publish single digit lifetimes to steer load. Honouring
        // them literally would drop the mapping before the connection it
        // explains is even observed.
        let mut cache = DnsCache::default();
        cache.observe(&[mapping([104, 18, 7, 1], "api.openai.com", 1)], 0);
        assert!(!cache
            .names_for(&IpAddr::from([104, 18, 7, 1]), 29)
            .is_empty());
    }

    #[test]
    fn a_very_long_lifetime_is_capped() {
        let mut cache = DnsCache::default();
        cache.observe(&[mapping([104, 18, 7, 1], "api.openai.com", u32::MAX)], 0);
        assert!(cache
            .names_for(&IpAddr::from([104, 18, 7, 1]), MAX_TTL_SECS + 1)
            .is_empty());
    }

    #[test]
    fn a_repeated_answer_extends_the_window_instead_of_shortening_it() {
        let mut cache = DnsCache::default();
        cache.observe(&[mapping([104, 18, 7, 1], "api.openai.com", 600)], 0);
        cache.observe(&[mapping([104, 18, 7, 1], "api.openai.com", 60)], 10);
        assert!(!cache
            .names_for(&IpAddr::from([104, 18, 7, 1]), 500)
            .is_empty());
    }

    #[test]
    fn several_names_for_one_address_all_survive_in_order() {
        // The CDN case. Choosing one and dropping the rest would decide the
        // classification here instead of where the evidence is weighed.
        let mut cache = DnsCache::default();
        cache.observe(
            &[
                mapping([104, 18, 7, 1], "b.example", 300),
                mapping([104, 18, 7, 1], "a.example", 300),
            ],
            0,
        );
        assert_eq!(
            cache.names_for(&IpAddr::from([104, 18, 7, 1]), 1),
            vec!["a.example", "b.example"]
        );
    }

    #[test]
    fn ipv6_and_ipv4_are_separate_addresses() {
        let mut cache = DnsCache::default();
        let v6: IpAddr = "2606:4700::6810:701".parse().unwrap();
        cache.observe(
            &[
                mapping([104, 18, 7, 1], "four.example", 300),
                DnsMapping {
                    ip: v6,
                    name: "six.example".to_owned(),
                    ttl_secs: 300,
                },
            ],
            0,
        );
        assert_eq!(cache.names_for(&v6, 1), vec!["six.example"]);
        assert_eq!(
            cache.names_for(&IpAddr::from([104, 18, 7, 1]), 1),
            vec!["four.example"]
        );
    }

    #[test]
    fn the_map_counts_what_it_took_in_so_a_silent_resolver_is_visible() {
        // Zero answers with connections happening is the signature of an
        // encrypted resolver, and the sensor has to be able to say so.
        let mut cache = DnsCache::default();
        assert_eq!(cache.answers_recorded(), 0);
        cache.observe(&[mapping([104, 18, 7, 1], "api.openai.com", 300)], 0);
        assert_eq!(cache.answers_recorded(), 1);
    }

    #[test]
    fn a_full_map_drops_entries_and_counts_the_drop() {
        // The budget is real, so the loss is real. It must not be silent.
        let mut cache = DnsCache::default();
        for index in 0..(MAX_ADDRESSES + 10) {
            let octets = (index as u32).to_be_bytes();
            cache.observe(
                &[DnsMapping {
                    ip: IpAddr::from(octets),
                    name: format!("host{index}.example"),
                    ttl_secs: 300,
                }],
                0,
            );
        }
        assert!(cache.entries.len() <= MAX_ADDRESSES);
        assert!(cache.evicted() >= 10);
    }

    #[test]
    fn an_address_whose_name_was_evicted_says_so_instead_of_reading_as_unnamed() {
        // The overflow produced for real: one more address than the budget
        // holds, the earliest expiring one dropped, and a later question about
        // that address. `names_for` answers the same empty list it answers for
        // an address nobody ever resolved, so the loss has to be readable
        // somewhere else or the flow is written as a blind spot it is not.
        let mut cache = DnsCache::default();
        let doomed = IpAddr::from([10, 0, 0, 1]);
        cache.observe(&[mapping([10, 0, 0, 1], "api.openai.com", 60)], 0);
        for index in 0..MAX_ADDRESSES {
            let octets = (index as u32).to_be_bytes();
            cache.observe(
                &[DnsMapping {
                    ip: IpAddr::from(octets),
                    name: format!("host{index}.example"),
                    ttl_secs: 3_600,
                }],
                0,
            );
        }

        assert!(cache.names_for(&doomed, 1).is_empty());
        assert_eq!(cache.name_loss_for(&doomed), NameMapLoss::NamesDropped);
    }

    #[test]
    fn an_address_nobody_answered_for_is_not_reported_as_a_dropped_name() {
        // The other half of the same distinction. A budget this build chose and
        // a destination the network never named must not read alike in either
        // direction.
        let mut cache = DnsCache::default();
        cache.observe(&[mapping([104, 18, 7, 1], "api.openai.com", 300)], 0);
        assert_eq!(
            cache.name_loss_for(&IpAddr::from([104, 18, 7, 9])),
            NameMapLoss::Intact
        );
        assert_eq!(cache.forgotten_evictions(), 0);
    }

    #[test]
    fn the_eviction_record_counts_what_it_could_no_longer_hold() {
        // The record is bounded like the map it describes, so it can overflow
        // too. A loss of a loss is still a loss and is counted rather than
        // leaving the per address answer looking complete.
        let mut cache = DnsCache::default();
        for index in 0..(MAX_ADDRESSES * 2 + 2) {
            let octets = (index as u32).to_be_bytes();
            cache.observe(
                &[DnsMapping {
                    ip: IpAddr::from(octets),
                    name: format!("host{index}.example"),
                    ttl_secs: 300,
                }],
                0,
            );
        }
        assert_eq!(cache.evicted_addresses.len(), MAX_ADDRESSES);
        assert!(cache.forgotten_evictions() > 0);
    }

    #[test]
    fn one_address_cannot_be_filled_with_unbounded_names() {
        let mut cache = DnsCache::default();
        for index in 0..(MAX_NAMES_PER_ADDRESS + 5) {
            cache.observe(
                &[mapping([104, 18, 7, 1], &format!("n{index}.example"), 300)],
                0,
            );
        }
        assert_eq!(
            cache.names_for(&IpAddr::from([104, 18, 7, 1]), 1).len(),
            MAX_NAMES_PER_ADDRESS
        );
        assert!(cache.evicted() >= 5);
        assert_eq!(
            cache.name_loss_for(&IpAddr::from([104, 18, 7, 1])),
            NameMapLoss::NamesDropped
        );
    }
}
