//! Joining what the hooks saw into one observation per connection.
//!
//! This is the join ADR-008 calls the sensor's most critical correctness point.
//! A connection is described by up to four separate events from two different
//! layers of the kernel, and putting them back together wrongly does not
//! produce an obvious error: it produces a plausible record attributing one
//! process's traffic to another. So the rules here are written to fail towards
//! saying less.
//!
//! - **A process is only ever copied from a kprobe event.** There is no code
//!   path that derives one from a packet, because the packet layer does not
//!   know it. An event from the `tc` helper that no connection claims still
//!   produces a record, as the ADR requires, with no process at all and
//!   `unattributed` written on it.
//! - **A closed connection stops owning its key immediately.** Ports are reused
//!   within seconds; a key left in the live map would let the next connection
//!   inherit the previous one's process.
//! - **Nothing is finalised until the window is sealed.** DNS answers arrive
//!   before and after the connections they explain, so weighing a flow the
//!   moment it closes would make the result depend on packet ordering. Sealing
//!   once at the end also makes two captures of the same traffic produce the
//!   same records, which is the determinism the reports depend on.
//!
//! What the assembler will not do is invent a flow out of an event it cannot
//! place. A byte counter for a connection it never saw open has no start time,
//! and a start time is part of a flow's identity. Those are counted as unlinked
//! rather than given a plausible one.

use std::collections::BTreeMap;

use crate::flow::DegradedReason;
use crate::kernel::event::{
    CloseEvent, ConnectEvent, KernelEvent, KernelProcess, PayloadEvent, PayloadFacts, VolumeEvent,
};
use crate::kernel::key::FlowKey;
use crate::observation::Observation;
use crate::parse::tls::ClientHelloFacts;
use crate::resolve::{arbitrate, DnsCache, DnsObservation, DNS_OVER_TLS_PORT};

/// What is known about a connection so far.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pending {
    t_start_bucket: u64,
    /// Observation seconds, used to age the DNS map against the moment this
    /// connection happened rather than against the end of the run.
    at_secs: u64,
    process: Option<KernelProcess>,
    pre_existing: bool,
    bytes_out: u64,
    bytes_in: u64,
    segments_out: u64,
    volume_seen: bool,
    duration_ms: Option<u64>,
    hello: Option<ClientHelloFacts>,
}

impl Pending {
    fn opened(t_start_bucket: u64, at_secs: u64) -> Self {
        Self {
            t_start_bucket,
            at_secs,
            process: None,
            pre_existing: false,
            bytes_out: 0,
            bytes_in: 0,
            segments_out: 0,
            volume_seen: false,
            duration_ms: None,
            hello: None,
        }
    }
}

/// Builds observations out of kernel events.
#[derive(Debug, Clone)]
pub struct FlowAssembler {
    host_id: String,
    boot_id: Option<String>,
    dns: DnsCache,
    live: BTreeMap<FlowKey, Pending>,
    closed: Vec<(FlowKey, Pending)>,
    dropped_events: u64,
    unlinked_events: u64,
    encrypted_dns_transport: bool,
}

impl FlowAssembler {
    pub fn new(host_id: impl Into<String>) -> Self {
        Self {
            host_id: host_id.into(),
            boot_id: None,
            dns: DnsCache::default(),
            live: BTreeMap::new(),
            closed: Vec::new(),
            dropped_events: 0,
            unlinked_events: 0,
            encrypted_dns_transport: false,
        }
    }

    pub fn with_boot_id(mut self, boot_id: impl Into<String>) -> Self {
        self.boot_id = Some(boot_id.into());
        self
    }

    /// Events the ring buffer lost before user space read it.
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    /// Events that named a connection this pass never saw open.
    ///
    /// Reported rather than swallowed: a byte counter with no flow is traffic
    /// the sensor watched and could not place, which is a coverage fact.
    pub fn unlinked_events(&self) -> u64 {
        self.unlinked_events
    }

    /// Names the DNS map threw away to stay inside its address budget.
    ///
    /// A run level number beside the per flow `map_overflow` reason: the flows
    /// say which destinations lost a name, this says how much resolution the
    /// budget cost the run as a whole.
    pub fn dns_names_evicted(&self) -> u64 {
        self.dns.evicted()
    }

    /// Evictions the map could not even remember the address of.
    ///
    /// Above zero means a flow reporting no name loss may still have had one,
    /// so the run has to declare the gap rather than presenting the per flow
    /// answers as complete.
    pub fn dns_evictions_forgotten(&self) -> u64 {
        self.dns.forgotten_evictions()
    }

    pub fn record_dropped(&mut self, count: u64) {
        self.dropped_events = self.dropped_events.saturating_add(count);
    }

    /// Whether plaintext DNS could be watched at all.
    ///
    /// Two conditions, both structural. Traffic to the registered DNS over TLS
    /// port says an encrypted resolver was in use; no recorded answers says the
    /// map learned nothing from the plaintext path. Either alone would be too
    /// weak: a host can run DoT for one process and plain DNS for another, and
    /// a quiet minute produces no answers without anything being encrypted.
    pub fn dns_observation(&self) -> DnsObservation {
        if self.encrypted_dns_transport && self.dns.answers_recorded() == 0 {
            DnsObservation::UnavailableEncryptedDns
        } else {
            DnsObservation::Available
        }
    }

    pub fn ingest(&mut self, event: KernelEvent) {
        if event.key().dst_port == DNS_OVER_TLS_PORT {
            self.encrypted_dns_transport = true;
        }
        match event {
            KernelEvent::Connect(event) => self.on_connect(event),
            KernelEvent::Volume(event) => self.on_volume(event),
            KernelEvent::Close(event) => self.on_close(event),
            KernelEvent::Payload(event) => self.on_payload(event),
        }
    }

    fn on_connect(&mut self, event: ConnectEvent) {
        let pending = self
            .live
            .entry(event.key)
            .or_insert_with(|| Pending::opened(event.t_start_bucket, event.at_secs));
        // A handshake seen before the connect event is kept; the connect is
        // what adds the process, and it does not overwrite what tc found.
        pending.t_start_bucket = event.t_start_bucket;
        pending.at_secs = event.at_secs;
        pending.process = Some(event.process);
        pending.pre_existing = event.pre_existing;
    }

    fn on_volume(&mut self, event: VolumeEvent) {
        let Some(pending) = self.live.get_mut(&event.key) else {
            self.unlinked_events = self.unlinked_events.saturating_add(1);
            return;
        };
        pending.bytes_out = pending.bytes_out.saturating_add(event.bytes_out);
        pending.bytes_in = pending.bytes_in.saturating_add(event.bytes_in);
        pending.segments_out = pending.segments_out.saturating_add(event.segments_out);
        pending.volume_seen = true;
    }

    fn on_close(&mut self, event: CloseEvent) {
        let Some(mut pending) = self.live.remove(&event.key) else {
            self.unlinked_events = self.unlinked_events.saturating_add(1);
            return;
        };
        pending.duration_ms = event.duration_ms;
        // Out of the live map at once, so the next connection on this key
        // cannot inherit this one's process.
        self.closed.push((event.key, pending));
    }

    fn on_payload(&mut self, event: PayloadEvent) {
        match event.facts {
            PayloadFacts::Dns(answers) => {
                // An answer describes an address, not the connection that
                // carried it, so it feeds the map and creates no flow of its
                // own. The DNS connection itself is recorded by its own connect
                // event like any other.
                self.dns.observe(&answers.mappings, event.at_secs);
            }
            PayloadFacts::Handshake(facts) => {
                let pending = self
                    .live
                    .entry(event.key)
                    .or_insert_with(|| Pending::opened(event.t_start_bucket, event.at_secs));
                pending.hello = Some(facts);
            }
        }
    }

    /// Closes the observation window and hands over one record per connection.
    ///
    /// Connections still open are included. Their duration is simply unknown,
    /// which the record says by carrying no duration; dropping them instead
    /// would lose every long lived connection, which is most of the interesting
    /// ones.
    pub fn seal(&mut self) -> Vec<Observation> {
        let mut flows = std::mem::take(&mut self.closed);
        flows.extend(std::mem::take(&mut self.live));
        // Two captures of the same traffic must produce the same list, whatever
        // order the ring buffer handed events over in.
        flows.sort_by(|(left_key, left), (right_key, right)| {
            left_key
                .cmp(right_key)
                .then_with(|| left.t_start_bucket.cmp(&right.t_start_bucket))
        });

        let dns_observation = self.dns_observation();
        flows
            .into_iter()
            .map(|(key, pending)| self.finalise(&key, pending, dns_observation))
            .collect()
    }

    fn finalise(
        &self,
        key: &FlowKey,
        pending: Pending,
        dns_observation: DnsObservation,
    ) -> Observation {
        let dns_names = self.dns.names_for(&key.dst_ip, pending.at_secs);
        // Asked per destination, because an empty name list is what a dropped
        // answer and an unanswered address have in common and the record has to
        // separate them.
        let name_map_loss = self.dns.name_loss_for(&key.dst_ip);
        let verdict = arbitrate(
            pending.hello.as_ref(),
            dns_names,
            dns_observation,
            name_map_loss,
        );

        let mut observation = Observation::new(
            self.host_id.clone(),
            pending.t_start_bucket,
            key.five_tuple(),
            verdict.sni_source,
        )
        .with_dns_names(verdict.dns_names);

        if let Some(boot_id) = &self.boot_id {
            observation = observation.with_boot_id(boot_id.clone());
        }
        if let Some(netns) = key.netns_label() {
            observation = observation.with_netns(netns);
        }
        if let Some(duration_ms) = pending.duration_ms {
            observation = observation.with_duration_ms(duration_ms);
        }
        if pending.volume_seen {
            observation = observation
                .with_volume(pending.bytes_out, pending.bytes_in)
                .with_segments_out(pending.segments_out);
        }
        if let Some(process) = pending.process {
            // The one place attribution is claimed, and it is claimed only from
            // a kprobe event, which ran in the calling task's context.
            observation = observation.kernel_attributed(process.into_record());
        }
        if let (Some(host), Some(source)) = (verdict.resolved_host, verdict.resolved_host_source) {
            observation = observation.resolved(host, source);
        }
        if let Some(sni) = verdict.sni {
            observation = observation.with_sni(sni);
        }

        let mut degraded = verdict.degraded_reasons;
        if pending.pre_existing {
            // Volume and duration are lower bounds on such a flow, and the spec
            // forbids a volume threshold from filtering it out on that basis.
            degraded.push(DegradedReason::PreExistingConnection);
        }
        observation.degraded(degraded)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::flow::{ProcessAttribution, Proto, ResolvedHostSource, SniSource};
    use crate::kernel::key::tests::key;
    use crate::parse::dns::{DnsAnswers, DnsMapping};
    use std::net::IpAddr;

    const START: u64 = 1_785_834_000;

    fn assembler() -> FlowAssembler {
        FlowAssembler::new("h_9f2c4a17be0d5386").with_boot_id("b_3f0a91c7d4e28b56")
    }

    fn process() -> KernelProcess {
        KernelProcess {
            pid: 4821,
            pid_start_time: Some(1_785_833_900),
            comm: Some("python3".to_owned()),
        }
    }

    fn connect(flow: &FlowKey, at_secs: u64) -> KernelEvent {
        KernelEvent::Connect(ConnectEvent {
            key: flow.clone(),
            t_start_bucket: START,
            at_secs,
            process: process(),
            pre_existing: false,
        })
    }

    fn handshake(flow: &FlowKey, facts: ClientHelloFacts, at_secs: u64) -> KernelEvent {
        KernelEvent::Payload(PayloadEvent {
            key: flow.clone(),
            t_start_bucket: START,
            at_secs,
            facts: PayloadFacts::Handshake(facts),
        })
    }

    fn dns_answer(flow: &FlowKey, ip: [u8; 4], name: &str, at_secs: u64) -> KernelEvent {
        KernelEvent::Payload(PayloadEvent {
            key: flow.clone(),
            t_start_bucket: START,
            at_secs,
            facts: PayloadFacts::Dns(DnsAnswers {
                query_name: Some(name.to_owned()),
                mappings: vec![DnsMapping {
                    ip: IpAddr::from(ip),
                    name: name.to_owned(),
                    ttl_secs: 300,
                }],
                truncated_by_server: false,
            }),
        })
    }

    fn server_name(name: &str) -> ClientHelloFacts {
        ClientHelloFacts::ServerName(name.to_owned())
    }

    #[test]
    fn a_connect_makes_a_flow_the_kernel_attributed_to_its_process() {
        // Milestone 51 in one assertion: the hook ran in the task's context, so
        // the attribution is certain rather than matched afterwards.
        let mut assembler = assembler();
        let flow = key("104.18.7.1", 443, 54321);
        assembler.ingest(connect(&flow, 1));

        let observations = assembler.seal();
        assert_eq!(observations.len(), 1);
        let observation = observations.first().unwrap();
        assert_eq!(
            observation.process_attribution,
            ProcessAttribution::KernelAttributed
        );
        assert_eq!(observation.process.as_ref().map(|p| p.pid), Some(4821));
        assert_eq!(observation.five_tuple.dst_ip, "104.18.7.1");
        assert_eq!(observation.t_start_bucket, START);
        assert_eq!(observation.netns.as_deref(), Some("4026531840"));
    }

    #[test]
    fn byte_counters_accumulate_onto_the_connection_that_opened() {
        let mut assembler = assembler();
        let flow = key("104.18.7.1", 443, 54321);
        assembler.ingest(connect(&flow, 1));
        for _ in 0..3 {
            assembler.ingest(KernelEvent::Volume(VolumeEvent {
                key: flow.clone(),
                bytes_out: 100,
                bytes_in: 400,
                segments_out: 2,
            }));
        }
        assembler.ingest(KernelEvent::Close(CloseEvent {
            key: flow.clone(),
            duration_ms: Some(412),
        }));

        let observations = assembler.seal();
        let observation = observations.first().unwrap();
        assert_eq!(observation.bytes_out, Some(300));
        assert_eq!(observation.bytes_in, Some(1200));
        assert_eq!(observation.segments_out, Some(6));
        assert_eq!(observation.duration_ms, Some(412));
    }

    #[test]
    fn a_connection_with_no_counters_reports_no_volume_rather_than_zero() {
        // Zero bytes is a measurement. "Nobody counted" is not, and writing the
        // first where the second happened would let a volume rule reason about
        // a number nothing produced.
        let mut assembler = assembler();
        assembler.ingest(connect(&key("104.18.7.1", 443, 54321), 1));
        let observations = assembler.seal();
        assert_eq!(observations.first().unwrap().bytes_out, None);
    }

    #[test]
    fn a_still_open_connection_is_reported_with_no_duration() {
        // Long lived connections are most of the interesting ones. Dropping
        // them because they had not closed by the end of the window would lose
        // exactly the traffic the sensor exists to see.
        let mut assembler = assembler();
        assembler.ingest(connect(&key("104.18.7.1", 443, 54321), 1));
        let observations = assembler.seal();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations.first().unwrap().duration_ms, None);
    }

    #[test]
    fn a_handshake_the_tc_helper_saw_names_the_destination() {
        let mut assembler = assembler();
        let flow = key("104.18.7.1", 443, 54321);
        assembler.ingest(connect(&flow, 1));
        assembler.ingest(handshake(&flow, server_name("api.openai.com"), 1));

        let observation = assembler.seal().into_iter().next().unwrap();
        assert_eq!(observation.resolved_host.as_deref(), Some("api.openai.com"));
        assert_eq!(observation.sni.as_deref(), Some("api.openai.com"));
        assert_eq!(observation.sni_source, SniSource::ClientHello);
    }

    #[test]
    fn a_dns_answer_names_a_destination_that_offered_no_handshake() {
        // Plain TCP, or a connection whose hello was never captured. The map is
        // the only signal left and it is enough to name the host.
        let mut assembler = assembler();
        let resolver = key("10.0.0.53", 53, 40000);
        let flow = key("104.18.7.1", 443, 54321);
        assembler.ingest(dns_answer(&resolver, [104, 18, 7, 1], "api.openai.com", 1));
        assembler.ingest(connect(&flow, 2));

        let observations = assembler.seal();
        let named = observations
            .iter()
            .find(|observation| observation.five_tuple.dst_ip == "104.18.7.1")
            .unwrap();
        assert_eq!(named.resolved_host.as_deref(), Some("api.openai.com"));
        assert_eq!(named.resolved_host_source, Some(ResolvedHostSource::Dns));
        assert_eq!(named.dns_names, vec!["api.openai.com".to_owned()]);
    }

    #[test]
    fn a_destination_whose_name_the_map_dropped_says_so_instead_of_reading_as_opaque() {
        // Finding O7, produced end to end rather than argued. The map learns
        // what 104.18.7.1 is called, a busy run then fills it past its address
        // budget and that answer is evicted, and the connection to the same
        // address arrives afterwards. Everything downstream sees an empty name
        // list, which is the same thing it sees for an address nobody ever
        // resolved, and the record is written `opaque`: "there was never a name
        // to look at". The name existed and this build threw it away, so the
        // record has to carry the reason.
        let mut assembler = assembler();
        let resolver = key("10.0.0.53", 53, 40_000);
        let flow = key("104.18.7.1", 443, 54_321);
        assembler.ingest(dns_answer(&resolver, [104, 18, 7, 1], "api.openai.com", 1));

        // One address more than the map holds, each with a longer lifetime, so
        // the answer above is the one that goes.
        for index in 0..8_192u32 {
            let octets = index.to_be_bytes();
            assembler.ingest(KernelEvent::Payload(PayloadEvent {
                key: resolver.clone(),
                t_start_bucket: START,
                at_secs: 2,
                facts: PayloadFacts::Dns(DnsAnswers {
                    query_name: None,
                    mappings: vec![DnsMapping {
                        ip: IpAddr::from(octets),
                        name: format!("host{index}.example"),
                        ttl_secs: 3_600,
                    }],
                    truncated_by_server: false,
                }),
            }));
        }
        assembler.ingest(connect(&flow, 3));

        let observation = assembler
            .seal()
            .into_iter()
            .find(|observation| observation.five_tuple.dst_ip == "104.18.7.1")
            .unwrap();
        assert!(observation.dns_names.is_empty());
        assert_eq!(observation.resolved_host, None);
        assert!(
            observation
                .degraded_reasons
                .contains(&DegradedReason::MapOverflow),
            "a name this run measured and dropped was reported as a name that never existed: {:?}",
            observation.degraded_reasons
        );
        assert!(assembler.dns_names_evicted() > 0);
    }

    #[test]
    fn a_dns_answer_does_not_create_a_flow_of_its_own() {
        // The answer is about an address. Turning it into a connection would
        // double count the resolver traffic that its own connect event covers.
        let mut assembler = assembler();
        let resolver = key("10.0.0.53", 53, 40000);
        assembler.ingest(dns_answer(&resolver, [104, 18, 7, 1], "api.openai.com", 1));
        assert!(assembler.seal().is_empty());
    }

    #[test]
    fn when_the_two_signals_disagree_the_record_carries_both_sides() {
        // Milestone 52's headline rule, end to end through the assembler.
        let mut assembler = assembler();
        let resolver = key("10.0.0.53", 53, 40000);
        let flow = key("104.18.7.1", 443, 54321);
        assembler.ingest(dns_answer(
            &resolver,
            [104, 18, 7, 1],
            "edge.cdn.example",
            1,
        ));
        assembler.ingest(connect(&flow, 2));
        assembler.ingest(handshake(&flow, server_name("api.openai.com"), 2));

        let observation = assembler
            .seal()
            .into_iter()
            .find(|observation| observation.five_tuple.dst_ip == "104.18.7.1")
            .unwrap();
        assert_eq!(observation.resolved_host.as_deref(), Some("api.openai.com"));
        assert_eq!(observation.dns_names, vec!["edge.cdn.example".to_owned()]);
        assert!(observation
            .degraded_reasons
            .contains(&DegradedReason::DnsSniMismatch));
    }

    #[test]
    fn an_encrypted_hello_leaves_the_destination_unnamed_and_says_why() {
        let mut assembler = assembler();
        let flow = key("104.18.7.1", 443, 54321);
        assembler.ingest(connect(&flow, 1));
        assembler.ingest(handshake(&flow, ClientHelloFacts::Encrypted, 1));

        let observation = assembler.seal().into_iter().next().unwrap();
        assert_eq!(observation.sni_source, SniSource::EncryptedClientHello);
        assert_eq!(observation.sni, None);
        assert_eq!(observation.resolved_host, None);
        assert!(observation.degraded_reasons.contains(&DegradedReason::Ech));
    }

    #[test]
    fn a_handshake_no_connection_claims_is_recorded_without_a_process() {
        // ADR-008 states this exactly: an unjoinable tc event is not dropped,
        // and it is not given a pid either.
        let mut assembler = assembler();
        let flow = key("104.18.7.1", 443, 54321);
        assembler.ingest(handshake(&flow, server_name("api.openai.com"), 1));

        let observation = assembler.seal().into_iter().next().unwrap();
        assert_eq!(
            observation.process_attribution,
            ProcessAttribution::Unattributed
        );
        assert!(observation.process.is_none());
        assert_eq!(observation.resolved_host.as_deref(), Some("api.openai.com"));
    }

    #[test]
    fn a_handshake_seen_before_the_connect_still_joins() {
        // The packet path and the socket path are different layers of the
        // kernel and their events do not arrive in a fixed order.
        let mut assembler = assembler();
        let flow = key("104.18.7.1", 443, 54321);
        assembler.ingest(handshake(&flow, server_name("api.openai.com"), 1));
        assembler.ingest(connect(&flow, 1));

        let observations = assembler.seal();
        assert_eq!(observations.len(), 1);
        let observation = observations.first().unwrap();
        assert_eq!(
            observation.process_attribution,
            ProcessAttribution::KernelAttributed
        );
        assert_eq!(observation.sni.as_deref(), Some("api.openai.com"));
    }

    #[test]
    fn a_reused_port_does_not_inherit_the_previous_connections_process() {
        // The join's worst failure mode: a plausible record attributing one
        // process's traffic to another. Ports come back within seconds.
        let mut assembler = assembler();
        let flow = key("104.18.7.1", 443, 54321);
        assembler.ingest(connect(&flow, 1));
        assembler.ingest(KernelEvent::Close(CloseEvent {
            key: flow.clone(),
            duration_ms: Some(10),
        }));
        assembler.ingest(handshake(&flow, server_name("elsewhere.example"), 2));

        let observations = assembler.seal();
        assert_eq!(observations.len(), 2);
        let attributed: Vec<ProcessAttribution> = observations
            .iter()
            .map(|observation| observation.process_attribution)
            .collect();
        assert!(attributed.contains(&ProcessAttribution::KernelAttributed));
        assert!(attributed.contains(&ProcessAttribution::Unattributed));
    }

    #[test]
    fn a_counter_for_a_connection_nobody_saw_open_is_counted_and_not_invented() {
        // Such an event has no start time, and a start time is part of a flow's
        // identity. Making one up would put a fabricated record in the report.
        let mut assembler = assembler();
        assembler.ingest(KernelEvent::Volume(VolumeEvent {
            key: key("104.18.7.1", 443, 54321),
            bytes_out: 10,
            bytes_in: 20,
            segments_out: 1,
        }));
        assert!(assembler.seal().is_empty());
        assert_eq!(assembler.unlinked_events(), 1);
    }

    #[test]
    fn a_close_for_a_connection_nobody_saw_open_is_counted_too() {
        let mut assembler = assembler();
        assembler.ingest(KernelEvent::Close(CloseEvent {
            key: key("104.18.7.1", 443, 54321),
            duration_ms: Some(5),
        }));
        assert!(assembler.seal().is_empty());
        assert_eq!(assembler.unlinked_events(), 1);
    }

    #[test]
    fn a_pre_existing_connection_says_its_numbers_are_lower_bounds() {
        let mut assembler = assembler();
        let flow = key("104.18.7.1", 443, 54321);
        assembler.ingest(KernelEvent::Connect(ConnectEvent {
            key: flow,
            t_start_bucket: START,
            at_secs: 0,
            process: process(),
            pre_existing: true,
        }));
        let observation = assembler.seal().into_iter().next().unwrap();
        assert!(observation
            .degraded_reasons
            .contains(&DegradedReason::PreExistingConnection));
    }

    #[test]
    fn dropped_events_are_carried_rather_than_forgotten() {
        let mut assembler = assembler();
        assembler.record_dropped(9);
        assembler.record_dropped(4);
        assert_eq!(assembler.dropped_events(), 13);
    }

    #[test]
    fn an_encrypted_resolver_with_no_plaintext_answers_is_declared() {
        // The most common practical loss of classification, and the sensor has
        // to be able to name it rather than just resolve nothing.
        let mut assembler = assembler();
        let dot = FlowKey {
            dst_port: DNS_OVER_TLS_PORT,
            ..key("10.0.0.53", 853, 40000)
        };
        assembler.ingest(connect(&dot, 1));
        assembler.ingest(connect(&key("104.18.7.1", 443, 54321), 2));

        assert_eq!(
            assembler.dns_observation(),
            DnsObservation::UnavailableEncryptedDns
        );
        let unresolved = assembler
            .seal()
            .into_iter()
            .find(|observation| observation.five_tuple.dst_ip == "104.18.7.1")
            .unwrap();
        assert!(unresolved
            .degraded_reasons
            .contains(&DegradedReason::EncryptedDns));
    }

    #[test]
    fn an_encrypted_resolver_alongside_plaintext_answers_is_not_declared() {
        // A host can run one resolver over TLS and another in the clear. The
        // map still works, so the run must not claim it went blind.
        let mut assembler = assembler();
        let dot = key("10.0.0.53", 853, 40000);
        let resolver = key("10.0.0.54", 53, 40001);
        assembler.ingest(connect(&dot, 1));
        assembler.ingest(dns_answer(&resolver, [104, 18, 7, 1], "api.openai.com", 1));
        assert_eq!(assembler.dns_observation(), DnsObservation::Available);
    }

    #[test]
    fn a_quiet_run_with_no_encrypted_resolver_does_not_claim_one() {
        let mut assembler = assembler();
        assembler.ingest(connect(&key("104.18.7.1", 443, 54321), 1));
        assert_eq!(assembler.dns_observation(), DnsObservation::Available);
    }

    #[test]
    fn the_same_events_in_any_order_produce_the_same_records() {
        // Determinism, which the whole report format depends on. The ring
        // buffer does not promise an order and neither does the network.
        let flow_a = key("104.18.7.1", 443, 54321);
        let flow_b = key("104.18.7.2", 443, 54322);
        let resolver = key("10.0.0.53", 53, 40000);

        let build = |events: Vec<KernelEvent>| {
            let mut assembler = assembler();
            for event in events {
                assembler.ingest(event);
            }
            assembler.seal()
        };

        let forwards = build(vec![
            dns_answer(&resolver, [104, 18, 7, 1], "api.openai.com", 1),
            connect(&flow_a, 1),
            handshake(&flow_a, server_name("api.openai.com"), 1),
            connect(&flow_b, 2),
        ]);
        let backwards = build(vec![
            connect(&flow_b, 2),
            handshake(&flow_a, server_name("api.openai.com"), 1),
            connect(&flow_a, 1),
            dns_answer(&resolver, [104, 18, 7, 1], "api.openai.com", 1),
        ]);
        assert_eq!(forwards, backwards);
        assert_eq!(forwards.len(), 2);
    }

    #[test]
    fn a_udp_flow_is_assembled_like_any_other() {
        // QUIC arrives this way and is the weakest case for resolution. Weak
        // resolution is not a reason to leave the connection out.
        let mut assembler = assembler();
        let quic = FlowKey {
            proto: Proto::Udp,
            ..key("104.18.7.1", 443, 54321)
        };
        assembler.ingest(connect(&quic, 1));
        let observation = assembler.seal().into_iter().next().unwrap();
        assert_eq!(observation.five_tuple.proto, Proto::Udp);
        assert_eq!(observation.sni_source, SniSource::Absent);
    }

    #[test]
    fn an_ipv6_destination_is_matched_against_the_ipv6_dns_answer() {
        let mut assembler = assembler();
        let v6: IpAddr = "2606:4700::6810:701".parse().unwrap();
        let resolver = key("10.0.0.53", 53, 40000);
        let flow = FlowKey {
            dst_ip: v6,
            ..key("104.18.7.1", 443, 54321)
        };
        assembler.ingest(KernelEvent::Payload(PayloadEvent {
            key: resolver,
            t_start_bucket: START,
            at_secs: 1,
            facts: PayloadFacts::Dns(DnsAnswers {
                query_name: Some("api.openai.com".to_owned()),
                mappings: vec![DnsMapping {
                    ip: v6,
                    name: "api.openai.com".to_owned(),
                    ttl_secs: 300,
                }],
                truncated_by_server: false,
            }),
        }));
        assembler.ingest(connect(&flow, 2));

        let observation = assembler
            .seal()
            .into_iter()
            .find(|observation| observation.five_tuple.dst_ip == "2606:4700::6810:701")
            .unwrap();
        assert_eq!(observation.resolved_host.as_deref(), Some("api.openai.com"));
    }

    #[test]
    fn a_mapping_that_expired_before_the_connection_does_not_name_it() {
        // A reassigned address keeping its old name would put a destination in
        // the report that the traffic never went to.
        let mut assembler = assembler();
        let resolver = key("10.0.0.53", 53, 40000);
        let flow = key("104.18.7.1", 443, 54321);
        assembler.ingest(dns_answer(&resolver, [104, 18, 7, 1], "api.openai.com", 0));
        assembler.ingest(connect(&flow, 10_000));

        let observation = assembler
            .seal()
            .into_iter()
            .find(|observation| observation.five_tuple.dst_ip == "104.18.7.1")
            .unwrap();
        assert_eq!(observation.resolved_host, None);
        assert!(observation.dns_names.is_empty());
    }
}
