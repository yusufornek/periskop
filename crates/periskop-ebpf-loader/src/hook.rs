//! The hooks a caller is allowed to ask this loader for.
//!
//! A closed enum rather than a symbol name. A loader that accepted an arbitrary
//! string could be pointed at any kernel function by anything that can reach its
//! configuration, and "which hooks does periskop attach" would stop being an
//! answerable question. The set is fixed by ADR-008, so it is fixed here, and
//! adding to it is an architecture decision about what the sensor observes
//! rather than a line a loader may add.
//!
//! The same list exists as `Program` in `periskop-network-sensor`. The two are
//! separate types because the crates cannot depend on each other in both
//! directions, and the translation between them is an exhaustive match on the
//! sensor's side: adding a program there stops compiling until somebody says
//! what this loader should do with it. The attach point strings are the shared
//! vocabulary, and the sensor holds a test that the two spell them identically.
//!
//! XDP is absent, and unconditionally so: ADR-008 rejects it because it sits at
//! the driver, sees ingress only, and egress is the entire subject of this
//! sensor.

/// A hook this loader may attach a program to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Hook {
    /// Outgoing IPv4 connection setup, in the calling task's context.
    KprobeTcpV4Connect,
    /// The IPv6 half of the same hook.
    KprobeTcpV6Connect,
    /// Datagram send, which is how DNS queries and QUIC are seen.
    KprobeUdpSendmsg,
    /// Byte counters, accumulated per call rather than per packet.
    KprobeTcpSendmsg,
    KprobeTcpRecvmsg,
    /// End of flow: duration and final counts.
    KprobeTcpClose,
    /// The payload helper, outbound. Sees the ClientHello.
    TrafficControlEgress,
    /// The payload helper, inbound. Sees DNS answers.
    TrafficControlIngress,
}

impl Hook {
    /// The kernel symbol or qdisc hook, spelled the way an operator would look
    /// it up and the way `periskop-network-sensor` spells the same thing.
    pub fn attach_point(self) -> &'static str {
        match self {
            Self::KprobeTcpV4Connect => "kprobe:tcp_v4_connect",
            Self::KprobeTcpV6Connect => "kprobe:tcp_v6_connect",
            Self::KprobeUdpSendmsg => "kprobe:udp_sendmsg",
            Self::KprobeTcpSendmsg => "kprobe:tcp_sendmsg",
            Self::KprobeTcpRecvmsg => "kprobe:tcp_recvmsg",
            Self::KprobeTcpClose => "kprobe:tcp_close",
            Self::TrafficControlEgress => "tc:clsact/egress",
            Self::TrafficControlIngress => "tc:clsact/ingress",
        }
    }

    /// Whether attaching this hook needs `CAP_NET_ADMIN`.
    ///
    /// True only for the two `clsact` programs. The loader refuses a request
    /// that includes one of them without the capability rather than attaching
    /// what it can and failing partway, which would leave programs in the kernel
    /// that nothing is reading.
    pub fn needs_traffic_control(self) -> bool {
        matches!(
            self,
            Self::TrafficControlEgress | Self::TrafficControlIngress
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every hook this loader knows, so a test cannot cover a subset by
    /// accident.
    const EVERY_HOOK: [Hook; 8] = [
        Hook::KprobeTcpV4Connect,
        Hook::KprobeTcpV6Connect,
        Hook::KprobeUdpSendmsg,
        Hook::KprobeTcpSendmsg,
        Hook::KprobeTcpRecvmsg,
        Hook::KprobeTcpClose,
        Hook::TrafficControlEgress,
        Hook::TrafficControlIngress,
    ];

    #[test]
    fn every_hook_names_a_distinct_attach_point() {
        // Two hooks resolving to one attach point would mean a plan of eight
        // programs quietly loading seven, and the missing one would only show
        // up as a gap in what the report saw.
        let points: std::collections::BTreeSet<&str> =
            EVERY_HOOK.iter().map(|hook| hook.attach_point()).collect();
        assert_eq!(points.len(), EVERY_HOOK.len());
    }

    #[test]
    fn only_the_packet_level_hooks_need_net_admin() {
        // ADR-008's rule, held as an assertion. If a kprobe ever started
        // requiring `CAP_NET_ADMIN`, process attribution would become dependent
        // on an optional privilege and the sensor would stop being able to
        // attribute a flow on a machine that granted the minimum.
        for hook in EVERY_HOOK {
            assert_eq!(
                hook.needs_traffic_control(),
                hook.attach_point().starts_with("tc:"),
                "{hook:?} disagrees with ADR-008 about what needs CAP_NET_ADMIN"
            );
        }
    }

    #[test]
    fn no_hook_is_an_xdp_hook() {
        // ADR-008 rejects XDP unconditionally: it sees ingress only, and this
        // sensor exists to see egress.
        assert!(EVERY_HOOK
            .iter()
            .all(|hook| !hook.attach_point().contains("xdp")));
    }

    #[test]
    fn the_hooks_that_attribute_a_flow_never_need_the_optional_capability() {
        // Connection setup and teardown are what make a flow attributable at
        // all. If either needed `CAP_NET_ADMIN`, a machine granting only the
        // minimum would produce flows with no process on them.
        for hook in [
            Hook::KprobeTcpV4Connect,
            Hook::KprobeTcpV6Connect,
            Hook::KprobeTcpClose,
        ] {
            assert!(!hook.needs_traffic_control());
        }
    }
}
