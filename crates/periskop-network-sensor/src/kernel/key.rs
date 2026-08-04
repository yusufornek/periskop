//! The key that joins a process to a packet.
//!
//! ADR-008 puts the sensor's hardest correctness problem in one sentence: the
//! hooks that know which process opened a connection cannot see payload, and
//! the hook that can see payload does not know which process produced it. The
//! two are joined on this key, and the ADR fixes what it contains:
//! `(netns, src_ip, src_port, dst_ip, dst_port, proto)`.
//!
//! **The source address lives here and never in a record.** It identifies the
//! machine rather than the connection, and reports in this project have to
//! compare equal across machines. So the join key carries it and
//! [`FlowKey::five_tuple`] is the one way to get from a key to something a
//! record may hold, which drops it.
//!
//! The network namespace is part of the key rather than a label on the side.
//! Two containers on one host reuse ports freely, and a key without the
//! namespace would join one container's handshake to another's process.

use std::net::IpAddr;

use crate::flow::{FiveTuple, Proto};

/// The connection identity a kprobe event and a `tc` event are matched on.
///
/// Ordered rather than hashed, because the assembler keeps flows in ordered
/// maps: a hash map's iteration order would reach the observation list and make
/// two captures of the same traffic serialize differently.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlowKey {
    /// Network namespace inode, absent where the kernel did not supply one.
    pub netns: Option<u64>,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub proto: Proto,
}

impl FlowKey {
    /// The part of the key a record is allowed to carry.
    ///
    /// The source address is dropped here and nowhere else, so there is one
    /// place to check that it never reaches a report.
    pub fn five_tuple(&self) -> FiveTuple {
        FiveTuple {
            src_port: self.src_port,
            dst_ip: self.dst_ip.to_string(),
            dst_port: self.dst_port,
            proto: self.proto,
        }
    }

    /// The namespace as a record spells it: the inode in decimal.
    pub fn netns_label(&self) -> Option<String> {
        self.netns.map(|inode| inode.to_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn key(dst_ip: &str, dst_port: u16, src_port: u16) -> FlowKey {
        FlowKey {
            netns: Some(4_026_531_840),
            src_ip: "10.1.2.3".parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
            src_port,
            dst_ip: dst_ip.parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
            dst_port,
            proto: Proto::Tcp,
        }
    }

    #[test]
    fn the_source_address_does_not_survive_into_a_record() {
        // The invariant that keeps a report comparable across machines. If this
        // ever fails, every report starts carrying the host's own addressing.
        let five_tuple = key("104.18.7.1", 443, 54321).five_tuple();
        let encoded = format!("{five_tuple:?}");
        assert!(
            !encoded.contains("10.1.2.3"),
            "the source address reached a record: {encoded}"
        );
        assert_eq!(five_tuple.dst_ip, "104.18.7.1");
        assert_eq!(five_tuple.src_port, 54321);
    }

    #[test]
    fn two_namespaces_reusing_one_port_pair_are_different_flows() {
        // Containers reuse ports freely. A key that ignored the namespace would
        // join one container's handshake onto another container's process.
        let host = key("104.18.7.1", 443, 54321);
        let container = FlowKey {
            netns: Some(4_026_532_001),
            ..host.clone()
        };
        assert_ne!(host, container);
    }

    #[test]
    fn the_same_ports_over_different_protocols_are_different_flows() {
        // QUIC and TCP to one destination from one port is an ordinary shape
        // for a browser, and merging them would double count volume.
        let tcp = key("104.18.7.1", 443, 54321);
        let udp = FlowKey {
            proto: Proto::Udp,
            ..tcp.clone()
        };
        assert_ne!(tcp, udp);
    }

    #[test]
    fn a_namespace_reaches_the_record_as_the_inode_a_reader_can_look_up() {
        assert_eq!(
            key("104.18.7.1", 443, 54321).netns_label().as_deref(),
            Some("4026531840")
        );
        let unnamed = FlowKey {
            netns: None,
            ..key("104.18.7.1", 443, 54321)
        };
        assert_eq!(unnamed.netns_label(), None);
    }

    #[test]
    fn an_ipv6_destination_is_written_the_way_the_address_type_spells_it() {
        // Both sides of the join format addresses through the same type, so a
        // DNS answer and a connection agree on how one address is written.
        let six = FlowKey {
            dst_ip: "2606:4700::6810:701".parse().unwrap(),
            ..key("104.18.7.1", 443, 54321)
        };
        assert_eq!(six.five_tuple().dst_ip, "2606:4700::6810:701");
    }
}
