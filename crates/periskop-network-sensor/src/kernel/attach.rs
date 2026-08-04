//! Which programs go on which hooks, decided before anything is loaded.
//!
//! The plan is data, and it is built from the grant rather than from what the
//! loader discovers as it goes. Two reasons.
//!
//! A loader that decided hook by hook could attach the `tc` helper on a machine
//! that never granted `CAP_NET_ADMIN`, and the failure would surface as a
//! permission error deep in a load sequence with a half attached sensor behind
//! it. Here the question is answered once, from the grant the privilege
//! evaluation produced, and a plan that includes `tc` is proof that the
//! capability was checked.
//!
//! And the plan is the place where ADR-008's program list is written down in a
//! form a test can hold. XDP is absent because the ADR rejects it
//! unconditionally: it sits at the driver, sees only ingress, and egress is the
//! entire subject of this sensor. `tc` is present but marked as carrying no
//! process context, which is the ADR's binding limit on its role.

use crate::privilege::Grant;

/// A program this sensor is allowed to attach.
///
/// Closed on purpose. A new hook is an ADR question about what the sensor
/// observes, not a detail a loader may add.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Program {
    /// Outgoing IPv4 connection setup, in the calling task's context.
    KprobeTcpV4Connect,
    /// The IPv6 half of the same hook.
    KprobeTcpV6Connect,
    /// Datagram send, which is how DNS queries and QUIC are seen.
    KprobeUdpSendmsg,
    /// Byte counters, accumulated per call rather than per packet so the CPU
    /// budget holds.
    KprobeTcpSendmsg,
    KprobeTcpRecvmsg,
    /// End of flow: duration and final counts.
    KprobeTcpClose,
    /// The payload helper, outbound. Sees the ClientHello.
    TcClsactEgress,
    /// The payload helper, inbound. Sees DNS answers.
    TcClsactIngress,
}

impl Program {
    /// The symbol or hook point, as an operator would name it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KprobeTcpV4Connect => "kprobe:tcp_v4_connect",
            Self::KprobeTcpV6Connect => "kprobe:tcp_v6_connect",
            Self::KprobeUdpSendmsg => "kprobe:udp_sendmsg",
            Self::KprobeTcpSendmsg => "kprobe:tcp_sendmsg",
            Self::KprobeTcpRecvmsg => "kprobe:tcp_recvmsg",
            Self::KprobeTcpClose => "kprobe:tcp_close",
            Self::TcClsactEgress => "tc:clsact/egress",
            Self::TcClsactIngress => "tc:clsact/ingress",
        }
    }

    /// Whether events from this program may name a process.
    ///
    /// False for both `tc` programs, and that is ADR-008 rather than an
    /// implementation limit: a packet is seen below the socket layer where the
    /// producing task is simply not knowable.
    pub fn carries_process_context(self) -> bool {
        !matches!(self, Self::TcClsactEgress | Self::TcClsactIngress)
    }

    /// Whether this program is what makes a flow attributable at all.
    pub fn is_required(self) -> bool {
        self.carries_process_context()
    }
}

/// The programs one attach will load, in a fixed order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachPlan {
    programs: Vec<Program>,
}

impl AttachPlan {
    pub fn programs(&self) -> &[Program] {
        &self.programs
    }

    /// Whether the payload helper is part of this plan.
    ///
    /// When it is not, the sensor still runs: classification falls back to the
    /// DNS map and the loss of server name resolution is declared per flow as
    /// `tc_unavailable`. A resolution loss, not a correctness loss.
    pub fn includes_payload_helper(&self) -> bool {
        self.programs
            .iter()
            .any(|program| !program.carries_process_context())
    }
}

/// Builds the plan a grant allows.
pub fn plan(grant: &Grant) -> AttachPlan {
    let mut programs = vec![
        Program::KprobeTcpV4Connect,
        Program::KprobeTcpV6Connect,
        Program::KprobeUdpSendmsg,
        Program::KprobeTcpSendmsg,
        Program::KprobeTcpRecvmsg,
        Program::KprobeTcpClose,
    ];
    if grant.tc_available {
        programs.push(Program::TcClsactEgress);
        programs.push(Program::TcClsactIngress);
    }
    AttachPlan { programs }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn granted(tc_available: bool) -> Grant {
        Grant {
            tc_available,
            elevated_as_root: false,
        }
    }

    #[test]
    fn without_net_admin_the_payload_helper_is_not_even_planned() {
        // The failure this prevents: a loader that tries anyway, fails deep in
        // a load sequence, and leaves a partly attached sensor behind.
        let plan = plan(&granted(false));
        assert!(!plan.includes_payload_helper());
        assert!(plan
            .programs()
            .iter()
            .all(|program| program.carries_process_context()));
    }

    #[test]
    fn with_net_admin_the_payload_helper_joins_on_both_directions() {
        // Egress carries the ClientHello, ingress carries the DNS answer.
        // Attaching one without the other would silently halve classification.
        let plan = plan(&granted(true));
        assert!(plan.includes_payload_helper());
        assert!(plan.programs().contains(&Program::TcClsactEgress));
        assert!(plan.programs().contains(&Program::TcClsactIngress));
    }

    #[test]
    fn the_hooks_that_attribute_a_flow_are_planned_whatever_the_grant_says() {
        // Process attribution is what makes this sensor part of periskop rather
        // than a traffic counter. It may never depend on an optional privilege.
        for tc_available in [true, false] {
            let plan = plan(&granted(tc_available));
            let required: Vec<Program> = plan
                .programs()
                .iter()
                .copied()
                .filter(|program| program.is_required())
                .collect();
            assert!(required.contains(&Program::KprobeTcpV4Connect));
            assert!(required.contains(&Program::KprobeTcpV6Connect));
            assert!(required.contains(&Program::KprobeTcpClose));
        }
    }

    #[test]
    fn no_planned_packet_level_program_may_claim_a_process() {
        // ADR-008's binding rule, held as an assertion rather than a comment.
        for program in plan(&granted(true)).programs() {
            let packet_level = program.as_str().starts_with("tc:");
            assert_eq!(
                packet_level,
                !program.carries_process_context(),
                "{program:?} disagrees with the ADR about what tc can know"
            );
        }
    }

    #[test]
    fn the_plan_is_the_same_list_in_the_same_order_every_time() {
        // The order programs load in changes which failure an operator sees
        // first on a machine that cannot host all of them.
        assert_eq!(plan(&granted(true)), plan(&granted(true)));
    }

    #[test]
    fn every_program_has_a_distinct_name_an_operator_can_look_up() {
        let programs = [
            Program::KprobeTcpV4Connect,
            Program::KprobeTcpV6Connect,
            Program::KprobeUdpSendmsg,
            Program::KprobeTcpSendmsg,
            Program::KprobeTcpRecvmsg,
            Program::KprobeTcpClose,
            Program::TcClsactEgress,
            Program::TcClsactIngress,
        ];
        let names: std::collections::BTreeSet<&str> =
            programs.iter().map(|program| program.as_str()).collect();
        assert_eq!(names.len(), programs.len());
        // XDP is rejected unconditionally by ADR-008: it sees ingress only, and
        // egress is the entire subject of this sensor.
        assert!(names.iter().all(|name| !name.contains("xdp")));
    }
}
