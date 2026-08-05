//! The compiled kernel object, and the table that says what goes where.
//!
//! The bytes come from `crates/periskop-ebpf-object/`, built for
//! `bpfel-unknown-none` on its own pinned nightly with `bpf-linker`, and
//! embedded here by `build.rs` when `PERISKOP_EBPF_OBJECT` names one. Embedded
//! rather than read from disk at run time, because ADR-002 fixes a single static
//! binary: a loader that went looking for a file beside itself would be a second
//! artefact to ship and a path an attacker could aim somewhere else.
//!
//! # The table below is the whole of what this crate decides
//!
//! Which program attaches to which kernel function, and nothing else. The names
//! on the left are symbols in the object; the names on the right are kernel
//! functions ADR-008 fixed. A hook with no row is a hook this object carries no
//! program for, and the loader refuses the whole plan rather than attaching the
//! rest, so a sensor never runs believing it sees something it does not.
//!
//! **The two traffic control hooks have no rows.** This object carries no
//! `clsact` classifier, so DNS answers and TLS server names are not observed by
//! a build using it, and the gate artefact says so in as many words. ADR-008
//! still fixes `tc` as the mechanism for them; what is missing is the program,
//! not the decision.

use crate::hook::Hook;

/// The object `build.rs` found.
#[cfg(all(target_os = "linux", periskop_kernel_object))]
pub const BYTES: &[u8] = include_bytes!(env!("PERISKOP_EBPF_OBJECT_PATH"));

/// One program at one kernel function.
///
/// The table is compiled on every platform on purpose, which is the same reason
/// ADR-014 §6.4 gave for keeping this crate in the workspace: a table that only
/// existed on the machine that can build the object would drift there unseen,
/// and the tests below are what keep it honest. Only the Linux build with an
/// object reads these two fields, so only that build can call it live code.
#[cfg_attr(
    not(all(target_os = "linux", periskop_kernel_object)),
    allow(
        dead_code,
        reason = "read by attached.rs, which only that build compiles"
    )
)]
pub struct Attachment {
    /// The symbol in the object.
    pub program: &'static str,
    /// The kernel function it is attached to, spelled the way ADR-008 spells it.
    pub function: &'static str,
}

const fn at(program: &'static str, function: &'static str) -> Attachment {
    Attachment { program, function }
}

/// Connection setup is an entry and a return probe on one function.
///
/// The entry probe stashes the socket and the return probe writes the record,
/// because at entry the kernel has not yet filled in the addresses or assigned
/// the source port: a record written there would carry a key no later event
/// could be joined to.
const V4_CONNECT: [Attachment; 2] = [
    at("periskop_connect_entry", "tcp_v4_connect"),
    at("periskop_connect_return", "tcp_v4_connect"),
];

/// The same two programs at the IPv6 entry point.
///
/// They report nothing for an `AF_INET6` socket, by design and not by omission:
/// the object reads only the leading, configuration independent prefix of
/// `struct sock`, and an IPv6 address is not in it. Attaching anyway is what
/// makes an IPv4 connection that took this path visible.
const V6_CONNECT: [Attachment; 2] = [
    at("periskop_connect_entry", "tcp_v6_connect"),
    at("periskop_connect_return", "tcp_v6_connect"),
];

const UDP_SENDMSG: [Attachment; 1] = [at("periskop_udp_sendmsg", "udp_sendmsg")];
const TCP_SENDMSG: [Attachment; 1] = [at("periskop_tcp_sendmsg", "tcp_sendmsg")];

/// Inbound volume is an entry and a return probe for the same reason as the
/// connect pair, and a different one: the third argument of `tcp_recvmsg` is the
/// size of the buffer the caller offered, so counting it would report whatever
/// the caller asked for rather than what arrived.
const TCP_RECVMSG: [Attachment; 2] = [
    at("periskop_tcp_recvmsg_entry", "tcp_recvmsg"),
    at("periskop_tcp_recvmsg_return", "tcp_recvmsg"),
];

const TCP_CLOSE: [Attachment; 1] = [at("periskop_tcp_close", "tcp_close")];

/// What this object attaches for a hook, empty when it carries no program.
pub fn attachments_for(hook: Hook) -> &'static [Attachment] {
    match hook {
        Hook::KprobeTcpV4Connect => &V4_CONNECT,
        Hook::KprobeTcpV6Connect => &V6_CONNECT,
        Hook::KprobeUdpSendmsg => &UDP_SENDMSG,
        Hook::KprobeTcpSendmsg => &TCP_SENDMSG,
        Hook::KprobeTcpRecvmsg => &TCP_RECVMSG,
        Hook::KprobeTcpClose => &TCP_CLOSE,
        // No `clsact` classifier in this object.
        Hook::TrafficControlEgress | Hook::TrafficControlIngress => &[],
    }
}

/// Whether this object can serve a hook at all.
///
/// Asked before anything is loaded, so a plan naming a hook with no program is
/// refused before a single program reaches the kernel rather than halfway
/// through the sequence with some already attached.
pub fn carries(hook: Hook) -> bool {
    !attachments_for(hook).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn every_attachment_names_the_kernel_function_its_hook_names() {
        // The hook's attach point is what an operator reads and what the sensor
        // spells; the function here is what the kernel is asked for. Two names
        // for one thing drift, so the agreement is asserted: a table entry that
        // pointed at `tcp_connect` while the hook said `tcp_v4_connect` would
        // attach to the wrong function and report a different set of
        // connections without anything looking wrong.
        for hook in EVERY_HOOK {
            let expected = hook.attach_point().trim_start_matches("kprobe:");
            for attachment in attachments_for(hook) {
                assert_eq!(
                    attachment.function, expected,
                    "{hook:?} attaches a program somewhere its own name does not point"
                );
            }
        }
    }

    #[test]
    fn no_traffic_control_hook_has_a_program_in_this_object() {
        // The absence this build declares. If a classifier is ever added, this
        // test goes red and whoever added it has to say so in the gate artefact
        // as well, which is the point.
        assert!(!carries(Hook::TrafficControlEgress));
        assert!(!carries(Hook::TrafficControlIngress));
    }

    #[test]
    fn every_hook_that_attributes_a_flow_has_a_program() {
        // The triple the F4 exit criterion asks for is destination, volume and
        // time, and all three come from these six. A hook that quietly lost its
        // row would take one of the three with it.
        for hook in EVERY_HOOK {
            if hook.needs_traffic_control() {
                continue;
            }
            assert!(carries(hook), "{hook:?} has no program in this object");
        }
    }

    #[test]
    fn a_connection_is_observed_by_an_entry_and_a_return_probe() {
        // The pairing is what makes the connect record's key equal to the key
        // every later event on that connection carries. A single entry probe
        // would produce a record the assembler could never join volume to, and
        // every flow would report zero bytes.
        for hook in [Hook::KprobeTcpV4Connect, Hook::KprobeTcpV6Connect] {
            assert_eq!(attachments_for(hook).len(), 2);
        }
        assert_eq!(attachments_for(Hook::KprobeTcpRecvmsg).len(), 2);
    }
}
