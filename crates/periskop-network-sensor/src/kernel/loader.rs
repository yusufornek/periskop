//! The seam: the one place a kernel object would be opened, and the translation
//! either side of it.
//!
//! Loading an eBPF program is a `bpf(2)` call, a set of file descriptors and a
//! memory mapped ring buffer. In Rust that is a foreign function boundary, and a
//! foreign function boundary is where the workspace's `unsafe_code = "forbid"`
//! (ADR-002) has to be lifted. `forbid` is not a level a crate can lift with an
//! `allow`; it can only be lifted where the lint is configured. ADR-002
//! anticipated this and named the eBPF loader as one of three crates allowed the
//! exception, but did not say through which mechanism.
//!
//! ADR-014 answers that: the exception is granted to a **separate crate behind a
//! non default feature**, never to this one. This module is the seam that
//! decision produces, and it stays on the sensor's side of it for a reason worth
//! stating, because it is a departure from ADR-014 §5's letter. That clause
//! expects the loader crate to be the thing that implements `KernelEvents`. It
//! cannot: the trait, the event types and the parsers all live here, so a loader
//! crate implementing the trait would have to depend on this crate while this
//! crate depends on it, which cargo will not build. So the trait implementation
//! lives here and the loader crate holds only the transport and the gate. The
//! clause's purpose is untouched: nothing that decides what a report says has
//! moved to the untestable side.
//!
//! # What crosses the seam, in each direction
//!
//! Down: an attach plan, translated into the loader's own closed hook list, and
//! the capabilities this process holds at the moment of the call. The loader is
//! told both rather than working either out, so it cannot attach a program the
//! privilege evaluation refused.
//!
//! Up: raw records. They are turned into [`KernelEvent`]s here, and for a `tc`
//! payload record that means running [`crate::parse`] on the sample. That parse
//! is on this side deliberately (ADR-014 §3): what a DNS answer or a handshake
//! *means* is a decision about what the report says, and every one of those
//! belongs where it runs in continuous integration. The sample itself dies at
//! that call and nothing downstream can hold a packet.
//!
//! # With the feature off, which is the default
//!
//! An attach on Linux reports `loader_not_built` and off Linux
//! `unsupported_platform`. Both are stated causes with distinct remedies,
//! spelled in the same vocabulary a permission failure uses, so a report cannot
//! present "nothing was observed because nothing was loaded" as a clean network.

use super::attach::AttachPlan;
use super::event::KernelBatch;
use super::KernelEvents;
use crate::privilege::SensorUnavailable;

#[cfg(feature = "ebpf-loader")]
use std::collections::BTreeMap;

#[cfg(feature = "ebpf-loader")]
use periskop_ebpf_loader as ebpf;

#[cfg(feature = "ebpf-loader")]
use super::attach::Program;
#[cfg(feature = "ebpf-loader")]
use super::event::{
    CloseEvent, ConnectEvent, KernelEvent, KernelProcess, PayloadEvent, PayloadFacts, VolumeEvent,
};
#[cfg(feature = "ebpf-loader")]
use super::key::FlowKey;
#[cfg(feature = "ebpf-loader")]
use crate::flow::Proto;
#[cfg(feature = "ebpf-loader")]
use crate::privilege::Privileges;

/// The kernel side of the sensor on the machine this build runs on.
///
/// Not `Copy`, because with the loader compiled in it accumulates a tally, and
/// a copy of a counter is a counter that stops counting.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PlatformKernel {
    #[cfg(feature = "ebpf-loader")]
    loader: ebpf::EbpfLoader,
    /// Payload samples the parsers refused, counted by cause.
    ///
    /// **This does not reach the coverage statement yet, and that is a stated
    /// gap rather than an oversight.** `SourceCoverage` and the coverage
    /// statement schema have no field for samples a parser rejected; the
    /// `DnsParseError` documentation says these are meant to be counted in one,
    /// so the field is missing rather than unwanted. Changing a contract is the
    /// integrator's decision, so the request is filed in
    /// `hub/memory/interfaces.md` and this build keeps the count where a test
    /// can see it instead of dropping it. Bounded by the number of distinct
    /// causes, which is nine, so it cannot grow with traffic.
    #[cfg(feature = "ebpf-loader")]
    rejected_samples: BTreeMap<&'static str, u64>,
    /// Whether a load has succeeded on this kernel.
    ///
    /// Held here rather than asked of the loader, because the question a poll
    /// has to answer is "was anything attached when I read", and the only party
    /// that saw the load return is this one. `false` until a load succeeds, so a
    /// caller that ignored an attach failure reads a batch that says nothing was
    /// attached instead of one that looks like a quiet machine.
    #[cfg(feature = "ebpf-loader")]
    attached: bool,
}

#[cfg(feature = "ebpf-loader")]
impl PlatformKernel {
    /// Payload samples the parsers refused since this kernel was created, by
    /// cause.
    pub fn rejected_samples(&self) -> &BTreeMap<&'static str, u64> {
        &self.rejected_samples
    }
}

#[cfg(not(feature = "ebpf-loader"))]
impl KernelEvents for PlatformKernel {
    fn attach(&mut self, _plan: &AttachPlan) -> Result<(), SensorUnavailable> {
        if cfg!(target_os = "linux") {
            Err(SensorUnavailable::LoaderNotBuilt)
        } else {
            Err(SensorUnavailable::UnsupportedPlatform)
        }
    }

    fn poll(&mut self) -> KernelBatch {
        // Reachable only if a caller ignored the attach failure, and the batch
        // says so rather than handing back a plausible looking empty result.
        // `KernelBatch::default()` carries `PollState::NotAttached`, which is
        // the difference between "nothing was attached, so nothing could have
        // been seen" and "the machine was quiet". Before that state existed this
        // return value was indistinguishable from a clean network.
        KernelBatch::default()
    }
}

#[cfg(feature = "ebpf-loader")]
impl KernelEvents for PlatformKernel {
    fn attach(&mut self, plan: &AttachPlan) -> Result<(), SensorUnavailable> {
        let hooks: Vec<ebpf::Hook> = plan.programs().iter().copied().map(hook_for).collect();
        // Probed here rather than taken from the earlier privilege evaluation.
        // Between that evaluation and this call the process may have dropped
        // capabilities or been re-executed, and the check that decides whether a
        // syscall will succeed is the one immediately before it.
        let capabilities = capabilities_from(&Privileges::probe());
        let loaded = self
            .loader
            .load(ebpf::HostPlatform::current(), &capabilities, &hooks)
            .map_err(cause_from);
        // Recorded only on success. A failed load leaves the flag false, so a
        // caller that dropped the error still reads batches that say nothing was
        // attached.
        self.attached = loaded.is_ok();
        loaded
    }

    fn poll(&mut self) -> KernelBatch {
        if !self.attached {
            return KernelBatch::default();
        }
        let batch = self.loader.poll();
        let mut events = Vec::with_capacity(batch.events.len());
        for raw in batch.events {
            match kernel_event_from(raw) {
                Ok(event) => events.push(event),
                Err(rejected) => {
                    // Counted, not dropped. A sample the parsers cannot read is
                    // a measured blind spot: the connection was seen, its
                    // destination was not resolved, and a run that lost a
                    // thousand of them must not look like a run that lost none.
                    *self.rejected_samples.entry(rejected).or_insert(0) += 1;
                }
            }
        }
        KernelBatch {
            state: super::event::PollState::Attached,
            events,
            dropped: batch.dropped,
        }
    }
}

/// The loader's cause, in the sensor's vocabulary.
///
/// Exhaustive on purpose: a fifth cause appearing in the loader stops this
/// compiling until somebody decides what a report should say about it, rather
/// than being folded into whichever existing label is nearest.
#[cfg(feature = "ebpf-loader")]
fn cause_from(cause: ebpf::LoaderUnavailable) -> SensorUnavailable {
    match cause {
        ebpf::LoaderUnavailable::UnsupportedPlatform => SensorUnavailable::UnsupportedPlatform,
        ebpf::LoaderUnavailable::MissingCapability => SensorUnavailable::MissingCapability,
        ebpf::LoaderUnavailable::KernelUnsupported => SensorUnavailable::KernelUnsupported,
        ebpf::LoaderUnavailable::LoaderNotBuilt => SensorUnavailable::LoaderNotBuilt,
    }
}

/// The planned program, as a hook the loader will accept.
///
/// Exhaustive for the same reason: a new program in the sensor's plan cannot
/// reach a loader that has no hook for it, and the compiler is what says so.
#[cfg(feature = "ebpf-loader")]
fn hook_for(program: Program) -> ebpf::Hook {
    match program {
        Program::KprobeTcpV4Connect => ebpf::Hook::KprobeTcpV4Connect,
        Program::KprobeTcpV6Connect => ebpf::Hook::KprobeTcpV6Connect,
        Program::KprobeUdpSendmsg => ebpf::Hook::KprobeUdpSendmsg,
        Program::KprobeTcpSendmsg => ebpf::Hook::KprobeTcpSendmsg,
        Program::KprobeTcpRecvmsg => ebpf::Hook::KprobeTcpRecvmsg,
        Program::KprobeTcpClose => ebpf::Hook::KprobeTcpClose,
        Program::TcClsactEgress => ebpf::Hook::TrafficControlEgress,
        Program::TcClsactIngress => ebpf::Hook::TrafficControlIngress,
    }
}

/// What this process holds, in the shape the loader checks.
#[cfg(feature = "ebpf-loader")]
fn capabilities_from(privileges: &Privileges) -> ebpf::Capabilities {
    ebpf::Capabilities {
        cap_bpf: privileges.cap_bpf,
        cap_perfmon: privileges.cap_perfmon,
        cap_net_admin: privileges.cap_net_admin,
        root: privileges.is_root(),
        btf_available: privileges.btf_available,
    }
}

#[cfg(feature = "ebpf-loader")]
fn flow_key_from(key: ebpf::RawKey) -> FlowKey {
    FlowKey {
        netns: key.netns,
        src_ip: key.src_ip,
        src_port: key.src_port,
        dst_ip: key.dst_ip,
        dst_port: key.dst_port,
        proto: match key.protocol {
            ebpf::Protocol::Tcp => Proto::Tcp,
            ebpf::Protocol::Udp => Proto::Udp,
        },
    }
}

/// One raw record, as the event the assembler understands.
///
/// The error is the fixed label of the parse that refused, which is the same
/// vocabulary the parsers already publish for a coverage statement to count.
#[cfg(feature = "ebpf-loader")]
fn kernel_event_from(raw: ebpf::RawEvent) -> Result<KernelEvent, &'static str> {
    Ok(match raw {
        ebpf::RawEvent::Connect {
            key,
            t_start_bucket,
            at_secs,
            process,
            pre_existing,
        } => KernelEvent::Connect(ConnectEvent {
            key: flow_key_from(key),
            t_start_bucket,
            at_secs,
            process: KernelProcess {
                pid: process.pid,
                pid_start_time: process.pid_start_time,
                comm: process.comm,
            },
            pre_existing,
        }),
        ebpf::RawEvent::Volume {
            key,
            bytes_out,
            bytes_in,
            segments_out,
        } => KernelEvent::Volume(VolumeEvent {
            key: flow_key_from(key),
            bytes_out,
            bytes_in,
            segments_out,
        }),
        ebpf::RawEvent::Close { key, duration_ms } => KernelEvent::Close(CloseEvent {
            key: flow_key_from(key),
            duration_ms,
        }),
        ebpf::RawEvent::Payload {
            key,
            t_start_bucket,
            at_secs,
            kind,
            sample,
        } => KernelEvent::Payload(PayloadEvent {
            key: flow_key_from(key),
            t_start_bucket,
            at_secs,
            facts: facts_from(kind, &sample)?,
        }),
    })
}

/// The two parses the `tc` helper's samples are put through.
///
/// This is the only call in the sensor that turns bytes into meaning, and it is
/// on the tested side of the seam on purpose. The bytes do not survive it.
#[cfg(feature = "ebpf-loader")]
fn facts_from(kind: ebpf::PayloadKind, sample: &[u8]) -> Result<PayloadFacts, &'static str> {
    match kind {
        ebpf::PayloadKind::DnsResponse => crate::parse::dns::parse_response(sample)
            .map(PayloadFacts::Dns)
            .map_err(|error| error.as_str()),
        ebpf::PayloadKind::TlsClientHello => crate::parse::tls::parse_client_hello(sample)
            .map(PayloadFacts::Handshake)
            .map_err(|error| error.as_str()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::kernel::attach;
    use crate::privilege::Grant;

    fn plan() -> AttachPlan {
        attach::plan(&Grant {
            tc_available: true,
            elevated_as_root: false,
        })
    }

    #[test]
    fn the_shipped_loader_refuses_in_a_vocabulary_a_report_can_carry() {
        // Runs on whatever machine this is, with or without the loader compiled
        // in. The point is that there is always a stated cause, never an attach
        // that quietly succeeds having loaded nothing.
        let refusal = PlatformKernel::default().attach(&plan()).unwrap_err();
        assert!(!refusal.as_str().is_empty());
        assert!(matches!(
            refusal,
            SensorUnavailable::LoaderNotBuilt
                | SensorUnavailable::UnsupportedPlatform
                | SensorUnavailable::MissingCapability
                | SensorUnavailable::KernelUnsupported
        ));
    }

    #[test]
    fn off_linux_the_cause_is_the_platform_and_not_a_missing_build() {
        // The two remedies are different: one is "build the loader", the other
        // is "there is nothing to build for this machine in v1". An operator
        // sent to the wrong one wastes the time the report was meant to save.
        if cfg!(target_os = "linux") {
            return;
        }
        assert_eq!(
            PlatformKernel::default().attach(&plan()),
            Err(SensorUnavailable::UnsupportedPlatform)
        );
    }

    #[test]
    fn a_kernel_that_never_attached_says_so_rather_than_reporting_a_quiet_machine() {
        // Critic round k3. The empty event list was the whole of what this read
        // used to say, and it is the same empty list a fully attached sensor
        // hands back on a machine that sent nothing. The state is what separates
        // "no programs are loaded" from "the network was silent"; without it a
        // caller that ignored the attach error would report the second.
        let batch = PlatformKernel::default().poll();
        assert!(batch.events.is_empty());
        assert_eq!(batch.dropped, 0);
        assert!(
            !batch.observed(),
            "an unattached kernel handed back a batch that reads as a measurement"
        );
    }
}

#[cfg(all(test, feature = "ebpf-loader"))]
#[allow(clippy::unwrap_used, clippy::panic)]
mod loader_backed_tests {
    use super::*;
    use crate::kernel::attach;
    use crate::privilege::Grant;
    use std::net::IpAddr;

    fn raw_key() -> ebpf::RawKey {
        ebpf::RawKey {
            netns: Some(4_026_531_840),
            src_ip: "10.1.2.3".parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
            src_port: 54_321,
            dst_ip: "104.18.7.1".parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
            dst_port: 443,
            protocol: ebpf::Protocol::Tcp,
        }
    }

    #[test]
    fn the_two_crates_spell_every_unavailability_the_same_way() {
        // The loader restates the sensor's vocabulary because a dependency in
        // both directions is not buildable. Restated means it can drift, so the
        // agreement is asserted rather than assumed: a fleet wide count of
        // `missing_capability` has to mean one thing.
        let pairs = [
            (
                ebpf::LoaderUnavailable::UnsupportedPlatform,
                SensorUnavailable::UnsupportedPlatform,
            ),
            (
                ebpf::LoaderUnavailable::MissingCapability,
                SensorUnavailable::MissingCapability,
            ),
            (
                ebpf::LoaderUnavailable::KernelUnsupported,
                SensorUnavailable::KernelUnsupported,
            ),
            (
                ebpf::LoaderUnavailable::LoaderNotBuilt,
                SensorUnavailable::LoaderNotBuilt,
            ),
        ];
        for (loader_cause, sensor_cause) in pairs {
            assert_eq!(cause_from(loader_cause), sensor_cause);
            assert_eq!(loader_cause.as_str(), sensor_cause.as_str());
        }
    }

    #[test]
    fn the_two_crates_name_the_same_kernel_objects() {
        // The plan is written in this crate's vocabulary and executed in the
        // loader's. If the two ever named different hooks, the sensor would
        // believe it had attached something it had not, and the shortfall would
        // only show up as traffic nobody saw.
        for program in attach::plan(&Grant {
            tc_available: true,
            elevated_as_root: false,
        })
        .programs()
        {
            assert_eq!(program.as_str(), hook_for(*program).attach_point());
        }
    }

    #[test]
    fn a_program_that_needs_no_process_context_maps_onto_a_hook_that_needs_net_admin() {
        // ADR-008 ties the two together: the packet level programs are exactly
        // the ones that see no task and exactly the ones that need
        // `CAP_NET_ADMIN`. A mapping that broke the pairing would let the sensor
        // plan a helper the loader would then refuse.
        for program in [Program::TcClsactEgress, Program::TcClsactIngress] {
            assert!(!program.carries_process_context());
            assert!(hook_for(program).needs_traffic_control());
        }
        for program in [Program::KprobeTcpV4Connect, Program::KprobeTcpClose] {
            assert!(program.carries_process_context());
            assert!(!hook_for(program).needs_traffic_control());
        }
    }

    #[test]
    fn the_loader_is_handed_the_privileges_this_process_actually_holds() {
        let privileges = Privileges {
            effective_uid: Some(0),
            cap_bpf: true,
            cap_perfmon: false,
            cap_net_admin: true,
            btf_available: true,
        };
        let capabilities = capabilities_from(&privileges);
        assert!(capabilities.root);
        assert!(capabilities.cap_bpf);
        assert!(!capabilities.cap_perfmon);
        assert!(capabilities.cap_net_admin);
        assert!(capabilities.btf_available);
        // Root without the pair still loads, which is the supported and
        // discouraged path.
        assert!(capabilities.may_load_programs());
    }

    #[test]
    fn an_unprivileged_process_is_never_translated_into_a_permitted_one() {
        let capabilities = capabilities_from(&Privileges::default());
        assert!(!capabilities.may_load_programs());
        assert!(!capabilities.may_attach_traffic_control());
    }

    #[test]
    fn a_raw_connect_record_becomes_an_attributed_kernel_event() {
        let event = kernel_event_from(ebpf::RawEvent::Connect {
            key: raw_key(),
            t_start_bucket: 1_785_834_000,
            at_secs: 7,
            process: ebpf::RawProcess {
                pid: 4_821,
                pid_start_time: Some(1_785_833_900),
                comm: Some("python3".to_owned()),
            },
            pre_existing: true,
        })
        .unwrap();
        let KernelEvent::Connect(connect) = event else {
            panic!("a connect record converted into something else");
        };
        assert_eq!(connect.process.pid, 4_821);
        assert_eq!(connect.process.comm.as_deref(), Some("python3"));
        assert_eq!(connect.key.dst_port, 443);
        assert_eq!(connect.key.netns, Some(4_026_531_840));
        assert_eq!(connect.key.proto, Proto::Tcp);
        assert!(connect.pre_existing);
    }

    #[test]
    fn the_source_address_crosses_the_seam_on_the_key_and_stops_there() {
        // The key needs it to join a packet onto a process. A record must not
        // carry it, or every report starts carrying the host's own addressing
        // and two machines observing the same destination stop comparing equal.
        let key = flow_key_from(raw_key());
        assert_eq!(key.src_ip.to_string(), "10.1.2.3");
        let five_tuple = format!("{:?}", key.five_tuple());
        assert!(
            !five_tuple.contains("10.1.2.3"),
            "the source address reached a record: {five_tuple}"
        );
    }

    #[test]
    fn a_raw_volume_and_close_record_keep_their_counts_and_their_absences() {
        let volume = kernel_event_from(ebpf::RawEvent::Volume {
            key: raw_key(),
            bytes_out: 8_192,
            bytes_in: 1_024,
            segments_out: 6,
        })
        .unwrap();
        assert!(matches!(
            volume,
            KernelEvent::Volume(VolumeEvent {
                bytes_out: 8_192,
                ..
            })
        ));

        let unmeasured = kernel_event_from(ebpf::RawEvent::Close {
            key: raw_key(),
            duration_ms: None,
        })
        .unwrap();
        assert!(matches!(
            unmeasured,
            KernelEvent::Close(CloseEvent {
                duration_ms: None,
                ..
            })
        ));
    }

    #[test]
    fn a_udp_record_stays_udp_across_the_seam() {
        // QUIC and TCP to one destination from one port is an ordinary browser
        // shape, and collapsing the two would double count volume.
        let key = ebpf::RawKey {
            protocol: ebpf::Protocol::Udp,
            ..raw_key()
        };
        assert_eq!(flow_key_from(key).proto, Proto::Udp);
    }

    /// One answer, `api` at 104.18.7.1, as a resolver would write it.
    fn dns_response() -> Vec<u8> {
        vec![
            0x00, 0x01, // transaction id
            0x81, 0x80, // response, recursion desired and available
            0x00, 0x01, // one question
            0x00, 0x01, // one answer
            0x00, 0x00, 0x00, 0x00, // no authority, no additional
            0x03, b'a', b'p', b'i', 0x00, // question name
            0x00, 0x01, 0x00, 0x01, // A, IN
            0xc0, 0x0c, // answer owner, pointing back at the question name
            0x00, 0x01, 0x00, 0x01, // A, IN
            0x00, 0x00, 0x00, 0x3c, // sixty second time to live
            0x00, 0x04, // four bytes of address
            104, 18, 7, 1,
        ]
    }

    #[test]
    fn a_payload_sample_becomes_facts_and_the_bytes_do_not_travel_with_it() {
        // The one call in the sensor that turns bytes into meaning, and the
        // reason it is on this side of the seam: what a DNS answer means is a
        // decision about what the report says, so it runs where continuous
        // integration can see it. What comes out carries no sample, which is
        // what stops a packet reaching a record even by mistake.
        let sample = dns_response();
        let event = kernel_event_from(ebpf::RawEvent::Payload {
            key: raw_key(),
            t_start_bucket: 1_785_834_000,
            at_secs: 3,
            kind: ebpf::PayloadKind::DnsResponse,
            sample: sample.clone(),
        })
        .unwrap();
        let KernelEvent::Payload(payload) = event else {
            panic!("a payload record converted into something else");
        };
        let PayloadFacts::Dns(answers) = &payload.facts else {
            panic!("a DNS sample was parsed as a handshake");
        };
        assert_eq!(answers.query_name.as_deref(), Some("api"));
        assert_eq!(answers.mappings.len(), 1);
        assert_eq!(answers.mappings[0].ip.to_string(), "104.18.7.1");
        assert_eq!(answers.mappings[0].ttl_secs, 60);
        assert_eq!(payload.at_secs, 3);

        // The sample itself has to be gone. Its distinguishing bytes are the
        // wire form of the address, which the facts hold as an address rather
        // than as the packet it arrived in.
        let printed = format!("{payload:?}");
        assert!(
            !printed.contains("104, 18, 7, 1"),
            "a packet survived the parse: {printed}"
        );
    }

    #[test]
    fn a_handshake_sample_is_put_through_the_other_parser() {
        // Which parse to run is the `tc` program's decision, made from the port
        // and direction it saw. Running the wrong one would turn every
        // handshake into a DNS refusal and lose SNI without saying so.
        let refusal = facts_from(ebpf::PayloadKind::TlsClientHello, &dns_response()).unwrap_err();
        assert!(
            refusal.starts_with("tls_"),
            "a handshake sample went to the DNS parser: {refusal}"
        );
    }

    #[test]
    fn a_sample_the_parsers_refuse_is_counted_rather_than_dropped() {
        // The failure this prevents: a run where every ClientHello was
        // unreadable looks exactly like a run where every connection resolved,
        // because the only trace of the difference was an early return.
        let refusal = facts_from(ebpf::PayloadKind::DnsResponse, &[0x00]).unwrap_err();
        assert_eq!(refusal, "dns_truncated");

        let mut kernel = PlatformKernel::default();
        let rejected = kernel_event_from(ebpf::RawEvent::Payload {
            key: raw_key(),
            t_start_bucket: 1_785_834_000,
            at_secs: 3,
            kind: ebpf::PayloadKind::DnsResponse,
            sample: vec![0x00],
        })
        .unwrap_err();
        *kernel.rejected_samples.entry(rejected).or_insert(0) += 1;
        assert_eq!(kernel.rejected_samples().get("dns_truncated"), Some(&1));
    }

    #[test]
    fn a_refused_load_is_a_refusal_and_not_an_empty_observation() {
        // This test used to open with `let _ = kernel.attach(..)`, which counted
        // the swallowed error as correct and then asserted the empty batch that
        // follows it. Those assertions passed for a kernel that had loaded
        // nothing and would have passed just as well for one that had, which is
        // the defect the state exists to make impossible. The refusal is now
        // asserted, and the batch is asserted to say it establishes nothing.
        let mut kernel = PlatformKernel::default();
        let refusal = kernel.attach(&attach::plan(&Grant {
            tc_available: false,
            elevated_as_root: false,
        }));
        assert!(
            refusal.is_err(),
            "this machine loaded eBPF programs inside a unit test"
        );

        let batch = kernel.poll();
        assert!(!batch.observed());
        assert!(batch.events.is_empty());
        assert_eq!(batch.dropped, 0);
        assert!(kernel.rejected_samples().is_empty());
    }
}
