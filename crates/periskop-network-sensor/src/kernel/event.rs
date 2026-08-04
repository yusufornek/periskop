//! What a kernel hook hands over, and what it is structurally unable to hand
//! over.
//!
//! Four events, and the difference between them is the whole attribution
//! model. [`ConnectEvent`], [`VolumeEvent`] and [`CloseEvent`] come from the
//! kprobe hooks, which run in the calling task's context: there is a process
//! there, and it is the right one, with no race and no sampling window. So
//! `ConnectEvent` carries a process and the sensor may write
//! `kernel_attributed` for it.
//!
//! [`PayloadEvent`] comes from the `tc` helper, which sees packets far below
//! the socket layer with no task context at all. **It has no process field, and
//! that is the design.** ADR-008 states as a binding rule that `tc` never
//! produces process attribution; a type with a nullable process field would put
//! the rule at the mercy of whoever writes the next `if`. Here it is not
//! expressible.
//!
//! `PayloadEvent` also carries no bytes. The parsers in [`crate::parse`] run at
//! the capture boundary and only their facts travel, so nothing downstream can
//! hold a packet even by mistake.

use crate::flow::ProcessRecord;
use crate::parse::dns::DnsAnswers;
use crate::parse::tls::ClientHelloFacts;

use super::key::FlowKey;

/// The process context a kprobe read out of the running task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelProcess {
    pub pid: u32,
    /// Distinguishes two processes that were given the same pid over a long
    /// observation.
    pub pid_start_time: Option<u64>,
    /// The short name the kernel keeps. Survives the process, which is why the
    /// record can still name a program that exited before user space looked.
    pub comm: Option<String>,
}

impl KernelProcess {
    /// The record form, with the fields user space enrichment would fill left
    /// out.
    ///
    /// `exe` and `cmdline_hash` come from reading `/proc/<pid>`, which this
    /// milestone does not do. The component spec is explicit that their absence
    /// is how "the kernel was certain and the process was already gone" is
    /// expressed; it is not a weaker kind of attribution and there is no enum
    /// value for one.
    pub fn into_record(self) -> ProcessRecord {
        ProcessRecord {
            pid: self.pid,
            pid_start_time: self.pid_start_time,
            comm: self.comm,
            exe: None,
            cmdline_hash: None,
        }
    }
}

/// A connection being opened, seen in the context of the task opening it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectEvent {
    pub key: FlowKey,
    /// Start time already rounded to the contract's bucket. Rounding in the
    /// capture path rather than at the record keeps a raw stamp from ever
    /// existing in a value a report is derived from.
    pub t_start_bucket: u64,
    /// Seconds since the sensor started looking. Not a wall clock: it exists to
    /// age the DNS map and must not reach a record.
    pub at_secs: u64,
    pub process: KernelProcess,
    /// Set for connections found by scanning existing sockets at startup rather
    /// than by the hook firing. Their byte counts and duration are lower bounds
    /// and the record has to say so.
    pub pre_existing: bool,
}

/// Bytes moved, accumulated per call rather than per packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeEvent {
    pub key: FlowKey,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub segments_out: u64,
}

/// A connection ending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseEvent {
    pub key: FlowKey,
    pub duration_ms: Option<u64>,
}

/// What the `tc` helper parsed out of one packet.
///
/// A DNS answer is about an address and not about the connection that carried
/// it; a handshake is about the connection it opened. The assembler treats them
/// differently for that reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadFacts {
    Dns(DnsAnswers),
    Handshake(ClientHelloFacts),
}

/// A packet level observation, with no process and no bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadEvent {
    pub key: FlowKey,
    /// Used only when this event is the first thing seen for a connection, in
    /// which case there is no `ConnectEvent` to take a start time from.
    pub t_start_bucket: u64,
    pub at_secs: u64,
    pub facts: PayloadFacts,
}

/// One thing a hook reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelEvent {
    Connect(ConnectEvent),
    Volume(VolumeEvent),
    Close(CloseEvent),
    Payload(PayloadEvent),
}

impl KernelEvent {
    pub fn key(&self) -> &FlowKey {
        match self {
            Self::Connect(event) => &event.key,
            Self::Volume(event) => &event.key,
            Self::Close(event) => &event.key,
            Self::Payload(event) => &event.key,
        }
    }
}

/// One read of the ring buffer.
///
/// `dropped` is not an error path. A fixed size buffer under load loses events,
/// the component spec requires the count to reach the coverage statement, and a
/// batch type that could not express the loss would make it disappear at the
/// first hop.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelBatch {
    pub events: Vec<KernelEvent>,
    pub dropped: u64,
}

impl KernelBatch {
    pub fn of(events: Vec<KernelEvent>) -> Self {
        Self { events, dropped: 0 }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::kernel::key::tests::key;

    #[test]
    fn a_kernel_process_becomes_a_record_without_inventing_enrichment() {
        // `exe` and `cmdline_hash` require reading /proc, which this milestone
        // does not do. Filling them with the kernel's short name would put a
        // guess where the contract expects a path.
        let record = KernelProcess {
            pid: 4821,
            pid_start_time: Some(1_785_833_900),
            comm: Some("python3".to_owned()),
        }
        .into_record();
        assert_eq!(record.pid, 4821);
        assert_eq!(record.comm.as_deref(), Some("python3"));
        assert_eq!(record.exe, None);
        assert_eq!(record.cmdline_hash, None);
    }

    #[test]
    fn a_payload_event_has_nowhere_to_put_a_process() {
        // ADR-008 forbids `tc` from producing attribution. Making it
        // inexpressible is stronger than checking for it, and this test exists
        // so the guarantee is stated where a reader will look for it.
        let event = PayloadEvent {
            key: key("104.18.7.1", 443, 54321),
            t_start_bucket: 1_785_834_000,
            at_secs: 3,
            facts: PayloadFacts::Handshake(ClientHelloFacts::NoServerName),
        };
        let fields = format!("{event:?}");
        assert!(
            !fields.contains("pid"),
            "tc gained a process field: {fields}"
        );
    }

    #[test]
    fn a_batch_can_say_it_lost_events() {
        // Under load the ring buffer overruns. A batch that could only carry
        // events would turn that into a quiet shortfall in the flow count.
        let batch = KernelBatch {
            events: Vec::new(),
            dropped: 17,
        };
        assert_eq!(batch.dropped, 17);
        assert_eq!(KernelBatch::of(Vec::new()).dropped, 0);
    }

    #[test]
    fn every_event_names_the_flow_it_belongs_to() {
        let flow = key("104.18.7.1", 443, 54321);
        let events = [
            KernelEvent::Volume(VolumeEvent {
                key: flow.clone(),
                bytes_out: 1,
                bytes_in: 2,
                segments_out: 3,
            }),
            KernelEvent::Close(CloseEvent {
                key: flow.clone(),
                duration_ms: Some(4),
            }),
        ];
        for event in &events {
            assert_eq!(event.key(), &flow);
        }
    }
}
