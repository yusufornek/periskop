//! The `sensor` command: one observation pass, written where a scan can read it.
//!
//! Until this module existed the network sensor had no path to disk at all. The
//! crate could observe, and `periskop scan --flows <DIR>` could read records, and
//! nothing in the product could put anything in that directory: every flow the
//! reconciler had ever seen was written by a test. That is why F3's gate could
//! not be built, and it is the concrete shape of "designed, not wired".
//!
//! Two properties are non negotiable here, and both are milestone 54's.
//!
//! **A sensor that may not run does not fail.** `observe` returns an outcome
//! rather than an error, and so does this: on a machine with no eBPF, no
//! capabilities or no loader compiled in, the command writes an empty record set,
//! prints why, and exits non zero. It never panics and never takes a scan down
//! with it. An observation tool that makes the product unusable when it cannot
//! observe has failed at the only thing it was for.
//!
//! **What could not be done is declared in a structured form.** The status
//! document below is the answer, and it is written whether or not anything was
//! observed. A command that printed nothing on a denied run would be
//! indistinguishable from one that watched a quiet machine, which is the exact
//! confusion `SensorOutcome` was built to prevent.
//!
//! The status is printed rather than written into the record directory. Anything
//! ending in `.json` inside that directory is read back as a flow record by
//! `scan --flows`, so a status file dropped beside the records would be reported
//! as an unparsable flow on every run.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use periskop_network_sensor::{
    observe, EbpfFlowSource, Flow, FlowScope, Privileges, ScopePolicy, SensorOutcome, SensorState,
};
use serde::Serialize;

use crate::write_target::{self, Existing};

/// Name of the record file one pass writes.
///
/// Fixed rather than stamped with a time. The directory is the unit a scan is
/// pointed at, and a file name carrying a clock would make two passes over the
/// same machine accumulate records nobody deletes, which is how a flow directory
/// silently starts describing last week.
const RECORD_FILE_NAME: &str = "flows.jsonl";

/// What one `sensor` invocation was asked for.
pub struct SensorRequest<'a> {
    /// Directory the records are written into. Created if it is not there.
    pub out_dir: &'a Path,
    /// Machine identity to stamp records with, when the caller states one.
    pub host_id: Option<&'a str>,
    /// Processes that belong to the codebase under scan.
    ///
    /// Empty is a legitimate and declared state: nothing can then be attributed
    /// to the codebase, every attributed flow lands in `out_of_scope_process`,
    /// and no unmatched traffic finding can be derived from this pass. The status
    /// says so rather than leaving the reader to work it out from four zeroes.
    pub codebase_processes: &'a [String],
    /// Destinations the operator declared benign.
    pub benign_hosts: &'a [String],
}

/// Writing the records failed.
///
/// Separate from everything the sensor could not observe, and the separation is
/// the point: a denied sensor is a stated outcome, while a directory that cannot
/// be written is the caller's problem and has to be reported as one.
#[derive(Debug, thiserror::Error)]
pub enum SensorWriteError {
    #[error("the record directory {0} could not be created: {1}")]
    DirectoryNotCreated(PathBuf, std::io::Error),

    /// The path carries the message, so it is not repeated here.
    #[error("the flow records could not be written: {0}")]
    FileNotWritten(#[from] write_target::WriteError),

    #[error("a record this build produced could not be serialized: {0}")]
    RecordNotSerialized(serde_json::Error),
}

/// What one pass established, in the form the command prints.
///
/// Serialized with `serde` so the shape is one declaration rather than a format
/// string somebody edits half of. Every field is present on every run, including
/// the zeroes: a counter that disappears when it is empty takes its zero with it,
/// and the zero is the answer to a question the reader asked.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SensorStatus {
    /// `observed` or `not_started`. The two are not spellings of one thing: the
    /// first says the machine was watched, the second that it was not.
    pub state: &'static str,
    /// The fixed label for why nothing was observed, absent when something was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<&'static str>,
    /// What this machine could have offered.
    pub detected_platform: &'static str,
    /// What a report may claim, which is `none` whenever nothing was observed.
    pub coverage_platform_class: &'static str,
    pub host_id: String,
    /// Where the machine identity came from, so a reader can weigh it.
    pub host_id_source: &'static str,
    pub flows_written: u64,
    /// All four buckets, including the empty ones.
    pub flow_scope_counts: BTreeMap<&'static str, u64>,
    /// Observations that could not become records, by fixed reason label.
    pub rejected_observations: BTreeMap<&'static str, u64>,
    pub dropped_events: u64,
    pub unlinked_events: u64,
    /// Payload samples no parser could read, by fixed cause label.
    ///
    /// The connection behind each was still observed; what was lost is the
    /// name of its destination. Printed because a run that could name none of
    /// its destinations and one that named all of them produce the same flow
    /// count and have to be told apart somewhere.
    pub rejected_payload_samples: BTreeMap<&'static str, u64>,
    /// Names the DNS map dropped to stay inside its address budget.
    pub dns_names_evicted: u64,
    /// Connections that had to share a `flow_id` with a connection in another
    /// network namespace.
    pub flow_identities_shared: u64,
    /// Absent on a pass that never started: the coverage contract closes this
    /// field at two values and both are claims about a run that happened.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_observation: Option<&'static str>,
    /// Everything this pass could not establish, in the sensor's own words.
    ///
    /// The structured half of "say what you could not do". A reader who sees an
    /// empty record set has to be able to tell a quiet machine from a machine
    /// nobody was allowed to look at, and from one where the scope policy made
    /// attribution impossible before a single packet arrived.
    pub not_measured: Vec<String>,
}

impl SensorStatus {
    /// Whether this pass observed the machine at all.
    ///
    /// The command's exit code is derived from it: a pass that never started
    /// must not exit zero, or a pipeline that runs the sensor and then scans
    /// would treat "nobody watched" as "nothing happened".
    pub fn observed(&self) -> bool {
        self.state == OBSERVED
    }
}

const OBSERVED: &str = "observed";
const NOT_STARTED: &str = "not_started";

/// What one pass produced.
pub struct SensorRun {
    pub status: SensorStatus,
    /// Where the records went, whether or not there were any. A pass that
    /// observed nothing still writes the file, because an absent file and an
    /// empty one say different things to the scan that reads the directory next.
    pub record_file: PathBuf,
}

/// Runs one observation pass and writes what it saw.
///
/// The `Result` is about the disk and nothing else. Everything the sensor could
/// not do arrives inside [`SensorStatus`], which is why this function has no
/// error variant for a denied sensor: there is no `?` a caller could write that
/// would turn a missing capability into a failed command.
pub fn run(request: &SensorRequest<'_>) -> Result<SensorRun, SensorWriteError> {
    let (host_id, host_id_source) = host_identity(request.host_id);

    let mut policy = ScopePolicy::for_codebase(request.codebase_processes.iter().cloned());
    for host in request.benign_hosts {
        policy = policy.with_declared_benign_host(host.clone());
    }

    let mut source = EbpfFlowSource::new(host_id.clone());
    let outcome = observe(&mut source, &Privileges::probe(), &policy);

    let record_file = write_records(request.out_dir, outcome.flows())?;
    let status = status_of(&outcome, host_id, host_id_source, request);

    Ok(SensorRun {
        status,
        record_file,
    })
}

/// Writes the records as one JSON document per line.
///
/// The shape `scan --flows` reads first, and the shape a live sensor can append
/// to without rewriting what it already wrote. The file is truncated rather than
/// appended to: two passes over one machine describe two windows, and silently
/// unioning them would let a report count a connection that closed yesterday.
///
/// The truncation goes through [`write_target`] rather than `std::fs::write`,
/// and that is the whole reason this function is not one line. This command is
/// documented to run with `CAP_BPF` and `CAP_PERFMON`, and `std::fs::write`
/// follows a symbolic link: with `flows.jsonl` linked at somebody's key file,
/// the plain call emptied the key file and then reported a sensor that could not
/// start, which is a privileged command destroying a file while announcing that
/// it had failed to do anything.
fn write_records(out_dir: &Path, flows: &[Flow]) -> Result<PathBuf, SensorWriteError> {
    std::fs::create_dir_all(out_dir)
        .map_err(|error| SensorWriteError::DirectoryNotCreated(out_dir.to_path_buf(), error))?;

    let mut body = String::new();
    for flow in flows {
        let line = serde_json::to_string(flow).map_err(SensorWriteError::RecordNotSerialized)?;
        body.push_str(&line);
        body.push('\n');
    }

    let path = out_dir.join(RECORD_FILE_NAME);
    // `Replace`: a pass overwrites the records the pass before it wrote, and
    // that file is a regular file this command created. Anything else at the
    // path, a link most of all, stops the write instead of being followed.
    write_target::write_public(&path, body.as_bytes(), Existing::Replace)?;
    Ok(path)
}

fn status_of(
    outcome: &SensorOutcome,
    host_id: String,
    host_id_source: &'static str,
    request: &SensorRequest<'_>,
) -> SensorStatus {
    let mut rejected: BTreeMap<&'static str, u64> = BTreeMap::new();
    for reason in outcome.rejected() {
        *rejected.entry(*reason).or_insert(0) += 1;
    }

    let mut flow_scope_counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    for (scope, count) in outcome.tally().counters() {
        flow_scope_counts.insert(scope.as_str(), count);
    }

    SensorStatus {
        state: match outcome.state() {
            SensorState::Observed => OBSERVED,
            SensorState::NotStarted(_) => NOT_STARTED,
        },
        unavailable_reason: outcome.unavailable_reason(),
        detected_platform: outcome.detected_platform().as_str(),
        coverage_platform_class: outcome.coverage_platform_class().as_str(),
        host_id,
        host_id_source,
        flows_written: outcome.flows().len() as u64,
        flow_scope_counts,
        rejected_observations: rejected,
        dropped_events: outcome.dropped_events(),
        unlinked_events: outcome.unlinked_events(),
        rejected_payload_samples: outcome.rejected_payload_samples().clone(),
        dns_names_evicted: outcome.dns_names_evicted(),
        flow_identities_shared: outcome.shared_identities(),
        dns_observation: outcome.dns_observation().map(|dns| dns.as_str()),
        not_measured: not_measured(outcome, host_id_source, request),
    }
}

/// The list of things this pass is unable to state, each with its consequence.
///
/// Written out rather than left for a reader to infer from a field being zero.
/// Each entry names what was not measured and what a report therefore cannot
/// say, because a limitation nobody can act on is a limitation nobody reads.
fn not_measured(
    outcome: &SensorOutcome,
    host_id_source: &'static str,
    request: &SensorRequest<'_>,
) -> Vec<String> {
    let mut notes = Vec::new();

    if let Some(reason) = outcome.unavailable_reason() {
        notes.push(format!(
            "nothing was observed on this machine ({reason}), so the records are empty because \
             nobody watched rather than because nothing was sent"
        ));
    }
    if request.codebase_processes.is_empty() {
        notes.push(
            "no codebase process was declared, so no flow can reach the in_scope bucket and this \
             pass cannot support an unmatched_wire_traffic finding"
                .to_owned(),
        );
    }
    if outcome.dns_observation().is_none() {
        notes.push(
            "plaintext DNS visibility was not measured, because measuring it needs a pass that \
             started"
                .to_owned(),
        );
    }
    if host_id_source == HOST_ID_NOT_IDENTIFIED {
        notes.push(
            "this machine could not be identified, so the host id is a constant and two machines \
             writing records into one directory would be indistinguishable"
                .to_owned(),
        );
    }
    if outcome.state() == SensorState::Observed
        && outcome.tally().count(FlowScope::InScope) == 0
        && outcome.tally().total() > 0
    {
        notes.push(
            "every observed flow fell outside the declared codebase, so this pass counts traffic \
             it cannot attribute to the project under scan"
                .to_owned(),
        );
    }
    if outcome.shared_identities() > 0 {
        notes.push(format!(
            "{} flows share an identity with a flow from another network namespace, because the \
             contract derives flow_id without netns: those connections cannot be told apart and \
             their volumes are read as one connection's",
            outcome.shared_identities()
        ));
    }
    if outcome.dns_names_evicted() > 0 {
        notes.push(format!(
            "{} names were dropped from the DNS map to stay inside its address budget, so the \
             flows carrying map_overflow had a destination name this run measured and discarded",
            outcome.dns_names_evicted()
        ));
    }
    if outcome.dns_evictions_forgotten() > 0 {
        notes.push(format!(
            "{} evictions happened whose address the map could no longer record, so a flow \
             without map_overflow may still have lost a name",
            outcome.dns_evictions_forgotten()
        ));
    }
    notes.extend(refused_sample_notes(outcome.rejected_payload_samples()));
    // The one number in this status that reads as an all clear when it is not.
    // `dropped_events` is zero both for a capture that lost nothing and for one
    // whose ring buffer loss counter the kernel would not answer for, and the
    // coverage contract has one integer field for it and no way to spell
    // "unknown". Until the contract gains one, the difference is stated here,
    // where a reader is already looking for what this pass could not establish.
    if outcome.dropped_events_unknown() {
        notes.push(format!(
            "the capture transport would not report its loss counter on at least one read, so \
             dropped_events ({}) is a floor rather than a count and this pass cannot say whether \
             events were lost",
            outcome.dropped_events()
        ));
    }
    notes
}

/// The cause the kernel object records when its in flight map is full.
const KERNEL_CALL_NOT_TRACKED: &str = "kernel_call_not_tracked";

/// What the refused-sample tally means, in two sentences rather than one.
///
/// The two entries in that map cost a reader different things, and one sentence
/// covering both understated the second badly enough to be worth splitting.
///
/// A sample the parsers refused is a connection that **was** observed and has no
/// destination name on it: incomplete in the capture. A call the kernel could
/// not track is a connection that was never described at all: missing from the
/// capture. And `dropped_events` cannot say so, because it counts frames the
/// ring buffer had no room for and this loss never became a frame. That is what
/// made a busy machine with a full in flight map report `dropped_events: 0`,
/// which is what a machine that lost nothing reports.
fn refused_sample_notes(samples: &BTreeMap<&'static str, u64>) -> Vec<String> {
    let mut notes = Vec::new();
    let unnamed: u64 = samples
        .iter()
        .filter(|(cause, _)| **cause != KERNEL_CALL_NOT_TRACKED)
        .map(|(_, count)| count)
        .sum();
    if unnamed > 0 {
        notes.push(format!(
            "{unnamed} payload samples could not be parsed, so those connections were observed \
             with no destination name: see rejected_payload_samples for the causes"
        ));
    }
    let untracked = samples.get(KERNEL_CALL_NOT_TRACKED).copied();
    if let Some(untracked) = untracked.filter(|count| *count > 0) {
        notes.push(format!(
            "{untracked} kernel calls produced no record at all because the in flight map was \
             full, so those connections are missing from this capture rather than incomplete in \
             it, and dropped_events does not count them: nothing was ever handed to the ring \
             buffer. The number counts calls and not flows, so it is a floor"
        ));
    }
    notes
}

/// Where a machine identity came from.
const HOST_ID_MACHINE_ID: &str = "machine_id";
const HOST_ID_STATED: &str = "stated_by_caller";
const HOST_ID_NOT_IDENTIFIED: &str = "not_identified";

/// The identity records are stamped with, and how it was arrived at.
///
/// Never the hostname itself. `flow.schema.json` is explicit that this is a
/// stable opaque id rather than a name, so a report does not carry infrastructure
/// naming; every source below is hashed before it is used.
///
/// A machine that offers none of the sources is not given an invented one that
/// looks unique. It gets a constant, and the status says so, because a fabricated
/// per run identity would give the same connection a new flow id on every pass
/// and quietly break the one property flow identity exists for.
fn host_identity(stated: Option<&str>) -> (String, &'static str) {
    if let Some(stated) = stated {
        return (opaque_host_id(stated), HOST_ID_STATED);
    }
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let trimmed = contents.trim();
            if !trimmed.is_empty() {
                return (opaque_host_id(trimmed), HOST_ID_MACHINE_ID);
            }
        }
    }
    (opaque_host_id("unidentified-host"), HOST_ID_NOT_IDENTIFIED)
}

fn opaque_host_id(seed: &str) -> String {
    format!("h_{}", periskop_core::ids::short_hash("host/v1", &[seed]))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("periskop-sensor-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn request<'a>(out: &'a Path, processes: &'a [String]) -> SensorRequest<'a> {
        SensorRequest {
            out_dir: out,
            host_id: Some("test-machine"),
            codebase_processes: processes,
            benign_hosts: &[],
        }
    }

    #[test]
    fn a_pass_on_a_machine_that_cannot_observe_still_answers() {
        // Milestone 54, through the command surface: whatever machine this is,
        // the pass produces a status, writes a record file and does not panic.
        // On a developer's macOS machine and on an unprivileged CI container the
        // sensor cannot start, and that has to be an answer rather than a crash.
        let out = TempDir::new("denied");
        let processes = vec!["/usr/bin/python3".to_owned()];
        let run = run(&request(&out.0, &processes)).unwrap();

        assert!(run.record_file.is_file());
        assert!(run.status.flow_scope_counts.len() == FlowScope::ALL.len());
        if !run.status.observed() {
            assert!(run.status.unavailable_reason.is_some());
            assert_eq!(run.status.coverage_platform_class, "none");
            assert!(
                run.status
                    .not_measured
                    .iter()
                    .any(|note| note.contains("nobody watched")),
                "{:?}",
                run.status.not_measured
            );
        }
    }

    #[test]
    fn a_full_in_flight_map_is_declared_as_missing_flows_rather_than_a_clean_capture() {
        // `known-gaps.md` KG-034. The kernel object counts a call it could not
        // track, and that loss never reaches `dropped_events` because it never
        // becomes a frame: an operator reading `dropped_events: 0` beside a
        // capture taken while the map was full would read a complete capture of
        // a quiet machine. This is the sentence that stops that reading, and it
        // has to be a sentence of its own rather than a share of the refused
        // samples total, because the two losses cost different things.
        let notes = refused_sample_notes(&[(KERNEL_CALL_NOT_TRACKED, 9)].into_iter().collect());
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("missing from this capture"), "{notes:?}");
        assert!(
            notes[0].contains("dropped_events does not count them"),
            "{notes:?}"
        );

        // The other cause keeps its own sentence, and a run carrying both says
        // both. A single total would have made nine untracked calls read as nine
        // connections that were seen and could not be named.
        let both = refused_sample_notes(
            &[(KERNEL_CALL_NOT_TRACKED, 9), ("dns_truncated", 4)]
                .into_iter()
                .collect(),
        );
        assert_eq!(both.len(), 2, "{both:?}");
        assert!(both[0].starts_with("4 payload samples"), "{both:?}");
        assert!(both[1].starts_with("9 kernel calls"), "{both:?}");

        // And a tally with nothing in it says nothing, so the absence of the
        // sentence is evidence rather than a default.
        assert!(refused_sample_notes(&BTreeMap::new()).is_empty());
    }

    #[test]
    fn an_empty_pass_writes_an_empty_file_rather_than_no_file() {
        // An absent file and an empty one say different things to the scan that
        // reads the directory next: no sensor ran, against a sensor that ran and
        // saw nothing.
        let out = TempDir::new("empty-file");
        let processes = vec!["/usr/bin/python3".to_owned()];
        let run = run(&request(&out.0, &processes)).unwrap();
        let body = std::fs::read_to_string(&run.record_file).unwrap();
        assert!(body.lines().all(|line| !line.trim().is_empty()));
    }

    #[test]
    fn a_pass_with_no_declared_codebase_says_what_that_costs() {
        // An empty scope policy is legitimate and its consequence is severe: no
        // flow can reach the only bucket that produces a finding.
        let out = TempDir::new("no-codebase");
        let run = run(&request(&out.0, &[])).unwrap();
        assert!(
            run.status
                .not_measured
                .iter()
                .any(|note| note.contains("in_scope")),
            "{:?}",
            run.status.not_measured
        );
    }

    #[test]
    fn the_status_serializes_with_every_bucket_including_the_zeroes() {
        let out = TempDir::new("status-shape");
        let processes = vec!["/usr/bin/python3".to_owned()];
        let run = run(&request(&out.0, &processes)).unwrap();
        let json = serde_json::to_value(&run.status).unwrap();
        for bucket in FlowScope::ALL {
            assert!(
                json["flow_scope_counts"].get(bucket.as_str()).is_some(),
                "{json}"
            );
        }
        assert!(json.get("state").is_some());
        assert!(json.get("not_measured").is_some());
        // The losses the sensor now measures, including their zeroes. A counter
        // that disappears when it is empty takes its zero with it, and the zero
        // is the answer to a question the reader asked: on this pass, was any
        // destination name dropped, was any sample unreadable, did any two
        // namespaces have to share an identity.
        for measured in [
            "rejected_payload_samples",
            "dns_names_evicted",
            "flow_identities_shared",
        ] {
            assert!(
                json.get(measured).is_some(),
                "{measured} is missing: {json}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_record_file_that_is_a_symbolic_link_stops_the_pass_and_spares_the_other_file() {
        // The live failure this pins, on a command documented to run with
        // `CAP_BPF`: with `flows.jsonl` linked at another file, `std::fs::write`
        // emptied that other file to zero bytes, left the link in place, and the
        // command still reported that the sensor could not start. A privileged
        // write that destroys a file it was never pointed at is the finding; the
        // exit code it destroyed the file behind is what made it invisible.
        let out = TempDir::new("symlinked-records");
        std::fs::create_dir_all(&out.0).unwrap();
        let victim = out.0.join("victim.txt");
        std::fs::write(&victim, b"data somebody needs\n").unwrap();
        std::os::unix::fs::symlink(&victim, out.0.join(RECORD_FILE_NAME)).unwrap();

        let processes = vec!["/usr/bin/python3".to_owned()];
        match run(&request(&out.0, &processes)) {
            Err(SensorWriteError::FileNotWritten(_)) => {}
            Err(other) => panic!("expected the write to be refused, got {other}"),
            Ok(_) => panic!("the pass wrote through a symbolic link"),
        }
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"data somebody needs\n",
            "the linked file was written through"
        );
        assert!(std::fs::symlink_metadata(out.0.join(RECORD_FILE_NAME))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn a_second_pass_replaces_the_records_of_the_first() {
        // The property the symlink refusal must not have cost: two passes over
        // one machine describe two windows, so the second pass owns the file.
        let out = TempDir::new("second-pass");
        let processes = vec!["/usr/bin/python3".to_owned()];
        let first = run(&request(&out.0, &processes)).unwrap();
        std::fs::write(&first.record_file, b"leftover from a pass nobody ran\n").unwrap();

        let second = run(&request(&out.0, &processes)).unwrap();
        let body = std::fs::read_to_string(&second.record_file).unwrap();
        assert!(!body.contains("leftover"), "{body}");
    }

    #[test]
    fn a_stated_host_id_is_hashed_rather_than_carried() {
        // The contract says a stable opaque id and not a name, so infrastructure
        // naming must not reach a record even when the caller hands one over.
        let (id, source) = host_identity(Some("build-box-07.corp.example"));
        assert_eq!(source, HOST_ID_STATED);
        assert!(!id.contains("corp.example"));
        assert!(id.starts_with("h_"));
        assert_eq!(id.len(), "h_".len() + 16);
    }

    #[test]
    fn one_machine_gets_one_identity_across_passes() {
        // A per run identity would give the same connection a new flow id every
        // pass, which is the one property flow identity exists for.
        assert_eq!(host_identity(Some("a")).0, host_identity(Some("a")).0);
        assert_ne!(host_identity(Some("a")).0, host_identity(Some("b")).0);
    }
}
