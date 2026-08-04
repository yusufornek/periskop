//! Reads back what the hooks left on disk.
//!
//! Each hooked process writes its own file, one JSON object per line, and
//! coordinates with nobody. That is not a simplification: a lock shared with an
//! application under observation is a way to stall that application, and §5 of
//! the runtime-hooks spec fixes the priority the other way round. The cost of
//! that choice lands here. Files are read while they are still being appended
//! to, so the last line of any file may be half a record, and a process killed
//! mid flush leaves a truncated line behind permanently.
//!
//! Hence the rule this module is built on: a damaged line is data, not an
//! exception. An observation tool cannot abandon a scan because the observations
//! came back dirty; that would hand any misbehaving hook the power to blind the
//! whole run. Every line that fails to become an event is counted and located,
//! and reading continues with the next one.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::event::EgressEvent;

/// Extension of a hook event file.
///
/// The directory also holds whatever a half finished write or an editor left
/// there. Selecting by extension keeps those out of the malformed list, which
/// only carries meaning if every entry in it is a real loss.
const EVENT_FILE_EXTENSION: &str = "jsonl";

/// Stands in for the event directory in diagnostics.
///
/// A fixed label rather than the path, because an absolute path in a report
/// makes the report differ between two machines that saw the same thing.
const DIRECTORY_LABEL: &str = "<event directory>";

/// What one pass over an event directory produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollectionResult {
    /// Deduplicated, and ordered by identity.
    pub events: Vec<EgressEvent>,
    /// Input lines that did not become events.
    ///
    /// Feeds `dropped_events` in the coverage statement. It counts lines rather
    /// than files, so a file that could not be opened at all adds nothing here:
    /// how many events it held is unknowable once it is unreadable, and a
    /// guessed number in a coverage report is worse than an absent one.
    pub dropped: u64,
    /// One entry per loss, naming where it happened and why.
    ///
    /// Entries read `file:line: reason`, and the reason is a fixed label. It
    /// never quotes the record, because the records this list describes are
    /// exactly the ones suspected of carrying content they should not.
    pub malformed: Vec<String>,
}

impl CollectionResult {
    /// Applies the ordering and deduplication the pipeline depends on.
    ///
    /// Two processes that made the same call write two records under one
    /// identity, which is the point of deriving that identity from the call
    /// shape. Collapsing them is not tidiness: it is what makes "this call
    /// happened" a single fact rather than a count of how many workers happened
    /// to be running when the scan started.
    ///
    /// Identity is the primary key and the whole record breaks ties, so the
    /// order in which the filesystem handed back the files cannot reach the
    /// output.
    fn normalize(&mut self) {
        self.events.sort_by(|a, b| {
            a.egress_event_id
                .cmp(&b.egress_event_id)
                .then_with(|| a.cmp(b))
        });
        self.events
            .dedup_by(|a, b| a.egress_event_id == b.egress_event_id);
        self.malformed.sort();
    }

    fn reject(&mut self, file_name: &str, line_number: u64, reason: &str) {
        self.dropped += 1;
        self.malformed
            .push(format!("{file_name}:{line_number}: {reason}"));
    }
}

/// Reads every event file in `dir`.
///
/// Returns a result rather than a `Result`: the caller asked what the hooks
/// recorded, and "these events, and here is what was lost" is an answer, while
/// an error would throw away the events that were readable in order to report
/// the ones that were not.
pub fn collect(dir: &Path) -> CollectionResult {
    let mut result = CollectionResult::default();

    for file_name in event_file_names(dir, &mut result) {
        read_event_file(&dir.join(&file_name), &file_name, &mut result);
    }

    result.normalize();
    result
}

/// Lists the event files, in an order that does not depend on the filesystem.
fn event_file_names(dir: &Path, result: &mut CollectionResult) -> Vec<String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => {
            // A directory that was never created and one that holds no events
            // are different facts, and §5 of the spec is explicit that the
            // difference between "nothing was observed" and "observation never
            // ran" must survive into the report.
            result
                .malformed
                .push(format!("{DIRECTORY_LABEL}: unreadable"));
            return Vec::new();
        }
    };

    let mut names = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            result
                .malformed
                .push(format!("{DIRECTORY_LABEL}: unreadable entry"));
            continue;
        };
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some(EVENT_FILE_EXTENSION) {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            names.push(name.to_owned());
        }
    }

    // read_dir returns whatever order the filesystem keeps. Sorting here is what
    // makes two runs over the same directory produce the same bytes.
    names.sort();
    names
}

fn read_event_file(path: &Path, file_name: &str, result: &mut CollectionResult) {
    let Ok(file) = File::open(path) else {
        // Named without a line count: see the note on `dropped`.
        result.malformed.push(format!("{file_name}: unreadable"));
        return;
    };

    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let mut line_number: u64 = 0;

    loop {
        line.clear();
        line_number += 1;
        match reader.read_line(&mut line) {
            Ok(0) => return,
            Ok(_) => consume_line(&line, file_name, line_number, result),
            Err(_) => {
                // Bytes that are not text, or a device that stopped answering.
                // The stream position after a failed read is not defined, so
                // this file ends here while the rest of the directory carries
                // on. Giving up on one file is a loss; giving up on the pass
                // would be a blind spot.
                result.reject(file_name, line_number, "unreadable");
                return;
            }
        }
    }
}

fn consume_line(line: &str, file_name: &str, line_number: u64, result: &mut CollectionResult) {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        // A blank line carries no event, so nothing was lost and nothing is
        // counted. Counting it would inflate a number whose only job is to say
        // how much was observed and could not be read.
        return;
    }

    // The half written last line of a file a live process is still appending to
    // lands here, and so does a record from a hook that writes a field this
    // build does not know about.
    let Ok(event) = serde_json::from_str::<EgressEvent>(trimmed) else {
        result.reject(file_name, line_number, "unparsable_record");
        return;
    };

    match event.validate() {
        Ok(()) => result.events.push(event),
        Err(error) => result.reject(file_name, line_number, error.reason()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::event::{EgressEvent, Language, Library, Mechanism, PayloadShape, Process, Target};
    use std::fs;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("periskop-collector-{name}"));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn write(&self, file_name: &str, contents: &str) {
            fs::write(self.0.join(file_name), contents).unwrap();
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn event(host_id: &str) -> EgressEvent {
        EgressEvent::new(
            Process {
                language: Language::Python,
                runtime: "cpython/3.12".to_owned(),
                entrypoint_hint: None,
            },
            Library {
                module: "openai".to_owned(),
                mechanism: Mechanism::SdkWrapper,
            },
            "chat.completions.create",
            Target {
                host_id: host_id.to_owned(),
                port: Some(443),
                path_template: Some("/v1/chat/completions".to_owned()),
                provider_ref: Some("openai".to_owned()),
            },
            PayloadShape {
                field_paths: vec!["messages[].content".to_owned()],
                byte_size_estimate: 512,
                truncated_depth: None,
            },
        )
        .unwrap()
    }

    fn line(host_id: &str) -> String {
        format!("{}\n", serde_json::to_string(&event(host_id)).unwrap())
    }

    #[test]
    fn an_empty_directory_yields_nothing_and_reports_nothing() {
        let dir = TempDir::new("empty");
        let result = collect(dir.path());
        assert!(result.events.is_empty());
        assert_eq!(result.dropped, 0);
        assert!(result.malformed.is_empty());
    }

    #[test]
    fn a_missing_directory_is_reported_rather_than_hidden() {
        // "The hook never ran" and "the hook ran and saw nothing" must not
        // arrive at the report looking the same.
        let dir = TempDir::new("missing");
        let absent = dir.path().join("never-created");
        let result = collect(&absent);
        assert!(result.events.is_empty());
        assert_eq!(result.malformed, [format!("{DIRECTORY_LABEL}: unreadable")]);
    }

    #[test]
    fn a_damaged_line_does_not_stop_the_read() {
        let dir = TempDir::new("damaged");
        dir.write(
            "worker-1.jsonl",
            &format!(
                "{}{{ not json at all\n{}",
                line("api.openai.com"),
                line("api.anthropic.com")
            ),
        );

        let result = collect(dir.path());

        assert_eq!(result.events.len(), 2);
        assert_eq!(result.dropped, 1);
        assert_eq!(result.malformed, ["worker-1.jsonl:2: unparsable_record"]);
    }

    #[test]
    fn a_half_written_last_line_costs_only_that_line() {
        // The normal state of a file belonging to a process that is still
        // running, not an exceptional one.
        let dir = TempDir::new("half-written");
        dir.write(
            "worker-1.jsonl",
            &format!(
                "{}{{\"schema_version\":\"1.0\",\"egress_event_id\":\"ee_5b18c30af79",
                line("api.openai.com")
            ),
        );

        let result = collect(dir.path());

        assert_eq!(result.events.len(), 1);
        assert_eq!(result.dropped, 1);
        assert_eq!(result.malformed, ["worker-1.jsonl:2: unparsable_record"]);
    }

    #[test]
    fn a_record_carrying_raw_content_never_reaches_the_events() {
        // Well formed JSON, correct field names, and a field path that has
        // copied a customer address out of the payload. The record is shaped
        // like an event, so only validation stops it.
        let dir = TempDir::new("raw-content");
        let leaking = serde_json::to_string(&serde_json::json!({
            "schema_version": "1.0",
            "egress_event_id": "ee_5b18c30af7924de6",
            "process": { "language": "python", "runtime": "cpython/3.12" },
            "library": { "module": "openai", "mechanism": "sdk_wrapper" },
            "operation": "chat.completions.create",
            "target": { "host_id": "api.openai.com" },
            "payload_shape": {
                "field_paths": ["customers.email=ahmet@firma.com"],
                "byte_size_estimate": 12
            }
        }))
        .unwrap();
        dir.write("worker-1.jsonl", &format!("{leaking}\n"));

        let result = collect(dir.path());

        assert!(result.events.is_empty());
        assert_eq!(result.dropped, 1);
        assert_eq!(
            result.malformed,
            ["worker-1.jsonl:1: raw_content_in_field_path"]
        );
        // The diagnostic locates the loss without repeating it.
        assert!(!result.malformed[0].contains("ahmet"));
    }

    #[test]
    fn the_same_call_seen_by_two_processes_is_one_event() {
        let dir = TempDir::new("dedup");
        dir.write("worker-1.jsonl", &line("api.openai.com"));
        dir.write("worker-2.jsonl", &line("api.openai.com"));

        let result = collect(dir.path());

        assert_eq!(result.events.len(), 1);
        // A duplicate is not a loss: it is the same fact, counted once.
        assert_eq!(result.dropped, 0);
    }

    #[test]
    fn events_are_ordered_by_identity() {
        let dir = TempDir::new("ordered");
        dir.write(
            "worker-1.jsonl",
            &format!(
                "{}{}{}",
                line("api.openai.com"),
                line("api.anthropic.com"),
                line("generativelanguage.googleapis.com")
            ),
        );

        let result = collect(dir.path());

        let ids: Vec<&str> = result.events.iter().map(EgressEvent::id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn ordering_does_not_depend_on_how_the_files_were_named() {
        // Same three calls, split across files two different ways. The report
        // has to come out identical, or a scan would differ from itself because
        // a worker restarted under a new pid.
        let one = TempDir::new("layout-a");
        one.write(
            "z-worker.jsonl",
            &format!("{}{}", line("api.openai.com"), line("api.anthropic.com")),
        );
        one.write("a-worker.jsonl", &line("api.cohere.com"));

        let other = TempDir::new("layout-b");
        other.write("a-worker.jsonl", &line("api.anthropic.com"));
        other.write(
            "m-worker.jsonl",
            &format!("{}{}", line("api.cohere.com"), line("api.openai.com")),
        );

        assert_eq!(collect(one.path()).events, collect(other.path()).events);
    }

    #[test]
    fn files_without_the_event_extension_are_left_alone() {
        // A partial write under a temporary name is not a loss to report; it is
        // a file that was never claimed to be an event file.
        let dir = TempDir::new("extensions");
        dir.write("worker-1.jsonl", &line("api.openai.com"));
        dir.write("worker-2.jsonl.tmp", "{ still being written");
        dir.write("hook-status.log", "disabled:import_failed");

        let result = collect(dir.path());

        assert_eq!(result.events.len(), 1);
        assert_eq!(result.dropped, 0);
        assert!(result.malformed.is_empty());
    }

    #[test]
    fn blank_lines_are_not_counted_as_loss() {
        let dir = TempDir::new("blank-lines");
        dir.write(
            "worker-1.jsonl",
            &format!("\n{}\n\n{}", line("api.openai.com"), line("api.cohere.com")),
        );

        let result = collect(dir.path());

        assert_eq!(result.events.len(), 2);
        assert_eq!(result.dropped, 0);
        assert!(result.malformed.is_empty());
    }

    #[test]
    fn a_record_from_a_newer_hook_is_reported_not_absorbed() {
        // An unknown field means this build cannot vouch for the record, and
        // vouching for it anyway is how an unvalidated channel gets in.
        let dir = TempDir::new("unknown-field");
        let mut record = serde_json::to_value(event("api.openai.com")).unwrap();
        if let Some(map) = record.as_object_mut() {
            map.insert("prompt_text".to_owned(), serde_json::json!("hello"));
        }
        dir.write(
            "worker-1.jsonl",
            &format!("{}\n", serde_json::to_string(&record).unwrap()),
        );

        let result = collect(dir.path());

        assert!(result.events.is_empty());
        assert_eq!(result.dropped, 1);
        assert_eq!(result.malformed, ["worker-1.jsonl:1: unparsable_record"]);
    }

    #[test]
    fn one_unreadable_file_does_not_cost_the_directory() {
        let dir = TempDir::new("bad-bytes");
        dir.write("worker-1.jsonl", &line("api.openai.com"));
        // Invalid UTF-8: the line cannot be read as text at all, which is a
        // different failure from a line that is text but not a record.
        fs::write(dir.path().join("worker-2.jsonl"), [0xff, 0xfe, b'\n']).unwrap();
        dir.write("worker-3.jsonl", &line("api.anthropic.com"));

        let result = collect(dir.path());

        assert_eq!(result.events.len(), 2);
        assert_eq!(result.dropped, 1);
        assert_eq!(result.malformed, ["worker-2.jsonl:1: unreadable"]);
    }
}
