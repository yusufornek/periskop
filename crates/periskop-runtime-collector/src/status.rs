//! The hook's own account of what it lost, read back.
//!
//! A hook counts what it drops: a ring that overflowed while the application was
//! faster than the disk, a batch whose write failed, a process that started with
//! the hook switched off. None of that fits in
//! `schemas/egress-event.schema.json`, whose property list is closed, so it
//! leaves through a sidecar the hook writes beside its stream, named
//! `<stream>.status.json`.
//!
//! Reading that sidecar is not optional bookkeeping. In a directory of `.jsonl`
//! files, an event that was counted and never written looks exactly like a call
//! that never happened, and the two are opposites: the first is a hole in the
//! evidence, the second is evidence. A collector that reads only the streams
//! reports the hole as a clean result, which is the single failure this product
//! exists to prevent. The hooks were already counting; nothing downstream was
//! reading.
//!
//! Two rules shape the parsing, and both run opposite to the event type.
//!
//! Unknown properties are ignored rather than rejected. An event carrying a
//! field this build does not know may be smuggling content through a channel
//! nothing validates, so [`crate::event::EgressEvent`] refuses it. A status file
//! carrying an extra counter is a newer hook doing more accounting, and refusing
//! to read it would throw away the loss count it came to deliver.
//!
//! Nothing from the file reaches a note before it has been checked to be a fixed
//! token. The hook is a different program, in a language this crate does not
//! compile, and a note is written into a report somebody diffs.

use serde::Deserialize;

/// Suffix of the file a hook writes beside its event stream.
///
/// It ends in `.json` rather than `.jsonl` so the collector never reads a run's
/// own accounting back as a malformed event.
pub const STATUS_FILE_SUFFIX: &str = ".status.json";

/// The one value of `hook_status` that means the hook was in the call path.
const ACTIVE: &str = "active";

/// Longest label copied out of a status file.
const MAX_LABEL_CHARS: usize = 64;

/// Ceiling on failure labels taken from one file.
///
/// A hook that fails on every call records a bounded set of labels, but the
/// bound belongs to the hook. Repeating it here keeps one broken process from
/// filling a report's diagnostics with its own noise.
const MAX_REPORTED_FAILURES: usize = 16;

/// The document both hooks write. Fields this crate does not use are ignored.
///
/// `hook_status` and `dropped_events_count` carry no `serde` default on purpose:
/// a file that omits the counter would otherwise read as "nothing was lost",
/// which is the assumption this module exists to stop anyone from making.
#[derive(Debug, Clone, Deserialize)]
struct StatusDocument {
    hook_status: String,
    dropped_events_count: u64,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    failures: Vec<String>,
}

/// What one status file adds to a collection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatusReport {
    /// Events the hook counted as lost before they reached the stream.
    pub dropped: u64,
    /// Fixed labels naming what happened, without the file they came from.
    ///
    /// The caller prefixes the file name, the way it does for a damaged line, so
    /// that every entry in a coverage statement can be traced to one process.
    pub reasons: Vec<String>,
}

/// Reads one status file's contents.
///
/// Never fails: a status file that cannot be understood is itself a loss worth
/// naming, and returning an error here would mean the caller either abandons the
/// directory or ignores the file, both of which lose more than they save.
pub fn read(contents: &str) -> StatusReport {
    let Ok(document) = serde_json::from_str::<StatusDocument>(contents) else {
        return StatusReport {
            dropped: 0,
            reasons: vec!["unreadable_status".to_owned()],
        };
    };

    let mut reasons = Vec::new();

    if document.hook_status != ACTIVE {
        // A process that ran un-hooked observed nothing, and "observed nothing"
        // must never arrive at the report looking like "there was nothing to
        // observe".
        reasons.push(labelled("hook_not_active", &document.reason));
    }

    if document.dropped_events_count > 0 {
        // The count is carried in the text as well as in the total, because the
        // total cannot say which process lost them and an operator fixing this
        // needs to know whether it was one worker or all of them.
        reasons.push(format!(
            "hook_dropped_events: {}",
            document.dropped_events_count
        ));
    }

    for failure in document.failures.iter().take(MAX_REPORTED_FAILURES) {
        reasons.push(labelled("hook_failure", failure));
    }

    StatusReport {
        dropped: document.dropped_events_count,
        reasons,
    }
}

/// Joins a label to a token, or drops the token if it is not one.
fn labelled(kind: &str, token: &str) -> String {
    if is_fixed_token(token) {
        format!("{kind}: {token}")
    } else {
        kind.to_owned()
    }
}

/// Whether a string is a short, fixed identifier rather than free text.
///
/// Both hooks build these labels out of a stage name and an error type name, so
/// the alphabet is known. Anything outside it is dropped rather than repeated:
/// the check is the same one the event type applies to a field path, for the
/// same reason. A hook with a bug could put a payload here, and a report that
/// copied it would move the leak one layer down where nobody is looking.
fn is_fixed_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LABEL_CHARS
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(dropped: u64) -> String {
        format!(
            r#"{{"hook_status":"active","reason":"","dropped_events_count":{dropped},
               "written_events_count":3,"failures":[]}}"#
        )
    }

    #[test]
    fn a_clean_run_adds_nothing_to_the_report() {
        // The common case has to stay silent, or every scan would carry a
        // diagnostic and operators would learn to skip the block.
        let report = read(&document(0));
        assert_eq!(report, StatusReport::default());
    }

    #[test]
    fn events_the_hook_dropped_are_counted_and_located() {
        // The finding this module was written for: the hook counted 200000 lost
        // events and nothing downstream read the number.
        let report = read(&document(200_000));
        assert_eq!(report.dropped, 200_000);
        assert_eq!(report.reasons, ["hook_dropped_events: 200000"]);
    }

    #[test]
    fn a_status_file_that_cannot_be_read_is_named_rather_than_skipped() {
        for contents in ["{ not json", "[]", r#"{"hook_status":"active"}"#] {
            let report = read(contents);
            assert_eq!(report.dropped, 0);
            assert_eq!(report.reasons, ["unreadable_status"]);
        }
    }

    #[test]
    fn a_missing_counter_is_not_read_as_a_clean_run() {
        // Absent and zero say different things, and only one of them is a claim
        // this crate is entitled to make on the hook's behalf.
        let report = read(r#"{"hook_status":"active","failures":[]}"#);
        assert_eq!(report.reasons, ["unreadable_status"]);
    }

    #[test]
    fn a_hook_that_never_started_says_so() {
        let report = read(
            r#"{"hook_status":"disabled","reason":"no_output_configured",
                "dropped_events_count":0,"failures":[]}"#,
        );
        assert_eq!(report.reasons, ["hook_not_active: no_output_configured"]);
    }

    #[test]
    fn swallowed_failures_reach_the_report() {
        let report = read(
            r#"{"hook_status":"active","reason":"","dropped_events_count":0,
                "failures":["writer.drain:OSError","writer.flush"]}"#,
        );
        assert_eq!(
            report.reasons,
            [
                "hook_failure: writer.drain:OSError",
                "hook_failure: writer.flush"
            ]
        );
    }

    #[test]
    fn a_label_that_is_not_a_fixed_token_is_dropped_not_repeated() {
        // A hook with a bug could put a payload where a label belongs. The count
        // still has to arrive; the string must not.
        let report = read(
            r#"{"hook_status":"disabled","reason":"user ahmet@firma.com sent 4111111111111111",
                "dropped_events_count":7,
                "failures":["prompt: merhaba dünya"]}"#,
        );
        assert_eq!(report.dropped, 7);
        assert_eq!(
            report.reasons,
            [
                "hook_not_active".to_owned(),
                "hook_dropped_events: 7".to_owned(),
                "hook_failure".to_owned(),
            ]
        );
        assert!(!report.reasons.join(" ").contains("ahmet"));
    }

    #[test]
    fn one_noisy_process_cannot_fill_the_report() {
        let failures: Vec<String> = (0..100).map(|i| format!("\"stage{i}\"")).collect();
        let report = read(&format!(
            r#"{{"hook_status":"active","dropped_events_count":0,"failures":[{}]}}"#,
            failures.join(",")
        ));
        assert_eq!(report.reasons.len(), MAX_REPORTED_FAILURES);
    }

    #[test]
    fn a_counter_this_build_does_not_know_does_not_cost_the_ones_it_does() {
        // The opposite rule from the event type, and the reason is in the module
        // note: refusing a newer hook's status file would throw away the loss
        // count it came to deliver.
        let report = read(
            r#"{"hook_status":"active","dropped_events_count":4,
                "sampled_events_count":9,"failures":[]}"#,
        );
        assert_eq!(report.dropped, 4);
    }
}
