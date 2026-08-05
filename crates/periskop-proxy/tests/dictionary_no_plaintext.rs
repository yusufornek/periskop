#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The organization's word list leaves no plaintext copy behind.
//!
//! Milestone 81 extends milestone 73's byte scan to cover the dictionary file:
//! "sözlük dosyası disk üzerinde açık liste bırakmaz (görev 73'ün bayt taraması
//! bu dosyayı da kapsar)". The claim is narrower than the vault's and it is
//! written narrowly on purpose.
//!
//! # What is claimed
//!
//! The operator's file is the operator's secret. periskop reads it and writes
//! **no copy of it anywhere**: not a cache, not a normalised form, not a
//! temporary file, not a log line, not a `Debug` rendering, not a process
//! stream. The identity `dictionary_id` is what a report may name; an entry is
//! not, in any surface a caller can reach.
//!
//! # What is not claimed
//!
//! That the list is unreadable in this process's memory while it is loaded. It
//! cannot be: scanning for a name requires holding the name. The automaton owns
//! its own copy of every pattern and no API reaches inside it. That residue is
//! `known-gaps.md` KG-019, the same exposure every decrypted value in this
//! process has, and it is `mlock`'s problem rather than this test's.
//!
//! # The surfaces
//!
//! | Surface | What is scanned |
//! |---|---|
//! | the directory the policy and the list live in | every byte of every file after a full load, compared against what was there before |
//! | `Debug` of everything a caller can reach | the policy, the dictionary, every load error, every candidate |
//! | `stdout` and `stderr` | everything a real child process that loads a dictionary and scans a prompt wrote to either stream |
//!
//! The third row is the one that catches a `dbg!` added to the scan path, and it
//! is a real child process rather than a description of one, for the reason
//! milestone 73's file gives: none of the in-process surfaces would see a byte
//! of it.

use std::path::{Path, PathBuf};

use periskop_proxy::detect::dictionary::Dictionary;
use periskop_proxy::policy::Policy;

/// Values planted in the word list and hunted for afterwards.
///
/// Distinctive enough that a hit is a hit: none of these occurs in this
/// repository, in a compiler artefact or in a stack trace.
const PLANTED: &[(&str, &str)] = &[
    ("Zubeyde Qorvax", "PERSON"),
    ("Xyllotherm Kollektif", "ORG"),
    ("vlorbik-07.zeta.internal", "HOST"),
];

/// The environment variable that turns this test binary into the child process.
const CHILD_MARKER: &str = "PERISKOP_DICTIONARY_CHILD";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Writes a policy and its word list into a fresh directory, and returns it.
fn plant(directory: &Path) {
    std::fs::create_dir_all(directory).unwrap();
    let mut list = String::from("schema_version = \"1.0\"\ndictionary_id = \"planted\"\n");
    for (value, entity) in PLANTED {
        list.push_str(&format!(
            "[[entries]]\nvalue = \"{value}\"\ntype = \"{entity}\"\n"
        ));
    }
    std::fs::write(directory.join("org-dictionary.toml"), list).unwrap();
    std::fs::write(
        directory.join("policy.toml"),
        "policy_id = \"planted\"\n\
         policy_version = \"1\"\n\
         [default]\n\
         mode = \"mask\"\n\
         [dictionary]\n\
         source = \"org-dictionary.toml\"\n\
         required = true\n\
         [affix_rules]\n\
         languages = [\"tr\"]\n",
    )
    .unwrap();
}

/// Every file under `directory`, as (path, bytes).
fn files_under(directory: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(directory) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(files_under(&path));
        } else if let Ok(bytes) = std::fs::read(&path) {
            out.push((path, bytes));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

#[test]
fn loading_a_word_list_writes_no_copy_of_it_to_disk() {
    let directory =
        std::env::temp_dir().join(format!("periskop-dictionary-scan-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    plant(&directory);

    let before = files_under(&directory);
    let policy =
        Policy::load_from_path(&directory.join("policy.toml"), &repository_root(), None).unwrap();
    // The list really did load, or this test would be proving that nothing
    // happened. The exhausted case is covered by the unit tests; here the point
    // is that a *populated* list leaves nothing behind.
    assert_eq!(policy.dictionary().len(), PLANTED.len());
    assert!(!policy.dictionary().scan("Zubeyde Qorvax geldi").is_empty());

    let after = files_under(&directory);
    // Nothing new, and nothing changed. The two files that hold the planted
    // values are the operator's own, and they are byte identical.
    assert_eq!(
        before.iter().map(|(path, _)| path).collect::<Vec<_>>(),
        after.iter().map(|(path, _)| path).collect::<Vec<_>>(),
        "a file appeared or disappeared while loading the word list"
    );
    for ((path, old), (_, new)) in before.iter().zip(&after) {
        assert_eq!(old, new, "{} changed", path.display());
    }

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn no_rendering_a_caller_can_reach_carries_an_entry() {
    let mut list = String::from("schema_version = \"1.0\"\ndictionary_id = \"planted\"\n");
    for (value, entity) in PLANTED {
        list.push_str(&format!(
            "[[entries]]\nvalue = \"{value}\"\ntype = \"{entity}\"\n"
        ));
    }
    let dictionary = Dictionary::parse(&list).unwrap();

    let text = "Zubeyde Qorvax ve Xyllotherm Kollektif, vlorbik-07.zeta.internal üzerinde";
    let candidates = dictionary.scan(text);
    assert_eq!(candidates.len(), PLANTED.len());

    // Every rendering a log line, a panic message or a test failure could carry.
    let mut renderings = vec![
        format!("{dictionary:?}"),
        format!("{:?}", dictionary.id()),
        format!("{candidates:?}"),
    ];
    // Load failures too: a message that quoted the offending entry would put a
    // name into whatever reported it.
    let bad = format!("{list}[[entries]]\nvalue = \"Zubeyde Qorvax\"\ntype = \"TCKN\"\n");
    renderings.push(format!("{:?}", Dictionary::parse(&bad).unwrap_err()));
    renderings.push(Dictionary::parse(&bad).unwrap_err().to_string());

    for rendering in renderings {
        for (value, _) in PLANTED {
            assert!(
                !rendering.contains(value),
                "'{value}' appeared in a rendering: {rendering}"
            );
        }
    }
}

#[test]
fn a_real_process_that_loads_and_scans_writes_nothing_to_either_stream() {
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let directory =
        std::env::temp_dir().join(format!("periskop-dictionary-child-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    plant(&directory);

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("child_loads_and_scans")
        .arg("--nocapture")
        .env(CHILD_MARKER, directory.display().to_string())
        .output()
        .expect("the child test binary did not start");

    for stream in [&output.stdout, &output.stderr] {
        for (value, _) in PLANTED {
            assert!(
                !contains(stream, value),
                "'{value}' reached a process stream: {}",
                String::from_utf8_lossy(stream)
            );
        }
    }
    assert!(output.status.success(), "the child run failed");

    let _ = std::fs::remove_dir_all(&directory);
}

/// The child half of the stream scan. Does the work; says nothing.
#[test]
fn child_loads_and_scans() {
    let Ok(directory) = std::env::var(CHILD_MARKER) else {
        // Run directly rather than as a child: there is nothing to load, and
        // passing vacuously here is correct because the parent above is what
        // makes the claim.
        return;
    };
    let directory = PathBuf::from(directory);
    let policy =
        Policy::load_from_path(&directory.join("policy.toml"), &repository_root(), None).unwrap();
    let found = policy
        .dictionary()
        .scan("Zubeyde Qorvax'in raporu Xyllotherm Kollektif'e gitti");
    assert_eq!(found.len(), 2);
}
