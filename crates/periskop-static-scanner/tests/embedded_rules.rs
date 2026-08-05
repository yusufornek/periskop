#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
//! The embedded rule set and the `rules/` tree are the same bytes.
//!
//! This is the one claim the whole embedding rests on. A binary that carries a
//! rule set which has drifted from the tree in the repository is worse than a
//! binary with no rules at all: it scans, it reports, and it reports against
//! detectors nobody is looking at. The comparison below is byte for byte and in
//! both directions, so a file added to the tree and left out of the binary fails
//! here just as loudly as a file whose contents diverged.
//!
//! Kept as an integration test rather than a unit test because it needs the
//! repository, and the repository is exactly what the binary is being compared
//! against.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use periskop_static_scanner::rules::{embedded_rule_files, load_directory, load_embedded};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every `.toml` file under `rules/`, keyed by its path relative to that root.
///
/// Reads the whole tree, including `rules/masking/`, which the detector loader
/// skips. The claim being checked is about the copy of the tree inside the
/// binary, not about which parts of it the scanner reads, and a file that is
/// embedded but never loaded would still be a file that could drift.
fn tree_on_disk() -> BTreeMap<String, Vec<u8>> {
    let root = repo_root().join("rules");
    let mut out = BTreeMap::new();
    collect(&root, "", &mut out);
    assert!(
        !out.is_empty(),
        "no rule file found under {}",
        root.display()
    );
    out
}

fn collect(dir: &Path, prefix: &str, out: &mut BTreeMap<String, Vec<u8>>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.expect("a directory entry");
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("a UTF-8 file name")
            .to_owned();
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        // `symlink_metadata` rather than `is_dir`, so this walk sees the same
        // tree the build script did.
        let metadata = std::fs::symlink_metadata(&path).expect("entry metadata");
        if metadata.is_dir() {
            collect(&path, &relative, out);
        } else if path.extension().is_some_and(|e| e == "toml") {
            out.insert(
                relative,
                std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
            );
        }
    }
}

#[test]
fn the_embedded_rule_set_is_the_rules_tree_byte_for_byte() {
    let disk = tree_on_disk();
    let embedded: BTreeMap<&str, &[u8]> = embedded_rule_files()
        .iter()
        .map(|file| (file.path, file.text.as_bytes()))
        .collect();

    let missing: Vec<&String> = disk
        .keys()
        .filter(|k| !embedded.contains_key(k.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "these rule files are on disk and not in the binary: {missing:?}"
    );

    let extra: Vec<&&str> = embedded
        .keys()
        .filter(|k| !disk.contains_key(**k))
        .collect();
    assert!(
        extra.is_empty(),
        "these rule files are in the binary and not on disk: {extra:?}"
    );

    for (path, bytes) in &disk {
        let compiled = embedded[path.as_str()];
        assert_eq!(
            compiled,
            bytes.as_slice(),
            "{path} differs between the binary and the tree: {} embedded bytes against {} on disk",
            compiled.len(),
            bytes.len()
        );
    }
}

#[test]
fn loading_the_embedded_set_and_the_tree_produces_the_same_rules() {
    // The consequence of the byte equality above, checked at the level the scan
    // works at. `rule_hash` is a hash of the file text, so two rule sets that
    // agree here agree on the digest the report carries and on the finding
    // identities derived from it: a run with `--rules rules` and a run with no
    // flag at all produce the same report.
    let (from_disk, disk_errors) = load_directory(&repo_root().join("rules"));
    let (from_binary, binary_errors) = load_embedded();

    assert!(disk_errors.is_empty(), "{disk_errors:?}");
    assert!(binary_errors.is_empty(), "{binary_errors:?}");

    let disk_ids: Vec<(&str, &str)> = from_disk
        .iter()
        .map(|r| (r.rule_id.as_str(), r.rule_hash.as_str()))
        .collect();
    let binary_ids: Vec<(&str, &str)> = from_binary
        .iter()
        .map(|r| (r.rule_id.as_str(), r.rule_hash.as_str()))
        .collect();

    assert_eq!(disk_ids, binary_ids);
}
