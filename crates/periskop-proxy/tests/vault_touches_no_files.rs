#![allow(clippy::unwrap_used, clippy::panic)]
//! The default configuration writes nothing to a disk, checked two ways.
//!
//! CLAUDE.md's list of prohibitions opens with this one: a default configuration
//! that puts the masking vault outside the process is forbidden. ADR-007 makes
//! `memory` the default backend for the reason behind that prohibition, which is
//! that the map from alias back to a real person is the most concentrated
//! personal data this product ever holds, and writing it down creates the pile
//! periskop exists to argue against.
//!
//! A promise of that shape needs a test that fails when it stops being true, and
//! "we did not write any file code" is not one. So there are two here:
//!
//! 1. **Watching.** A whole vault lifetime runs, from passphrase to purge, with
//!    the working directory and `~/.periskop` listed before and after. Any new,
//!    removed or resized entry fails.
//! 2. **Reading our own source.** Every module under `src/vault/` is scanned for
//!    the names of filesystem APIs, and there are no exceptions. This is the same
//!    device ADR-014 used for its `unsafe` boundary, and it is here for the same
//!    reason: a boundary written down before anything crosses it is a boundary,
//!    and one written afterwards is a description.
//!
//! **The `file` backend has arrived** (`vault.psk`, milestone 71 and 72) and this
//! test did fail, which was the intended behaviour rather than an obstacle. Two
//! modules were added to `MAY_TOUCH_FILES` below, by name and with a reason, so
//! that persistence is a decision somebody signed rather than an edit. What must
//! never happen is the allowance being widened to the whole vault: the facade, the
//! keys, the records, the sessions, the byte layout and the chain are all still
//! scanned, and none of them may open a file.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use periskop_proxy::vault::record::ALIAS_SEED_BYTES;
use periskop_proxy::vault::{
    AliasSeed, Backing, OpenRequest, Passphrase, ProfileName, Restored, SessionId, Storage, Vault,
};

/// Vault modules allowed to name a filesystem API.
///
/// Every entry here is a place where the alias to person map can reach a disk, so
/// every entry carries the reason it is allowed to:
///
/// - **`file.rs`** owns `vault.psk`: it creates the file, reads it back, verifies
///   the chain over it and appends to it. It is the `file` backend
///   (`proxy/spec.md` section 9), which is opt in and is not the default.
/// - **`compaction.rs`** owns the swap: it writes the rebuilt file beside the old
///   one and renames it over. ADR-007 requires the rename to be atomic, and a
///   rename is a filesystem call.
///
/// Nothing else may appear here. In particular `mod.rs` may not: the facade
/// decides *whether* records are persisted, and if it could also write them the
/// two modules above would stop being the whole of the disk surface. The
/// `file`-backed tests of the facade live in `tests/vault_file_backend.rs` for
/// exactly that reason.
const MAY_TOUCH_FILES: &[&str] = &["file.rs", "compaction.rs"];

/// What a filesystem call looks like in this codebase.
///
/// Names rather than behaviour, which makes this a screen and not a proof: it
/// catches the ordinary way a write appears, in a review or a merge, rather than
/// a determined attempt to hide one. The watching test above is what covers
/// behaviour.
const FILESYSTEM_APIS: &[&str] = &[
    "std::fs",
    "fs::",
    "File::",
    "OpenOptions",
    "create_dir",
    "remove_file",
    "remove_dir",
    "read_to_string",
    "tempfile",
];

#[test]
fn a_whole_vault_lifetime_leaves_the_filesystem_as_it_found_it() {
    let working = std::env::current_dir().unwrap();
    let home_vault = std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".periskop"));
    let before = listing(&working, home_vault.as_deref());

    let now = 1_700_000_000_000;
    // The real opening path, key derivation included. A vault that cached a salt,
    // a derived key or a session would do it here.
    let mut vault = Vault::open(&OpenRequest {
        passphrase: &Passphrase::new(b"the operator typed this".to_vec()),
        // The reduced profile, because this test is about the filesystem and not
        // about how long Argon2id takes.
        profile: ProfileName::Ci,
        // The default backing, written out rather than left implicit: the claim
        // being tested is about what the default configuration does, and a default
        // that has to be named is a default a reader can check.
        backing: Backing::Memory,
    })
    .unwrap();
    assert_eq!(vault.storage(), Storage::Memory);

    let session = SessionId::generate().unwrap();
    vault
        .store_alias(
            &session,
            AliasSeed::from_bytes([1u8; ALIAS_SEED_BYTES]),
            "PSK_PERSON_1",
            b"Ahmet Yilmaz",
            now,
        )
        .unwrap();
    vault
        .store_alias(
            &session,
            AliasSeed::from_bytes([2u8; ALIAS_SEED_BYTES]),
            "PSK_PERSON_2",
            b"Ayse Demir",
            now,
        )
        .unwrap();
    assert!(matches!(
        vault.restore(&session, "PSK_PERSON_1", now).unwrap(),
        Restored::Value(_)
    ));
    vault.purge_expired(now + vault.limits().ttl_ms + 1);
    drop(vault);

    let after = listing(&working, home_vault.as_deref());
    assert_eq!(
        after,
        before,
        "the vault touched the filesystem: {:?}",
        after.symmetric_difference(&before).collect::<Vec<_>>()
    );
}

#[test]
fn no_vault_module_names_a_filesystem_api() {
    let vault_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/vault");
    let mut sources = Vec::new();
    collect_rust_sources(&vault_root, &mut sources);

    // A scan that found nothing to scan would pass silently, which is the failure
    // shape this repository has been bitten by before.
    assert!(
        sources.len() >= 5,
        "only {} vault sources found under {}",
        sources.len(),
        vault_root.display()
    );

    let mut offences = Vec::new();
    let mut allowance_used: BTreeSet<&str> = BTreeSet::new();
    for source in &sources {
        let name = source
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        if let Some(allowed) = MAY_TOUCH_FILES.iter().find(|entry| **entry == name) {
            if names_a_filesystem_api(source) {
                allowance_used.insert(allowed);
            }
            continue;
        }

        let text = std::fs::read_to_string(source).unwrap();
        for (number, line) in text.lines().enumerate() {
            let code = line.trim_start();
            // A comment is not a call. The module documentation in this tree talks
            // about files at length, which is the point of it.
            if code.starts_with("//") {
                continue;
            }
            for api in FILESYSTEM_APIS {
                if code.contains(api) {
                    offences.push(format!("{name}:{} names {api}", number + 1));
                }
            }
        }
    }

    assert!(offences.is_empty(), "{offences:#?}");

    // An exception nobody needs is an exception that quietly widens the boundary
    // the next time somebody adds a file. Every name on the list has to be a
    // module that actually writes, or it comes off the list.
    let unused: Vec<&&str> = MAY_TOUCH_FILES
        .iter()
        .filter(|entry| !allowance_used.contains(**entry))
        .collect();
    assert!(
        unused.is_empty(),
        "these modules are allowed to touch files and do not: {unused:?}"
    );
}

/// Whether one source names a filesystem API, by the same screen the scan uses.
fn names_a_filesystem_api(source: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(source) else {
        return false;
    };
    text.lines()
        .map(str::trim_start)
        .filter(|code| !code.starts_with("//"))
        .any(|code| FILESYSTEM_APIS.iter().any(|api| code.contains(api)))
}

/// Every path under the watched roots, with the size that would change if a file
/// were rewritten where it stands.
fn listing(working: &Path, home_vault: Option<&Path>) -> BTreeSet<(PathBuf, u64)> {
    let mut seen = BTreeSet::new();
    list_into(working, &mut seen);
    if let Some(home_vault) = home_vault {
        list_into(home_vault, &mut seen);
    }
    seen
}

fn list_into(root: &Path, seen: &mut BTreeSet<(PathBuf, u64)>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        // A root that is not there is a perfectly good answer: it stays not
        // there, and the comparison below notices if it appears.
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let size = entry.metadata().map(|data| data.len()).unwrap_or_default();
        seen.insert((path.clone(), size));
        if path.is_dir() {
            list_into(&path, seen);
        }
    }
}

fn collect_rust_sources(root: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, found);
        } else if path.extension().is_some_and(|kind| kind == "rs") {
            found.push(path);
        }
    }
}
