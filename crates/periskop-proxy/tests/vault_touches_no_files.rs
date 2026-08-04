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
//! **When the `file` backend arrives** (`vault.psk`, its own task), this test
//! will fail, and that is the intended behaviour rather than an obstacle. Its
//! author has to add the one module that may touch a disk to `MAY_TOUCH_FILES`
//! below, which makes persistence a decision with a name on it. What must never
//! happen is the allowance being widened to the whole vault.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use periskop_proxy::vault::record::ALIAS_SEED_BYTES;
use periskop_proxy::vault::{
    AliasSeed, OpenRequest, Passphrase, ProfileName, Restored, SessionId, Storage, Vault,
};

/// Vault modules allowed to name a filesystem API.
///
/// Empty, and every entry added here is a place where the alias to person map can
/// reach a disk.
const MAY_TOUCH_FILES: &[&str] = &[];

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
    for source in &sources {
        let name = source
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        if MAY_TOUCH_FILES.contains(&name.as_str()) {
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
