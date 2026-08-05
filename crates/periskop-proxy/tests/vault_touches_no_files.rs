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
//! 2. **Reading our own source.** Every module under `src/` is scanned for the
//!    names of filesystem APIs, against a written allowance. This is the same
//!    device ADR-014 used for its `unsafe` boundary, and it is here for the same
//!    reason: a boundary written down before anything crosses it is a boundary,
//!    and one written afterwards is a description.
//!
//! **The `file` backend has arrived** (`vault.psk`, milestone 71 and 72) and this
//! test did fail, which was the intended behaviour rather than an obstacle. Two
//! modules were added to `MAY_TOUCH_FILES` below, by path and with a reason, so
//! that persistence is a decision somebody signed rather than an edit. What must
//! never happen is the allowance being widened to the whole vault: the facade, the
//! keys, the records, the sessions, the byte layout and the chain are all still
//! scanned, and none of them may open a file.
//!
//! # Why the scan is the crate and not the vault subtree
//!
//! It read `src/vault` alone, and the claim it was making is not a claim about a
//! directory. The thing that may not reach a disk is the map from alias back to a
//! real person, and that map is at its widest **outside** the vault: it is read
//! out of a request body in `http`, scanned in `detect`, minted in `alias` and put
//! back into an answer in `http::stream`. A `std::fs::write` of a request record,
//! a findings dump or a debug snapshot in any of those modules was a new disk
//! surface that this scan could not see, while the file's own summary said the
//! default configuration writes nothing to a disk. `vault_no_plaintext.rs`'s
//! `no_source_writes_to_a_process_stream` had exactly this hole and was widened
//! for exactly this reason; this is the other half of the same correction.
//!
//! Widening the scan means the allowance has to name **paths** rather than file
//! names. A bare `file.rs` was unambiguous inside one directory and would hand a
//! future `src/http/file.rs` the vault backend's permission the day somebody
//! created it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use periskop_proxy::vault::{
    AliasSeed, Backing, OpenRequest, Passphrase, ProfileName, Restored, SessionId, Storage, Vault,
    ALIAS_SEED_BYTES,
};

/// Modules of this crate allowed to name a filesystem API, by path under `src/`.
///
/// Paths and not file names: the scan covers the whole crate, and a bare
/// `file.rs` would silently extend the vault backend's permission to any future
/// module that happened to be called the same thing.
///
/// The first two are the only places the alias to person map can reach a disk,
/// and each carries the reason it is allowed to:
///
/// - **`vault/file.rs`** owns `vault.psk`: it creates the file, reads it back,
///   verifies the chain over it and appends to it. It is the `file` backend
///   (`proxy/spec.md` section 9), which is opt in and is not the default.
/// - **`vault/compaction.rs`** owns the swap: it writes the rebuilt file beside
///   the old one and renames it over. ADR-007 requires the rename to be atomic,
///   and a rename is a filesystem call.
///
/// The next three came with the widening and are reads of configuration, in the
/// opposite direction to the one this test is about. They are listed rather than
/// waved through, because "it only reads" is a claim about today's code and this
/// list is what makes changing it a decision:
///
/// - **`policy/load.rs`** reads the policy document and the dictionary the policy
///   points at. Both are operator authored input; nothing derived from a prompt
///   travels back out through it.
/// - **`detect/affix.rs`** reads `rules/masking/<language>/affixes.toml`, which is
///   rule data shipped with the build.
/// - **`alias/entity.rs`** reads `schemas/proxy-policy.schema.json` in its own
///   test, so that the entity registry and the contract's closed set cannot drift
///   apart unnoticed.
///
/// Nothing else may appear here. In particular `vault/mod.rs` may not: the facade
/// decides *whether* records are persisted, and if it could also write them the
/// two modules above would stop being the whole of the disk surface. The
/// `file`-backed tests of the facade live in `tests/vault_file_backend.rs` for
/// exactly that reason.
const MAY_TOUCH_FILES: &[&str] = &[
    "vault/file.rs",
    "vault/compaction.rs",
    "policy/load.rs",
    "detect/affix.rs",
    "alias/entity.rs",
];

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
    let watched = Watched {
        working: &working,
        home_vault: home_vault.as_deref(),
        temporary: &std::env::temp_dir(),
    };
    let before = listing(&watched);

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

    let after = listing(&watched);
    assert_eq!(
        after,
        before,
        "the vault touched the filesystem: {:?}",
        after.symmetric_difference(&before).collect::<Vec<_>>()
    );
}

#[test]
fn no_module_of_this_crate_names_a_filesystem_api_without_an_allowance() {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    collect_rust_sources(&source_root, &mut sources);

    // A scan that found nothing to scan would pass silently, which is the failure
    // shape this repository has been bitten by before. The floor is the crate
    // rather than the vault subtree now, so it is a number this crate cannot fall
    // below without somebody having deleted most of it.
    assert!(
        sources.len() >= 40,
        "only {} sources found under {}, so this scan is reading a fraction of the crate",
        sources.len(),
        source_root.display()
    );
    // And the vault is inside what was read, because it is the subtree the claim
    // at the top of this file is about.
    assert!(
        sources.iter().any(|path| path.ends_with("vault/record.rs")),
        "the scan did not reach the vault sources"
    );

    let mut offences = Vec::new();
    let mut allowance_used: BTreeSet<&str> = BTreeSet::new();
    for source in &sources {
        let path = relative_to(&source_root, source);
        if let Some(allowed) = MAY_TOUCH_FILES.iter().find(|entry| **entry == path) {
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
                    offences.push(format!("{path}:{} names {api}", number + 1));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "a module of this crate names a filesystem API and is not on MAY_TOUCH_FILES. \
         The alias to person map is at its widest outside the vault, so a write here is \
         a disk surface nothing else in this repository is looking at: {offences:#?}"
    );

    // An exception nobody needs is an exception that quietly widens the boundary
    // the next time somebody adds a file. Every path on the list has to be a
    // module that actually names one, or it comes off the list.
    let unused: Vec<&&str> = MAY_TOUCH_FILES
        .iter()
        .filter(|entry| !allowance_used.contains(**entry))
        .collect();
    assert!(
        unused.is_empty(),
        "these modules are allowed to touch files and do not: {unused:?}"
    );
}

/// A source path as the allowance list spells it: relative to `src/`, with
/// forward slashes.
fn relative_to(root: &Path, source: &Path) -> String {
    source
        .strip_prefix(root)
        .unwrap_or(source)
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<String>>()
        .join("/")
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

/// The three places a vault would leave something behind.
struct Watched<'a> {
    working: &'a Path,
    home_vault: Option<&'a Path>,
    /// `$TMPDIR`, which was missing and is where a scratch file lands by default.
    ///
    /// A vault that wrote a temporary copy while it worked would put it here and
    /// neither of the other two roots would notice, which made "nothing was
    /// written" a claim about two of the three plausible destinations.
    temporary: &'a Path,
}

/// Every path under the watched roots, with the size that would change if a file
/// were rewritten where it stands.
fn listing(watched: &Watched<'_>) -> BTreeSet<(PathBuf, u64)> {
    let mut seen = BTreeSet::new();
    list_into(watched.working, &mut seen);
    if let Some(home_vault) = watched.home_vault {
        list_into(home_vault, &mut seen);
    }
    list_named_into(watched.temporary, &mut seen);
    seen
}

/// The entries of `$TMPDIR` this product could have written, and only those.
///
/// The whole directory is shared with the rest of the machine, so a full listing
/// would fail whenever anything else on the system happened to write a file during
/// the lifetime above, and a test that fails for reasons outside its subject is a
/// test people learn to rerun. Screening by name keeps the check pointed at what it
/// is about: nothing carrying this product's or this vault's name appeared. That is
/// a screen and not a proof, exactly as the source scan below is.
fn list_named_into(root: &Path, seen: &mut BTreeSet<(PathBuf, u64)>) {
    const OURS: &[&str] = &["periskop", "vault", "psk"];

    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        if !OURS.iter().any(|ours| name.contains(ours)) {
            continue;
        }
        let path = entry.path();
        let size = entry.metadata().map(|data| data.len()).unwrap_or_default();
        seen.insert((path.clone(), size));
        if path.is_dir() {
            list_into(&path, seen);
        }
    }
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
