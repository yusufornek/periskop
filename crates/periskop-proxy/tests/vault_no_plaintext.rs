#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
//! **F4 exit criterion 3.** The vault writes nothing outside this process in the
//! clear, demonstrated by searching for planted values byte by byte.
//!
//! `roadmap.md`'s third exit criterion for F4 is one sentence: the vault is local
//! and encrypted by default, and that it puts no plaintext outside the process is
//! *verified by a security test*. This is that test, and milestone 73 fixes what
//! it has to cover.
//!
//! # The surfaces
//!
//! | Surface | What is scanned |
//! |---|---|
//! | the vault file | every byte of `vault.psk` after a full lifecycle |
//! | temporary files | every other file the vault's directory ever holds, including a compaction candidate left behind by a process that was killed |
//! | `TRACE` level output | every `Debug` and `Display` rendering of every vault type a caller can reach, plus every refusal message |
//! | `/admin/*` responses | the body of `GET /admin/vault/status` |
//! | the `ProxyEvent` record | the counters the vault contributes to it |
//!
//! # Two profiles, because one would prove something narrower
//!
//! `milestones.md` is explicit: the run has to happen under the shipped Argon2id
//! profile **and** under `--vault-profile ci`, "aksi hâlde kanıt CI profiline özgü
//! olur". Both are run here and the artefact records which ones were covered. A
//! machine that cannot spare 256 MiB skips the shipped profile loudly, and with
//! `PERISKOP_REQUIRE_PROOF` set it fails instead: that is the setting continuous
//! integration uses, and it is what stops the gate from being quietly narrowed.
//!
//! # What this test cannot cover yet, said out loud
//!
//! Two of the five surfaces do not exist as running code in this crate. There is
//! no logging framework, so "every `TRACE` line" is approximated by every
//! rendering a log line could contain, and there is no `ProxyEvent` type, so its
//! vault contribution is approximated by the counters. Approximations rot, so both
//! are backed by a structural guard: this test reads the crate's own manifest and
//! its own sources, and it **fails** the moment a logging dependency or a
//! serialisation derive appears on a vault type. Whoever adds either has to widen
//! the surface list here in the same change.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use periskop_proxy::vault::{
    AliasSeed, Backing, CounterFloor, OpenRequest, Passphrase, ProfileName, Restored, SessionId,
    Vault, VaultError,
};

/// Set in continuous integration so that a machine that cannot run the shipped
/// profile fails the gate instead of narrowing it. The same switch, and the same
/// reasoning, as `crates/periskop-cli/tests/proof.rs`.
const REQUIRE_PROOF: &str = "PERISKOP_REQUIRE_PROOF";

/// Set by this test on the child it spawns: where the vault to compact lives.
const CHILD_DIRECTORY: &str = "PERISKOP_NO_PLAINTEXT_CHILD_DIR";
/// How long the child waits, in microseconds, before terminating itself.
const CHILD_DELAY_US: &str = "PERISKOP_NO_PLAINTEXT_CHILD_DELAY_US";
/// Which Argon2id profile the child opens under.
const CHILD_PROFILE: &str = "PERISKOP_NO_PLAINTEXT_CHILD_PROFILE";
const KILLED: i32 = 70;

/// The values planted in the vault, and hunted for afterwards.
///
/// Synthetic, and deliberately so: `benchmarks.md`'s data rule and CLAUDE.md's
/// prohibition on periskop being an egress source both mean that no real personal
/// data goes into this repository. Each one is a distinctive byte string, long
/// enough that a chance match in a key, a nonce or a ciphertext is not a thing
/// that happens.
const PLANTED: &[(&str, &str)] = &[
    ("PERSON", "Zeynep Kucukates Ozdemir"),
    ("EMAIL", "zeynep.kucukates@ornek-firma-a.invalid"),
    ("IBAN", "TR889999888877776666555544"),
    ("PHONE", "+90 532 000 44 55"),
    ("NATIONAL_ID", "99988877766"),
    ("SECRET", "sk-periskop-synthetic-3f9a2b7c1d4e"),
    ("ADDRESS", "Kucukayasofya Mahallesi 41/7 Fatih"),
];

/// The alias each planted value is stored under.
///
/// Aliases are not secret: they are the strings that were sent to the provider,
/// and `proxy/spec.md` section 9 lists `alias` among the four fields `TRACE` may
/// carry. They are used here as the **positive control**: the same search that
/// must never find a planted value has to find these, or it is searching nothing.
fn alias_for(kind: &str) -> String {
    format!("PSK_{kind}_1")
}

const NOW: u64 = 1_700_000_000_000;
const LIVE: SessionId = SessionId::from_bytes([0x01; 16]);
const EXPIRED: SessionId = SessionId::from_bytes([0x02; 16]);

// ---------------------------------------------------------------------------
// The child, which leaves a compaction candidate on the disk by dying
// ---------------------------------------------------------------------------

/// A compaction that is killed part way, so that this test has a real temporary
/// file to search rather than a description of one.
///
/// The only way a candidate survives is a process that dies before the rename:
/// every failure path in `vault::compaction` removes it. So the temporary file
/// surface is produced the only way it occurs in the wild.
#[test]
#[ignore = "spawned by the gate below; it terminates itself on purpose"]
fn compaction_child_terminates_itself_mid_run() {
    let Some(directory) = std::env::var_os(CHILD_DIRECTORY) else {
        return;
    };
    let directory = PathBuf::from(directory);
    let delay_us: u64 = std::env::var(CHILD_DELAY_US)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let profile = std::env::var(CHILD_PROFILE)
        .ok()
        .and_then(|name| ProfileName::parse(&name))
        .expect("the parent passes a profile this build knows");

    let mut vault = open_vault(&directory, profile).expect("the parent wrote a vault");
    let at = NOW + vault.limits().ttl_ms + 2;

    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_micros(delay_us));
        std::process::exit(KILLED);
    });
    let _ = vault.compact(at);
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

#[test]
fn f4_gate_no_planted_value_reaches_any_surface_outside_this_process() {
    let required = std::env::var_os(REQUIRE_PROOF).is_some();
    let mut covered = Vec::new();
    let mut skipped = Vec::new();

    for profile in [ProfileName::Ci, ProfileName::Standard] {
        match sweep(profile) {
            Ok(surfaces) => {
                check(profile, &surfaces);
                covered.push(profile.as_str());
            }
            Err(reason) => {
                // The only legitimate reason is a machine that cannot give
                // Argon2id its memory. It is never a reason to call the gate
                // passed, so it is recorded and, in continuous integration, fatal.
                assert!(
                    !required,
                    "{REQUIRE_PROOF} is set and the {} profile could not run: {reason}",
                    profile.as_str()
                );
                eprintln!(
                    "\n  NARROWED: the F4 vault plaintext gate did not run under the {} \
                     profile.\n  Reason: {reason}\n  This run does not close F4 exit criterion \
                     3. Set {REQUIRE_PROOF}=1 to make it a failure instead.\n",
                    profile.as_str()
                );
                skipped.push(profile.as_str());
            }
        }
    }

    // Both structural guards run once: they are about the crate rather than about
    // a profile.
    no_logging_dependency_has_appeared();
    no_vault_type_can_serialise_itself();

    record_outcome(&covered, &skipped);
    assert!(
        covered.contains(&"ci"),
        "the reduced profile must always be runnable"
    );
}

/// Runs a whole vault lifetime under one profile and collects every surface.
fn sweep(profile: ProfileName) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let scratch = Scratch::new(profile.as_str());
    let mut vault = open_vault(&scratch.directory(), profile).map_err(|refusal| {
        // A machine without the memory for the shipped profile lands here, and so
        // would a real defect; the message carries the difference.
        format!("{refusal}")
    })?;

    // Plant every value twice: once in a session that stays live and once in one
    // that compaction will drop, so both the surviving and the discarded halves of
    // the file are covered.
    for (kind, value) in PLANTED {
        vault
            .store_alias(
                &LIVE,
                AliasSeed::from_bytes(seed_for(kind, 1)),
                &alias_for(kind),
                value.as_bytes(),
                NOW + vault.limits().ttl_ms + 1,
            )
            .map_err(|refusal| format!("{refusal}"))?;
        vault
            .store_alias(
                &EXPIRED,
                AliasSeed::from_bytes(seed_for(kind, 2)),
                &format!("PSK_{kind}_2"),
                value.as_bytes(),
                NOW,
            )
            .map_err(|refusal| format!("{refusal}"))?;
    }

    let mut surfaces = BTreeMap::new();

    // The file as `store_alias` left it, **before** anything is compacted away.
    // Reading it only after a compaction would scan the survivors and miss
    // everything the rewrite dropped, which is half the records and the half more
    // likely to be forgotten: a leak that compaction happens to clean up is still
    // a leak that was on the disk. This snapshot is what a mutation writing a
    // value into a frame is caught by.
    for (name, bytes) in scratch.files() {
        surfaces.insert(format!("appended_file:{name}"), bytes);
    }

    surfaces.insert("renderings".to_owned(), renderings(&mut vault).into_bytes());
    surfaces.insert(
        "admin_vault_status".to_owned(),
        vault.status().to_json().into_bytes(),
    );
    surfaces.insert(
        "proxy_event_counters".to_owned(),
        format!("{:?}", vault.counters()).into_bytes(),
    );

    // A compaction, so that the file has been rewritten from `M_0` as well as
    // appended to: both shapes of write are covered.
    let at = NOW + vault.limits().ttl_ms + 2;
    vault.compact(at).map_err(|refusal| format!("{refusal}"))?;
    drop(vault);

    // And a compaction that was killed, so that a real leftover candidate is on
    // the disk when the directory is read.
    let candidate = leave_a_candidate(&scratch, profile)?;
    for (name, bytes) in scratch.files() {
        surfaces.insert(format!("file:{name}"), bytes);
    }
    assert!(
        surfaces.contains_key(&format!("file:{candidate}")),
        "the killed compaction left no candidate to search"
    );

    Ok(surfaces)
}

/// Asserts the claim, on every surface, for every planted value.
fn check(profile: ProfileName, surfaces: &BTreeMap<String, Vec<u8>>) {
    // A scan over nothing passes, so first: there is something to scan.
    assert!(
        surfaces.len() >= 5,
        "{} profile: only {} surfaces collected",
        profile.as_str(),
        surfaces.len()
    );
    for (name, bytes) in surfaces {
        assert!(
            !bytes.is_empty(),
            "{} profile: the {name} surface is empty",
            profile.as_str()
        );
    }

    // The positive control. The same search, on the same surfaces, has to find
    // the aliases: they are in the vault file in the clear by design, and a search
    // that could not find them could not find a plaintext either. Both snapshots
    // of the file are controlled, because a surface that turned out to be empty or
    // stale would make the claim below vacuous on exactly the bytes it covers.
    for name in ["file:vault.psk", "appended_file:vault.psk"] {
        let vault_file = surfaces
            .get(name)
            .unwrap_or_else(|| panic!("{name} is a surface"));
        for (kind, _) in PLANTED {
            assert!(
                contains(vault_file, alias_for(kind).as_bytes()),
                "{} profile: the search cannot find the alias {} in {name}, so it is proving nothing",
                profile.as_str(),
                alias_for(kind)
            );
        }
    }
    // The pre compaction snapshot has to hold the records compaction drops, or it
    // is not the snapshot it claims to be.
    assert!(
        contains(
            surfaces
                .get("appended_file:vault.psk")
                .expect("the appended file is a surface"),
            b"PSK_PERSON_2"
        ),
        "{} profile: the pre compaction snapshot is missing the records compaction drops",
        profile.as_str()
    );
    assert!(
        contains(
            surfaces
                .get("renderings")
                .expect("the renderings are a surface"),
            b"<redacted>"
        ),
        "the renderings surface is not what it claims to be"
    );

    // The claim.
    for (kind, value) in PLANTED {
        for (name, bytes) in surfaces {
            assert!(
                !contains(bytes, value.as_bytes()),
                "{} profile: the planted {kind} value reached the {name} surface in the clear",
                profile.as_str()
            );
        }
    }
}

/// Every rendering of every vault type a caller can reach.
///
/// This stands in for `TRACE` level output: there is no logging framework in this
/// crate yet, so what a log line could carry is exactly what these produce.
/// `proxy/spec.md` section 9 allows four fields at `TRACE` (`entity_type`,
/// `alias`, `offset`, `confidence`) and puts vault content outside every level.
fn renderings(vault: &mut Vault) -> String {
    let mut out = String::new();
    let mut push = |value: String| {
        out.push_str(&value);
        out.push('\n');
    };

    push(format!("{vault:?}"));
    push(format!("{:?}", vault.status()));
    push(format!("{:?}", vault.counters()));
    push(format!("{:?}", vault.storage()));
    push(format!("{:?}", vault.limits()));
    push(format!("{:?}", vault.notes()));
    for note in vault.notes() {
        push(note.to_string());
    }
    push(format!(
        "{:?}",
        Passphrase::new(PLANTED[0].1.as_bytes().to_vec())
    ));

    // A session and the key alias derivation runs under.
    if let Ok(session) = vault.open_session(&LIVE, NOW) {
        push(format!("{session:?}"));
        push(format!("{:?}", session.session_key()));
    }

    // Both answers a restore can give, including the one that carries a value.
    for (kind, _) in PLANTED {
        match vault.restore(&LIVE, &alias_for(kind), NOW) {
            Ok(answer) => {
                if let Restored::Value(value) = &answer {
                    push(format!("{value:?}"));
                }
                push(format!("{answer:?}"));
            }
            Err(refusal) => {
                push(format!("{refusal:?}"));
                push(refusal.to_string());
            }
        }
    }
    push(format!(
        "{:?}",
        vault.restore(&LIVE, "PSK_PERSON_NOBODY", NOW)
    ));

    // Every refusal the vault can produce, rendered both ways. An error message is
    // a log line and a response body at the same time.
    for refusal in refusals() {
        push(format!("{refusal:?}"));
        push(refusal.to_string());
    }
    out
}

/// One of every `VaultError`, so the scan covers all of them rather than the ones
/// this lifecycle happened to produce.
fn refusals() -> Vec<VaultError> {
    vec![
        VaultError::PassphraseMissing,
        VaultError::KeyDerivationFailed,
        VaultError::EntropyUnavailable,
        VaultError::RecordTamper,
        VaultError::AliasCollision,
        VaultError::AliasCeilingReached { ceiling: 10_000 },
        VaultError::KdfParameterOutOfRange {
            parameter: "memory",
            claimed: 1,
            floor: 2,
            ceiling: 3,
        },
        VaultError::IntegrityFailed {
            integrity: periskop_proxy::vault::Integrity::ChainMismatch,
        },
        VaultError::VaultFileMalformed {
            field: periskop_proxy::vault::VaultField::Magic,
        },
        VaultError::VaultFileUnsupported {
            field: periskop_proxy::vault::VaultField::LayoutVersion,
            found: 2000,
        },
        VaultError::VaultFileUnavailable {
            operation: "opened",
            cause: "PermissionDenied".to_owned(),
        },
    ]
}

// ---------------------------------------------------------------------------
// The structural guards
// ---------------------------------------------------------------------------

/// The surface list above is complete only while there is no logger.
///
/// The moment one is added, `TRACE` output stops being "whatever a `Debug` would
/// have printed" and becomes a real stream with its own sinks and its own files.
/// This fails then, on purpose, so that the person adding it extends the sweep
/// rather than inheriting a gate that quietly covers less than it says.
fn no_logging_dependency_has_appeared() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("this crate has a manifest");

    // Dependency lines only. Matching anywhere in the file would make a comment
    // containing the word "log" fail the gate, and a guard that cries wolf is a
    // guard somebody deletes.
    let named: Vec<&str> = manifest
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once('=').map(|(name, _)| name.trim()))
        .collect();

    for logger in [
        "tracing",
        "log",
        "slog",
        "env_logger",
        "fern",
        "tracing-subscriber",
    ] {
        assert!(
            !named.contains(&logger),
            "`{logger}` is a dependency of this crate now, so TRACE output is a real \
             surface. Add its sink to the sweep in this test before removing this check."
        );
    }
}

/// The `ProxyEvent` surface is a projection, and it stays one only while no vault
/// type can serialise itself.
///
/// The event record is written by a later task. If a vault type ever derives
/// `Serialize`, an event could carry a record without anybody deciding to, which
/// is exactly the shape of accident this gate exists to catch.
fn no_vault_type_can_serialise_itself() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/vault");
    let mut sources = Vec::new();
    collect_sources(&root, &mut sources);
    assert!(
        sources.len() >= 8,
        "only {} vault sources found under {}",
        sources.len(),
        root.display()
    );

    let mut offences = Vec::new();
    for source in &sources {
        let text = std::fs::read_to_string(source).expect("a vault source");
        for (number, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            for marker in ["Serialize", "Deserialize", "serde"] {
                if code.contains(marker) {
                    offences.push(format!(
                        "{}:{} names {marker}",
                        source.file_name().unwrap_or_default().to_string_lossy(),
                        number + 1
                    ));
                }
            }
        }
    }
    assert!(
        offences.is_empty(),
        "a vault type can serialise itself, so a ProxyEvent could carry one: {offences:#?}"
    );
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

fn open_vault(directory: &Path, profile: ProfileName) -> Result<Vault, VaultError> {
    Vault::open(&OpenRequest {
        passphrase: &Passphrase::new(b"the operator typed this".to_vec()),
        profile,
        backing: Backing::File {
            path: &directory.join("vault.psk"),
            floor: CounterFloor::Unknown,
        },
    })
}

fn seed_for(kind: &str, salt: u8) -> [u8; 32] {
    let mut seed = [salt; 32];
    for (at, byte) in kind.bytes().enumerate().take(31) {
        seed[at + 1] = byte;
    }
    seed
}

/// Kills a compaction until a candidate is left behind, and returns its name.
///
/// Retried rather than timed: the window is short and a machine under load may
/// miss it, and a gate that skipped a surface because the timing did not work out
/// would be a gate that covers less on a busy day than on a quiet one.
fn leave_a_candidate(scratch: &Scratch, profile: ProfileName) -> Result<String, String> {
    let before: Vec<String> = scratch.files().into_keys().collect();
    for delay_us in [100u64, 250, 500, 900, 1_400, 2_200, 3_500, 5_000] {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "compaction_child_terminates_itself_mid_run",
                "--ignored",
                "--test-threads=1",
            ])
            .env(CHILD_DIRECTORY, scratch.directory())
            .env(CHILD_DELAY_US, delay_us.to_string())
            .env(CHILD_PROFILE, profile.as_str())
            .output()
            .map_err(|cause| format!("{cause}"))?;
        assert_eq!(
            status.status.code(),
            Some(KILLED),
            "the child ended some other way: {}",
            String::from_utf8_lossy(&status.stderr)
        );

        // A candidate with nothing in it is a file the kill landed before the
        // first write reached; it is a real outcome and a useless surface, so the
        // search keeps going until there are bytes to look through.
        if let Some((candidate, _)) = scratch
            .files()
            .into_iter()
            .find(|(name, bytes)| !before.contains(name) && !bytes.is_empty())
        {
            return Ok(candidate);
        }
        // Whatever this run left is not a surface; clear it so the next attempt
        // starts from the same place.
        for (name, bytes) in scratch.files() {
            if !before.contains(&name) && bytes.is_empty() {
                let _ = std::fs::remove_file(scratch.directory().join(name));
            }
        }
    }
    Err("no run of the killed compaction left a candidate with bytes in it".to_owned())
}

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "periskop-vault-plaintext-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("vault")).unwrap();
        Self { root }
    }

    fn directory(&self) -> PathBuf {
        self.root.join("vault")
    }

    /// Every file under the vault's directory, by name and by content.
    fn files(&self) -> BTreeMap<String, Vec<u8>> {
        let mut found = BTreeMap::new();
        collect_files(&self.directory(), &mut found);
        found
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn collect_files(root: &Path, found: &mut BTreeMap<String, Vec<u8>>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, found);
        } else if let Ok(bytes) = std::fs::read(&path) {
            found.insert(
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                bytes,
            );
        }
    }
}

fn collect_sources(root: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_sources(&path, found);
        } else if path.extension().is_some_and(|kind| kind == "rs") {
            found.push(path);
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// What this run established, written where a release check can read it.
///
/// A gate that ran under one profile and a gate that ran under both leave the same
/// green line in the test output, so the difference goes in a file. The planted
/// values are counted rather than listed: an artefact that carried them would be
/// the leak this test is about.
fn record_outcome(covered: &[&str], skipped: &[&str]) {
    let status = if skipped.is_empty() {
        "passed"
    } else {
        "narrowed"
    };
    let list = |names: &[&str]| {
        names
            .iter()
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(",")
    };

    let record = format!(
        "{{\n  \"gate\": \"F4-73\",\n  \"criterion\": \"roadmap.md F4 exit criterion 3\",\n  \
         \"status\": \"{status}\",\n  \"profiles_covered\": [{}],\n  \"profiles_skipped\": [{}],\n  \
         \"planted_values\": {},\n  \"surfaces\": [\"vault_file\",\"temporary_files\",\
         \"renderings\",\"admin_vault_status\",\"proxy_event_counters\"],\n  \
         \"caveat\": \"There is no logging framework and no ProxyEvent type in this crate yet. \
         The TRACE surface is approximated by every Debug and Display rendering a log line could \
         contain, and the event surface by the counters the vault contributes. Both are held in \
         place by structural guards that fail when a logger or a serialisation derive appears.\"\n}}\n",
        list(covered),
        list(skipped),
        PLANTED.len()
    );

    let out =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/f4-vault-no-plaintext-proof.json");
    if let Some(parent) = out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&out, record);
}
