#![allow(clippy::unwrap_used, clippy::panic)]
//! The `file` backend seen from outside: a vault that survives a restart, and the
//! three ways it refuses to open.
//!
//! These are the facade's tests rather than the file module's, and they live here
//! rather than in `src/vault/mod.rs` because of the boundary in
//! `vault_touches_no_files.rs`: that scan reads every vault module, test modules
//! included, and only `file.rs` and `compaction.rs` may name a filesystem call.
//! Keeping the facade off that list is what keeps the list worth reading.
//!
//! What is checked here is milestone 71's acceptance criterion in the words it was
//! written in: each of the three violations is exercised separately, none of them
//! opens the vault, each answers 503, each carries the right `integrity` value,
//! and no recovery is attempted.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use periskop_proxy::vault::{
    AliasSeed, Backing, CounterFloor, Integrity, OpenRequest, Passphrase, ProfileName, Restored,
    SessionId, Storage, UnresolvedReason, Vault, VaultError, VaultField, VaultState,
};

const AHMET: &[u8] = b"Ahmet Yilmaz";
const AYSE: &[u8] = b"Ayse Demir";
const NOW: u64 = 1_700_000_000_000;

/// A throwaway directory, written out rather than pulled in: a test only
/// dependency is still a dependency decision, and this needs a few lines (the
/// same reasoning `crates/periskop-cli/tests/proof.rs` records).
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "periskop-vault-backend-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn vault(&self) -> PathBuf {
        self.root.join("vault.psk")
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.root)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn passphrase() -> Passphrase {
    Passphrase::new(b"the operator typed this".to_vec())
}

/// Opens under the reduced profile, because these tests are about the file format
/// and not about how long Argon2id takes. The shipped profile is exercised by
/// `vault_no_plaintext.rs`, which runs under both.
fn on_file(path: &Path, floor: CounterFloor) -> Result<Vault, VaultError> {
    // One derivation at a time. Argon2id is asked for its profile's whole memory
    // and this binary runs its tests in parallel, so several at once is several
    // times that allocated together; unbounded parallelism here locked a machine
    // once. Taken and released around the one call that derives, which is the only
    // place in this file that does, so it cannot nest.
    let _permit = one_derivation_at_a_time();
    Vault::open(&OpenRequest {
        passphrase: &passphrase(),
        profile: ProfileName::Ci,
        backing: Backing::File { path, floor },
    })
}

fn one_derivation_at_a_time() -> MutexGuard<'static, ()> {
    static PERMIT: Mutex<()> = Mutex::new(());
    // What the permit protects is memory rather than state, so a poisoning left by
    // a failed test does not turn one failure into every failure.
    PERMIT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn seed(byte: u8) -> AliasSeed {
    AliasSeed::from_bytes([byte; 32])
}

/// Where each frame really starts and ends, read the way the reader reads it:
/// from each frame's own length word.
///
/// Written out because the records in these files are **not** the same size. The
/// values behind them differ in length, so dividing the record region by the
/// number of records lands in the middle of a frame, and a test that moved such a
/// slice was corrupting a frame while claiming to move a whole record. That
/// difference was invisible while every structural failure was answered with
/// `chain_mismatch`, and it is the reason these two tests are written this way.
fn frame_bounds(bytes: &[u8]) -> Vec<std::ops::Range<usize>> {
    const HEADER_BYTES: usize = 128;
    const FRAME_HEAD_BYTES: usize = 96;

    let mut bounds = Vec::new();
    let mut at = HEADER_BYTES;
    while at + FRAME_HEAD_BYTES <= bytes.len() {
        let length = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        assert!(
            length >= FRAME_HEAD_BYTES,
            "frame at {at} declares {length}"
        );
        bounds.push(at..at + length);
        at += length;
    }
    assert_eq!(at, bytes.len(), "the frames do not tile the file");
    bounds
}

/// Two records, and the bytes of the honest file they produce.
fn seeded(scratch: &Scratch, session: &SessionId) -> Vec<u8> {
    let mut vault = on_file(&scratch.vault(), CounterFloor::Unknown).unwrap();
    vault
        .store_alias(session, seed(1), "PSK_PERSON_1", AHMET, NOW)
        .unwrap();
    vault
        .store_alias(session, seed(2), "PSK_PERSON_2", AYSE, NOW)
        .unwrap();
    drop(vault);
    std::fs::read(scratch.vault()).unwrap()
}

/// The point of persistence: a restart keeps the conversation readable.
#[test]
fn a_file_backed_vault_restores_its_mappings_after_a_restart() {
    let scratch = Scratch::new("restart");
    let session = SessionId::from_bytes([0x11; 16]);
    seeded(&scratch, &session);

    let mut restarted = on_file(&scratch.vault(), CounterFloor::AtLeast(2)).unwrap();
    assert_eq!(restarted.storage(), Storage::File);
    match restarted.restore(&session, "PSK_PERSON_1", NOW).unwrap() {
        Restored::Value(value) => assert_eq!(value.expose(), AHMET),
        other => panic!("{other:?}"),
    }
    match restarted.restore(&session, "PSK_PERSON_2", NOW).unwrap() {
        Restored::Value(value) => assert_eq!(value.expose(), AYSE),
        other => panic!("{other:?}"),
    }
    assert_eq!(restarted.status().entries(), 2);
    assert_eq!(restarted.record_counter(), Some(2));
}

/// A record is bound to its slot on disk exactly as it is in memory.
#[test]
fn a_restored_vault_still_refuses_an_alias_it_never_published() {
    let scratch = Scratch::new("unknown-alias");
    let session = SessionId::from_bytes([0x12; 16]);
    seeded(&scratch, &session);

    let mut restarted = on_file(&scratch.vault(), CounterFloor::Unknown).unwrap();
    assert!(matches!(
        restarted.restore(&session, "PSK_PERSON_9", NOW).unwrap(),
        Restored::Unresolved(UnresolvedReason::AliasUnknown)
    ));

    let elsewhere = SessionId::from_bytes([0x99; 16]);
    assert!(matches!(
        restarted.restore(&elsewhere, "PSK_PERSON_1", NOW).unwrap(),
        Restored::Unresolved(UnresolvedReason::SessionUnknown)
    ));
}

#[test]
fn a_repeated_value_does_not_append_a_second_record() {
    let scratch = Scratch::new("repeat");
    let session = SessionId::from_bytes([0x22; 16]);
    let mut vault = on_file(&scratch.vault(), CounterFloor::Unknown).unwrap();

    for _ in 0..5 {
        vault
            .store_alias(&session, seed(1), "PSK_PERSON_1", AHMET, NOW)
            .unwrap();
    }
    // A long conversation about one customer must not grow the file without
    // bound, and the counter is where that would show.
    assert_eq!(vault.record_counter(), Some(1));
}

/// Compaction is the disk half of the time to live (milestone 72).
#[test]
fn compaction_keeps_what_is_live_and_forgets_the_rest_on_disk_too() {
    let scratch = Scratch::new("compact");
    let old = SessionId::from_bytes([0x01; 16]);
    let fresh = SessionId::from_bytes([0x02; 16]);

    let mut vault = on_file(&scratch.vault(), CounterFloor::Unknown).unwrap();
    vault
        .store_alias(&old, seed(1), "PSK_PERSON_1", AHMET, NOW)
        .unwrap();
    let later = NOW + vault.limits().ttl_ms;
    vault
        .store_alias(&fresh, seed(2), "PSK_PERSON_2", AYSE, later)
        .unwrap();

    let outcome = vault.compact(later + 1).unwrap().unwrap();
    assert_eq!(outcome.before, 2);
    assert_eq!(outcome.after, 1);
    assert_eq!(outcome.dropped(), 1);
    let counter = vault.record_counter().unwrap();
    drop(vault);

    // The counter did not go backwards, so the compacted file opens against the
    // floor from before it.
    let mut restarted = on_file(&scratch.vault(), CounterFloor::AtLeast(counter)).unwrap();
    assert_eq!(restarted.status().entries(), 1);
    assert!(matches!(
        restarted.restore(&old, "PSK_PERSON_1", later + 1).unwrap(),
        Restored::Unresolved(UnresolvedReason::SessionUnknown)
    ));
    assert!(matches!(
        restarted
            .restore(&fresh, "PSK_PERSON_2", later + 1)
            .unwrap(),
        Restored::Value(_)
    ));
    assert_eq!(scratch.names(), vec!["vault.psk".to_owned()]);
}

/// Violation one of three: the record set is not the one the header signed.
///
/// Two shapes, and the second one is the load bearing half. Cutting bytes off the
/// end is caught even by a reader that only counts frames, so a test that stopped
/// there would stay green with the chain comparison deleted; that was found by
/// deleting it. Flipping one byte inside a record leaves the file exactly as long,
/// with exactly as many frames, all of them structurally perfect: the chain is the
/// only thing that can see it.
#[test]
fn chain_mismatch_does_not_open_the_vault_and_repairs_nothing() {
    let scratch = Scratch::new("chain");
    let session = SessionId::from_bytes([0x44; 16]);
    let honest = seeded(&scratch, &session);

    // Shape one: the tail of the last record goes away.
    let truncated = honest[..honest.len() - 40].to_vec();
    std::fs::write(scratch.vault(), &truncated).unwrap();
    let refusal = on_file(&scratch.vault(), CounterFloor::Unknown).unwrap_err();
    assert_eq!(refusal.integrity(), Some(Integrity::ChainMismatch));
    assert_eq!(refusal.http_status(), 503);
    no_recovery_was_attempted(&scratch, &truncated, CounterFloor::Unknown);

    // Shape two: one byte inside the first record's sealed body, same length,
    // same frame count, same structure.
    let mut edited = honest.clone();
    let inside_the_first_record = 128 + 96 + 4;
    edited[inside_the_first_record] ^= 0x01;
    assert_eq!(edited.len(), honest.len());
    std::fs::write(scratch.vault(), &edited).unwrap();

    let refusal = on_file(&scratch.vault(), CounterFloor::Unknown).unwrap_err();
    assert_eq!(
        refusal.integrity(),
        Some(Integrity::ChainMismatch),
        "a same length edit inside a record has to be caught at open, not at restore"
    );
    assert_eq!(refusal.http_status(), 503);
    no_recovery_was_attempted(&scratch, &edited, CounterFloor::Unknown);

    // Shape three: two records exchanged, on their real boundaries, so that both
    // frames still decode perfectly and the chain is once again the only thing
    // that can tell.
    let frames = frame_bounds(&honest);
    assert_eq!(frames.len(), 2);
    let mut swapped = honest[..128].to_vec();
    swapped.extend_from_slice(&honest[frames[1].clone()]);
    swapped.extend_from_slice(&honest[frames[0].clone()]);
    assert_eq!(swapped.len(), honest.len());
    assert_ne!(swapped, honest);
    std::fs::write(scratch.vault(), &swapped).unwrap();

    let refusal = on_file(&scratch.vault(), CounterFloor::Unknown).unwrap_err();
    assert_eq!(refusal.integrity(), Some(Integrity::ChainMismatch));
    no_recovery_was_attempted(&scratch, &swapped, CounterFloor::Unknown);
}

/// The scenario the acceptance criterion names in as many words: a record is cut
/// out of the **middle** of the file.
#[test]
fn chain_mismatch_a_record_removed_from_the_middle_does_not_open_the_vault() {
    let scratch = Scratch::new("chain-middle");
    let session = SessionId::from_bytes([0x47; 16]);

    // Three records, so that there is a middle to remove.
    let mut vault = on_file(&scratch.vault(), CounterFloor::Unknown).unwrap();
    for (byte, value) in [(1u8, AHMET), (2, AYSE), (3, b"Mehmet Kaya".as_slice())] {
        vault
            .store_alias(
                &session,
                seed(byte),
                &format!("PSK_PERSON_{byte}"),
                value,
                NOW,
            )
            .unwrap();
    }
    drop(vault);

    let honest = std::fs::read(scratch.vault()).unwrap();
    let frames = frame_bounds(&honest);
    assert_eq!(frames.len(), 3);
    let mut without_the_middle = honest[..frames[1].start].to_vec();
    without_the_middle.extend_from_slice(&honest[frames[2].clone()]);
    std::fs::write(scratch.vault(), &without_the_middle).unwrap();

    let refusal = on_file(&scratch.vault(), CounterFloor::Unknown).unwrap_err();
    assert_eq!(refusal.integrity(), Some(Integrity::ChainMismatch));
    assert_eq!(refusal.http_status(), 503);
    no_recovery_was_attempted(&scratch, &without_the_middle, CounterFloor::Unknown);
}

/// A length field that no longer describes its own frame is a corrupt file, and
/// reporting `chain_mismatch` for it hands the operator the wrong remedy.
///
/// The two failures need opposite moves. A corrupt file is restored from a backup
/// and the machine keeps working; a chain violation means somebody wrote to the
/// vault and the machine is evidence that must not be touched. `proxy/spec.md`
/// section 10 keeps them in two rows for that reason ("dur, ortamı düzelt" against
/// "durdur ve incele"), and `integrity` is how a client tells the rows apart.
///
/// Nothing is missing here: every byte the header counted is still on disk, and
/// only the field that describes them disagrees with them.
#[test]
fn a_corrupt_frame_length_is_a_malformed_file_and_not_a_tampering_report() {
    let scratch = Scratch::new("frame-length");
    let session = SessionId::from_bytes([0x48; 16]);
    let honest = seeded(&scratch, &session);

    // The first frame's own length word, one byte longer than the fields inside
    // the frame add up to.
    let declared = u32::from_le_bytes(honest[128..132].try_into().unwrap());
    let mut corrupt = honest.clone();
    corrupt[128..132].copy_from_slice(&(declared + 1).to_le_bytes());
    assert_eq!(corrupt.len(), honest.len());
    std::fs::write(scratch.vault(), &corrupt).unwrap();

    let refusal = on_file(&scratch.vault(), CounterFloor::Unknown).unwrap_err();
    assert_eq!(refusal.http_status(), 503);
    assert_eq!(
        refusal.integrity(),
        None,
        "a corrupt length field was reported as one of the three integrity violations"
    );
    assert!(
        matches!(
            refusal,
            VaultError::VaultFileMalformed {
                field: VaultField::FrameLength
            }
        ),
        "{refusal:?}"
    );
    // The reason the old mapping threw away: an operator who is not told which
    // field is wrong has nowhere to look.
    assert!(refusal.to_string().contains("frame length"), "{refusal}");
    no_recovery_was_attempted(&scratch, &corrupt, CounterFloor::Unknown);
}

/// Violation two of three: an older copy of the file is put back.
#[test]
fn counter_rollback_does_not_open_the_vault_and_repairs_nothing() {
    let scratch = Scratch::new("rollback");
    let session = SessionId::from_bytes([0x45; 16]);
    let old = seeded(&scratch, &session);

    // The proxy carries on and the vault grows.
    let mut vault = on_file(&scratch.vault(), CounterFloor::AtLeast(2)).unwrap();
    vault
        .store_alias(&session, seed(3), "PSK_PERSON_3", b"Mehmet Kaya", NOW)
        .unwrap();
    let reached = vault.record_counter().unwrap();
    assert_eq!(reached, 3);
    drop(vault);

    // Somebody restores yesterday's backup underneath it. The restored file is
    // internally perfect, which is exactly why the counter has to be checked
    // against something that did not come out of it.
    std::fs::write(scratch.vault(), &old).unwrap();
    let refusal = on_file(&scratch.vault(), CounterFloor::AtLeast(reached)).unwrap_err();
    assert_eq!(refusal.integrity(), Some(Integrity::CounterRollback));
    assert_eq!(refusal.http_status(), 503);
    no_recovery_was_attempted(&scratch, &old, CounterFloor::AtLeast(reached));
}

/// Violation three of three: the Argon2id parameters in the header are weakened.
///
/// The edited value stays inside the hard bounds on purpose. Pushing it outside
/// them would be refused by the range check one step earlier, and this test would
/// then be proving that bounds work rather than that the header is authenticated.
#[test]
fn header_mac_failed_does_not_open_the_vault_and_repairs_nothing() {
    let scratch = Scratch::new("header");
    let session = SessionId::from_bytes([0x46; 16]);
    let honest = seeded(&scratch, &session);

    // Parallelism 4 -> 1, inside the bounds and a different derived key.
    let mut weakened = honest.clone();
    assert_eq!(&weakened[20..24], &4u32.to_le_bytes());
    weakened[20..24].copy_from_slice(&1u32.to_le_bytes());
    std::fs::write(scratch.vault(), &weakened).unwrap();

    let refusal = on_file(&scratch.vault(), CounterFloor::Unknown).unwrap_err();
    assert_eq!(refusal.integrity(), Some(Integrity::HeaderMacFailed));
    assert_eq!(refusal.http_status(), 503);
    no_recovery_was_attempted(&scratch, &weakened, CounterFloor::Unknown);
}

/// The other half of every violation test: nothing was repaired.
///
/// ADR-007 and `proxy/spec.md` section 10 both say the same thing in the same
/// words: the vault is not opened and **no recovery is attempted**. Checked by
/// bytes rather than by reading the code, because a truncation, a rewritten
/// header or a quarantine copy beside the file would each be a repair, and each
/// would leave a green test behind if only the refusal were asserted.
fn no_recovery_was_attempted(scratch: &Scratch, expected: &[u8], floor: CounterFloor) {
    assert_eq!(
        std::fs::read(scratch.vault()).unwrap(),
        expected,
        "the refused vault file was rewritten"
    );
    assert_eq!(
        scratch.names(),
        vec!["vault.psk".to_owned()],
        "a refused open left a file beside the vault"
    );

    // And a second attempt does not heal what the first refused, which is what a
    // retry loop in the request path would look like.
    //
    // Under the caller's own floor, not `AtLeast(u64::MAX)`. That value refuses
    // every file there is, healthy ones included, so the two assertions below held
    // whatever the bytes were and measured nothing at all;
    // `the_retry_check_can_tell_a_healthy_vault_apart` is the control that says
    // this version does not have that problem.
    let first = on_file(&scratch.vault(), floor).unwrap_err();
    let second = on_file(&scratch.vault(), floor).unwrap_err();
    assert_eq!(
        first.integrity(),
        second.integrity(),
        "a second attempt answered differently from the first"
    );
    assert_eq!(std::fs::read(scratch.vault()).unwrap(), expected);
}

/// The control for the helper above: a healthy vault opens under the same call.
#[test]
fn the_retry_check_can_tell_a_healthy_vault_apart() {
    let scratch = Scratch::new("retry-control");
    let session = SessionId::from_bytes([0x77; 16]);
    let honest = seeded(&scratch, &session);

    assert!(on_file(&scratch.vault(), CounterFloor::AtLeast(2)).is_ok());
    assert!(on_file(&scratch.vault(), CounterFloor::Unknown).is_ok());
    assert_eq!(std::fs::read(scratch.vault()).unwrap(), honest);
}

/// The rollback that needs no forgery at all: the file is deleted.
///
/// A missing vault has a record counter of zero, so a proxy that reached three and
/// finds nothing is looking at a vault that went backwards. Creating a fresh one
/// here would make `rm vault.psk` succeed where restoring an older copy is refused,
/// and every mapping the proxy was serving would quietly become
/// `masking_unresolved` with no 503 and no `integrity` value to explain it.
#[test]
fn counter_rollback_a_deleted_vault_file_does_not_open_a_new_one() {
    let scratch = Scratch::new("deleted");
    let session = SessionId::from_bytes([0x88; 16]);
    seeded(&scratch, &session);
    std::fs::remove_file(scratch.vault()).unwrap();

    let refusal = on_file(&scratch.vault(), CounterFloor::AtLeast(2)).unwrap_err();
    assert_eq!(refusal.integrity(), Some(Integrity::CounterRollback));
    assert_eq!(refusal.http_status(), 503);

    // Nothing was created on the way to that refusal. A vault left here would be
    // adopted by the next caller that passes `Unknown`, which is the rollback
    // completing one restart later.
    assert!(scratch.names().is_empty(), "{:?}", scratch.names());

    // And the caller that knows nothing still gets its new vault, or the rule above
    // would just be a broken create.
    assert!(on_file(&scratch.vault(), CounterFloor::Unknown).is_ok());
}

/// Sessions read out of a file are subject to the time to live like any other.
///
/// A vault file records when each session was last used, and a file that sat on a
/// disk over a weekend is mostly expired sessions. Loading them and keeping them
/// is two failures at once: `/admin/vault/status` reports live mappings that are
/// not live, and each one holds a session key in memory for the life of the
/// process, which is the opposite of what a time to live is for.
#[test]
fn a_restart_does_not_resurrect_sessions_whose_time_to_live_has_run_out() {
    let scratch = Scratch::new("expired-restart");
    let stale = SessionId::from_bytes([0xA1; 16]);
    let fresh = SessionId::from_bytes([0xA2; 16]);

    let mut vault = on_file(&scratch.vault(), CounterFloor::Unknown).unwrap();
    let ttl = vault.limits().ttl_ms;
    vault
        .store_alias(&stale, seed(1), "PSK_PERSON_1", AHMET, NOW)
        .unwrap();
    vault
        .store_alias(&fresh, seed(2), "PSK_PERSON_2", AYSE, NOW + ttl)
        .unwrap();
    drop(vault);

    let mut restarted = on_file(&scratch.vault(), CounterFloor::AtLeast(2)).unwrap();
    // Both are on the disk, so both are loaded: the file cannot apply a time to
    // live, because opening it happens before any request supplies a clock.
    assert_eq!(restarted.status().entries(), 2);

    // The first request that does supply one sweeps. The stale session is a full
    // time to live past its last use by then; the fresh one is not.
    let now = NOW + ttl + 1;
    assert!(matches!(
        restarted.restore(&fresh, "PSK_PERSON_2", now).unwrap(),
        Restored::Value(_)
    ));
    assert_eq!(
        restarted.session_count(),
        1,
        "an expired session survived the first request after a restart"
    );
    assert_eq!(restarted.status().entries(), 1);
    assert!(matches!(
        restarted.restore(&stale, "PSK_PERSON_1", now).unwrap(),
        Restored::Unresolved(UnresolvedReason::SessionUnknown)
    ));
}

/// A file the operator points at that is not a vault at all.
///
/// Refused, and deliberately not as one of the three: reporting `chain_mismatch`
/// for a text file would put a fact in `/admin/vault/status` that did not happen.
#[test]
fn a_file_that_is_not_a_vault_is_refused_without_claiming_a_violation() {
    let scratch = Scratch::new("not-a-vault");
    std::fs::write(scratch.vault(), b"this is somebody's notes, not a vault").unwrap();

    let refusal = on_file(&scratch.vault(), CounterFloor::Unknown).unwrap_err();
    assert_eq!(refusal.integrity(), None);
    assert_eq!(refusal.http_status(), 503);
    assert_eq!(
        std::fs::read(scratch.vault()).unwrap(),
        b"this is somebody's notes, not a vault"
    );
}

#[test]
fn the_status_projection_says_where_the_vault_is_and_never_what_it_holds() {
    let scratch = Scratch::new("status");
    let session = SessionId::from_bytes([0x55; 16]);
    seeded(&scratch, &session);

    let vault = on_file(&scratch.vault(), CounterFloor::Unknown).unwrap();
    let status = vault.status();
    assert_eq!(status.backend(), Storage::File);
    assert_eq!(status.state(), VaultState::Unsealed);
    assert_eq!(status.integrity(), Integrity::Ok);
    assert_eq!(status.entries(), 2);

    let json = status.to_json();
    assert!(json.contains("\"backend\":\"file\""), "{json}");
    assert!(json.contains("\"integrity\":\"ok\""), "{json}");
    assert!(json.contains("vault.psk"), "{json}");
    assert!(!json.contains("Ahmet"), "{json}");
    assert!(!json.contains("Ayse"), "{json}");
    assert!(!json.contains("PSK_PERSON_1"), "{json}");
}

/// The vault file is not readable by anybody else on the machine.
#[cfg(unix)]
#[test]
fn the_vault_file_is_readable_only_by_its_owner() {
    use std::os::unix::fs::PermissionsExt;

    let scratch = Scratch::new("mode");
    let session = SessionId::from_bytes([0x66; 16]);
    seeded(&scratch, &session);

    let mode = std::fs::metadata(scratch.vault())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "{mode:o}");
}
