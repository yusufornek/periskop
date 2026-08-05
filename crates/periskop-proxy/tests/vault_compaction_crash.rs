#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
//! Milestone 72's acceptance criterion: a compaction that is cut off part way
//! leaves the old file intact and the vault openable.
//!
//! # This kills a process, it does not describe killing one
//!
//! A claim about crash safety that is argued rather than demonstrated is a claim
//! about the argument. So this test spawns a real child process, lets it open a
//! real vault, and terminates it from a second thread while the compaction is
//! writing. Nothing about the compaction knows it is being tested: there is no
//! fault injection hook in the shipped code, because a hook nothing in production
//! uses is production code written for a test.
//!
//! `std::process::exit` from another thread is what does the killing. It is
//! abrupt in the ways that matter here: no destructor runs, no buffer is flushed,
//! no temporary file is cleaned up and no rename happens after it. What it does
//! not simulate is a torn write inside the kernel's own page cache, which no test
//! in user space can produce; that limit is stated rather than papered over.
//!
//! # The assertion holds whenever the kill lands, which is why this is not flaky
//!
//! The property is not "the kill lands in the middle". It is that **at every**
//! instant the vault on disk is one whole vault: the one from before the
//! compaction or the one from after it, and never a mixture. So the run is
//! repeated across a spread of delays and each one is checked against the same
//! invariant. A separate assertion then confirms that at least one run really was
//! killed between the start and the end of a compaction, because a suite where
//! every child finished first would be green while proving nothing.
//!
//! # How the child's ending is decided, and why it used to be a race
//!
//! The killer thread and the compaction run at the same time on purpose, so
//! "which of the two got there first" is the one question this file may not
//! answer by looking at wall clock leftovers. It used to: the parent read the
//! exit status beside two marker files and matched on the triple. Three
//! combinations were listed and a fourth was reachable, because the killer could
//! fire **after** the `finished` mark was written and before the process left
//! `main`. That child exited 70 with both marks present, the match arm for it did
//! not exist, and the parent panicked with "a state this test does not model".
//! It happened on continuous integration and never on the development machine,
//! which is the worst shape a gate can have: green means proved, red means look
//! at the harness, and nobody looks at the code either way.
//!
//! The race is gone rather than modelled. The two threads now claim the ending
//! through one [`AtomicBool`]: whoever swaps it wins, and the loser does nothing
//! at all. A killer that loses never calls `exit`, so the process ends `0` with
//! both marks; a compaction that loses writes no mark and parks, so the process
//! ends `70` with `finished` absent. Every exit status therefore has exactly one
//! meaning, the classification below is a total function of it, and no arm of it
//! depends on which thread the scheduler happened to favour.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use periskop_proxy::vault::{
    AliasSeed, Backing, CounterFloor, OpenRequest, Passphrase, ProfileName, Restored, SessionId,
    Vault, VaultError,
};

/// Set by the parent, read by the child: where the vault to compact lives.
const CHILD_DIRECTORY: &str = "PERISKOP_COMPACTION_CRASH_DIR";
/// How long the child waits, in microseconds, before terminating itself.
const CHILD_DELAY_US: &str = "PERISKOP_COMPACTION_CRASH_DELAY_US";
/// Where the child records how far it got. Outside the vault's own directory,
/// because the parent wipes that between runs and the marks have to survive it.
const CHILD_MARKS: &str = "PERISKOP_COMPACTION_CRASH_MARKS";
/// The exit status the child's killer thread uses, so the parent can tell a kill
/// apart from an ordinary failure.
const KILLED: i32 = 70;

/// Records the vault is seeded with.
///
/// Enough that writing the compacted image takes long enough to be interrupted,
/// and few enough that seeding it does not dominate the suite: every append
/// flushes twice, so this is the expensive half of the test rather than the
/// compaction is.
const RECORDS: u8 = 200;

const NOW: u64 = 1_700_000_000_000;
/// The session that is still live when the compaction runs.
const LIVE: SessionId = SessionId::from_bytes([0x01; 16]);
/// The session whose time to live has run out, and which compaction drops.
const EXPIRED: SessionId = SessionId::from_bytes([0x02; 16]);

fn passphrase() -> Passphrase {
    Passphrase::new(b"the operator typed this".to_vec())
}

fn open_vault(directory: &Path) -> Result<Vault, VaultError> {
    Vault::open(&OpenRequest {
        passphrase: &passphrase(),
        // The reduced profile: this test is about a rename, not about how long
        // Argon2id takes, and the child pays the derivation on every run.
        profile: ProfileName::Ci,
        backing: Backing::File {
            path: &directory.join("vault.psk"),
            floor: CounterFloor::Unknown,
        },
    })
}

/// The instant compaction is asked to prune at: past the expired session's
/// deadline and inside the live one's.
fn prune_at(vault: &Vault) -> u64 {
    NOW + vault.limits().ttl_ms + 2
}

// ---------------------------------------------------------------------------
// The child
// ---------------------------------------------------------------------------

/// Runs only when the parent asks for it, and then it does not come back.
///
/// Ignored so an ordinary `cargo test` does not run it, and a no-op when the
/// environment is not set so that `--include-ignored` cannot make it fail.
#[test]
#[ignore = "spawned by the parent test below; it terminates itself on purpose"]
fn compaction_child_terminates_itself_mid_run() {
    let Some(directory) = std::env::var_os(CHILD_DIRECTORY) else {
        return;
    };
    let directory = PathBuf::from(directory);
    let delay_us: u64 = std::env::var(CHILD_DELAY_US)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);

    let mut vault = open_vault(&directory).expect("the parent wrote a vault this can open");
    let at = prune_at(&vault);

    let marks = PathBuf::from(std::env::var_os(CHILD_MARKS).expect("the parent sets this"));
    std::fs::create_dir_all(&marks).expect("marks");

    // Two flags, and the order between them is the whole timing contract of this
    // file. `window` says the compaction is about to begin; `ending` is the single
    // claim on how this process exits, and whichever thread swaps it decides,
    // while the other is required to do nothing at all.
    let window = Arc::new(AtomicBool::new(false));
    let ending = Arc::new(AtomicBool::new(true));
    let (killer_window, killer_ending) = (Arc::clone(&window), Arc::clone(&ending));
    std::thread::spawn(move || {
        // The delay is measured from the instant the compaction is about to
        // begin, not from whenever the scheduler got round to starting this
        // thread. Starting the clock at thread startup shifted every sample by
        // however long the spawn took, which on a loaded runner is longer than
        // the compaction itself, so the sweep stopped covering the window it was
        // written to cover.
        while !killer_window.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        // Spun rather than slept. `thread::sleep` rounds up to the scheduler's
        // granularity, which on the machines this runs on is around a
        // millisecond, so every "short" delay would land at the same instant and
        // the early part of a compaction would never be sampled. That is not a
        // detail: with a sleep, a mutation that rewrote the vault in place before
        // the rename survived this test, because the only window ever sampled was
        // the flush at the end.
        let until = std::time::Duration::from_micros(delay_us);
        let started = std::time::Instant::now();
        while started.elapsed() < until {
            std::hint::spin_loop();
        }
        // The claim, taken before the kill rather than after it. A killer that
        // wakes up once the compaction has already returned finds the claim gone
        // and leaves the process alone, which is the whole of the fix: it used to
        // terminate a child that had finished its work, and the parent had no
        // arm for the state that produced.
        if !killer_ending.swap(false, Ordering::SeqCst) {
            return;
        }
        // No unwinding, no destructors, no cleanup, no rename: the closest thing
        // to a kill that a portable test can produce from inside the process.
        std::process::exit(KILLED);
    });

    // Written before the window opens, so a child that was killed always carries
    // this mark and "killed before the compaction was reached" is not a state the
    // parent has to tell apart from a mark that lost a race with `exit`.
    std::fs::write(marks.join("started"), b"1").expect("started");
    window.store(true, Ordering::Release);
    let outcome = vault.compact(at);
    if !ending.swap(false, Ordering::SeqCst) {
        // The killer took the claim while the compaction was still running and is
        // about to end this process. Nothing more may be written from here: a
        // `finished` mark laid down now would describe a run that was interrupted
        // as one that completed, which is the misreading this whole arrangement
        // exists to prevent. Parking is what lets the killer's `exit` be the only
        // way out.
        loop {
            std::thread::park();
        }
    }
    std::fs::write(marks.join("finished"), b"1").expect("finished");
    outcome.expect("the compaction itself must not fail");
}

// ---------------------------------------------------------------------------
// The parent
// ---------------------------------------------------------------------------

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "periskop-vault-crash-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("vault")).unwrap();
        Self { root }
    }

    fn directory(&self) -> PathBuf {
        self.root.join("vault")
    }

    fn vault(&self) -> PathBuf {
        self.directory().join("vault.psk")
    }

    fn marks(&self) -> PathBuf {
        self.root.join("marks")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Seeds the vault and returns its bytes, so the parent can put it back between
/// runs.
fn seed(scratch: &Scratch) -> Vec<u8> {
    let mut vault = open_vault(&scratch.directory()).unwrap();
    let expires_at = NOW;
    let stays_alive_at = NOW + vault.limits().ttl_ms + 1;

    for byte in 1..=RECORDS {
        vault
            .store_alias(
                &EXPIRED,
                AliasSeed::from_bytes([byte; 32]),
                &format!("PSK_ORGID_{byte}"),
                format!("expired customer {byte}").as_bytes(),
                expires_at,
            )
            .unwrap();
    }
    for byte in 1..=RECORDS {
        vault
            .store_alias(
                &LIVE,
                AliasSeed::from_bytes([byte; 32]),
                &format!("PSK_PERSON_{byte}"),
                format!("live customer {byte}").as_bytes(),
                stays_alive_at,
            )
            .unwrap();
    }
    drop(vault);
    std::fs::read(scratch.vault()).unwrap()
}

/// What one child run left behind.
///
/// Two endings, and the child can produce exactly two, because the claim it takes
/// on its own ending decides which. There is no third state to model and no
/// combination left over, which is the difference between this and the match that
/// broke a continuous integration run.
#[derive(Debug, PartialEq, Eq)]
enum Ending {
    /// The child was terminated between the start and the end of the compaction:
    /// the window this whole test is about.
    KilledDuring,
    /// The compaction finished first, and the killer found the claim gone.
    Finished,
}

fn run_child(scratch: &Scratch, delay_us: u64) -> Ending {
    let _ = std::fs::remove_dir_all(scratch.marks());
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "compaction_child_terminates_itself_mid_run",
            "--ignored",
            "--nocapture",
            // One thread, so the delay is measured against the compaction and not
            // against whatever else the harness decided to run beside it.
            "--test-threads=1",
        ])
        .env(CHILD_DIRECTORY, scratch.directory())
        .env(CHILD_DELAY_US, delay_us.to_string())
        .env(CHILD_MARKS, scratch.marks())
        .output()
        .unwrap();

    let started = scratch.marks().join("started").exists();
    let finished = scratch.marks().join("finished").exists();
    // Both arms are decided by the exit status, and the marks are asserted rather
    // than consulted. The child cannot exit `KILLED` without `started`, because
    // that mark is written before the killer's window opens; and it cannot exit
    // `KILLED` with `finished`, because the thread that writes `finished` has by
    // then taken the claim the killer needs. So no arm here has to guess which of
    // two threads ran first, and a build where either of those stops holding
    // fails loudly instead of being classified anyway.
    match child.status.code() {
        Some(KILLED) if started && !finished => Ending::KilledDuring,
        Some(0) if started && finished => Ending::Finished,
        // Anything else is a broken test rather than a result: a child that
        // exited zero without recording both marks, one that recorded a
        // completed compaction and was killed anyway, or one that died of
        // something other than its own killer. Saying so beats letting the
        // invariant below pass over it.
        other => panic!(
            "the child exited {other:?} with started={started} finished={finished}, which is \
             not an ending it can produce\n{}",
            String::from_utf8_lossy(&child.stderr)
        ),
    }
}

/// The gate for milestone 72.
#[test]
fn a_compaction_killed_part_way_leaves_a_whole_vault_behind() {
    let scratch = Scratch::new("kill");
    let before = seed(&scratch);

    // The two states a run may legitimately end in, measured once so that the
    // invariant below is comparing against something real rather than a number
    // written by hand.
    let (all_records, live_records) = both_states(&scratch, &before);
    assert!(all_records > live_records && live_records > 0);

    let mut endings = Vec::new();
    // A spread across the whole window. A compaction of this vault takes single
    // digit milliseconds and the flush at the end dominates it, so the early
    // points are packed close together: without them the only instant ever
    // sampled is the flush, and a compaction that had already damaged the vault
    // before reaching it would pass.
    for delay_us in [
        5u64, 15, 30, 60, 120, 250, 500, 900, 1_400, 2_000, 2_800, 4_000,
    ] {
        // Every run starts from the same file, residue from the last one removed:
        // the claim is about one interrupted compaction, not about a sequence.
        reset(&scratch, &before);

        let ending = run_child(&scratch, delay_us);

        // The invariant, checked after every single run and independent of where
        // the kill landed: whatever is at the path is a vault, it verifies, and it
        // holds one of the two whole states.
        let mut vault = open_vault(&scratch.directory()).unwrap_or_else(|refusal| {
            panic!("delay {delay_us}us left an unopenable vault: {refusal}")
        });
        let entries = vault.status().entries();
        assert!(
            entries == all_records || entries == live_records,
            "delay {delay_us}us left {entries} records, which is neither the vault \
             from before the compaction ({all_records}) nor the one from after it \
             ({live_records})"
        );

        // And it is readable, not merely parseable: a record from the live session
        // still opens under its own identity.
        match vault.restore(&LIVE, "PSK_PERSON_1", NOW).unwrap() {
            Restored::Value(value) => assert_eq!(value.expose(), b"live customer 1"),
            other => panic!("delay {delay_us}us lost a live record: {other:?}"),
        }

        // A vault that survived an interrupted compaction can still be compacted.
        let at = prune_at(&vault);
        vault.compact(at).unwrap();
        assert_eq!(vault.status().entries(), live_records);

        endings.push((delay_us, ending));
    }

    // Without this the suite could be green because every child happened to
    // finish before its killer thread woke up, which would exercise nothing.
    assert!(
        endings
            .iter()
            .any(|(_, ending)| *ending == Ending::KilledDuring),
        "no run was killed between the start and the end of a compaction: {endings:?}"
    );
}

/// Opens the vault twice to learn how many records each of the two whole states
/// holds, then puts the file back.
fn both_states(scratch: &Scratch, before: &[u8]) -> (usize, usize) {
    reset(scratch, before);
    let mut vault = open_vault(&scratch.directory()).unwrap();
    let all = vault.status().entries();

    let at = prune_at(&vault);
    vault.compact(at).unwrap();
    let live = vault.status().entries();
    drop(vault);

    reset(scratch, before);
    (all, live)
}

/// Puts the directory back to one file: the vault as it was before any
/// compaction, and no residue from the run that just ended.
fn reset(scratch: &Scratch, before: &[u8]) {
    let _ = std::fs::remove_dir_all(scratch.directory());
    std::fs::create_dir_all(scratch.directory()).unwrap();
    std::fs::write(scratch.vault(), before).unwrap();
}
