//! Compaction: dropping expired records from an append-only file.
//!
//! ADR-007 records this as a cost of the integrity chain rather than as a
//! feature: "zincirleme MAC, kasayı append-only bir yapıya bağlar: kayıt silme
//! (TTL dolan oturumların budanması) artık dosyayı yeniden yazıp zinciri baştan
//! kurmayı gerektirir". A chain cannot lose a link, so a vault cannot forget a
//! record in place. It forgets by being written again from `M_0`.
//!
//! # The whole design is the swap
//!
//! ```text
//! build the new image in memory  ->  write it to vault.psk.compact
//!                                ->  flush it to the disk
//!                                ->  rename it over vault.psk   (atomic)
//! ```
//!
//! Until the rename, `vault.psk` is untouched: not truncated, not opened for
//! writing, not read from after the image was built. So a run that dies anywhere
//! before the rename leaves the old vault exactly as it was, and a run that dies
//! after it leaves the new one whole. There is no third state, because `rename(2)`
//! on the same filesystem is atomic and every byte of the new file is on the disk
//! before it is called.
//!
//! # Why there is no directory flush
//!
//! Flushing the directory entry would make the *rename* durable across a power
//! cut. It is deliberately not done, because the property this module owes its
//! caller is not that a compaction survives a power cut: it is that the vault
//! survives one. A rename that did not reach the disk leaves the old file, which
//! is a complete, verifying vault holding a superset of the records. Losing a
//! compaction costs disk space; losing the vault costs every live conversation.
//!
//! # A leftover temporary file is not a vault
//!
//! `vault.psk.compact` is only ever a candidate. It is authoritative for exactly
//! zero instants: before the rename it is incomplete, and after it there is no
//! temporary file at all. Nothing reads it, and a stale one left by a killed run
//! is removed by the next compaction rather than adopted, because a file that was
//! never renamed is a file that was never committed.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::error::VaultError;
use super::file::VaultFile;
use super::layout::Frame;

/// The suffix of the file compaction writes before it swaps it in.
///
/// Beside the vault rather than in the system temporary directory: `rename` is
/// only atomic within one filesystem, and a temporary directory is regularly on
/// another one. A cross device rename would fall back to a copy, and a copy is
/// exactly the half written state this module exists to make impossible.
const CANDIDATE_SUFFIX: &str = ".compact";

/// What a compaction did, in numbers an operator can read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Compacted {
    /// Frames the file held before.
    pub before: u64,
    /// Frames it holds now.
    pub after: u64,
}

impl Compacted {
    pub fn dropped(&self) -> u64 {
        self.before.saturating_sub(self.after)
    }
}

/// Rewrites the vault so that it holds exactly `frames`, and swaps it in.
///
/// The record counter is carried across rather than restarted; see
/// [`VaultFile::image`] for why a compaction that lowered it would be
/// indistinguishable from the rollback the counter exists to catch.
pub(super) fn compact(file: &mut VaultFile, frames: &[Frame]) -> Result<Compacted, VaultError> {
    let before = file.frame_count();
    let image = file.image(frames)?;
    let candidate = candidate_path(file.path());

    // A stale candidate is the residue of a run that was killed before its
    // rename. It was never committed, so it carries no records this vault does
    // not already have, and it is removed rather than inspected.
    remove_stale(&candidate)?;
    // The descriptor comes back from here rather than being opened after the
    // rename. `rename(2)` does not move an inode, so this handle addresses the
    // new vault the instant the swap lands; opening afterwards meant an open
    // that failed left the vault holding a descriptor on the unlinked old file,
    // and every append after that succeeded into nothing. See `VaultFile::adopt`.
    let handle = write_candidate(&candidate, &image.bytes)?;

    // The last question before the irreversible instant: is the file about to be
    // replaced still the one this process is describing? A second opener that
    // committed a record since the frame list was built would have it dropped by
    // the swap, and it was told the record was stored.
    if let Err(refusal) = file.confirm_unchanged_before_swap() {
        // The candidate goes with the refusal, for the reason the rename failure
        // below gives: a leftover nobody was told about is cleared by the next
        // compaction and looks like a repair.
        drop(handle);
        return Err(match std::fs::remove_file(&candidate) {
            Ok(()) => refusal,
            Err(cause) => VaultError::VaultFileUnavailable {
                operation: "compacted, and its candidate could not be removed either",
                cause: format!("{:?}", cause.kind()),
            },
        });
    }

    // The one irreversible instant, and it is a single system call.
    if let Err(cause) = std::fs::rename(&candidate, file.path()) {
        // The old vault is untouched, so the honest thing is to leave it in place
        // and say the compaction did not happen. The candidate goes away with it;
        // leaving one behind would make the next run's cleanup look like a repair.
        //
        // If it cannot be removed, the operator hears that too. A discarded result
        // here would leave a file beside the vault that nobody was told about, and
        // the next compaction would silently clear it: the one place a leftover
        // candidate is visible is this message.
        let operation = match std::fs::remove_file(&candidate) {
            Ok(()) => "swapped in",
            Err(_) => "swapped in, and its candidate could not be removed either",
        };
        return Err(VaultError::VaultFileUnavailable {
            operation,
            cause: format!("{:?}", cause.kind()),
        });
    }

    file.adopt(handle, &image);
    Ok(Compacted {
        before,
        after: file.frame_count(),
    })
}

fn candidate_path(vault: &Path) -> PathBuf {
    let mut name = vault.as_os_str().to_os_string();
    name.push(CANDIDATE_SUFFIX);
    PathBuf::from(name)
}

fn remove_stale(candidate: &Path) -> Result<(), VaultError> {
    match std::fs::remove_file(candidate) {
        Ok(()) => Ok(()),
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(cause) => Err(VaultError::VaultFileUnavailable {
            operation: "cleared of a stale candidate",
            cause: format!("{:?}", cause.kind()),
        }),
    }
}

/// Writes the candidate, flushes it, and hands back the descriptor on it.
///
/// The descriptor is the return value because the caller needs one that survives
/// the rename; see [`VaultFile::adopt`] for what opening it afterwards cost.
fn write_candidate(candidate: &Path, bytes: &[u8]) -> Result<File, VaultError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    // The candidate becomes the vault, so it is born with the vault's mode rather
    // than being widened for an instant in between.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut handle = options
        .open(candidate)
        .map_err(|cause| unavailable(&cause))?;
    handle
        .write_all(bytes)
        .map_err(|cause| unavailable(&cause))?;
    // Before the rename, not after: the rename is only atomic in the useful sense
    // if the bytes it points at are already on the disk.
    handle.sync_all().map_err(|cause| unavailable(&cause))?;
    Ok(handle)
}

fn unavailable(cause: &std::io::Error) -> VaultError {
    VaultError::VaultFileUnavailable {
        operation: "written as a compaction candidate",
        cause: format!("{:?}", cause.kind()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::vault::file::{self, CounterFloor};
    use crate::vault::key::ProfileName;
    use crate::vault::layout::HEADER_BYTES;
    use crate::vault::record::{SealedRecord, ALIAS_SEED_BYTES, NONCE_BYTES};
    use crate::vault::secret::Passphrase;
    use crate::vault::session::SESSION_ID_BYTES;
    use crate::vault::{AliasSeed, SessionId};

    struct Scratch {
        root: PathBuf,
    }

    impl Scratch {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "periskop-vault-compaction-{name}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn vault(&self) -> PathBuf {
            self.root.join("vault.psk")
        }

        fn names(&self) -> BTreeSet<String> {
            std::fs::read_dir(&self.root)
                .unwrap()
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
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

    fn frame(byte: u8, session: u8) -> Frame {
        Frame {
            stored_at_ms: 1_700_000_000_000 + u64::from(byte),
            session: SessionId::from_bytes([session; SESSION_ID_BYTES]),
            alias_seed: AliasSeed::from_bytes([byte; ALIAS_SEED_BYTES]),
            alias: format!("PSK_PERSON_{byte}"),
            sealed: SealedRecord::from_parts([byte; NONCE_BYTES], vec![byte; 48]),
        }
    }

    /// Every open in these tests goes through here, so no two Argon2id
    /// derivations run at once; see [`crate::vault::key::one_derivation_at_a_time`].
    fn open_here(path: &Path, floor: CounterFloor) -> Result<file::Loaded, VaultError> {
        let _permit = crate::vault::key::one_derivation_at_a_time();
        file::open(path, &passphrase(), ProfileName::Ci, floor)
    }

    fn seeded(scratch: &Scratch, count: u8) -> (file::Loaded, Vec<Frame>) {
        let mut loaded = open_here(&scratch.vault(), CounterFloor::Unknown).unwrap();
        let mut frames = Vec::new();
        for byte in 1..=count {
            let frame = frame(byte, byte % 2);
            loaded.file.append(&frame).unwrap();
            frames.push(frame);
        }
        (loaded, frames)
    }

    #[test]
    fn compaction_drops_the_frames_it_was_not_given_and_keeps_the_rest() {
        let scratch = Scratch::new("drop");
        let (mut loaded, frames) = seeded(&scratch, 4);

        let kept: Vec<Frame> = frames
            .iter()
            .filter(|frame| frame.session == SessionId::from_bytes([1; SESSION_ID_BYTES]))
            .cloned()
            .collect();
        let outcome = compact(&mut loaded.file, &kept).unwrap();

        assert_eq!(outcome.before, 4);
        assert_eq!(outcome.after, 2);
        assert_eq!(outcome.dropped(), 2);
        drop(loaded);

        let reloaded = open_here(&scratch.vault(), CounterFloor::Unknown).unwrap();
        assert_eq!(reloaded.frames.len(), 2);
        assert_eq!(reloaded.frames[0].alias, "PSK_PERSON_1");
        assert_eq!(reloaded.frames[1].alias, "PSK_PERSON_3");
    }

    /// The chain is rebuilt from `M_0`, and the proof is that the new file
    /// verifies on a fresh open. A compaction that copied the old tail forward
    /// would produce a file that fails its own integrity check.
    #[test]
    fn the_chain_is_rebuilt_from_the_start_and_verifies_afterwards() {
        let scratch = Scratch::new("rebuild");
        let (mut loaded, frames) = seeded(&scratch, 3);
        let tail_before = std::fs::read(scratch.vault()).unwrap()[64..96].to_vec();

        compact(&mut loaded.file, &frames[..2]).unwrap();
        drop(loaded);

        let after = std::fs::read(scratch.vault()).unwrap();
        assert_ne!(&after[64..96], tail_before.as_slice(), "the tail moved");
        assert!(open_here(&scratch.vault(), CounterFloor::Unknown).is_ok());
    }

    /// A compaction that lowered the counter would be indistinguishable from an
    /// older file being restored, so the next open would refuse the vault this
    /// process just wrote.
    #[test]
    fn compaction_does_not_lower_the_record_counter() {
        let scratch = Scratch::new("counter");
        let (mut loaded, _) = seeded(&scratch, 5);
        assert_eq!(loaded.file.record_counter(), 5);

        compact(&mut loaded.file, &[]).unwrap();
        assert_eq!(loaded.file.record_counter(), 5);
        assert_eq!(loaded.file.frame_count(), 0);
        drop(loaded);

        // The floor from before the compaction still opens the compacted file,
        // which is the property that matters.
        let reloaded = open_here(&scratch.vault(), CounterFloor::AtLeast(5)).unwrap();
        assert_eq!(reloaded.file.record_counter(), 5);
        assert!(reloaded.frames.is_empty());
    }

    #[test]
    fn appending_after_a_compaction_continues_the_new_chain() {
        let scratch = Scratch::new("append-after");
        let (mut loaded, frames) = seeded(&scratch, 3);

        compact(&mut loaded.file, &frames[..1]).unwrap();
        loaded.file.append(&frame(9, 1)).unwrap();
        assert_eq!(loaded.file.record_counter(), 4);
        drop(loaded);

        let reloaded = open_here(&scratch.vault(), CounterFloor::Unknown).unwrap();
        assert_eq!(reloaded.frames.len(), 2);
        assert_eq!(reloaded.frames[1].alias, "PSK_PERSON_9");
    }

    #[test]
    fn a_finished_compaction_leaves_no_candidate_behind() {
        let scratch = Scratch::new("clean");
        let (mut loaded, frames) = seeded(&scratch, 2);
        compact(&mut loaded.file, &frames).unwrap();

        assert_eq!(
            scratch.names(),
            BTreeSet::from(["vault.psk".to_owned()]),
            "a candidate file survived a finished compaction"
        );
    }

    /// The interruption test, injected at the first step that touches a disk.
    ///
    /// A directory at the candidate path makes the compaction fail while it is
    /// *clearing a stale candidate*, one step before it writes one. The name used
    /// to say "cannot write its candidate", which is a different step and one this
    /// test never reached: `remove_stale` refuses a directory and returns before
    /// `write_candidate` is called at all. The `operation` field is asserted here so
    /// that the name and the step it describes cannot drift apart again.
    ///
    /// What is proved is the same either way and it is the part that matters: a
    /// compaction that fails anywhere before its rename leaves the old vault byte
    /// for byte identical and still openable.
    #[test]
    fn a_compaction_that_cannot_clear_a_stale_candidate_leaves_the_old_vault_intact() {
        let scratch = Scratch::new("write-fault");
        let (mut loaded, frames) = seeded(&scratch, 3);
        let before = std::fs::read(scratch.vault()).unwrap();

        let blocked = candidate_path(&scratch.vault());
        std::fs::create_dir(&blocked).unwrap();

        let refusal = compact(&mut loaded.file, &frames[..1]).unwrap_err();
        match &refusal {
            VaultError::VaultFileUnavailable { operation, .. } => {
                assert_eq!(*operation, "cleared of a stale candidate");
            }
            other => panic!("expected the file to be unavailable, got {other:?}"),
        }
        assert_eq!(refusal.http_status(), 503);

        // Not truncated, not partly rewritten, not replaced.
        assert_eq!(std::fs::read(scratch.vault()).unwrap(), before);
        std::fs::remove_dir(&blocked).unwrap();
        drop(loaded);

        let reloaded = open_here(&scratch.vault(), CounterFloor::Unknown).unwrap();
        assert_eq!(reloaded.frames.len(), 3);
        assert_eq!(reloaded.file.record_counter(), 3);
    }

    /// The state a killed run leaves on the disk: a candidate that was written but
    /// never renamed.
    ///
    /// Reconstructed byte for byte rather than described, and it has to be
    /// invisible to the vault: the old file opens, the records are all there, and
    /// the next compaction clears the residue instead of adopting it.
    #[test]
    fn a_candidate_left_by_a_killed_run_is_ignored_and_then_cleared() {
        let scratch = Scratch::new("stale");
        let (loaded, frames) = seeded(&scratch, 3);
        let before = std::fs::read(scratch.vault()).unwrap();

        // Half of what a compaction to a single record would have written.
        let half = loaded.file.image(&frames[..1]).unwrap();
        let residue = &half.bytes[..HEADER_BYTES + 10];
        std::fs::write(candidate_path(&scratch.vault()), residue).unwrap();
        drop(loaded);

        // The vault is unaware of it.
        let mut reloaded = open_here(&scratch.vault(), CounterFloor::Unknown).unwrap();
        assert_eq!(std::fs::read(scratch.vault()).unwrap(), before);
        assert_eq!(reloaded.frames.len(), 3);

        // And the next compaction does not mistake it for a starting point.
        compact(&mut reloaded.file, &frames[..2]).unwrap();
        assert_eq!(scratch.names(), BTreeSet::from(["vault.psk".to_owned()]));
        drop(reloaded);

        let after = open_here(&scratch.vault(), CounterFloor::Unknown).unwrap();
        assert_eq!(after.frames.len(), 2);
    }

    /// A compaction is a whole file replacement, so it drops every record it was
    /// not given, including the ones it never saw.
    ///
    /// Two openers of one vault is the case: the second appends, the first
    /// compacts from the frame list it built before that append existed, and the
    /// rename puts a file over the vault that has no trace of the record the
    /// second opener was told had been stored. Nothing reports a loss, and the
    /// counter carried across makes the shortened file look like the current one.
    #[test]
    fn a_compaction_does_not_discard_a_record_another_opener_committed() {
        let scratch = Scratch::new("second-opener");
        let (mut first, frames) = seeded(&scratch, 3);

        let mut second = open_here(&scratch.vault(), CounterFloor::Unknown).unwrap();
        second.file.append(&frame(9, 1)).unwrap();

        let refusal = compact(&mut first.file, &frames[..2]).unwrap_err();
        match &refusal {
            VaultError::VaultFileUnavailable { operation, .. } => {
                assert_eq!(*operation, "compacted");
            }
            other => panic!("expected the compaction to be refused, got {other:?}"),
        }
        assert_eq!(refusal.http_status(), 503);

        // Refused before the swap, so the record the other opener committed is
        // still there, and so is the candidate's absence.
        assert_eq!(scratch.names(), BTreeSet::from(["vault.psk".to_owned()]));
        drop(first);
        drop(second);

        let reloaded = open_here(&scratch.vault(), CounterFloor::AtLeast(4)).unwrap();
        assert_eq!(reloaded.frames.len(), 4);
        assert_eq!(reloaded.frames[3].alias, "PSK_PERSON_9");
    }

    /// The candidate is beside the vault, which is what keeps the rename on one
    /// filesystem and therefore atomic.
    #[test]
    fn the_candidate_is_written_beside_the_vault() {
        let candidate = candidate_path(Path::new("/somewhere/.periskop/vault.psk"));
        assert_eq!(candidate.parent(), Path::new("/somewhere/.periskop").into());
        assert_eq!(
            candidate.file_name().unwrap().to_string_lossy(),
            "vault.psk.compact"
        );
    }
}
