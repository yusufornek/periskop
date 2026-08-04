//! The `file` backend: `vault.psk` on a disk, and the three ways it refuses.
//!
//! `memory` is the default and this module is the exception somebody has to ask
//! for (`proxy/spec.md` section 9). It is also the only module in this vault
//! besides [`super::compaction`] that is allowed to name a filesystem call, and
//! `tests/vault_touches_no_files.rs` is what makes that a boundary rather than a
//! habit.
//!
//! # Opening is a sequence, and the order is the design
//!
//! 1. **Read the header structurally.** Magic, layout version, algorithm tags and
//!    the reserved word, before anything is derived or allocated.
//! 2. **Bound the claimed Argon2id parameters** ([`KdfProfile::validate`]). A
//!    header claiming 64 GiB must cost three comparisons, not 64 GiB. This is the
//!    order of operations ADR-007 section 4 leaves open and `super::key` closes.
//! 3. **Derive the master key** from the parameters the header *claims*, then the
//!    chain key from it.
//! 4. **Verify the header tag.** Weakened parameters derive a different key, so
//!    the tag does not check out: `header_mac_failed`.
//! 5. **Check the counter against what this process already knows.**  A file whose
//!    counter went backwards is an older copy put back: `counter_rollback`.
//! 6. **Walk the chain over the frames.** Anything removed, edited, reordered or
//!    truncated moves the tail: `chain_mismatch`.
//!
//! Steps 4, 5 and 6 are the three violations ADR-007 enumerates, and all three end
//! the same way: 503, the vault stays sealed, **and nothing is repaired**. A
//! partly opened vault is more dangerous than one that did not open, because every
//! layer above it would carry on believing its answers.
//!
//! # What the counter can and cannot see
//!
//! `record_counter` only detects a rollback against a value known from somewhere
//! other than the file. Inside one process that is free: the vault remembers the
//! highest counter it has seen and refuses anything below it, which covers the
//! file being swapped underneath a running proxy. Across a restart the caller has
//! to supply the floor, and if it cannot, an older self consistent copy of the
//! vault is indistinguishable from the current one. That limit is arithmetic
//! rather than an omission, and it is written down in `known-gaps.md` KG-022
//! instead of being papered over with a second state file that would roll back
//! in exactly the same way.
//!
//! # Bytes after the authenticated region
//!
//! The header says how many frames it authenticates. Bytes after them are not part
//! of the vault: they are what a process killed between writing a frame and
//! committing the header leaves behind. They are ignored on open and overwritten
//! by the next append, and neither is a repair — the authenticated region is never
//! touched by either. The record in a torn append was never committed, so a vault
//! that opens without it is telling the truth.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::chain::{ChainMac, ChainTag};
use super::error::{Integrity, VaultError};
use super::key::{self, KdfProfile, ProfileName, Salt};
use super::layout::{Frame, Header, HEADER_BYTES, PREFIX_BYTES};
use super::secret::{MasterKey, Passphrase};

/// The lowest record counter this vault will accept from a file.
///
/// `Unknown` is honest rather than convenient: it says that this open cannot tell
/// an older copy of the vault from the current one, and the caller who can do
/// better passes [`CounterFloor::AtLeast`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CounterFloor {
    /// Nothing is known about this vault's history.
    Unknown,
    /// The caller knows the vault reached at least this counter.
    AtLeast(u64),
}

impl CounterFloor {
    fn value(self) -> u64 {
        match self {
            Self::Unknown => 0,
            Self::AtLeast(counter) => counter,
        }
    }
}

/// What opening a vault file produced.
pub(super) struct Loaded {
    pub(super) master: MasterKey,
    pub(super) file: VaultFile,
    pub(super) frames: Vec<Frame>,
    parameters: KdfProfile,
}

/// Counts, like every other rendering in this vault.
///
/// Written by hand rather than derived so that a `Loaded` printed by a test
/// failure or a future log line is a number of records and not the records.
impl std::fmt::Debug for Loaded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Loaded")
            .field("file", &self.file)
            .field("frames", &self.frames.len())
            .finish()
    }
}

impl Loaded {
    /// The Argon2id parameters this vault is *actually* protected by.
    ///
    /// For an existing file that is what its header says, which need not be what
    /// the command line asked for. The caller turns it into the note an operator
    /// sees.
    pub(super) fn effective_profile(&self) -> KdfProfile {
        self.parameters
    }
}

/// A complete file image, ready to be written somewhere in one go.
pub(super) struct FileImage {
    pub(super) bytes: Vec<u8>,
    frame_count: u64,
    chain_tail: ChainTag,
}

/// An open `vault.psk`.
pub struct VaultFile {
    path: PathBuf,
    handle: File,
    chain: ChainMac,
    prefix: [u8; PREFIX_BYTES],
    record_counter: u64,
    frame_count: u64,
    chain_tail: ChainTag,
    /// Where the authenticated region ends, and therefore where the next frame is
    /// written. Tracked rather than taken from the file length so that bytes left
    /// by a torn append are overwritten instead of appended after.
    end_of_records: u64,
    floor: u64,
}

/// Counts and paths, never content.
impl std::fmt::Debug for VaultFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultFile")
            .field("record_counter", &self.record_counter)
            .field("frame_count", &self.frame_count)
            .finish()
    }
}

impl VaultFile {
    pub fn record_counter(&self) -> u64 {
        self.record_counter
    }

    pub fn frame_count(&self) -> u64 {
        self.frame_count
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one record and commits it.
    ///
    /// The frame is written and flushed before the header names it, so the two are
    /// never both half done: either the header counts the frame and the frame is
    /// there, or the header does not and the bytes are outside the authenticated
    /// region.
    pub(super) fn append(&mut self, frame: &Frame) -> Result<(), VaultError> {
        let bytes = frame.encode()?;
        let tail = self.chain.link(&self.chain_tail, &bytes)?;
        let record_counter = self.record_counter.saturating_add(1);
        let frame_count = self.frame_count.saturating_add(1);

        // Any leftovers from a previous torn append sit here; the frame goes over
        // them rather than after them.
        self.truncate_to(self.end_of_records)?;
        self.write_at(self.end_of_records, &bytes)?;
        self.sync()?;

        let header = Header::encode(
            &self.prefix,
            record_counter,
            frame_count,
            &tail,
            &self
                .chain
                .header(&self.prefix, record_counter, frame_count, &tail)?,
        );
        self.write_at(0, &header)?;
        self.sync()?;

        self.record_counter = record_counter;
        self.frame_count = frame_count;
        self.chain_tail = tail;
        self.end_of_records += bytes.len() as u64;
        self.floor = self.floor.max(record_counter);
        Ok(())
    }

    /// Builds the file this vault would be if it held exactly `frames`.
    ///
    /// The chain is rebuilt from `M_0`, which is what makes compaction possible at
    /// all: an append-only chain cannot lose a link, so dropping records means
    /// writing a new file. The record counter is carried over rather than reset,
    /// because resetting it would make every compaction look like the rollback the
    /// counter exists to detect.
    pub(super) fn image(&self, frames: &[Frame]) -> Result<FileImage, VaultError> {
        let mut body = Vec::new();
        let mut tail = self.chain.seed(&self.prefix)?;
        for frame in frames {
            let bytes = frame.encode()?;
            tail = self.chain.link(&tail, &bytes)?;
            body.extend_from_slice(&bytes);
        }

        let frame_count = frames.len() as u64;
        let header = Header::encode(
            &self.prefix,
            self.record_counter,
            frame_count,
            &tail,
            &self
                .chain
                .header(&self.prefix, self.record_counter, frame_count, &tail)?,
        );

        let mut bytes = Vec::with_capacity(HEADER_BYTES + body.len());
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&body);
        Ok(FileImage {
            bytes,
            frame_count,
            chain_tail: tail,
        })
    }

    /// Takes on an image that has already been swapped in on disk.
    ///
    /// Called by [`super::compaction`] after the rename, and only then: adopting
    /// an image the disk does not carry would leave this process describing a file
    /// that does not exist.
    pub(super) fn adopt(&mut self, image: &FileImage) -> Result<(), VaultError> {
        self.handle = open_handle(&self.path)?;
        self.frame_count = image.frame_count;
        self.chain_tail = image.chain_tail;
        self.end_of_records = image.bytes.len() as u64;
        Ok(())
    }

    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), VaultError> {
        self.handle
            .seek(SeekFrom::Start(offset))
            .map_err(|cause| io_error("written to", &cause))?;
        self.handle
            .write_all(bytes)
            .map_err(|cause| io_error("written to", &cause))
    }

    fn truncate_to(&mut self, length: u64) -> Result<(), VaultError> {
        self.handle
            .set_len(length)
            .map_err(|cause| io_error("written to", &cause))
    }

    fn sync(&mut self) -> Result<(), VaultError> {
        self.handle
            .sync_data()
            .map_err(|cause| io_error("flushed to disk", &cause))
    }
}

/// Opens the vault at `path`, creating it if it is not there yet.
pub(super) fn open(
    path: &Path,
    passphrase: &Passphrase,
    profile: ProfileName,
    floor: CounterFloor,
) -> Result<Loaded, VaultError> {
    match read_all(path)? {
        Some(bytes) => load(path, &bytes, passphrase, floor),
        None => create(path, passphrase, profile),
    }
}

/// Reads the whole file, or says it is not there.
///
/// The vault is bounded by the alias ceiling per session, so reading it whole is
/// how it is verified: the chain has to be walked from `M_0` in order anyway, and
/// a streaming reader would buy nothing but a second code path.
fn read_all(path: &Path) -> Result<Option<Vec<u8>>, VaultError> {
    match File::open(path) {
        Ok(mut handle) => {
            let mut bytes = Vec::new();
            handle
                .read_to_end(&mut bytes)
                .map_err(|cause| io_error("read", &cause))?;
            Ok(Some(bytes))
        }
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(cause) => Err(io_error("opened", &cause)),
    }
}

fn create(
    path: &Path,
    passphrase: &Passphrase,
    profile: ProfileName,
) -> Result<Loaded, VaultError> {
    let parameters = KdfProfile::named(profile);
    let salt = Salt::generate()?;
    let master = key::derive_master_key(&parameters, passphrase, &salt)?;
    let chain = ChainMac::new(key::derive_chain_key(&master)?);

    let prefix = Header::prefix_bytes(&parameters.claimed(), &salt);
    let tail = chain.seed(&prefix)?;
    let header = Header::encode(&prefix, 0, 0, &tail, &chain.header(&prefix, 0, 0, &tail)?);

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|cause| io_error("created", &cause))?;
        }
    }

    let mut handle = create_handle(path)?;
    handle
        .write_all(&header)
        .map_err(|cause| io_error("written to", &cause))?;
    handle
        .sync_data()
        .map_err(|cause| io_error("flushed to disk", &cause))?;

    Ok(Loaded {
        master,
        file: VaultFile {
            path: path.to_path_buf(),
            handle,
            chain,
            prefix,
            record_counter: 0,
            frame_count: 0,
            chain_tail: tail,
            end_of_records: HEADER_BYTES as u64,
            floor: 0,
        },
        frames: Vec::new(),
        parameters,
    })
}

fn load(
    path: &Path,
    bytes: &[u8],
    passphrase: &Passphrase,
    floor: CounterFloor,
) -> Result<Loaded, VaultError> {
    // Step 1: structure, before anything expensive.
    let header = Header::decode(bytes)?;
    // Step 2: bounds, before any derivation. A forged header costs comparisons.
    let parameters = KdfProfile::validate(&header.claimed_kdf)?;
    // Step 3: the key the header's own claims derive.
    let master = key::derive_master_key(&parameters, passphrase, &header.salt)?;
    let chain = ChainMac::new(key::derive_chain_key(&master)?);

    // Step 4: the header tag. Weakened parameters derive a different key, so this
    // is where they are caught, and they are caught before the counter and the
    // chain are believed at all.
    let computed = chain.header(
        &header.prefix,
        header.record_counter,
        header.frame_count,
        &header.chain_tail,
    )?;
    if !chain.verify(&computed, &header.header_mac) {
        return Err(VaultError::IntegrityFailed {
            integrity: Integrity::HeaderMacFailed,
        });
    }

    // Step 5: the counter. The header is authentic by now, so a counter below the
    // floor is an authentic older file, which is what a restore looks like.
    if header.record_counter < floor.value() {
        return Err(VaultError::IntegrityFailed {
            integrity: Integrity::CounterRollback,
        });
    }

    // Step 6: the chain over the frames.
    let (frames, tail, end_of_records) = walk(&chain, &header, bytes)?;
    if !chain.verify(&tail, header.chain_tail.as_bytes()) {
        return Err(VaultError::IntegrityFailed {
            integrity: Integrity::ChainMismatch,
        });
    }

    let handle = open_handle(path)?;
    Ok(Loaded {
        master,
        file: VaultFile {
            path: path.to_path_buf(),
            handle,
            chain,
            prefix: header.prefix,
            record_counter: header.record_counter,
            frame_count: header.frame_count,
            chain_tail: header.chain_tail,
            end_of_records,
            floor: header.record_counter.max(floor.value()),
        },
        frames,
        parameters,
    })
}

/// Walks exactly the frames the header authenticates.
///
/// Every structural failure in here becomes `chain_mismatch` rather than a format
/// error: the header has already authenticated, so these bytes were written by
/// this product or by somebody who edited them, and the second is what the chain
/// is for. Bytes past the last authenticated frame are left alone; see the module
/// documentation.
fn walk(
    chain: &ChainMac,
    header: &Header,
    bytes: &[u8],
) -> Result<(Vec<Frame>, ChainTag, u64), VaultError> {
    let mut tail = chain.seed(&header.prefix)?;
    let mut at = HEADER_BYTES;
    let mut frames = Vec::new();

    for _ in 0..header.frame_count {
        let rest = bytes.get(at..).ok_or(VaultError::IntegrityFailed {
            integrity: Integrity::ChainMismatch,
        })?;
        let (frame, used) = Frame::decode(rest).map_err(|_| VaultError::IntegrityFailed {
            integrity: Integrity::ChainMismatch,
        })?;
        tail = chain.link(&tail, used)?;
        at += used.len();
        frames.push(frame);
    }

    Ok((frames, tail, at as u64))
}

fn open_handle(path: &Path) -> Result<File, VaultError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|cause| io_error("opened", &cause))
}

/// Creates the file, refusing to overwrite one that is already there.
///
/// `create_new` rather than `create`: this path runs when the read above said the
/// file was absent, and between those two moments another process may have
/// created it. Truncating it would destroy a vault.
fn create_handle(path: &Path) -> Result<File, VaultError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    // The vault holds the map from alias back to a real person. Nobody but the
    // account running the proxy has any business reading it (`security.md`,
    // "Kasa"). Set at creation rather than afterwards, so there is no window in
    // which the file exists at the default mode.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|cause| io_error("created", &cause))
}

fn io_error(operation: &'static str, cause: &std::io::Error) -> VaultError {
    VaultError::VaultFileUnavailable {
        operation,
        // The kind rather than the message: the message can carry the path, and a
        // path in a log line is noise the caller already knows.
        cause: format!("{:?}", cause.kind()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::vault::layout::MAGIC;
    use crate::vault::record::{RecordType, SealedRecord, ALIAS_SEED_BYTES, NONCE_BYTES};
    use crate::vault::session::SESSION_ID_BYTES;
    use crate::vault::{AliasSeed, SessionId};

    /// A throwaway directory, written out rather than pulled in: a test only
    /// dependency is still a dependency decision (the same reasoning `proof.rs`
    /// records).
    struct Scratch {
        root: PathBuf,
    }

    impl Scratch {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "periskop-vault-file-{name}-{}-{:?}",
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

        fn listing(&self) -> BTreeMap<PathBuf, Vec<u8>> {
            let mut seen = BTreeMap::new();
            for entry in std::fs::read_dir(&self.root).unwrap().flatten() {
                let path = entry.path();
                let bytes = std::fs::read(&path).unwrap_or_default();
                seen.insert(path, bytes);
            }
            seen
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

    fn frame(byte: u8, alias: &str) -> Frame {
        Frame {
            stored_at_ms: 1_700_000_000_000 + u64::from(byte),
            session: SessionId::from_bytes([0x0A; SESSION_ID_BYTES]),
            alias_seed: AliasSeed::from_bytes([byte; ALIAS_SEED_BYTES]),
            alias: alias.to_owned(),
            sealed: SealedRecord::from_parts([byte; NONCE_BYTES], vec![byte; 40]),
        }
    }

    /// Opens a vault, appends `count` records and returns the path.
    fn seeded(scratch: &Scratch, count: u8) -> PathBuf {
        let path = scratch.vault();
        let mut loaded =
            open(&path, &passphrase(), ProfileName::Ci, CounterFloor::Unknown).unwrap();
        for byte in 1..=count {
            loaded
                .file
                .append(&frame(byte, &format!("PSK_PERSON_{byte}")))
                .unwrap();
        }
        path
    }

    fn reopen(path: &Path, floor: CounterFloor) -> Result<Loaded, VaultError> {
        open(path, &passphrase(), ProfileName::Ci, floor)
    }

    #[test]
    fn a_new_vault_is_a_header_and_nothing_else() {
        let scratch = Scratch::new("create");
        let loaded = open(
            &scratch.vault(),
            &passphrase(),
            ProfileName::Ci,
            CounterFloor::Unknown,
        )
        .unwrap();

        assert_eq!(loaded.file.record_counter(), 0);
        assert_eq!(loaded.file.frame_count(), 0);
        assert!(loaded.frames.is_empty());

        let bytes = std::fs::read(scratch.vault()).unwrap();
        assert_eq!(bytes.len(), HEADER_BYTES);
        assert_eq!(&bytes[..8], &MAGIC);
    }

    #[cfg(unix)]
    #[test]
    fn a_new_vault_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let scratch = Scratch::new("mode");
        open(
            &scratch.vault(),
            &passphrase(),
            ProfileName::Ci,
            CounterFloor::Unknown,
        )
        .unwrap();

        let mode = std::fs::metadata(scratch.vault())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }

    #[test]
    fn records_survive_a_close_and_a_reopen() {
        let scratch = Scratch::new("roundtrip");
        let path = seeded(&scratch, 3);

        let loaded = reopen(&path, CounterFloor::Unknown).unwrap();
        assert_eq!(loaded.file.record_counter(), 3);
        assert_eq!(loaded.file.frame_count(), 3);
        assert_eq!(loaded.frames.len(), 3);
        assert_eq!(loaded.frames[0].alias, "PSK_PERSON_1");
        assert_eq!(loaded.frames[2].alias, "PSK_PERSON_3");
        assert_eq!(loaded.frames[1].sealed, frame(2, "PSK_PERSON_2").sealed);
    }

    #[test]
    fn a_vault_does_not_open_under_another_passphrase() {
        let scratch = Scratch::new("passphrase");
        let path = seeded(&scratch, 1);

        let refusal = open(
            &path,
            &Passphrase::new(b"a different operator".to_vec()),
            ProfileName::Ci,
            CounterFloor::Unknown,
        )
        .unwrap_err();
        // The wrong passphrase derives a different chain key, so the header tag is
        // where it is caught. Fail closed, and the message says nothing about how
        // close the guess was.
        assert_eq!(
            refusal,
            VaultError::IntegrityFailed {
                integrity: Integrity::HeaderMacFailed
            }
        );
    }

    /// Violation one: a record is cut out of the middle of the file.
    #[test]
    fn chain_mismatch_a_record_removed_from_the_middle_does_not_open_the_vault() {
        let scratch = Scratch::new("chain");
        let path = seeded(&scratch, 3);
        let before = std::fs::read(&path).unwrap();

        // Cut the second frame out. Every remaining record still authenticates
        // under its own AAD; only the chain notices.
        let second_at = HEADER_BYTES + frame(1, "PSK_PERSON_1").encode().unwrap().len();
        let second_len = frame(2, "PSK_PERSON_2").encode().unwrap().len();
        let mut tampered = before.clone();
        tampered.drain(second_at..second_at + second_len);
        std::fs::write(&path, &tampered).unwrap();

        let refusal = reopen(&path, CounterFloor::Unknown).unwrap_err();
        assert_eq!(
            refusal,
            VaultError::IntegrityFailed {
                integrity: Integrity::ChainMismatch
            }
        );
        assert_eq!(refusal.http_status(), 503);
        assert_eq!(refusal.integrity(), Some(Integrity::ChainMismatch));
        no_recovery_was_attempted(&scratch, &path, &tampered);
    }

    /// Violation two: an older copy of the file is put back.
    ///
    /// The restored file is internally perfect: its header authenticates, its
    /// chain closes. The only thing wrong with it is that this process has already
    /// seen a later one, which is exactly what the counter is for.
    #[test]
    fn counter_rollback_an_older_file_put_back_does_not_open_the_vault() {
        let scratch = Scratch::new("rollback");
        let path = seeded(&scratch, 2);
        let old = std::fs::read(&path).unwrap();

        // The proxy carries on and the vault grows.
        let mut loaded = reopen(&path, CounterFloor::AtLeast(2)).unwrap();
        loaded.file.append(&frame(3, "PSK_PERSON_3")).unwrap();
        loaded.file.append(&frame(4, "PSK_PERSON_4")).unwrap();
        assert_eq!(loaded.file.record_counter(), 4);
        drop(loaded);

        // Somebody restores yesterday's backup underneath it.
        std::fs::write(&path, &old).unwrap();

        // The older file on its own is a valid vault, which is the point: only the
        // floor tells it apart from the current one.
        assert!(reopen(&path, CounterFloor::Unknown).is_ok());

        let refusal = reopen(&path, CounterFloor::AtLeast(4)).unwrap_err();
        assert_eq!(
            refusal,
            VaultError::IntegrityFailed {
                integrity: Integrity::CounterRollback
            }
        );
        assert_eq!(refusal.http_status(), 503);
        assert_eq!(refusal.integrity(), Some(Integrity::CounterRollback));
        no_recovery_was_attempted(&scratch, &path, &old);
    }

    /// Violation three: the Argon2id parameters in the header are weakened.
    ///
    /// The attack ADR-007 section 4 is written against: lower the cost of guessing
    /// the passphrase offline by editing the parameters the vault will use next
    /// time. The tampered value stays inside the hard bounds on purpose, so that
    /// the refusal comes from the header tag rather than from the range check;
    /// otherwise this test would be proving the wrong thing.
    #[test]
    fn header_mac_failed_weakened_argon2_parameters_do_not_open_the_vault() {
        let scratch = Scratch::new("header");
        let path = scratch.vault();

        // Created at the shipped strength, which is what makes weakening possible
        // while staying in range.
        let mut loaded = open(
            &path,
            &passphrase(),
            ProfileName::Standard,
            CounterFloor::Unknown,
        )
        .unwrap();
        loaded.file.append(&frame(1, "PSK_PERSON_1")).unwrap();
        drop(loaded);

        let honest = std::fs::read(&path).unwrap();
        assert_eq!(&honest[12..16], &(256u32 * 1024).to_le_bytes());

        let mut tampered = honest.clone();
        tampered[12..16].copy_from_slice(&(64u32 * 1024).to_le_bytes());
        std::fs::write(&path, &tampered).unwrap();

        let refusal = open(
            &path,
            &passphrase(),
            ProfileName::Standard,
            CounterFloor::Unknown,
        )
        .unwrap_err();
        assert_eq!(
            refusal,
            VaultError::IntegrityFailed {
                integrity: Integrity::HeaderMacFailed
            }
        );
        assert_eq!(refusal.http_status(), 503);
        assert_eq!(refusal.integrity(), Some(Integrity::HeaderMacFailed));
        no_recovery_was_attempted(&scratch, &path, &tampered);
    }

    /// The other half of every violation test: nothing was repaired.
    ///
    /// A refusal that quietly truncated the file, wrote a repaired copy or left a
    /// quarantine file beside it would be a recovery attempt, and ADR-007 and
    /// `proxy/spec.md` section 10 both forbid one. Checked by bytes rather than by
    /// reading the code, and repeated so that a second attempt cannot heal what the
    /// first refused.
    fn no_recovery_was_attempted(scratch: &Scratch, path: &Path, expected: &[u8]) {
        assert_eq!(
            std::fs::read(path).unwrap(),
            expected,
            "the refused vault file was rewritten"
        );

        let listing = scratch.listing();
        assert_eq!(
            listing.keys().collect::<Vec<_>>(),
            vec![&path.to_path_buf()],
            "a refused open left a file beside the vault"
        );

        let first = reopen(path, CounterFloor::AtLeast(u64::MAX)).is_err();
        let second = reopen(path, CounterFloor::AtLeast(u64::MAX)).is_err();
        assert!(
            first && second,
            "a second attempt opened what the first refused"
        );
        assert_eq!(std::fs::read(path).unwrap(), expected);
    }

    #[test]
    fn a_truncated_file_does_not_open_the_vault() {
        let scratch = Scratch::new("truncated");
        let path = seeded(&scratch, 3);
        let whole = std::fs::read(&path).unwrap();

        // Cut in the middle of the last frame.
        let cut = whole.len() - 10;
        std::fs::write(&path, &whole[..cut]).unwrap();
        assert_eq!(
            reopen(&path, CounterFloor::Unknown).unwrap_err(),
            VaultError::IntegrityFailed {
                integrity: Integrity::ChainMismatch
            }
        );

        // Cut inside the header: not one of the three violations, and it does not
        // claim to be.
        std::fs::write(&path, &whole[..HEADER_BYTES - 1]).unwrap();
        let refusal = reopen(&path, CounterFloor::Unknown).unwrap_err();
        assert_eq!(refusal.integrity(), None);
        assert_eq!(refusal.http_status(), 503);
    }

    #[test]
    fn a_reordered_pair_of_records_does_not_open_the_vault() {
        let scratch = Scratch::new("reorder");
        let path = seeded(&scratch, 2);
        let whole = std::fs::read(&path).unwrap();

        let first = frame(1, "PSK_PERSON_1").encode().unwrap();
        let second = frame(2, "PSK_PERSON_2").encode().unwrap();
        let mut swapped = whole[..HEADER_BYTES].to_vec();
        swapped.extend_from_slice(&second);
        swapped.extend_from_slice(&first);
        std::fs::write(&path, &swapped).unwrap();

        assert_eq!(
            reopen(&path, CounterFloor::Unknown).unwrap_err(),
            VaultError::IntegrityFailed {
                integrity: Integrity::ChainMismatch
            }
        );
    }

    /// A record cannot be moved from one vault into another, even when the two
    /// were opened with the same passphrase.
    ///
    /// The donor's record is deliberately a different one: grafting a byte
    /// identical frame would prove nothing, because it would still be this vault's
    /// own record. What is grafted here is a record this vault never held, which
    /// is what an attacker with two vault files actually has.
    #[test]
    fn a_record_from_another_vault_does_not_open_this_one() {
        let scratch = Scratch::new("graft");
        let donor = Scratch::new("graft-donor");
        let path = seeded(&scratch, 1);

        let other = donor.vault();
        let mut donated = open(
            &other,
            &passphrase(),
            ProfileName::Ci,
            CounterFloor::Unknown,
        )
        .unwrap();
        donated
            .file
            .append(&frame(0x7E, "PSK_PERSON_ELSEWHERE"))
            .unwrap();
        drop(donated);

        let mine = std::fs::read(&path).unwrap();
        let theirs = std::fs::read(&other).unwrap();
        assert_ne!(&mine[HEADER_BYTES..], &theirs[HEADER_BYTES..]);

        // The header stays mine, so the counter and the frame count still say one
        // record; the record itself comes from the other file.
        let mut grafted = mine[..HEADER_BYTES].to_vec();
        grafted.extend_from_slice(&theirs[HEADER_BYTES..]);
        std::fs::write(&path, &grafted).unwrap();

        assert_eq!(
            reopen(&path, CounterFloor::Unknown).unwrap_err(),
            VaultError::IntegrityFailed {
                integrity: Integrity::ChainMismatch
            }
        );
    }

    /// The counter does not go down and the floor rises with it.
    #[test]
    fn the_record_counter_only_ever_rises() {
        let scratch = Scratch::new("monotonic");
        let path = scratch.vault();
        let mut loaded =
            open(&path, &passphrase(), ProfileName::Ci, CounterFloor::Unknown).unwrap();

        let mut seen = 0;
        for byte in 1..=4u8 {
            loaded
                .file
                .append(&frame(byte, &format!("PSK_PERSON_{byte}")))
                .unwrap();
            assert!(loaded.file.record_counter() > seen);
            seen = loaded.file.record_counter();
        }
        assert_eq!(seen, 4);

        // And the floor a caller passes cannot be talked down by the file.
        assert!(reopen(&path, CounterFloor::AtLeast(5)).is_err());
        assert!(reopen(&path, CounterFloor::AtLeast(4)).is_ok());
    }

    /// A process killed between writing a frame and committing the header.
    ///
    /// The record was never counted by the header, so it was never in the vault:
    /// the file opens with the records that were committed and the orphan bytes
    /// are outside the authenticated region. The next append writes over them
    /// rather than after them, which is checked here because an append that landed
    /// after the orphan would leave a hole the chain could never close.
    #[test]
    fn a_torn_append_leaves_the_committed_records_readable() {
        let scratch = Scratch::new("torn");
        let path = seeded(&scratch, 2);

        let mut torn = std::fs::read(&path).unwrap();
        torn.extend_from_slice(&frame(3, "PSK_PERSON_3").encode().unwrap()[..30]);
        std::fs::write(&path, &torn).unwrap();

        let mut loaded = reopen(&path, CounterFloor::Unknown).unwrap();
        assert_eq!(loaded.frames.len(), 2);
        assert_eq!(loaded.file.record_counter(), 2);

        loaded.file.append(&frame(4, "PSK_PERSON_4")).unwrap();
        drop(loaded);

        let reloaded = reopen(&path, CounterFloor::Unknown).unwrap();
        assert_eq!(reloaded.frames.len(), 3);
        assert_eq!(reloaded.frames[2].alias, "PSK_PERSON_4");
        assert_eq!(reloaded.file.record_counter(), 3);
    }

    /// A header claiming parameters outside the hard bounds is refused before any
    /// derivation, which is the resource exhaustion answer ADR-007 section 4 asks
    /// for. It is not one of the three integrity violations and does not say it is.
    #[test]
    fn a_header_claiming_impossible_parameters_is_refused_before_derivation() {
        let scratch = Scratch::new("bounds");
        let path = seeded(&scratch, 1);

        let mut tampered = std::fs::read(&path).unwrap();
        tampered[12..16].copy_from_slice(&4_000_000u32.to_le_bytes());
        std::fs::write(&path, &tampered).unwrap();

        let started = std::time::Instant::now();
        let refusal = reopen(&path, CounterFloor::Unknown).unwrap_err();
        assert!(matches!(refusal, VaultError::KdfParameterOutOfRange { .. }));
        assert_eq!(refusal.integrity(), None);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn the_debug_rendering_of_an_open_file_says_nothing_about_its_records() {
        let scratch = Scratch::new("debug");
        let loaded = reopen(&seeded(&scratch, 1), CounterFloor::Unknown).unwrap();
        let rendered = format!("{:?}", loaded.file);
        assert!(rendered.contains("record_counter"), "{rendered}");
        assert!(!rendered.contains("PSK_PERSON_1"), "{rendered}");
    }

    #[test]
    fn the_record_type_tag_round_trips_and_refuses_what_it_does_not_know() {
        assert_eq!(
            RecordType::from_tag(RecordType::Alias.tag()),
            Some(RecordType::Alias)
        );
        assert_eq!(RecordType::from_tag(0), None);
        assert_eq!(RecordType::from_tag(2), None);
    }
}
