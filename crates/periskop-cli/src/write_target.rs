//! The one place this program creates or replaces a file.
//!
//! Every command writes somewhere a user named: an envelope beside a report, a
//! key pair, a directory of flow records. A path a user names is a path a user
//! can get wrong, and here it is worse than that. The sensor is documented to
//! run with `CAP_BPF` and `CAP_PERFMON`, so a write it performs carries
//! privileges the person who arranged the path may not hold.
//!
//! The rule this module exists to enforce is narrow and absolute: **a write
//! never travels through a symbolic link.** `std::fs::write` follows one, and so
//! does `OpenOptions::truncate`, which means a record file that is a link to
//! somebody's key material empties that key material instead. Worse, truncation
//! happens when the file is opened, so the command can report a failure it
//! believes was harmless while the other file is already gone.
//!
//! Refusing rather than replacing the link is the deliberate half. A link at a
//! path this command was told to write is a fact about the machine its operator
//! should hear about, and quietly replacing it would answer a question nobody
//! asked while hiding one somebody needs to.

use std::fs::{File, Metadata, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// What to do about a file that is already at the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Existing {
    /// Stop, and leave what is there exactly as it is.
    Refuse,
    /// Replace the contents of the file that is there.
    Replace,
}

/// Whether a file may be read by anyone else on the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Visibility {
    Private,
    Public,
}

/// What a completed private write could not guarantee.
///
/// Returned rather than logged in here, because the caller is the one that knows
/// what the file holds and can say what an unenforced restriction costs. The
/// alternative was the line this type replaced, a discard that turned a platform
/// this build cannot restrict a file on into no output at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Restriction {
    /// The file is readable by its owner and nobody else.
    AsRequested,
    /// The file was written on a platform whose access control this build does
    /// not set, so it carries whatever access that platform gives by default.
    NotEnforceable,
}

#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error(
        "{path} is {kind}, and this command writes regular files: writing through it would change a file nobody named"
    )]
    NotARegularFile { path: PathBuf, kind: &'static str },

    #[error("{path} is already there")]
    AlreadyThere { path: PathBuf },

    #[error(
        "{path} was replaced while this command was looking at it, so nothing was written to it"
    )]
    ChangedUnderneath { path: PathBuf },

    #[error("{path} could not be written: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Writes a file the rest of the machine may read.
pub fn write_public(path: &Path, contents: &[u8], existing: Existing) -> Result<(), WriteError> {
    // Public files ask for nothing a platform could fail to enforce, so the
    // caller is handed no outcome to weigh.
    let _restriction = write(path, contents, existing, Visibility::Public)?;
    Ok(())
}

/// Writes a file only its owner may read, and says whether that could be kept.
pub fn write_private(
    path: &Path,
    contents: &[u8],
    existing: Existing,
) -> Result<Restriction, WriteError> {
    write(path, contents, existing, Visibility::Private)
}

fn write(
    path: &Path,
    contents: &[u8],
    existing: Existing,
    visibility: Visibility,
) -> Result<Restriction, WriteError> {
    let (mut file, replacing) = open(path, existing, visibility)?;
    let io = |source| WriteError::Io {
        path: path.to_path_buf(),
        source,
    };

    let restriction = restrict(&file, visibility).map_err(io)?;
    if replacing {
        // Emptied here rather than by `truncate(true)` on the open above. The
        // truncation an open performs happens before anything can be checked, so
        // a path swapped for a link since the look below would already have been
        // followed and emptied. By this line the descriptor is known to be the
        // file that was checked.
        file.set_len(0).map_err(io)?;
    }
    file.write_all(contents).map_err(io)?;
    file.sync_all().map_err(io)?;
    Ok(restriction)
}

/// Opens the target, and refuses anything that is not a regular file.
///
/// Returns whether an existing file is being replaced, because the caller has to
/// empty that file and must not empty one it just created.
#[cfg_attr(not(unix), allow(unused_variables))]
fn open(
    path: &Path,
    existing: Existing,
    visibility: Visibility,
) -> Result<(File, bool), WriteError> {
    let io = |source| WriteError::Io {
        path: path.to_path_buf(),
        source,
    };

    // `symlink_metadata` rather than `metadata`: it reports the link itself
    // instead of whatever the link points at, which is the only way to see that
    // a write would land somewhere else entirely.
    let present = match std::fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(io(e)),
    };

    if let Some(metadata) = &present {
        if let Some(kind) = irregular(metadata) {
            return Err(WriteError::NotARegularFile {
                path: path.to_path_buf(),
                kind,
            });
        }
        if existing == Existing::Refuse {
            return Err(WriteError::AlreadyThere {
                path: path.to_path_buf(),
            });
        }
    }

    let mut options = OpenOptions::new();
    options.write(true);
    if present.is_none() {
        // `create_new` rather than `create`: it fails when anything at all is at
        // the path, a symbolic link included, so a link made in the moment
        // between the look above and this call cannot be raced into a write that
        // follows it.
        options.create_new(true);
    }

    #[cfg(unix)]
    if visibility == Visibility::Private {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Applied at creation rather than afterwards, so a newly created key is
        // never world readable, not even for the moment between two calls.
        options.mode(0o600);
    }

    let file = options.open(path).map_err(io)?;

    let Some(checked) = present else {
        return Ok((file, false));
    };
    // The look and the open are two steps, and the path can be swapped between
    // them. Nothing has been emptied or written yet, so a mismatch costs the
    // caller an error rather than a file.
    if !is_the_checked_file(&checked, &file.metadata().map_err(io)?) {
        return Err(WriteError::ChangedUnderneath {
            path: path.to_path_buf(),
        });
    }
    Ok((file, true))
}

/// Names what is at the path when it is not a regular file, for the message.
fn irregular(metadata: &Metadata) -> Option<&'static str> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        Some("a symbolic link")
    } else if file_type.is_dir() {
        Some("a directory")
    } else if file_type.is_file() {
        None
    } else {
        Some("not a regular file")
    }
}

/// Whether the opened descriptor is the file that was looked at.
///
/// The device and inode numbers identify a file independently of the name it was
/// reached through, so a path swapped for a link to somewhere else opens a
/// different pair and is caught.
#[cfg(unix)]
fn is_the_checked_file(checked: &Metadata, opened: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    checked.dev() == opened.dev() && checked.ino() == opened.ino()
}

/// Platforms without inode numbers keep the check that does exist: what was at
/// the path a moment ago was a regular file. The window between that look and
/// the open is not closed there, and this build says so here rather than
/// implying a guarantee it does not deliver.
#[cfg(not(unix))]
fn is_the_checked_file(_checked: &Metadata, _opened: &Metadata) -> bool {
    true
}

/// Narrows an open file to its owner, or reports that it could not be narrowed.
///
/// Through the descriptor rather than the path, so this cannot be pointed at a
/// second file by anything that happens to the name in between.
#[cfg_attr(not(unix), allow(unused_variables))]
fn restrict(file: &File, visibility: Visibility) -> std::io::Result<Restriction> {
    if visibility == Visibility::Public {
        return Ok(Restriction::AsRequested);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // The mode given at creation only applies to a file this call created.
        // A replaced file keeps whatever permissions it had, so a key written
        // over a world readable file would stay world readable.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(Restriction::AsRequested)
    }
    #[cfg(not(unix))]
    {
        Ok(Restriction::NotEnforceable)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "periskop-write-target-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Self(root)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_new_file_is_created_with_the_contents_it_was_given() {
        let scratch = Scratch::new("create");
        let path = scratch.path("out.txt");
        write_public(&path, b"one\n", Existing::Refuse).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"one\n");
    }

    #[test]
    fn a_replaced_file_holds_only_the_new_contents() {
        // The truncation this module performs through the descriptor has to be
        // as complete as the one it refuses to let the open perform.
        let scratch = Scratch::new("replace");
        let path = scratch.path("out.txt");
        write_public(&path, b"a longer first version\n", Existing::Refuse).unwrap();
        write_public(&path, b"short\n", Existing::Replace).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"short\n");
    }

    #[test]
    fn an_existing_file_is_left_alone_when_replacing_was_not_asked_for() {
        let scratch = Scratch::new("refuse");
        let path = scratch.path("out.txt");
        write_public(&path, b"first\n", Existing::Refuse).unwrap();

        let error = write_public(&path, b"second\n", Existing::Refuse).unwrap_err();
        assert!(matches!(error, WriteError::AlreadyThere { .. }), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), b"first\n");
    }

    #[cfg(unix)]
    #[test]
    fn a_write_through_a_symbolic_link_is_refused_and_the_other_file_is_untouched() {
        // The whole reason this module exists. `std::fs::write` here empties
        // `victim.txt`, which is a file nobody pointed this command at.
        let scratch = Scratch::new("symlink");
        let victim = scratch.path("victim.txt");
        let link = scratch.path("out.txt");
        std::fs::write(&victim, b"data somebody needs\n").unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        for existing in [Existing::Refuse, Existing::Replace] {
            let error = write_public(&link, b"clobber\n", existing).unwrap_err();
            assert!(
                matches!(error, WriteError::NotARegularFile { .. }),
                "{error}"
            );
        }
        assert_eq!(std::fs::read(&victim).unwrap(), b"data somebody needs\n");
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symbolic_link_is_refused_rather_than_creating_its_target() {
        // A link to a path that does not exist yet is the version of the attack
        // that leaves nothing to notice afterwards: the write creates the target.
        let scratch = Scratch::new("dangling");
        let link = scratch.path("out.txt");
        let target = scratch.path("not-there-yet.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let error = write_public(&link, b"clobber\n", Existing::Replace).unwrap_err();
        assert!(
            matches!(error, WriteError::NotARegularFile { .. }),
            "{error}"
        );
        assert!(!target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_at_the_path_is_refused_by_name() {
        let scratch = Scratch::new("directory");
        let path = scratch.path("out.txt");
        std::fs::create_dir(&path).unwrap();

        match write_public(&path, b"x\n", Existing::Replace) {
            Err(WriteError::NotARegularFile { kind, .. }) => assert_eq!(kind, "a directory"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_private_file_is_readable_by_its_owner_and_nobody_else() {
        use std::os::unix::fs::PermissionsExt as _;
        let scratch = Scratch::new("private");
        let path = scratch.path("k.secret");
        assert_eq!(
            write_private(&path, b"key\n", Existing::Refuse).unwrap(),
            Restriction::AsRequested
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode is {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn a_replaced_private_file_is_narrowed_rather_than_inheriting_its_old_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let scratch = Scratch::new("private-replace");
        let path = scratch.path("k.secret");
        std::fs::write(&path, b"placeholder\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(
            write_private(&path, b"key\n", Existing::Replace).unwrap(),
            Restriction::AsRequested
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode is {mode:o}");
    }
}
