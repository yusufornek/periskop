//! Walking a project and deciding what counts as a code surface.
//!
//! Two categories of file leave the walk here, and the difference between them is
//! the whole point of this module.
//!
//! A file excluded by an ignore rule is not part of the code surface at all. It
//! does not appear in the coverage statement, because counting a repository's
//! dependency tree would make the coverage ratio a measure of `node_modules`
//! rather than of anything the scan missed.
//!
//! A file that *is* a code surface but could not be read is different. It is
//! recorded with the reason it was skipped. That is the honest coverage rule made
//! operational: a clean report from an unreadable tree is a lie, and the only
//! defence is to make the skip visible.

use std::io::Read;
use std::path::{Path, PathBuf};

use periskop_core::coverage::UnparsedReason;

use crate::language::Language;

/// Default ceiling on file size. Larger files are counted, never read.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// How much of a file is inspected when deciding whether it is binary.
const BINARY_SNIFF_BYTES: usize = 8 * 1024;

/// A file that will be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredFile {
    /// Always relative to the scan root. Absolute paths never reach a report,
    /// because they would embed the build machine into supposedly identical runs.
    pub path: PathBuf,
    pub language: Language,
    pub size_bytes: u64,
    /// blake3 of the contents, used to skip re-parsing unchanged files.
    pub content_hash: String,
}

/// A file that belongs to the code surface but was not parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedFile {
    pub path: PathBuf,
    pub reason: UnparsedReason,
}

/// Result of walking a project root.
#[derive(Debug, Default)]
pub struct Discovery {
    pub files: Vec<DiscoveredFile>,
    pub skipped: Vec<SkippedFile>,
    /// Problems with the walk itself rather than with any one file: an ignore
    /// file the walker could not parse, or a path that cannot be written into a
    /// report at all.
    ///
    /// Kept apart from `skipped` on purpose. These are engine level faults and
    /// belong in the report diagnostics block; folding them into the coverage
    /// counters would make a threshold over those counters meaningless (K-10).
    pub diagnostics: Vec<String>,
}

/// Knobs a caller may turn. Defaults match the specification.
#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub max_file_bytes: u64,
    /// Honour `.gitignore`, `.ignore` and `.periskopignore`.
    pub respect_ignore_files: bool,
    /// Directory names dropped from the walk whatever the ignore files say.
    ///
    /// Defaults to [`ALWAYS_EXCLUDED_DIRS`] and is a field rather than a
    /// constant because the default is a guess about what a name means. `build`
    /// and `dist` are output directories in most repositories and ordinary
    /// source packages in some, so `src/build/pipeline.py` was dropped by name
    /// alone with nothing anywhere saying it had been; `vendor` is third party
    /// code that a Go binary actually ships, which is a different question from
    /// "did the user write it". A caller who knows their own layout can now say
    /// so instead of being overruled by a list compiled from other people's.
    pub excluded_dirs: Vec<String>,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            respect_ignore_files: true,
            excluded_dirs: ALWAYS_EXCLUDED_DIRS
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
        }
    }
}

/// Directories excluded unless the caller says otherwise.
///
/// These are usually not code the user wrote. Reporting a call site inside a
/// vendored dependency as if it were the user's own is a false positive that
/// erodes trust in every other finding in the report.
///
/// "Usually" is the whole reason this is a default rather than a law, and why
/// [`DiscoveryOptions::excluded_dirs`] exists: the list matches on a name, and a
/// name is not a fact about what is inside. A tree excluded here leaves no trace
/// in any coverage counter, so the caller who disagrees with the guess has to be
/// able to say so.
pub const ALWAYS_EXCLUDED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "target",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "vendor",
];

/// Walks `root` and classifies everything under it.
///
/// Results are sorted by path so that two runs over the same tree produce the
/// same order. Ordering is applied here rather than at serialization time,
/// because a later stage that forgets to sort would otherwise leak filesystem
/// order into the report.
pub fn discover(root: &Path, options: &DiscoveryOptions) -> Discovery {
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .hidden(false)
        .parents(false)
        .follow_links(false)
        .git_ignore(options.respect_ignore_files)
        .git_global(false)
        .git_exclude(options.respect_ignore_files)
        .ignore(options.respect_ignore_files)
        // Without this, .gitignore is only applied inside a git checkout. Scanning
        // an exported tree or a container build context would then quietly walk
        // everything the author meant to exclude, and the extra findings would look
        // like the user's own code.
        .require_git(false);

    if options.respect_ignore_files {
        // Project specific overrides, applied on top of .gitignore.
        builder.add_custom_ignore_filename(".periskopignore");
    }

    // Cloned because the walker keeps the predicate for the length of the walk
    // and will not borrow from this frame.
    let excluded: Vec<String> = options.excluded_dirs.clone();
    builder.filter_entry(move |entry| {
        !entry
            .file_name()
            .to_str()
            .is_some_and(|name| excluded.iter().any(|e| e == name))
    });

    let mut discovery = Discovery::default();

    for entry in builder.build() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                record_walk_error(root, &error, &mut discovery);
                continue;
            }
        };

        let path = entry.path();
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        if relative.as_os_str().is_empty() {
            continue;
        }
        if relative.to_str().is_none() {
            // A path that is not valid UTF-8 cannot be written into a report
            // without being altered, and two different names can collapse onto
            // one string once the invalid bytes are replaced. Two findings would
            // then share an identity, so the file leaves the scan here and says
            // so rather than being converted quietly.
            discovery.diagnostics.push(format!(
                "path is not valid UTF-8 and was left out of the scan: {}",
                relative.display()
            ));
            continue;
        }

        let file_type = entry.file_type();
        if file_type.is_some_and(|t| t.is_symlink()) {
            discovery.skipped.push(SkippedFile {
                path: relative.to_path_buf(),
                reason: unfollowed_link_reason(path, relative),
            });
            continue;
        }
        if !file_type.is_some_and(|t| t.is_file()) {
            continue;
        }

        classify_file(path, relative, options, &mut discovery);
    }

    discovery.files.sort_by(|a, b| a.path.cmp(&b.path));
    discovery.skipped.sort_by(|a, b| a.path.cmp(&b.path));
    discovery.skipped.dedup();
    discovery.diagnostics.sort();
    discovery.diagnostics.dedup();
    discovery
}

/// Records a path the walk could not read.
///
/// The path comes from the error when the walker managed to name one and falls
/// back to the scan root when it did not, which is the most specific thing that
/// can be said in that case. Either way the gap reaches the coverage statement.
/// An unreadable directory used to be dropped with `continue` while a comment
/// claimed it was counted, so every source file underneath it left no trace in
/// any list or counter, the ratio still read zero, and the coverage gate passed.
///
/// Errors that are not about reading a path are a different thing: an ignore
/// file with a pattern the walker rejects does not mean a file went unread, so
/// it goes to diagnostics rather than to the coverage counters.
fn record_walk_error(root: &Path, error: &ignore::Error, discovery: &mut Discovery) {
    if !error.is_io() && !matches!(error, ignore::Error::Loop { .. }) {
        discovery.diagnostics.push(format!("walk problem: {error}"));
        return;
    }

    let path = walk_error_path(error)
        .and_then(|p| p.strip_prefix(root).ok())
        .filter(|p| !p.as_os_str().is_empty() && p.to_str().is_some())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    discovery.skipped.push(SkippedFile {
        path,
        reason: UnparsedReason::IoError,
    });
}

/// The path a walk error is about, when it names one.
///
/// The walker wraps errors in layers that carry the depth or the line number, so
/// the path sits underneath rather than on the outside.
fn walk_error_path(error: &ignore::Error) -> Option<&Path> {
    match error {
        ignore::Error::WithPath { path, .. } => Some(path),
        ignore::Error::Loop { child, .. } => Some(child),
        ignore::Error::WithDepth { err, .. } | ignore::Error::WithLineNumber { err, .. } => {
            walk_error_path(err)
        }
        _ => None,
    }
}

/// How a link the walk refused to follow is counted.
///
/// Links are not followed because a link back to an ancestor makes the walk
/// unbounded and the walker cannot tell one from a shortcut before walking it.
/// The consequence is that whatever the link points at went unread, and that has
/// to be stated: a monorepo whose `services/shared` is a link into `libs/shared`
/// used to produce a clean report with the linked tree never scanned, and the
/// list that collected the links was written and never read by anything.
///
/// Of the eight reasons the contract fixes, `io_error` is the only one that says
/// "this path belongs to the code surface and its contents were not obtained".
/// A link whose own name is not a code file is counted the way a plain file of
/// that name would be, so a linked README does not move the ratio.
fn unfollowed_link_reason(absolute: &Path, relative: &Path) -> UnparsedReason {
    let points_at_a_directory = std::fs::metadata(absolute).is_ok_and(|m| m.is_dir());
    if points_at_a_directory || Language::from_path(relative).is_some() {
        UnparsedReason::IoError
    } else {
        UnparsedReason::UnknownLanguage
    }
}

fn classify_file(
    absolute: &Path,
    relative: &Path,
    options: &DiscoveryOptions,
    discovery: &mut Discovery,
) {
    let skip = |reason: UnparsedReason, discovery: &mut Discovery| {
        discovery.skipped.push(SkippedFile {
            path: relative.to_path_buf(),
            reason,
        });
    };

    let size_bytes = match absolute.metadata() {
        Ok(meta) => meta.len(),
        Err(_) => {
            skip(UnparsedReason::IoError, discovery);
            return;
        }
    };

    if size_bytes > options.max_file_bytes {
        skip(UnparsedReason::SkippedTooLarge, discovery);
        return;
    }

    let bytes = match std::fs::read(absolute) {
        Ok(bytes) => bytes,
        Err(_) => {
            skip(UnparsedReason::IoError, discovery);
            return;
        }
    };

    // Binary check runs before language detection. A `.py` file that is really a
    // compiled blob would otherwise reach the parser and produce noise.
    if looks_binary(&bytes) {
        skip(UnparsedReason::SkippedBinary, discovery);
        return;
    }

    let Some(language) = Language::from_path(relative) else {
        skip(UnparsedReason::UnknownLanguage, discovery);
        return;
    };

    discovery.files.push(DiscoveredFile {
        path: relative.to_path_buf(),
        language,
        size_bytes,
        content_hash: blake3::hash(&bytes).to_hex().to_string(),
    });
}

/// Heuristic used by git and most scanners: a NUL byte early in the file.
///
/// It is a heuristic and it can be wrong. Being wrong is acceptable here only
/// because the outcome is recorded rather than silent: a misjudged file shows up
/// as `skipped_binary` in the coverage statement, where a reader can see it.
fn looks_binary(bytes: &[u8]) -> bool {
    let window = &bytes[..bytes.len().min(BINARY_SNIFF_BYTES)];
    window.contains(&0)
}

/// Reads a file's text for parsing, mapping failures onto coverage reasons.
pub fn read_source(root: &Path, relative: &Path) -> Result<String, UnparsedReason> {
    let mut file = std::fs::File::open(root.join(relative)).map_err(|_| UnparsedReason::IoError)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|_| UnparsedReason::IoError)?;
    // Invalid UTF-8 is an encoding problem, not a syntax problem. Calling it
    // io_error would be wrong, and inventing a ninth reason is forbidden, so it
    // is reported as unreadable input.
    String::from_utf8(buffer).map_err(|_| UnparsedReason::IoError)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    struct TempTree(PathBuf);

    impl TempTree {
        fn new(name: &str) -> Self {
            // The process id is part of the name because the first thing this
            // does is delete the directory. Two runs on one machine, or two
            // users on a shared one, would otherwise remove each other's tree
            // mid-test and produce a red result with no visible cause.
            let dir = std::env::temp_dir()
                .join(format!("periskop-discovery-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn write(&self, relative: &str, contents: &[u8]) {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, contents).unwrap();
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn finds_source_files_and_records_relative_paths() {
        let tree = TempTree::new("basic");
        tree.write("app/main.py", b"x = 1\n");
        tree.write("web/index.ts", b"const a = 1;\n");

        let found = discover(tree.path(), &DiscoveryOptions::default());

        assert_eq!(found.files.len(), 2);
        assert!(found.files.iter().all(|f| f.path.is_relative()));
        assert_eq!(found.files[0].path, PathBuf::from("app/main.py"));
        assert_eq!(found.files[0].language, Language::Python);
    }

    #[test]
    fn results_are_sorted_so_two_runs_agree() {
        let tree = TempTree::new("order");
        for name in ["z.py", "a.py", "m.py"] {
            tree.write(name, b"pass\n");
        }
        let first = discover(tree.path(), &DiscoveryOptions::default());
        let second = discover(tree.path(), &DiscoveryOptions::default());

        let names: Vec<_> = first.files.iter().map(|f| f.path.clone()).collect();
        assert_eq!(
            names,
            vec![
                PathBuf::from("a.py"),
                PathBuf::from("m.py"),
                PathBuf::from("z.py")
            ]
        );
        assert_eq!(first.files, second.files);
    }

    #[test]
    fn a_deliberately_broken_file_is_never_skipped_silently() {
        // The acceptance criterion for this stage: whatever the reason, the file
        // reaches the coverage statement with the right label.
        let tree = TempTree::new("skips");
        tree.write("bin/blob.py", b"\x00\x01\x02binary");
        tree.write("notes.md", b"# not code\n");
        tree.write("big.py", &vec![b'x'; 4096]);

        let options = DiscoveryOptions {
            max_file_bytes: 1024,
            ..Default::default()
        };
        let found = discover(tree.path(), &options);

        let reason_for = |name: &str| {
            found
                .skipped
                .iter()
                .find(|s| s.path == Path::new(name))
                .map(|s| s.reason)
        };

        assert_eq!(
            reason_for("bin/blob.py"),
            Some(UnparsedReason::SkippedBinary)
        );
        assert_eq!(
            reason_for("notes.md"),
            Some(UnparsedReason::UnknownLanguage)
        );
        assert_eq!(reason_for("big.py"), Some(UnparsedReason::SkippedTooLarge));
        assert!(found.files.is_empty());
    }

    #[test]
    fn dependency_trees_are_excluded_and_not_counted() {
        // Excluded is not the same as skipped. A vendored tree is not part of the
        // code surface, so counting it would distort the coverage ratio.
        let tree = TempTree::new("vendored");
        tree.write("src/app.py", b"pass\n");
        tree.write("node_modules/pkg/index.js", b"module.exports = 1;\n");
        tree.write("target/debug/build.py", b"pass\n");

        let found = discover(tree.path(), &DiscoveryOptions::default());

        assert_eq!(found.files.len(), 1);
        assert_eq!(found.files[0].path, PathBuf::from("src/app.py"));
        assert!(
            found.skipped.is_empty(),
            "excluded paths must not inflate the coverage statement"
        );
    }

    #[test]
    fn a_source_package_named_like_an_output_directory_is_dropped_by_default() {
        // The defect this records rather than hides. `build` is an output
        // directory in most repositories and a package name in some, and the
        // default list cannot tell them apart: the call in `src/build/` leaves
        // no finding, no skipped entry and no counter, so a reader of the report
        // sees a clean scan of a tree that was never opened.
        let tree = TempTree::new("named-build");
        tree.write("src/build/pipeline.py", b"pass\n");

        let found = discover(tree.path(), &DiscoveryOptions::default());

        assert!(found.files.is_empty());
        assert!(found.skipped.is_empty());
    }

    #[test]
    fn a_caller_can_narrow_the_exclusions_and_get_its_own_source_back() {
        // The half of the defect that is fixable here: the list is a default,
        // so a project that keeps sources under `build/` can say so.
        let tree = TempTree::new("narrowed");
        tree.write("src/build/pipeline.py", b"pass\n");
        tree.write("node_modules/pkg/index.js", b"module.exports = 1;\n");

        let options = DiscoveryOptions {
            excluded_dirs: ALWAYS_EXCLUDED_DIRS
                .iter()
                .filter(|name| **name != "build")
                .map(|name| (*name).to_owned())
                .collect(),
            ..DiscoveryOptions::default()
        };
        let found = discover(tree.path(), &options);

        let paths: Vec<_> = found.files.iter().map(|f| f.path.clone()).collect();
        assert_eq!(paths, [PathBuf::from("src/build/pipeline.py")]);
    }

    #[test]
    fn gitignore_entries_are_honoured() {
        let tree = TempTree::new("gitignore");
        tree.write(".gitignore", b"generated/\n");
        tree.write("src/app.py", b"pass\n");
        tree.write("generated/schema.py", b"pass\n");

        let found = discover(tree.path(), &DiscoveryOptions::default());
        let paths: Vec<_> = found.files.iter().map(|f| f.path.clone()).collect();

        assert_eq!(paths, vec![PathBuf::from("src/app.py")]);
    }

    #[test]
    fn periskopignore_is_honoured_alongside_gitignore() {
        let tree = TempTree::new("periskopignore");
        tree.write(".periskopignore", b"fixtures/\n");
        tree.write("src/app.py", b"pass\n");
        tree.write("fixtures/sample.py", b"pass\n");

        let found = discover(tree.path(), &DiscoveryOptions::default());
        let paths: Vec<_> = found.files.iter().map(|f| f.path.clone()).collect();

        assert_eq!(paths, vec![PathBuf::from("src/app.py")]);
    }

    #[test]
    fn content_hash_tracks_content_not_name() {
        let tree = TempTree::new("hash");
        tree.write("a.py", b"same\n");
        tree.write("b.py", b"same\n");
        tree.write("c.py", b"different\n");

        let found = discover(tree.path(), &DiscoveryOptions::default());
        let hash_of = |name: &str| {
            found
                .files
                .iter()
                .find(|f| f.path == Path::new(name))
                .map(|f| f.content_hash.clone())
                .unwrap()
        };

        assert_eq!(hash_of("a.py"), hash_of("b.py"));
        assert_ne!(hash_of("a.py"), hash_of("c.py"));
    }

    #[test]
    fn empty_tree_yields_empty_results_without_error() {
        let tree = TempTree::new("empty");
        let found = discover(tree.path(), &DiscoveryOptions::default());
        assert!(found.files.is_empty());
        assert!(found.skipped.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn a_link_the_walk_will_not_follow_reaches_the_coverage_statement() {
        // The error class this test catches: a linked source tree that is never
        // scanned and never mentioned. The links used to be collected into a
        // field that nothing in the workspace read, so the report came back
        // clean with an entire subtree unvisited.
        use std::os::unix::fs::symlink;

        let tree = TempTree::new("links");
        tree.write("real/app.py", b"pass\n");
        tree.write("lib/client.py", b"pass\n");
        tree.write("notes.txt", b"text\n");
        symlink(tree.path().join("lib"), tree.path().join("shared")).unwrap();
        symlink(
            tree.path().join("real/app.py"),
            tree.path().join("alias.py"),
        )
        .unwrap();
        symlink(tree.path().join("notes.txt"), tree.path().join("alias.txt")).unwrap();

        let found = discover(tree.path(), &DiscoveryOptions::default());
        let reason_for = |name: &str| {
            found
                .skipped
                .iter()
                .find(|s| s.path == Path::new(name))
                .map(|s| s.reason)
        };

        assert_eq!(reason_for("shared"), Some(UnparsedReason::IoError));
        assert_eq!(reason_for("alias.py"), Some(UnparsedReason::IoError));
        // A link to something that is not code is counted the way a plain file
        // of that name would be, so it does not inflate the ratio.
        assert_eq!(
            reason_for("alias.txt"),
            Some(UnparsedReason::UnknownLanguage)
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_directory_that_cannot_be_read_moves_the_ratio() {
        // The error class this test catches: an unreadable directory was skipped
        // with `continue` while the comment beside it claimed the opposite. Every
        // source file under it reached no list and no counter, the ratio stayed
        // at zero, and the coverage gate passed on a tree nobody had read.
        use std::os::unix::fs::PermissionsExt;

        let tree = TempTree::new("unreadable");
        tree.write("open/app.py", b"pass\n");
        tree.write("closed/secret.py", b"pass\n");
        let closed = tree.path().join("closed");
        fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).unwrap();

        let readable_anyway = fs::read_dir(&closed).is_ok();
        let found = discover(tree.path(), &DiscoveryOptions::default());
        // Restore before asserting, so a failure does not leave a directory the
        // cleanup cannot remove.
        fs::set_permissions(&closed, fs::Permissions::from_mode(0o755)).unwrap();

        if readable_anyway {
            // Running as a user that ignores the permission bits, so there is no
            // walk error to observe. Saying so is better than asserting nothing.
            assert!(found
                .files
                .iter()
                .any(|f| f.path == Path::new("open/app.py")));
            return;
        }

        assert!(
            found
                .skipped
                .iter()
                .any(|s| s.reason == UnparsedReason::IoError),
            "the unreadable directory left no trace: {found:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_path_that_is_not_utf8_is_declared_rather_than_converted() {
        // Lossy conversion maps different byte sequences onto one string, and
        // that string feeds an egress point identity, so two files could collapse
        // into one finding.
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let tree = TempTree::new("nonutf8");
        tree.write("fine.py", b"pass\n");
        let bad = tree.path().join(OsStr::from_bytes(b"br\xffoken.py"));
        let created = fs::write(&bad, b"pass\n").is_ok();

        let found = discover(tree.path(), &DiscoveryOptions::default());
        assert!(found.files.iter().any(|f| f.path == Path::new("fine.py")));

        if !created {
            // Some filesystems, APFS among them, reject a name that is not valid
            // UTF-8 outright. There is nothing to observe here on those, and
            // saying so beats asserting something that would always hold.
            return;
        }
        assert_eq!(found.files.len(), 1, "{:?}", found.files);
        assert!(
            found
                .diagnostics
                .iter()
                .any(|d| d.contains("not valid UTF-8")),
            "{:?}",
            found.diagnostics
        );
    }

    #[test]
    fn invalid_utf8_is_reported_rather_than_parsed() {
        let tree = TempTree::new("utf8");
        // No NUL byte, so the binary sniff lets it through; the decode is what fails.
        tree.write("bad.py", &[0xff, 0xfe, b'x']);
        let err = read_source(tree.path(), Path::new("bad.py")).unwrap_err();
        assert_eq!(err, UnparsedReason::IoError);
    }
}
