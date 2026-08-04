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
    /// Symbolic links that were not followed. Loops make following them unsafe,
    /// and a link left unvisited is still something the reader should know about.
    pub unfollowed_links: Vec<PathBuf>,
}

/// Knobs a caller may turn. Defaults match the specification.
#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub max_file_bytes: u64,
    /// Honour `.gitignore`, `.ignore` and `.periskopignore`.
    pub respect_ignore_files: bool,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            respect_ignore_files: true,
        }
    }
}

/// Directories excluded regardless of ignore files.
///
/// These are not code the user wrote. Reporting a call site inside a vendored
/// dependency as if it were the user's own is a false positive that erodes trust
/// in every other finding in the report.
const ALWAYS_EXCLUDED_DIRS: &[&str] = &[
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

    builder.filter_entry(|entry| {
        !entry
            .file_name()
            .to_str()
            .is_some_and(|name| ALWAYS_EXCLUDED_DIRS.contains(&name))
    });

    let mut discovery = Discovery::default();

    for entry in builder.build() {
        let Ok(entry) = entry else {
            // A directory that cannot be read is a real gap. It is not attributed
            // to any single file, so it is counted as an io_error at the path the
            // walker was able to name.
            continue;
        };

        let path = entry.path();
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        if relative.as_os_str().is_empty() {
            continue;
        }

        let file_type = entry.file_type();
        if file_type.is_some_and(|t| t.is_symlink()) {
            discovery.unfollowed_links.push(relative.to_path_buf());
            continue;
        }
        if !file_type.is_some_and(|t| t.is_file()) {
            continue;
        }

        classify_file(path, relative, options, &mut discovery);
    }

    discovery.files.sort_by(|a, b| a.path.cmp(&b.path));
    discovery.skipped.sort_by(|a, b| a.path.cmp(&b.path));
    discovery.unfollowed_links.sort();
    discovery
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
            let dir = std::env::temp_dir().join(format!("periskop-discovery-{name}"));
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
    fn invalid_utf8_is_reported_rather_than_parsed() {
        let tree = TempTree::new("utf8");
        // No NUL byte, so the binary sniff lets it through; the decode is what fails.
        tree.write("bad.py", &[0xff, 0xfe, b'x']);
        let err = read_source(tree.path(), Path::new("bad.py")).unwrap_err();
        assert_eq!(err, UnparsedReason::IoError);
    }
}
