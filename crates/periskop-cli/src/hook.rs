//! Putting the runtime hooks where an interpreter will find them.
//!
//! The hooks are a convenience, never a prerequisite. `periskop scan` reads code
//! and produces the same report whether or not a hook was ever installed, and
//! nothing on that path reaches this module. What a hook adds is the second
//! source reconciliation compares the first against; a project that never runs
//! one gets a report that says so in its coverage block rather than a report that
//! fails.
//!
//! Two properties shape everything below.
//!
//! An installation is never silently replaced. Both hooks land in directories
//! that belong to somebody else: a python `site-packages` holds every library the
//! interpreter has, and overwriting an entry there can break a tool that has
//! nothing to do with this one. So every destination is checked before the first
//! byte is written, and a collision stops the command with the list of what is in
//! the way instead of taking that decision for the operator.
//!
//! An environment variable is appended to, never assigned over. `NODE_OPTIONS`
//! and `PYTHONPATH` routinely already carry a debugger, a coverage tool or a
//! vendor agent. Printing a bare assignment would read as correct and quietly
//! drop whatever was there, which is the same class of damage as overwriting a
//! file.
//!
//! Every byte this module puts on disk goes through [`crate::write_target`],
//! and that is a security property rather than a style choice. `--target` names
//! a directory that belongs to an interpreter, which on a shared machine means
//! a directory this command may be run against with more authority than the
//! person who arranged its contents holds. `std::fs::copy` follows a symbolic
//! link at the destination and writes through it, so a link planted at a
//! payload path turns an installation into a write to a file nobody named. The
//! collision check below sees such a link and refuses, but a check and a copy
//! are two steps and the path can be swapped between them; the write target
//! module closes that window by creating the file exclusively.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::write_target::{self, Existing};

/// Which runtime the hook is being installed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Python,
    Node,
}

/// The languages this build has a hook for, in the order the error lists them.
const SUPPORTED: [(&str, Language); 2] = [("python", Language::Python), ("node", Language::Node)];

impl Language {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Node => "node",
        }
    }

    /// What gets copied, as `(name under the source directory, name at the
    /// destination)`.
    ///
    /// Written out per language rather than "copy the directory", because for
    /// python the difference matters: `hooks/python` also contains
    /// `sitecustomize.py`, which is the fallback mechanism and the one file that
    /// must never be dropped into `site-packages`. Only one `sitecustomize` can
    /// win an import, and the loser is a debugger or coverage tool that stops
    /// working with nothing to say why. This list is the allow list that keeps it
    /// out.
    fn payload(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Python => &[
                ("periskop_hook", "periskop_hook"),
                ("periskop-hook.pth", "periskop-hook.pth"),
            ],
            // The build output, renamed on the way in so the destination says
            // whose it is. A directory called `dist` next to an application's
            // own files would not.
            Self::Node => &[("dist", "periskop-hook")],
        }
    }

    /// The directory an application has to be pointed at, inside a checkout.
    fn root_in_source(self, source: &Path) -> PathBuf {
        match self {
            // The import path is the directory holding the package, not the
            // package itself.
            Self::Python => source.to_path_buf(),
            Self::Node => source.join("dist"),
        }
    }

    /// The same directory, once the payload has been copied to a destination.
    fn root_in_target(self, target: &Path) -> PathBuf {
        match self {
            Self::Python => target.to_path_buf(),
            Self::Node => target.join("periskop-hook"),
        }
    }

    /// The file whose absence means the hook is not really there.
    ///
    /// The node hook is TypeScript and ships compiled, so a checkout that has
    /// not been built has an empty or absent `dist`. Copying it anyway would
    /// produce an installation that looks complete and instruments nothing.
    fn probe(self, root: &Path) -> PathBuf {
        match self {
            Self::Python => root.join("periskop_hook").join("__init__.py"),
            Self::Node => root.join("preload.js"),
        }
    }

    fn build_hint(self) -> &'static str {
        match self {
            Self::Python => {
                "the python hook needs no build step; check that --source names the hooks directory"
            }
            Self::Node => "build it first: cd hooks/node && npm install && npm run build",
        }
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Language {
    type Err = HookError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        SUPPORTED
            .iter()
            .find(|(name, _)| *name == value)
            .map(|(_, language)| *language)
            .ok_or_else(|| HookError::UnknownLanguage {
                given: value.to_owned(),
            })
    }
}

/// Why the command stopped.
///
/// Each variant carries what the operator needs in order to act, because the
/// alternative is a message that names a failure without naming a next step.
#[derive(Debug)]
pub enum HookError {
    /// `--language` named something this build has no hook for.
    UnknownLanguage { given: String },
    /// The hook is missing from where it was expected, or was never built.
    NotBuilt { language: Language, probe: PathBuf },
    /// An installation was asked for without saying where.
    TargetRequired { language: Language },
    /// Something is already at the destination.
    AlreadyInstalled { occupied: Vec<PathBuf> },
    /// A payload entry whose name this build cannot reproduce at the
    /// destination.
    ///
    /// Skipping it is what this variant exists to prevent. A hook missing one
    /// module still installs, still loads its `.pth`, and then fails its import
    /// inside somebody else's interpreter, where the failure is swallowed by the
    /// hook's own fail-open guard. The operator is told the installation
    /// succeeded and the application runs with no instrumentation at all.
    UnreadableName { path: PathBuf },
    /// A path `NODE_OPTIONS` cannot carry.
    ///
    /// The variable is split on whitespace and understands quoting, but it has
    /// no escape for a quote character inside a quoted argument. A path
    /// containing one cannot be written down correctly, and writing it down
    /// incorrectly produces a variable that looks right and loads nothing.
    UnquotablePath { path: PathBuf },
    /// A payload file could not be written where it was meant to go.
    ///
    /// Separate from [`Self::Io`] because it is the refusal that protects
    /// somebody else's file: the destination was a link, a directory, or a path
    /// something else claimed between the collision check and the write. The
    /// inner error names the path and what was in the way.
    NotWritten { error: write_target::WriteError },
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
}

impl HookError {
    /// The line printed after the arrow, per the error format in `cli/spec.md`
    /// section 6.
    pub fn suggestion(&self) -> String {
        match self {
            Self::UnknownLanguage { .. } => format!(
                "supported languages: {}",
                SUPPORTED
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::NotBuilt { language, .. } => language.build_hint().to_owned(),
            Self::TargetRequired { language } => match language {
                Language::Python => concat!(
                    "name the interpreter's package directory: --target \"$(python3 -c ",
                    "'import sysconfig; print(sysconfig.get_paths()[\"purelib\"])')\", ",
                    "or use --print-env and install it yourself",
                )
                .to_owned(),
                Language::Node => concat!(
                    "name a directory to hold the hook with --target, or use --print-env ",
                    "to point an application at the build tree instead",
                )
                .to_owned(),
            },
            Self::AlreadyInstalled { .. } => "remove it, or pass --force to replace it".to_owned(),
            Self::UnreadableName { .. } => {
                "rename it to valid UTF-8 in the hook source tree, then install again".to_owned()
            }
            Self::UnquotablePath { .. } => {
                "install the hook under a path without a quote character, or pass --target"
                    .to_owned()
            }
            Self::NotWritten { .. } => {
                "look at what is at that path before removing it: a hook is never written through \
                 a link, so whatever is there belongs to something else"
                    .to_owned()
            }
            Self::Io { .. } => "check that the path exists and is writable".to_owned(),
        }
    }
}

impl fmt::Display for HookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownLanguage { given } => write!(f, "no runtime hook for language {given:?}"),
            Self::NotBuilt { language, probe } => write!(
                f,
                "the {language} hook is not present at {}",
                probe.display()
            ),
            Self::TargetRequired { language } => {
                write!(f, "installing the {language} hook needs a destination")
            }
            Self::AlreadyInstalled { occupied } => write!(
                f,
                "a hook is already installed: {}",
                occupied
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::UnreadableName { path } => write!(
                f,
                "a hook file has a name that is not valid UTF-8: {}",
                path.display()
            ),
            Self::UnquotablePath { path } => write!(
                f,
                "NODE_OPTIONS cannot carry a path containing a quote character: {}",
                path.display()
            ),
            Self::NotWritten { error } => write!(f, "a hook file was not written: {error}"),
            Self::Io { path, error } => write!(f, "{}: {error}", path.display()),
        }
    }
}

impl std::error::Error for HookError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { error, .. } => Some(error),
            Self::NotWritten { error } => Some(error),
            _ => None,
        }
    }
}

/// Environment the printed variables have to coexist with.
///
/// Taken as an argument rather than read inside the formatter, so that the output
/// is a function of its inputs and a test does not have to mutate the process
/// wide environment to cover the case that matters.
#[derive(Debug, Default)]
pub struct Ambient {
    pub node_options: Option<String>,
    pub python_path: Option<String>,
}

impl Ambient {
    pub fn from_env() -> Self {
        Self {
            node_options: std::env::var("NODE_OPTIONS").ok(),
            python_path: std::env::var("PYTHONPATH").ok(),
        }
    }
}

/// One `NAME=value` line.
#[derive(Debug, PartialEq, Eq)]
pub struct EnvVar {
    pub name: &'static str,
    pub value: String,
}

impl fmt::Display for EnvVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.value)
    }
}

/// What the caller asked for.
#[derive(Debug)]
pub struct HookRequest<'a> {
    pub language: Language,
    /// Directory holding the hook sources, normally the repository's `hooks/`.
    pub source_root: &'a Path,
    /// Where the payload goes. `None` means nothing is installed and the
    /// variables point at the source tree instead.
    pub target: Option<&'a Path>,
    /// Directory the hook writes its event stream into.
    pub event_dir: &'a Path,
    /// Replace an existing installation instead of stopping.
    pub force: bool,
}

/// What an installation did.
#[derive(Debug)]
pub struct Installed {
    pub written: Vec<PathBuf>,
    /// True when something was already there and `--force` replaced it.
    pub replaced: bool,
}

/// The directory hook sources are read from when the caller does not say.
///
/// Beside the executable first, which is how an installed build finds the hooks
/// shipped with it, then the repository layout so a development checkout needs no
/// extra flag. The same two step lookup the rules use, for the same reason.
pub fn default_source_root() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let beside = dir.join("hooks");
            if beside.is_dir() {
                return beside;
            }
        }
    }
    PathBuf::from("hooks")
}

/// Where the hook writes its event stream when the caller does not say.
///
/// Under the project rather than a system temporary directory. An event stream
/// somewhere the operator did not choose is a side effect an observation tool
/// should not have, and a path they can see is a path they can delete.
pub fn default_event_dir() -> PathBuf {
    PathBuf::from(".periskop/events")
}

/// Copies the hook payload to the destination.
///
/// Every destination is checked before anything is written, so a collision on the
/// second entry cannot leave the first one installed.
pub fn install(request: &HookRequest<'_>) -> Result<Installed, HookError> {
    let source = source_dir(request.language, request.source_root);
    require_present(request.language, &request.language.root_in_source(&source))?;

    let Some(target) = request.target else {
        return Err(HookError::TargetRequired {
            language: request.language,
        });
    };

    let entries: Vec<(PathBuf, PathBuf)> = request
        .language
        .payload()
        .iter()
        .map(|(from, to)| (source.join(from), target.join(to)))
        .collect();

    let occupied: Vec<PathBuf> = entries
        .iter()
        .map(|(_, to)| to.clone())
        .filter(|to| occupies(to))
        .collect();
    if !occupied.is_empty() && !request.force {
        return Err(HookError::AlreadyInstalled { occupied });
    }
    let replaced = !occupied.is_empty();

    create_dir_all(target)?;
    for (from, to) in &entries {
        // Removed rather than merged into. A file the previous version shipped
        // and this one does not would otherwise survive the upgrade and be
        // imported alongside the new package.
        if occupies(to) {
            remove(to)?;
        }
        copy_entry(from, to)?;
    }

    Ok(Installed {
        written: entries.into_iter().map(|(_, to)| to).collect(),
        replaced,
    })
}

/// The variables an application needs so that the hook loads and records.
///
/// Absolute paths on purpose. These values are read by a process started from a
/// working directory this command cannot know, and a relative path would resolve
/// somewhere else there. The determinism rule that forbids absolute paths governs
/// reports, which have to be comparable between machines; this output is a local
/// instruction and has to work.
pub fn env_vars(request: &HookRequest<'_>, ambient: &Ambient) -> Result<Vec<EnvVar>, HookError> {
    // After an install the variables point at the copy, not at the tree it came
    // from. Naming the source would produce an environment that works until the
    // checkout moves, and then fails silently, because a hook that cannot be
    // loaded takes the process no further than it would have gone anyway.
    let root = match request.target {
        Some(target) => request.language.root_in_target(target),
        None => request
            .language
            .root_in_source(&source_dir(request.language, request.source_root)),
    };
    require_present(request.language, &root)?;
    let root = absolute(&root);

    let mut vars = Vec::new();
    match request.language {
        Language::Python => {
            // Needed only for the fallback installation: a payload dropped into
            // site-packages is already importable through its .pth file. It is
            // printed either way rather than inferred from the shape of the
            // destination, and the note on stderr says which case is which.
            vars.push(EnvVar {
                name: "PYTHONPATH",
                value: join_after(ambient.python_path.as_deref(), &root.display().to_string()),
            });
        }
        Language::Node => {
            let preload = root.join("preload.js");
            let require = format!("--require {}", quote_for_node_options(&preload)?);
            vars.push(EnvVar {
                name: "NODE_OPTIONS",
                value: append_argument(ambient.node_options.as_deref(), &require),
            });
        }
    }

    // Without this the python hook stays off entirely and the node hook writes
    // into a temporary directory the operator never named. Printing it is what
    // makes the difference between those two defaults stop mattering.
    vars.push(EnvVar {
        name: "PERISKOP_EVENT_DIR",
        value: absolute(request.event_dir).display().to_string(),
    });
    Ok(vars)
}

/// Guidance that goes with the variables, for stderr.
///
/// Kept off stdout so stdout stays a list of assignments a script can read, per
/// the stdout contract in `cli/spec.md` section 3.
pub fn env_notes(language: Language) -> &'static str {
    match language {
        Language::Python => concat!(
            "PYTHONPATH is only needed for the fallback installation. A payload copied into\n",
            "site-packages is imported through its .pth file and needs PERISKOP_EVENT_DIR alone.\n",
            "Any existing value is kept in front rather than replaced.",
        ),
        Language::Node => concat!(
            "NODE_OPTIONS is inherited by every child process. The hook expects that and\n",
            "leaves package managers and build tools alone by itself.\n",
            "Any existing value is kept in front rather than replaced.",
        ),
    }
}

fn source_dir(language: Language, source_root: &Path) -> PathBuf {
    source_root.join(language.as_str())
}

/// Whether anything at all sits at this path, including a link to nothing.
///
/// `Path::exists` follows symbolic links and answers `false` for one whose
/// target is gone, which is the wrong answer to both questions this module asks.
/// A broken link belonging to another tool passed the collision check, `--force`
/// was never demanded, and the copy that followed wrote *through* the link to
/// whatever path it named: a destination the operator never saw and this command
/// never reported. The header of this module promises an installation is never
/// silently replaced, and that promise was kept by a call that cannot see links.
fn occupies(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

fn require_present(language: Language, root: &Path) -> Result<(), HookError> {
    let probe = language.probe(root);
    if probe.exists() {
        Ok(())
    } else {
        Err(HookError::NotBuilt { language, probe })
    }
}

/// Puts a directory at the end of a path list, keeping what was there.
fn join_after(existing: Option<&str>, value: &str) -> String {
    match non_empty(existing) {
        Some(existing) => format!("{existing}{}{value}", path_separator()),
        None => value.to_owned(),
    }
}

/// A path written so that `NODE_OPTIONS` reads it as one argument.
///
/// The variable is split on whitespace before anything else looks at it, so an
/// unquoted `/Users/ali/My Project/.../preload.js` arrives at node as
/// `--require /Users/ali/My` followed by two stray arguments. Node then either
/// refuses to start or starts without the hook, and the command that printed the
/// line said it had succeeded. Paths with spaces in them are ordinary on macOS
/// and Windows, so this is the common case rather than the exotic one.
///
/// Quoted unconditionally rather than only when a space is present: a value
/// whose shape changes with its contents is one a script can get right for the
/// paths it was tested on and wrong for the next one.
///
/// A quote character inside the path has no representation here, because the
/// variable offers no escape inside a quoted argument. That is an error rather
/// than a best effort, since best effort means printing a line that looks
/// correct and loads nothing.
fn quote_for_node_options(path: &Path) -> Result<String, HookError> {
    let rendered = path.display().to_string();
    if rendered.contains('"') {
        return Err(HookError::UnquotablePath {
            path: path.to_path_buf(),
        });
    }
    Ok(format!("\"{rendered}\""))
}

/// Puts an argument at the end of a command line, keeping what was there.
fn append_argument(existing: Option<&str>, value: &str) -> String {
    match non_empty(existing) {
        Some(existing) => format!("{existing} {value}"),
        None => value.to_owned(),
    }
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn path_separator() -> char {
    if cfg!(windows) {
        ';'
    } else {
        ':'
    }
}

/// Resolves a relative path against the working directory.
fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(path),
        // A process whose working directory cannot be read has no better answer
        // available than the path it supplied, and printing that is more useful
        // than printing nothing.
        Err(_) => path.to_path_buf(),
    }
}

/// Copies one file or one directory tree.
fn copy_entry(from: &Path, to: &Path) -> Result<(), HookError> {
    let metadata = std::fs::metadata(from).map_err(|error| HookError::Io {
        path: from.to_path_buf(),
        error,
    })?;
    if metadata.is_dir() {
        copy_tree(from, to)
    } else {
        copy_file(from, to)
    }
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), HookError> {
    create_dir_all(to)?;

    // Read fully and sorted, so two installations of the same source write the
    // same tree in the same order and a failure part way through lands in the
    // same place twice.
    let mut children: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(from).map_err(|error| HookError::Io {
        path: from.to_path_buf(),
        error,
    })? {
        let entry = entry.map_err(|error| HookError::Io {
            path: from.to_path_buf(),
            error,
        })?;
        children.push(entry.path());
    }
    children.sort();

    for child in children {
        let name = entry_name(&child)?.to_owned();
        if is_development_residue(&name) {
            continue;
        }
        copy_entry(&child, &to.join(name))?;
    }
    Ok(())
}

/// The name a payload entry will be written under.
///
/// A name this build cannot read is a name it cannot reproduce, and the entry is
/// refused rather than passed over. Skipping it produced an installation
/// reported as complete with a module missing from it; the import error that
/// followed happened inside the application's own interpreter, where the hook's
/// fail-open guard swallowed it by design. Refusing here is the last place the
/// operator can still be told.
///
/// Its own function so the decision can be pinned without a filesystem that can
/// hold such a name: APFS and NTFS both reject one outright, so a test that
/// created the file would only ever run on Linux.
fn entry_name(child: &Path) -> Result<&str, HookError> {
    child
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| HookError::UnreadableName {
            path: child.to_path_buf(),
        })
}

/// Files that belong to the hook's own development rather than to a deployment.
///
/// A compiled cache is tied to one interpreter version and a test file exercises
/// the hook rather than running alongside it. Neither is harmful to copy, but
/// both land in somebody else's library directory, and the smaller that footprint
/// is the easier the installation is to recognise and to remove.
fn is_development_residue(name: &str) -> bool {
    name == "__pycache__" || name.contains(".test.")
}

/// Puts one payload file at its destination, and never through a link.
///
/// Read and written rather than `std::fs::copy`d. The copy call follows a
/// symbolic link at the destination, so with `periskop-hook.pth` linked at an
/// operator's key file a privileged install overwrote that file with the hook's
/// contents while reporting a successful installation. `Existing::Refuse` is
/// what the destination is opened with: `install` has already refused or
/// removed whatever was at the path, so anything there by now appeared in the
/// window between that check and this call, and a file appearing in that window
/// is the attack this is guarding against rather than a state to write over.
///
/// The file mode is not carried across from the source. Both payloads are
/// modules an interpreter imports, so nothing depends on an execute bit, and
/// the alternative is a second write of somebody else's permissions.
fn copy_file(from: &Path, to: &Path) -> Result<(), HookError> {
    if let Some(parent) = to.parent() {
        create_dir_all(parent)?;
    }
    let contents = std::fs::read(from).map_err(|error| HookError::Io {
        path: from.to_path_buf(),
        error,
    })?;
    write_target::write_public(to, &contents, Existing::Refuse)
        .map_err(|error| HookError::NotWritten { error })
}

fn create_dir_all(path: &Path) -> Result<(), HookError> {
    std::fs::create_dir_all(path).map_err(|error| HookError::Io {
        path: path.to_path_buf(),
        error,
    })
}

/// Takes one entry away, link included.
///
/// `symlink_metadata` for the same reason the collision check uses it, and for
/// one more: a link pointing at a directory reports itself as a directory to
/// `metadata`, and removing it as one would delete the contents of a directory
/// this command was never pointed at. Seen as a link it is removed as the single
/// entry it is.
fn remove(path: &Path) -> Result<(), HookError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| HookError::Io {
        path: path.to_path_buf(),
        error,
    })?;
    let removed = if metadata.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    removed.map_err(|error| HookError::Io {
        path: path.to_path_buf(),
        error,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A throwaway tree, built by hand.
    ///
    /// The same shape the integration suite uses, repeated here rather than
    /// shared because these three cases are about how this module reads the
    /// filesystem, and a unit test that lives beside the code it pins is the one
    /// a reader finds from the code.
    struct TempTree {
        root: PathBuf,
    }

    impl TempTree {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("periskop-hook-unit-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn write(&self, relative: &str, contents: &str) -> PathBuf {
            let path = self.root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, contents).unwrap();
            path
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.root.join(relative)
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn node_source(tree: &TempTree) -> PathBuf {
        tree.write("hooks/node/dist/preload.js", "// preload\n");
        tree.path("hooks")
    }

    #[test]
    fn a_node_require_path_survives_a_space_in_it() {
        // The bug: the argument was printed unquoted. NODE_OPTIONS is split on
        // whitespace, so a target under `My Project` produced
        // `--require /Users/ali/My`, node loaded nothing, and the command
        // reported success. Paths with spaces are ordinary on macOS.
        let tree = TempTree::new("spaces");
        let source = node_source(&tree);
        let target = tree.path("My Project/node_modules");
        std::fs::create_dir_all(target.join("periskop-hook")).unwrap();
        std::fs::write(target.join("periskop-hook/preload.js"), "// preload\n").unwrap();

        let request = HookRequest {
            language: Language::Node,
            source_root: &source,
            target: Some(&target),
            event_dir: Path::new(".periskop/events"),
            force: false,
        };
        let vars = env_vars(&request, &Ambient::default()).unwrap();
        let node_options = vars
            .iter()
            .find(|v| v.name == "NODE_OPTIONS")
            .expect("NODE_OPTIONS is printed for node");

        assert!(
            node_options.value.contains("--require \""),
            "{}",
            node_options.value
        );
        assert!(
            node_options.value.trim_end().ends_with("preload.js\""),
            "{}",
            node_options.value
        );
        // Split the way node splits the variable: on whitespace, but not inside
        // a quoted run. Unquoted, this produced three arguments and the second
        // was a path ending at the space.
        let pieces = split_node_options(&node_options.value);
        assert_eq!(pieces.len(), 2, "{pieces:?}");
        assert_eq!(pieces[0], "--require");
        assert!(Path::new(&pieces[1]).is_file(), "{pieces:?}");
    }

    /// Whitespace separated arguments, with double quotes grouping.
    ///
    /// The half of node's own parser this output has to survive. Written out
    /// because asserting on the string alone would pass for a value that no
    /// parser reads the way this test intends.
    fn split_node_options(value: &str) -> Vec<String> {
        let mut pieces = Vec::new();
        let mut current = String::new();
        let mut quoted = false;
        let mut started = false;
        for c in value.chars() {
            match c {
                '"' => {
                    quoted = !quoted;
                    started = true;
                }
                c if c.is_whitespace() && !quoted => {
                    if started {
                        pieces.push(std::mem::take(&mut current));
                        started = false;
                    }
                }
                c => {
                    current.push(c);
                    started = true;
                }
            }
        }
        if started {
            pieces.push(current);
        }
        pieces
    }

    #[test]
    fn a_path_node_options_cannot_carry_is_refused_rather_than_mangled() {
        // No escape exists inside a quoted NODE_OPTIONS argument, so this path
        // has no correct spelling. Printing an incorrect one would look right.
        let quoted = Path::new("/tmp/we\"ird/preload.js");
        let error = quote_for_node_options(quoted).unwrap_err();
        assert!(matches!(error, HookError::UnquotablePath { .. }), "{error}");
    }

    #[test]
    #[cfg(unix)]
    fn a_payload_name_that_is_not_utf8_stops_the_install() {
        // The bug: `let Some(name) = ... else { continue; }`. Skipping produced
        // an installation reported as complete with a module missing from it,
        // and the import error that followed was swallowed by the hook's own
        // fail-open guard inside the application's interpreter.
        //
        // Pinned on the decision rather than on a file: APFS refuses to create
        // a name like this at all, so a filesystem test would only run on Linux
        // and would report as passing everywhere else.
        use std::os::unix::ffi::OsStrExt;

        let invalid = PathBuf::from(std::ffi::OsStr::from_bytes(
            b"/tmp/periskop_hook/writer\xff.py",
        ));
        let error = entry_name(&invalid).unwrap_err();
        assert!(
            matches!(error, HookError::UnreadableName { .. }),
            "silently skipped instead: {error}"
        );

        // The ordinary case still resolves, so the guard is not simply refusing
        // everything.
        assert_eq!(
            entry_name(Path::new("/tmp/periskop_hook/writer.py")).unwrap(),
            "writer.py"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_broken_symlink_at_the_destination_is_a_collision() {
        // `Path::exists` follows links and answers false for a broken one, so
        // the collision check passed, --force was never demanded, and the copy
        // wrote through the link to a path the operator never saw. The link here
        // belongs to another tool, which is the case the module header is about.
        let tree = TempTree::new("brokenlink");
        tree.write("hooks/python/periskop_hook/__init__.py", "# package\n");
        tree.write("hooks/python/periskop-hook.pth", "import periskop_hook\n");
        let target = tree.path("site-packages");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(
            tree.path("gone/elsewhere.pth"),
            target.join("periskop-hook.pth"),
        )
        .unwrap();

        let source = tree.path("hooks");
        let request = HookRequest {
            language: Language::Python,
            source_root: &source,
            target: Some(&target),
            event_dir: Path::new(".periskop/events"),
            force: false,
        };
        let error = install(&request).unwrap_err();
        assert!(
            matches!(error, HookError::AlreadyInstalled { .. }),
            "wrote through a link instead: {error}"
        );

        // With --force the link itself is removed, not followed: nothing appears
        // at the path it pointed at.
        let forced = HookRequest {
            force: true,
            ..request
        };
        install(&forced).unwrap();
        assert!(!tree.path("gone/elsewhere.pth").exists());
        assert!(std::fs::symlink_metadata(target.join("periskop-hook.pth"))
            .unwrap()
            .is_file());
    }

    #[test]
    #[cfg(unix)]
    fn a_payload_file_is_never_written_through_a_link_at_its_destination() {
        // CL-SEC2, at the write itself. The collision check above is one guard
        // and it is not the last one: it looks, and then the copy writes, and a
        // path can change between the two. On a machine where the target
        // directory is writable by somebody other than the operator, a link
        // planted in that window used to be followed by `std::fs::copy`, which
        // overwrote the file it pointed at. `hook install --target` is run
        // against interpreter directories and can run privileged, so the file
        // it overwrites is chosen by whoever planted the link.
        //
        // The link here is real and is at the destination when the write
        // happens, which is exactly the state the window produces.
        let tree = TempTree::new("copy-through-link");
        let source = tree.write("hooks/python/periskop-hook.pth", "import periskop_hook\n");
        let victim = tree.write("keys/id_ed25519", "PRIVATE KEY\n");
        let destination = tree.path("site-packages/periskop-hook.pth");
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&victim, &destination).unwrap();

        let error = copy_file(&source, &destination).unwrap_err();
        assert!(
            matches!(error, HookError::NotWritten { .. }),
            "wrote through the link instead: {error}"
        );
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "PRIVATE KEY\n",
            "the linked file was written through"
        );
        assert!(std::fs::symlink_metadata(&destination)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn a_payload_file_still_arrives_where_nothing_is_in_the_way() {
        // The refusal must not have cost the ordinary case: the guard is worth
        // nothing if the installation it protects no longer happens.
        let tree = TempTree::new("copy-plain");
        let source = tree.write("hooks/python/periskop-hook.pth", "import periskop_hook\n");
        let destination = tree.path("site-packages/periskop-hook.pth");

        copy_file(&source, &destination).unwrap();
        assert_eq!(
            std::fs::read_to_string(&destination).unwrap(),
            "import periskop_hook\n"
        );
    }
}
