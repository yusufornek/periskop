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

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

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
            Self::Io { path, error } => write!(f, "{}: {error}", path.display()),
        }
    }
}

impl std::error::Error for HookError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { error, .. } => Some(error),
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
        .filter(|to| to.exists())
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
        if to.exists() {
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
            let require = format!("--require {}", root.join("preload.js").display());
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
        let Some(name) = child.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if is_development_residue(name) {
            continue;
        }
        copy_entry(&child, &to.join(name))?;
    }
    Ok(())
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

fn copy_file(from: &Path, to: &Path) -> Result<(), HookError> {
    if let Some(parent) = to.parent() {
        create_dir_all(parent)?;
    }
    std::fs::copy(from, to)
        .map(drop)
        .map_err(|error| HookError::Io {
            path: to.to_path_buf(),
            error,
        })
}

fn create_dir_all(path: &Path) -> Result<(), HookError> {
    std::fs::create_dir_all(path).map_err(|error| HookError::Io {
        path: path.to_path_buf(),
        error,
    })
}

fn remove(path: &Path) -> Result<(), HookError> {
    let metadata = std::fs::metadata(path).map_err(|error| HookError::Io {
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
