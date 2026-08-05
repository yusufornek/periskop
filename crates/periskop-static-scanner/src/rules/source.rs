//! Where one run's detector rules come from.
//!
//! Two sources and no third. The set compiled into this binary is the default,
//! and a directory the caller names replaces it. Nothing is discovered
//! implicitly: looking for a `rules` directory beside the executable and then in
//! the working directory is how a scan used to pick up whichever rule tree
//! happened to be underfoot, and how the same command produced different
//! detections from two different directories.

use std::fmt;
use std::path::Path;

use periskop_core::coverage::RuleSetSource;

use crate::rules::embedded::load_embedded;
use crate::rules::loader::{load_directory, RuleLoadError};
use crate::rules::model::RuleFile;

/// The rule set a scan was asked to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSource<'a> {
    /// The set compiled in at build time, byte for byte the repository's tree.
    Embedded,
    /// A directory the caller named, which wins over the embedded set so that an
    /// operator can run detectors they wrote themselves.
    Directory(&'a Path),
}

impl RuleSource<'_> {
    /// Reads the rule set, whichever source it is.
    pub fn load(self) -> (Vec<RuleFile>, Vec<RuleLoadError>) {
        match self {
            Self::Embedded => load_embedded(),
            Self::Directory(dir) => load_directory(dir),
        }
    }
}

/// The same fact as the report states it, with the path dropped.
///
/// Two spellings for one thing on purpose. [`fmt::Display`] below names the
/// directory because it is written to stderr, where an operator needs to see
/// which tree they pointed at. The report gets the source and nothing else: an
/// absolute path differs between machines, so putting one in the body would mean
/// two runs over the same tree no longer produce the same bytes. Same rule that
/// keeps paths out of `finding_id`.
impl From<RuleSource<'_>> for RuleSetSource {
    fn from(source: RuleSource<'_>) -> Self {
        match source {
            RuleSource::Embedded => Self::Embedded,
            RuleSource::Directory(_) => Self::Directory,
        }
    }
}

/// How a run announces which detectors decided it.
///
/// A reader who is told a tree is clean has to be able to ask "clean according to
/// what", and the answer is not the same in a checkout with a modified rule
/// directory as it is for a downloaded binary.
impl fmt::Display for RuleSource<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Embedded => write!(f, "built into this binary"),
            Self::Directory(dir) => write!(f, "read from {}", dir.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_named_directory_wins_over_the_embedded_set() {
        // The rule the operator depends on: their own detectors run, and the
        // shipped ones do not quietly run beside them.
        let (rules, errors) = RuleSource::Directory(Path::new("no-such-rule-directory")).load();
        assert!(
            rules.is_empty(),
            "the embedded set answered for a directory"
        );
        assert_eq!(errors.len(), 1, "{errors:?}");
    }

    #[test]
    fn the_report_learns_the_source_and_not_the_path() {
        // The report field is what an auditor reads six months later, and it has
        // to say which detectors decided the run without carrying a path that
        // would differ on the next machine.
        assert_eq!(
            RuleSetSource::from(RuleSource::Embedded),
            RuleSetSource::Embedded
        );
        assert_eq!(
            RuleSetSource::from(RuleSource::Directory(Path::new("/opt/rules"))),
            RuleSetSource::Directory
        );
        assert_eq!(
            RuleSetSource::from(RuleSource::Directory(Path::new("/somewhere/else"))),
            RuleSetSource::from(RuleSource::Directory(Path::new("/opt/rules"))),
            "the directory itself reached the report"
        );
    }

    #[test]
    fn each_source_says_what_it_is() {
        assert_eq!(RuleSource::Embedded.to_string(), "built into this binary");
        assert_eq!(
            RuleSource::Directory(Path::new("/opt/rules")).to_string(),
            "read from /opt/rules"
        );
    }
}
