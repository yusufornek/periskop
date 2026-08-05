//! The rule set compiled into this binary.
//!
//! `build.rs` turns the repository's `rules/` tree into the table below, so a
//! downloaded executable carries its detectors with it. Before this existed the
//! binary looked for a `rules` directory beside itself and then in the working
//! directory, and found neither when it was run from anywhere else: the scan
//! stopped with `no rule directory at rules` and the product's own README told
//! people to run `periskop scan path/to/project` from wherever they were.
//!
//! The embedded set is the default, never an override. A directory named with
//! `--rules` wins, because an operator writing their own detectors has to be able
//! to run them.

use std::path::Path;

use crate::rules::loader::{parse_rule, RuleLoadError, FOREIGN_RULE_DIRECTORIES};
use crate::rules::model::RuleFile;

/// One rule file, exactly as it sat on disk when this binary was built.
///
/// The text is kept rather than the parsed rule so that the copy inside the
/// binary can be compared against the tree byte for byte. A parsed rule would
/// compare equal after a whitespace edit or a dropped comment, and this type
/// exists to make that kind of drift impossible to miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddedRuleFile {
    /// Path relative to the repository's `rules/` directory, forward slashed.
    ///
    /// This is the path the loader validates against, and the same string the
    /// error messages name, so a rule that fails to load points at the file
    /// somebody wrote rather than at an offset into a binary.
    pub path: &'static str,
    /// The file's contents.
    pub text: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/embedded_rules.rs"));

/// Every rule file this binary carries, sorted by path.
///
/// Public because the guarantee that matters about this set is one an outside
/// test has to check: `tests/embedded_rules.rs` walks the repository's `rules/`
/// tree and compares it against this list. A build whose copy has drifted from
/// the tree fails there rather than shipping detectors nobody edited.
pub fn embedded_rule_files() -> &'static [EmbeddedRuleFile] {
    EMBEDDED_RULE_FILES
}

/// Loads the rule set compiled into this binary.
///
/// The counterpart of [`crate::rules::load_directory`], and it applies the same
/// two rules: a broken entry does not hide the others, and a directory belonging
/// to another component's rule language is not read as a detector rule. Errors
/// are still possible even though nothing is read from disk, because a rule that
/// no longer validates is a rule this build must not silently drop.
pub fn load_embedded() -> (Vec<RuleFile>, Vec<RuleLoadError>) {
    let mut rules = Vec::new();
    let mut errors = Vec::new();

    for file in EMBEDDED_RULE_FILES {
        if is_foreign_rule_language(file.path) {
            continue;
        }
        match parse_rule(Path::new(file.path), file.text) {
            Ok(rule) => rules.push(rule),
            Err(e) => errors.push(e),
        }
    }

    rules.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    // Ordered for the same reason the directory loader orders its own: these
    // strings reach a report that has to be byte identical across runs.
    errors.sort_by_key(std::string::ToString::to_string);
    (rules, errors)
}

/// Whether an embedded path belongs to another component's rule language.
///
/// Only the first segment is examined, which is the directory walk's rule
/// spelled for a flattened path: `rules/masking/` is the proxy's affix language,
/// while a `masking` directory nested inside a language family is an ordinary
/// directory and is still read.
fn is_foreign_rule_language(path: &str) -> bool {
    path.split('/')
        .next()
        .is_some_and(|segment| FOREIGN_RULE_DIRECTORIES.contains(&segment))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_set_is_not_empty() {
        // The failure this guards: a table that generated empty would load no
        // detector, match nothing, and report every tree as clean.
        assert!(
            !embedded_rule_files().is_empty(),
            "no rule file was compiled in"
        );
    }

    #[test]
    fn every_embedded_rule_parses_and_validates() {
        let (rules, errors) = load_embedded();
        assert!(errors.is_empty(), "{errors:?}");
        assert!(!rules.is_empty(), "the embedded set produced no rule");
    }

    #[test]
    fn the_proxy_masking_rules_are_not_read_as_detector_rules() {
        // `rules/masking/<lang>/` is a different rule language read by a
        // different loader. Parsed as a detector rule every affix file becomes a
        // load error, and load errors fail the whole run: a scanner that finds
        // nothing because another component shipped a file.
        let (rules, _) = load_embedded();
        assert!(
            rules.iter().all(|rule| rule.language != "tr"),
            "an affix file was read as a detector rule"
        );
        assert!(is_foreign_rule_language("masking/tr/affixes.toml"));
        assert!(!is_foreign_rule_language("python/openai.toml"));
    }

    #[test]
    fn embedded_paths_are_forward_slashed_and_relative() {
        for file in embedded_rule_files() {
            assert!(
                !file.path.contains('\\'),
                "{} is not forward slashed",
                file.path
            );
            assert!(
                !Path::new(file.path).is_absolute(),
                "{} carries a build machine's path",
                file.path
            );
        }
    }
}
