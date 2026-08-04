//! Loading and validating rule files.
//!
//! Every error here names the file and, where the parser gives one, the line. A
//! rule set is only maintainable if a broken entry can be traced back to the file
//! a person wrote, so "invalid rule" without a location is treated as an
//! unacceptable error message rather than an acceptable one.

use std::path::{Path, PathBuf};

use crate::rules::model::RuleFile;

/// Why a rule file was rejected.
#[derive(Debug, thiserror::Error)]
pub enum RuleLoadError {
    #[error("{path}: cannot be read: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{path}:{line}: {detail}")]
    Syntax {
        path: PathBuf,
        line: usize,
        detail: String,
    },

    #[error("{path}: {detail}")]
    Invalid { path: PathBuf, detail: String },
}

impl RuleLoadError {
    pub fn path(&self) -> &Path {
        match self {
            Self::Read { path, .. } | Self::Syntax { path, .. } | Self::Invalid { path, .. } => {
                path
            }
        }
    }
}

/// Schema version this build understands.
const SUPPORTED_SCHEMA_VERSION: &str = "1.0";

/// Reads and validates one rule file.
pub fn load_rule_file(path: &Path) -> Result<RuleFile, RuleLoadError> {
    let text = std::fs::read_to_string(path).map_err(|source| RuleLoadError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    parse_rule(path, &text)
}

/// Parses rule text. Split out from file reading so tests do not need a temp dir.
pub fn parse_rule(path: &Path, text: &str) -> Result<RuleFile, RuleLoadError> {
    let rule: RuleFile = toml::from_str(text).map_err(|e| {
        // The toml crate reports a byte span. Turning it into a line number is
        // what makes the message actionable in an editor.
        let line = e
            .span()
            .map(|span| text[..span.start.min(text.len())].lines().count())
            .unwrap_or(1);
        RuleLoadError::Syntax {
            path: path.to_path_buf(),
            line,
            detail: e.message().to_owned(),
        }
    })?;

    validate(path, &rule)?;
    Ok(rule)
}

fn validate(path: &Path, rule: &RuleFile) -> Result<(), RuleLoadError> {
    let invalid = |detail: String| RuleLoadError::Invalid {
        path: path.to_path_buf(),
        detail,
    };

    if rule.schema_version != SUPPORTED_SCHEMA_VERSION {
        return Err(invalid(format!(
            "schema_version is {}, this build understands {SUPPORTED_SCHEMA_VERSION}",
            rule.schema_version
        )));
    }

    // A rule with no patterns loads cleanly and then never fires. Left in place it
    // reads as coverage that does not exist, which is worse than a load failure.
    if rule.matches.is_empty() {
        return Err(invalid(
            "no [[match]] block: a rule with no pattern can never produce a finding".to_owned(),
        ));
    }

    validate_rule_id(&rule.rule_id).map_err(invalid)?;

    if rule.rule_version.split('.').count() != 3 {
        return Err(invalid(format!(
            "rule_version must be three segment semver, found {}",
            rule.rule_version
        )));
    }

    for (index, spec) in rule.matches.iter().enumerate() {
        if spec.query.trim().is_empty() {
            return Err(invalid(format!("[[match]] {index}: query is empty")));
        }
    }

    for downgrade in &rule.classify.downgrade {
        if !downgrade.when.ends_with(".unresolved") {
            return Err(invalid(format!(
                "downgrade condition {:?} is not supported; the only form is <field>.unresolved",
                downgrade.when
            )));
        }
        let field = downgrade.when.trim_end_matches(".unresolved");
        if !rule.extract.contains_key(field) {
            return Err(invalid(format!(
                "downgrade refers to {field:?}, which no [extract] entry defines"
            )));
        }
    }

    Ok(())
}

/// Enforces the `language.source.rule-name` shape.
///
/// The format is fixed by the finding contract, because `rule_id` is the key the
/// known gaps catalogue and the benchmark results join on. Two spellings of one
/// rule would silently split those joins.
fn validate_rule_id(rule_id: &str) -> Result<(), String> {
    let segments: Vec<&str> = rule_id.split('.').collect();
    if segments.len() != 3 {
        return Err(format!(
            "rule_id must be language.source.rule-name, found {rule_id:?}"
        ));
    }
    if segments.iter().any(|s| s.is_empty()) {
        return Err(format!("rule_id has an empty segment: {rule_id:?}"));
    }
    let name = segments[2];
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(format!(
            "rule name segment must be lowercase with hyphens, found {name:?}"
        ));
    }
    Ok(())
}

/// Loads every rule file under a directory, sorted by path.
///
/// Errors do not stop the load. A broken file must not hide the other rules, and
/// the caller needs the full list to report every problem in one pass rather than
/// one per run.
pub fn load_directory(dir: &Path) -> (Vec<RuleFile>, Vec<RuleLoadError>) {
    let mut rules = Vec::new();
    let mut errors = Vec::new();

    let mut paths: Vec<PathBuf> = Vec::new();
    collect_toml_files(dir, &mut paths);
    paths.sort();

    for path in paths {
        match load_rule_file(&path) {
            Ok(rule) => rules.push(rule),
            Err(e) => errors.push(e),
        }
    }

    rules.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    (rules, errors)
}

fn collect_toml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_toml_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "toml") {
            out.push(path);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
schema_version = "1.0"
language = "python"
provider = "openai"
rule_id = "python.static.openai-chat-completions"
rule_version = "1.0.0"

[[match]]
kind = "call"
query = "(call) @call"

[classify]
egress_kind = "llm_chat"
default_confidence = "confirmed"
"#;

    fn parse(text: &str) -> Result<RuleFile, RuleLoadError> {
        parse_rule(Path::new("rules/python/openai.toml"), text)
    }

    #[test]
    fn loads_a_minimal_rule() {
        let rule = parse(MINIMAL).unwrap();
        assert_eq!(rule.rule_id, "python.static.openai-chat-completions");
        assert_eq!(rule.matches.len(), 1);
    }

    #[test]
    fn syntax_error_reports_file_and_line() {
        let broken = "schema_version = \"1.0\"\nlanguage = python\n";
        let err = parse(broken).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("rules/python/openai.toml"), "{rendered}");
        assert!(rendered.contains(":2"), "expected line 2 in {rendered}");
    }

    #[test]
    fn unknown_field_is_rejected_rather_than_ignored() {
        // A typo in a rule file would otherwise load cleanly and silently do
        // nothing, which is the failure mode hardest to notice.
        let text = MINIMAL.replace("provider = \"openai\"", "provdier = \"openai\"");
        assert!(parse(&text).is_err());
    }

    #[test]
    fn rule_without_a_pattern_is_rejected() {
        let text = MINIMAL.replace("[[match]]\nkind = \"call\"\nquery = \"(call) @call\"\n", "");
        let err = parse(&text).unwrap_err();
        assert!(err.to_string().contains("match"), "{err}");
    }

    #[test]
    fn rule_id_must_follow_the_contract_format() {
        for bad in [
            "py.openai.chat_completions",
            "python.static",
            "python..name",
            "python.static.Name",
        ] {
            let text = MINIMAL.replace("python.static.openai-chat-completions", bad);
            assert!(parse(&text).is_err(), "{bad} should have been rejected");
        }
    }

    #[test]
    fn unsupported_schema_version_is_named_in_the_error() {
        let text = MINIMAL.replace("schema_version = \"1.0\"", "schema_version = \"2.0\"");
        let err = parse(&text).unwrap_err();
        assert!(err.to_string().contains("2.0"), "{err}");
    }

    #[test]
    fn downgrade_must_reference_a_field_that_exists() {
        let text = format!(
            "{MINIMAL}\n[[classify.downgrade]]\nwhen = \"base_url.unresolved\"\nto = \"suspect\"\n"
        );
        let err = parse(&text).unwrap_err();
        assert!(err.to_string().contains("base_url"), "{err}");
    }

    #[test]
    fn downgrade_accepts_a_declared_field() {
        let text = format!(
            "{MINIMAL}\n[extract]\nbase_url = {{ from = \"recv\", constructor_keyword = \"base_url\" }}\n\n[[classify.downgrade]]\nwhen = \"base_url.unresolved\"\nto = \"suspect\"\ncoverage_note = \"target_host_unresolved\"\n"
        );
        let rule = parse(&text).unwrap();
        assert_eq!(rule.classify.downgrade.len(), 1);
    }

    #[test]
    fn unsupported_downgrade_condition_is_rejected() {
        let text =
            format!("{MINIMAL}\n[[classify.downgrade]]\nwhen = \"always\"\nto = \"suspect\"\n");
        assert!(parse(&text).is_err());
    }

    #[test]
    fn rule_version_must_be_three_segments() {
        let text = MINIMAL.replace("rule_version = \"1.0.0\"", "rule_version = \"1.0\"");
        assert!(parse(&text).is_err());
    }
}
