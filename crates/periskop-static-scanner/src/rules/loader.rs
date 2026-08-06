//! Loading and validating rule files.
//!
//! Every error here names the file and, where the parser gives one, the line. A
//! rule set is only maintainable if a broken entry can be traced back to the file
//! a person wrote, so "invalid rule" without a location is treated as an
//! unacceptable error message rather than an acceptable one.

use std::path::{Path, PathBuf};

use crate::language::Language;
use crate::rules::model::{ExtractRole, MatchSpec, RuleFile};

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

    /// The same error with its file named relative to the rule root.
    ///
    /// The rule root arrives on the command line and is usually absolute. These
    /// messages reach the report as diagnostics, and an absolute path there would
    /// tie the output to one machine, which breaks the promise that two runs over
    /// the same tree compare equal. The root itself renders as `.` rather than as
    /// an empty string, so a failure to read the root is still legible.
    fn relative_to(self, root: &Path) -> Self {
        let shorten = |path: PathBuf| {
            let stripped = path.strip_prefix(root).map(|p| {
                if p.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    p.to_path_buf()
                }
            });
            stripped.unwrap_or(path)
        };
        match self {
            Self::Read { path, source } => Self::Read {
                path: shorten(path),
                source,
            },
            Self::Syntax { path, line, detail } => Self::Syntax {
                path: shorten(path),
                line,
                detail,
            },
            Self::Invalid { path, detail } => Self::Invalid {
                path: shorten(path),
                detail,
            },
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
    let mut rule: RuleFile = toml::from_str(text).map_err(|e| {
        // The toml crate reports a byte span. Turning it into a line number is
        // what makes the message actionable in an editor.
        //
        // Counting newlines rather than lines: an error at the first column of a
        // line has a prefix that ends in a newline, and `lines()` does not count
        // the empty piece after it, so the message pointed one line above the
        // problem and the reader looked at the wrong row. An error with no span
        // becomes an `Invalid`, because naming line one would be a guess that
        // reads exactly like a fact.
        match e.span() {
            Some(span) => RuleLoadError::Syntax {
                path: path.to_path_buf(),
                line: text[..span.start.min(text.len())].matches('\n').count() + 1,
                detail: e.message().to_owned(),
            },
            None => RuleLoadError::Invalid {
                path: path.to_path_buf(),
                detail: e.message().to_owned(),
            },
        }
    })?;

    rule.rule_hash = blake3::hash(text.as_bytes()).to_hex().to_string();
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
    validate_language(path, rule).map_err(invalid)?;

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
        validate_method_agreement(index, spec).map_err(&invalid)?;
    }

    validate_extract_roles(rule).map_err(&invalid)?;

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

/// Field names the engine used to read as a destination before roles existed.
///
/// Kept only to refuse them. A rule still spelling one of these without saying
/// what it is for reads as a working rule and is not one: the engine matches on
/// the role now, so the field would be carried into the report and never
/// compared against anything.
const FORMER_DESTINATION_FIELDS: [&str; 2] = ["base_url", "target_url"];

/// Checks that a rule says which of its fields is the destination, and says it once.
///
/// `[extract]` used to give a key and a place to read it from, and the engine
/// made up the rest: it looked for `base_url`, then for `target_url`, and took
/// whichever it found. A rule whose SDK calls the same thing `endpoint` or
/// `api_base` produced a finding with no destination, no error and no
/// diagnostic, so `target_drift` was underivable for that rule and the report
/// gave no sign of it. `role` is what replaces the guess (ADR-003).
///
/// Two failures are refused here rather than at the call site. A rule with two
/// destination fields has not said where the call goes, it has said two things;
/// and a rule still using one of the old names without a role is a rule that
/// silently lost its destination in this change, which is precisely the failure
/// the change is about.
fn validate_extract_roles(rule: &RuleFile) -> Result<(), String> {
    let destinations: Vec<&str> = rule
        .extract
        .iter()
        .filter(|(_, spec)| spec.role == Some(ExtractRole::DestinationUrl))
        .map(|(field, _)| field.as_str())
        .collect();

    if destinations.len() > 1 {
        return Err(format!(
            "[extract] declares role = \"destination_url\" on more than one field ({}); a call \
             has one destination, and two claims about it are not a stronger claim",
            destinations.join(", ")
        ));
    }

    for field in FORMER_DESTINATION_FIELDS {
        let Some(spec) = rule.extract.get(field) else {
            continue;
        };
        if spec.role.is_none() {
            return Err(format!(
                "[extract] {field:?} carries no role; the engine reads the destination from \
                 role = \"destination_url\" rather than from the field name, so this field \
                 would be reported and never compared. Add the role, or rename the field if \
                 it is not the destination"
            ));
        }
    }

    Ok(())
}

/// Holds a query's method predicate and its `[match.method]` list to one answer.
///
/// Eleven rule files spell the accepted method names twice: once as a
/// `(#match? @method "^(create|stream)$")` predicate inside the query, and once
/// as `one_of` beside it. Both copies have to stay because they do different
/// jobs. The predicate is a filter tree-sitter applies while it walks, so
/// dropping it turns every attribute call in a file into a candidate the engine
/// has to build and then discard; `one_of` is what the engine enforces, and it is
/// the only one of the two a rule can be trusted on, since a query with no
/// predicate is legal.
///
/// What could not stay is the two of them disagreeing silently. Editing the list
/// and forgetting the predicate narrows the rule with nothing red: the engine
/// would accept `parse`, and no match carrying it ever reaches the engine. The
/// copies are still two, and this is what makes the second one a derived claim
/// rather than an independent one, in the same shape `tests/provider_table.rs`
/// holds the provider host alternations to `schemas/providers.json`.
///
/// A predicate that is not a plain alternation is left alone. A real regular
/// expression says more than a list can, and comparing the two would either
/// reject a legitimate pattern or wave a genuine disagreement through.
fn validate_method_agreement(index: usize, spec: &MatchSpec) -> Result<(), String> {
    let Some(method) = &spec.method else {
        return Ok(());
    };
    let Some(pinned) = predicate_alternatives(&spec.query, &method.capture) else {
        return Ok(());
    };

    let mut declared = method.one_of.clone();
    declared.sort();
    declared.dedup();
    let mut queried = pinned;
    queried.sort();
    queried.dedup();

    if declared == queried {
        return Ok(());
    }
    Err(format!(
        "[[match]] {index}: the query predicate on @{} accepts {queried:?} but [match.method] \
         one_of accepts {declared:?}; the two are the same list written twice, and a rule whose \
         copies disagree silently applies the narrower one",
        method.capture
    ))
}

/// The alternatives a `#match?` predicate pins on `capture`, when it pins a set.
///
/// Deliberately literal about the shape it reads: `^(a|b|c)$` and nothing else.
/// Anchors, a character class or a quantifier anywhere in the pattern make it a
/// regular expression rather than a list, and the answer is then `None` so the
/// caller does not compare it to one.
fn predicate_alternatives(query: &str, capture: &str) -> Option<Vec<String>> {
    let opening = format!("#match? @{capture} \"");
    let start = query.find(&opening)? + opening.len();
    let rest = query.get(start..)?;
    let pattern = rest.get(..rest.find('"')?)?;

    let inner = pattern.strip_prefix("^(")?.strip_suffix(")$")?;
    let is_plain_name = |name: &str| {
        !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    };
    let alternatives: Vec<String> = inner.split('|').map(str::to_owned).collect();
    alternatives
        .iter()
        .all(|a| is_plain_name(a))
        .then_some(alternatives)
}

/// Checks that a rule agrees with itself and with where it sits about its family.
///
/// Three ways a rule could name a family and be ignored or misapplied, none of
/// which produced an error before. A family no grammar serves loaded cleanly,
/// matched no language and never ran, with an empty error list to prove it went
/// well. A `rule_id` whose first segment disagreed with `language` split the join
/// key the gap catalogue and the benchmark use. And a rule for one language sitting
/// in another language's directory compiled against the wrong grammar, which takes
/// down the whole family it landed in rather than just itself.
///
/// The directory check is skipped when the file does not sit under a directory
/// named for a family. Rule text is also loaded from strings in tests, where
/// there is no directory to agree with.
fn validate_language(path: &Path, rule: &RuleFile) -> Result<(), String> {
    let families: Vec<&str> = Language::ALL.iter().map(|l| l.rule_family()).collect();
    if !families.contains(&rule.language.as_str()) {
        return Err(format!(
            "language {:?} is not one of the rule families this build serves: {}",
            rule.language,
            families.join(", ")
        ));
    }

    let first_segment = rule.rule_id.split('.').next().unwrap_or_default();
    if first_segment != rule.language {
        return Err(format!(
            "rule_id starts with {first_segment:?} but language is {:?}; the two are the same key",
            rule.language
        ));
    }

    let directory = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str());
    match directory {
        Some(name) if families.contains(&name) && name != rule.language => Err(format!(
            "rule sits in {name:?} but declares language {:?}",
            rule.language
        )),
        _ => Ok(()),
    }
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
///
/// A directory that cannot be walked is an error too, not an empty result. An
/// unreadable rule tree and a rule tree with nothing in it produce the same empty
/// rule list, and the caller has no way to tell them apart unless the walk says so.
pub fn load_directory(dir: &Path) -> (Vec<RuleFile>, Vec<RuleLoadError>) {
    let mut rules = Vec::new();
    let mut errors = Vec::new();

    let mut paths: Vec<PathBuf> = Vec::new();
    collect_toml_files(dir, &mut paths, &mut errors);
    paths.sort();

    for path in paths {
        match load_rule_file(&path) {
            Ok(rule) => rules.push(rule),
            Err(e) => errors.push(e),
        }
    }

    rules.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    // Directory entries arrive in filesystem order, so errors are ordered here
    // rather than left as the walk found them. These strings reach a report that
    // has to be byte identical across runs.
    let mut errors: Vec<RuleLoadError> = errors.into_iter().map(|e| e.relative_to(dir)).collect();
    errors.sort_by_key(|e| e.to_string());
    (rules, errors)
}

/// How deep the rule tree may nest.
///
/// The walk used to recurse without a bound and `is_dir` follows links, so a
/// link back to an ancestor turned the walk into an unbounded descent that ended
/// in a stack overflow. That is not a panic and not an error the caller can
/// report; the process dies with a signal and the user sees nothing at all. The
/// depth is generous: the shipped layout is one directory per language.
const MAX_RULE_TREE_DEPTH: usize = 8;

fn collect_toml_files(dir: &Path, out: &mut Vec<PathBuf>, errors: &mut Vec<RuleLoadError>) {
    collect_toml_files_at(dir, 0, out, errors);
}

/// Directories under `rules/` that hold a **different** rule language, owned by a
/// different component and read by a different loader.
///
/// One entry today: `rules/masking/<natural-language>/`, the proxy's affix rules
/// for detection layer B (`docs/04-contracts/proxy-policy.md` section 11). That
/// contract picked the `masking/` prefix precisely so the two rule languages
/// would not share a directory, and this is the other half of the same decision:
/// the static scanner's walk has to know not to descend, or every affix file
/// becomes a malformed detector rule and the rule set fails to load.
///
/// Named rather than inferred. Skipping "anything that does not parse" would
/// turn a genuinely broken detector rule into a silent omission, which is the
/// failure mode this whole loader is written against.
///
/// Visible to the crate because the embedded rule set carries the same tree and
/// has to skip the same directories. Two lists would let the disk walk and the
/// compiled-in copy disagree about what a detector rule is.
pub(crate) const FOREIGN_RULE_DIRECTORIES: &[&str] = &["masking"];

/// Whether this directory belongs to another component's rule language.
///
/// Only checked at the top level of the tree; a `masking` directory nested
/// inside a language family is not this contract's directory and is still read,
/// because pretending otherwise would give somebody a way to hide a rule file.
fn is_foreign_rule_language(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| FOREIGN_RULE_DIRECTORIES.contains(&name))
}

fn collect_toml_files_at(
    dir: &Path,
    depth: usize,
    out: &mut Vec<PathBuf>,
    errors: &mut Vec<RuleLoadError>,
) {
    if depth > MAX_RULE_TREE_DEPTH {
        errors.push(RuleLoadError::Invalid {
            path: dir.to_path_buf(),
            detail: format!(
                "rule tree is nested more than {MAX_RULE_TREE_DEPTH} levels deep and was not \
                 followed further; a link back to an ancestor looks like this"
            ),
        });
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(source) => {
            // The quietest way to run with no rules at all: the directory is
            // unreadable, the rule list comes back empty, the scan matches
            // nothing and every counter says the run was clean.
            errors.push(RuleLoadError::Read {
                path: dir.to_path_buf(),
                source,
            });
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) => {
                // The entry has no name to report, so the directory holding it is
                // the most specific location available.
                errors.push(RuleLoadError::Read {
                    path: dir.to_path_buf(),
                    source,
                });
                continue;
            }
        };
        let path = entry.path();
        // `symlink_metadata` does not follow the link, so a link to a directory
        // is not descended into. Together with the depth bound this makes the
        // walk terminate on any tree, including one that points at itself.
        let is_directory = std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir());
        if is_directory {
            if is_foreign_rule_language(&path) {
                continue;
            }
            collect_toml_files_at(&path, depth + 1, out, errors);
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

    /// The message of a rejection, so a test can say why a rule was refused
    /// rather than only that it was. A rule refused for the wrong reason is as
    /// much a defect as one that loads.
    fn invalid_detail(outcome: Result<RuleFile, RuleLoadError>) -> String {
        match outcome {
            Err(RuleLoadError::Invalid { detail, .. }) => detail,
            Err(other) => format!("__wrong error variant: {other}"),
            Ok(_) => "__the rule loaded".to_owned(),
        }
    }

    #[test]
    fn loads_a_minimal_rule() {
        let rule = parse(MINIMAL).unwrap();
        assert_eq!(rule.rule_id, "python.static.openai-chat-completions");
        assert_eq!(rule.matches.len(), 1);
    }

    /// A rule spelling its method list in the query and beside it, as the shipped
    /// rules do. `predicate` is dropped into the query verbatim.
    fn with_method(predicate: &str, one_of: &str) -> String {
        format!(
            r#"
schema_version = "1.0"
language = "python"
provider = "openai"
rule_id = "python.static.openai-chat-completions"
rule_version = "1.0.0"

[[match]]
kind = "call"
query = '''
(call
  function: (attribute attribute: (identifier) @method)
  {predicate}) @call
'''
[match.method]
capture = "method"
one_of = {one_of}

[classify]
egress_kind = "llm_chat"
default_confidence = "confirmed"
"#
        )
    }

    #[test]
    fn a_method_list_written_twice_has_to_agree() {
        // The drift that used to be silent: the list gains `parse`, the
        // predicate does not, and the rule narrows to what the predicate lets
        // through while every reader of the file believes the list.
        let text = with_method(
            r#"(#match? @method "^(create|stream)$")"#,
            r#"["create", "stream", "parse"]"#,
        );
        let detail = invalid_detail(parse(&text));
        assert!(detail.contains("one_of"), "{detail}");
        assert!(detail.contains("parse"), "{detail}");
    }

    #[test]
    fn agreeing_copies_load_whatever_order_they_are_written_in() {
        let text = with_method(
            r#"(#match? @method "^(stream|create)$")"#,
            r#"["create", "stream"]"#,
        );
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn a_predicate_that_is_a_real_regex_is_not_compared_to_a_list() {
        // `^(create|acreate)$` is a list. `^a.*` is not, and reading it as one
        // would reject a legitimate pattern for disagreeing with a list it was
        // never a copy of.
        let text = with_method(r#"(#match? @method "^create[0-9]+$")"#, r#"["create1"]"#);
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn a_query_with_no_predicate_is_left_to_its_list() {
        let text = with_method("", r#"["create", "stream"]"#);
        assert!(parse(&text).is_ok());
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
            "{MINIMAL}\n[extract]\nbase_url = {{ from = \"recv\", constructor_keyword = \"base_url\", role = \"destination_url\" }}\n\n[[classify.downgrade]]\nwhen = \"base_url.unresolved\"\nto = \"suspect\"\ncoverage_note = \"target_host_unresolved\"\n"
        );
        let rule = parse(&text).unwrap();
        assert_eq!(rule.classify.downgrade.len(), 1);
    }

    #[test]
    fn a_destination_field_under_a_new_name_is_found_by_its_role() {
        // The whole point of the role. `endpoint` is not a name the engine ever
        // knew, and before this the field was carried into the report and never
        // compared, so the join had nothing to work with and said nothing about
        // it.
        let text = format!(
            "{MINIMAL}\n[extract]\nendpoint = {{ from = \"recv\", constructor_keyword = \"base_url\", role = \"destination_url\" }}\n"
        );
        let rule = parse(&text).unwrap();
        assert_eq!(
            rule.extract.get("endpoint").and_then(|spec| spec.role),
            Some(ExtractRole::DestinationUrl)
        );
    }

    #[test]
    fn an_old_style_destination_field_with_no_role_is_refused() {
        // The migration guard. Left to load, this rule reads as working and
        // produces findings with no destination at all.
        let text = format!(
            "{MINIMAL}\n[extract]\nbase_url = {{ from = \"recv\", constructor_keyword = \"base_url\" }}\n"
        );
        let detail = invalid_detail(parse(&text));
        assert!(detail.contains("destination_url"), "{detail}");
    }

    #[test]
    fn two_destination_roles_in_one_rule_are_refused() {
        let text = format!(
            "{MINIMAL}\n[extract]\nbase_url = {{ from = \"recv\", role = \"destination_url\" }}\nendpoint = {{ from = \"args\", keyword = \"endpoint\", role = \"destination_url\" }}\n"
        );
        assert!(parse(&text).is_err());
    }

    #[test]
    fn a_misspelled_role_is_a_load_error_rather_than_a_field_that_does_nothing() {
        let text = format!(
            "{MINIMAL}\n[extract]\nendpoint = {{ from = \"url\", role = \"destination\" }}\n"
        );
        assert!(parse(&text).is_err());
    }

    #[test]
    fn a_field_the_report_only_carries_needs_no_role() {
        let text =
            format!("{MINIMAL}\n[extract]\nmodel = {{ from = \"args\", keyword = \"model\" }}\n");
        assert!(parse(&text).is_ok());
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

    #[test]
    fn a_syntax_error_at_the_start_of_a_line_names_that_line() {
        // The bug this pins: the prefix before a column zero error ends in a
        // newline, and `lines()` does not count the empty piece after it, so
        // every such error pointed one row above the actual problem.
        let broken = "schema_version = \"1.0\"\nlanguage = \"python\"\n= 1\n";
        let err = parse(broken).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains(":3:"), "expected line 3 in {rendered}");
    }

    #[test]
    fn an_unknown_rule_family_is_rejected_at_load_time() {
        // A family no grammar serves used to load cleanly, match no language and
        // never run, leaving an empty error list behind it. Only a repository
        // wide lint caught it, and that lint does not see rules passed with
        // --rules at all.
        let text = MINIMAL
            .replace("language = \"python\"", "language = \"js\"")
            .replace("python.static.openai", "js.static.openai");
        let err = parse(&text).unwrap_err();
        assert!(err.to_string().contains("js"), "{err}");
    }

    #[test]
    fn the_rule_id_and_the_language_have_to_agree() {
        let text = MINIMAL.replace("language = \"python\"", "language = \"typescript\"");
        let err = parse(&text).unwrap_err();
        assert!(err.to_string().contains("rule_id"), "{err}");
    }

    #[test]
    fn a_rule_in_the_wrong_language_directory_is_rejected() {
        // Left alone this compiles a TypeScript query against the Python grammar,
        // which fails and takes every other Python rule down with it.
        let text = MINIMAL
            .replace("language = \"python\"", "language = \"typescript\"")
            .replace("python.static.openai", "typescript.static.openai");
        let err = parse_rule(Path::new("rules/python/openai.toml"), &text).unwrap_err();
        assert!(err.to_string().contains("python"), "{err}");
        // The same text under the directory it belongs in is fine.
        assert!(parse_rule(Path::new("rules/typescript/openai.toml"), &text).is_ok());
    }

    #[test]
    fn a_rule_directory_that_links_to_its_own_parent_terminates() {
        // Without a depth bound this recursed until the stack ran out, which
        // kills the process with a signal rather than an error anyone can read.
        #[cfg(unix)]
        {
            let root =
                std::env::temp_dir().join(format!("periskop-rule-loop-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("python")).unwrap();
            std::fs::write(root.join("python/openai.toml"), MINIMAL).unwrap();
            std::os::unix::fs::symlink(&root, root.join("python/loop")).unwrap();

            let (rules, errors) = load_directory(&root);
            let _ = std::fs::remove_dir_all(&root);

            assert_eq!(rules.len(), 1, "{rules:?}");
            assert!(errors.is_empty(), "{errors:?}");
        }
    }

    #[test]
    fn the_proxy_masking_rules_are_not_read_as_detector_rules() {
        // `rules/masking/<lang>/` is the proxy's affix rule language
        // (`proxy-policy.md` section 11). Descending into it makes every affix
        // file a malformed detector rule, and because `load_directory`'s errors
        // are fatal to the caller, the whole rule set stops loading: a scanner
        // that finds nothing because a *different* component shipped a file.
        let root =
            std::env::temp_dir().join(format!("periskop-rule-foreign-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("python")).unwrap();
        std::fs::create_dir_all(root.join("masking/tr")).unwrap();
        std::fs::write(root.join("python/openai.toml"), MINIMAL).unwrap();
        std::fs::write(
            root.join("masking/tr/affixes.toml"),
            "schema_version = \"1.0\"\nlanguage = \"tr\"\nsuffixes = [\"ler\"]\n",
        )
        .unwrap();

        let (rules, errors) = load_directory(&root);
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(rules.len(), 1, "{rules:?}");
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn a_directory_that_cannot_be_walked_is_an_error_not_an_empty_rule_set() {
        // The error class this test catches: a rule tree that is missing, renamed
        // or unreadable used to return no rules and no errors, so the scan ran
        // with nothing loaded and reported a clean result to prove it.
        let (rules, errors) = load_directory(Path::new("rules/this-directory-does-not-exist"));
        assert!(rules.is_empty());
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].to_string().contains("cannot be read"),
            "{}",
            errors[0]
        );
    }
}
