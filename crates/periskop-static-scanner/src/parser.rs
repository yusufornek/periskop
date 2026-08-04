//! Parsing source into a syntax tree.
//!
//! tree-sitter is error tolerant: it does not refuse broken input, it produces a
//! tree containing error nodes and carries on. That property is what lets a scan
//! survive one unparseable file, but it also means a caller who only checks for a
//! returned tree will treat a half understood file as fully understood.
//!
//! So parsing here reports three outcomes rather than two. A clean tree, a tree
//! with damaged regions, and a hard failure. The middle case is the one that
//! matters: it is real coverage loss, and it is passed on as such instead of being
//! rounded up to success.

use std::path::{Path, PathBuf};

use periskop_core::coverage::UnparsedReason;

use crate::language::Language;

/// A parsed file together with the source it was parsed from.
///
/// The source is kept because tree-sitter nodes carry byte offsets, not text, and
/// every later stage needs to read the bytes a node covers.
#[derive(Debug)]
pub struct ParsedFile {
    path: PathBuf,
    language: Language,
    source: String,
    tree: tree_sitter::Tree,
    /// Regions the grammar could not make sense of. Empty means a clean parse.
    error_node_count: usize,
}

impl ParsedFile {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn language(&self) -> Language {
        self.language
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn tree(&self) -> &tree_sitter::Tree {
        &self.tree
    }

    pub fn root_node(&self) -> tree_sitter::Node<'_> {
        self.tree.root_node()
    }

    /// Whether the grammar failed to understand part of the file.
    ///
    /// A partially parsed file still yields findings from the regions that did
    /// parse. Those findings are real, but the file must also appear in the
    /// coverage statement, because the regions that failed may have contained
    /// egress the scan never saw.
    pub fn is_partial(&self) -> bool {
        self.error_node_count > 0
    }

    pub fn error_node_count(&self) -> usize {
        self.error_node_count
    }

    /// The coverage reason this file contributes, if any.
    pub fn coverage_reason(&self) -> Option<UnparsedReason> {
        self.is_partial().then_some(UnparsedReason::PartialParse)
    }

    /// Total node count, used by tests and by the corpus statistics.
    pub fn node_count(&self) -> usize {
        count_nodes(self.root_node())
    }
}

/// Why a file produced no tree at all.
///
/// Distinct from a partial parse: here there is nothing to match rules against.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseFailure {
    #[error("no grammar is linked for this file")]
    NoGrammar,

    /// The grammar object was rejected by the parser. In practice this means the
    /// linked grammar was built against an incompatible tree-sitter version, which
    /// is a build problem rather than an input problem.
    #[error("grammar rejected by the parser: {detail}")]
    GrammarIncompatible { detail: String },

    /// tree-sitter returned no tree. It does this on cancellation or on input past
    /// its size limit, never on ordinary syntax errors.
    #[error("parser returned no tree")]
    NoTree,
}

impl ParseFailure {
    /// How this failure is counted in the coverage statement.
    pub fn coverage_reason(&self) -> UnparsedReason {
        match self {
            Self::NoGrammar => UnparsedReason::NoGrammar,
            // A grammar that will not load is an engine fault, not a property of
            // the file, but from the reader's side the effect is identical: the
            // file was not read. It is counted, and the diagnostics block carries
            // the engine level detail.
            Self::GrammarIncompatible { .. } => UnparsedReason::ParseError,
            Self::NoTree => UnparsedReason::ParseError,
        }
    }
}

/// Parses source text with the grammar chosen for `path`.
///
/// Never panics on malformed input. Syntax errors surface through
/// [`ParsedFile::is_partial`], not through the error type.
pub fn parse(
    path: impl Into<PathBuf>,
    source: impl Into<String>,
) -> Result<ParsedFile, ParseFailure> {
    let path = path.into();
    let language = Language::from_path(&path).ok_or(ParseFailure::NoGrammar)?;
    parse_as(path, source, language)
}

/// Parses with an explicitly chosen grammar.
pub fn parse_as(
    path: impl Into<PathBuf>,
    source: impl Into<String>,
    language: Language,
) -> Result<ParsedFile, ParseFailure> {
    let path = path.into();
    let source = source.into();

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language.grammar())
        .map_err(|e| ParseFailure::GrammarIncompatible {
            detail: e.to_string(),
        })?;

    let tree = parser.parse(&source, None).ok_or(ParseFailure::NoTree)?;
    let error_node_count = count_error_nodes(tree.root_node());

    Ok(ParsedFile {
        path,
        language,
        source,
        tree,
        error_node_count,
    })
}

/// Walks the tree once and counts damaged nodes.
///
/// `is_error` covers regions the grammar could not reduce; `is_missing` covers
/// tokens tree-sitter inserted to recover. Both mean the text on disk is not
/// fully represented by the tree, so both count.
fn count_error_nodes(root: tree_sitter::Node<'_>) -> usize {
    let mut cursor = root.walk();
    let mut count = 0usize;
    let mut nodes = vec![root];
    while let Some(node) = nodes.pop() {
        if node.is_error() || node.is_missing() {
            count += 1;
        }
        // Descending only into subtrees flagged as containing errors would be
        // faster, but has_error() is set on ancestors too, and skipping clean
        // siblings early has caused undercounts in other scanners. Correctness
        // first; the file level cost is bounded by the tree size.
        nodes.extend(node.children(&mut cursor));
    }
    count
}

fn count_nodes(root: tree_sitter::Node<'_>) -> usize {
    let mut cursor = root.walk();
    let mut count = 0usize;
    let mut nodes = vec![root];
    while let Some(node) = nodes.pop() {
        count += 1;
        nodes.extend(node.children(&mut cursor));
    }
    count
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const PYTHON_SAMPLE: &str = r#"
from openai import OpenAI

client = OpenAI()

def summarize(record):
    return client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": record}],
    )
"#;

    #[test]
    fn parses_python_and_reports_a_plausible_node_count() {
        let parsed = parse("services/customer.py", PYTHON_SAMPLE).unwrap();
        assert_eq!(parsed.language(), Language::Python);
        assert!(!parsed.is_partial());
        assert_eq!(parsed.root_node().kind(), "module");
        // The exact number is grammar dependent, so the assertion is a range: it
        // catches an empty or truncated tree without breaking on a grammar bump.
        let nodes = parsed.node_count();
        assert!(nodes > 40, "expected a populated tree, got {nodes} nodes");
    }

    #[test]
    fn broken_source_yields_a_tree_and_is_marked_partial() {
        // The point of the test: this must not be an Err, and it must not be
        // silently treated as a clean parse either.
        let parsed = parse("broken.py", "def f(:\n    return ???\n").unwrap();
        assert!(parsed.is_partial());
        assert!(parsed.error_node_count() > 0);
        assert_eq!(
            parsed.coverage_reason(),
            Some(UnparsedReason::PartialParse),
            "a partially read file has to reach the coverage statement"
        );
    }

    #[test]
    fn clean_source_contributes_no_coverage_entry() {
        let parsed = parse("ok.py", "x = 1\n").unwrap();
        assert_eq!(parsed.coverage_reason(), None);
    }

    #[test]
    fn unknown_extension_is_a_typed_error_not_a_panic() {
        let failure = parse("README.md", "# title").unwrap_err();
        assert_eq!(failure, ParseFailure::NoGrammar);
        assert_eq!(failure.coverage_reason(), UnparsedReason::NoGrammar);
    }

    #[test]
    fn empty_source_parses_without_error() {
        let parsed = parse("empty.py", "").unwrap();
        assert!(!parsed.is_partial());
        assert_eq!(parsed.node_count(), 1);
    }

    #[test]
    fn typescript_and_tsx_both_parse_jsx_bearing_source() {
        let jsx = "const a = <div>{value}</div>;\n";
        let as_tsx = parse_as("view.tsx", jsx, Language::Tsx).unwrap();
        assert!(!as_tsx.is_partial());

        // Same bytes through the plain TypeScript grammar: the JSX is not
        // understood. This is exactly the silent corruption the grammar split
        // exists to prevent, so it is pinned by a test.
        let as_ts = parse_as("view.ts", jsx, Language::TypeScript).unwrap();
        assert!(as_ts.is_partial());
    }

    #[test]
    fn javascript_parses_module_syntax() {
        let parsed = parse("client.mjs", "import OpenAI from 'openai';\n").unwrap();
        assert_eq!(parsed.language(), Language::JavaScript);
        assert!(!parsed.is_partial());
    }

    #[test]
    fn source_is_retained_for_later_stages() {
        let parsed = parse("x.py", "y = 2\n").unwrap();
        assert_eq!(parsed.source(), "y = 2\n");
        assert_eq!(parsed.path(), Path::new("x.py"));
    }
}
