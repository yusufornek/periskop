//! Languages the scanner can parse, and how a path maps to one.
//!
//! A file whose extension is not listed here is not skipped quietly. It reaches
//! the coverage statement as `unknown_language`, which is the difference between
//! a tool that says "clean" and a tool that says "clean for what I could read".

use std::path::Path;

/// A grammar the scanner is built against.
///
/// TypeScript and TSX are separate grammars even though they share a rule family.
/// Parsing a `.tsx` file with the plain TypeScript grammar silently mangles the
/// JSX regions, so the distinction has to live at the grammar level rather than
/// being smoothed over at the rule level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Language {
    Python,
    TypeScript,
    Tsx,
    JavaScript,
    Go,
    Java,
}

impl Language {
    /// Stable identifier used in rule files, reports and coverage entries.
    ///
    /// TSX reports as `typescript` on purpose: it is a grammar variant, not a
    /// language of its own, and the coverage vocabulary has no `tsx` member.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::TypeScript | Self::Tsx => "typescript",
            Self::JavaScript => "javascript",
            Self::Go => "go",
            Self::Java => "java",
        }
    }

    /// The rule family this grammar draws detectors from.
    ///
    /// TypeScript and JavaScript share one family: the SDK call shapes are
    /// identical, and duplicating the rules would let the two copies drift.
    pub fn rule_family(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::TypeScript | Self::Tsx | Self::JavaScript => "typescript",
            Self::Go => "go",
            Self::Java => "java",
        }
    }

    pub fn grammar(self) -> tree_sitter::Language {
        match self {
            Self::Python => tree_sitter_python::LANGUAGE.into(),
            Self::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Self::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Self::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Self::Go => tree_sitter_go::LANGUAGE.into(),
            Self::Java => tree_sitter_java::LANGUAGE.into(),
        }
    }

    /// Resolves a path to a grammar, or `None` when the extension is not covered.
    ///
    /// Returning `None` rather than guessing is deliberate. A wrong grammar
    /// produces a tree full of error nodes and findings that look real, which is
    /// worse than admitting the file was not read.
    pub fn from_path(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?;
        Self::from_extension(ext)
    }

    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension {
            "py" | "pyi" => Some(Self::Python),
            "ts" | "mts" | "cts" => Some(Self::TypeScript),
            "tsx" => Some(Self::Tsx),
            "js" | "mjs" | "cjs" | "jsx" => Some(Self::JavaScript),
            "go" => Some(Self::Go),
            "java" => Some(Self::Java),
            _ => None,
        }
    }

    /// Every grammar the build links against, in a stable order.
    pub const ALL: [Language; 6] = [
        Language::Python,
        Language::TypeScript,
        Language::Tsx,
        Language::JavaScript,
        Language::Go,
        Language::Java,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn tsx_uses_its_own_grammar_but_reports_as_typescript() {
        assert_eq!(Language::from_extension("tsx"), Some(Language::Tsx));
        assert_ne!(Language::Tsx.grammar(), Language::TypeScript.grammar());
        assert_eq!(Language::Tsx.as_str(), "typescript");
    }

    #[test]
    fn typescript_and_javascript_share_a_rule_family() {
        assert_eq!(
            Language::JavaScript.rule_family(),
            Language::TypeScript.rule_family()
        );
        assert_ne!(
            Language::Python.rule_family(),
            Language::TypeScript.rule_family()
        );
    }

    #[test]
    fn unknown_extension_resolves_to_nothing() {
        assert_eq!(Language::from_path(&PathBuf::from("notes.md")), None);
        assert_eq!(Language::from_path(&PathBuf::from("Makefile")), None);
    }

    #[test]
    fn every_declared_grammar_loads() {
        // Guards against a grammar crate upgrade that renames or drops a language
        // constant. Without this the failure would only surface on the first file
        // of that type, deep inside a scan.
        for language in Language::ALL {
            let mut parser = tree_sitter::Parser::new();
            assert!(
                parser.set_language(&language.grammar()).is_ok(),
                "{language:?} grammar failed to load"
            );
        }
    }

    #[test]
    fn extensions_map_to_the_expected_grammar() {
        let cases = [
            ("py", Language::Python),
            ("pyi", Language::Python),
            ("ts", Language::TypeScript),
            ("mts", Language::TypeScript),
            ("tsx", Language::Tsx),
            ("js", Language::JavaScript),
            ("mjs", Language::JavaScript),
            ("cjs", Language::JavaScript),
            ("go", Language::Go),
            ("java", Language::Java),
        ];
        for (ext, expected) in cases {
            assert_eq!(Language::from_extension(ext), Some(expected), "{ext}");
        }
    }
}
