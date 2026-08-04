//! Turning query matches into findings.
//!
//! A query match is a candidate, not a result. This is where the candidate is
//! tested against the constraints the rule declared, and only what survives
//! becomes a finding.
//!
//! The order of the checks matters. Method names are cheap to test and rule out
//! most candidates; binding resolution is the expensive part and runs last. More
//! importantly, a failed binding means "this is not that library" and drops the
//! candidate outright, while a failed field extraction means "this is that library
//! but I cannot see one detail" and only lowers confidence. Collapsing those two
//! into one behaviour would either hide real egress or fabricate it.
//!
//! Identity is decided here too, and it is decided last on purpose. Two calls to
//! the same method in one file are two call sites and owe the reader two findings,
//! so the identity has to separate them; but no identity may contain a line
//! number, or inserting a line at the top of a file would rewrite every identifier
//! in the report. What separates them instead is the scope the call sits in and,
//! within one scope, the order the calls appear in. Both survive an edit
//! elsewhere in the file, and neither can be read off a single match, which is
//! why matches are collected first and turned into findings afterwards.

use std::collections::BTreeMap;

use periskop_core::finding::{
    Component, Confidence, Detector, EntityRef, Evidence, EvidenceType, Finding, Kind, Location,
    RefType, Span,
};
use periskop_core::ids::short_hash;
use streaming_iterator::StreamingIterator;

use crate::engine::{bindings, bindings_go, bindings_java, bindings_ts, BindingTable};
use crate::language::Language;
use crate::parser::ParsedFile;
use crate::rules::model::{Confidence as RuleConfidence, MatchSpec, RuleFile};
use crate::rules::CompiledRules;

/// Everything one scan of one file produced.
#[derive(Debug, Default)]
pub struct FileFindings {
    pub findings: Vec<Finding>,
    /// Modules the file imported that no rule claims. Feeds the coverage
    /// statement, so a library nobody wrote a detector for stays visible.
    pub unclaimed_imports: Vec<String>,
}

/// Builds the binding table using the collector for the file's grammar.
fn collect_bindings(parsed: &ParsedFile) -> BindingTable {
    match parsed.language() {
        Language::Python => bindings::collect_python(parsed.root_node(), parsed.source()),
        Language::TypeScript | Language::Tsx | Language::JavaScript => {
            bindings_ts::collect(parsed.root_node(), parsed.source())
        }
        Language::Go => bindings_go::collect(parsed.root_node(), parsed.source()),
        Language::Java => bindings_java::collect(parsed.root_node(), parsed.source()),
    }
}

/// A match that survived every constraint, held until it can be given an identity.
///
/// Nothing here is a tree-sitter node. Everything a finding needs is copied out
/// while the match is still in hand, which keeps this collection free of the
/// borrow the query cursor holds and lets the call sites be reordered afterwards.
struct CallSite<'a> {
    /// Byte range of the anchor node. It orders the call sites and locates the
    /// evidence; it deliberately never reaches an identity.
    range: std::ops::Range<usize>,
    anchor_kind: &'static str,
    span: Span,
    enclosing_symbol: String,
    shape: String,
    rule: &'a RuleFile,
}

/// Runs the compiled rule set over one parsed file.
pub fn detect(parsed: &ParsedFile, compiled: &CompiledRules, rules: &[RuleFile]) -> FileFindings {
    let source = parsed.source();
    let table = collect_bindings(parsed);

    let mut sites: Vec<CallSite<'_>> = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut matches = cursor.matches(compiled.query(), parsed.root_node(), source.as_bytes());

    while let Some(m) = matches.next() {
        let Some(origin) = compiled.origin(m.pattern_index) else {
            continue;
        };
        let Some(rule) = rules.iter().find(|r| r.rule_id == origin.rule_id) else {
            continue;
        };
        let Some(spec) = rule.matches.get(origin.match_index) else {
            continue;
        };

        if let Some(site) = evaluate(parsed, compiled, m, rule, spec, &table) {
            sites.push(site);
        }
    }

    let mut out = FileFindings {
        findings: findings_from(parsed, sites),
        unclaimed_imports: unclaimed_imports(&table, rules),
    };

    // Sorted, not deduplicated. Uniqueness is established by the numbering in
    // `findings_from`, where a repeated match is recognised as one call site seen
    // twice. Dropping by identity here is what used to swallow the second call in
    // a file, and there is no longer a case it would catch.
    out.findings.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
    out
}

/// Turns surviving call sites into findings, giving each one an identity.
///
/// The numbering is what stops a second call from disappearing. Before it, the
/// egress point was hashed from the file path and the call shape alone, so two
/// `client.chat.completions.create(...)` calls in one file produced one identity,
/// deduplication dropped the second, and the dropped call reached no list and no
/// counter. The occurrence number is scoped to the enclosing symbol so that
/// editing one function does not renumber the calls in another.
fn findings_from(parsed: &ParsedFile, mut sites: Vec<CallSite<'_>>) -> Vec<Finding> {
    // Source order, not the order the query engine happened to yield matches in.
    // That order is not part of any contract, and occurrence numbers taken from it
    // would make identities depend on it.
    sites.sort_by(|a, b| {
        a.range
            .start
            .cmp(&b.range.start)
            .then_with(|| a.range.end.cmp(&b.range.end))
            .then_with(|| a.rule.rule_id.cmp(&b.rule.rule_id))
            .then_with(|| a.shape.cmp(&b.shape))
    });
    // One node matched twice by one rule in one shape is one call site seen twice.
    // Numbering those as two would inflate the report with a call the file does
    // not contain, which is the opposite of the loss this function fixes.
    sites.dedup_by(|a, b| {
        a.range == b.range && a.rule.rule_id == b.rule.rule_id && a.shape == b.shape
    });

    let mut occurrences: BTreeMap<(String, String), u32> = BTreeMap::new();
    let mut findings = Vec::new();
    for site in sites {
        let counter = occurrences
            .entry((site.enclosing_symbol.clone(), site.shape.clone()))
            .or_default();
        let occurrence = *counter;
        *counter += 1;
        if let Some(finding) = build_finding(parsed, site, occurrence) {
            findings.push(finding);
        }
    }
    findings
}

fn evaluate<'a>(
    parsed: &ParsedFile,
    compiled: &CompiledRules,
    m: &tree_sitter::QueryMatch<'_, '_>,
    rule: &'a RuleFile,
    spec: &MatchSpec,
    table: &BindingTable,
) -> Option<CallSite<'a>> {
    let source = parsed.source();
    let capture = |name: &str| capture_node(compiled, m, name);

    // Cheap check first.
    if let Some(method) = &spec.method {
        let node = capture(&method.capture)?;
        let called = source[node.byte_range()].to_owned();
        if !method.one_of.contains(&called) {
            return None;
        }
    }

    // A binding that does not resolve is not a weaker finding. It means the
    // receiver came from somewhere else entirely, so there is nothing to report.
    if let Some(binding) = &spec.binding {
        let node = capture(&binding.capture)?;
        let root = bindings::root_identifier(node, source)?;
        if !table.satisfies(
            &root,
            &binding.resolves_to.module,
            &binding.resolves_to.symbol_path,
        ) {
            return None;
        }
    }

    let anchor = capture("call")
        .or_else(|| capture("import"))
        .unwrap_or_else(|| parsed.root_node());

    let start = anchor.start_position();
    let end = anchor.end_position();

    Some(CallSite {
        range: anchor.byte_range(),
        anchor_kind: anchor.kind(),
        span: Span {
            // tree-sitter counts from zero; the contract counts from one.
            start_line: start.row as u32 + 1,
            start_col: start.column as u32 + 1,
            end_line: end.row as u32 + 1,
            end_col: end.column as u32 + 1,
        },
        enclosing_symbol: enclosing_symbol(anchor, source),
        shape: call_shape(source, spec, m, compiled),
        rule,
    })
}

fn build_finding(parsed: &ParsedFile, site: CallSite<'_>, occurrence: u32) -> Option<Finding> {
    let source = parsed.source();
    let path = parsed.path().to_string_lossy().replace('\\', "/");

    // The contract derives an egress point from the path, the enclosing symbol and
    // the shape of the call. The occurrence number is the tie breaker the contract
    // leaves open: without it, a scope that makes the same call twice would still
    // collapse to one identity.
    let occurrence = occurrence.to_string();
    let egress_point_id = format!(
        "ep_{}",
        short_hash(
            "ep/v1",
            &[&path, &site.enclosing_symbol, &site.shape, &occurrence],
        )
    );

    let confidence = match site.rule.classify.default_confidence {
        RuleConfidence::Confirmed => Confidence::Confirmed,
        RuleConfidence::Suspect => Confidence::Suspect,
    };

    let finding = Finding::new(
        Kind::DeclaredEgressPoint,
        confidence,
        site.rule.provider.clone(),
        EntityRef {
            ref_type: RefType::EgressPoint,
            ref_id: egress_point_id,
        },
        Evidence {
            evidence_type: EvidenceType::AstNode,
            r#ref: format!("{}@{}", site.anchor_kind, path),
            hash: Some(
                blake3::hash(source[site.range].as_bytes())
                    .to_hex()
                    .to_string(),
            ),
        },
        Detector {
            component: Component::StaticScanner,
            rule_id: site.rule.rule_id.clone(),
            rule_version: site.rule.rule_version.clone(),
            rule_hash: site.rule.rule_hash.clone(),
        },
    )
    .ok()?;

    Some(
        finding
            .with_egress_kind(site.rule.classify.egress_kind.clone())
            .with_location(Location {
                component: Component::StaticScanner,
                path: Some(path),
                span: Some(site.span),
                symbol: None,
            }),
    )
}

/// The dotted path of named definitions a node sits inside.
///
/// This is what tells two call sites in one file apart without putting a line
/// number into an identity. A function keeps its name when lines are inserted
/// above it, so the value survives an edit made elsewhere in the file; a line
/// number would not. An empty string means file scope, which is a scope like any
/// other rather than a missing value.
fn enclosing_symbol(node: tree_sitter::Node<'_>, source: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if names_a_scope(ancestor.kind()) {
            if let Some(name) = ancestor.child_by_field_name("name") {
                if let Some(text) = source.get(name.byte_range()) {
                    parts.push(text);
                }
            }
        }
        current = ancestor.parent();
    }
    parts.reverse();
    parts.join(".")
}

/// Whether a node kind names a scope a call can sit inside.
///
/// Only functions and types. A variable or a field also carries a name, and
/// including those would put an identifier back into an identity: renaming a
/// local would move every call in its initializer, which is the invariant the
/// call shape exists to protect.
///
/// The list is per grammar and deliberately short. A kind that is missing costs
/// an empty scope, and the occurrence number still separates the calls; a kind
/// that should not be here costs a broken diff. The bias is toward leaving things
/// out.
fn names_a_scope(kind: &str) -> bool {
    const SCOPES: &[&str] = &[
        // Python
        "function_definition",
        "class_definition",
        // TypeScript and JavaScript
        "function_declaration",
        "generator_function_declaration",
        "method_definition",
        "class_declaration",
        "abstract_class_declaration",
        // Go and Java share the two spellings below with the list above
        "method_declaration",
        "constructor_declaration",
        "interface_declaration",
        "enum_declaration",
        "record_declaration",
    ];
    SCOPES.contains(&kind)
}

/// A rename stable description of the call.
///
/// Identifiers are deliberately excluded. Renaming `client` to `c` must not
/// produce a different identity, so the shape is built from what the call resolves
/// to rather than from what it is spelled.
fn call_shape(
    source: &str,
    spec: &MatchSpec,
    m: &tree_sitter::QueryMatch<'_, '_>,
    compiled: &CompiledRules,
) -> String {
    let mut parts = vec![spec.kind.as_str().to_owned()];
    if let Some(method) = &spec.method {
        if let Some(node) = capture_node(compiled, m, &method.capture) {
            parts.push(source[node.byte_range()].to_owned());
        }
    }
    if let Some(binding) = &spec.binding {
        parts.push(binding.resolves_to.module.clone());
    }
    parts.join("/")
}

fn capture_node<'t>(
    compiled: &CompiledRules,
    m: &tree_sitter::QueryMatch<'t, 't>,
    name: &str,
) -> Option<tree_sitter::Node<'t>> {
    let index = compiled
        .query()
        .capture_names()
        .iter()
        .position(|n| *n == name)?;
    m.captures
        .iter()
        .find(|c| c.index as usize == index)
        .map(|c| c.node)
}

/// Imported modules that no loaded rule mentions.
///
/// Reported rather than ignored. "We have no detector for this" is a different
/// statement from "there is nothing here", and only the first one is honest.
fn unclaimed_imports(table: &BindingTable, rules: &[RuleFile]) -> Vec<String> {
    let mut known: Vec<&str> = rules
        .iter()
        .flat_map(|r| r.matches.iter())
        .filter_map(|m| m.binding.as_ref())
        .map(|b| b.resolves_to.module.as_str())
        .collect();
    known.extend(
        rules
            .iter()
            .flat_map(|r| r.covers_modules.iter().map(String::as_str)),
    );

    let mut out: Vec<String> = table
        .imported_modules()
        .iter()
        .filter(|module| !is_standard_library(module))
        .filter(|module| !known.iter().any(|k| covers(k, module)))
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Whether a rule claiming `known` accounts for an import of `module`.
///
/// Three relations count. An exact match, obviously. An import below a claimed
/// module, since claiming a package claims what is inside it. And an import
/// above one: `from google import genai` records the namespace package `google`
/// while the rule names `google.genai`, and treating those as unrelated would
/// report a package as undetected while its own rule sits right there.
fn covers(known: &str, module: &str) -> bool {
    module == known
        || module.starts_with(&format!("{known}."))
        || known.starts_with(&format!("{module}."))
}

/// Modules that ship with the language.
///
/// The coverage field is for third party packages nobody wrote a detector for.
/// Listing the standard library there would bury the one or two entries that
/// actually mean something under noise from every file that imports `os`.
///
/// The list is short on purpose. It covers what appears near egress code; a
/// missing entry costs one noisy line, while a wrong entry would hide a real
/// package, so the bias is toward leaving things out.
fn is_standard_library(module: &str) -> bool {
    const PYTHON: &[&str] = &[
        "abc",
        "argparse",
        "asyncio",
        "base64",
        "collections",
        "contextlib",
        "csv",
        "dataclasses",
        "datetime",
        "enum",
        "functools",
        "hashlib",
        "http",
        "io",
        "itertools",
        "json",
        "logging",
        "math",
        "os",
        "pathlib",
        "random",
        "re",
        "socket",
        "ssl",
        "string",
        "subprocess",
        "sys",
        "tempfile",
        "threading",
        "time",
        "typing",
        "urllib",
        "uuid",
        "warnings",
    ];
    const NODE: &[&str] = &[
        "assert",
        "buffer",
        "child_process",
        "crypto",
        "events",
        "fs",
        "http",
        "https",
        "net",
        "path",
        "process",
        "stream",
        "tls",
        "url",
        "util",
        "zlib",
    ];
    // Go and Java import their standard libraries by path rather than by a bare
    // name, so these are matched against the path root rather than the whole
    // module string.
    const GO: &[&str] = &[
        "bufio", "bytes", "context", "crypto", "encoding", "errors", "flag", "fmt", "io", "log",
        "math", "net", "os", "path", "regexp", "sort", "strconv", "strings", "sync", "time",
    ];
    const JAVA_PREFIXES: &[&str] = &["java", "javax", "jdk", "sun"];

    let dotted_root = module.split('.').next().unwrap_or(module);
    let bare = dotted_root.strip_prefix("node:").unwrap_or(dotted_root);
    if PYTHON.contains(&bare) || NODE.contains(&bare) {
        return true;
    }

    // A Go standard library path has no dot in its first segment. Anything with a
    // dot there is a domain name, which means a third party module, and treating
    // net/http and github.com/x/net alike would hide a real dependency.
    let slashed_root = module.split('/').next().unwrap_or(module);
    if !slashed_root.contains('.') && GO.contains(&slashed_root) {
        return true;
    }

    JAVA_PREFIXES
        .iter()
        .any(|p| module == *p || module.starts_with(&format!("{p}.")))
}
