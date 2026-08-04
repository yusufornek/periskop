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

use periskop_core::finding::{
    Component, Confidence, Detector, EntityRef, Evidence, EvidenceType, Finding, Kind, Location,
    RefType, Span,
};
use periskop_core::ids::short_hash;
use streaming_iterator::StreamingIterator;

use crate::engine::bindings::{self, BindingTable};
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

/// Runs the compiled rule set over one parsed file.
pub fn detect(parsed: &ParsedFile, compiled: &CompiledRules, rules: &[RuleFile]) -> FileFindings {
    let source = parsed.source();
    let table = bindings::collect_python(parsed.root_node(), source);

    let mut out = FileFindings::default();
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

        if let Some(finding) = evaluate(parsed, compiled, m, rule, spec, &table) {
            out.findings.push(finding);
        }
    }

    // Identical calls in one file collapse to one finding. The contract treats a
    // repeated identity as the same claim seen twice, not as two claims.
    out.findings.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
    out.findings.dedup_by(|a, b| a.finding_id == b.finding_id);

    out.unclaimed_imports = unclaimed_imports(&table, rules);
    out
}

fn evaluate(
    parsed: &ParsedFile,
    compiled: &CompiledRules,
    m: &tree_sitter::QueryMatch<'_, '_>,
    rule: &RuleFile,
    spec: &MatchSpec,
    table: &BindingTable,
) -> Option<Finding> {
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

    let shape = call_shape(source, spec, m, compiled);
    let path = parsed.path().to_string_lossy().replace('\\', "/");
    let egress_point_id = format!("ep_{}", short_hash("ep/v1", &[&path, &shape]));

    let confidence = match rule.classify.default_confidence {
        RuleConfidence::Confirmed => Confidence::Confirmed,
        RuleConfidence::Suspect => Confidence::Suspect,
    };

    let start = anchor.start_position();
    let end = anchor.end_position();

    let finding = Finding::new(
        Kind::DeclaredEgressPoint,
        confidence,
        rule.provider.clone(),
        EntityRef {
            ref_type: RefType::EgressPoint,
            ref_id: egress_point_id,
        },
        Evidence {
            evidence_type: EvidenceType::AstNode,
            r#ref: format!("{}@{}", anchor.kind(), path),
            hash: Some(
                blake3::hash(source[anchor.byte_range()].as_bytes())
                    .to_hex()
                    .to_string(),
            ),
        },
        Detector {
            component: Component::StaticScanner,
            rule_id: rule.rule_id.clone(),
            rule_version: rule.rule_version.clone(),
            rule_hash: rule.rule_hash.clone(),
        },
    )
    .ok()?;

    Some(
        finding
            .with_egress_kind(rule.classify.egress_kind.clone())
            .with_location(Location {
                component: Component::StaticScanner,
                path: Some(path),
                span: Some(Span {
                    // tree-sitter counts from zero; the contract counts from one.
                    start_line: start.row as u32 + 1,
                    start_col: start.column as u32 + 1,
                    end_line: end.row as u32 + 1,
                    end_col: end.column as u32 + 1,
                }),
                symbol: None,
            }),
    )
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
    let known: Vec<&str> = rules
        .iter()
        .flat_map(|r| r.matches.iter())
        .filter_map(|m| m.binding.as_ref())
        .map(|b| b.resolves_to.module.as_str())
        .collect();

    let mut out: Vec<String> = table
        .imported_modules()
        .iter()
        .filter(|module| {
            !known
                .iter()
                .any(|k| module.as_str() == *k || module.starts_with(&format!("{k}.")))
        })
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}
