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

use periskop_core::coverage::{UnresolvedReason, UnresolvedTarget};
use periskop_core::finding::{
    Component, Confidence, DeclaredTarget, Detector, EntityRef, Evidence, EvidenceType, Finding,
    Kind, Location, RefType, Span,
};
use periskop_core::ids::short_hash;
use streaming_iterator::StreamingIterator;

use crate::engine::{bindings, bindings_go, bindings_java, bindings_ts, BindingTable};
use crate::language::Language;
use crate::parser::ParsedFile;
use crate::rules::model::{
    Confidence as RuleConfidence, ExtractSpec, MatchKind, MatchSpec, RuleFile,
};
use crate::rules::CompiledRules;

/// Everything one scan of one file produced.
#[derive(Debug, Default)]
pub struct FileFindings {
    pub findings: Vec<Finding>,
    /// Modules the file imported that no rule claims. Feeds the coverage
    /// statement, so a library nobody wrote a detector for stays visible.
    pub unclaimed_imports: Vec<String>,
    /// Egress points whose destination a rule asked about and the engine could
    /// not pin down. Feeds `coverage.unresolved_targets`, which was empty in
    /// every report this engine had ever produced.
    pub unresolved_targets: Vec<UnresolvedTarget>,
    /// The engine disagreeing with itself: a compiled pattern with no rule, a
    /// rule with no such match, a field a rule declared that this grammar gives
    /// no way to read. These are not coverage; they belong in the report
    /// diagnostics block, and until now every one of them was a bare `continue`.
    pub engine_faults: Vec<String>,
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
    /// After any declared downgrade has been applied.
    confidence: Confidence,
    /// Set when a downgrade fired, so the coverage statement can say why.
    unresolved: Option<UnresolvedReason>,
    /// Where the code says this call goes, when a rule field named it and the
    /// value could be read. One of the two keys reconciliation joins on.
    declared_target: Option<DeclaredTarget>,
    /// What the code says this call invokes, spelled the way a runtime hook
    /// spells it. The other key reconciliation joins on.
    operation: Option<String>,
    rule: &'a RuleFile,
}

/// Runs the compiled rule set over one parsed file.
pub fn detect(parsed: &ParsedFile, compiled: &CompiledRules, rules: &[RuleFile]) -> FileFindings {
    let source = parsed.source();
    let table = collect_bindings(parsed);
    let constructors = constructor_arguments(parsed);
    let mut faults: Vec<String> = Vec::new();

    let mut sites: Vec<CallSite<'_>> = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut matches = cursor.matches(compiled.query(), parsed.root_node(), source.as_bytes());

    // Each of the three lookups below used to be a bare `continue`. All three
    // mean the engine contradicting itself, and all three dropped a real query
    // match, which is to say a possible egress call, without leaving a trace in
    // the findings, the coverage block or the diagnostics.
    while let Some(m) = matches.next() {
        let Some(origin) = compiled.origin(m.pattern_index) else {
            faults.push(format!(
                "compiled pattern {} has no rule of origin",
                m.pattern_index
            ));
            continue;
        };
        let Some(rule) = rules.iter().find(|r| r.rule_id == origin.rule_id) else {
            faults.push(format!(
                "compiled pattern names rule {:?}, which is not in the loaded set",
                origin.rule_id
            ));
            continue;
        };
        let Some(spec) = rule.matches.get(origin.match_index) else {
            faults.push(format!(
                "rule {:?} has no [[match]] at index {}",
                rule.rule_id, origin.match_index
            ));
            continue;
        };

        if let Some(site) = evaluate(
            parsed,
            compiled,
            m,
            rule,
            spec,
            origin.match_index,
            &table,
            &constructors,
            &mut faults,
        ) {
            sites.push(site);
        }
    }

    let built = findings_from(parsed, sites);
    faults.extend(built.faults);
    faults.sort();
    faults.dedup();

    let mut out = FileFindings {
        findings: built.findings,
        unclaimed_imports: unclaimed_imports(&table, rules, parsed.language()),
        unresolved_targets: built.unresolved_targets,
        engine_faults: faults,
    };

    // Sorted, not deduplicated. Uniqueness is established by the numbering in
    // `findings_from`, where a repeated match is recognised as one call site seen
    // twice. Dropping by identity here is what used to swallow the second call in
    // a file, and there is no longer a case it would catch.
    out.findings.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
    out.unresolved_targets.sort();
    out.unresolved_targets.dedup();
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
struct BuiltFindings {
    findings: Vec<Finding>,
    unresolved_targets: Vec<UnresolvedTarget>,
    faults: Vec<String>,
}

fn findings_from(parsed: &ParsedFile, mut sites: Vec<CallSite<'_>>) -> BuiltFindings {
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
    let mut built = BuiltFindings {
        findings: Vec::new(),
        unresolved_targets: Vec::new(),
        faults: Vec::new(),
    };
    for site in sites {
        let counter = occurrences
            .entry((site.enclosing_symbol.clone(), site.shape.clone()))
            .or_default();
        let occurrence = *counter;
        *counter += 1;

        let rule_id = site.rule.rule_id.clone();
        let unresolved = site.unresolved;
        match build_finding(parsed, site, occurrence) {
            Ok(finding) => {
                if let Some(reason) = unresolved {
                    // The finding stays. What weakens is the claim about where
                    // the call goes, and the coverage statement is where that is
                    // recorded rather than left for the reader to infer from a
                    // confidence value.
                    match finding.refs.first() {
                        Some(reference) => built.unresolved_targets.push(UnresolvedTarget {
                            egress_point_id: reference.ref_id.clone(),
                            reason,
                        }),
                        // Unreachable by construction: every finding is built with
                        // exactly one reference. Writing a placeholder identity
                        // the contract forbids would be worse than saying so.
                        None => built.faults.push(format!(
                            "rule {rule_id} produced a finding with no reference to record as an \
                             unresolved target"
                        )),
                    }
                }
                built.findings.push(finding);
            }
            // A detected call site that cannot be given a contract shaped
            // identity used to disappear through `.ok()?`. It is the one line in
            // the engine where a real egress call could be swallowed whole.
            Err(e) => built.faults.push(format!(
                "rule {rule_id} matched but the finding could not be built: {e}"
            )),
        }
    }
    built
}

#[allow(clippy::too_many_arguments)]
fn evaluate<'a>(
    parsed: &ParsedFile,
    compiled: &CompiledRules,
    m: &tree_sitter::QueryMatch<'_, '_>,
    rule: &'a RuleFile,
    spec: &MatchSpec,
    match_index: usize,
    table: &BindingTable,
    constructors: &ConstructorIndex<'_>,
    faults: &mut Vec<String>,
) -> Option<CallSite<'a>> {
    let source = parsed.source();
    let capture = |name: &str| capture_node(compiled, m, name);

    // Two ways to return nothing from here, and they are not the same event.
    //
    // A rule that looked at a match and said no is the rule working, and it stays
    // silent: the method was not one it names, or the receiver resolved to a
    // different library. A rule that matched and then could not be *evaluated* is
    // the engine failing, and it leaves an `INTERNAL` diagnostic naming the rule,
    // because from the report alone the two are indistinguishable and a possible
    // egress call is what sits between them.
    //
    // Why the second case is worth this much code. This tool exists to find the
    // places where a program sends data somewhere without saying so. An engine
    // that drops its own matches without saying so has no standing to report
    // that, and every `?` below used to do exactly that: no finding, no coverage
    // entry, no diagnostic, and a clean looking file. Defect AK-001 was three of
    // five Java fixtures lost that way for an entire phase.

    // Cheap check first.
    if let Some(method) = &spec.method {
        let Some(node) = capture(&method.capture) else {
            faults.push(format!(
                "rule {:?} [[match]] {match_index} names a method capture @{} that its own \
                 query does not produce, so the match was dropped without being judged",
                rule.rule_id, method.capture
            ));
            return None;
        };
        let called = source[node.byte_range()].to_owned();
        if !method.one_of.contains(&called) {
            return None;
        }
    }

    // Set when the receiver resolves through a name two value bindings in this
    // file disagreed about. Hoisted out of the block below because it survives
    // the binding check: the receiver did resolve, it just resolved to one of two
    // answers and the table cannot say which one this call site reads.
    let mut receiver_is_contested = false;

    // A binding that does not resolve is not a weaker finding. It means the
    // receiver came from somewhere else entirely, so there is nothing to report.
    if let Some(binding) = &spec.binding {
        let Some(node) = capture(&binding.capture) else {
            faults.push(format!(
                "rule {:?} [[match]] {match_index} names a binding capture @{} that its own \
                 query does not produce, so the match was dropped without being judged",
                rule.rule_id, binding.capture
            ));
            return None;
        };
        let Some(root) = bindings::root_identifier(node, source) else {
            faults.push(format!(
                "rule {:?} [[match]] {match_index} matched, but this engine cannot walk a \
                 {} receiver in {:?} source back to the name it starts from, so the binding \
                 was never checked and the match was dropped without being judged",
                rule.rule_id,
                node.kind(),
                compiled.language()
            ));
            return None;
        };
        if !table.satisfies(
            &root,
            &binding.resolves_to.module,
            &binding.resolves_to.symbol_path,
        ) {
            return None;
        }
        receiver_is_contested = table.is_contested(&root);
    }

    // No fallback to the file root. A query that captures neither anchor used to
    // produce a finding spanning the entire file, with the whole file in its
    // evidence hash, so an edit anywhere in it changed the report. The compiler
    // rejects such a rule now; this is the second line of defence and it names
    // the rule rather than inventing a location.
    let Some(anchor) = capture("call").or_else(|| capture("import")) else {
        faults.push(format!(
            "rule {:?} [[match]] {match_index} matched but captured neither @call nor @import, \
             so there is nothing to anchor a finding to",
            rule.rule_id
        ));
        return None;
    };

    let start = anchor.start_position();
    let end = anchor.end_position();
    let (confidence, unresolved) = classify(rule, m, compiled, source, constructors, faults);
    // Applied after the rule's own downgrades and independently of them, because
    // this is not something a rule can declare. The rule matched correctly: the
    // name it asked about does resolve into the package it named. What is in
    // doubt is whether the winning binding is the one this call site reads, and
    // only the table knows that. A rule that already declared `suspect` stays
    // there, and a reason a downgrade already recorded is not overwritten, since
    // the first one names a concrete field and this one names the receiver.
    let (confidence, unresolved) = if receiver_is_contested {
        (
            Confidence::Suspect,
            unresolved.or(Some(UnresolvedReason::UnsupportedPattern)),
        )
    } else {
        (confidence, unresolved)
    };

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
        confidence,
        unresolved,
        declared_target: declared_target(rule, m, compiled, source, constructors),
        operation: declared_operation(spec, m, compiled, source),
        rule,
    })
}

/// Rule fields whose value is a destination rather than a request detail.
///
/// Recognised by name because the rule schema has no way to say what a field
/// means: `[extract]` gives a key and a place to read it from, and nothing else.
/// Every rule set in the repository already uses exactly these two names, so the
/// convention is described here rather than invented. A rule that spells its
/// destination field something else loses the destination and keeps the finding,
/// which is the safe direction; the request for a declared role on `[extract]`
/// is filed against the rule schema owner in `hub/memory/interfaces.md`.
const DESTINATION_FIELDS: [&str; 2] = ["base_url", "target_url"];

/// Where the code says this call goes.
///
/// Resolution runs a second time here rather than being threaded out of
/// [`classify`], because the two ask different questions of the same node: the
/// downgrade logic needs to know whether a value was knowable at all, and this
/// needs the value. Sharing one pass would tie the destination to whichever
/// fields a rule happens to downgrade on.
///
/// A value the engine cannot read yields no destination. That is the same
/// absence as a rule that names no destination field, and both are honest: the
/// join then has nothing to compare rather than something invented.
fn declared_target(
    rule: &RuleFile,
    m: &tree_sitter::QueryMatch<'_, '_>,
    compiled: &CompiledRules,
    source: &str,
    constructors: &ConstructorIndex<'_>,
) -> Option<DeclaredTarget> {
    for field in DESTINATION_FIELDS {
        let Some(extract) = rule.extract.get(field) else {
            continue;
        };
        if let FieldResolution::Resolved(Some(written)) =
            resolve_field(extract, m, compiled, source, constructors)
        {
            return DeclaredTarget::parse(&written, None);
        }
    }
    None
}

/// What the code says this call invokes, in the spelling a hook would record.
///
/// The two sides have to agree or the join silently misses. A Python hook
/// wrapping the OpenAI SDK records `chat.completions.create`, which is the
/// attribute path below the client object plus the method; a hook wrapping an
/// HTTP client records `http.post`. Both are reproduced here from the syntax
/// tree, so the code side and the runtime side spell one call one way.
///
/// An import names no operation and gets none. Inventing one would let an import
/// match a call.
fn declared_operation(
    spec: &MatchSpec,
    m: &tree_sitter::QueryMatch<'_, '_>,
    compiled: &CompiledRules,
    source: &str,
) -> Option<String> {
    let method = spec
        .method
        .as_ref()
        .and_then(|method| capture_node(compiled, m, &method.capture))
        .and_then(|node| source.get(node.byte_range()))?;

    let operation = match spec.kind {
        MatchKind::Import => return None,
        // The hook's own normalisation, reproduced: `post` becomes `http.post`.
        MatchKind::HttpRequest => format!("http.{method}"),
        MatchKind::Call => match receiver_path(spec, m, compiled, source) {
            Some(path) => format!("{path}.{method}"),
            None => method.to_owned(),
        },
    };

    let operation = operation.to_ascii_lowercase();
    // The event contract fixes the spelling, and a value outside it can never
    // match anything. A subscript or a call in the receiver chain produces one,
    // and reporting it would put a string that looks like an operation into a
    // field nothing can join on.
    is_operation_spelling(&operation).then_some(operation)
}

/// The attribute path between the bound receiver and the method.
///
/// `client.chat.completions.create(...)` binds on `client` and captures
/// `client.chat.completions` as the receiver, so what is left is
/// `chat.completions`. The binding root is stripped rather than the first
/// segment, because `self.client.chat` resolves to the root `self.client` and
/// removing one segment would leave the object name in the operation.
fn receiver_path(
    spec: &MatchSpec,
    m: &tree_sitter::QueryMatch<'_, '_>,
    compiled: &CompiledRules,
    source: &str,
) -> Option<String> {
    let binding = spec.binding.as_ref()?;
    let node = capture_node(compiled, m, &binding.capture)?;
    let written = source.get(node.byte_range())?;
    let root = bindings::root_identifier(node, source)?;
    let path = written.strip_prefix(&root)?.trim_start_matches('.');
    (!path.is_empty()).then(|| path.to_owned())
}

/// Whether a value matches the operation pattern the event contract fixes.
fn is_operation_spelling(value: &str) -> bool {
    value.starts_with(|c: char| c.is_ascii_lowercase())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
}

/// Applies the rule's declared downgrades to one match.
///
/// The `[extract]` and `[[classify.downgrade]]` blocks were parsed, validated and
/// then read by nothing at all. Two consequences followed and both were invisible:
/// a call whose destination the scanner could not read was reported as `confirmed`
/// anyway, and `coverage.unresolved_targets` came back empty in every report the
/// tool had ever produced, so one of the three coverage promises the README makes
/// was never kept.
fn classify(
    rule: &RuleFile,
    m: &tree_sitter::QueryMatch<'_, '_>,
    compiled: &CompiledRules,
    source: &str,
    constructors: &ConstructorIndex<'_>,
    faults: &mut Vec<String>,
) -> (Confidence, Option<UnresolvedReason>) {
    let declared = match rule.classify.default_confidence {
        RuleConfidence::Confirmed => Confidence::Confirmed,
        RuleConfidence::Suspect => Confidence::Suspect,
    };

    for downgrade in &rule.classify.downgrade {
        let field = downgrade.when.trim_end_matches(".unresolved");
        // The loader rejects a downgrade whose field has no [extract] entry, so
        // a missing entry here is the engine disagreeing with the loader.
        let Some(extract) = rule.extract.get(field) else {
            faults.push(format!(
                "rule {:?} downgrades on {field:?}, which has no [extract] entry",
                rule.rule_id
            ));
            continue;
        };

        match resolve_field(extract, m, compiled, source, constructors) {
            FieldResolution::Resolved(_) => {}
            FieldResolution::Unresolved(reason) => {
                // A downgrade may only weaken. Written out rather than as an
                // ordering over the enum, because "weaker" is a property of this
                // rule and not of the order the two values happen to sit in.
                let weakened = match (declared, downgrade.to) {
                    (Confidence::Confirmed, RuleConfidence::Suspect) => Confidence::Suspect,
                    _ => declared,
                };
                return (weakened, Some(reason));
            }
            FieldResolution::NotEvaluable => faults.push(format!(
                "rule {:?} downgrades on {field:?}, which this engine cannot read for {:?} \
                 source; the finding keeps its declared confidence",
                rule.rule_id,
                compiled.language()
            )),
        }
    }

    (declared, None)
}

/// What the engine could say about one extracted field.
///
/// `Resolved` carries the text when there is text to carry. Two callers ask
/// different questions of the same answer: the downgrade logic only needs to
/// know whether the value was knowable, while the destination a finding reports
/// needs the value itself. Returning only the verdict is what used to make the
/// scanner read a base url and then throw it away.
#[derive(Debug, PartialEq, Eq)]
enum FieldResolution {
    /// A value the engine can see, or a keyword the caller left at its default.
    ///
    /// `None` is the default case: the caller passed nothing and the library
    /// decides the value. That is a determinate destination but not one this
    /// engine can name, and naming it anyway would put a guess in the report.
    Resolved(Option<String>),
    /// The engine looked and the value is not knowable from the syntax alone.
    Unresolved(UnresolvedReason),
    /// The engine has no way to look for this field in this grammar. Distinct
    /// from `Unresolved` on purpose: claiming a target is unresolved when
    /// nothing was examined would put a guess into the coverage statement.
    NotEvaluable,
}

fn resolve_field(
    extract: &ExtractSpec,
    m: &tree_sitter::QueryMatch<'_, '_>,
    compiled: &CompiledRules,
    source: &str,
    constructors: &ConstructorIndex<'_>,
) -> FieldResolution {
    let Some(node) = capture_node(compiled, m, &extract.from) else {
        // The rule named a capture its own query does not produce. The match
        // stands, but nothing can be said about the field.
        return FieldResolution::Unresolved(UnresolvedReason::UnsupportedPattern);
    };

    if let Some(keyword) = &extract.keyword {
        return keyword_resolution(node, keyword, source);
    }

    if let Some(keyword) = &extract.constructor_keyword {
        let Some(receiver) = bindings::root_identifier(node, source) else {
            return FieldResolution::NotEvaluable;
        };
        return match constructors.get(&receiver) {
            Some(arguments) => keyword_resolution(*arguments, keyword, source),
            // The construction site is somewhere this engine does not index:
            // another file, a factory, a builder chain, a grammar with no
            // collector. Nothing was read, so nothing is asserted.
            None => FieldResolution::NotEvaluable,
        };
    }

    literal_resolution(node, source)
}

/// Resolution of one keyword argument inside an argument list.
///
/// An absent keyword resolves. A caller who does not pass `base_url` gets the
/// library default, which is a determinate destination; treating that as
/// unresolved would downgrade every ordinary call in the corpus.
fn keyword_resolution(
    arguments: tree_sitter::Node<'_>,
    keyword: &str,
    source: &str,
) -> FieldResolution {
    match keyword_value(arguments, keyword, source) {
        Some(value) => literal_resolution(value, source),
        None => FieldResolution::Resolved(None),
    }
}

/// The value node bound to `keyword` inside an argument list, if it is there.
///
/// Both call vocabularies are handled: Python spells it `keyword_argument` with
/// `name` and `value` fields, and TypeScript passes an object literal whose
/// `pair` nodes carry `key` and `value`.
fn keyword_value<'t>(
    arguments: tree_sitter::Node<'t>,
    keyword: &str,
    source: &str,
) -> Option<tree_sitter::Node<'t>> {
    let mut cursor = arguments.walk();
    let mut stack: Vec<tree_sitter::Node<'t>> = vec![arguments];
    while let Some(node) = stack.pop() {
        let named = matches!(node.kind(), "keyword_argument" | "pair");
        if named {
            let name = node
                .child_by_field_name("name")
                .or_else(|| node.child_by_field_name("key"));
            let matches_keyword = name
                .and_then(|n| source.get(n.byte_range()))
                .map(|text| text.trim_matches(['"', '\''].as_slice()) == keyword)
                .unwrap_or(false);
            if matches_keyword {
                return node.child_by_field_name("value");
            }
        }
        // An object literal sits one level below the argument list, so the walk
        // descends rather than looking only at direct children.
        stack.extend(node.children(&mut cursor));
    }
    None
}

/// Whether a value node is something the scanner can read off the page.
fn literal_resolution(node: tree_sitter::Node<'_>, source: &str) -> FieldResolution {
    let text = || literal_text(node, source);
    match node.kind() {
        "string" | "integer" | "float" | "number" | "true" | "false" | "concatenated_string" => {
            FieldResolution::Resolved(text())
        }
        // A template with no substitution is still a literal.
        "template_string" if !source[node.byte_range()].contains("${") => {
            FieldResolution::Resolved(text())
        }
        _ => FieldResolution::Unresolved(unresolved_reason_for(node, source)),
    }
}

/// The value of a literal node, without the quoting the grammar kept.
///
/// A concatenated string is deliberately not joined back together. Its pieces
/// are separate nodes with quotes between them, and pasting the raw text would
/// produce a destination containing quote characters, which is worse than
/// reporting no destination at all.
fn literal_text(node: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    if node.kind() == "concatenated_string" {
        return None;
    }
    let raw = source.get(node.byte_range())?.trim();
    // Python raw and byte prefixes sit outside the quotes.
    let raw = raw.trim_start_matches(|c: char| c.is_ascii_alphabetic());
    let quote = raw.chars().next().filter(|c| "\"'`".contains(*c))?;
    let unquoted = raw.trim_matches(quote);
    (!unquoted.is_empty()).then(|| unquoted.to_owned())
}

/// Names the shape of a value the scanner could not read.
///
/// The distinction is what the reader acts on. An environment variable is a
/// deployment question; an arbitrary expression is a code question.
fn unresolved_reason_for(node: tree_sitter::Node<'_>, source: &str) -> UnresolvedReason {
    let text = source.get(node.byte_range()).unwrap_or_default();
    if text.contains("os.environ") || text.contains("getenv") || text.contains("process.env") {
        return UnresolvedReason::EnvVar;
    }
    match node.kind() {
        "identifier" | "attribute" | "member_expression" => UnresolvedReason::ConfigIndirection,
        _ => UnresolvedReason::DynamicExpression,
    }
}

/// Local name to the argument list of the constructor that produced it.
///
/// Separate from the binding table, which answers "what package is this" rather
/// than "what was it built with". Only the two call vocabularies this engine can
/// read are indexed; for the rest a field that lives on the constructor is
/// reported as not evaluable rather than guessed at.
type ConstructorIndex<'t> = BTreeMap<String, tree_sitter::Node<'t>>;

fn constructor_arguments(parsed: &ParsedFile) -> ConstructorIndex<'_> {
    let source = parsed.source();
    let mut index: BTreeMap<String, tree_sitter::Node<'_>> = BTreeMap::new();
    let root = parsed.root_node();
    let mut cursor = root.walk();
    let mut stack = vec![root];

    while let Some(node) = stack.pop() {
        let bound = match node.kind() {
            // Python: `client = OpenAI(base_url=...)`
            "assignment" => node
                .child_by_field_name("left")
                .filter(|left| left.kind() == "identifier")
                .zip(node.child_by_field_name("right")),
            // TypeScript and JavaScript: `const client = new OpenAI({...})`
            "variable_declarator" => node
                .child_by_field_name("name")
                .filter(|name| name.kind() == "identifier")
                .zip(node.child_by_field_name("value")),
            _ => None,
        };

        if let Some((name, value)) = bound {
            if let Some(arguments) = value.child_by_field_name("arguments") {
                if let Some(text) = source.get(name.byte_range()) {
                    index.insert(text.to_owned(), arguments);
                }
            }
        }
        stack.extend(node.children(&mut cursor));
    }
    index
}

fn build_finding(
    parsed: &ParsedFile,
    site: CallSite<'_>,
    occurrence: u32,
) -> periskop_core::Result<Finding> {
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

    let finding = Finding::new(
        Kind::DeclaredEgressPoint,
        site.confidence,
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
    )?;

    let mut finding = finding
        .with_egress_kind(site.rule.classify.egress_kind.clone())
        .with_location(Location {
            component: Component::StaticScanner,
            path: Some(path),
            span: Some(site.span),
            symbol: None,
        });

    // The two keys reconciliation joins on. Set only when the syntax tree said
    // so: an absent field means nothing was established, and the join then falls
    // to a weaker key instead of comparing against a value nobody wrote.
    if let Some(target) = site.declared_target {
        finding = finding.with_declared_target(target);
    }
    if let Some(operation) = site.operation {
        finding = finding.with_operation(operation);
    }

    // A finding the scanner could not pin a destination for says so in the
    // finding as well as in the coverage statement, so a reader working from one
    // finding alone still learns that the target claim is the weak part.
    Ok(match site.unresolved {
        Some(_) => {
            finding.with_coverage_impact(periskop_core::finding::CoverageImpact::UnresolvedTarget)
        }
        None => finding,
    })
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
fn unclaimed_imports(table: &BindingTable, rules: &[RuleFile], language: Language) -> Vec<String> {
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
        .filter(|module| !is_first_party(module))
        .filter(|module| !is_standard_library(module, language))
        .filter(|module| !known.iter().any(|k| covers(k, module)))
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Whether an import names the project's own code rather than a library.
///
/// The field this feeds is documented as libraries with no detector. A relative
/// import is not a library at all, and letting `.llm` or `./services/client` into
/// the list fills it with the project's own modules in any repository past a
/// handful of files, which buries the one entry that means something: a model
/// SDK nobody has written a rule for.
///
/// Only the relative forms are excluded. A first party package imported by its
/// absolute name is indistinguishable from a third party one without knowing the
/// project layout, and guessing would drop real libraries.
fn is_first_party(module: &str) -> bool {
    module.starts_with('.') || module.starts_with('/') || module.starts_with("#")
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
///
/// The language decides which list applies. Merging them meant a Python project
/// importing the real PyPI packages `path`, `events` or `stream` had them
/// recognised as Node built-ins and dropped, so "I have no detector for this"
/// went unsaid for exactly the third party packages the field exists to name.
fn is_standard_library(module: &str, language: Language) -> bool {
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

    match language {
        Language::Python => {
            let root = module.split('.').next().unwrap_or(module);
            PYTHON.contains(&root)
        }
        Language::TypeScript | Language::Tsx | Language::JavaScript => {
            let root = module.split('/').next().unwrap_or(module);
            NODE.contains(&root.strip_prefix("node:").unwrap_or(root))
        }
        // A Go standard library path has no dot in its first segment. Anything
        // with a dot there is a domain name, which means a third party module,
        // and treating net/http and github.com/x/net alike would hide a real
        // dependency.
        Language::Go => {
            let root = module.split('/').next().unwrap_or(module);
            !root.contains('.') && GO.contains(&root)
        }
        Language::Java => JAVA_PREFIXES
            .iter()
            .any(|p| module == *p || module.starts_with(&format!("{p}."))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_python_package_is_not_hidden_by_the_node_standard_library() {
        // The bug this pins: the two lists were consulted together, so a Python
        // project importing the real PyPI packages `path`, `events` or `stream`
        // had them recognised as Node built-ins and dropped. "I have no detector
        // for this" then went unsaid for exactly the packages the field is for.
        for module in ["path", "events", "stream", "crypto"] {
            assert!(
                !is_standard_library(module, Language::Python),
                "{module} is not in the Python standard library"
            );
            assert!(
                is_standard_library(module, Language::JavaScript),
                "{module} is a Node built-in"
            );
        }

        assert!(is_standard_library("os", Language::Python));
        assert!(!is_standard_library("os", Language::JavaScript));
        assert!(is_standard_library("net/http", Language::Go));
        assert!(!is_standard_library("github.com/x/net", Language::Go));
        assert!(is_standard_library("java.net.http", Language::Java));
    }

    #[test]
    fn an_operation_outside_the_event_spelling_is_refused_rather_than_reported() {
        // The join compares this field against what a hook wrote, and a hook
        // writes lower case dotted names by contract. A value that cannot match
        // anything would still look like an operation in the report, so it is
        // refused at the source instead.
        assert!(is_operation_spelling("chat.completions.create"));
        assert!(is_operation_spelling("http.post"));
        assert!(is_operation_spelling("generate_content"));
        for wrong in [
            "Chat.Completions.Create",
            "clients[\"a\"].chat.create",
            "",
            ".create",
            "3.create",
        ] {
            assert!(!is_operation_spelling(wrong), "{wrong:?}");
        }
    }

    #[test]
    fn a_relative_import_is_not_a_library_with_no_detector() {
        // The coverage field is documented as libraries nobody wrote a rule for.
        // Relative imports filled it with the project's own modules in any
        // repository past a handful of files, burying the one entry that means
        // something under names the reader already knows about.
        assert!(is_first_party(".llm"));
        assert!(is_first_party("..services.client"));
        assert!(is_first_party("./client"));
        assert!(!is_first_party("openai"));
        assert!(!is_first_party("myapp.services"));
    }
}
