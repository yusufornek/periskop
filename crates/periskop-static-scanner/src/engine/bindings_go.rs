//! Import resolution for Go.
//!
//! The other resolvers read the local name straight out of the import statement.
//! Go usually does not write one: `import "github.com/openai/openai-go"` makes the
//! package available as `openai`, and that name comes from the package clause of
//! the imported package, which is neither in this file nor necessarily on this
//! machine. So the name has to be derived from the path by the convention the
//! ecosystem follows, and an alias, when present, overrides the derivation.
//!
//! A wrong derivation costs a missed call, never an invented one. The derived
//! name only matters if the file actually calls through it, and what the name
//! resolves to is still compared as a full module path, so a lookalike package
//! cannot slip in behind a name that happens to match.

use tree_sitter::Node;

use crate::engine::bindings::BindingTable;

/// Builds the binding table for one parsed Go file.
pub fn collect(root: Node<'_>, source: &str) -> BindingTable {
    let mut table = BindingTable::default();
    let mut cursor = root.walk();

    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "import_spec" {
            collect_import(node, source, &mut table);
        }
        stack.extend(node.children(&mut cursor));
    }

    // Constructors are collected in a second pass. Go puts imports at the top of
    // the file, but this walk pops nodes in its own order, so relying on source
    // order would make resolution depend on the shape of the tree.
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "short_var_declaration" | "assignment_statement" => {
                collect_pairs(node, source, &mut table);
            }
            "var_spec" => collect_var_spec(node, source, &mut table),
            _ => {}
        }
        stack.extend(node.children(&mut cursor));
    }

    table.finish();
    table
}

/// One entry of an import block, or the whole of a single line import.
///
/// Three name forms exist and only one of them binds anything. An alias names the
/// package outright. `_` imports for the side effect of the package's init, and
/// `.` drops the package's exported names into file scope, where following them
/// would mean knowing what the package exports. Both of the latter are recorded
/// for coverage and bound to nothing, because a binding invented here would hand
/// every rule a receiver that does not exist.
fn collect_import(node: Node<'_>, source: &str, table: &mut BindingTable) {
    let Some(path_node) = node.child_by_field_name("path") else {
        return;
    };
    let module = canonical_module(&unquote(path_node, source));
    table.record_module(&module);

    match node.child_by_field_name("name") {
        Some(name) if name.kind() == "package_identifier" => {
            table.bind_import(text(name, source), module);
        }
        Some(_) => {}
        None => table.bind_import(package_name(&module), module),
    }
}

/// The import path with a major version element removed.
///
/// `github.com/openai/openai-go/v2` and its v1 path name the same library; the
/// element identifies a module revision, not a package. Keeping it would force
/// every rule to enumerate the major versions of the library it describes, and
/// would split the coverage list, which answers "which library has no detector",
/// into one entry per release line.
fn canonical_module(module: &str) -> String {
    match module.rsplit_once('/') {
        Some((head, last)) if is_major_version(last) => head.to_owned(),
        _ => module.to_owned(),
    }
}

/// The identifier a package is reachable through when the file does not alias it.
///
/// Derived from the convention rather than read: a repository is named
/// `<package>-go`, `go-<package>` or `<package>-<qualifier>-go`, and the package
/// itself is the leading word of what remains.
fn package_name(module: &str) -> String {
    let segment = module.rsplit('/').next().unwrap_or(module);
    let stem = segment
        .strip_suffix("-go")
        .or_else(|| segment.strip_prefix("go-"))
        .unwrap_or(segment);
    stem.split(['-', '.']).next().unwrap_or(stem).to_owned()
}

fn is_major_version(segment: &str) -> bool {
    segment
        .strip_prefix('v')
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// `client := openai.NewClient()` and its plain assignment form.
///
/// Names and values are paired by position, and only when the two lists are the
/// same length. Go spreads one call over several names all the time, and pairing
/// `resp, err := client.Do(req)` positionally would bind `resp` to a value that
/// was never assigned to it.
fn collect_pairs(node: Node<'_>, source: &str, table: &mut BindingTable) {
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    bind_positionally(&named_children(left), &named_children(right), source, table);
}

/// `var client = openai.NewClient()`
fn collect_var_spec(node: Node<'_>, source: &str, table: &mut BindingTable) {
    let Some(values) = node.child_by_field_name("value") else {
        return;
    };
    let mut cursor = node.walk();
    let names: Vec<Node<'_>> = node.children_by_field_name("name", &mut cursor).collect();
    bind_positionally(&names, &named_children(values), source, table);
}

fn bind_positionally(
    names: &[Node<'_>],
    values: &[Node<'_>],
    source: &str,
    table: &mut BindingTable,
) {
    if names.len() != values.len() {
        return;
    }
    for (name, value) in names.iter().zip(values) {
        bind_constructed(*name, *value, source, table);
    }
}

/// Binds a name to the package of the constructor its value came from.
///
/// Only a package qualified call is followed. `openai.NewClient()` says which
/// package produced the value; a bare `newStore()` is a local function whose
/// return type is not written at the call site, and guessing at it is how a
/// scanner starts reporting a company's own client as a provider SDK.
fn bind_constructed(name: Node<'_>, value: Node<'_>, source: &str, table: &mut BindingTable) {
    if name.kind() != "identifier" || value.kind() != "call_expression" {
        return;
    }
    let Some(function) = value.child_by_field_name("function") else {
        return;
    };
    let (Some(operand), Some(field)) = (
        function.child_by_field_name("operand"),
        function.child_by_field_name("field"),
    ) else {
        return;
    };
    if operand.kind() != "identifier" {
        return;
    }
    let Some(module) = table.resolve(&text(operand, source)).map(str::to_owned) else {
        return;
    };
    table.bind_value(
        text(name, source),
        format!("{module}.{}", text(field, source)),
    );
}

fn named_children<'t>(node: Node<'t>) -> Vec<Node<'t>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

/// Strips the quotes from an import path literal.
fn unquote(node: Node<'_>, source: &str) -> String {
    text(node, source)
        .trim_matches(|c| c == '"' || c == '`')
        .to_owned()
}

fn text(node: Node<'_>, source: &str) -> String {
    source[node.byte_range()].to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::language::Language;
    use crate::parser::parse_as;

    fn table_for(source: &str) -> BindingTable {
        let parsed = parse_as("t.go", source, Language::Go).unwrap();
        collect(parsed.root_node(), parsed.source())
    }

    #[test]
    fn a_plain_import_binds_the_conventional_package_name() {
        let t = table_for("package main\n\nimport \"net/http\"\n");
        assert_eq!(t.resolve("http"), Some("net/http"));
    }

    #[test]
    fn the_go_affix_of_a_repository_name_is_not_part_of_the_package_name() {
        // Both spellings are in use for the same package name, and neither is
        // written anywhere in the importing file.
        let t = table_for(
            "package main\n\nimport (\n\t\"github.com/openai/openai-go\"\n)\n\nfunc f() { _ = openai.NewClient() }\n",
        );
        assert_eq!(t.resolve("openai"), Some("github.com/openai/openai-go"));

        let t = table_for("package main\n\nimport \"github.com/sashabaranov/go-openai\"\n");
        assert_eq!(
            t.resolve("openai"),
            Some("github.com/sashabaranov/go-openai")
        );
    }

    #[test]
    fn an_alias_wins_over_the_derived_name() {
        let t = table_for("package main\n\nimport oai \"github.com/openai/openai-go\"\n");
        assert_eq!(t.resolve("oai"), Some("github.com/openai/openai-go"));
        assert_eq!(t.resolve("openai"), None);
    }

    #[test]
    fn a_blank_import_records_the_module_and_binds_nothing() {
        let t = table_for("package main\n\nimport _ \"github.com/lib/pq\"\n");
        assert_eq!(t.imported_modules(), ["github.com/lib/pq"]);
        assert_eq!(t.resolve("pq"), None);
    }

    #[test]
    fn a_dot_import_binds_nothing_because_its_names_are_not_in_this_file() {
        let t = table_for("package main\n\nimport . \"github.com/onsi/gomega\"\n");
        assert_eq!(t.imported_modules(), ["github.com/onsi/gomega"]);
        assert_eq!(t.resolve("gomega"), None);
    }

    #[test]
    fn a_major_version_element_is_not_part_of_the_library_identity() {
        let t = table_for("package main\n\nimport \"github.com/go-resty/resty/v2\"\n");
        assert_eq!(t.resolve("resty"), Some("github.com/go-resty/resty"));
    }

    #[test]
    fn a_short_declaration_carries_the_package_forward() {
        let t = table_for(
            "package main\n\nimport \"github.com/openai/openai-go\"\n\nfunc f() {\n\tclient := openai.NewClient()\n}\n",
        );
        assert!(t.satisfies(
            "client",
            "github.com/openai/openai-go",
            &["NewClient".to_owned()]
        ));
    }

    #[test]
    fn a_var_declaration_carries_the_package_forward() {
        let t = table_for(
            "package main\n\nimport \"github.com/sashabaranov/go-openai\"\n\nvar client = openai.NewClient(\"token\")\n",
        );
        assert!(t.satisfies(
            "client",
            "github.com/sashabaranov/go-openai",
            &["NewClient".to_owned()]
        ));
    }

    #[test]
    fn a_multi_value_assignment_is_not_paired_by_position() {
        // One call, two names. Pairing them would bind `err` to the client.
        let t = table_for(
            "package main\n\nimport \"github.com/openai/openai-go\"\n\nfunc f() {\n\tresp, err := openai.NewClient()\n}\n",
        );
        assert_eq!(t.resolve("resp"), None);
        assert_eq!(t.resolve("err"), None);
    }

    #[test]
    fn a_local_constructor_resolves_to_nothing() {
        // The negative fixture case: an unqualified call gives no package away.
        let t = table_for(
            "package main\n\ntype store struct{}\n\nfunc newStore() *store { return &store{} }\n\nfunc f() {\n\ts := newStore()\n}\n",
        );
        assert_eq!(t.resolve("s"), None);
    }

    #[test]
    fn a_similarly_named_module_does_not_satisfy_the_rule() {
        // The derived name is identical; the module path is what decides.
        let t = table_for(
            "package main\n\nimport \"github.com/acme/openai-go\"\n\nfunc f() {\n\tclient := openai.NewClient()\n}\n",
        );
        assert!(!t.satisfies(
            "client",
            "github.com/openai/openai-go",
            &["NewClient".to_owned()]
        ));
    }

    #[test]
    fn a_parameter_is_not_resolved() {
        // Dependency injection, catalogued as a gap rather than guessed at.
        let t = table_for(
            "package main\n\nfunc send(client *openai.Client) {\n\tclient.Chat.Completions.New(ctx, params)\n}\n",
        );
        assert_eq!(t.resolve("client"), None);
    }

    #[test]
    fn imported_modules_are_listed_for_coverage() {
        let t = table_for(
            "package main\n\nimport (\n\t\"net/http\"\n\t\"github.com/openai/openai-go\"\n)\n",
        );
        assert_eq!(
            t.imported_modules(),
            ["github.com/openai/openai-go", "net/http"]
        );
    }
}
