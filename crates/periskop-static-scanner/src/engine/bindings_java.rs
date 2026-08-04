//! Import resolution for Java.
//!
//! Java writes down what Python leaves to be inferred. A declaration names its
//! own type, so the receiver of a call does not have to be reconstructed from
//! the value that was assigned to it, and a client arriving as a parameter is as
//! visible as one built in place. The resolver reads declared types first and
//! only follows a value when the source said `var` and left the type out.
//!
//! What Java does leave open is which package a name came from. Source says
//! `OpenAIClient`, never `com.openai.client.OpenAIClient`, and the package sits
//! in the import list at the top of the file. Everything below is that lookup:
//! imports build the map, declarations spend it.
//!
//! The reach is still one file and one step, as everywhere else in this engine.
//! Names are held in a single flat namespace, so two methods that use one
//! parameter name for two different types leave only the last one resolved. That
//! is a shallow reading, it is the same shallowness the other languages have,
//! and the response to it is a dropped finding rather than a guessed one.

use tree_sitter::Node;

use crate::engine::bindings::BindingTable;

/// Builds the binding table for one parsed Java file.
pub fn collect(root: Node<'_>, source: &str) -> BindingTable {
    let mut table = BindingTable::default();
    let mut wildcards: Vec<String> = Vec::new();
    let mut cursor = root.walk();

    // Imports are collected first because a declaration cannot be read until the
    // packages behind its type names are known.
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "import_declaration" {
            collect_import(node, source, &mut table, &mut wildcards);
        }
        stack.extend(node.children(&mut cursor));
    }

    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "local_variable_declaration" | "field_declaration" => {
                bind_declaration(node, source, &mut table, &wildcards);
            }
            "formal_parameter" => bind_parameter(node, source, &mut table, &wildcards),
            "method_invocation" => bind_qualified_receiver(node, source, &mut table),
            _ => {}
        }
        stack.extend(node.children(&mut cursor));
    }

    table.finish();
    table
}

/// `import com.openai.client.OpenAIClient;` and its wildcard and static forms.
///
/// Java binds the last segment: the file writes `OpenAIClient`, and the package
/// in front of it is the only thing that tells a class apart from a same named
/// class in another library.
fn collect_import(
    node: Node<'_>,
    source: &str,
    table: &mut BindingTable,
    wildcards: &mut Vec<String>,
) {
    let mut cursor = node.walk();
    let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
    let is_static = children.iter().any(|c| c.kind() == "static");
    let is_wildcard = children.iter().any(|c| c.kind() == "asterisk");

    let Some(path_node) = children
        .iter()
        .find(|c| matches!(c.kind(), "scoped_identifier" | "identifier"))
    else {
        return;
    };
    let path = text(*path_node, source);

    if is_wildcard {
        table.record_module(&path);
        // A static wildcard brings in the members of a class, not type names, so
        // it is recorded for coverage and kept out of the type candidates.
        if !is_static {
            wildcards.push(path);
        }
        return;
    }

    let Some((container, member)) = path.rsplit_once('.') else {
        // A single segment import comes from the default package; there is no
        // container to record.
        table.record_module(&path);
        return;
    };
    // The container of a plain import is a package and the container of a static
    // import is a class. Spelling alone cannot tell the two apart, and for
    // coverage it does not need to: both answer "which library did this file
    // reach for".
    table.record_module(container);
    table.bind(member.to_owned(), path);
}

/// `OpenAIClient client = ...`, and the field form of the same statement.
///
/// The declared type is taken first because it is the answer the language has
/// already written down. `var` is the one case where it is missing, and there
/// the root of the initialiser is followed instead: one step, to the type the
/// builder chain hangs off.
fn bind_declaration(node: Node<'_>, source: &str, table: &mut BindingTable, wildcards: &[String]) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let declared = type_name(type_node, source);

    let mut cursor = node.walk();
    let declarators: Vec<Node<'_>> = node
        .children(&mut cursor)
        .filter(|c| c.kind() == "variable_declarator")
        .collect();

    for declarator in declarators {
        let Some(name) = declarator.child_by_field_name("name") else {
            continue;
        };
        let resolved = declared
            .as_deref()
            .and_then(|declared| resolve_type_name(declared, table, wildcards))
            .or_else(|| {
                let value = declarator.child_by_field_name("value")?;
                let root = root_identifier(value, source)?;
                resolve_type_name(&root, table, wildcards)
            });
        if let Some(path) = resolved {
            table.bind(text(name, source), path);
        }
    }
}

/// `String summarize(OpenAIClient client, String record)`.
///
/// A client that arrives as a parameter is where the Python resolver has to give
/// up. Java does not have to: the type is part of the signature, so injected
/// clients resolve by the same lookup as constructed ones.
fn bind_parameter(node: Node<'_>, source: &str, table: &mut BindingTable, wildcards: &[String]) {
    let (Some(type_node), Some(name)) = (
        node.child_by_field_name("type"),
        node.child_by_field_name("name"),
    ) else {
        return;
    };
    let Some(declared) = type_name(type_node, source) else {
        return;
    };
    if let Some(path) = resolve_type_name(&declared, table, wildcards) {
        table.bind(text(name, source), path);
    }
}

/// `com.openai.client.okhttp.OpenAIOkHttpClient.builder()` written out in full.
///
/// A fully qualified receiver needs no import to be understood, because the path
/// is spelled at the call site. Binding it to itself is what lets one check
/// handle both spellings instead of two.
fn bind_qualified_receiver(node: Node<'_>, source: &str, table: &mut BindingTable) {
    let Some(object) = node.child_by_field_name("object") else {
        return;
    };
    let Some(path) = package_qualified_name(object, source) else {
        return;
    };
    if let Some((container, _)) = path.rsplit_once('.') {
        table.record_module(container);
    }
    table.bind(path.clone(), path);
}

/// Turns a type name as written into the path it came from.
///
/// An explicit import is exact. A wildcard is not: it says a package *may*
/// supply the name, not that it does. That weaker reading is only taken when a
/// single non platform wildcard is in scope, because with two the file itself no
/// longer says which one, and a resolver that picks anyway has started guessing.
/// It is also why every Java rule names the symbols it accepts instead of
/// trusting a package prefix on its own.
fn resolve_type_name(name: &str, table: &BindingTable, wildcards: &[String]) -> Option<String> {
    if let Some(path) = table.resolve(name) {
        return Some(path.to_owned());
    }
    // Already fully qualified. There is nothing left to look up.
    if name.contains('.') {
        return Some(name.to_owned());
    }
    let mut candidates = wildcards.iter().filter(|p| !is_platform_package(p));
    let package = candidates.next()?;
    candidates
        .next()
        .is_none()
        .then(|| format!("{package}.{name}"))
}

/// The name a receiver expression hangs off.
///
/// Three shapes arrive here. `client.chat().completions()` is a call chain and
/// walks down to `client`. `com.openai.client.OpenAIClient.builder()` is not a
/// chain of values but a package path, and there the whole dotted name is the
/// answer. `this.client` is a field reference, where the field name is what was
/// bound.
///
/// The shared resolver in `bindings` walks the Python and JavaScript node names
/// and stops at Java's, so the Java vocabulary is spelled out here. `detect`
/// calls the shared one for every language today; sending Java receivers through
/// this function is part of wiring the module in, and without it every bound
/// Java rule declines rather than resolving.
pub fn root_identifier(node: Node<'_>, source: &str) -> Option<String> {
    let mut current = node;
    loop {
        match current.kind() {
            "identifier" | "type_identifier" | "scoped_type_identifier" => {
                return Some(text(current, source))
            }
            "field_access" => {
                if let Some(qualified) = package_qualified_name(current, source) {
                    return Some(qualified);
                }
                let object = current.child_by_field_name("object")?;
                if object.kind() == "this" {
                    return current
                        .child_by_field_name("field")
                        .map(|field| text(field, source));
                }
                current = object;
            }
            "method_invocation" | "object_creation_expression" => {
                current = current
                    .child_by_field_name("object")
                    .or_else(|| current.child_by_field_name("type"))?;
            }
            "parenthesized_expression" => current = current.named_child(0)?,
            _ => return None,
        }
    }
}

/// The dotted text of a receiver that is a package path rather than a value.
///
/// `com.openai.client.OpenAIClient` and `order.customer.address` parse into the
/// same nested field accesses, and without a symbol table the only thing that
/// separates them is the naming convention every Java package follows: lowercase
/// package segments, then a capitalised type. Reading it wrong costs a binding
/// that fails to resolve, which drops a candidate rather than inventing one.
fn package_qualified_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "field_access" {
        return None;
    }
    let path = text(node, source);
    let segments: Vec<&str> = path.split('.').collect();
    if segments.len() < 2 {
        return None;
    }
    if !segments
        .iter()
        .all(|s| s.chars().all(|c| c.is_alphanumeric() || c == '_'))
    {
        return None;
    }
    let starts_with_package = segments
        .first()
        .is_some_and(|s| s.starts_with(|c: char| c.is_lowercase()));
    let ends_with_type = segments
        .last()
        .is_some_and(|s| s.starts_with(|c: char| c.is_uppercase()));
    (starts_with_package && ends_with_type).then_some(path)
}

/// The simple name of a declared type.
fn type_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "type_identifier" => {
            let name = text(node, source);
            // `var` is a declaration with the type left out. The value has to
            // answer instead, so nothing is reported from here.
            (name != "var").then_some(name)
        }
        "scoped_type_identifier" => Some(text(node, source)),
        // `HttpResponse<String>` names its type in the first child.
        "generic_type" => node.child(0).and_then(|child| type_name(child, source)),
        _ => None,
    }
}

/// Packages that ship with the platform.
///
/// A wildcard on one of these appears in a large share of Java files. Counting
/// it as a candidate would make the one wildcard that carries meaning ambiguous
/// in exactly the files that matter.
fn is_platform_package(package: &str) -> bool {
    let root = package.split('.').next().unwrap_or(package);
    matches!(root, "java" | "javax" | "jakarta")
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
        let parsed = parse_as("T.java", source, Language::Java).unwrap();
        collect(parsed.root_node(), parsed.source())
    }

    /// Wraps a statement in the class and method Java requires around it.
    fn in_method(body: &str) -> String {
        format!("class T {{\n  void f() {{\n    {body}\n  }}\n}}\n")
    }

    const OPENAI: &str = "com.openai.client.OpenAIClient";

    #[test]
    fn an_import_binds_the_last_segment() {
        let t = table_for("import com.openai.client.OpenAIClient;\n");
        assert_eq!(t.resolve("OpenAIClient"), Some(OPENAI));
    }

    #[test]
    fn an_import_records_its_package_for_coverage() {
        let t = table_for(
            "import com.openai.client.OpenAIClient;\nimport dev.langchain4j.model.chat.ChatModel;\n",
        );
        assert_eq!(
            t.imported_modules(),
            ["com.openai.client", "dev.langchain4j.model.chat"]
        );
    }

    #[test]
    fn a_declared_type_carries_the_package_forward() {
        let source = format!(
            "import com.openai.client.OpenAIClient;\nimport com.openai.client.okhttp.OpenAIOkHttpClient;\n{}",
            in_method("OpenAIClient client = OpenAIOkHttpClient.fromEnv();")
        );
        let t = table_for(&source);
        assert!(t.satisfies("client", "com.openai", &["OpenAIClient".to_owned()]));
    }

    #[test]
    fn var_falls_back_to_the_root_of_the_builder_chain() {
        // No declared type, so the only thing left is what the chain starts from.
        let source = format!(
            "import com.openai.client.okhttp.OpenAIOkHttpClient;\n{}",
            in_method("var client = OpenAIOkHttpClient.builder().apiKey(\"k\").build();")
        );
        let t = table_for(&source);
        assert_eq!(
            t.resolve("client"),
            Some("com.openai.client.okhttp.OpenAIOkHttpClient")
        );
        assert!(t.satisfies("client", "com.openai", &["OpenAIOkHttpClient".to_owned()]));
    }

    #[test]
    fn a_field_resolves_the_same_way_a_local_does() {
        // Where an enterprise codebase actually keeps its client.
        let t = table_for(
            "import com.openai.client.OpenAIClient;\nclass T {\n  private final OpenAIClient client = null;\n}\n",
        );
        assert!(t.satisfies("client", "com.openai", &["OpenAIClient".to_owned()]));
    }

    #[test]
    fn a_parameter_resolves_because_java_writes_the_type_down() {
        // The case Python has to give up on. An injected client is still typed.
        let t = table_for(
            "import com.anthropic.client.AnthropicClient;\nclass T {\n  void f(AnthropicClient client) {}\n}\n",
        );
        assert!(t.satisfies("client", "com.anthropic", &["AnthropicClient".to_owned()]));
    }

    #[test]
    fn a_single_wildcard_import_supplies_the_package() {
        let source = format!(
            "import java.util.*;\nimport com.openai.client.*;\n{}",
            in_method("OpenAIClient client = null;")
        );
        let t = table_for(&source);
        assert!(t.satisfies("client", "com.openai", &["OpenAIClient".to_owned()]));
    }

    #[test]
    fn two_wildcard_imports_leave_the_name_unresolved() {
        // The file no longer says which package supplied the name, so neither
        // does the table.
        let source = format!(
            "import com.openai.client.*;\nimport com.example.internal.*;\n{}",
            in_method("OpenAIClient client = null;")
        );
        let t = table_for(&source);
        assert_eq!(t.resolve("client"), None);
    }

    #[test]
    fn a_static_import_binds_the_member() {
        let t = table_for("import static com.openai.models.ChatModel.GPT_4O;\n");
        assert_eq!(
            t.resolve("GPT_4O"),
            Some("com.openai.models.ChatModel.GPT_4O")
        );
    }

    #[test]
    fn a_fully_qualified_receiver_needs_no_import() {
        let t = table_for(&in_method(
            "com.openai.client.okhttp.OpenAIOkHttpClient.builder().build();",
        ));
        assert!(t.satisfies(
            "com.openai.client.okhttp.OpenAIOkHttpClient",
            "com.openai",
            &["OpenAIOkHttpClient".to_owned()]
        ));
    }

    #[test]
    fn a_fully_qualified_declaration_resolves_without_a_lookup() {
        let t = table_for(&in_method("com.openai.client.OpenAIClient client = null;"));
        assert!(t.satisfies("client", "com.openai", &["OpenAIClient".to_owned()]));
    }

    #[test]
    fn a_similarly_named_package_does_not_satisfy_the_module() {
        // Prefix matching without segment awareness would accept this.
        let source = format!(
            "import com.openaimock.client.OpenAIClient;\n{}",
            in_method("OpenAIClient client = null;")
        );
        let t = table_for(&source);
        assert!(!t.satisfies("client", "com.openai", &["OpenAIClient".to_owned()]));
    }

    #[test]
    fn right_module_wrong_symbol_is_rejected() {
        let source = format!(
            "import com.openai.azure.AzureOpenAIClient;\n{}",
            in_method("AzureOpenAIClient client = null;")
        );
        let t = table_for(&source);
        assert!(!t.satisfies("client", "com.openai", &["OpenAIClient".to_owned()]));
        assert!(t.satisfies("client", "com.openai", &["AzureOpenAIClient".to_owned()]));
    }

    #[test]
    fn a_local_class_resolves_to_nothing() {
        // The negative fixture case: a class defined here, with a create method.
        let t = table_for(
            "class RecordStore {\n  Object create(Object o) { return o; }\n}\nclass T {\n  void f() {\n    RecordStore store = new RecordStore();\n    store.create(null);\n  }\n}\n",
        );
        assert!(!t.satisfies("store", "com.openai", &["OpenAIClient".to_owned()]));
    }

    #[test]
    fn a_call_chain_resolves_to_the_name_it_starts_from() {
        let source = in_method("client.chat().completions().create(params);");
        let parsed = parse_as("T.java", source.as_str(), Language::Java).unwrap();
        let receiver = find_receiver(parsed.root_node(), parsed.source(), "create").unwrap();
        assert_eq!(
            root_identifier(receiver, parsed.source()),
            Some("client".to_owned())
        );
    }

    #[test]
    fn a_field_of_this_resolves_to_the_field_name() {
        let source = in_method("this.client.messages().create(params);");
        let parsed = parse_as("T.java", source.as_str(), Language::Java).unwrap();
        let receiver = find_receiver(parsed.root_node(), parsed.source(), "create").unwrap();
        assert_eq!(
            root_identifier(receiver, parsed.source()),
            Some("client".to_owned())
        );
    }

    #[test]
    fn a_field_chain_is_not_mistaken_for_a_package_path() {
        // All lowercase segments, so it is a value being read, not a package.
        let source = in_method("order.customer.address.create(params);");
        let parsed = parse_as("T.java", source.as_str(), Language::Java).unwrap();
        let receiver = find_receiver(parsed.root_node(), parsed.source(), "create").unwrap();
        assert_eq!(
            root_identifier(receiver, parsed.source()),
            Some("order".to_owned())
        );
    }

    /// The receiver node of the first call to `method`.
    fn find_receiver<'t>(root: Node<'t>, source: &str, method: &str) -> Option<Node<'t>> {
        let mut cursor = root.walk();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "method_invocation" {
                let named = node
                    .child_by_field_name("name")
                    .map(|n| source[n.byte_range()].to_owned());
                if named.as_deref() == Some(method) {
                    return node.child_by_field_name("object");
                }
            }
            stack.extend(node.children(&mut cursor));
        }
        None
    }
}
