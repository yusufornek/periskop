//! Resolving a name to the package it came from.
//!
//! This is what separates a detection from a coincidence. A query can see that
//! something called `create` was invoked on something called `client`, and that
//! shape is shared by an enormous amount of unrelated code. Whether it is an
//! egress call depends on where `client` came from, which lives in the import
//! statements and the assignment above it.
//!
//! The resolution here is deliberately shallow. It follows imports, aliases and a
//! single assignment step inside one file. It does not cross files, and it does
//! not track a client passed in as a parameter. Those are real limits, they are
//! catalogued, and the honest response to them is a weaker confidence rather than
//! a confident guess.

use std::collections::BTreeMap;

use tree_sitter::Node;

/// Names visible in a file and the dotted paths they resolve to.
#[derive(Debug, Default, Clone)]
pub struct BindingTable {
    /// Local name to fully qualified path, for example `client` to `openai.OpenAI`.
    resolved: BTreeMap<String, String>,
    /// Modules the file imported, whether or not anything was bound from them.
    /// Used to report a library nobody has a detector for.
    imported_modules: Vec<String>,
}

impl BindingTable {
    pub fn resolve(&self, name: &str) -> Option<&str> {
        self.resolved.get(name).map(String::as_str)
    }

    pub fn imported_modules(&self) -> &[String] {
        &self.imported_modules
    }

    /// Whether `name` resolves into `module` and reaches one of `symbols`.
    ///
    /// Both halves matter. The module check rejects a same named class from
    /// somewhere else; the symbol check rejects a different class from the right
    /// package. An empty symbol list means the module alone is enough.
    pub fn satisfies(&self, name: &str, module: &str, symbols: &[String]) -> bool {
        let Some(path) = self.resolve(name) else {
            return false;
        };
        if !path_starts_with_module(path, module) {
            return false;
        }
        if symbols.is_empty() {
            return true;
        }
        let segments: Vec<&str> = path.split('.').collect();
        symbols.iter().any(|s| segments.contains(&s.as_str()))
    }
}

/// Segment aware prefix test, so `openai_helper` does not look like `openai`.
fn path_starts_with_module(path: &str, module: &str) -> bool {
    path == module
        || path
            .strip_prefix(module)
            .is_some_and(|rest| rest.starts_with('.'))
}

/// Builds the table for one parsed Python file.
pub fn collect_python(root: Node<'_>, source: &str) -> BindingTable {
    let mut table = BindingTable::default();
    let mut cursor = root.walk();
    let mut stack = vec![root];

    // Imports are collected first because an assignment can only be understood
    // once the names it refers to are known.
    while let Some(node) = stack.pop() {
        match node.kind() {
            "import_statement" => collect_import(node, source, &mut table),
            "import_from_statement" => collect_import_from(node, source, &mut table),
            _ => {}
        }
        stack.extend(node.children(&mut cursor));
    }

    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "assignment" {
            collect_assignment(node, source, &mut table);
        }
        stack.extend(node.children(&mut cursor));
    }

    table.imported_modules.sort();
    table.imported_modules.dedup();
    table
}

/// `import openai`, `import openai as oa`, `import a.b.c`
fn collect_import(node: Node<'_>, source: &str, table: &mut BindingTable) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "dotted_name" => {
                let path = text(child, source);
                // `import a.b.c` binds the root name, matching Python semantics.
                let local = path.split('.').next().unwrap_or(&path).to_owned();
                table.imported_modules.push(path.clone());
                table.resolved.insert(local, path);
            }
            "aliased_import" => {
                let (Some(name), Some(alias)) = (
                    child.child_by_field_name("name"),
                    child.child_by_field_name("alias"),
                ) else {
                    continue;
                };
                let path = text(name, source);
                table.imported_modules.push(path.clone());
                table.resolved.insert(text(alias, source), path);
            }
            _ => {}
        }
    }
}

/// `from openai import OpenAI`, `from google import genai`, with aliases.
///
/// The bound path is `module.symbol`. That is what makes `from google import genai`
/// followed by `genai.Client()` resolve to `google.genai.Client`, which is how the
/// unified Google SDK is actually imported.
fn collect_import_from(node: Node<'_>, source: &str, table: &mut BindingTable) {
    let Some(module_node) = node.child_by_field_name("module_name") else {
        return;
    };
    let module = text(module_node, source);
    table.imported_modules.push(module.clone());

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.id() == module_node.id() {
            continue;
        }
        match child.kind() {
            "dotted_name" => {
                let symbol = text(child, source);
                table
                    .resolved
                    .insert(symbol.clone(), format!("{module}.{symbol}"));
            }
            "aliased_import" => {
                let (Some(name), Some(alias)) = (
                    child.child_by_field_name("name"),
                    child.child_by_field_name("alias"),
                ) else {
                    continue;
                };
                let symbol = text(name, source);
                table
                    .resolved
                    .insert(text(alias, source), format!("{module}.{symbol}"));
            }
            _ => {}
        }
    }
}

/// One assignment step: `client = OpenAI()` or `client = genai.Client()`.
///
/// Only direct constructor calls are followed. A value returned from a factory or
/// arriving as a parameter is not resolved, and pretending otherwise would put a
/// guess behind a confirmed finding.
fn collect_assignment(node: Node<'_>, source: &str, table: &mut BindingTable) {
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    if left.kind() != "identifier" || right.kind() != "call" {
        return;
    }
    let Some(function) = right.child_by_field_name("function") else {
        return;
    };

    let constructed = match function.kind() {
        // `OpenAI()`
        "identifier" => table.resolve(&text(function, source)).map(str::to_owned),
        // `genai.Client()`
        "attribute" => {
            let (Some(object), Some(attribute)) = (
                function.child_by_field_name("object"),
                function.child_by_field_name("attribute"),
            ) else {
                return;
            };
            let Some(root) = root_identifier(object, source) else {
                return;
            };
            table
                .resolve(&root)
                .map(|base| format!("{base}.{}", text(attribute, source)))
        }
        _ => None,
    };

    if let Some(path) = constructed {
        table.resolved.insert(text(left, source), path);
    }
}

/// Leftmost identifier of an attribute chain: `a.b.c` yields `a`.
pub fn root_identifier(node: Node<'_>, source: &str) -> Option<String> {
    let mut current = node;
    loop {
        match current.kind() {
            "identifier" => return Some(text(current, source)),
            "attribute" | "call" => {
                current = current
                    .child_by_field_name("object")
                    .or_else(|| current.child_by_field_name("function"))?;
            }
            _ => return None,
        }
    }
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
        let parsed = parse_as("t.py", source, Language::Python).unwrap();
        collect_python(parsed.root_node(), parsed.source())
    }

    #[test]
    fn plain_import_binds_the_root_name() {
        let t = table_for("import openai\n");
        assert_eq!(t.resolve("openai"), Some("openai"));
    }

    #[test]
    fn aliased_import_binds_the_alias() {
        let t = table_for("import openai as oa\n");
        assert_eq!(t.resolve("oa"), Some("openai"));
        assert_eq!(t.resolve("openai"), None);
    }

    #[test]
    fn from_import_binds_module_and_symbol() {
        let t = table_for("from openai import OpenAI\n");
        assert_eq!(t.resolve("OpenAI"), Some("openai.OpenAI"));
    }

    #[test]
    fn constructor_assignment_carries_the_package_forward() {
        let t = table_for("from openai import OpenAI\nclient = OpenAI()\n");
        assert!(t.satisfies("client", "openai", &["OpenAI".to_owned()]));
    }

    #[test]
    fn nested_module_import_resolves_through_the_attribute() {
        // How the unified Google SDK is imported in practice.
        let t = table_for("from google import genai\nclient = genai.Client()\n");
        assert_eq!(t.resolve("client"), Some("google.genai.Client"));
        assert!(t.satisfies("client", "google.genai", &["Client".to_owned()]));
    }

    #[test]
    fn a_similarly_named_package_does_not_satisfy_the_module() {
        // Prefix matching without segment awareness would accept this.
        let t = table_for("from openai_helper import OpenAI\nclient = OpenAI()\n");
        assert!(!t.satisfies("client", "openai", &["OpenAI".to_owned()]));
    }

    #[test]
    fn right_module_wrong_symbol_is_rejected() {
        let t = table_for("from openai import AzureOpenAI\nclient = AzureOpenAI()\n");
        assert!(!t.satisfies("client", "openai", &["Anthropic".to_owned()]));
        assert!(t.satisfies("client", "openai", &["AzureOpenAI".to_owned()]));
    }

    #[test]
    fn an_unbound_name_satisfies_nothing() {
        // The negative fixture case: a local class with a create method.
        let t = table_for("class Store:\n    pass\n\nstore = Store()\n");
        assert!(!t.satisfies("store", "openai", &["OpenAI".to_owned()]));
    }

    #[test]
    fn a_parameter_is_not_resolved() {
        // Dependency injection. Catalogued as a gap rather than guessed at.
        let t = table_for("def send(client):\n    return client.chat.completions.create()\n");
        assert_eq!(t.resolve("client"), None);
    }

    #[test]
    fn imported_modules_are_listed_for_coverage() {
        let t = table_for("import openai\nfrom anthropic import Anthropic\n");
        assert_eq!(t.imported_modules(), ["anthropic", "openai"]);
    }
}
