//! Import resolution for TypeScript and JavaScript.
//!
//! Same job as the Python side, different surface. JavaScript has three ways to
//! bring a package in and they bind different things: a default import takes
//! whatever the module exports as default, a named import takes one symbol, and
//! `require` hands back the module object itself. A resolver that treats them
//! alike will accept a call it should reject.
//!
//! Instantiation is also spelled differently. `new OpenAI()` is a distinct node
//! from an ordinary call, so following it needs its own branch rather than
//! falling out of the call handling for free.

use tree_sitter::Node;

use crate::engine::bindings::BindingTable;

/// Builds the binding table for one parsed TypeScript or JavaScript file.
pub fn collect(root: Node<'_>, source: &str) -> BindingTable {
    let mut table = BindingTable::default();
    let mut cursor = root.walk();

    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "import_statement" => collect_import(node, source, &mut table),
            "lexical_declaration" | "variable_declaration" => {
                collect_declaration(node, source, &mut table)
            }
            _ => {}
        }
        stack.extend(node.children(&mut cursor));
    }

    // Instantiations are collected in a second pass so that the imports they
    // depend on are already known regardless of source order.
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "lexical_declaration" | "variable_declaration") {
            collect_instantiation(node, source, &mut table);
        }
        stack.extend(node.children(&mut cursor));
    }

    table.finish();
    table
}

/// `import OpenAI from 'openai'` and `import { OpenAI } from 'openai'`.
fn collect_import(node: Node<'_>, source: &str, table: &mut BindingTable) {
    let Some(source_node) = node.child_by_field_name("source") else {
        return;
    };
    let module = string_literal_text(source_node, source);
    table.record_module(&module);

    let mut cursor = node.walk();
    let mut stack: Vec<Node<'_>> = node.children(&mut cursor).collect();
    let mut inner = node.walk();

    while let Some(child) = stack.pop() {
        match child.kind() {
            // `import OpenAI from 'openai'`: the default export.
            "identifier" => {
                let local = text(child, source);
                table.bind(local, format!("{module}.default"));
            }
            // `import { OpenAI as Client } from 'openai'`
            "import_specifier" => {
                let Some(name) = child.child_by_field_name("name") else {
                    continue;
                };
                let symbol = text(name, source);
                let local = child
                    .child_by_field_name("alias")
                    .map(|a| text(a, source))
                    .unwrap_or_else(|| symbol.clone());
                table.bind(local, format!("{module}.{symbol}"));
            }
            // `import * as openai from 'openai'`
            "namespace_import" => {
                if let Some(name) = child
                    .children(&mut inner)
                    .find(|n| n.kind() == "identifier")
                {
                    table.bind(text(name, source), module.clone());
                }
            }
            _ => {
                stack.extend(child.children(&mut inner));
            }
        }
    }
}

/// `const OpenAI = require('openai')`
///
/// require yields the module object, so the bound path is the module itself.
/// Binding it straight to `module.default` here would let a named export check
/// pass on something that never went through one; the default export reading is
/// applied later, and only where the value is actually used as a constructor.
fn collect_declaration(node: Node<'_>, source: &str, table: &mut BindingTable) {
    for (name, value) in declarators(node) {
        if value.kind() != "call_expression" {
            continue;
        }
        let Some(function) = value.child_by_field_name("function") else {
            continue;
        };
        if text(function, source) != "require" {
            continue;
        }
        let Some(args) = value.child_by_field_name("arguments") else {
            continue;
        };
        let mut cursor = args.walk();
        let Some(literal) = args.children(&mut cursor).find(|n| n.kind() == "string") else {
            continue;
        };
        let module = string_literal_text(literal, source);
        table.record_module(&module);
        table.bind(text(name, source), module);
    }
}

/// `const client = new OpenAI()` and `const client = new genai.Client()`.
fn collect_instantiation(node: Node<'_>, source: &str, table: &mut BindingTable) {
    for (name, value) in declarators(node) {
        if value.kind() != "new_expression" {
            continue;
        }
        let Some(constructor) = value.child_by_field_name("constructor") else {
            continue;
        };
        let resolved = match constructor.kind() {
            "identifier" => table
                .resolve(&text(constructor, source))
                .map(|path| as_constructed(path, table)),
            "member_expression" => {
                let (Some(object), Some(property)) = (
                    constructor.child_by_field_name("object"),
                    constructor.child_by_field_name("property"),
                ) else {
                    continue;
                };
                table
                    .resolve(&text(object, source))
                    .map(|base| format!("{base}.{}", text(property, source)))
            }
            _ => None,
        };
        if let Some(path) = resolved {
            table.bind(text(name, source), path);
        }
    }
}

/// Interprets a resolved path that is being used as a constructor.
///
/// `require` hands back the module object, so a name bound that way resolves to
/// a bare module path. Applying `new` to it means the module object is itself the
/// constructor, which in package terms is the default export. Without this step a
/// CommonJS import would resolve to the module and then fail a rule that asks for
/// the default export, even though the two describe the same value.
fn as_constructed(path: &str, table: &BindingTable) -> String {
    let is_bare_module = table.imported_modules().iter().any(|m| m == path);
    if is_bare_module {
        format!("{path}.default")
    } else {
        path.to_owned()
    }
}

/// Name and initialiser of every declarator in a declaration.
fn declarators<'t>(node: Node<'t>) -> Vec<(Node<'t>, Node<'t>)> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .filter(|c| c.kind() == "variable_declarator")
        .filter_map(|d| {
            let name = d.child_by_field_name("name")?;
            let value = d.child_by_field_name("value")?;
            (name.kind() == "identifier").then_some((name, value))
        })
        .collect()
}

/// Strips the surrounding quotes from a string literal node.
fn string_literal_text(node: Node<'_>, source: &str) -> String {
    text(node, source)
        .trim_matches(|c| c == '\'' || c == '"' || c == '`')
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

    fn table_for(source: &str, language: Language) -> BindingTable {
        let parsed = parse_as("t.ts", source, language).unwrap();
        collect(parsed.root_node(), parsed.source())
    }

    #[test]
    fn default_import_binds_the_default_export() {
        let t = table_for("import OpenAI from 'openai';\n", Language::TypeScript);
        assert_eq!(t.resolve("OpenAI"), Some("openai.default"));
    }

    #[test]
    fn named_import_binds_the_symbol() {
        let t = table_for("import { OpenAI } from 'openai';\n", Language::TypeScript);
        assert_eq!(t.resolve("OpenAI"), Some("openai.OpenAI"));
    }

    #[test]
    fn aliased_named_import_binds_the_alias() {
        let t = table_for(
            "import { OpenAI as Client } from 'openai';\n",
            Language::TypeScript,
        );
        assert_eq!(t.resolve("Client"), Some("openai.OpenAI"));
        assert_eq!(t.resolve("OpenAI"), None);
    }

    #[test]
    fn new_expression_carries_the_package_forward() {
        let t = table_for(
            "import OpenAI from 'openai';\nconst client = new OpenAI();\n",
            Language::TypeScript,
        );
        assert!(t.satisfies("client", "openai", &["default".to_owned()]));
    }

    #[test]
    fn require_binds_the_module_and_new_reads_it_as_the_default_export() {
        let t = table_for(
            "const OpenAI = require('openai');\nconst client = new OpenAI();\n",
            Language::JavaScript,
        );
        // The name from require holds the module object.
        assert_eq!(t.resolve("OpenAI"), Some("openai"));
        // Constructing from it means the module object is the constructor, which
        // is what a package calls its default export. A rule asking for the
        // default export has to accept this.
        assert_eq!(t.resolve("client"), Some("openai.default"));
        assert!(t.satisfies("client", "openai", &["default".to_owned()]));
    }

    #[test]
    fn scoped_package_names_survive_intact() {
        // The Anthropic SDK ships under a scoped name; splitting on the slash
        // would leave a module nothing matches.
        let t = table_for(
            "import Anthropic from '@anthropic-ai/sdk';\nconst c = new Anthropic();\n",
            Language::TypeScript,
        );
        assert!(t.satisfies("c", "@anthropic-ai/sdk", &["default".to_owned()]));
    }

    #[test]
    fn a_local_class_resolves_to_nothing() {
        let t = table_for(
            "class Store { create() {} }\nconst store = new Store();\n",
            Language::TypeScript,
        );
        assert!(!t.satisfies("store", "openai", &["default".to_owned()]));
    }

    #[test]
    fn tsx_source_resolves_the_same_way() {
        let t = table_for(
            "import OpenAI from 'openai';\nconst client = new OpenAI();\nconst v = <div/>;\n",
            Language::Tsx,
        );
        assert!(t.satisfies("client", "openai", &["default".to_owned()]));
    }

    #[test]
    fn namespace_import_binds_the_module() {
        let t = table_for("import * as openai from 'openai';\n", Language::TypeScript);
        assert_eq!(t.resolve("openai"), Some("openai"));
    }
}
