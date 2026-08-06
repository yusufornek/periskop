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
//!
//! And it is written in three places, not one. A module level `const` is what a
//! script does; a class holds the client in a field, and the field is written
//! either as a class property or as an assignment to `this` in the constructor.
//! The two class spellings are different node kinds and neither falls out of the
//! declaration handling, so each needs its own branch. Skipping them meant
//! skipping the shape most application code is actually written in.

use tree_sitter::Node;

use crate::engine::bindings::{field_key, BindingTable, JS_THIS};

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
        for (key, value) in instantiation_targets(node, source) {
            bind_instantiation(key, value, source, &mut table);
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
                table.bind_import(local, format!("{module}.default"));
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
                table.bind_import(local, format!("{module}.{symbol}"));
            }
            // `import * as openai from 'openai'`
            "namespace_import" => {
                if let Some(name) = child
                    .children(&mut inner)
                    .find(|n| n.kind() == "identifier")
                {
                    table.bind_import(text(name, source), module.clone());
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
        // A value binding rather than an import one, even though what it carries
        // is a module. `require` sits in a declaration, so the name belongs to
        // whichever scope wrote it, and two scopes requiring different modules
        // into one name is the same collision an instantiation makes.
        table.bind_value(text(name, source), module);
    }
}

/// Every name this node assigns to, paired with the value it assigns.
///
/// Three shapes reach the same place. `const client = new OpenAI()` binds a local.
/// `client = new OpenAI()` written in a class body and `this.client = new OpenAI()`
/// written in a constructor both bind the same field, so both produce the same
/// qualified key and a call site does not have to know which spelling was used.
fn instantiation_targets<'t>(node: Node<'t>, source: &str) -> Vec<(String, Node<'t>)> {
    match node.kind() {
        "lexical_declaration" | "variable_declaration" => declarators(node)
            .into_iter()
            .map(|(name, value)| (text(name, source), value))
            .collect(),
        "public_field_definition" | "field_definition" => {
            class_field_target(node, source).into_iter().collect()
        }
        "assignment_expression" => this_field_target(node, source).into_iter().collect(),
        _ => Vec::new(),
    }
}

/// `class S { private client = new OpenAI(); }`
///
/// TypeScript calls the field's name `name` and JavaScript calls it `property`,
/// so both are tried. A resolver that knew only one of the two would keep seeing
/// class fields in one language and silently stop in the other.
fn class_field_target<'t>(node: Node<'t>, source: &str) -> Option<(String, Node<'t>)> {
    let name = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("property"))?;
    let value = node.child_by_field_name("value")?;
    Some((field_key(JS_THIS, &text(name, source)), value))
}

/// `this.client = new OpenAI()`, the constructor spelling of the same field.
///
/// Only `this` is followed. An assignment into any other object writes a field
/// whose readers reach it through a name this pass never sees, so binding it
/// would be a guess rather than one more resolution step.
fn this_field_target<'t>(node: Node<'t>, source: &str) -> Option<(String, Node<'t>)> {
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    if left.kind() != "member_expression" {
        return None;
    }
    // The grammar gives `this` a node kind of its own, named after the keyword.
    if left.child_by_field_name("object")?.kind() != "this" {
        return None;
    }
    let property = left.child_by_field_name("property")?;
    Some((field_key(JS_THIS, &text(property, source)), right))
}

/// Binds one name to what `new` on the right hand side constructs.
///
/// Anything other than a direct `new` is left unresolved. A value handed back by
/// a factory says nothing about which package built it, and guessing there would
/// put an unearned provider behind a confirmed finding.
fn bind_instantiation(key: String, value: Node<'_>, source: &str, table: &mut BindingTable) {
    if value.kind() != "new_expression" {
        return;
    }
    let Some(constructor) = value.child_by_field_name("constructor") else {
        return;
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
                return;
            };
            table
                .resolve(&text(object, source))
                .map(|base| format!("{base}.{}", text(property, source)))
        }
        _ => None,
    };
    if let Some(path) = resolved {
        table.bind_value(key, path);
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

    #[test]
    fn a_field_assigned_in_the_constructor_binds_under_this() {
        let t = table_for(
            "import OpenAI from 'openai';\n\
             class Summariser {\n  constructor() { this.client = new OpenAI(); }\n}\n",
            Language::TypeScript,
        );
        assert!(t.satisfies("this.client", "openai", &["default".to_owned()]));
    }

    #[test]
    fn a_class_property_binds_under_the_same_key_as_the_constructor_form() {
        // The two spellings are different node kinds and the same value. A call
        // site cannot tell them apart, so neither may the table.
        let t = table_for(
            "import OpenAI from 'openai';\n\
             class Summariser {\n  private client = new OpenAI();\n}\n",
            Language::TypeScript,
        );
        assert!(t.satisfies("this.client", "openai", &["default".to_owned()]));
    }

    #[test]
    fn a_javascript_class_field_binds_too() {
        // JavaScript names the field node differently from TypeScript, so this is
        // a separate branch rather than the same one seen twice.
        let t = table_for(
            "const OpenAI = require('openai');\n\
             class Summariser {\n  client = new OpenAI();\n}\n",
            Language::JavaScript,
        );
        assert!(t.satisfies("this.client", "openai", &["default".to_owned()]));
    }

    #[test]
    fn a_field_holding_a_local_class_resolves_to_nothing() {
        let t = table_for(
            "class Store {}\nclass S {\n  constructor() { this.client = new Store(); }\n}\n",
            Language::TypeScript,
        );
        assert!(!t.satisfies("this.client", "openai", &["default".to_owned()]));
    }

    #[test]
    fn a_field_on_another_object_is_not_bound() {
        // `ctx` may not even be owned by this file, and the call sites reading it
        // are reached through a name this pass never sees.
        let t = table_for(
            "import OpenAI from 'openai';\n\
             function boot(ctx) { ctx.client = new OpenAI(); }\n",
            Language::TypeScript,
        );
        assert_eq!(t.resolve("ctx.client"), None);
        assert_eq!(t.resolve("this.client"), None);
    }

    #[test]
    fn a_local_and_a_field_of_the_same_name_stay_apart() {
        let t = table_for(
            "import OpenAI from 'openai';\n\
             class Store {}\n\
             const client = new Store();\n\
             class S {\n  constructor() { this.client = new OpenAI(); }\n}\n",
            Language::TypeScript,
        );
        assert_eq!(t.resolve("client"), None);
        assert!(t.satisfies("this.client", "openai", &["default".to_owned()]));
    }
}
