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
//!
//! One assignment step means two spellings, not one. A client kept in a local is
//! the shape a small script has; a client kept in an instance field is the shape
//! almost every class has, and a resolver that only understood locals walked past
//! all of it. Field assignments are therefore tracked too, under a qualified key
//! (`self.client`, `this.client`) so that a field and a local of the same name
//! never answer for each other. The file boundary still holds: a field assigned
//! in another file or inherited from a base class is out of reach, and that
//! remains catalogued rather than guessed at.
//!
//! The table is one namespace per file, and that is where the last honest thing
//! it can say lives. Imports belong to the file, so a flat key is the right model
//! for them. A value binding does not: `self.client` written in one class and
//! `self.client` written in the class below it are two different names that
//! happen to be spelled alike, and a table with no scope to hang them on keeps
//! whichever it saw last. What follows from that is not a missed call, it is a
//! reported call carrying another vendor's name, at `confirmed`. Silence is
//! countable and a confident wrong answer is not, so the table remembers which
//! names two value bindings disagreed about and the engine refuses to state a
//! provider as fact for any receiver rooted at one.

use std::collections::{BTreeMap, BTreeSet};

use tree_sitter::Node;

use crate::engine::bindings_java;

/// The name a Python method uses for the instance it was called on.
///
/// Convention rather than syntax: the grammar sees an ordinary parameter. Keying
/// on the conventional spelling is what keeps the qualified key readable, and a
/// method that spells its receiver otherwise is a catalogued gap.
const PYTHON_SELF: &str = "self";

/// The JavaScript equivalent. Here the grammar does give it a node of its own,
/// which is why the two languages need different branches to reach the same key.
pub(crate) const JS_THIS: &str = "this";

/// The table key an instance field is stored under.
///
/// Qualified on purpose. A file can hold both a local named `client` and a field
/// named `client` that point at different packages, and a flat key would let one
/// answer for the other.
pub(crate) fn field_key(receiver: &str, field: &str) -> String {
    format!("{receiver}.{field}")
}

/// Names visible in a file and the dotted paths they resolve to.
#[derive(Debug, Default, Clone)]
pub struct BindingTable {
    /// Visible name to fully qualified path, for example `client` to
    /// `openai.OpenAI`. An instance field is keyed by its qualified spelling
    /// (`self.client`, `this.client`), which is also how a call site reaches it.
    resolved: BTreeMap<String, String>,
    /// Modules the file imported, whether or not anything was bound from them.
    /// Used to report a library nobody has a detector for.
    imported_modules: Vec<String>,
    /// Names that two value bindings in this file gave different paths.
    ///
    /// The entry survives even though `resolved` keeps only one of the paths,
    /// because the useful fact is not which one won: it is that the winner
    /// answers for call sites that never read it.
    contested: BTreeSet<String>,
    /// Modules a star import pulled names from without naming any of them.
    ///
    /// Kept apart from `imported_modules`, which answers "which libraries did
    /// this file reach for" and needs every import in it. This one answers a
    /// narrower question, "which package may have supplied a name nothing else
    /// bound", and only a star import can be an answer to it.
    ///
    /// A set rather than a list because the count is what decides the answer,
    /// and it is read during collection, before [`BindingTable::finish`] has a
    /// chance to normalise anything. `from x import *` written twice is one
    /// package, and a list would have made it look like two and resolved
    /// nothing.
    wildcard_modules: BTreeSet<String>,
    /// Names that resolved only by reading them off a star import.
    ///
    /// The path is a reading of the file rather than a statement in it, so a
    /// call site reached through one of these names is reported with a weaker
    /// claim. Recorded here rather than folded into `contested`: two value
    /// bindings disagreeing and one import declining to say are different
    /// facts, and a reader of a downgrade deserves the one that happened.
    speculative: BTreeSet<String>,
}

impl BindingTable {
    /// Binds a name an import introduced.
    ///
    /// Module scope is file scope in every grammar this engine parses, so the
    /// flat key is the correct model here and a second import writing the same
    /// name is not a disagreement about scope. `import a.b` and `import a.c`
    /// both bind the root `a` and neither is wrong about it.
    pub fn bind_import(&mut self, local: String, path: String) {
        self.resolved.insert(local, path);
    }

    /// Binds a name to the value an assignment, declaration or parameter gave it.
    ///
    /// Separate from [`Self::bind_import`] because this is the kind of binding a
    /// file wide table gets wrong. A value binding belongs to the function or
    /// class it was written in; this table has no scope to key it on, so two of
    /// them writing one name collapse into one entry. Recording the collision is
    /// what turns that from an invisible wrong answer into a stated limit.
    pub fn bind_value(&mut self, local: String, path: String) {
        if self.resolved.get(&local).is_some_and(|held| *held != path) {
            self.contested.insert(local.clone());
        }
        self.resolved.insert(local, path);
    }

    /// Whether more than one value binding wrote `name`, with different answers.
    ///
    /// A caller that resolves through a contested name got an answer this table
    /// cannot stand behind, and the only correct response is to weaken the claim
    /// and say so rather than to drop it: the call is real, its destination is
    /// one of two, and the reader needs both of those facts.
    pub fn is_contested(&self, name: &str) -> bool {
        self.contested.contains(name)
    }

    /// Records that the file imported a module, whether or not anything bound.
    pub fn record_module(&mut self, module: &str) {
        self.imported_modules.push(module.to_owned());
    }

    /// Records a star import: a module that may supply names this file uses.
    pub fn record_wildcard(&mut self, module: &str) {
        self.wildcard_modules.insert(module.to_owned());
    }

    /// Binds a name to a path only a star import could have supplied.
    ///
    /// Separate from [`Self::bind_import`] because the two carry different
    /// warrants. An import writes the name down; a star import says a package
    /// exports something and leaves the reader to assume this is it. Both bind,
    /// and only one of them is a fact the file states.
    pub fn bind_speculative(&mut self, local: String, path: String) {
        self.speculative.insert(local.clone());
        self.resolved.insert(local, path);
    }

    /// Whether `name` was resolved by reading it off a star import.
    pub fn is_speculative(&self, name: &str) -> bool {
        self.speculative.contains(name)
    }

    /// The single star import a name may be attributed to, if there is one.
    ///
    /// `None` when the file has no star import, and also when it has more than
    /// one: with two in scope the file itself no longer says which package a
    /// bare name came from, and a resolver that picks anyway has started
    /// guessing. This mirrors the rule `bindings_java` applies to Java's
    /// wildcard imports, for the same reason and with the same failure
    /// direction: no answer rather than a made up one.
    pub fn sole_wildcard(&self) -> Option<&str> {
        (self.wildcard_modules.len() == 1)
            .then(|| self.wildcard_modules.first().map(String::as_str))
            .flatten()
    }

    /// Normalises the module list. Called once collection is complete.
    pub fn finish(&mut self) {
        self.imported_modules.sort();
        self.imported_modules.dedup();
    }

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

    table.finish();
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
                table.record_module(&path);
                table.bind_import(local, path);
            }
            "aliased_import" => {
                let (Some(name), Some(alias)) = (
                    child.child_by_field_name("name"),
                    child.child_by_field_name("alias"),
                ) else {
                    continue;
                };
                let path = text(name, source);
                table.record_module(&path);
                table.bind_import(text(alias, source), path);
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
    table.record_module(&module);

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.id() == module_node.id() {
            continue;
        }
        match child.kind() {
            "dotted_name" => {
                let symbol = text(child, source);
                table.bind_import(symbol.clone(), format!("{module}.{symbol}"));
            }
            "aliased_import" => {
                let (Some(name), Some(alias)) = (
                    child.child_by_field_name("name"),
                    child.child_by_field_name("alias"),
                ) else {
                    continue;
                };
                let symbol = text(name, source);
                table.bind_import(text(alias, source), format!("{module}.{symbol}"));
            }
            // `from openai import *`. There is no name here to bind, which is
            // why this used to fall through every branch and leave the file
            // with a recorded module and nothing resolved. A rule claims the
            // module, so it stayed out of `undetected_libraries` as well: the
            // call was neither detected nor declared, and that combination is
            // the one this scanner exists to make impossible.
            "wildcard_import" => table.record_wildcard(&module),
            _ => {}
        }
    }
}

/// One assignment step: `client = OpenAI()`, `genai.Client()` or `self.client = OpenAI()`.
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
    let Some(target) = assignment_target(left, source) else {
        return;
    };
    if right.kind() != "call" {
        return;
    }
    let Some(function) = right.child_by_field_name("function") else {
        return;
    };

    let constructed = match function.kind() {
        // `OpenAI()`
        "identifier" => {
            let name = text(function, source);
            table
                .resolve(&name)
                .map(str::to_owned)
                // Nothing bound this name, so the last thing left that could
                // have supplied it is a star import. Attributed to it and
                // marked, so the finding is produced and the claim about where
                // the class came from is the part that weakens.
                .map(Constructed::Stated)
                .or_else(|| {
                    let module = table.sole_wildcard()?;
                    Some(Constructed::Assumed(format!("{module}.{name}")))
                })
        }
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
                .map(Constructed::Stated)
        }
        _ => None,
    };

    match constructed {
        Some(Constructed::Stated(path)) => table.bind_value(target, path),
        Some(Constructed::Assumed(path)) => table.bind_speculative(target, path),
        None => {}
    }
}

/// Where a constructor's package came from, which decides how strong the claim is.
enum Constructed {
    /// The file names the import the class came from.
    Stated(String),
    /// Only a star import could have supplied the name, so the package is read
    /// off the file rather than written in it.
    Assumed(String),
}

/// The table key an assignment target writes, if it is one this pass can key on.
///
/// A plain name is itself. `self.<field>` is the other case that matters, because
/// holding the client in an instance field is how a Python class is ordinarily
/// written and skipping it meant skipping the calls that read it.
///
/// Nothing else is a target. `other.field = OpenAI()` assigns into an object this
/// file may not own, and the call sites reading it are reached through a name
/// this pass never sees, so binding it would be a guess rather than a step.
fn assignment_target(left: Node<'_>, source: &str) -> Option<String> {
    match left.kind() {
        "identifier" => Some(text(left, source)),
        "attribute" => {
            let object = left.child_by_field_name("object")?;
            let attribute = left.child_by_field_name("attribute")?;
            let is_self = object.kind() == "identifier" && text(object, source) == PYTHON_SELF;
            is_self.then(|| field_key(PYTHON_SELF, &text(attribute, source)))
        }
        _ => None,
    }
}

/// The table key an attribute chain reads from: `a.b.c` yields `a`.
///
/// Node names differ per grammar, so every vocabulary the engine parses is listed
/// here. Python calls the node `attribute`, JavaScript calls it
/// `member_expression`, Java calls it `field_access` and reaches a method through
/// `method_invocation`. A resolver that only knows some of them stops resolving
/// in the rest, and the cost is not a weaker answer but no answer at all: the
/// caller cannot tell "this receiver is not that library" from "I could not read
/// this receiver", and only the first of those is a rejection.
///
/// Java is the language that made that distinction expensive. Its rules capture
/// the receiver as `object: (_) @recv`, so `client.chat().completions().create(p)`
/// arrives here as a `method_invocation`, fell into `_ => None`, and three of the
/// five Java fixtures produced nothing end to end (defect AK-001).
///
/// A chain rooted at the instance receiver yields the qualified field key instead
/// of the receiver itself. `self` and `this` name no value on their own, so
/// stopping at them resolved nothing and the whole field-held-client shape fell
/// through; the field directly attached to the receiver is what was bound, and it
/// is what has to be looked up.
pub fn root_identifier(node: Node<'_>, source: &str) -> Option<String> {
    let mut current = node;
    // The member stepped over most recently. Once the walk bottoms out at the
    // receiver, this holds the field being read, because each step overwrites it
    // and the last step is the one nearest the receiver.
    let mut field: Option<String> = None;
    loop {
        match current.kind() {
            "identifier" | "shorthand_property_identifier" => {
                let name = text(current, source);
                return match field {
                    Some(f) if name == PYTHON_SELF => Some(field_key(PYTHON_SELF, &f)),
                    _ => Some(name),
                };
            }
            // A bare `this` carries no binding, so a chain that stops there
            // resolves to nothing rather than to the enclosing object.
            "this" => return field.map(|f| field_key(JS_THIS, &f)),
            "attribute" | "member_expression" => {
                field = current
                    .child_by_field_name("attribute")
                    .or_else(|| current.child_by_field_name("property"))
                    .map(|n| text(n, source));
                current = current.child_by_field_name("object")?;
            }
            "call" | "call_expression" | "new_expression" | "parenthesized_expression" => {
                current = current.child_by_field_name("function")?;
            }
            // The Java vocabulary. Knowing the node names is only half of what
            // Java needs: a receiver may be a package path written out in full
            // (`com.openai.client.okhttp.OpenAIOkHttpClient.builder()`), and a
            // field of `this` is bound under its plain name rather than under a
            // qualified key the way Python and JavaScript fields are. Those rules
            // belong to the Java collector, so the walk hands the node over
            // instead of restating them here where the two copies would drift.
            "method_invocation"
            | "field_access"
            | "object_creation_expression"
            | "type_identifier"
            | "scoped_type_identifier" => return bindings_java::root_identifier(current, source),
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
    fn a_single_star_import_supplies_the_package_and_says_it_is_assuming() {
        // The defect this closes: the module was recorded, so a rule claimed it
        // and it never reached `undetected_libraries`, while the name resolved
        // to nothing and no finding was produced. Neither detected nor declared.
        let t = table_for("from openai import *\nclient = OpenAI()\n");
        assert!(t.satisfies("client", "openai", &["OpenAI".to_owned()]));
        assert!(t.is_speculative("client"));
        assert_eq!(t.imported_modules(), ["openai"]);
    }

    #[test]
    fn an_explicit_import_beats_a_star_import_and_stays_a_stated_fact() {
        let t =
            table_for("from openai import *\nfrom vendor.sdk import OpenAI\nclient = OpenAI()\n");
        assert_eq!(t.resolve("client"), Some("vendor.sdk.OpenAI"));
        assert!(!t.is_speculative("client"));
    }

    #[test]
    fn two_star_imports_leave_the_name_unresolved() {
        // With two in scope the file no longer says which package supplied the
        // name. Both modules are still recorded, so the coverage statement can
        // report what was reached for even though nothing bound.
        let t = table_for("from openai import *\nfrom anthropic import *\nclient = OpenAI()\n");
        assert_eq!(t.resolve("client"), None);
        assert_eq!(t.imported_modules(), ["anthropic", "openai"]);
    }

    #[test]
    fn the_same_star_import_twice_is_still_one_package() {
        let t = table_for("from openai import *\nfrom openai import *\nclient = OpenAI()\n");
        assert!(t.satisfies("client", "openai", &["OpenAI".to_owned()]));
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

    #[test]
    fn a_client_kept_in_an_instance_field_is_bound() {
        // The shape almost every Python class uses. Before this it resolved to
        // nothing, so a file making plain OpenAI calls reported no egress at all.
        let t = table_for(
            "from openai import OpenAI\n\
             class Summarizer:\n    def __init__(self):\n        self.client = OpenAI()\n",
        );
        assert!(t.satisfies("self.client", "openai", &["OpenAI".to_owned()]));
    }

    #[test]
    fn a_field_holding_a_local_class_resolves_to_nothing() {
        let t = table_for(
            "class Store:\n    pass\n\n\
             class S:\n    def __init__(self):\n        self.client = Store()\n",
        );
        assert!(!t.satisfies("self.client", "openai", &["OpenAI".to_owned()]));
    }

    #[test]
    fn a_field_on_another_object_is_not_bound() {
        // `ctx` may belong to a caller in another file, and nothing here can say
        // which name its call sites reach the field through.
        let t = table_for(
            "from openai import OpenAI\n\
             def boot(ctx):\n    ctx.client = OpenAI()\n",
        );
        assert_eq!(t.resolve("ctx.client"), None);
        assert_eq!(t.resolve("self.client"), None);
    }

    #[test]
    fn a_local_and_a_field_of_the_same_name_stay_apart() {
        let t = table_for(
            "from openai import OpenAI\n\
             class Store:\n    pass\n\n\
             client = Store()\n\
             class S:\n    def __init__(self):\n        self.client = OpenAI()\n",
        );
        assert_eq!(t.resolve("client"), None);
        assert!(t.satisfies("self.client", "openai", &["OpenAI".to_owned()]));
    }

    #[test]
    fn two_classes_writing_one_field_name_leave_it_contested() {
        // The flat namespace, seen from inside. One of the two paths is kept and
        // the other is gone; what this records is that the survivor is not the
        // only answer, which is the part a call site needs to be told.
        let t = table_for(
            "import anthropic\nimport openai\n\
             class A:\n    def __init__(self):\n        self.client = anthropic.Anthropic()\n\
             class B:\n    def __init__(self):\n        self.client = openai.OpenAI()\n",
        );
        assert!(t.is_contested("self.client"));
    }

    #[test]
    fn one_binding_is_never_contested() {
        let t = table_for("from openai import OpenAI\nclient = OpenAI()\n");
        assert!(!t.is_contested("client"));
        assert!(!t.is_contested("OpenAI"));
    }

    #[test]
    fn rebinding_a_name_to_the_same_path_is_not_a_disagreement() {
        // Two classes constructing the same client is the ordinary shape of a
        // service module. Nothing about it is ambiguous, and treating repetition
        // as conflict would weaken half the findings in such a file for nothing.
        let t = table_for(
            "from openai import OpenAI\n\
             class A:\n    def __init__(self):\n        self.client = OpenAI()\n\
             class B:\n    def __init__(self):\n        self.client = OpenAI()\n",
        );
        assert!(!t.is_contested("self.client"));
    }

    #[test]
    fn two_imports_writing_one_root_name_are_not_contested() {
        // `import a.b` and `import a.c` both bind the root `a`, and neither is
        // wrong about what `a` means. Module scope is file scope, so the flat key
        // is the right model here and the collision is an artefact of storing the
        // dotted path under the root rather than a disagreement in the source.
        let t = table_for("import openai.types\nimport openai.resources\n");
        assert!(!t.is_contested("openai"));
    }

    /// The receiver chain a call site hands to the resolver, resolved to a key.
    fn root_of(source: &str, language: Language) -> Option<String> {
        let parsed = parse_as("t", source, language).unwrap();
        // The expression statement at the end of the file is the call under test.
        let mut stack = vec![parsed.root_node()];
        let mut cursor = parsed.root_node().walk();
        let mut receiver = None;
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "attribute" | "member_expression") {
                let parent_is_call = node
                    .parent()
                    .is_some_and(|p| matches!(p.kind(), "call" | "call_expression"));
                if parent_is_call {
                    receiver = node.child_by_field_name("object");
                }
            }
            stack.extend(node.children(&mut cursor));
        }
        root_identifier(receiver?, parsed.source())
    }

    #[test]
    fn a_chain_rooted_at_self_resolves_to_the_field_key() {
        // What the call site actually reads. Stopping at `self` was what made the
        // field binding unreachable even once it existed.
        let key = root_of(
            "class S:\n    def run(self):\n        self.client.chat.completions.create(model='x')\n",
            Language::Python,
        );
        assert_eq!(key.as_deref(), Some("self.client"));
    }

    #[test]
    fn a_chain_rooted_at_this_resolves_to_the_field_key() {
        let key = root_of(
            "class S { run() { this.client.chat.completions.create({}); } }\n",
            Language::TypeScript,
        );
        assert_eq!(key.as_deref(), Some("this.client"));
    }

    #[test]
    fn an_ordinary_chain_still_resolves_to_its_leftmost_name() {
        let key = root_of(
            "client.chat.completions.create(model='x')\n",
            Language::Python,
        );
        assert_eq!(key.as_deref(), Some("client"));
    }

    /// The key the receiver of the first Java call to `method` resolves to.
    fn java_receiver_key(source: &str, method: &str) -> Option<String> {
        let parsed = parse_as("T.java", source, Language::Java).ok()?;
        let mut cursor = parsed.root_node().walk();
        let mut stack = vec![parsed.root_node()];
        while let Some(node) = stack.pop() {
            let named = (node.kind() == "method_invocation")
                .then(|| node.child_by_field_name("name"))
                .flatten()
                .map(|n| parsed.source()[n.byte_range()].to_owned());
            if named.as_deref() == Some(method) {
                let receiver = node.child_by_field_name("object")?;
                return root_identifier(receiver, parsed.source());
            }
            stack.extend(node.children(&mut cursor));
        }
        None
    }

    #[test]
    fn a_java_accessor_chain_resolves_through_the_shared_entry_point() {
        // Defect AK-001, pinned where it actually broke. `detect` calls this
        // function for every language, so a Java receiver that stops here stops
        // the whole detection; the Java collector's own tests never saw it
        // because they call the Java walker directly.
        let key = java_receiver_key(
            "class T {\n  void f(Object p) {\n    client.chat().completions().create(p);\n  }\n}\n",
            "create",
        );
        assert_eq!(key.as_deref(), Some("client"));
    }

    #[test]
    fn a_java_field_of_this_resolves_to_its_plain_name() {
        // Java diverges from JavaScript here and the divergence is not cosmetic:
        // the Java collector binds a field under its plain name, so returning the
        // qualified `this.client` would look resolved and match nothing.
        let key = java_receiver_key(
            "class T {\n  void f(Object p) {\n    this.client.messages().create(p);\n  }\n}\n",
            "create",
        );
        assert_eq!(key.as_deref(), Some("client"));
    }

    #[test]
    fn a_fully_qualified_java_receiver_keeps_its_package_path() {
        let key = java_receiver_key(
            "class T {\n  void f() {\n    com.openai.client.okhttp.OpenAIOkHttpClient.builder().build();\n  }\n}\n",
            "builder",
        );
        assert_eq!(
            key.as_deref(),
            Some("com.openai.client.okhttp.OpenAIOkHttpClient")
        );
    }
}
