//! Field scoped rules, and the two places masking is not allowed to go.
//!
//! # Narrowest scope wins, and it cannot be relaxed
//!
//! `proxy-policy.md` section 3 and `proxy/spec.md` section 8 write the same
//! sentence twice:
//!
//! > En dar kapsam kazanır: `messages[0].content` > `messages[*].content` >
//! > global. Eşit darlıkta **`block` > `mask` > `allow`**. Sıralama
//! > muhafazakârdır; gevşetme yönünde bir öncelik kuralı eklenemez.
//!
//! The second half is the load bearing one. A precedence rule added "in the
//! relaxing direction" is how a policy that reads as protective stops being
//! protective: an operator writes a broad `block` and a narrow `allow` gets
//! there first. So the order is a total function of the rule's own shape and the
//! [`Mode`] ordering below is the enforcement, not a comment about it.
//!
//! # Two things masking never touches
//!
//! **JSON keys** (spec section 7 rule 1). Renaming a key breaks the schema the
//! provider parses, and a key is a name the application chose, not a person's.
//! [`string_values`] never yields one, in any mode; there is no policy that turns
//! it on.
//!
//! **Nested JSON inside a string** is resolved one level (spec section 7 rule 3).
//! One, not "until it stops": a JSON string that parses as JSON that parses as
//! JSON is a decoder loop with attacker-chosen depth.

use serde_json::Value;

use crate::alias::EntityType;

/// What happens to an entity (`proxy-policy.md` section 2).
///
/// `Ord` is the conflict rule, in the conservative direction: `Block > Mask >
/// Allow`. Deriving it from the declaration order rather than writing a
/// comparison function is deliberate, because a hand written comparison is where
/// a relaxation would be introduced without looking like one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    /// The entity crosses unchanged and is counted in `entities_allowed[]`.
    /// "No masking" and not "no record".
    Allow,
    /// Replaced by an alias, restored in the response. The default.
    #[default]
    Mask,
    /// The request is refused.
    Block,
}

impl Mode {
    /// Reads the spelling `policy.toml` uses.
    ///
    /// Not `FromStr`: that trait's error type would have to carry the key the
    /// value belonged to for the load failure to name it, and an `Option` here
    /// keeps the naming where the context is.
    pub fn parse_mode(text: &str) -> Option<Self> {
        match text {
            "mask" => Some(Self::Mask),
            "block" => Some(Self::Block),
            "allow" => Some(Self::Allow),
            _ => None,
        }
    }

    /// The spelling `/admin/policy` returns.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mask => "mask",
            Self::Block => "block",
            Self::Allow => "allow",
        }
    }
}

/// One step of a JSON path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// An object key.
    Key(String),
    /// A specific array index: `messages[0]`.
    Index(usize),
    /// Any array index: `messages[*]`.
    AnyIndex,
}

/// A `scope` expression, parsed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scope {
    steps: Vec<Step>,
}

impl Scope {
    /// The scope of a rule with no `scope` key: every scanned field.
    pub fn everything() -> Self {
        Self { steps: Vec::new() }
    }

    /// Parses `messages[*].content` and friends.
    ///
    /// `None` on anything this build does not understand, which stops the policy
    /// load. A scope expression nobody parsed is a rule nobody applies.
    pub fn parse(text: &str) -> Option<Self> {
        if text.is_empty() {
            return None;
        }
        let mut steps = Vec::new();
        for part in text.split('.') {
            if part.is_empty() {
                return None;
            }
            let (name, rest) = match part.find('[') {
                Some(at) => (part.get(..at)?, part.get(at..)?),
                None => (part, ""),
            };
            if !name.is_empty() {
                if !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    return None;
                }
                steps.push(Step::Key(name.to_owned()));
            }
            let mut remainder = rest;
            while !remainder.is_empty() {
                let close = remainder.find(']')?;
                let inside = remainder.get(1..close)?;
                steps.push(match inside {
                    "*" => Step::AnyIndex,
                    digits => Step::Index(digits.parse().ok()?),
                });
                remainder = remainder.get(close + 1..)?;
            }
        }
        (!steps.is_empty()).then_some(Self { steps })
    }

    /// How narrow this scope is.
    ///
    /// More steps is narrower, and an explicit index is narrower than a wildcard
    /// at the same depth. A single number, so "narrowest wins" is a comparison
    /// and not a special case per shape.
    pub fn narrowness(&self) -> usize {
        self.steps
            .iter()
            .map(|step| match step {
                Step::Key(_) | Step::Index(_) => 2,
                Step::AnyIndex => 1,
            })
            .sum()
    }

    /// Whether this scope covers the field at `path`.
    pub fn covers(&self, path: &[Step]) -> bool {
        if self.steps.len() > path.len() {
            return false;
        }
        self.steps
            .iter()
            .zip(path)
            .all(|(rule, actual)| match rule {
                Step::AnyIndex => matches!(actual, Step::Index(_) | Step::AnyIndex),
                other => other == actual,
            })
    }

    /// The path as it is written in a policy file.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for step in &self.steps {
            match step {
                Step::Key(name) => {
                    if !out.is_empty() {
                        out.push('.');
                    }
                    out.push_str(name);
                }
                Step::Index(index) => out.push_str(&format!("[{index}]")),
                Step::AnyIndex => out.push_str("[*]"),
            }
        }
        out
    }
}

/// One `[[rule]]` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub scope: Scope,
    /// `None` means every type.
    pub entity: Option<EntityType>,
    pub mode: Mode,
}

impl Rule {
    /// How specific this rule is, for the "narrowest wins" comparison.
    ///
    /// A rule that names a type is narrower than one that does not at the same
    /// path, which is the reading `proxy/spec.md` section 8's example requires:
    /// `entity = "DATE"` with no scope has to beat the global default.
    fn specificity(&self) -> (usize, usize) {
        (self.scope.narrowness(), usize::from(self.entity.is_some()))
    }
}

/// Picks the mode for one entity at one path.
///
/// The rule is the whole of `proxy-policy.md` section 3: narrowest scope wins,
/// and at equal narrowness the **most conservative mode** wins. Not "the last
/// rule in the file", which would make behaviour depend on editing order, and
/// not "the first match", which would make it depend on the same thing in
/// reverse.
pub fn resolve(rules: &[Rule], default_mode: Mode, path: &[Step], entity: EntityType) -> Mode {
    let mut best: Option<(usize, usize, Mode)> = None;
    for rule in rules {
        if rule.entity.is_some_and(|wanted| wanted != entity) {
            continue;
        }
        if !rule.scope.covers(path) {
            continue;
        }
        let (breadth, typed) = rule.specificity();
        best = Some(match best {
            None => (breadth, typed, rule.mode),
            Some((held_breadth, held_typed, held_mode)) => {
                match (breadth, typed).cmp(&(held_breadth, held_typed)) {
                    std::cmp::Ordering::Greater => (breadth, typed, rule.mode),
                    std::cmp::Ordering::Less => (held_breadth, held_typed, held_mode),
                    // Equal narrowness: the conservative mode wins, and `Ord` on
                    // `Mode` is what says which that is.
                    std::cmp::Ordering::Equal => {
                        (held_breadth, held_typed, held_mode.max(rule.mode))
                    }
                }
            }
        });
    }
    best.map_or(default_mode, |(_, _, mode)| mode)
}

/// Every string **value** in a JSON body, with its path.
///
/// Keys are never yielded (spec section 7 rule 1) and there is no argument that
/// takes them, in any mode. A JSON string that itself parses as a JSON object is
/// descended **once**, which is section 7 rule 3's "tek seviye"; the nested
/// document's paths are reported under the outer string's path, so a rule can
/// still name them.
pub fn string_values(body: &Value) -> Vec<(Vec<Step>, String)> {
    let mut out = Vec::new();
    walk(body, &mut Vec::new(), 1, &mut out);
    out
}

fn walk(
    value: &Value,
    path: &mut Vec<Step>,
    nesting_left: usize,
    out: &mut Vec<(Vec<Step>, String)>,
) {
    match value {
        Value::String(text) => {
            out.push((path.clone(), text.clone()));
            if nesting_left > 0 {
                if let Ok(inner) = serde_json::from_str::<Value>(text) {
                    if inner.is_object() || inner.is_array() {
                        walk(&inner, path, nesting_left - 1, out);
                    }
                }
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(Step::Index(index));
                walk(item, path, nesting_left, out);
                path.pop();
            }
        }
        Value::Object(fields) => {
            for (key, field) in fields {
                path.push(Step::Key(key.clone()));
                walk(field, path, nesting_left, out);
                path.pop();
            }
        }
        // Numbers, booleans and null carry no text to mask and no key to protect.
        _ => {}
    }
}

/// Which detection layers run over one segment of text.
///
/// `proxy/spec.md` section 7 rule 2: inside a fence only layer A runs, because
/// `Ahmet` in code is a variable name and an IBAN in code is still an IBAN. The
/// three `code_block_policy` values are the three answers an operator can give,
/// and there is no fourth.
pub fn layers_for(
    kind: crate::detect::segment::SegmentKind,
    policy: super::CodeBlockPolicy,
) -> (bool, bool) {
    use crate::detect::segment::SegmentKind;
    match (kind, policy) {
        // Prose: everything the profile enables.
        (SegmentKind::Prose, _) => (true, true),
        // The default. Pattern only, and the caller owes a
        // `degraded_reasons[] = code_block_skipped` for the layer that did not
        // run over this segment.
        (SegmentKind::CodeBlock, super::CodeBlockPolicy::PatternOnly) => (true, false),
        (SegmentKind::CodeBlock, super::CodeBlockPolicy::Full) => (true, true),
        (SegmentKind::CodeBlock, super::CodeBlockPolicy::Skip) => (false, false),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn path(text: &str) -> Vec<Step> {
        Scope::parse(text).unwrap().steps
    }

    #[test]
    fn a_scope_expression_parses_and_renders_back() {
        for text in [
            "messages[*].content",
            "messages[0].content",
            "system",
            "a[1][2].b",
        ] {
            assert_eq!(Scope::parse(text).unwrap().render(), text);
        }
        assert_eq!(Scope::parse(""), None);
        assert_eq!(Scope::parse("messages["), None);
        assert_eq!(Scope::parse("messages[x]"), None);
        assert_eq!(Scope::parse("a..b"), None);
        assert_eq!(Scope::parse("bad key"), None);
    }

    #[test]
    fn a_wildcard_covers_an_index_and_an_index_does_not_cover_another() {
        let any = Scope::parse("messages[*].content").unwrap();
        let first = Scope::parse("messages[0].content").unwrap();
        assert!(any.covers(&path("messages[0].content")));
        assert!(first.covers(&path("messages[0].content")));
        assert!(!first.covers(&path("messages[1].content")));
        // Everything covers everything.
        assert!(Scope::everything().covers(&path("messages[3].content")));
    }

    #[test]
    fn the_narrowest_scope_wins() {
        // The example from `proxy/spec.md` section 8, resolved.
        let rules = vec![
            Rule {
                scope: Scope::parse("messages[*].content").unwrap(),
                entity: Some(EntityType::Tckn),
                mode: Mode::Block,
            },
            Rule {
                scope: Scope::parse("messages[0].content").unwrap(),
                entity: None,
                mode: Mode::Allow,
            },
        ];
        // The system prompt is allowed, even for a type the broader rule blocks.
        assert_eq!(
            resolve(
                &rules,
                Mode::Mask,
                &path("messages[0].content"),
                EntityType::Tckn
            ),
            Mode::Allow
        );
        // Everywhere else the broader block still holds.
        assert_eq!(
            resolve(
                &rules,
                Mode::Mask,
                &path("messages[1].content"),
                EntityType::Tckn
            ),
            Mode::Block
        );
        // And a type nobody named falls to the default.
        assert_eq!(
            resolve(
                &rules,
                Mode::Mask,
                &path("messages[1].content"),
                EntityType::Email
            ),
            Mode::Mask
        );
    }

    #[test]
    fn at_equal_narrowness_the_conservative_mode_wins() {
        let rules = vec![
            Rule {
                scope: Scope::parse("messages[*].content").unwrap(),
                entity: Some(EntityType::Iban),
                mode: Mode::Allow,
            },
            Rule {
                scope: Scope::parse("messages[*].content").unwrap(),
                entity: Some(EntityType::Iban),
                mode: Mode::Block,
            },
        ];
        assert_eq!(
            resolve(
                &rules,
                Mode::Mask,
                &path("messages[0].content"),
                EntityType::Iban
            ),
            Mode::Block
        );
        // And the file order does not change it, which is what makes this a rule
        // rather than an accident of editing.
        let mut reversed = rules;
        reversed.reverse();
        assert_eq!(
            resolve(
                &reversed,
                Mode::Mask,
                &path("messages[0].content"),
                EntityType::Iban
            ),
            Mode::Block
        );
    }

    #[test]
    fn the_ordering_cannot_be_relaxed() {
        // Milestone 84 asks for this to be pinned. The ordering is `Ord` on
        // `Mode`; if somebody reorders the variants to make `allow` win, this is
        // what goes red, and so does every equal-narrowness resolution above.
        assert!(Mode::Block > Mode::Mask);
        assert!(Mode::Mask > Mode::Allow);
        assert_eq!(Mode::Allow.max(Mode::Block), Mode::Block);
        assert_eq!(Mode::Allow.max(Mode::Mask), Mode::Mask);
        // Stated the other way round too, so that a partial reorder is caught:
        // the conservative mode is the maximum of any pair.
        for pair in [
            (Mode::Allow, Mode::Mask),
            (Mode::Allow, Mode::Block),
            (Mode::Mask, Mode::Block),
        ] {
            assert_eq!(pair.0.max(pair.1), pair.1);
        }
    }

    #[test]
    fn a_typed_rule_beats_an_untyped_one_at_the_same_path() {
        let rules = vec![Rule {
            scope: Scope::everything(),
            entity: Some(EntityType::Date),
            mode: Mode::Block,
        }];
        assert_eq!(
            resolve(
                &rules,
                Mode::Mask,
                &path("messages[0].content"),
                EntityType::Date
            ),
            Mode::Block
        );
        assert_eq!(
            resolve(
                &rules,
                Mode::Mask,
                &path("messages[0].content"),
                EntityType::Iban
            ),
            Mode::Mask
        );
    }

    #[test]
    fn with_no_rules_at_all_the_default_decides() {
        // The exhausted case: an empty rule list is a working policy, not a hole.
        assert_eq!(
            resolve(
                &[],
                Mode::Mask,
                &path("messages[0].content"),
                EntityType::Tckn
            ),
            Mode::Mask
        );
        assert_eq!(
            resolve(&[], Mode::Block, &path("a"), EntityType::Tckn),
            Mode::Block
        );
    }

    #[test]
    fn json_keys_are_never_offered_for_masking() {
        // Spec section 7 rule 1, and there is no mode that turns it on.
        let body: Value = serde_json::from_str(
            r#"{"ahmet": "Kestane", "messages": [{"role": "user", "content": "merhaba"}]}"#,
        )
        .unwrap();
        let values = string_values(&body);
        let texts: Vec<&str> = values.iter().map(|(_, text)| text.as_str()).collect();
        assert!(texts.contains(&"Kestane"));
        assert!(texts.contains(&"merhaba"));
        assert!(texts.contains(&"user"));
        // The key `ahmet` is a key. It is never a value.
        assert!(!texts.contains(&"ahmet"));
        assert!(!texts.contains(&"messages"));
        assert!(!texts.contains(&"content"));
    }

    #[test]
    fn nested_json_in_a_string_is_resolved_one_level_and_no_further() {
        // Spec section 7 rule 3. One level, because "until it stops" is a
        // decoder loop whose depth the caller chooses.
        let inner = r#"{"iban": "TR33"}"#;
        let deeper = serde_json::to_string(&serde_json::json!({ "nested": inner })).unwrap();
        let body = serde_json::json!({ "payload": deeper });
        let values = string_values(&body);
        let texts: Vec<&str> = values.iter().map(|(_, text)| text.as_str()).collect();
        // Level one: the string itself and the values inside it.
        assert!(texts.contains(&inner));
        // Level two would be `TR33`, and it is not reached.
        assert!(!texts.contains(&"TR33"));
    }

    #[test]
    fn inside_a_fence_only_the_pattern_layer_runs_by_default() {
        use super::super::CodeBlockPolicy;
        use crate::detect::segment::SegmentKind;
        assert_eq!(
            layers_for(SegmentKind::CodeBlock, CodeBlockPolicy::PatternOnly),
            (true, false)
        );
        assert_eq!(
            layers_for(SegmentKind::CodeBlock, CodeBlockPolicy::Full),
            (true, true)
        );
        assert_eq!(
            layers_for(SegmentKind::CodeBlock, CodeBlockPolicy::Skip),
            (false, false)
        );
        // Prose is unaffected by the code block policy, in all three values.
        for policy in [
            CodeBlockPolicy::PatternOnly,
            CodeBlockPolicy::Full,
            CodeBlockPolicy::Skip,
        ] {
            assert_eq!(layers_for(SegmentKind::Prose, policy), (true, true));
        }
    }

    #[test]
    fn a_name_in_a_code_block_survives_and_an_iban_in_one_does_not() {
        // Spec section 7 rule 2 and rule 3, end to end over one body: the code
        // stays syntactically valid because the identifier is untouched and the
        // IBAN is replaced by a same-shaped alias.
        use super::super::CodeBlockPolicy;
        use crate::detect::segment::segments;
        use crate::detect::{dictionary::Dictionary, pattern};

        let text = "Ahmet için:\n```python\nahmet_iban = \"TR330006100519786457841326\"\n```";
        let dictionary = Dictionary::parse(
            "schema_version = \"1.0\"\ndictionary_id = \"x\"\n[[entries]]\nvalue = \"Ahmet\"\ntype = \"PERSON\"\n",
        )
        .unwrap();

        let mut found = Vec::new();
        for segment in segments(text) {
            let slice = text.get(segment.start..segment.end).unwrap();
            let (run_pattern, run_dictionary) =
                layers_for(segment.kind, CodeBlockPolicy::PatternOnly);
            if run_pattern {
                found.extend(pattern::scan(slice).into_iter().map(|mut c| {
                    c.start += segment.start;
                    c.end += segment.start;
                    c
                }));
            }
            if run_dictionary {
                found.extend(dictionary.scan(slice).into_iter().map(|mut c| {
                    c.start += segment.start;
                    c.end += segment.start;
                    c
                }));
            }
        }

        let tags: Vec<&str> = found.iter().map(|c| c.entity.tag()).collect();
        // The IBAN in the code block was found by layer A.
        assert!(tags.contains(&"IBAN"));
        // The name in the prose was found by layer B, exactly once: the
        // identifier `ahmet_iban` inside the fence is not a person.
        assert_eq!(tags.iter().filter(|tag| **tag == "PERSON").count(), 1);
        let person = found.iter().find(|c| c.entity.tag() == "PERSON").unwrap();
        assert_eq!(person.text_of(text), Some("Ahmet"));
        assert!(person.start < text.find("```").unwrap());
    }

    #[test]
    fn paths_are_reported_so_a_rule_can_name_a_field() {
        let body: Value =
            serde_json::from_str(r#"{"messages":[{"content":"a"},{"content":"b"}]}"#).unwrap();
        let values = string_values(&body);
        let rendered: Vec<String> = values
            .iter()
            .map(|(path, _)| {
                Scope {
                    steps: path.clone(),
                }
                .render()
            })
            .collect();
        assert!(rendered.contains(&"messages[0].content".to_owned()));
        assert!(rendered.contains(&"messages[1].content".to_owned()));
    }
}
