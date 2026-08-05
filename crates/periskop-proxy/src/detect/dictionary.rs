//! Layer B: the organization's word list, in one pass, affix aware.
//!
//! # What this layer is for
//!
//! Nothing about the shape of `Kestane` says it is a project rather than a
//! chestnut. Layer A cannot find it and, in this build, no model is asked to
//! guess. The only thing that knows is the organization, and this layer is where
//! what it knows is applied (`proxy/spec.md` section 3.2, ADR-011 section 1:
//! mandatory, always on, empty when the list is empty).
//!
//! # One pass
//!
//! Aho-Corasick, built once when the policy loads and frozen for the life of a
//! request (ADR-004, and ADR-010 section 4 for why it may not be rebuilt mid
//! stream). One automaton over the whole list means the cost of the layer is the
//! length of the text and not the length of the list, which is what makes a list
//! of ten thousand names affordable inside the latency budget.
//!
//! # The list is a secret and stays one
//!
//! A word on what is *not* claimed. The automaton owns its own copy of every
//! pattern and this crate cannot reach inside it, so there is no honest way to
//! zeroize the list while it is loaded: it is in memory for as long as scanning
//! is possible. Holding a second, self clearing copy beside it would add a copy
//! rather than remove one. The residual exposure is `known-gaps.md` KG-019, the
//! same one every decrypted value in this process has, and the vault's own
//! discipline is what covers values at rest.
//!
//! `proxy-policy.md` section 10: the file holds exactly the names this component
//! exists to keep from leaving. So the list is never echoed to `/admin/*`, never
//! written into a `ProxyEvent`, never logged, and this crate writes no copy of it
//! anywhere. `dictionary_id` is what a report names; the entries are not.
//!
//! # The empty case is a working configuration
//!
//! A dictionary with no entries runs and matches nothing, and that is different
//! from a dictionary that could not be read (`degraded_reasons =
//! dictionary_unavailable`). The distinction matters because one of them is a
//! choice and the other is a failure, and reporting them the same way would
//! teach an operator to ignore both.

use std::collections::BTreeSet;

use aho_corasick::{AhoCorasick, MatchKind};

use crate::alias::EntityType;

use super::affix::{fold, is_word_character, AffixRules};
use super::layer::dictionary_may_claim;
use super::span::{sort_candidates, Candidate};

/// Why a word list would not load.
///
/// Every variant stops the policy load when `dictionary.required = true`
/// (`proxy-policy.md` section 7). An entry that loaded and could not be aliased
/// would fail in the middle of an accepted request; refusing at startup turns a
/// mid-request failure into a startup failure, which is the trade section 10
/// argues for.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DictionaryError {
    /// The file is not the shape `proxy-dictionary.schema.json` describes.
    #[error("dictionary is malformed: {detail}")]
    Malformed { detail: String },
    /// An entry names a type this build does not know.
    #[error("dictionary entry {index} names unknown entity type '{tag}'")]
    UnknownType { index: usize, tag: String },
    /// An entry names a type layer A owns.
    ///
    /// Separate from [`Self::UnknownType`] because the operator's next move is
    /// different: an unknown type is a typo, this is a type that exists and
    /// belongs to another layer. `proxy-dictionary.schema.json` gives the reason
    /// for the checksum bearing types; `detect::layer` gives it for `API_KEY`.
    #[error(
        "dictionary entry {index} claims '{tag}', which detection layer A owns; \
         a word list cannot decide a type the text decides for itself"
    )]
    TypeOwnedByAnotherLayer { index: usize, tag: String },
    /// An entry has no value.
    #[error("dictionary entry {index} has an empty value")]
    EmptyValue { index: usize },
}

/// The shape a dictionary file deserializes into.
#[derive(serde::Deserialize)]
struct DictionaryFile {
    schema_version: String,
    dictionary_id: String,
    entries: Vec<RawEntry>,
}

#[derive(serde::Deserialize)]
struct RawEntry {
    value: String,
    #[serde(rename = "type")]
    entity: String,
}

/// What the automaton knows about the pattern at each index.
struct EntryMeta {
    entity: EntityType,
    /// Length of the folded pattern, in folded bytes. Kept so a match can be
    /// bounded without asking the automaton for the pattern text back.
    folded_len: usize,
}

/// The organization's word list, compiled.
pub struct Dictionary {
    id: String,
    automaton: Option<AhoCorasick>,
    entries: Vec<EntryMeta>,
    affixes: Option<AffixRules>,
}

impl Dictionary {
    /// A dictionary with no entries.
    ///
    /// Not an error state. `layer B runs and matches nothing` is a supported
    /// configuration (`proxy-dictionary.schema.json`: "May be empty").
    pub fn empty() -> Self {
        Self {
            id: String::new(),
            automaton: None,
            entries: Vec::new(),
            affixes: None,
        }
    }

    /// Parses and compiles a dictionary from its TOML text.
    pub fn parse(text: &str) -> Result<Self, DictionaryError> {
        let parsed: DictionaryFile =
            toml::from_str(text).map_err(|error| DictionaryError::Malformed {
                detail: error.to_string(),
            })?;
        if !parsed.schema_version.starts_with("1.") {
            return Err(DictionaryError::Malformed {
                detail: format!("schema_version {} is not supported", parsed.schema_version),
            });
        }
        if parsed.dictionary_id.is_empty() {
            return Err(DictionaryError::Malformed {
                detail: "dictionary_id is empty".to_owned(),
            });
        }

        let mut patterns: Vec<String> = Vec::with_capacity(parsed.entries.len());
        let mut entries = Vec::with_capacity(parsed.entries.len());
        let mut seen = BTreeSet::new();
        for (index, raw) in parsed.entries.iter().enumerate() {
            if raw.value.trim().is_empty() {
                return Err(DictionaryError::EmptyValue { index });
            }
            let Some(entity) = EntityType::from_tag(&raw.entity) else {
                return Err(DictionaryError::UnknownType {
                    index,
                    tag: raw.entity.clone(),
                });
            };
            if !dictionary_may_claim(entity) {
                return Err(DictionaryError::TypeOwnedByAnotherLayer {
                    index,
                    tag: raw.entity.clone(),
                });
            }
            let (folded, _) = fold(&raw.value);
            // A duplicate would give the same bytes two patterns and make the
            // leftmost-longest tie-break depend on file order, which is not
            // determinism (README principle 7).
            if !seen.insert(folded.clone()) {
                continue;
            }
            entries.push(EntryMeta {
                entity,
                folded_len: folded.len(),
            });
            patterns.push(folded);
        }

        let automaton = if patterns.is_empty() {
            None
        } else {
            // Leftmost-longest: when two entries start at the same place the
            // longer one is the entity. `Ali` and `Ali Veli` both in the list and
            // `Ali Veli` in the text is one person, not one person and a word.
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .build(&patterns)
                .ok()
        };
        if !patterns.is_empty() && automaton.is_none() {
            return Err(DictionaryError::Malformed {
                detail: "the word list could not be compiled into an automaton".to_owned(),
            });
        }

        Ok(Self {
            id: parsed.dictionary_id,
            automaton,
            entries,
            affixes: None,
        })
    }

    /// Attaches affix rules. Without them, matching is word-boundary only.
    pub fn with_affixes(mut self, affixes: AffixRules) -> Self {
        self.affixes = Some(affixes);
        self
    }

    /// The identity a report may name. Never an entry.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// How many entries compiled.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the list is empty, which is a working configuration.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Scans `text` in one pass.
    ///
    /// Offsets in the returned candidates are byte offsets into `text`, not into
    /// the folded copy the automaton runs over; [`fold`]'s origin map is what
    /// joins the two.
    pub fn scan(&self, text: &str) -> Vec<Candidate> {
        let mut found = Vec::new();
        let Some(automaton) = self.automaton.as_ref() else {
            // The exhausted case. An empty list runs and finds nothing, which is
            // a different state from being unavailable, and neither is an error
            // here.
            return found;
        };
        let (folded, origins) = fold(text);
        for hit in automaton.find_iter(folded.as_str()) {
            let Some(meta) = self.entries.get(hit.pattern().as_usize()) else {
                continue;
            };
            if hit.end() - hit.start() != meta.folded_len {
                continue;
            }
            if !self.boundaries_hold(&folded, hit.start(), hit.end()) {
                continue;
            }
            let (Some(start), Some(end)) = (origins.get(hit.start()), origins.get(hit.end()))
            else {
                continue;
            };
            if !text.is_char_boundary(*start) || !text.is_char_boundary(*end) || end <= start {
                continue;
            }
            found.push(Candidate::new(meta.entity, *start, *end));
        }
        sort_candidates(&mut found);
        found
    }

    /// Whether a hit sits on word boundaries, with the affix rules deciding the
    /// trailing one.
    ///
    /// The leading boundary is not negotiable: a match that starts inside a word
    /// is a different word. The trailing boundary is where Turkish lives, and
    /// [`AffixRules::tail_is_an_affix`] is the whole of the judgement.
    fn boundaries_hold(&self, folded: &str, start: usize, end: usize) -> bool {
        let before = folded
            .get(..start)
            .and_then(|head| head.chars().next_back());
        if before.is_some_and(is_word_character) {
            return false;
        }
        let Some(rest) = folded.get(end..) else {
            return false;
        };
        // Only the rest of the *word* can be an affix. Handing the whole
        // remainder of the text to the affix parser would ask it whether
        // "ler toplandi" is a suffix chain, which it is not, and every suffixed
        // match in a sentence would be lost.
        let tail = word_tail(rest);
        let next = tail.chars().next();
        let Some(next) = next else {
            return true;
        };
        if !is_word_character(next) && !self.tail_opens_with_an_apostrophe(tail) {
            return true;
        }
        let Some(affixes) = self.affixes.as_ref() else {
            // No affix rules for this deployment: word boundary only. A language
            // whose rules are declared and missing never gets here, because that
            // stops the policy load (`proxy-policy.md` section 7).
            return false;
        };
        let Some(base) = folded.get(start..end) else {
            return false;
        };
        affixes.tail_is_an_affix(base, tail)
    }

    /// Whether the text after a match opens with an apostrophe.
    ///
    /// Checked separately from the word-character test because an apostrophe is
    /// not a word character: without this, `Ahmet'in` would take the "no word
    /// character follows, boundary holds" path and produce a match over `Ahmet`
    /// even with no affix rules loaded, which would make the affix rules look
    /// optional when they are what decides the Turkish case.
    fn tail_opens_with_an_apostrophe(&self, tail: &str) -> bool {
        tail.starts_with(['\'', '\u{2019}', '\u{02bc}'])
    }
}

/// The rest of the word a match sits at the start of.
///
/// An optional leading apostrophe, then the run of word characters. Everything
/// after that belongs to the next word and is not a suffix of this one.
fn word_tail(rest: &str) -> &str {
    let mut end = 0usize;
    for (index, character) in rest.char_indices() {
        let is_leading_apostrophe =
            index == 0 && matches!(character, '\'' | '\u{2019}' | '\u{02bc}');
        if is_word_character(character) || is_leading_apostrophe {
            end = index + character.len_utf8();
        } else {
            break;
        }
    }
    rest.get(..end).unwrap_or_default()
}

impl std::fmt::Debug for Dictionary {
    /// Prints the identity and the count, never an entry.
    ///
    /// A derived `Debug` would put the whole word list into any log line, panic
    /// message or test failure that formatted this type. `proxy-policy.md`
    /// section 10 forbids exactly that, and forbidding it in review rather than
    /// in the type is how it comes back.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Dictionary")
            .field("id", &self.id)
            .field("entries", &self.entries.len())
            .field("affixes", &self.affixes.as_ref().map(AffixRules::language))
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::Path;

    const LIST: &str = r#"
schema_version = "1.0"
dictionary_id = "test-list"
[[entries]]
value = "Ahmet"
type = "PERSON"
[[entries]]
value = "Kestane"
type = "ORG"
[[entries]]
value = "build-01.corp.example"
type = "HOST"
"#;

    fn turkish() -> AffixRules {
        AffixRules::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."), "tr").unwrap()
    }

    fn loaded() -> Dictionary {
        Dictionary::parse(LIST).unwrap().with_affixes(turkish())
    }

    fn matches_of(dictionary: &Dictionary, text: &str) -> Vec<(String, &'static str)> {
        dictionary
            .scan(text)
            .into_iter()
            .filter_map(|candidate| {
                candidate
                    .text_of(text)
                    .map(|matched| (matched.to_owned(), candidate.entity.tag()))
            })
            .collect()
    }

    #[test]
    fn an_empty_list_runs_and_finds_nothing_without_failing() {
        // ADR-011 section 1: "liste boşsa katman boş çalışır". The exhausted case
        // at the gate, which is where the interesting branch always is.
        let empty = Dictionary::empty();
        assert!(empty.is_empty());
        assert!(empty.scan("Ahmet ve Kestane").is_empty());

        let parsed = Dictionary::parse(
            r#"
schema_version = "1.0"
dictionary_id = "nothing"
entries = []
"#,
        )
        .unwrap();
        assert!(parsed.is_empty());
        assert_eq!(parsed.id(), "nothing");
        assert!(parsed.scan("Ahmet").is_empty());
        // And an empty list with affix rules attached is still not an error.
        assert!(parsed.with_affixes(turkish()).scan("Ahmet'in").is_empty());
    }

    #[test]
    fn a_bare_entry_matches_on_word_boundaries_only() {
        let dictionary = loaded();
        assert_eq!(
            matches_of(&dictionary, "Ahmet geldi"),
            vec![("Ahmet".to_owned(), "PERSON")]
        );
        // Inside a longer word: a different word. Three shapes, because only
        // the last two actually exercise the *leading* boundary: in the first,
        // the trailing check rejects `oglu` on its own and the match would be
        // refused even with no leading check at all. A mutation run found that
        // this test proved nothing until the next two lines existed.
        assert!(matches_of(&dictionary, "Mehmetahmetoglu").is_empty());
        // Match at the end of a word: nothing follows, so the trailing boundary
        // holds and only the leading one can refuse it.
        assert!(matches_of(&dictionary, "MehmetAhmet geldi").is_empty());
        // Match inside a word with a legal Turkish suffix after it: the trailing
        // check accepts, and again only the leading one can refuse.
        assert!(matches_of(&dictionary, "MehmetAhmetler geldi").is_empty());
        assert_eq!(
            matches_of(&dictionary, "(Kestane) projesi"),
            vec![("Kestane".to_owned(), "ORG")]
        );
    }

    #[test]
    fn five_turkish_affixes_match_and_the_span_stops_before_the_suffix() {
        // Milestone 81: at least five suffixes. The span stopping before the
        // suffix is what makes `PERSON_1'in` fall out of the replacement with no
        // reattach step to get wrong.
        let dictionary = loaded();
        for (text, expected) in [
            ("Ahmet'in dosyası", "Ahmet"),
            ("Ahmet'e verdim", "Ahmet"),
            ("Ahmet'ten aldım", "Ahmet"),
            ("Ahmet'le konuştum", "Ahmet"),
            ("Ahmetler toplandı", "Ahmet"),
            ("Ahmetlerden biri", "Ahmet"),
            ("Kestane'yi bitirdik", "Kestane"),
        ] {
            let found = matches_of(&dictionary, text);
            assert_eq!(
                found,
                vec![(
                    expected.to_owned(),
                    if expected == "Ahmet" { "PERSON" } else { "ORG" }
                )],
                "{text}"
            );
        }
    }

    #[test]
    fn the_replacement_carries_the_suffix_because_the_span_excludes_it() {
        // The end-to-end statement of the rule, done the way the request path
        // will do it: splice the alias into the span.
        let dictionary = loaded();
        let text = "Ahmet'in raporu Ahmetlere gitti";
        let mut out = String::new();
        let mut cursor = 0;
        for candidate in dictionary.scan(text) {
            out.push_str(text.get(cursor..candidate.start).unwrap_or_default());
            out.push_str("PERSON_1");
            cursor = candidate.end;
        }
        out.push_str(text.get(cursor..).unwrap_or_default());
        assert_eq!(out, "PERSON_1'in raporu PERSON_1lere gitti");
    }

    #[test]
    fn a_tail_that_is_not_a_turkish_suffix_does_not_extend_the_match() {
        let dictionary = loaded();
        // `-ce` is derivational and out of the list on purpose; without that, an
        // entry `Ali` would match inside `Alice`.
        assert!(matches_of(&dictionary, "Ahmetce").is_empty());
        assert!(matches_of(&dictionary, "Kestanelik").is_empty());
    }

    #[test]
    fn without_affix_rules_only_the_bare_form_matches() {
        // The mutation target: drop the affix rules and the suffixed forms stop
        // matching. That is what makes the affix test above load bearing rather
        // than incidental.
        let bare = Dictionary::parse(LIST).unwrap();
        assert_eq!(
            matches_of(&bare, "Ahmet geldi"),
            vec![("Ahmet".to_owned(), "PERSON")]
        );
        assert!(matches_of(&bare, "Ahmet'in dosyası").is_empty());
        assert!(matches_of(&bare, "Ahmetler").is_empty());
    }

    #[test]
    fn matching_is_case_insensitive_in_the_turkish_way() {
        let dictionary = loaded();
        // A shouty prompt is the same person.
        assert_eq!(
            matches_of(&dictionary, "AHMET GELDI"),
            vec![("AHMET".to_owned(), "PERSON")]
        );
        // And the offsets survive a multi-byte character before the match.
        let text = "Şirketimizde Ahmet çalışıyor";
        assert_eq!(
            matches_of(&dictionary, text),
            vec![("Ahmet".to_owned(), "PERSON")]
        );
    }

    #[test]
    fn a_host_entry_is_matched_whole_and_not_by_its_labels() {
        let dictionary = loaded();
        assert_eq!(
            matches_of(&dictionary, "ssh build-01.corp.example ile"),
            vec![("build-01.corp.example".to_owned(), "HOST")]
        );
    }

    #[test]
    fn an_entry_claiming_a_layer_a_type_is_refused_at_load() {
        // proxy-dictionary.schema.json for the checksum bearing types, and
        // `detect::layer` for API_KEY. Refusing at load turns what would be a
        // mid-request alias failure into a startup failure.
        for tag in ["TCKN", "IBAN", "CREDIT_CARD", "VKN", "API_KEY", "URL"] {
            let text = format!(
                "schema_version = \"1.0\"\ndictionary_id = \"x\"\n[[entries]]\nvalue = \"v\"\ntype = \"{tag}\"\n"
            );
            let error = Dictionary::parse(&text).unwrap_err();
            assert!(
                matches!(error, DictionaryError::TypeOwnedByAnotherLayer { .. }),
                "{tag} was accepted: {error}"
            );
        }
    }

    #[test]
    fn an_unknown_or_empty_entry_stops_the_load_rather_than_being_skipped() {
        let unknown = Dictionary::parse(
            "schema_version = \"1.0\"\ndictionary_id = \"x\"\n[[entries]]\nvalue = \"v\"\ntype = \"PASSPORT\"\n",
        )
        .unwrap_err();
        assert!(matches!(unknown, DictionaryError::UnknownType { .. }));

        let empty = Dictionary::parse(
            "schema_version = \"1.0\"\ndictionary_id = \"x\"\n[[entries]]\nvalue = \"  \"\ntype = \"PERSON\"\n",
        )
        .unwrap_err();
        assert!(matches!(empty, DictionaryError::EmptyValue { .. }));
    }

    #[test]
    fn the_debug_form_never_prints_an_entry() {
        // proxy-policy.md section 10: the list never reaches a log, an admin
        // response or an event. A derived `Debug` would put it in all three the
        // first time anything formatted this type.
        let rendered = format!("{:?}", loaded());
        assert!(!rendered.contains("Ahmet"), "{rendered}");
        assert!(!rendered.contains("Kestane"), "{rendered}");
        assert!(rendered.contains("test-list"));
    }

    #[test]
    fn scanning_is_deterministic() {
        let dictionary = loaded();
        let text = "Ahmet'in Kestane projesi build-01.corp.example üzerinde";
        assert_eq!(dictionary.scan(text), dictionary.scan(text));
    }
}
