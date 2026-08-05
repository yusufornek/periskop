//! Turkish affix awareness for layer B, and the case folding it needs.
//!
//! # The problem in one line
//!
//! `proxy/spec.md` section 3.2: `Ahmet` in the dictionary has to match `Ahmet'in`
//! and `Ahmet'e`, the suffix has to be split off, and the alias has to carry it
//! back (`PERSON_1'in`). Turkish is agglutinative and this is not a nicety: a
//! matcher with no affix knowledge misses most real occurrences of every name in
//! the list, and every miss is a person's name reaching the provider.
//!
//! # How the suffix comes back without anybody putting it back
//!
//! The candidate span covers **the base only**. Replacing `Ahmet` inside
//! `Ahmet'in` with `PERSON_1` yields `PERSON_1'in` by itself; there is no reattach
//! step to get wrong, and no place for the suffix to be dropped. The whole of
//! "split the affix and add it after the alias" is therefore a statement about
//! where the span ends.
//!
//! # Which way this errs, and where the line is
//!
//! Two paths, deliberately asymmetric:
//!
//! - **With an apostrophe** the match is accepted whatever follows. Turkish
//!   orthography puts an apostrophe there precisely to mark the boundary, and
//!   the text before it is already an exact dictionary hit. Erring toward the
//!   match costs nothing that was not already claimed.
//! - **Without an apostrophe** three conditions must all hold: the tail parses
//!   as a chain of listed inflectional suffixes, vowel harmony holds on the
//!   first of them, and the base is long enough. This is where `Ali` inside
//!   `Alice` would get in, and the suffix list is what keeps it out: `-ce` is
//!   derivational and is not in the list.
//!
//! The residual false positive is real and named: a dictionary entry that is a
//! prefix of a longer word whose tail happens to be an inflectional suffix
//! (`Ali` inside `Aliye`) is matched. It is `known-gaps.md` KG-025, it damages a
//! prompt rather than leaking a value, and the operator sees it.

use std::collections::BTreeSet;
use std::path::Path;

/// Where the affix rules for a language live, relative to the repository root.
///
/// `proxy-policy.md` section 11 fixes this path and fixes that it is not
/// `rules/<lang>/`.
pub const RULES_SUBDIRECTORY: &str = "rules/masking";

/// Errors reading a language's affix rules.
///
/// Every one of them stops the policy load (`proxy-policy.md` section 7): running
/// with a language declared and its rules missing is silent under-masking, which
/// is more expensive than a visible startup failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AffixError {
    /// The language is listed in `affix_rules.languages` and its directory is
    /// not there.
    #[error("affix rules for language '{language}' are declared but {path} does not exist")]
    DirectoryMissing { language: String, path: String },
    /// The directory exists and holds no readable rule file.
    #[error("affix rules for language '{language}' at {path} could not be read: {detail}")]
    Unreadable {
        language: String,
        path: String,
        detail: String,
    },
    /// The file parsed as TOML but is not affix rules.
    #[error("affix rules for language '{language}' are malformed: {detail}")]
    Malformed { language: String, detail: String },
}

/// The rules for one natural language.
#[derive(Clone, Debug)]
pub struct AffixRules {
    language: String,
    apostrophes: Vec<char>,
    suffixes: BTreeSet<String>,
    min_base_chars: usize,
    max_affix_chain: usize,
}

/// The shape `affixes.toml` deserializes into.
#[derive(serde::Deserialize)]
struct RuleFile {
    schema_version: String,
    language: String,
    apostrophes: Vec<String>,
    min_base_chars: usize,
    max_affix_chain: usize,
    suffixes: Vec<String>,
}

impl AffixRules {
    /// Loads `rules/masking/<language>/affixes.toml` under `root`.
    pub fn load(root: &Path, language: &str) -> Result<Self, AffixError> {
        let directory = root.join(RULES_SUBDIRECTORY).join(language);
        if !directory.is_dir() {
            return Err(AffixError::DirectoryMissing {
                language: language.to_owned(),
                path: directory.display().to_string(),
            });
        }
        let file = directory.join("affixes.toml");
        let text = std::fs::read_to_string(&file).map_err(|error| AffixError::Unreadable {
            language: language.to_owned(),
            path: file.display().to_string(),
            detail: error.to_string(),
        })?;
        Self::parse(language, &text)
    }

    /// Parses rule text. Separate from [`Self::load`] so the rules can be tested
    /// without a filesystem and so the loader's error paths are reachable.
    pub fn parse(language: &str, text: &str) -> Result<Self, AffixError> {
        let parsed: RuleFile = toml::from_str(text).map_err(|error| AffixError::Malformed {
            language: language.to_owned(),
            detail: error.to_string(),
        })?;
        if !parsed.schema_version.starts_with("1.") {
            return Err(AffixError::Malformed {
                language: language.to_owned(),
                detail: format!("schema_version {} is not supported", parsed.schema_version),
            });
        }
        if parsed.language != language {
            return Err(AffixError::Malformed {
                language: language.to_owned(),
                detail: format!("file declares language '{}'", parsed.language),
            });
        }
        // An empty suffix list is not "no affixes", it is a rule file that
        // silently under-masks. The whole reason section 11 stops the load on a
        // missing directory applies to an empty one.
        if parsed.suffixes.is_empty() {
            return Err(AffixError::Malformed {
                language: language.to_owned(),
                detail: "the suffix list is empty".to_owned(),
            });
        }
        Ok(Self {
            language: parsed.language,
            apostrophes: parsed
                .apostrophes
                .iter()
                .filter_map(|entry| entry.chars().next())
                .collect(),
            suffixes: parsed.suffixes.into_iter().map(|s| fold(&s).0).collect(),
            min_base_chars: parsed.min_base_chars,
            max_affix_chain: parsed.max_affix_chain,
        })
    }

    /// The language tag these rules are for.
    pub fn language(&self) -> &str {
        &self.language
    }

    /// Whether `tail`, the folded text immediately after a dictionary match, is a
    /// suffix this base may take.
    ///
    /// `base` is the folded matched text. Both are folded because harmony is
    /// decided on vowels and `İ` folds to `i`.
    pub fn tail_is_an_affix(&self, base: &str, tail: &str) -> bool {
        let mut characters = tail.chars();
        if let Some(first) = characters.next() {
            if self.apostrophes.contains(&first) {
                // The apostrophe is the boundary. Nothing after it can turn the
                // base into a different word.
                return true;
            }
        }
        if base.chars().count() < self.min_base_chars {
            return false;
        }
        let Some(base_vowel) = last_vowel(base) else {
            // No vowel in the base means no harmony to check, and no Turkish
            // word to be part of either. Refuse rather than guess.
            return false;
        };
        self.parses_as_chain(tail, base_vowel, self.max_affix_chain)
    }

    /// Whether `tail` splits into at most `remaining` listed suffixes.
    ///
    /// Harmony is checked on the first suffix only. After the first, the
    /// preceding suffix's own vowel governs, and the variants in the list
    /// already encode that; checking each link would reject the correct
    /// `-ler` + `-den` (front then back) that Turkish actually writes as
    /// `-lerden`.
    fn parses_as_chain(&self, tail: &str, base_vowel: char, remaining: usize) -> bool {
        if tail.is_empty() {
            return false;
        }
        if remaining == 0 {
            return false;
        }
        for (index, character) in tail.char_indices() {
            let end = index + character.len_utf8();
            let Some(head) = tail.get(..end) else {
                continue;
            };
            if !self.suffixes.contains(head) {
                continue;
            }
            if !harmonizes(base_vowel, head) {
                continue;
            }
            let Some(rest) = tail.get(end..) else {
                continue;
            };
            if rest.is_empty() {
                return true;
            }
            // The next link's harmony is governed by this suffix's own last
            // vowel, which is why the recursion carries it forward.
            let next_vowel = last_vowel(head).unwrap_or(base_vowel);
            if self.parses_as_chain(rest, next_vowel, remaining - 1) {
                return true;
            }
        }
        false
    }
}

/// Turkish back vowels. Everything else in [`VOWELS`] is front.
const BACK_VOWELS: [char; 4] = ['a', 'ı', 'o', 'u'];
/// Every Turkish vowel, in lower case.
const VOWELS: [char; 8] = ['a', 'e', 'ı', 'i', 'o', 'ö', 'u', 'ü'];

/// The last vowel of a folded string.
fn last_vowel(text: &str) -> Option<char> {
    text.chars().rev().find(|c| VOWELS.contains(c))
}

/// Whether a suffix's first vowel agrees with the base's last vowel.
///
/// Two-way harmony for `e`/`a`, four-way for `i`/`ı`/`u`/`ü`. This is the rule
/// that keeps `Ali` out of `Alida`: locative after a front vowel is `-de`, and
/// `-da` does not agree.
fn harmonizes(base_vowel: char, suffix: &str) -> bool {
    let Some(suffix_vowel) = suffix.chars().find(|c| VOWELS.contains(c)) else {
        // A suffix with no vowel has nothing to disagree with.
        return true;
    };
    let base_is_back = BACK_VOWELS.contains(&base_vowel);
    match suffix_vowel {
        'e' => !base_is_back,
        'a' => base_is_back,
        'i' => matches!(base_vowel, 'e' | 'i'),
        'ı' => matches!(base_vowel, 'a' | 'ı'),
        'u' => matches!(base_vowel, 'o' | 'u'),
        'ü' => matches!(base_vowel, 'ö' | 'ü'),
        // 'o' and 'ö' never open a Turkish suffix.
        _ => false,
    }
}

/// Case folds `text` for matching, returning the folded string and, for every
/// byte of it, the byte offset in the original it came from.
///
/// # Why a map and not a plain lowercase
///
/// The candidate spans this crate produces are byte ranges into the **original**
/// text, because the replacement step splices the original. Folding changes byte
/// lengths (`İ` is two bytes, `i` is one), so matching on a folded copy and
/// reporting its offsets would put every span after the first non-ASCII
/// character in the wrong place. The map is what keeps the two coordinate
/// systems joined.
///
/// # Why fold at all
///
/// An organization writes its word list in title case and its people write
/// prompts in whatever case they like. `AHMET` in a shouty prompt is the same
/// person, and not matching it is a leak. Turkish makes this worse than usual:
/// `I` lowercases to `ı` and `İ` to `i`, so a Unicode-default fold turns
/// `İSTANBUL` into something that does not match `istanbul`.
pub fn fold(text: &str) -> (String, Vec<usize>) {
    let mut folded = String::with_capacity(text.len());
    let mut origins = Vec::with_capacity(text.len() + 1);
    for (index, character) in text.char_indices() {
        let mut push = |produced: char| {
            let start = folded.len();
            folded.push(produced);
            origins.resize(folded.len(), index);
            debug_assert!(origins.len() > start);
        };
        match character {
            'I' => push('ı'),
            'İ' => push('i'),
            other => {
                for lowered in other.to_lowercase() {
                    push(lowered);
                }
            }
        }
    }
    // One past the end, so a folded end offset always has an original.
    origins.push(text.len());
    (folded, origins)
}

/// Whether a folded character is part of a word for boundary purposes.
///
/// Alphanumeric plus underscore. Turkish letters are alphanumeric under Unicode,
/// so `ş` and `ğ` are inside a word without a table of their own.
pub fn is_word_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn rules() -> AffixRules {
        AffixRules::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."), "tr").unwrap()
    }

    #[test]
    fn the_shipped_turkish_rules_load() {
        let rules = rules();
        assert_eq!(rules.language(), "tr");
        assert!(rules.suffixes.contains("ler"));
    }

    #[test]
    fn a_declared_language_with_no_directory_is_an_error_not_a_default() {
        let error = AffixRules::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."), "de")
            .unwrap_err();
        assert!(matches!(error, AffixError::DirectoryMissing { .. }));
    }

    #[test]
    fn an_empty_suffix_list_is_refused_rather_than_run_as_no_affixes() {
        // The exhausted case at the gate: a rule file that parses and matches
        // nothing under-masks silently, which is what section 11 exists to stop.
        let error = AffixRules::parse(
            "tr",
            r#"
schema_version = "1.0"
language = "tr"
apostrophes = ["'"]
min_base_chars = 3
max_affix_chain = 3
suffixes = []
"#,
        )
        .unwrap_err();
        assert!(matches!(error, AffixError::Malformed { .. }));
    }

    #[test]
    fn the_five_turkish_suffixes_the_milestone_names_and_more_are_recognised() {
        let rules = rules();
        // Milestone 81 asks for at least five. These are the forms that actually
        // occur around a person's name in a Turkish prompt.
        for (base, tail) in [
            ("ahmet", "'in"),  // genitive with apostrophe
            ("ahmet", "'e"),   // dative with apostrophe
            ("ahmet", "'ten"), // ablative with apostrophe
            ("ahmet", "'le"),  // instrumental with apostrophe
            ("ahmet", "ler"),  // plural, no apostrophe
            ("ahmet", "lerden"),
            ("ahmet", "in"),
            ("ahmet", "ten"),
            ("kestane", "ler"),
            ("kestane", "yi"),
        ] {
            assert!(
                rules.tail_is_an_affix(base, tail),
                "{base} + {tail} was not recognised"
            );
        }
    }

    #[test]
    fn a_tail_that_is_not_a_suffix_does_not_extend_a_match() {
        let rules = rules();
        // The `Alice` case: `-ce` is derivational and deliberately absent.
        assert!(!rules.tail_is_an_affix("ali", "ce"));
        assert!(!rules.tail_is_an_affix("ahmet", "oglu"));
        assert!(!rules.tail_is_an_affix("ali", "na"));
        assert!(!rules.tail_is_an_affix("ahmet", ""));
    }

    #[test]
    fn vowel_harmony_rejects_the_wrong_variant() {
        let rules = rules();
        // Front-vowel base takes -de, not -da.
        assert!(rules.tail_is_an_affix("ali", "de"));
        assert!(!rules.tail_is_an_affix("ali", "da"));
        // Back-vowel base takes -da, not -de. `kadir` would be the wrong
        // vector here: its last vowel is `i`, so it is a front-vowel base and
        // `Kadir'den` is the correct Turkish.
        assert!(rules.tail_is_an_affix("orhan", "dan"));
        assert!(!rules.tail_is_an_affix("orhan", "den"));
    }

    #[test]
    fn a_base_shorter_than_the_minimum_only_matches_with_an_apostrophe() {
        let rules = rules();
        assert!(!rules.tail_is_an_affix("ay", "ler"));
        assert!(rules.tail_is_an_affix("ay", "'in"));
    }

    #[test]
    fn the_affix_chain_is_bounded() {
        let rules = rules();
        // Three links is Turkish; a longer run is a coincidence.
        assert!(rules.tail_is_an_affix("ahmet", "lerinden"));
        assert!(!rules.tail_is_an_affix("ahmet", "lerlerlerler"));
    }

    #[test]
    fn folding_keeps_the_dotted_and_dotless_i_apart_and_maps_every_byte_back() {
        let (folded, origins) = fold("İSTANBUL Ilgın");
        assert_eq!(folded, "istanbul ılgın");
        // Every folded byte points at a real byte of the original.
        for origin in &origins {
            assert!(*origin <= "İSTANBUL Ilgın".len());
        }
        assert_eq!(origins.len(), folded.len() + 1);
        assert_eq!(origins[0], 0);
        // `İ` occupies two bytes, so the second folded character starts at 2.
        assert_eq!(origins[1], 2);
    }

    #[test]
    fn folding_an_empty_string_still_produces_a_usable_map() {
        let (folded, origins) = fold("");
        assert!(folded.is_empty());
        assert_eq!(origins, vec![0]);
    }
}
