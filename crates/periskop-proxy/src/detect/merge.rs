//! Where the layers become one answer, and where the answer declares itself.
//!
//! # Two jobs, and they belong together
//!
//! **Resolving overlaps.** `proxy/spec.md` section 3: "çakışan aday aralıklarda en
//! yüksek güvenli katman kazanır, eşitlikte en uzun aralık kazanır". Two claims
//! over the same bytes cannot both be honoured, because the replacement step
//! splices one string and there is only one span to splice. The rule is written
//! here, once, rather than inside a detector, so that adding a detector cannot
//! quietly change who wins an argument.
//!
//! **Declaring the profile.** ADR-011 section 2 and `proxy-events.md`: the run has
//! to say which layers actually ran. A build with NER off that reports as if it
//! masked person names is worse than one that masks nothing, because the operator
//! stops looking. So `masking_profile` is derived from the policy, never written
//! by it (`proxy-policy.md` section 4.1), and `ner_disabled` goes out on every
//! request as a **declaration**, not a fault.
//!
//! The two jobs sit in the same module because they are the same claim seen from
//! two sides: what was found, and what was never looked for.

use crate::alias::EntityType;

use super::layer::{owning_layer, DetectionLayer};
use super::span::{sort_candidates, Candidate};

/// Which detection layers actually ran (`proxy-events.md`, `masking_profile`).
///
/// Not a policy key. `proxy-policy.md` section 4.1: it is derived from
/// `detection.ner.enabled`, because the same fact settable in two places is the
/// same fact reported wrongly in one of them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MaskingProfile {
    /// The two deterministic layers. K-11's v1 default and F4's only value.
    #[default]
    PatternDictionary,
    /// Both, plus the statistical layer. Not reachable in this build; present so
    /// that the field is the closed set the contract publishes rather than a
    /// string that grows a value later.
    PatternDictionaryNer,
}

impl MaskingProfile {
    /// The spelling the event record carries.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PatternDictionary => "pattern+dictionary",
            Self::PatternDictionaryNer => "pattern+dictionary+ner",
        }
    }

    /// Derives the profile from the one key it is allowed to depend on.
    pub const fn derived_from(ner_enabled: bool) -> Self {
        if ner_enabled {
            Self::PatternDictionaryNer
        } else {
            Self::PatternDictionary
        }
    }

    /// The layers this profile claims to run.
    pub fn layers(self) -> Vec<DetectionLayer> {
        match self {
            Self::PatternDictionary => vec![DetectionLayer::Pattern, DetectionLayer::Dictionary],
            Self::PatternDictionaryNer => DetectionLayer::ALL.to_vec(),
        }
    }
}

/// The closed vocabulary of `degraded_reasons[]` (`proxy-events.md`).
///
/// Closed, and the closure is the point: `x-periskop-degraded` takes its value
/// verbatim from this list, so a reason that is not here cannot be declared, and
/// a gap that cannot be declared is a silent gap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DegradedReason {
    /// The policy keeps NER off. K-11's default: a declaration, not a fault.
    NerDisabled,
    /// The word list could not be read and `dictionary.required = false`.
    DictionaryUnavailable,
    /// Inside a fenced code block only layer A ran (`code_block_policy =
    /// "pattern-only"`).
    CodeBlockSkipped,
    /// Structured tool-call or tool-result arguments reached the provider
    /// unmasked (`proxy-api.md`, "Tool-call argümanları": the default is to pass
    /// and to declare, and this is one of the three places the declaration is
    /// made).
    ToolArgumentsUnmasked,
    /// A whole endpoint with no masking passed through: the Responses and
    /// Assistants surfaces (roadmap F4 phase boundary item 4). Field level and
    /// endpoint level are counted apart on purpose, because they are two
    /// different sizes of gap.
    EndpointUnsupportedPassthrough,
}

impl DegradedReason {
    /// The spelling the header and the event carry.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NerDisabled => "ner_disabled",
            Self::DictionaryUnavailable => "dictionary_unavailable",
            Self::CodeBlockSkipped => "code_block_skipped",
            Self::ToolArgumentsUnmasked => "tool_arguments_unmasked",
            Self::EndpointUnsupportedPassthrough => "endpoint_unsupported_passthrough",
        }
    }

    /// Every reason this build can declare.
    ///
    /// Shorter than the schema's list, which also holds the four NER and vault
    /// restart reasons no code path in F4 reaches. Named so that the header
    /// renderer can be tested against a closed set rather than against whichever
    /// reasons a particular request happened to raise.
    pub const ALL: [Self; 5] = [
        Self::NerDisabled,
        Self::DictionaryUnavailable,
        Self::CodeBlockSkipped,
        Self::ToolArgumentsUnmasked,
        Self::EndpointUnsupportedPassthrough,
    ];
}

/// The sentence ADR-011 section 2 requires to reach the user verbatim.
///
/// Turkish, because it is the operator-facing declaration the ADR quotes, not a
/// code comment. Held as a constant so that the wording cannot drift between the
/// report, the response and the test that checks it is there.
pub const NER_DISABLED_DECLARATION: &str = "sözlükte olmayan kişi/kurum adları maskelenmemiştir";

/// What one scan concluded, and what it admits it did not look for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    /// Surviving candidates, sorted by position, never overlapping.
    pub candidates: Vec<Candidate>,
    /// Which layers ran.
    pub profile: MaskingProfile,
    /// Sorted and deduplicated, so the header value is deterministic.
    pub degraded_reasons: Vec<DegradedReason>,
}

impl Detection {
    /// The declaration lines that must appear in the response and the report.
    ///
    /// Non-empty whenever NER is off, which in this build is always. A caller
    /// that renders a report renders these; a caller that renders none of them
    /// is what `every_result_declares_the_layer_that_did_not_run` catches.
    pub fn declarations(&self) -> Vec<&'static str> {
        self.degraded_reasons
            .iter()
            .filter_map(|reason| match reason {
                DegradedReason::NerDisabled => Some(NER_DISABLED_DECLARATION),
                _ => None,
            })
            .collect()
    }
}

/// Merges the layers' candidates and attaches the profile declaration.
///
/// `extra` carries reasons the caller already knows about (an unavailable word
/// list, a code block that skipped layers); `ner_disabled` is added here because
/// it is a property of the build rather than of the request.
pub fn merge(
    pattern: Vec<Candidate>,
    dictionary: Vec<Candidate>,
    profile: MaskingProfile,
    extra: &[DegradedReason],
) -> Detection {
    let mut all: Vec<Candidate> = pattern
        .into_iter()
        .chain(dictionary)
        .filter(|candidate| !candidate.is_empty())
        .collect();

    // Priority order: confidence first, then width, then position, then type.
    // Every tie is broken by something total, because a partial order here would
    // make the alias numbering depend on which detector reported first.
    all.sort_by(|a, b| {
        b.layer
            .cmp(&a.layer)
            .then(b.len().cmp(&a.len()))
            .then(a.start.cmp(&b.start))
            .then(a.entity.cmp(&b.entity))
    });

    let mut kept: Vec<Candidate> = Vec::with_capacity(all.len());
    for candidate in all {
        if kept.iter().any(|held| held.overlaps(&candidate)) {
            continue;
        }
        kept.push(candidate);
    }
    sort_candidates(&mut kept);

    let mut reasons: Vec<DegradedReason> = extra.to_vec();
    if !profile.layers().contains(&DetectionLayer::Ner) {
        reasons.push(DegradedReason::NerDisabled);
    }
    reasons.sort_unstable();
    reasons.dedup();

    Detection {
        candidates: kept,
        profile,
        degraded_reasons: reasons,
    }
}

/// Whether every registered type is claimed by exactly one layer.
///
/// The runtime form of ADR-011 section 1's rule, exposed so that the admin
/// projection and the tests read the same function rather than two copies of it.
pub fn every_type_has_exactly_one_layer() -> bool {
    EntityType::ALL
        .into_iter()
        .all(|entity| DetectionLayer::ALL.contains(&owning_layer(entity)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::alias::{AliasKey, AliasStyle, Minter};
    use crate::detect::{dictionary::Dictionary, pattern};

    fn candidate(entity: EntityType, start: usize, end: usize) -> Candidate {
        Candidate::new(entity, start, end)
    }

    #[test]
    fn the_higher_confidence_layer_wins_an_overlap_even_when_it_is_the_shorter_claim() {
        // Spec section 3: confidence first, width only as the tie-break. The
        // dictionary claim here is deliberately the WIDER one, because with two
        // claims of equal width the width rule alone would pick the same winner
        // and this test would prove nothing about layers. A mutation run that
        // deleted the layer comparison escaped exactly that way.
        let merged = merge(
            vec![candidate(EntityType::Iban, 20, 46)],
            vec![candidate(EntityType::Org, 10, 50)],
            MaskingProfile::PatternDictionary,
            &[],
        );
        assert_eq!(merged.candidates.len(), 1);
        assert_eq!(
            merged.candidates[0].entity,
            EntityType::Iban,
            "the longer dictionary claim outranked a deterministic checksum"
        );
        assert_eq!(merged.candidates[0].layer, DetectionLayer::Pattern);
    }

    #[test]
    fn at_equal_confidence_the_longest_range_wins() {
        // A card and a ten digit run inside it. Both are layer A, so width
        // decides, and the card is the entity.
        let merged = merge(
            vec![
                candidate(EntityType::CreditCard, 0, 16),
                candidate(EntityType::Vkn, 3, 13),
            ],
            Vec::new(),
            MaskingProfile::PatternDictionary,
            &[],
        );
        assert_eq!(merged.candidates.len(), 1);
        assert_eq!(merged.candidates[0].entity, EntityType::CreditCard);
    }

    #[test]
    fn adjacent_candidates_both_survive() {
        // Touching is not overlapping. Two numbers separated by a comma are two
        // entities, and dropping one of them is a leak.
        let merged = merge(
            vec![
                candidate(EntityType::Tckn, 0, 11),
                candidate(EntityType::Tckn, 11, 22),
            ],
            Vec::new(),
            MaskingProfile::PatternDictionary,
            &[],
        );
        assert_eq!(merged.candidates.len(), 2);
    }

    #[test]
    fn the_merge_is_deterministic_whatever_order_the_layers_report_in() {
        let pattern_side = vec![
            candidate(EntityType::Email, 5, 20),
            candidate(EntityType::Url, 5, 12),
        ];
        let dictionary_side = vec![
            candidate(EntityType::Person, 30, 35),
            candidate(EntityType::Org, 30, 40),
        ];
        let forward = merge(
            pattern_side.clone(),
            dictionary_side.clone(),
            MaskingProfile::PatternDictionary,
            &[],
        );
        let mut reversed_pattern = pattern_side;
        reversed_pattern.reverse();
        let mut reversed_dictionary = dictionary_side;
        reversed_dictionary.reverse();
        let backward = merge(
            reversed_pattern,
            reversed_dictionary,
            MaskingProfile::PatternDictionary,
            &[],
        );
        assert_eq!(forward, backward);
    }

    #[test]
    fn no_type_is_searched_in_more_than_one_layer() {
        assert!(every_type_has_exactly_one_layer());
        // And the two running layers do not both claim anything: the pattern
        // scanner never emits a type the dictionary may carry, and the reverse.
        let dictionary = Dictionary::parse(
            "schema_version = \"1.0\"\ndictionary_id = \"x\"\n[[entries]]\nvalue = \"Kestane\"\ntype = \"ORG\"\n",
        )
        .unwrap();
        let text = "Kestane projesi, TCKN 10000000146, mail a@b.com";
        let from_pattern: Vec<EntityType> =
            pattern::scan(text).into_iter().map(|c| c.entity).collect();
        let from_dictionary: Vec<EntityType> = dictionary
            .scan(text)
            .into_iter()
            .map(|c| c.entity)
            .collect();
        for entity in &from_pattern {
            assert!(!from_dictionary.contains(entity), "{entity} came from both");
            assert_eq!(owning_layer(*entity), DetectionLayer::Pattern);
        }
        for entity in &from_dictionary {
            assert_eq!(owning_layer(*entity), DetectionLayer::Dictionary);
        }
    }

    #[test]
    fn every_result_declares_the_layer_that_did_not_run() {
        // ADR-011 section 2: the declaration goes out on every request, even one
        // that found nothing, because "we masked nothing" and "we did not look"
        // are different sentences.
        for candidates in [Vec::new(), vec![candidate(EntityType::Tckn, 0, 11)]] {
            let merged = merge(
                candidates,
                Vec::new(),
                MaskingProfile::PatternDictionary,
                &[],
            );
            assert!(merged
                .degraded_reasons
                .contains(&DegradedReason::NerDisabled));
            assert_eq!(merged.profile.as_str(), "pattern+dictionary");
            assert_eq!(
                merged.declarations(),
                vec!["sözlükte olmayan kişi/kurum adları maskelenmemiştir"]
            );
        }
    }

    #[test]
    fn a_profile_that_runs_ner_does_not_declare_it_disabled() {
        // The negative half. Without it, `ner_disabled` could be hard-coded and
        // the declaration test above would still pass.
        let merged = merge(
            Vec::new(),
            Vec::new(),
            MaskingProfile::PatternDictionaryNer,
            &[],
        );
        assert!(!merged
            .degraded_reasons
            .contains(&DegradedReason::NerDisabled));
        assert!(merged.declarations().is_empty());
        assert_eq!(merged.profile.as_str(), "pattern+dictionary+ner");
    }

    #[test]
    fn the_profile_is_derived_from_the_one_key_it_may_depend_on() {
        assert_eq!(
            MaskingProfile::derived_from(false),
            MaskingProfile::PatternDictionary
        );
        assert_eq!(
            MaskingProfile::derived_from(true),
            MaskingProfile::PatternDictionaryNer
        );
        assert_eq!(MaskingProfile::default(), MaskingProfile::PatternDictionary);
    }

    #[test]
    fn extra_reasons_are_carried_sorted_and_deduplicated() {
        let merged = merge(
            Vec::new(),
            Vec::new(),
            MaskingProfile::PatternDictionary,
            &[
                DegradedReason::CodeBlockSkipped,
                DegradedReason::DictionaryUnavailable,
                DegradedReason::CodeBlockSkipped,
            ],
        );
        let spelled: Vec<&str> = merged
            .degraded_reasons
            .iter()
            .map(|reason| reason.as_str())
            .collect();
        assert_eq!(
            spelled,
            vec![
                "ner_disabled",
                "dictionary_unavailable",
                "code_block_skipped"
            ]
        );
    }

    #[test]
    fn a_rung_i_alias_is_never_detected_again() {
        // ADR-010 section 5.1's deliberate complementarity, checked across the
        // two modules that have to agree on it: rung `I` fails the very validator
        // layer A applies, so an alias cannot be re-masked on the next turn and
        // the conversation cannot end up two aliases deep on one value.
        let mut minter = Minter::new(
            AliasKey::from_key_bytes([7u8; 32]),
            AliasStyle::TypePreserving,
        );
        let stripe = crate::detect::sample::stripe_key();
        let github = crate::detect::sample::github_token();
        for (entity, source) in [
            (EntityType::Iban, "TR330006100519786457841326"),
            (EntityType::Tckn, "10000000146"),
            (EntityType::Vkn, "4980312200"),
            (EntityType::ApiKey, stripe.as_str()),
            (EntityType::Secret, github.as_str()),
        ] {
            let minted = minter.mint(entity, source).unwrap();
            let found = pattern::scan(&minted.alias);
            assert!(
                !found.iter().any(|candidate| candidate.entity == entity),
                "alias {} for {entity} was detected as {entity} again",
                minted.alias
            );
        }
    }

    #[test]
    fn a_rung_r_card_alias_is_detected_again_and_that_is_the_designed_answer() {
        // The honest other half, written down rather than left as a surprise.
        // `CREDIT_CARD` enters the ladder at rung `R`, which means its alias is a
        // **published test PAN**: a well formed card by construction, so layer A
        // finds it, exactly as it finds the real one. The complementarity
        // argument does not apply here and pretending it does would be a false
        // claim about P-0's coverage.
        //
        // What covers this case instead is spec section 4.4's other rule: an
        // alias that already appears in the input is reserved out of the pool
        // (`Minter::reserve_literal`), so the second turn does not mint a second
        // alias for the first one's text. This test is the link between the two
        // mechanisms; without it, removing the reservation would leave nothing
        // red.
        let mut minter = Minter::new(
            AliasKey::from_key_bytes([9u8; 32]),
            AliasStyle::TypePreserving,
        );
        let minted = minter
            .mint(EntityType::CreditCard, "4242424242424242")
            .unwrap();
        let found = pattern::scan(&minted.alias);
        assert!(
            found
                .iter()
                .any(|candidate| candidate.entity == EntityType::CreditCard),
            "a published test PAN stopped looking like a card: {}",
            minted.alias
        );
        // And the alias is not free to be minted a second time.
        assert!(!minter.is_free(&minted.alias));
    }
}
