//! Which layer owns which entity type, and how much a layer's word is worth.
//!
//! # One type, one layer
//!
//! ADR-011 section 1 states the rule and the reason in two sentences:
//!
//! > Varlık türleri, çözüldükleri katmana göre kesin olarak ayrılır. Bir tür
//! > birden fazla katmanda aranmaz.
//!
//! > Biçimi kendini doğrulayan hiçbir tür NER'e bırakılmaz.
//!
//! The rule is not tidiness. Two layers hunting the same type means the same
//! bytes get two verdicts and something downstream has to pick, and the picking
//! rule is where a measurable guarantee quietly turns into a guess. So ownership
//! here is a **total function** over [`EntityType`], the two sets are disjoint
//! and their union is the whole registry, and `detect::merge` has a test that
//! says so.
//!
//! # Where the split falls, and the two places it is not obvious
//!
//! The dividing question is *what decides membership*: the text itself, or the
//! operator's list.
//!
//! - **Layer A** owns every type a published shape decides, with a check digit
//!   where one exists. Nobody has to be asked whether `TR33 0006 1005 1978 6457
//!   8413 26` is an IBAN.
//! - **Layer B** owns every type only the organization can name. No shape says
//!   `Kestane` is a project rather than a chestnut.
//!
//! Two assignments are worth their own paragraph because a contract reads the
//! other way and this module deliberately does not follow it.
//!
//! **`API_KEY` is layer A, so a dictionary entry typed `API_KEY` is refused at
//! load.** `proxy-dictionary.schema.json` lists `API_KEY` among the types a word
//! list may carry; ADR-011 section 1 lists it among layer A's types. ADR beats
//! contract (CLAUDE.md hierarchy) and milestone 80 requires the layer A detector,
//! so the type stays in A and `policy::load` rejects the dictionary entry with a
//! message of its own. Nothing is lost by it: a literal secret with no provider
//! prefix is exactly what `SECRET` is for, and section 4.4 of the spec gives
//! `API_KEY` and `SECRET` the same rung, the same generator and the same length
//! ceiling. The request is filed in `hub/memory/interfaces.md`.
//!
//! **`HOST` is layer B, not layer A.** `proxy-policy.md` section 1 says a host is
//! also detected directly. A bare hostname pattern over prose is the single
//! largest false positive source this component could take on: `node.js`,
//! `v1.2.3`, `dosya.txt`, and every sentence whose full stop is not followed by a
//! space. A false positive here is not free, it rewrites the user's prompt and
//! the model answers a different question. Hosts inside a URL are still caught,
//! because layer A owns `URL` and the alias is minted from its host component
//! (spec section 4.4). A bare internal hostname that the dictionary does not list
//! is a declared gap, not a silent one.

use crate::alias::EntityType;

/// A detection layer, in the order `proxy/spec.md` section 3 names them.
///
/// The ordinal is also the confidence ranking the merge step uses, which is why
/// it is `Ord`: section 3 resolves an overlap in favour of "en yüksek güvenli
/// katman", and the only honest reading of that phrase is the order in which the
/// layers were argued for. A deterministic checksum outranks a hand written list,
/// which outranks a probabilistic model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DetectionLayer {
    /// Statistical span labelling. Not written in this build; present so that the
    /// ordering and the profile derivation are complete rather than implied.
    Ner,
    /// The organization's word list, scanned in one Aho-Corasick pass.
    Dictionary,
    /// Regular expressions plus the check digit rules in `alias::checksum`.
    Pattern,
}

impl DetectionLayer {
    /// Every layer, weakest first. The order is the confidence order.
    pub const ALL: [Self; 3] = [Self::Ner, Self::Dictionary, Self::Pattern];

    /// The name this layer carries in `masking_profile` (`proxy-events.md`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pattern => "pattern",
            Self::Dictionary => "dictionary",
            Self::Ner => "ner",
        }
    }

    /// Whether this build actually runs the layer.
    ///
    /// `false` for NER, and that is a declaration rather than a defect: F4's
    /// scope boundary 1 forbids the code path, ADR-011 section 2 makes the layer
    /// an opt in plug-in, and `degraded_reasons[] = ner_disabled` says so on
    /// every request.
    pub const fn runs_in_this_build(self) -> bool {
        !matches!(self, Self::Ner)
    }
}

/// Which layer is allowed to look for this type.
///
/// Total by construction: the `match` is exhaustive, so adding a variant to
/// [`EntityType`] fails to compile until somebody decides which layer owns it.
/// That is the point. A type with no owner is a type nothing scans for, and the
/// operator would only find out by reading the output.
pub const fn owning_layer(entity: EntityType) -> DetectionLayer {
    match entity {
        // Decided by the text. Four of these carry a check digit, and for those
        // the shape alone is not enough (`pattern::checked`).
        EntityType::Iban
        | EntityType::Tckn
        | EntityType::Vkn
        | EntityType::CreditCard
        | EntityType::Email
        | EntityType::Phone
        | EntityType::Ipv4
        | EntityType::Ipv6
        | EntityType::ApiKey
        | EntityType::Url
        | EntityType::Date => DetectionLayer::Pattern,
        // Decided by the organization's list. See the module docs for why `HOST`
        // and `SECRET` are here and not in A.
        EntityType::Person
        | EntityType::Org
        | EntityType::Loc
        | EntityType::Address
        | EntityType::Host
        | EntityType::Secret => DetectionLayer::Dictionary,
    }
}

/// The types a dictionary entry may claim in this build.
///
/// The intersection with layer A's set is empty, which is the whole reason this
/// function exists rather than a copy of the schema's enum: the schema's list is
/// the contract's, this one is what the loader enforces, and the one place they
/// differ (`API_KEY`) is argued for in the module docs.
pub fn dictionary_may_claim(entity: EntityType) -> bool {
    owning_layer(entity) == DetectionLayer::Dictionary
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn no_type_is_searched_in_more_than_one_layer() {
        // ADR-011 section 1, stated as a partition: every registered type lands
        // in exactly one bucket and no bucket is empty.
        let mut buckets: std::collections::BTreeMap<DetectionLayer, BTreeSet<&str>> =
            std::collections::BTreeMap::new();
        for entity in EntityType::ALL {
            buckets
                .entry(owning_layer(entity))
                .or_default()
                .insert(entity.tag());
        }
        let total: usize = buckets.values().map(BTreeSet::len).sum();
        assert_eq!(
            total,
            EntityType::ALL.len(),
            "a type was counted twice, so it is searched twice"
        );
        assert!(buckets.contains_key(&DetectionLayer::Pattern));
        assert!(buckets.contains_key(&DetectionLayer::Dictionary));
        // And nothing is assigned to the layer this build does not run: a type
        // whose only owner is switched off is a type nothing masks.
        assert!(
            !buckets.contains_key(&DetectionLayer::Ner),
            "a type is owned by a layer that does not run"
        );
    }

    #[test]
    fn the_checksum_bearing_types_belong_to_the_pattern_layer_and_no_list() {
        // proxy-policy.md section 10: moving a self proving decision onto a hand
        // written list is what this refuses.
        for entity in [
            EntityType::Tckn,
            EntityType::Iban,
            EntityType::Vkn,
            EntityType::CreditCard,
        ] {
            assert_eq!(owning_layer(entity), DetectionLayer::Pattern);
            assert!(!dictionary_may_claim(entity), "{entity} is list decidable");
        }
    }

    #[test]
    fn a_dictionary_entry_may_not_claim_a_pattern_type() {
        assert!(!dictionary_may_claim(EntityType::ApiKey));
        assert!(dictionary_may_claim(EntityType::Secret));
        assert!(dictionary_may_claim(EntityType::Host));
        assert!(dictionary_may_claim(EntityType::Person));
    }

    #[test]
    fn the_confidence_order_is_pattern_over_dictionary_over_ner() {
        assert!(DetectionLayer::Pattern > DetectionLayer::Dictionary);
        assert!(DetectionLayer::Dictionary > DetectionLayer::Ner);
        assert!(DetectionLayer::Pattern.runs_in_this_build());
        assert!(DetectionLayer::Dictionary.runs_in_this_build());
        assert!(!DetectionLayer::Ner.runs_in_this_build());
    }
}
