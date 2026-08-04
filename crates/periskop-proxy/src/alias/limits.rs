//! Length ceilings: the one place a generator's output bound is written down.
//!
//! # Why a ceiling is load bearing
//!
//! ADR-010's carrying engineering constraint is that no generator may derive an
//! **unbounded** length from its source. The streaming state machine
//! (`proxy/spec.md` section 6.2) holds bytes back so that an alias split across
//! two chunks is never emitted half masked, and the size of that hold is
//! `W = L_max - 1`. If any alias could be as long as its source value, the hold
//! is as large as the response and the latency budget is gone.
//!
//! So every type declares a static ceiling here, and every generator is checked
//! against it rather than trusted to respect it.
//!
//! # The formula, and why the opaque base is inside it
//!
//! ```text
//! L_type_max(t) = max( type_preserving_bound(t), 21 + len(ENTITY_TAG(t)) )
//! ```
//!
//! The second term is the opaque alias `PSK_<TAG>_<16 hex>`: four bytes of
//! prefix, the tag, one underscore, sixteen hex characters. It is inside the
//! formula because **every** type can fall to rung `O` (ADR-010 section 5.1), so
//! a ceiling that only covered the type preserving generator would be exceeded by
//! the fallback the ladder is built around. The buffer ceiling is a safety
//! constant; it may be loose, it may not be small.
//!
//! ADR-010 section 2 also prints a table of numbers. Where the formula and that
//! table disagree, the larger of the two is taken and the formula's term is the
//! table's value, which is how `PERSON` ends up at 27 rather than the printed 26:
//! `PSK_PERSON_` plus sixteen hex digits does not fit in 26 bytes, and a ceiling
//! that a real alias exceeds is worse than a table that reads untidily. The same
//! ADR corrected the opaque ceiling from 28 to 32 in D-14 for this exact reason.

use super::entity::{AliasStyle, EntityType};

/// Bytes an opaque alias spends on everything except the tag:
/// `"PSK_"` + `"_"` + sixteen hex characters.
pub const OPAQUE_OVERHEAD: usize = 4 + 1 + 16;

/// The ceiling of the type preserving generator alone, before the opaque base is
/// taken into account.
///
/// Each number is ADR-010 section 2's table entry, and the comment is the
/// construction it bounds. Changing one of these is changing a published
/// contract, not tuning a buffer.
const fn type_preserving_bound(entity: EntityType) -> usize {
    match entity {
        // Label plus index: ADR-010 allows a tag of ten and an index of five.
        EntityType::Person | EntityType::Org | EntityType::Loc | EntityType::Address => 26,
        // userNNNNN@example-XX.invalid
        EntityType::Email => 40,
        // E.164 at most fifteen digits, plus the separators a format keeps.
        EntityType::Phone => 26,
        // ISO 13616 allows thirty four characters, plus grouping spaces.
        EntityType::Iban => 42,
        // Eleven digits fixed; the opaque base is what dominates.
        EntityType::Tckn => 32,
        // Ten digits fixed; the opaque base is what dominates.
        EntityType::Vkn => 31,
        // Nineteen digits plus separators; the opaque base is what dominates.
        EntityType::CreditCard => 32,
        // Declared for the ceiling table only. No date alias is minted in this
        // phase (ADR-010 section 7), so nothing of this type ever enters the
        // automaton.
        EntityType::Date => 32,
        // Fifteen characters fixed; the opaque base is what dominates.
        EntityType::Ipv4 => 25,
        // RFC 4291's longest textual form.
        EntityType::Ipv6 => 45,
        // hostNN.example-a.invalid, with room for a longer label.
        EntityType::Host => 64,
        // A URL is never aliased whole (ADR-010 section 2). Its host component is
        // aliased under HOST, so it borrows that bound and carries none of the
        // source URL's length.
        EntityType::Url => 64,
        // Prefix plus a body rounded to the 32/64/128 length class.
        EntityType::ApiKey | EntityType::Secret => 128,
    }
}

/// The bytes an opaque alias of this type occupies.
pub const fn opaque_bound(entity: EntityType) -> usize {
    OPAQUE_OVERHEAD + entity.tag().len()
}

/// The ceiling for one type: no alias of this type may be longer, in either
/// style.
pub const fn l_type_max(entity: EntityType) -> usize {
    let preserving = type_preserving_bound(entity);
    let opaque = opaque_bound(entity);
    if preserving > opaque {
        preserving
    } else {
        opaque
    }
}

/// The compile time ceiling over every type, in the type preserving style.
///
/// This is the number the streaming buffer and the worst case latency analysis
/// are built on (`W_max = L_MAX_STATIC - 1 = 127`).
pub const L_MAX_STATIC: usize = max_over_all(false);

/// The compile time ceiling in the opaque style, where every type is a
/// `PSK_<TAG>_<16 hex>` string and the longest tag decides.
pub const L_MAX_STATIC_OPAQUE: usize = max_over_all(true);

/// Folds the ceiling over the whole registry at compile time.
///
/// Written as a loop rather than a hand copied number so that adding a type
/// updates the constant. A forgotten update here would not fail loudly: it would
/// hold back one byte too few and cut an alias in half in a stream.
const fn max_over_all(opaque_only: bool) -> usize {
    let mut largest = 0;
    let mut index = 0;
    while index < EntityType::ALL.len() {
        let entity = EntityType::ALL[index];
        let bound = if opaque_only {
            opaque_bound(entity)
        } else {
            l_type_max(entity)
        };
        if bound > largest {
            largest = bound;
        }
        index += 1;
    }
    largest
}

/// The ceiling the policy's alias style selects.
///
/// `proxy-event.schema.json` restricts `stream_stats.l_max_static` to exactly
/// these two values, which is the contract this function has to keep producing.
pub const fn l_max_static(style: AliasStyle) -> usize {
    match style {
        AliasStyle::TypePreserving => L_MAX_STATIC,
        AliasStyle::Opaque => L_MAX_STATIC_OPAQUE,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_formula_holds_for_every_type_including_the_opaque_base() {
        for entity in EntityType::ALL {
            let expected = type_preserving_bound(entity).max(OPAQUE_OVERHEAD + entity.tag().len());
            assert_eq!(
                l_type_max(entity),
                expected,
                "{entity} breaks L_type_max = max(generator bound, 21 + len(tag))"
            );
            // The second term is not decorative: every type can fall to rung O,
            // so its ceiling has to cover the opaque form.
            assert!(
                l_type_max(entity) >= opaque_bound(entity),
                "{entity} cannot hold its own opaque alias"
            );
        }
    }

    #[test]
    fn the_opaque_overhead_is_the_length_of_the_opaque_form_itself() {
        // Measured from the string rather than restated, so that changing the
        // opaque format without changing this constant fails here instead of
        // truncating a stream buffer somewhere far away.
        let mut stream = super::super::derive::SeedStream::new(&[0xAB; 32]).unwrap();
        let alias = super::super::opaque::render(EntityType::CreditCard, &mut stream);
        assert_eq!(
            alias.len(),
            OPAQUE_OVERHEAD + EntityType::CreditCard.tag().len()
        );
        assert_eq!(alias.len(), 32);
    }

    #[test]
    fn l_max_static_is_128_type_preserving_and_32_opaque() {
        // The two values `proxy-event.schema.json` allows for
        // stream_stats.l_max_static. A third value would be a schema violation
        // reported by every run.
        assert_eq!(L_MAX_STATIC, 128);
        assert_eq!(L_MAX_STATIC_OPAQUE, 32);
        assert_eq!(l_max_static(AliasStyle::TypePreserving), 128);
        assert_eq!(l_max_static(AliasStyle::Opaque), 32);

        // And they are the maxima of the table rather than numbers beside it.
        let preserving = EntityType::ALL.map(l_type_max).into_iter().max().unwrap();
        let opaque = EntityType::ALL.map(opaque_bound).into_iter().max().unwrap();
        assert_eq!(preserving, L_MAX_STATIC);
        assert_eq!(opaque, L_MAX_STATIC_OPAQUE);
    }

    #[test]
    fn the_longest_tag_is_what_the_opaque_ceiling_rests_on() {
        // D-14 corrected this ceiling from 28 to 32 because the longest tag was
        // not counted. If a longer tag is ever added, this fails and the ceiling
        // is recomputed rather than silently exceeded.
        let longest = EntityType::ALL
            .into_iter()
            .max_by_key(|entity| entity.tag().len())
            .unwrap();
        assert_eq!(longest, EntityType::CreditCard);
        assert_eq!(longest.tag().len(), 11);
        assert_eq!(L_MAX_STATIC_OPAQUE, OPAQUE_OVERHEAD + 11);
    }

    #[test]
    fn every_ceiling_is_at_least_the_number_adr_010_prints() {
        // The ADR's own table, transcribed. Where the formula produces more (the
        // label types, whose opaque form does not fit in 26 bytes) the larger
        // value wins, because a buffer ceiling may not be wrong on the small
        // side. Where it produces less the ADR is what stands.
        let printed = [
            (EntityType::Person, 26),
            (EntityType::Org, 26),
            (EntityType::Loc, 26),
            (EntityType::Address, 26),
            (EntityType::Email, 40),
            (EntityType::Phone, 26),
            (EntityType::Iban, 42),
            (EntityType::Tckn, 32),
            (EntityType::Vkn, 31),
            (EntityType::CreditCard, 32),
            (EntityType::Date, 32),
            (EntityType::Ipv4, 25),
            (EntityType::Ipv6, 45),
            (EntityType::Host, 64),
            (EntityType::ApiKey, 128),
            (EntityType::Secret, 128),
        ];
        for (entity, adr) in printed {
            assert!(
                l_type_max(entity) >= adr,
                "{entity}: {} is below the {adr} ADR-010 section 2 prints",
                l_type_max(entity)
            );
        }
    }
}
