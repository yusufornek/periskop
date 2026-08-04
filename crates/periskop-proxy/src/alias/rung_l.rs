//! Rung `L`: a counted label, for the types where realism buys nothing.
//!
//! `PERSON_1`, `ORG_2`, `ADDRESS_1`. No value is drawn from the type's value
//! space at all, which is why this sits beside the ladder rather than on it:
//! there is no allocation question to answer, because nothing that could be
//! allocated is produced.
//!
//! # Why not a plausible name
//!
//! What a model needs from a masked person is **distinguishability**, not
//! realism: that the person in the second paragraph is the person in the first,
//! and that the other one is somebody else. A label delivers exactly that. A
//! generated name delivers it too, and brings a real person's name along with
//! it: every plausible Turkish name belongs to thousands of people, and an
//! address that reads correctly is somebody's front door. ADR-010 puts `ADDRESS`
//! here for that reason in one line: "an invented address is a real address".
//!
//! # The index
//!
//! Counted per type, per session, starting at one, in the order values are first
//! seen. The count is state rather than a hash so that the numbers a reader sees
//! are small and stable, and the ordering is the request's own order, which is
//! deterministic for a given request.

use super::entity::EntityType;

/// `TAG_index`.
pub fn render(entity: EntityType, index: u32) -> String {
    format!("{}_{index}", entity.tag())
}

/// The invariant rung `L` has to keep (ADR-010 section 5.1): `^[A-Z]+_[0-9]+$`.
///
/// Matched by hand rather than with a regular expression, because this crate
/// carries no regular expression engine for the sake of one pattern and because
/// the shape is four lines.
pub fn is_counted_label(alias: &str) -> bool {
    let Some((tag, index)) = alias.split_once('_') else {
        return false;
    };
    !tag.is_empty()
        && tag.chars().all(|character| character.is_ascii_uppercase())
        && !index.is_empty()
        && index.chars().all(|character| character.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alias::entity::{LadderRung, Minting};

    #[test]
    fn every_label_type_renders_the_shape_the_invariant_demands() {
        for entity in EntityType::ALL {
            if entity.minting() != Minting::EntersAt(LadderRung::Label) {
                continue;
            }
            for index in [1u32, 9, 10, 4321, 99999] {
                let alias = render(entity, index);
                assert!(is_counted_label(&alias), "{alias}");
                assert!(alias.starts_with(entity.tag()), "{alias}");
                assert!(alias.ends_with(&index.to_string()), "{alias}");
            }
        }
    }

    #[test]
    fn a_label_type_tag_carries_no_underscore_of_its_own() {
        // `^[A-Z]+_[0-9]+$` has room for exactly one underscore. A label type
        // whose tag contained one (CREDIT_CARD, if it were ever moved to this
        // rung) would render an alias its own invariant rejects, so the shape of
        // the tag is part of the rung's contract.
        for entity in EntityType::ALL {
            if entity.minting() == Minting::EntersAt(LadderRung::Label) {
                assert!(
                    entity.tag().chars().all(|c| c.is_ascii_uppercase()),
                    "{entity} carries a character the label pattern refuses"
                );
            }
        }
    }

    #[test]
    fn the_matcher_refuses_what_is_not_a_label() {
        assert!(!is_counted_label("PSK_PERSON_ab12cd34ab12cd34"));
        assert!(!is_counted_label("PERSON"));
        assert!(!is_counted_label("PERSON_"));
        assert!(!is_counted_label("_1"));
        assert!(!is_counted_label("person_1"));
        assert!(!is_counted_label("PERSON_1a"));
        assert!(is_counted_label("CREDIT_1"));
    }
}
