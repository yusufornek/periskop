//! Rung `O`: the alias that claims nothing.
//!
//! `PSK_<TAG>_<16 hex>` is what ADR-004 and ADR-007 originally specified for
//! every type, and ADR-010 kept it for two jobs rather than deleting it.
//!
//! It is the **floor of the ladder**: a type whose evidence cannot be shown
//! falls here, which is P-0 being applied rather than a generator giving up. A
//! country with no published numbering citation produces `PSK_PHONE_...`, and
//! the alias says exactly as much as the proxy can prove.
//!
//! It is also the **whole of the `opaque` alias style**: an operator who does
//! not want realistic looking substitutes at all sets `alias_style = "opaque"`
//! and every type renders here (ADR-010 section 5.2).
//!
//! Sixteen hexadecimal characters is 64 bits drawn from the session keyed
//! stream. Two values collide inside one session with probability far below the
//! per session alias ceiling's reach, and the collision walk in [`super::mint`]
//! catches the case anyway.

use super::derive::SeedStream;
use super::entity::EntityType;

/// Hexadecimal characters in the body of an opaque alias.
///
/// Part of the length contract: `21 + len(TAG)` in [`super::limits`] counts
/// these sixteen. Changing it changes every type's ceiling.
pub const HEX_CHARS: usize = 16;

/// `PSK_<TAG>_<16 hex>`.
pub fn render(entity: EntityType, stream: &mut SeedStream) -> String {
    format!("PSK_{}_{}", entity.tag(), stream.hex(HEX_CHARS))
}

/// The invariant rung `O` has to keep (ADR-010 section 5.1).
///
/// Written here beside the generator rather than only in the test, so that the
/// gate and the generator cannot drift apart.
pub fn is_opaque(alias: &str) -> bool {
    alias.starts_with("PSK_")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::derive::SeedStream;
    use super::*;

    fn stream(byte: u8) -> SeedStream {
        SeedStream::new(&[byte; 32]).unwrap()
    }

    #[test]
    fn every_type_renders_an_opaque_alias_of_the_declared_length() {
        for entity in EntityType::ALL {
            let alias = render(entity, &mut stream(0x11));
            assert!(is_opaque(&alias), "{alias}");
            assert_eq!(alias.len(), 21 + entity.tag().len(), "{alias}");
            assert!(
                alias.starts_with(&format!("PSK_{}_", entity.tag())),
                "{alias}"
            );
            let body = alias.rsplit('_').next().unwrap_or_default();
            assert_eq!(body.len(), HEX_CHARS);
            assert!(body
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        }
    }

    #[test]
    fn the_body_follows_the_seed_and_nothing_else() {
        let first = render(EntityType::Person, &mut stream(0x01));
        let same = render(EntityType::Person, &mut stream(0x01));
        let other = render(EntityType::Person, &mut stream(0x02));
        assert_eq!(first, same);
        assert_ne!(first, other);
    }
}
