//! `PHONE`: a published fiction range, then a length no plan allows, then
//! opaque.
//!
//! # Why this type walks three rungs
//!
//! Telephone numbering is national, so what can be proved about a number depends
//! entirely on which regulator published what. Three cases, and the ladder takes
//! them in order:
//!
//! 1. **The country publishes a fiction range.** Ofcom sets aside
//!    `07700 900000` to `07700 900999` for drama; the North American plan
//!    reserves the line numbers `555-0100` to `555-0199`. Those are rung `R`.
//! 2. **The country publishes a maximum length and no fiction range.** Turkey is
//!    the worked example. A number one digit past the maximum cannot be
//!    allocated to anybody, because the plan has no room for it, and a validator
//!    answers `TOO_LONG`. That is rung `I`.
//! 3. **This build knows nothing published about the country.** Then nothing can
//!    be proved and the alias is opaque, which is rung `O` and is KG-011.
//!
//! # The range that was removed
//!
//! `+90 555 ...` used to be this generator's Turkish output, on the claim that
//! it was an unallocated range. It is not: `555` sits inside Turkey's allocated
//! mobile block, so the old generator handed out numbers that can ring a real
//! phone. The rung `I` construction below cannot produce it, and not by
//! filtering: the national number it builds starts with a zero, which no
//! national significant number does, and it carries one digit more than the plan
//! allows. Two independent published rules, both broken on purpose.

use super::catalog;
use super::checksum::Verdict;
use super::derive::SeedStream;
use super::entity::{EntityType, LadderRung};
use super::mint::Rendered;
use super::opaque;

/// A phone alias for this source number.
pub fn render(stream: &mut SeedStream, source: &str, attempt: u32, pool_attempts: u32) -> Rendered {
    let Some(country) = catalog::country_code_of(source) else {
        // No country code, or one this build has no citation for. Nothing can be
        // proved, so nothing type preserving is produced (KG-011).
        return Rendered {
            alias: opaque::render(EntityType::Phone, stream),
            rung: LadderRung::Opaque,
            pool_exhausted: false,
            length_class_capped: false,
        };
    };
    let Some(plan) = catalog::plan_for_country(country) else {
        return Rendered {
            alias: opaque::render(EntityType::Phone, stream),
            rung: LadderRung::Opaque,
            pool_exhausted: false,
            length_class_capped: false,
        };
    };

    if let Some(fiction) = plan.fiction {
        if attempt < pool_attempts {
            let head = area_code(stream, fiction.head_digits);
            let tail = stream.digits(fiction.tail_digits);
            return Rendered {
                alias: format!("+{country}{head}{}{tail}", fiction.block),
                rung: LadderRung::Reserved,
                pool_exhausted: false,
                length_class_capped: false,
            };
        }
    }

    // One digit past the published maximum, behind a leading zero.
    let national = stream.digits(plan.national_digits);
    Rendered {
        alias: format!("+{country}0{national}"),
        rung: LadderRung::Invalid,
        pool_exhausted: plan.fiction.is_some(),
        length_class_capped: false,
    }
}

/// Digits in front of a reserved block, where the plan leaves them free.
///
/// For the North American plan those digits are an area code, and the format is
/// `NXX`: the first digit runs from two to nine and `N11` codes are service
/// codes rather than areas. Producing one that breaks the format would put the
/// alias outside the published reservation, which is the one thing rung `R` may
/// not do.
fn area_code(stream: &mut SeedStream, digits: usize) -> String {
    if digits == 0 {
        return String::new();
    }
    let mut out = String::with_capacity(digits);
    out.push(char::from(b'2' + stream.digit() % 8));
    for _ in 1..digits {
        out.push(char::from(b'0' + stream.digit()));
    }
    if digits == 3 && out.ends_with("11") {
        out.pop();
        out.push('2');
    }
    out
}

/// What the published national numbering plan says about this number.
///
/// Three valued on purpose. A number from a country with no entry in the rule
/// file is not "invalid", it is unknown, and answering `Invalid` there would let
/// the P-0 gate accept an alias on evidence that does not exist.
pub fn plan_verdict(alias: &str) -> Verdict {
    let Some(country) = catalog::country_code_of(alias) else {
        return Verdict::NoDocumentedCheck;
    };
    let Some(plan) = catalog::plan_for_country(country) else {
        return Verdict::NoDocumentedCheck;
    };
    let digits: String = alias.chars().filter(char::is_ascii_digit).collect();
    let Some(national) = digits.strip_prefix(country) else {
        return Verdict::NoDocumentedCheck;
    };
    if national.is_empty() || national.len() > plan.national_digits || national.starts_with('0') {
        return Verdict::Invalid;
    }
    Verdict::Valid
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const POOL_ATTEMPTS: u32 = 12;

    fn stream(byte: u8) -> SeedStream {
        SeedStream::new(&[byte; 32]).unwrap()
    }

    #[test]
    fn a_turkish_number_lands_on_rung_i_and_never_inside_the_old_range() {
        // The acceptance criterion for milestone 77, over the seed space: not
        // one Turkish alias may read as `+90 555`, in any formatting, on any
        // rung. The construction makes it structural rather than filtered.
        let mut produced = 0;
        for byte in 0..=255u8 {
            for attempt in [0u32, 1, 5, 12, 40] {
                let alias = render(&mut stream(byte), "+905321234567", attempt, POOL_ATTEMPTS);
                assert_eq!(alias.rung, LadderRung::Invalid, "{}", alias.alias);
                assert!(alias.alias.starts_with("+900"), "{}", alias.alias);
                assert!(!alias.alias.starts_with("+90555"), "{}", alias.alias);
                assert!(!alias.alias.contains("+90 555"), "{}", alias.alias);
                // One digit past the published maximum.
                let national = alias.alias.trim_start_matches("+90");
                assert_eq!(national.len(), 11, "{}", alias.alias);
                assert_eq!(plan_verdict(&alias.alias), Verdict::Invalid);
                assert!(!catalog::phone_is_documented(&alias.alias));
                produced += 1;
            }
        }
        assert_eq!(produced, 256 * 5);
    }

    #[test]
    fn a_country_with_a_published_fiction_range_stays_inside_it() {
        let mut produced = 0;
        for byte in 0..=255u8 {
            for (source, country) in [("+447911123456", "44"), ("+12125551234", "1")] {
                let alias = render(&mut stream(byte), source, 0, POOL_ATTEMPTS);
                assert_eq!(alias.rung, LadderRung::Reserved, "{}", alias.alias);
                assert!(
                    catalog::phone_is_documented(&alias.alias),
                    "{} is outside the published fiction range",
                    alias.alias
                );
                assert!(alias.alias.starts_with(&format!("+{country}")));
                produced += 1;
            }
        }
        assert_eq!(produced, 256 * 2);
    }

    #[test]
    fn an_exhausted_fiction_range_falls_to_rung_i_and_reports_it() {
        let alias = render(
            &mut stream(3),
            "+447911123456",
            POOL_ATTEMPTS,
            POOL_ATTEMPTS,
        );
        assert_eq!(alias.rung, LadderRung::Invalid);
        assert!(alias.pool_exhausted);
        assert_eq!(plan_verdict(&alias.alias), Verdict::Invalid);
    }

    #[test]
    fn a_country_with_no_citation_goes_opaque_rather_than_guessing() {
        // KG-011. Germany is a real numbering plan with real rules, and this
        // build has no citation for it, so it gets nothing type preserving.
        for source in ["+4930123456", "05321234567", "1234", ""] {
            let alias = render(&mut stream(1), source, 0, POOL_ATTEMPTS);
            assert_eq!(alias.rung, LadderRung::Opaque, "{}", alias.alias);
            assert!(alias.alias.starts_with("PSK_PHONE_"), "{}", alias.alias);
        }
    }

    #[test]
    fn an_area_code_keeps_the_format_the_plan_publishes() {
        for byte in 0..=255u8 {
            let code = area_code(&mut stream(byte), 3);
            assert_eq!(code.len(), 3);
            let first = code.chars().next().unwrap();
            assert!(('2'..='9').contains(&first), "{code}");
            assert!(!code.ends_with("11"), "{code}");
        }
        assert_eq!(area_code(&mut stream(1), 0), "");
    }

    #[test]
    fn the_verdict_says_unknown_for_a_country_it_has_no_citation_for() {
        assert_eq!(plan_verdict("+4930123456"), Verdict::NoDocumentedCheck);
        assert_eq!(
            plan_verdict("PSK_PHONE_0123456789abcdef"),
            Verdict::NoDocumentedCheck
        );
        assert_eq!(plan_verdict("+905321234567"), Verdict::Valid);
        assert_eq!(plan_verdict("+9005321234567"), Verdict::Invalid);
        assert_eq!(plan_verdict("+447700900123"), Verdict::Valid);
    }
}
