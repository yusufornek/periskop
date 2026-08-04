//! `CREDIT_CARD`: a published test number first, a Luhn breaking number after.
//!
//! # The path this module may not take
//!
//! ADR-010 names it and forbids it: taking the `4111` prefix and computing a
//! valid Luhn check digit is **not** drawing from a reserved range. The
//! published reservation is a finite list of specific numbers, not a BIN, and
//! another number inside that BIN can be a real card in somebody's wallet. So
//! there is no code here that completes a Luhn sum, and
//! `tests/p0_invariants.rs` reads this crate's own sources to keep it that way.
//!
//! # What happens when the list runs out
//!
//! The list is a few dozen numbers, and a session may mask more cards than that
//! (KG-012). The answer is the ladder's: fall to rung `I` and produce a card
//! that is the right length and the right brand digit and **fails Luhn**, then
//! count it in `alias_stats.alias_pool_exhausted` so the loss is visible rather
//! than silent. Downstream validation breaks at that point, loudly, which is the
//! trade ADR-010 section 5.3 accepts on purpose.
//!
//! Breaking Luhn needs no check digit computation. Changing the last digit by
//! one moves the Luhn sum by exactly one, so a number that happened to satisfy
//! the rule stops satisfying it, and one that already failed keeps failing.

use super::catalog::TEST_PANS;
use super::checksum;
use super::derive::SeedStream;
use super::entity::LadderRung;
use super::mint::Rendered;

/// Card lengths this generator will produce. Outside this range the source is
/// not something detection should have called a card, and the alias falls back
/// to the commonest length rather than copying a nonsense one.
const PLAUSIBLE_LENGTHS: core::ops::RangeInclusive<usize> = 13..=19;

/// The length used when the source length is not plausible.
const FALLBACK_LENGTH: usize = 16;

/// A card alias.
///
/// `probe_base` comes from the value's seed and stays the same across attempts,
/// which turns the retry walk into a linear probe over the matching part of the
/// published list. That is what makes "the pool is exhausted" a fact rather than
/// a guess: after as many attempts as there are candidates, every candidate has
/// been offered exactly once.
pub fn render(stream: &mut SeedStream, source: &str, probe_base: u32, attempt: u32) -> Rendered {
    let digits: String = source.chars().filter(char::is_ascii_digit).collect();
    let length = if PLAUSIBLE_LENGTHS.contains(&digits.len()) {
        digits.len()
    } else {
        FALLBACK_LENGTH
    };
    let brand = digits.chars().next();

    let candidates = candidates_for(length, brand);
    if !candidates.is_empty() && (attempt as usize) < candidates.len() {
        let index = (probe_base as usize + attempt as usize) % candidates.len();
        if let Some(pan) = candidates.get(index) {
            return Rendered {
                alias: (*pan).to_owned(),
                rung: LadderRung::Reserved,
                pool_exhausted: false,
                length_class_capped: false,
            };
        }
    }

    Rendered {
        alias: luhn_breaking(stream, length, brand),
        rung: LadderRung::Invalid,
        pool_exhausted: true,
        length_class_capped: false,
    }
}

/// The published numbers that match this card's length and brand digit.
///
/// Matching on both keeps the alias parseable: a fifteen digit number stays
/// fifteen digits and an Amex stays an Amex, which is what a caller reading the
/// brand out of the first digit depends on. When no published number matches,
/// the whole list is offered rather than failing, because a card of the wrong
/// brand is a far smaller problem than a card that is somebody's.
fn candidates_for(length: usize, brand: Option<char>) -> Vec<&'static str> {
    let exact: Vec<&'static str> = TEST_PANS
        .iter()
        .filter(|pan| pan.digits.len() == length && pan.digits.chars().next() == brand)
        .map(|pan| pan.digits)
        .collect();
    if !exact.is_empty() {
        return exact;
    }
    let by_length: Vec<&'static str> = TEST_PANS
        .iter()
        .filter(|pan| pan.digits.len() == length)
        .map(|pan| pan.digits)
        .collect();
    if !by_length.is_empty() {
        return by_length;
    }
    TEST_PANS.iter().map(|pan| pan.digits).collect()
}

/// A number of the right shape that fails Luhn.
fn luhn_breaking(stream: &mut SeedStream, length: usize, brand: Option<char>) -> String {
    let mut digits = String::with_capacity(length);
    match brand.filter(char::is_ascii_digit) {
        // The brand digit is a property of the card scheme rather than of the
        // person, and keeping it is what lets a reader see that this was a Visa.
        Some(first) => digits.push(first),
        None => digits.push(char::from(b'1' + stream.digit() % 9)),
    }
    while digits.len() < length {
        digits.push(char::from(b'0' + stream.digit()));
    }

    if checksum::luhn_is_valid(&digits) {
        // One step on the last digit moves the Luhn sum by exactly one, so the
        // result cannot be a multiple of ten. No check digit is computed here,
        // and none may be.
        let mut characters: Vec<char> = digits.chars().collect();
        if let Some(last) = characters.last_mut() {
            let bumped = (last.to_digit(10).unwrap_or(0) + 1) % 10;
            *last = char::from_digit(bumped, 10).unwrap_or('1');
        }
        return characters.into_iter().collect();
    }
    digits
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::catalog;
    use super::*;

    fn stream(byte: u8) -> SeedStream {
        SeedStream::new(&[byte; 32]).unwrap()
    }

    #[test]
    fn the_first_attempt_comes_from_the_published_list() {
        for byte in 0..=255u8 {
            let produced = render(&mut stream(byte), "4111111111111111", u32::from(byte), 0);
            assert_eq!(produced.rung, LadderRung::Reserved);
            assert!(!produced.pool_exhausted);
            assert!(
                catalog::pan_is_documented(&produced.alias),
                "{} is not on the published list",
                produced.alias
            );
            // Same length and same brand, so a reader can still tell what it was.
            assert_eq!(produced.alias.len(), 16);
            assert!(produced.alias.starts_with('4'));
        }
    }

    #[test]
    fn the_probe_walks_the_whole_matching_list_before_declaring_it_empty() {
        // Sixteen digit Visa numbers are the largest group in the published
        // list, and every attempt below that count has to offer a different one.
        let candidates = candidates_for(16, Some('4'));
        let mut offered = std::collections::BTreeSet::new();
        for attempt in 0..candidates.len() as u32 {
            let produced = render(&mut stream(0x40), "4111111111111111", 0, attempt);
            assert_eq!(produced.rung, LadderRung::Reserved);
            offered.insert(produced.alias);
        }
        assert_eq!(offered.len(), candidates.len());
    }

    #[test]
    fn every_card_produced_after_the_pool_runs_out_fails_luhn() {
        // The invariant KG-012 rests on, over the seed space and over every card
        // length. A card that passes Luhn here is a card a payment form accepts.
        let sources = [
            "4111111111111111",
            "378282246310005",
            "36227206271667",
            "4222222222222",
            "6011111111111117",
            "not a card at all",
        ];
        let mut produced = 0;
        for byte in 0..=255u8 {
            for source in sources {
                let exhausted_attempt = TEST_PANS.len() as u32 + 1;
                let alias = render(
                    &mut stream(byte),
                    source,
                    u32::from(byte),
                    exhausted_attempt,
                );
                assert_eq!(alias.rung, LadderRung::Invalid, "{}", alias.alias);
                assert!(alias.pool_exhausted);
                assert!(
                    !checksum::luhn_is_valid(&alias.alias),
                    "{} passes Luhn after the pool ran out",
                    alias.alias
                );
                assert!(
                    !catalog::pan_is_documented(&alias.alias),
                    "{} is a published number produced by the fallback",
                    alias.alias
                );
                assert!(alias.alias.chars().all(|c| c.is_ascii_digit()));
                produced += 1;
            }
        }
        assert_eq!(produced, 256 * sources.len());
    }

    #[test]
    fn the_fallback_keeps_the_length_and_brand_of_a_plausible_source() {
        let cases = [("378282246310005", 15, '3'), ("4222222222222", 13, '4')];
        for (source, length, brand) in cases {
            let alias = render(&mut stream(5), source, 0, 99).alias;
            assert_eq!(alias.len(), length, "{alias}");
            assert_eq!(alias.chars().next(), Some(brand), "{alias}");
        }
        // An implausible length falls back to sixteen rather than copying it.
        let alias = render(&mut stream(5), "12345", 0, 99).alias;
        assert_eq!(alias.len(), FALLBACK_LENGTH);
    }
}
