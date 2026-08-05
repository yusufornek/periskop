//! The gates a shape has to pass before it becomes a candidate.
//!
//! # Why the shape alone is not the detector
//!
//! `proxy/spec.md` section 3.1 puts it in one line:
//!
//! > Kontrol basamağı olan türlerde sağlama **zorunludur**: sağlaması tutmayan
//! > 11 haneli sayı TCKN değildir, maskelenmez.
//!
//! A regular expression that accepts eleven digits accepts order numbers, part
//! codes, phone numbers written without separators and the year 20250101010. If
//! all of those were masked, the prompt the model reads would be a different
//! prompt, and the answer would be wrong in a way nobody can see from the
//! outside. The check digit is what turns "eleven digits" into "an identity
//! number", and it throws away roughly ninety nine of every hundred impostors.
//!
//! The check functions themselves are **not** here. They live in
//! [`crate::alias::checksum`], because rung `I` of the alias ladder has to fail
//! exactly the rule this layer enforces: the generator that breaks a rule and the
//! detector that applies it have to be reading the same rule, or an alias gets
//! masked a second time on the next turn.
//!
//! # What each gate throws away, and in which direction it errs
//!
//! Every gate below states the direction, because the two errors are not
//! symmetric: a missed entity is a leak, silent and irreversible; a false
//! positive is a damaged prompt, loud and fixable. Where a gate errs toward the
//! false positive it says so, and where it errs toward the miss it says so and
//! points at the `known-gaps.md` line that carries it.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Issuer identification ranges this build recognises, with the length the
/// scheme publishes for them.
///
/// This is the "BIN" half of `proxy/spec.md` section 3.1's `CREDIT_CARD` rule.
/// Luhn alone accepts one in ten arbitrary digit runs, and a sixteen digit order
/// reference passes it often enough to matter; the issuer range is what says the
/// number is a *card*.
///
/// Each entry is a numeric prefix range over the leading digits, closed at both
/// ends, and the set of lengths the scheme issues. Ranges are the published
/// assignments; a scheme with no entry here is not detected, which is a declared
/// miss rather than a guess.
struct IssuerRange {
    /// Inclusive low end of the leading digits.
    low: u64,
    /// Inclusive high end, with the same number of digits as `low`.
    high: u64,
    /// How many leading digits `low` and `high` cover.
    digits: u32,
    /// Total card lengths the scheme issues.
    lengths: &'static [usize],
}

/// The published issuer ranges. Order does not matter; membership is a scan.
const ISSUER_RANGES: &[IssuerRange] = &[
    // Visa.
    IssuerRange {
        low: 4,
        high: 4,
        digits: 1,
        lengths: &[13, 16, 19],
    },
    // Mastercard, both the classic 51-55 block and the 2221-2720 block.
    IssuerRange {
        low: 51,
        high: 55,
        digits: 2,
        lengths: &[16],
    },
    IssuerRange {
        low: 2221,
        high: 2720,
        digits: 4,
        lengths: &[16],
    },
    // American Express.
    IssuerRange {
        low: 34,
        high: 34,
        digits: 2,
        lengths: &[15],
    },
    IssuerRange {
        low: 37,
        high: 37,
        digits: 2,
        lengths: &[15],
    },
    // Diners Club.
    IssuerRange {
        low: 300,
        high: 305,
        digits: 3,
        lengths: &[14, 16, 19],
    },
    IssuerRange {
        low: 36,
        high: 36,
        digits: 2,
        lengths: &[14, 16, 19],
    },
    IssuerRange {
        low: 38,
        high: 39,
        digits: 2,
        lengths: &[14, 16, 19],
    },
    // Discover.
    IssuerRange {
        low: 6011,
        high: 6011,
        digits: 4,
        lengths: &[16, 19],
    },
    IssuerRange {
        low: 644,
        high: 649,
        digits: 3,
        lengths: &[16, 19],
    },
    IssuerRange {
        low: 65,
        high: 65,
        digits: 2,
        lengths: &[16, 19],
    },
    // JCB.
    IssuerRange {
        low: 3528,
        high: 3589,
        digits: 4,
        lengths: &[16, 19],
    },
    // UnionPay.
    IssuerRange {
        low: 62,
        high: 62,
        digits: 2,
        lengths: &[16, 17, 18, 19],
    },
    // Maestro.
    IssuerRange {
        low: 50,
        high: 50,
        digits: 2,
        lengths: &[12, 13, 14, 15, 16, 17, 18, 19],
    },
    IssuerRange {
        low: 56,
        high: 58,
        digits: 2,
        lengths: &[12, 13, 14, 15, 16, 17, 18, 19],
    },
    // Troy, the Turkish domestic scheme. Present because this component's first
    // deployment is Turkish and a domestic card is the likeliest card in a
    // Turkish prompt.
    IssuerRange {
        low: 9792,
        high: 9792,
        digits: 4,
        lengths: &[16],
    },
];

/// Whether a digit run is a card: Luhn holds **and** the leading digits fall in a
/// published issuer range at a length that scheme issues.
///
/// Errs toward the miss: a scheme with no entry above is not detected. That is a
/// bounded, listable gap (add the range), whereas dropping the issuer check to
/// close it would mask one in ten of every sixteen digit reference number in
/// every prompt.
pub fn card_is_detectable(digits: &str) -> bool {
    if !digits.chars().all(|character| character.is_ascii_digit()) {
        return false;
    }
    if !crate::alias::checksum::luhn_is_valid(digits) {
        return false;
    }
    ISSUER_RANGES.iter().any(|range| {
        let Some(head) = digits.get(..range.digits as usize) else {
            return false;
        };
        let Ok(value) = head.parse::<u64>() else {
            return false;
        };
        (range.low..=range.high).contains(&value) && range.lengths.contains(&digits.len())
    })
}

/// What an IP address says about somebody.
///
/// `proxy/spec.md` section 3.1 asks for "biçim + özel aralık ayrımı". The
/// distinction is load bearing rather than decorative: `127.0.0.1` and `::1` name
/// no host anywhere and carry no information about any person or any network, so
/// masking them buys nothing and costs a broken prompt in every developer
/// conversation. A private address does carry information (internal topology), so
/// it is masked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressClass {
    /// Reachable on the public internet: masked.
    Global,
    /// RFC 1918 / RFC 4193 and friends: masked, because internal topology is
    /// exactly what an operator does not want a provider to learn.
    Private,
    /// Loopback, unspecified, and the documentation ranges the alias generators
    /// themselves draw from. Not masked, and not a miss: there is nobody behind
    /// these addresses to leak.
    NotAnEntity,
}

/// Classifies an IPv4 literal, or `None` when it is not one.
pub fn ipv4_class(text: &str) -> Option<AddressClass> {
    // `Ipv4Addr` accepts exactly the dotted quad and rejects leading zeros and
    // out of range octets, which is the whole of the format gate. Writing the
    // octet arithmetic by hand would be a second, drifting copy of it.
    let address = Ipv4Addr::from_str(text).ok()?;
    if address.is_loopback() || address.is_unspecified() || address.is_documentation() {
        return Some(AddressClass::NotAnEntity);
    }
    if address.is_private() || address.is_link_local() {
        return Some(AddressClass::Private);
    }
    Some(AddressClass::Global)
}

/// Classifies an IPv6 literal, or `None` when it is not one.
pub fn ipv6_class(text: &str) -> Option<AddressClass> {
    let address = Ipv6Addr::from_str(text).ok()?;
    if address.is_loopback() || address.is_unspecified() {
        return Some(AddressClass::NotAnEntity);
    }
    // 2001:db8::/32 is RFC 3849's documentation range and is where this crate's
    // own IPv6 aliases come from. Masking it would mask an alias.
    let segments = address.segments();
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return Some(AddressClass::NotAnEntity);
    }
    // fc00::/7 unique local, fe80::/10 link local.
    if segments[0] & 0xfe00 == 0xfc00 || segments[0] & 0xffc0 == 0xfe80 {
        return Some(AddressClass::Private);
    }
    Some(AddressClass::Global)
}

/// Whether year, month and day name a day that exists.
///
/// This is `DATE`'s equivalent of a check digit and it is what keeps `1.2.3`,
/// `13.45.2026` and a version string out of the date detector.
pub fn date_is_real(year: i64, month: u32, day: u32) -> bool {
    if !(1..=12).contains(&month) || day == 0 {
        return false;
    }
    // A four digit year is required by the shapes, so the range check is a
    // sanity bound rather than a calendar claim.
    if !(1000..=9999).contains(&year) {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let last = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        // Unreachable given the range check above; answering `false` rather than
        // panicking keeps this a total function.
        _ => return false,
    };
    day <= last
}

/// The smallest number of distinct character classes a key body must mix.
///
/// Two of {lowercase, uppercase, digit}. One class is a word, and `sk-this-is-a-
/// placeholder` is a word.
const KEY_CLASS_DIVERSITY: usize = 2;

/// Shannon entropy per character a key body must reach, in bits.
///
/// Three bits per character is roughly what a random draw from a sixteen symbol
/// alphabet gives. English prose sits near two.
const KEY_MIN_ENTROPY_BITS: f64 = 3.0;

/// The shortest body this build calls a key.
///
/// Twelve, and the number is not arbitrary. The alias generator for this family
/// breaks its own output into runs of at most eight characters separated by
/// `.` (`alias::rung_i`, KG-023), so no run in an alias can reach twelve and no
/// alias this crate produced can be detected as a key and masked a second time.
/// That is ADR-010 section 5.1's deliberate complementarity, and
/// `an_alias_this_crate_mints_is_never_detected_again` in `detect::merge` is what
/// holds it.
pub const KEY_MIN_BODY: usize = 12;

/// Whether a provider prefixed token's body looks drawn rather than written.
///
/// Errs toward the false positive on purpose: a leaked provider key is the
/// single most expensive thing in this component's threat model, so a body that
/// is merely long and mixed is masked even when it turns out to be a base64
/// blob. The cost of the reverse is a credential in a provider's request log.
pub fn key_body_is_high_entropy(body: &str) -> bool {
    if body.chars().count() < KEY_MIN_BODY {
        return false;
    }
    let mut classes = 0;
    if body.chars().any(|c| c.is_ascii_lowercase()) {
        classes += 1;
    }
    if body.chars().any(|c| c.is_ascii_uppercase()) {
        classes += 1;
    }
    if body.chars().any(|c| c.is_ascii_digit()) {
        classes += 1;
    }
    if classes < KEY_CLASS_DIVERSITY {
        return false;
    }
    shannon_bits_per_char(body) >= KEY_MIN_ENTROPY_BITS
}

/// Shannon entropy of a string in bits per character.
fn shannon_bits_per_char(text: &str) -> f64 {
    let mut counts = std::collections::BTreeMap::new();
    let mut total = 0usize;
    for character in text.chars() {
        *counts.entry(character).or_insert(0usize) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let total_f = total as f64;
    -counts
        .values()
        .map(|count| {
            let probability = *count as f64 / total_f;
            probability * probability.log2()
        })
        .sum::<f64>()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn positive_a_published_test_card_passes_luhn_and_lands_in_an_issuer_range() {
        for pan in [
            "4242424242424242",
            "4111111111111111",
            "5555555555554444",
            "2223003122003222",
            "378282246310005",
            "6011111111111117",
            "3530111333300000",
        ] {
            assert!(card_is_detectable(pan), "{pan} was not detected");
        }
    }

    #[test]
    fn negative_luhn_and_the_issuer_range_each_reject_on_their_own() {
        // Luhn fails.
        assert!(!card_is_detectable("4242424242424243"));
        // Luhn holds, no issuer range: a sixteen digit reference starting with 1.
        assert!(crate::alias::checksum::luhn_is_valid("1234567812345670"));
        assert!(!card_is_detectable("1234567812345670"));
        // Issuer range holds, wrong length for the scheme.
        assert!(!card_is_detectable("42424242424242426"));
        assert!(!card_is_detectable(""));
        assert!(!card_is_detectable("42x2424242424242"));
    }

    #[test]
    fn escape_a_scheme_with_no_published_range_here_is_not_detected() {
        // A Luhn valid sixteen digit number in the unassigned 7 range. This is
        // the declared miss: the closing move is adding the range, not dropping
        // the issuer check.
        let candidate = "7000000000000005";
        assert!(crate::alias::checksum::luhn_is_valid(candidate));
        assert!(!card_is_detectable(candidate));
    }

    #[test]
    fn addresses_are_classified_and_the_ones_with_nobody_behind_them_are_not_entities() {
        assert_eq!(ipv4_class("8.8.8.8"), Some(AddressClass::Global));
        assert_eq!(ipv4_class("10.0.0.5"), Some(AddressClass::Private));
        assert_eq!(ipv4_class("192.168.1.1"), Some(AddressClass::Private));
        assert_eq!(ipv4_class("127.0.0.1"), Some(AddressClass::NotAnEntity));
        assert_eq!(ipv4_class("0.0.0.0"), Some(AddressClass::NotAnEntity));
        // The range this crate's own IPv4 aliases come from (RFC 5737).
        assert_eq!(ipv4_class("203.0.113.7"), Some(AddressClass::NotAnEntity));
        // Not addresses at all.
        assert_eq!(ipv4_class("999.1.1.1"), None);
        assert_eq!(ipv4_class("1.2.3"), None);

        assert_eq!(ipv6_class("2606:4700::1111"), Some(AddressClass::Global));
        assert_eq!(ipv6_class("fd00::1"), Some(AddressClass::Private));
        assert_eq!(ipv6_class("fe80::1"), Some(AddressClass::Private));
        assert_eq!(ipv6_class("::1"), Some(AddressClass::NotAnEntity));
        // RFC 3849, where this crate's IPv6 aliases come from.
        assert_eq!(ipv6_class("2001:db8::7"), Some(AddressClass::NotAnEntity));
        assert_eq!(ipv6_class("nonsense"), None);
    }

    #[test]
    fn a_date_gate_refuses_a_day_that_does_not_exist() {
        assert!(date_is_real(2026, 8, 5));
        assert!(date_is_real(2024, 2, 29));
        assert!(!date_is_real(2025, 2, 29));
        assert!(!date_is_real(2026, 13, 1));
        assert!(!date_is_real(2026, 4, 31));
        assert!(!date_is_real(2026, 1, 0));
        assert!(!date_is_real(3, 1, 1));
    }

    #[test]
    fn a_key_body_has_to_be_long_and_mixed_and_drawn() {
        assert!(key_body_is_high_entropy("4eC39HqLyjWDarjtT1zdp7dc"));
        assert!(key_body_is_high_entropy("AbCd1234EfGh5678IjKl"));
        // Too short.
        assert!(!key_body_is_high_entropy("AbCd1234"));
        // One class only: a placeholder somebody typed.
        assert!(!key_body_is_high_entropy("thisisnotarealkeyatall"));
        assert!(!key_body_is_high_entropy("000000000000000000"));
        // Long and two classed but repetitive: entropy is what rejects it.
        assert!(!key_body_is_high_entropy("a1a1a1a1a1a1a1a1a1a1a1a1"));
    }

    #[test]
    fn no_run_inside_a_key_alias_reaches_the_minimum_body_length() {
        // The complementarity ADR-010 section 5.1 asks for, checked against the
        // constant rather than against a sample: if the generator's grouping ever
        // grows past this, the detector starts masking its own output and the
        // conversation loses the value behind two layers of alias.
        // Stated over a real string rather than over the two constants, so the
        // assertion is about what the gate does and not about arithmetic the
        // compiler folds away.
        let longest_run: String = "aB3dE7gH9jK2mN5p"
            .chars()
            .take(crate::alias::rung_i::KEY_GROUP)
            .collect();
        assert_eq!(longest_run.len(), crate::alias::rung_i::KEY_GROUP);
        assert!(
            !key_body_is_high_entropy(&longest_run),
            "the longest run a key alias can carry ({longest_run}) is detectable as a key body"
        );
    }
}
