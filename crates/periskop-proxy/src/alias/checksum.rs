//! The validation functions rung `I` has to fail, and nothing else.
//!
//! # Why failing a validator is a proof
//!
//! ADR-010 section 5.1 states the argument in one line: a check digit rule is a
//! **total** function, so a string that fails it is, by definition, not a value
//! that was ever issued. An IBAN whose mod 97 remainder is wrong is not somebody
//! else's account with a typo; it is not an account. That is the whole of rung
//! `I`'s evidence, and it is why these functions are here rather than inlined
//! into the generators: the generator that breaks a rule and the test that
//! proves it broken have to be reading the same rule.
//!
//! The same functions are what detection layer A will use (`proxy/spec.md`
//! section 3.1: "a eleven digit number whose checksum does not hold is not a
//! TCKN"). That is the deliberate complementarity ADR-010 section 5.1 points at:
//! because an alias fails the validator, the detector does not classify it, so
//! an alias is not masked a second time on the next turn.
//!
//! # One function that is deliberately absent
//!
//! There is no function here that **computes** a Luhn check digit, and there may
//! not be one. ADR-010 forbids the "take the 4111 prefix and compute a valid
//! Luhn digit" path by name, because the result is a well formed card number in
//! a real issuer's range and one of those numbers belongs to somebody. Cards get
//! their aliases from the published pool in [`super::catalog`], and when that
//! runs out [`super::card`] breaks Luhn instead of satisfying it. Breaking it
//! needs no check digit: changing the last digit by one moves the Luhn sum by
//! exactly one, so a valid number becomes invalid without anybody computing what
//! valid would have been.
//!
//! IBAN, TCKN and VKN do compute their correct check digits, because "different
//! from the correct value" is the only way to be sure the wrong one is wrong.
//! The computed value is never emitted.

use super::entity::EntityType;

/// What a total validator says about a string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The type's published rule holds. No alias of this type may read this way.
    Valid,
    /// The rule fails, which is what rung `I` is for.
    Invalid,
    /// This build knows no total rule for this type, so it can prove nothing
    /// here. Callers may not read this as "invalid"; see
    /// [`EntityType::evidence_is_entropic`].
    NoDocumentedCheck,
}

/// Runs the type's own validator over an alias.
pub fn verdict(entity: EntityType, alias: &str) -> Verdict {
    let holds = match entity {
        EntityType::Iban => iban_is_valid(alias),
        EntityType::Tckn => tckn_is_valid(alias),
        EntityType::Vkn => vkn_is_valid(alias),
        EntityType::CreditCard => luhn_is_valid(alias),
        // A numbering plan rather than a check digit, and three valued rather
        // than two: a country with no entry in the rule file is unknown, not
        // invalid. Answering "invalid" there would let the P-0 gate accept an
        // alias on evidence nobody has.
        EntityType::Phone => return super::phone::plan_verdict(alias),
        // No published, total rule this build implements. API keys and secrets
        // are the marked case (threat model R14); the rest are types whose
        // evidence comes from a documented range or from not drawing a value at
        // all, and asking this question about them is a caller error rather than
        // a fact about the string.
        EntityType::ApiKey
        | EntityType::Secret
        | EntityType::Email
        | EntityType::Host
        | EntityType::Url
        | EntityType::Ipv4
        | EntityType::Ipv6
        | EntityType::Date
        | EntityType::Person
        | EntityType::Org
        | EntityType::Loc
        | EntityType::Address => return Verdict::NoDocumentedCheck,
    };
    if holds {
        Verdict::Valid
    } else {
        Verdict::Invalid
    }
}

/// Luhn (ISO/IEC 7812-1), for validation only.
///
/// Separators are ignored so that a formatted card reads the same as a bare one;
/// anything else that is not a digit makes the answer no.
pub fn luhn_is_valid(number: &str) -> bool {
    let mut sum = 0u32;
    let mut digits = 0usize;
    // Right to left, because the doubling alternates from the check digit.
    for character in number.chars().rev() {
        if matches!(character, ' ' | '-') {
            continue;
        }
        let Some(value) = character.to_digit(10) else {
            return false;
        };
        let value = if digits % 2 == 1 {
            let doubled = value * 2;
            if doubled > 9 {
                doubled - 9
            } else {
                doubled
            }
        } else {
            value
        };
        sum += value;
        digits += 1;
    }
    digits >= 2 && sum % 10 == 0
}

/// ISO 7064 MOD 97-10 over an IBAN (ISO 13616).
///
/// Computed as a running remainder rather than through a big integer: an IBAN is
/// up to 34 characters and the expanded decimal form does not fit in any
/// primitive type.
pub fn iban_is_valid(iban: &str) -> bool {
    let compact = compact_iban(iban);
    if !iban_shape_is_plausible(&compact) {
        return false;
    }
    mod_97_of_rearranged(&compact) == Some(1)
}

/// The check digits an IBAN with this country code and account body should
/// carry.
///
/// `body` is everything after the two check digits. Returns `None` when the
/// input is not something an IBAN could be built from, rather than a number that
/// would look like an answer.
pub fn iban_check_digits(country: &str, body: &str) -> Option<u8> {
    if country.len() != 2 || !country.chars().all(|c| c.is_ascii_uppercase()) {
        return None;
    }
    let mut with_zeros = String::with_capacity(4 + body.len());
    with_zeros.push_str(country);
    with_zeros.push_str("00");
    with_zeros.push_str(body);
    if !iban_shape_is_plausible(&with_zeros) {
        return None;
    }
    let remainder = mod_97_of_rearranged(&with_zeros)?;
    // 98 minus the remainder is the ISO 7064 completion, and it always lands in
    // 2..=98, which is the range ADR-010 requires a deliberately wrong pair to
    // stay inside as well.
    u8::try_from(98 - remainder).ok()
}

/// Whether a string could be an IBAN at all: country letters, check digits, an
/// alphanumeric body, and a length ISO 13616 allows.
fn iban_shape_is_plausible(compact: &str) -> bool {
    if !(5..=34).contains(&compact.len()) {
        return false;
    }
    let bytes = compact.as_bytes();
    let country_ok = bytes
        .get(..2)
        .is_some_and(|head| head.iter().all(u8::is_ascii_uppercase));
    let check_ok = bytes
        .get(2..4)
        .is_some_and(|head| head.iter().all(u8::is_ascii_digit));
    let body_ok = bytes
        .get(4..)
        .is_some_and(|rest| rest.iter().all(u8::is_ascii_alphanumeric));
    let upper_ok = compact
        .chars()
        .all(|character| !character.is_ascii_lowercase());
    country_ok && check_ok && body_ok && upper_ok
}

/// The remainder of the rearranged IBAN modulo 97.
///
/// "Rearranged" is the ISO 13616 step: the first four characters move to the
/// end, then every letter becomes two decimal digits (A is 10).
fn mod_97_of_rearranged(compact: &str) -> Option<u32> {
    let head = compact.get(..4)?;
    let tail = compact.get(4..)?;
    let mut remainder = 0u32;
    for character in tail.chars().chain(head.chars()) {
        remainder = if let Some(digit) = character.to_digit(10) {
            (remainder * 10 + digit) % 97
        } else if character.is_ascii_uppercase() {
            let value = u32::from(character as u8 - b'A') + 10;
            (remainder * 100 + value) % 97
        } else {
            return None;
        };
    }
    Some(remainder)
}

/// Strips the separators an IBAN is usually printed with.
pub fn compact_iban(iban: &str) -> String {
    iban.chars()
        .filter(|character| !matches!(character, ' ' | '-'))
        .collect()
}

/// The official TCKN rule (Turkish national identification number).
///
/// Eleven digits, the first of which is not zero. The tenth digit is
/// `((d1+d3+d5+d7+d9) * 7 - (d2+d4+d6+d8)) mod 10` and the eleventh is the sum
/// of the first ten modulo ten. The published example `10000000146` satisfies
/// both and is the vector the unit test below pins this implementation to.
pub fn tckn_is_valid(number: &str) -> bool {
    let Some(digits) = digits_of(number, 11) else {
        return false;
    };
    if digits.first() == Some(&0) {
        return false;
    }
    let Some(head) = digits.get(..9) else {
        return false;
    };
    let mut first_nine = [0u8; 9];
    first_nine.copy_from_slice(head);
    let (tenth, eleventh) = tckn_check_digits(&first_nine);
    digits.get(9) == Some(&tenth) && digits.get(10) == Some(&eleventh)
}

/// The tenth and eleventh digits a TCKN with this body should carry.
pub fn tckn_check_digits(first_nine: &[u8; 9]) -> (u8, u8) {
    let odd: i32 = [0, 2, 4, 6, 8]
        .iter()
        .map(|index| i32::from(first_nine[*index]))
        .sum();
    let even: i32 = [1, 3, 5, 7]
        .iter()
        .map(|index| i32::from(first_nine[*index]))
        .sum();
    // rem_euclid rather than %, because the subtraction can go negative and a
    // negative remainder would make the rule accept numbers it should refuse.
    let tenth = (odd * 7 - even).rem_euclid(10);
    let sum_of_ten: i32 = first_nine
        .iter()
        .map(|digit| i32::from(*digit))
        .sum::<i32>()
        + tenth;
    let eleventh = sum_of_ten.rem_euclid(10);
    (tenth as u8, eleventh as u8)
}

/// The published VKN rule (Turkish tax identification number).
///
/// Ten digits: nine of body and a check digit computed by the algorithm the
/// revenue administration publishes. Each body digit is shifted by its distance
/// from the end, weighted by a power of two modulo nine, and the check digit
/// completes the total to a multiple of ten.
///
/// **Reviewer's note.** Every other rung `I` rule in this module is pinned to a
/// published vector (an IBAN from ISO 13616's own examples, TCKN's `10000000146`).
/// For VKN this build carries no published vector, so what is pinned below is
/// only self consistency: computing the digit and then validating agrees, and
/// changing any digit is rejected. If this algorithm turns out not to be the
/// published one, VKN's rung `I` proof is weaker than it claims and the type
/// belongs on rung `O` until it is fixed. That is a review item, and it is
/// written here rather than in a commit message so that the next reader sees it.
pub fn vkn_is_valid(number: &str) -> bool {
    let Some(digits) = digits_of(number, 10) else {
        return false;
    };
    let Some(head) = digits.get(..9) else {
        return false;
    };
    let mut first_nine = [0u8; 9];
    first_nine.copy_from_slice(head);
    digits.get(9) == Some(&vkn_check_digit(&first_nine))
}

/// The check digit a VKN with this body should carry.
pub fn vkn_check_digit(first_nine: &[u8; 9]) -> u8 {
    let mut total = 0u32;
    for (index, digit) in first_nine.iter().enumerate() {
        let shifted = (u32::from(*digit) + (9 - index as u32)) % 10;
        // A shifted value of nine contributes nine. Without the special case the
        // power of two term would be zero modulo nine and two different bodies
        // would share a check digit.
        total += if shifted == 9 {
            9
        } else {
            (shifted * 2u32.pow(9 - index as u32)) % 9
        };
    }
    let remainder = total % 10;
    let check = if remainder == 0 { 0 } else { 10 - remainder };
    // The arithmetic above cannot leave the 0..=9 range; the cast is bounded by
    // the modulo rather than by an assumption.
    (check % 10) as u8
}

/// Digits of a string that must be exactly `expected` of them and nothing else.
fn digits_of(number: &str, expected: usize) -> Option<Vec<u8>> {
    if number.len() != expected {
        return None;
    }
    let mut digits = Vec::with_capacity(expected);
    for character in number.chars() {
        let value = character.to_digit(10)?;
        digits.push(value as u8);
    }
    Some(digits)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn luhn_agrees_with_published_test_cards() {
        assert!(luhn_is_valid("4242424242424242"));
        assert!(luhn_is_valid("4242 4242 4242 4242"));
        assert!(luhn_is_valid("378282246310005"));
        // One digit moved is one digit too many.
        assert!(!luhn_is_valid("4242424242424243"));
        assert!(!luhn_is_valid("4242424242424252"));
        assert!(!luhn_is_valid("42x2424242424242"));
        assert!(!luhn_is_valid(""));
        assert!(!luhn_is_valid("4"));
    }

    #[test]
    fn changing_the_last_digit_by_one_always_breaks_luhn() {
        // The property `card.rs` relies on when the published pool runs out. It
        // is what lets this crate produce a Luhn invalid card without owning a
        // function that computes a Luhn valid one.
        for pan in super::super::catalog::TEST_PANS {
            let mut digits: Vec<char> = pan.digits.chars().collect();
            let last = digits.len() - 1;
            let bumped = (digits[last].to_digit(10).unwrap() + 1) % 10;
            digits[last] = char::from_digit(bumped, 10).unwrap();
            let broken: String = digits.into_iter().collect();
            assert!(!luhn_is_valid(&broken), "{broken} still passes Luhn");
        }
    }

    #[test]
    fn iban_agrees_with_the_published_example() {
        // The example IBAN from the ISO 13616 registry entry for the United
        // Kingdom, which is the vector this implementation is pinned to.
        assert!(iban_is_valid("GB82WEST12345698765432"));
        assert!(iban_is_valid("GB82 WEST 1234 5698 7654 32"));
        assert!(iban_is_valid("DE89370400440532013000"));
        assert!(iban_is_valid("TR330006100519786457841326"));

        // Wrong check digits, wrong body, wrong shape.
        assert!(!iban_is_valid("GB83WEST12345698765432"));
        assert!(!iban_is_valid("GB82WEST12345698765433"));
        assert!(!iban_is_valid("gb82west12345698765432"));
        assert!(!iban_is_valid("GB82"));
        assert!(!iban_is_valid(""));
    }

    #[test]
    fn iban_check_digits_complete_the_example() {
        assert_eq!(iban_check_digits("GB", "WEST12345698765432"), Some(82));
        assert_eq!(iban_check_digits("DE", "370400440532013000"), Some(89));
        assert_eq!(iban_check_digits("TR", "0006100519786457841326"), Some(33));
        // And the completion always lands in the range ADR-010 asks a wrong pair
        // to stay inside.
        for body in ["WEST12345698765432", "0006100519786457841326"] {
            let digits = iban_check_digits("GB", body).unwrap();
            assert!((2..=98).contains(&digits), "{digits}");
        }
        assert_eq!(iban_check_digits("gb", "WEST12345698765432"), None);
        assert_eq!(iban_check_digits("GBR", "WEST12345698765432"), None);
    }

    #[test]
    fn tckn_agrees_with_the_published_example() {
        assert!(tckn_is_valid("10000000146"));
        // Both check digits matter, and so does the leading zero rule.
        assert!(!tckn_is_valid("10000000156"));
        assert!(!tckn_is_valid("10000000147"));
        assert!(!tckn_is_valid("00000000146"));
        assert!(!tckn_is_valid("1000000014"));
        assert!(!tckn_is_valid("100000001460"));
        assert!(!tckn_is_valid("1000000014x"));
    }

    #[test]
    fn tckn_check_digits_are_a_total_function_of_the_body() {
        let body = [1, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(tckn_check_digits(&body), (4, 6));

        // Every body has exactly one valid pair, so any other pair is refused.
        // This is the property rung I rests on.
        for tenth in 0..10u8 {
            for eleventh in 0..10u8 {
                let candidate = format!("100000001{tenth}{eleventh}");
                assert_eq!(
                    tckn_is_valid(&candidate),
                    (tenth, eleventh) == (4, 6),
                    "{candidate}"
                );
            }
        }
    }

    #[test]
    fn vkn_is_self_consistent_and_rejects_every_other_check_digit() {
        // See the reviewer's note on `vkn_is_valid`: this pins the algorithm's
        // shape, not its agreement with the published one.
        for body in [
            [1, 2, 3, 4, 5, 6, 7, 8, 9],
            [0, 0, 0, 0, 0, 0, 0, 0, 0],
            [9, 9, 9, 9, 9, 9, 9, 9, 9],
            [4, 9, 8, 0, 3, 1, 2, 2, 0],
        ] {
            let check = vkn_check_digit(&body);
            assert!(check < 10);
            let digits: String = body
                .iter()
                .map(|digit| char::from_digit(u32::from(*digit), 10).unwrap())
                .collect();
            for candidate in 0..10u8 {
                let number = format!("{digits}{candidate}");
                assert_eq!(vkn_is_valid(&number), candidate == check, "{number}");
            }
        }
        assert!(!vkn_is_valid("12345678"));
        assert!(!vkn_is_valid("12345678901"));
    }

    #[test]
    fn the_verdict_says_nothing_it_cannot_prove() {
        assert_eq!(
            verdict(EntityType::CreditCard, "4242424242424242"),
            Verdict::Valid
        );
        assert_eq!(
            verdict(EntityType::CreditCard, "4242424242424243"),
            Verdict::Invalid
        );
        assert_eq!(
            verdict(EntityType::Iban, "GB82WEST12345698765432"),
            Verdict::Valid
        );
        assert_eq!(verdict(EntityType::Tckn, "10000000146"), Verdict::Valid);

        // The types with no total rule answer with the third value rather than
        // with "invalid", which would be a claim this build cannot support.
        for entity in [
            EntityType::ApiKey,
            EntityType::Secret,
            EntityType::Email,
            EntityType::Person,
        ] {
            assert_eq!(
                verdict(entity, "anything at all"),
                Verdict::NoDocumentedCheck
            );
        }
    }
}
