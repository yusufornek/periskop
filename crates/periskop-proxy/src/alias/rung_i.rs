//! Rung `I`: the shape survives, the validator does not.
//!
//! # The argument, in one line
//!
//! A check digit rule is a total function. A string that fails it was never
//! issued to anybody, whatever else it looks like. So an alias that fails the
//! rule on purpose is provably unallocated, which is exactly what P-0 asks for
//! and is the only proof available for the types with no reserved range: ISO
//! 13616 defines no test IBAN space, and Turkey publishes no unassigned identity
//! number block. The original design claimed both existed. They do not.
//!
//! # What is kept and what is broken
//!
//! Kept: the country code, the length, the digit and letter positions, the
//! prefix of a key. That is what makes the alias parseable, and parseability is
//! the whole remaining product value of type preservation for these types
//! (ADR-010 section 5.3): field extraction works, a JSON schema still validates,
//! the model does not confuse an IBAN with a tax number.
//!
//! Broken: the check digits, deliberately and always. A downstream validator
//! says "invalid IBAN", which is a **visible** failure. The alternative it
//! replaced was a silent one: a valid IBAN that belongs to a stranger.
//!
//! # The one type here whose evidence is weaker
//!
//! `API_KEY` and `SECRET` keep their prefix and their length class, and their
//! body comes from the session keyed stream. No provider publishes a checksum
//! this build can break on purpose, so the proof is a counting argument rather
//! than a rule: a body of at least 22 drawn base62 characters carries more than
//! 128 bits, and the chance of colliding with a real key is at most 2^-128.
//! Threat model R14 records that as the catalogue's one weak evidence row, and
//! [`super::entity::EntityType::reported_rung`] makes the run report `O` for
//! these types so the measurement never claims more than the proof supports.
//!
//! # Why the body is grouped, and what it costs
//!
//! Keeping the prefix and drawing a high entropy body from the same alphabet a
//! provider uses produced a string that a secret scanner cannot tell from a real
//! key: `sk_live_` followed by twenty four base62 characters *is* the Stripe
//! pattern, whatever the bytes mean here. That is a defect in its own right and
//! not only a push protection annoyance. A masked prompt is meant to be safe to
//! keep: it lands in logs, tickets and repositories, and every scanner
//! downstream of us would raise a credential alert on it. Preventing a leak by
//! manufacturing false alerts moves the cost rather than removing it, and alert
//! fatigue is how a real leak gets missed.
//!
//! Two things had to hold at once. The prefix has to survive, because dropping
//! it breaks the one downstream behaviour type preservation buys here: an
//! application that routes on "this is a Stripe key" keeps working. And the
//! alias may not be believable, which is P-0 read the other way round.
//!
//! So the prefix is carried unchanged and the body is drawn in runs of at most
//! [`KEY_GROUP`] characters separated by [`KEY_SEPARATOR`]. Every published
//! scanner pattern is a literal marker followed by a run of body characters, and
//! the shortest run any of them accepts is ten; a run that stops at eight cannot
//! complete one, and the separator is outside every published key charset. The
//! claim is structural rather than probabilistic: it does not depend on which
//! bytes the stream happened to draw, and it holds for a family nobody has
//! written a pattern for yet, as long as that family needs nine or more
//! characters in a row. `tests/p0_invariants.rs` is where it is enforced.

use super::checksum;
use super::derive::SeedStream;

/// Characters a generated key body is drawn from.
const BASE62: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Letters an IBAN body may use, ISO 13616 being upper case only.
const IBAN_LETTERS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// The longest prefix carried over from a key, in bytes.
///
/// Eight, which is what the longest provider prefix this build has to keep
/// whole costs: `sk_live_` and `sk_test_` are eight bytes and the difference
/// between them is a routing difference. It used to be ten, and the two bytes
/// came back to pay for the group separators below; nothing published loses a
/// prefix by it, because the only longer shape in circulation is
/// `github_pat_`, which is cut at its first underscore either way.
const MAX_KEY_PREFIX: usize = 8;

/// The longest run of drawn characters a key alias may carry uninterrupted.
///
/// Pinned from both sides, so it is a consequence rather than a taste.
///
/// From below: the shortest length class leaves twenty four bytes of body once
/// an eight byte prefix is carried. Runs of seven would need three separators
/// and leave twenty one drawn characters, under the twenty two the counting
/// argument in this module's header needs. Runs of eight need two and leave
/// exactly twenty two.
///
/// From above: the shortest body a published scanner will call a key is
/// Stripe's ten characters, so a run has to stop under ten to be unable to
/// finish one.
///
/// Eight is the only value both sides allow. It is public because the P-0 gate
/// checks against this number rather than against a copy of it.
pub const KEY_GROUP: usize = 8;

/// What interrupts a run.
///
/// A full stop, for two reasons that pull in opposite directions and both have
/// to hold. It is outside every published key charset, which are `[A-Za-z0-9]`
/// and sometimes also `_` and `-`, so it is what makes the run stop counting for
/// a scanner. And it is ordinary in every transport the alias has to survive
/// where the real value did: unreserved in a URI (RFC 3986 section 2.3), plain
/// inside a JSON string, plain in an HTTP header value, and not a shell
/// metacharacter. An alias that needed escaping where the key did not would
/// break the caller in a new way while fixing this one.
pub const KEY_SEPARATOR: char = '.';

/// The length classes a key body is rounded up to (ADR-010 section 2).
const LENGTH_CLASSES: [usize; 3] = [32, 64, 128];

/// An IBAN with the source's country, length and field shape, and check digits
/// that are deliberately not the right ones.
///
/// `None` when the source is not something an IBAN could be, which is a
/// detection failure rather than a masking one; the caller drops to rung `O`
/// rather than inventing a country.
pub fn iban(stream: &mut SeedStream, source: &str) -> Option<String> {
    let compact = checksum::compact_iban(source);
    if !(15..=34).contains(&compact.len()) {
        return None;
    }
    let country = compact.get(..2)?;
    if !country
        .chars()
        .all(|character| character.is_ascii_uppercase())
    {
        return None;
    }
    let source_body = compact.get(4..)?;
    if !source_body
        .chars()
        .all(|character| character.is_ascii_alphanumeric())
    {
        return None;
    }

    // The field shape is copied, the field contents are not. A country whose
    // account body starts with four letters still starts with four letters, so
    // substring extraction downstream keeps working.
    let body: String = source_body
        .chars()
        .map(|character| {
            if character.is_ascii_digit() {
                char::from(b'0' + stream.digit())
            } else {
                stream.pick_char(IBAN_LETTERS)
            }
        })
        .collect();

    let correct = checksum::iban_check_digits(country, &body)?;
    let wrong = wrong_check_digits(stream, correct);
    Some(format!("{country}{wrong:02}{body}"))
}

/// A pair of check digits inside ISO 13616's 02 to 98 range that is not the
/// correct pair.
///
/// The offset is never zero, so the result differs from `correct` by
/// construction rather than by a check afterwards. Staying inside 02 to 98
/// matters because a pair outside it is refused by shape before mod 97 is even
/// reached, and the alias would then fail for the wrong reason.
fn wrong_check_digits(stream: &mut SeedStream, correct: u8) -> u8 {
    let offset = stream.below(96) + 1;
    let shifted = (u32::from(correct.saturating_sub(2)) + offset) % 97;
    // The arithmetic stays under 99, so the conversion cannot lose anything.
    // The fallback is still one that holds the invariant rather than a constant
    // that happens to be in range: see [`a_pair_other_than`].
    u8::try_from(shifted + 2).unwrap_or_else(|_| a_pair_other_than(correct))
}

/// A check digit pair inside ISO 13616's 02 to 98 range that is not `correct`.
///
/// **Why this exists when the branch above cannot be taken.** `shifted + 2` is at
/// most 98, so the conversion in [`wrong_check_digits`] never fails and a reader
/// can prove it from the modulus on the line above. `unwrap_or(2)` was written on
/// that proof and it is the wrong thing to lean on: the proof holds until somebody
/// edits the modulus, and what it protects is ADR-010's P-0, which says every rung
/// `I` alias is **provably** not a real value. A constant `2` is not provably
/// different from `correct`, so the one edit that broke the reachability argument
/// would also have handed out an alias with the right check digits on it, silently
/// and only sometimes. The value is what the invariant needs and the argument is
/// no longer load bearing.
///
/// Total for every `u8`, including the ones `iban_check_digits` cannot return, so
/// the test below can be exhaustive rather than representative.
const fn a_pair_other_than(correct: u8) -> u8 {
    if correct == 2 {
        3
    } else {
        2
    }
}

/// Eleven digits with a leading digit that is not zero, and both check digits
/// deliberately wrong.
pub fn tckn(stream: &mut SeedStream) -> String {
    let mut digits = [0u8; 9];
    // The first digit of a TCKN is never zero, and that is a shape rule rather
    // than a check digit rule: keeping it is what makes the alias parseable.
    digits[0] = 1 + stream.digit() % 9;
    for slot in digits.iter_mut().skip(1) {
        *slot = stream.digit();
    }

    let (correct_tenth, _) = checksum::tckn_check_digits(&digits);
    let tenth = wrong_digit(stream, correct_tenth);
    // The eleventh rule reads the tenth digit, so its correct value is computed
    // against the tenth this alias actually carries. Breaking both means neither
    // rule can be the one that accidentally holds.
    let sum: u32 = digits.iter().map(|digit| u32::from(*digit)).sum::<u32>() + u32::from(tenth);
    let correct_eleventh = u8::try_from(sum % 10).unwrap_or(0);
    let eleventh = wrong_digit(stream, correct_eleventh);

    let body: String = digits
        .iter()
        .map(|digit| char::from(b'0' + digit))
        .collect();
    format!("{body}{tenth}{eleventh}")
}

/// Ten digits with a check digit that is deliberately wrong.
pub fn vkn(stream: &mut SeedStream) -> String {
    let mut digits = [0u8; 9];
    for slot in digits.iter_mut() {
        *slot = stream.digit();
    }
    let correct = checksum::vkn_check_digit(&digits);
    let check = wrong_digit(stream, correct);
    let body: String = digits
        .iter()
        .map(|digit| char::from(b'0' + digit))
        .collect();
    format!("{body}{check}")
}

/// A digit that is not `correct`, chosen from the stream.
fn wrong_digit(stream: &mut SeedStream, correct: u8) -> u8 {
    let offset = stream.below(9) + 1;
    // Offsets run one to nine, so the result is never the correct digit.
    // `% 10` bounds the conversion's input to nine and the branch below cannot be
    // taken; it returns a digit that holds the invariant anyway, for the reason
    // [`a_pair_other_than`] gives.
    u8::try_from((u32::from(correct) + offset) % 10).unwrap_or_else(|_| a_digit_other_than(correct))
}

/// A decimal digit that is not `correct`.
///
/// The counterpart of [`a_pair_other_than`] for the TCKN and VKN check digits, and
/// it is here for the same reason: `unwrap_or(0)` returned a fixed digit that
/// nothing proved differs from the correct one, so a build whose modulus had been
/// edited would mint a TCKN alias carrying a **valid** check digit one time in ten
/// and P-0's "provably not a real value" would be false with no test able to see
/// it.
const fn a_digit_other_than(correct: u8) -> u8 {
    if correct == 0 {
        1
    } else {
        0
    }
}

/// What a key alias came out as, and whether its length class had to be cut.
pub struct KeyAlias {
    pub alias: String,
    /// The source was longer than the largest class, so the alias is capped at
    /// 128 bytes and `alias_stats.alias_length_class_capped` counts it
    /// (ADR-010 section 2).
    pub length_class_capped: bool,
}

/// A key alias: the source's prefix, then a grouped body drawn from the stream,
/// rounded to the smallest length class that covers the source.
pub fn key(stream: &mut SeedStream, source: &str) -> KeyAlias {
    let prefix = carried_prefix(source);
    let (class, capped) = length_class(source.len());
    let body_length = class.saturating_sub(prefix.len());
    let body = grouped_body(stream, body_length);
    KeyAlias {
        alias: format!("{prefix}{body}"),
        length_class_capped: capped,
    }
}

/// `length` bytes of drawn characters, in runs of at most [`KEY_GROUP`]
/// separated by [`KEY_SEPARATOR`].
///
/// The runs are as even as the length allows rather than "eight until the
/// remainder runs out", so that the last group is not a short tail announcing
/// where the body ends.
fn grouped_body(stream: &mut SeedStream, length: usize) -> String {
    let groups = group_count(length);
    if groups == 0 {
        return String::new();
    }
    // `groups - 1` separators, and what is left is drawn.
    let drawn = length.saturating_sub(groups - 1);
    let base = drawn / groups;
    let longer = drawn % groups;
    let mut out = String::with_capacity(length);
    for group in 0..groups {
        if group > 0 {
            out.push(KEY_SEPARATOR);
        }
        for _ in 0..(base + usize::from(group < longer)) {
            out.push(stream.pick_char(BASE62));
        }
    }
    out
}

/// How many runs a body of `length` bytes is split into.
///
/// The fewest that keep every run at or under [`KEY_GROUP`]: `g` runs cost
/// `g - 1` separators, so `length - (g - 1) <= KEY_GROUP * g`, which rearranges
/// to `g >= (length + 1) / (KEY_GROUP + 1)`. Fewest, because every separator is
/// a byte the counting argument does not get.
fn group_count(length: usize) -> usize {
    if length == 0 {
        return 0;
    }
    length.saturating_add(1).div_ceil(KEY_GROUP + 1).max(1)
}

/// The part of a key that says which provider it belongs to.
///
/// Everything up to and including the last underscore inside the first
/// [`MAX_KEY_PREFIX`] bytes, which covers the shapes providers actually publish
/// (`ghp_`, `sk_live_`). A key with no underscore there carries no prefix,
/// because guessing where an opaque token's "prefix" ends would move source
/// bytes into the alias for no gain.
fn carried_prefix(source: &str) -> &str {
    let window_end = source
        .char_indices()
        .map(|(index, character)| index + character.len_utf8())
        .take_while(|end| *end <= MAX_KEY_PREFIX)
        .last()
        .unwrap_or(0);
    let window = source.get(..window_end).unwrap_or_default();
    match window.rfind('_') {
        Some(at) => window.get(..=at).unwrap_or_default(),
        None => "",
    }
}

/// The smallest class that covers this length, and whether the cap was reached.
fn length_class(source_length: usize) -> (usize, bool) {
    for class in LENGTH_CLASSES {
        if source_length <= class {
            return (class, false);
        }
    }
    // Over the largest class. ADR-010 section 2: the alias is 128 bytes and the
    // run reports that a length class was capped, rather than the alias growing
    // with the secret and taking the streaming buffer with it.
    (128, true)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::checksum::Verdict;
    use super::super::entity::EntityType;
    use super::*;

    fn stream(byte: u8) -> SeedStream {
        SeedStream::new(&[byte; 32]).unwrap()
    }

    /// A sweep of the seed space rather than one example. ADR-010's invariant is
    /// "the validator rejects it", not "the validator rejected it once".
    fn seeds() -> impl Iterator<Item = SeedStream> {
        (0..=255u8).map(|byte| SeedStream::new(&[byte; 32]).unwrap())
    }

    #[test]
    fn every_generated_iban_fails_mod_97_and_keeps_the_source_shape() {
        let sources = [
            "TR330006100519786457841326",
            "GB82WEST12345698765432",
            "DE89370400440532013000",
        ];
        let mut produced = 0;
        for mut source_stream in seeds() {
            for source in sources {
                let alias = iban(&mut source_stream, source).expect("shaped like an IBAN");
                assert!(
                    !checksum::iban_is_valid(&alias),
                    "{alias} passes mod 97, so it could be somebody's account"
                );
                assert_eq!(alias.len(), source.len(), "{alias}");
                assert_eq!(alias.get(..2), source.get(..2), "{alias}");
                // The check digits stay inside the range ISO 13616 allows, so
                // the alias fails on the checksum rather than on its shape.
                let check: u8 = alias.get(2..4).unwrap().parse().unwrap();
                assert!((2..=98).contains(&check), "{alias}");
                // Digit and letter positions survive, which is what keeps field
                // extraction working downstream.
                for (mine, theirs) in alias.chars().skip(4).zip(source.chars().skip(4)) {
                    assert_eq!(mine.is_ascii_digit(), theirs.is_ascii_digit(), "{alias}");
                }
                produced += 1;
            }
        }
        assert_eq!(produced, 256 * sources.len());
    }

    #[test]
    fn a_source_that_is_not_an_iban_produces_no_iban() {
        // The caller falls to rung O rather than this function inventing a
        // country code out of a value detection got wrong.
        assert!(iban(&mut stream(1), "").is_none());
        assert!(iban(&mut stream(1), "12345678901234567").is_none());
        assert!(iban(&mut stream(1), "TR33").is_none());
        assert!(iban(&mut stream(1), &"T".repeat(40)).is_none());
    }

    #[test]
    fn every_generated_tckn_fails_both_check_digits() {
        let mut produced = 0;
        for mut source in seeds() {
            for _ in 0..4 {
                let alias = tckn(&mut source);
                assert_eq!(alias.len(), 11, "{alias}");
                assert!(alias.chars().all(|c| c.is_ascii_digit()), "{alias}");
                assert_ne!(alias.chars().next(), Some('0'), "{alias}");
                assert!(
                    !checksum::tckn_is_valid(&alias),
                    "{alias} passes the TCKN rule, so it could be somebody's number"
                );
                produced += 1;
            }
        }
        assert_eq!(produced, 256 * 4);
    }

    #[test]
    fn every_generated_vkn_fails_its_check_digit() {
        let mut produced = 0;
        for mut source in seeds() {
            for _ in 0..4 {
                let alias = vkn(&mut source);
                assert_eq!(alias.len(), 10, "{alias}");
                assert!(alias.chars().all(|c| c.is_ascii_digit()), "{alias}");
                assert!(
                    !checksum::vkn_is_valid(&alias),
                    "{alias} passes the VKN rule"
                );
                produced += 1;
            }
        }
        assert_eq!(produced, 256 * 4);
    }

    /// The longest run of alphanumeric characters in a string.
    ///
    /// The quantity a scanner pattern counts: every one of them is a literal
    /// marker followed by a run of body characters, so a short longest run is
    /// what makes the pattern unfinishable.
    fn longest_run(text: &str) -> usize {
        let mut longest = 0;
        let mut current = 0;
        for character in text.chars() {
            if character.is_ascii_alphanumeric() {
                current += 1;
                longest = longest.max(current);
            } else {
                current = 0;
            }
        }
        longest
    }

    /// Characters drawn from the stream, which is what the counting argument
    /// counts. Separators are structure and carry nothing.
    fn drawn_characters(alias: &str, prefix: &str) -> usize {
        alias
            .get(prefix.len()..)
            .unwrap_or_default()
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .count()
    }

    #[test]
    fn a_key_alias_keeps_its_prefix_and_rounds_to_a_length_class() {
        // The sources here carry provider prefixes on purpose and are broken up
        // on purpose: a test input does not need to be a string a secret
        // scanner will call a key, and one that is turns this file into a
        // finding in every repository that holds it. What is under test is the
        // prefix and the length class, and neither needs a long run.
        let cases = [
            // Thirty nine characters: over the 32 class, so it rounds to 64.
            ("ghp_ABCDEFGH.IJKLMNOP.QRSTUVWX.YZ012345", "ghp_", 64),
            // Twenty five: the smallest class that covers it is 32.
            ("sk_live_ABCDEFGH.IJKLMNOP", "sk_live_", 32),
            ("AKIA.IOSFODNN7EXAMPLE", "", 32),
            ("github_pat_11ABCDE0123456789", "github_", 32),
        ];
        for (source, prefix, class) in cases {
            let produced = key(&mut stream(7), source);
            assert!(produced.alias.starts_with(prefix), "{}", produced.alias);
            assert_eq!(produced.alias.len(), class, "{}", produced.alias);
            assert!(!produced.length_class_capped);
            assert_ne!(produced.alias, source);
            // Nothing of the body survives: only the prefix is carried.
            assert!(!produced.alias.contains("EXAMPLE"));
            assert!(!produced.alias.contains("IJKLMNOP"));
            // And no run is long enough for a scanner to finish a pattern on.
            assert!(
                longest_run(&produced.alias) <= KEY_GROUP,
                "{}",
                produced.alias
            );
        }
    }

    #[test]
    fn no_key_alias_offers_a_run_a_scanner_could_finish() {
        // The structural half of the fix, swept rather than sampled. A single
        // example proves nothing about a generator that draws from a seed, and
        // the property has to hold for every prefix length: the prefix is what
        // decides how many bytes the groups have to share.
        // No source here is a scanner match either: a marker is followed by a
        // short run, or there is no marker at all. A fixture that is itself a
        // match is a finding in every clone of this repository, and nothing
        // under test needs one, because the generator reads only the total
        // length and the first underscore.
        let sources = [
            "x",
            "sk_live_x",
            "sk_test_01234567.01234567",
            "ghp_01234567.01234567",
            "github_pat_01234567.01234567",
            "AKIA0123.45678901",
            "xoxb-0123.45678901",
            "AIza0123.45678901",
            "a_b",
            "abcdefg_hij",
            &"y".repeat(64),
            &"z".repeat(300),
        ];
        let mut produced = 0;
        for mut source_stream in seeds() {
            for source in sources {
                let alias = key(&mut source_stream, source).alias;
                assert!(
                    longest_run(&alias) <= KEY_GROUP,
                    "{alias} carries a run of {}",
                    longest_run(&alias)
                );
                produced += 1;
            }
        }
        assert_eq!(produced, 256 * sources.len());
    }

    #[test]
    fn a_secret_over_the_largest_class_is_capped_and_says_so() {
        let long = format!("sk_{}", "x".repeat(200));
        let produced = key(&mut stream(9), &long);
        assert!(produced.length_class_capped);
        assert_eq!(produced.alias.len(), 128);

        // And the body still carries more than the 128 bits the entropy
        // argument in this module's documentation rests on. Counted in drawn
        // characters, because the separators are structure and a body that lost
        // its entropy to separators would still be 125 bytes long.
        let drawn = drawn_characters(&produced.alias, "sk_");
        assert!(drawn >= 22, "{drawn}");
    }

    #[test]
    fn a_long_key_body_does_not_repeat_itself() {
        // A regression lock. The seed window used to be shorter than the longest
        // body, so a 128 character alias wrapped and printed its own opening
        // characters again halfway through. That is not a P-0 failure, it is a
        // recognisable pattern in something that should look like nothing.
        let produced = key(&mut stream(0x33), &"x".repeat(300));
        let body = produced.alias.as_str();
        let half = body.len() / 2;
        assert_eq!(body.len(), 128);
        assert_ne!(body.get(..half), body.get(half..), "{body}");
        for window in 8..=32 {
            let head = body.get(..window).unwrap_or_default();
            assert_eq!(
                body.matches(head).count(),
                1,
                "the first {window} characters appear twice in {body}"
            );
        }
    }

    #[test]
    fn every_key_body_is_long_enough_for_the_entropy_argument() {
        // Threat model R14's proof is a counting argument, and this is the
        // quantity it counts. Twenty two base62 characters is just over 128
        // bits; every class and prefix combination has to clear it, and the
        // group separators are not allowed to eat into it.
        for source in [
            "x",
            "sk_live_x",
            // The tightest case there is: the longest prefix this build carries
            // against the shortest length class, which leaves exactly the
            // twenty two the argument needs and no slack at all.
            "sk_live_01234567.0123456",
            "0123456789_0123456789",
            &"y".repeat(64),
            &"z".repeat(300),
        ] {
            let produced = key(&mut stream(3), source);
            let prefix = carried_prefix(source);
            let drawn = drawn_characters(&produced.alias, prefix);
            assert!(drawn >= 22, "{source} left {drawn} drawn characters");
        }
    }

    #[test]
    fn a_prefix_longer_than_the_window_is_cut_rather_than_carried_whole() {
        // The window shrank from ten bytes to eight to pay for the separators,
        // and this is what that costs: a prefix whose underscore sits past the
        // eighth byte is not carried. Nothing published has one, and the two
        // shapes that come close are unaffected.
        assert_eq!(carried_prefix("sk_live_abcdef"), "sk_live_");
        assert_eq!(carried_prefix("sk_test_abcdef"), "sk_test_");
        assert_eq!(carried_prefix("ghp_abcdef"), "ghp_");
        assert_eq!(carried_prefix("github_pat_abcdef"), "github_");
        assert_eq!(carried_prefix("abcdefgh_abcdef"), "");
        assert_eq!(carried_prefix("xoxb-abcdef"), "");
    }

    /// The branch the arithmetic cannot reach, held to the invariant anyway.
    ///
    /// P-0 says a rung `I` alias is provably not a real value, and before this the
    /// proof had a hole with an argument in it: `unwrap_or(2)` and `unwrap_or(0)`
    /// returned a fixed digit, nothing showed that digit differs from the correct
    /// one, and the only thing keeping it out of an alias was that `% 97` and
    /// `% 10` bound their conversions. That is a proof about **today's** modulus.
    /// Tested exhaustively over every `u8` rather than over the range the
    /// checksums actually produce, because the point is that the fallback is total
    /// and not that it happens to be safe on the inputs it sees.
    #[test]
    fn the_fallback_check_digit_is_never_the_correct_one() {
        for correct in 0u8..=u8::MAX {
            let pair = a_pair_other_than(correct);
            assert_ne!(pair, correct, "the pair fallback returned the correct pair");
            // ISO 13616's range, or the alias would be refused by shape before mod
            // 97 is reached and would fail for the wrong reason.
            assert!((2..=98).contains(&pair), "{pair} is outside 02..=98");

            let digit = a_digit_other_than(correct);
            assert_ne!(
                digit, correct,
                "the digit fallback returned the correct one"
            );
            assert!(digit <= 9, "{digit} is not a decimal digit");
        }
    }

    #[test]
    fn the_verdict_over_generated_aliases_is_invalid_for_the_checksum_types() {
        // The same claim as the sweeps above, phrased the way the P-0 gate asks
        // it: through the type's own validator rather than through a helper.
        let mut source = stream(0x2C);
        assert_eq!(
            checksum::verdict(EntityType::Tckn, &tckn(&mut source)),
            Verdict::Invalid
        );
        assert_eq!(
            checksum::verdict(EntityType::Vkn, &vkn(&mut source)),
            Verdict::Invalid
        );
        let produced = iban(&mut source, "TR330006100519786457841326").unwrap();
        assert_eq!(
            checksum::verdict(EntityType::Iban, &produced),
            Verdict::Invalid
        );
    }
}
