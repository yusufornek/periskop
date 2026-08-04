//! The rule file: every range an alias may be drawn from, and where it is
//! published.
//!
//! ADR-010 section 5.1 makes the citation part of the rule rather than part of
//! the commit message:
//!
//! > The reference of the source document (RFC number, regulator decision
//! > number) is written into the rule file; a range with no reference may not be
//! > used.
//!
//! The audit that produced that sentence is the reason for it. The original
//! design listed five "reserved ranges" and two of them did not exist: ISO 13616
//! defines no test IBAN space, and `+90 555` is inside Turkey's allocated mobile
//! block. Both had been written down with the same confidence as `.invalid`, and
//! nothing in the code could tell the difference. So a range here is a value of a
//! type that cannot be built without a [`Citation`], and a test walks the whole
//! file to check that every citation is filled in.
//!
//! # What a citation is not
//!
//! It is not a promise that the range is safe forever, and it is not a substitute
//! for the invariant tests. It is the evidence a reviewer can check without
//! trusting this module: read the publication, decide whether it says what the
//! entry claims.
//!
//! # The three kinds of entry here
//!
//! - **Address space** ([`INVALID_TLD`], [`IPV4_DOCUMENTATION`], [`IPV6_DOCUMENTATION`]):
//!   ranges standards bodies have removed from allocation entirely.
//! - **Published test values** ([`TEST_PANS`]): finite lists that payment
//!   providers publish precisely so that they can be used in place of a real
//!   card. Finite is the operative word; see [`super::card`].
//! - **National numbering facts** ([`PHONE_PLANS`]): the fiction ranges some
//!   regulators publish, and the maximum national number length every plan
//!   publishes. A country with neither is a country whose numbers go opaque.

use super::entity::EntityType;

/// Where a range is published.
///
/// Both fields are required. A publication with no locator ("RFC 5737", but
/// which part) sends a reviewer hunting, and the point of this type is that
/// checking an entry is cheaper than trusting it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Citation {
    /// The document: an RFC number, a regulator's publication, a provider's
    /// published test list.
    pub publication: &'static str,
    /// Where inside it: a section number, or the name of the table.
    pub locator: &'static str,
}

impl Citation {
    /// Whether this citation actually points at something.
    ///
    /// Used by the coverage test rather than at run time: an empty citation is a
    /// review failure, not a request failure.
    pub fn is_filled_in(&self) -> bool {
        !self.publication.trim().is_empty() && !self.locator.trim().is_empty()
    }
}

/// The top level domain that is never resolved and never delegated.
///
/// RFC 2606 sets aside `.invalid` "for use in online construction of domain
/// names that are sure to be invalid". No registry may allocate under it, so an
/// alias ending in it cannot be somebody's host, and a resolver that is handed
/// one fails immediately and visibly rather than reaching a stranger's server.
pub const INVALID_TLD: &str = ".invalid";

/// The citation for [`INVALID_TLD`].
pub const INVALID_TLD_CITATION: Citation = Citation {
    publication: "RFC 2606, Reserved Top Level DNS Names",
    locator: "section 2",
};

/// The second level labels the generators put in front of [`INVALID_TLD`].
///
/// These carry no reservation of their own and they do not need one: everything
/// under `.invalid` is unallocatable whatever the label says. They exist so that
/// two different hosts in one conversation stay two different hosts.
pub const EXAMPLE_LABELS: [&str; 8] = [
    "example-a",
    "example-b",
    "example-c",
    "example-d",
    "example-e",
    "example-f",
    "example-g",
    "example-h",
];

/// An IPv4 block reserved for documentation. All three of RFC 5737's blocks are
/// /24, so the first three octets are the whole of the membership test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Documentation {
    /// The fixed part of every address in the block.
    pub network: [u8; 3],
    /// What the block is called in the RFC, for log lines and review.
    pub name: &'static str,
    pub citation: Citation,
}

/// The IPv4 documentation blocks (RFC 5737).
///
/// "Addresses within these blocks ... should not appear on the public Internet",
/// and no registry allocates from them. Three blocks rather than one because a
/// /24 holds 256 addresses and a session may mask more hosts than that; running
/// out means falling to rung `O`, which is a real quality loss (see
/// [`super::rung_r`]).
pub const IPV4_DOCUMENTATION: [Ipv4Documentation; 3] = [
    Ipv4Documentation {
        network: [203, 0, 113],
        name: "TEST-NET-3",
        citation: Citation {
            publication: "RFC 5737, IPv4 Address Blocks Reserved for Documentation",
            locator: "section 3",
        },
    },
    Ipv4Documentation {
        network: [198, 51, 100],
        name: "TEST-NET-2",
        citation: Citation {
            publication: "RFC 5737, IPv4 Address Blocks Reserved for Documentation",
            locator: "section 3",
        },
    },
    Ipv4Documentation {
        network: [192, 0, 2],
        name: "TEST-NET-1",
        citation: Citation {
            publication: "RFC 5737, IPv4 Address Blocks Reserved for Documentation",
            locator: "section 3",
        },
    },
];

/// The IPv6 documentation prefix, `2001:db8::/32` (RFC 3849).
pub const IPV6_DOCUMENTATION_PREFIX: &str = "2001:db8:";

/// The citation for [`IPV6_DOCUMENTATION_PREFIX`].
pub const IPV6_DOCUMENTATION_CITATION: Citation = Citation {
    publication: "RFC 3849, IPv6 Address Prefix Reserved for Documentation",
    locator: "section 4",
};

/// One published test card number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TestPan {
    /// The digits, with no separators.
    pub digits: &'static str,
    pub citation: Citation,
}

/// Payment provider test card lists, published so that a caller has something to
/// send that is not a real card.
const STRIPE: Citation = Citation {
    publication: "Stripe published test card numbers",
    locator: "docs.stripe.com/testing, basic test cards",
};

/// The other widely published list, carried separately so that an entry can be
/// checked against the list it came from.
const PAYPAL: Citation = Citation {
    publication: "PayPal published test credit card numbers",
    locator: "developer.paypal.com, credit card numbers for testing",
};

/// The finite pool rung `R` draws card aliases from.
///
/// Finite is the property that matters and it is why [`super::card`] has a
/// second rung underneath. ADR-010 is explicit about what may **not** happen
/// when the pool runs out: taking the `4111` prefix and computing a valid Luhn
/// check digit is forbidden, because another number in that BIN can be a real
/// card. The fallback breaks Luhn instead.
///
/// Every entry is verified by the unit test below to be Luhn valid and to be the
/// length its brand uses, which is the cheapest way to catch a mistyped digit.
/// A mistyped PAN is not a cosmetic defect here: it is a number nobody published.
pub const TEST_PANS: [TestPan; 16] = [
    TestPan {
        digits: "4242424242424242",
        citation: STRIPE,
    },
    TestPan {
        digits: "4000056655665556",
        citation: STRIPE,
    },
    TestPan {
        digits: "4111111111111111",
        citation: PAYPAL,
    },
    TestPan {
        digits: "4012888888881881",
        citation: PAYPAL,
    },
    TestPan {
        digits: "4222222222222",
        citation: PAYPAL,
    },
    TestPan {
        digits: "5555555555554444",
        citation: STRIPE,
    },
    TestPan {
        digits: "5200828282828210",
        citation: STRIPE,
    },
    TestPan {
        digits: "5105105105105100",
        citation: PAYPAL,
    },
    TestPan {
        digits: "2223003122003222",
        citation: STRIPE,
    },
    TestPan {
        digits: "378282246310005",
        citation: STRIPE,
    },
    TestPan {
        digits: "371449635398431",
        citation: PAYPAL,
    },
    TestPan {
        digits: "6011111111111117",
        citation: STRIPE,
    },
    TestPan {
        digits: "6011000990139424",
        citation: PAYPAL,
    },
    TestPan {
        digits: "3056930009020004",
        citation: STRIPE,
    },
    TestPan {
        digits: "3566002020360505",
        citation: STRIPE,
    },
    TestPan {
        digits: "36227206271667",
        citation: PAYPAL,
    },
];

/// A published fiction range inside a national numbering plan.
///
/// The shape covers both kinds a regulator publishes: a fixed prefix (Ofcom's
/// drama numbers) and a reserved block that sits behind a free area code
/// (NANPA's 555-01XX line numbers). The digits the seed supplies are named
/// rather than implied so that a generator cannot accidentally step outside the
/// reserved block while filling them in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FictionRange {
    /// Digits taken from the seed before the reserved block, such as a NANPA
    /// area code. Zero for a plan whose reservation starts at the front.
    pub head_digits: usize,
    /// The reserved block itself.
    pub block: &'static str,
    /// Digits taken from the seed after the block.
    pub tail_digits: usize,
    pub citation: Citation,
}

impl FictionRange {
    /// Total national significant number length this range produces.
    pub const fn national_digits(&self) -> usize {
        self.head_digits + self.block.len() + self.tail_digits
    }

    /// How many distinct numbers the range holds, saturating rather than
    /// overflowing on a plan with many free digits.
    pub fn capacity(&self) -> u64 {
        10u64.saturating_pow((self.head_digits + self.tail_digits) as u32)
    }
}

/// What is published about one country's numbering plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhonePlan {
    /// E.164 country code, digits only.
    pub country_code: &'static str,
    /// The published maximum national significant number length. Rung `I` adds
    /// one digit past this, which is what makes the result unallocatable.
    pub national_digits: usize,
    /// Where that maximum is published.
    pub length_citation: Citation,
    /// The fiction range, where the regulator publishes one.
    pub fiction: Option<FictionRange>,
}

/// The countries this build can say something published about.
///
/// A short list on purpose. KG-011 records the consequence: a country that is not
/// here produces an opaque alias, which masks correctly and loses the shape. The
/// way to close that gap is to add entries with citations, never to guess a range
/// from a pattern. Turkey is the worked example of why: the range the original
/// design used, `+90 555`, is inside the allocated mobile block.
pub const PHONE_PLANS: [PhonePlan; 3] = [
    PhonePlan {
        country_code: "90",
        national_digits: 10,
        length_citation: Citation {
            publication: "ITU-T E.164 national numbering plan for Turkey (BTK numbering plan)",
            locator: "national significant number is 10 digits",
        },
        // Turkey publishes no drama or fiction range. This `None` is the whole
        // point of the D-14 revision: the previous design invented one.
        fiction: None,
    },
    PhonePlan {
        country_code: "44",
        national_digits: 10,
        length_citation: Citation {
            publication: "Ofcom National Telephone Numbering Plan",
            locator: "mobile numbers, 10 digit national significant number",
        },
        fiction: Some(FictionRange {
            head_digits: 0,
            block: "7700900",
            tail_digits: 3,
            citation: Citation {
                publication: "Ofcom, telephone numbers for drama use",
                locator: "07700 900000 to 07700 900999",
            },
        }),
    },
    PhonePlan {
        country_code: "1",
        national_digits: 10,
        length_citation: Citation {
            publication: "North American Numbering Plan",
            locator: "NPA-NXX-XXXX, 10 digit national significant number",
        },
        fiction: Some(FictionRange {
            // The area code is free: the reservation is on the line numbers
            // behind central office code 555, in every area code.
            head_digits: 3,
            block: "55501",
            tail_digits: 2,
            citation: Citation {
                publication: "INC 555 NXX Assignment Guidelines",
                locator: "line numbers 555-0100 through 555-0199, fictitious use",
            },
        }),
    },
];

/// The plan for a country code, or `None` if this build has no citation for it.
pub fn plan_for_country(country_code: &str) -> Option<&'static PhonePlan> {
    PHONE_PLANS
        .iter()
        .find(|plan| plan.country_code == country_code)
}

/// The longest registered country code that this number starts with, after the
/// leading `+`.
///
/// Longest match, because country codes are a prefix code only when read that
/// way: `1` and `44` would both match a number that begins `+1...` if the
/// shorter were taken first.
pub fn country_code_of(e164: &str) -> Option<&'static str> {
    let digits = e164.strip_prefix('+')?;
    let mut best: Option<&'static str> = None;
    for plan in &PHONE_PLANS {
        if digits.starts_with(plan.country_code)
            && best.is_none_or(|current| plan.country_code.len() > current.len())
        {
            best = Some(plan.country_code);
        }
    }
    best
}

/// Whether a host name lies in the documented range.
pub fn host_is_documented(alias: &str) -> bool {
    let lowered = alias.to_ascii_lowercase();
    lowered.ends_with(INVALID_TLD) && lowered.len() > INVALID_TLD.len()
}

/// Whether an address lies in the documented range.
pub fn email_is_documented(alias: &str) -> bool {
    match alias.split_once('@') {
        Some((local, domain)) => !local.is_empty() && host_is_documented(domain),
        None => false,
    }
}

/// Whether an IPv4 address lies in one of RFC 5737's blocks.
pub fn ipv4_is_documented(alias: &str) -> bool {
    let mut octets = [0u16; 4];
    let mut seen = 0;
    for part in alias.split('.') {
        if seen == octets.len() {
            return false;
        }
        match part.parse::<u16>() {
            Ok(value) if value <= 255 && !part.is_empty() => octets[seen] = value,
            _ => return false,
        }
        seen += 1;
    }
    if seen != octets.len() {
        return false;
    }
    IPV4_DOCUMENTATION.iter().any(|block| {
        u16::from(block.network[0]) == octets[0]
            && u16::from(block.network[1]) == octets[1]
            && u16::from(block.network[2]) == octets[2]
    })
}

/// Whether an IPv6 address lies in `2001:db8::/32`.
///
/// A prefix comparison rather than a parse, because the generator only ever
/// writes the canonical lower case form and a parser here would be a second
/// implementation of something no other code in this crate needs yet.
pub fn ipv6_is_documented(alias: &str) -> bool {
    alias
        .to_ascii_lowercase()
        .starts_with(IPV6_DOCUMENTATION_PREFIX)
}

/// Whether a card number is one of the published test numbers.
pub fn pan_is_documented(alias: &str) -> bool {
    let digits: String = alias.chars().filter(char::is_ascii_digit).collect();
    TEST_PANS.iter().any(|pan| pan.digits == digits)
}

/// Whether a phone number lies inside a published fiction range.
pub fn phone_is_documented(alias: &str) -> bool {
    let Some(country) = country_code_of(alias) else {
        return false;
    };
    let Some(plan) = plan_for_country(country) else {
        return false;
    };
    let Some(fiction) = plan.fiction else {
        return false;
    };
    let Some(digits) = alias.strip_prefix('+').map(|rest| {
        rest.chars()
            .filter(char::is_ascii_digit)
            .collect::<String>()
    }) else {
        return false;
    };
    let Some(national) = digits.strip_prefix(country) else {
        return false;
    };
    if national.len() != fiction.national_digits() {
        return false;
    }
    let block_at = fiction.head_digits;
    let block_end = block_at + fiction.block.len();
    national
        .get(block_at..block_end)
        .is_some_and(|found| found == fiction.block)
}

/// Whether this alias lies in the documented range its type draws from.
///
/// The invariant rung `R` has to keep (ADR-010 section 5.1), in one place, so
/// that the P-0 gate can ask the question for any type rather than restating it
/// per generator.
pub fn is_in_documented_range(entity: EntityType, alias: &str) -> bool {
    match entity {
        EntityType::Email => email_is_documented(alias),
        EntityType::Host | EntityType::Url => host_is_documented(alias),
        EntityType::Ipv4 => ipv4_is_documented(alias),
        EntityType::Ipv6 => ipv6_is_documented(alias),
        EntityType::CreditCard => pan_is_documented(alias),
        EntityType::Phone => phone_is_documented(alias),
        // No documented range is claimed for these types, so nothing can be in
        // one. Saying `false` rather than `true` matters: a caller asking "is
        // this rung R evidence" about an IBAN must not be told yes.
        EntityType::Iban
        | EntityType::Tckn
        | EntityType::Vkn
        | EntityType::ApiKey
        | EntityType::Secret
        | EntityType::Date
        | EntityType::Person
        | EntityType::Org
        | EntityType::Loc
        | EntityType::Address => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::checksum;
    use super::*;

    #[test]
    fn every_range_in_this_file_carries_a_citation() {
        let mut checked = 0;

        assert!(INVALID_TLD_CITATION.is_filled_in());
        assert!(IPV6_DOCUMENTATION_CITATION.is_filled_in());
        checked += 2;

        for block in &IPV4_DOCUMENTATION {
            assert!(
                block.citation.is_filled_in(),
                "{} has no citation",
                block.name
            );
            checked += 1;
        }
        for pan in &TEST_PANS {
            assert!(
                pan.citation.is_filled_in(),
                "{} has no citation",
                pan.digits
            );
            checked += 1;
        }
        for plan in &PHONE_PLANS {
            assert!(
                plan.length_citation.is_filled_in(),
                "+{} has no length citation",
                plan.country_code
            );
            checked += 1;
            if let Some(fiction) = plan.fiction {
                assert!(
                    fiction.citation.is_filled_in(),
                    "+{} has an uncited fiction range",
                    plan.country_code
                );
                checked += 1;
            }
        }

        // A scan that found nothing to scan passes silently, and this repository
        // has been bitten by that shape before. The count is the guard.
        assert!(checked >= 20, "only {checked} entries were checked");
    }

    #[test]
    fn every_published_test_pan_is_luhn_valid_and_distinct() {
        // A mistyped digit produces a number that nobody published, which is the
        // one thing this pool exists to avoid. Luhn catches most typos, and the
        // uniqueness check catches a duplicated line.
        let mut seen = std::collections::BTreeSet::new();
        for pan in &TEST_PANS {
            assert!(
                pan.digits
                    .chars()
                    .all(|character| character.is_ascii_digit()),
                "{} is not all digits",
                pan.digits
            );
            assert!(
                (13..=19).contains(&pan.digits.len()),
                "{} is {} digits",
                pan.digits,
                pan.digits.len()
            );
            assert!(
                checksum::luhn_is_valid(pan.digits),
                "{} fails Luhn, so it is not the number the provider published",
                pan.digits
            );
            assert!(seen.insert(pan.digits), "{} appears twice", pan.digits);
        }
        assert_eq!(seen.len(), TEST_PANS.len());
    }

    #[test]
    fn turkey_has_no_fiction_range_and_that_is_the_point() {
        let turkey = plan_for_country("90").unwrap();
        assert!(turkey.fiction.is_none());
        assert_eq!(turkey.national_digits, 10);

        // The only fiction ranges in this file are the two that are published,
        // and both belong to a country that is not Turkey. The behavioural half
        // of this claim, that no generator can produce a Turkish number inside
        // any range, is in `phone.rs` and runs over the seed space.
        let with_fiction: Vec<&str> = PHONE_PLANS
            .iter()
            .filter(|plan| plan.fiction.is_some())
            .map(|plan| plan.country_code)
            .collect();
        assert_eq!(with_fiction, vec!["44", "1"]);
    }

    #[test]
    fn documented_membership_answers_the_ranges_and_nothing_else() {
        assert!(host_is_documented("host7.example-a.invalid"));
        assert!(!host_is_documented("host7.example-a.com"));
        assert!(!host_is_documented(".invalid"));
        assert!(email_is_documented("user7@example-a.invalid"));
        assert!(!email_is_documented("user7@gmail.com"));
        assert!(!email_is_documented("example-a.invalid"));

        assert!(ipv4_is_documented("203.0.113.7"));
        assert!(ipv4_is_documented("192.0.2.255"));
        assert!(!ipv4_is_documented("8.8.8.8"));
        assert!(!ipv4_is_documented("203.0.114.7"));
        assert!(!ipv4_is_documented("203.0.113"));
        assert!(!ipv4_is_documented("203.0.113.7.7"));
        assert!(!ipv4_is_documented("203.0.113.256"));

        assert!(ipv6_is_documented("2001:db8:1234::1"));
        assert!(ipv6_is_documented("2001:DB8:1234::1"));
        assert!(!ipv6_is_documented("2001:db9:1234::1"));

        assert!(pan_is_documented("4242424242424242"));
        assert!(pan_is_documented("4242 4242 4242 4242"));
        assert!(!pan_is_documented("4242424242424243"));

        assert!(phone_is_documented("+447700900123"));
        assert!(!phone_is_documented("+447700901123"));
        assert!(phone_is_documented("+12125550123"));
        assert!(!phone_is_documented("+12125551234"));
        // Turkey has no fiction range, so no Turkish number is ever in one.
        assert!(!phone_is_documented("+905551234567"));
    }

    #[test]
    fn a_country_code_is_matched_at_its_full_length() {
        assert_eq!(country_code_of("+905551234567"), Some("90"));
        assert_eq!(country_code_of("+447700900123"), Some("44"));
        assert_eq!(country_code_of("+12125550123"), Some("1"));
        // Germany is not in the table, and nothing pretends otherwise.
        assert_eq!(country_code_of("+4930123456"), None);
        assert_eq!(country_code_of("05551234567"), None);
    }

    #[test]
    fn no_type_without_a_documented_range_claims_one() {
        for entity in EntityType::ALL {
            if matches!(
                entity,
                EntityType::Iban
                    | EntityType::Tckn
                    | EntityType::Vkn
                    | EntityType::ApiKey
                    | EntityType::Secret
                    | EntityType::Date
                    | EntityType::Person
                    | EntityType::Org
                    | EntityType::Loc
                    | EntityType::Address
            ) {
                // Whatever string is offered. There is no documented range for
                // these types, so the answer is no for every input.
                assert!(!is_in_documented_range(entity, "203.0.113.7"));
                assert!(!is_in_documented_range(entity, "user@example-a.invalid"));
                assert!(!is_in_documented_range(entity, ""));
            }
        }
    }
}
