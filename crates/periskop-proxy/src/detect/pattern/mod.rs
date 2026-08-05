//! Layer A: shapes that decide themselves, and the gates that finish the job.
//!
//! `proxy/spec.md` section 3.1 and ADR-011 section 1 make this layer mandatory
//! and always on, for a reason worth restating: the centre of gravity of the risk
//! this component exists for (identity numbers, tax numbers, IBANs, card
//! numbers, e-mail addresses, phone numbers, API keys) is entirely here, and all
//! of it is decidable from the text without asking anybody anything.
//!
//! # Two passes, not one
//!
//! Every detector is a **shape** and a **gate**. The shape is a regular
//! expression, run by `regex`, which ADR-016 section 1 chose for its linear time
//! guarantee: this scan runs over text an attacker picks, and a backtracking
//! engine would turn one prompt into a hang of a fail closed component, which
//! means every model call in the organization stops.
//!
//! The gate is in [`gate`], and it is what makes the layer usable. A shape alone
//! produces false positives at a rate that would make the product worse than not
//! running it: eleven digits is an order number as often as it is a TCKN.
//!
//! # Which way this layer errs, stated once
//!
//! A **missed** entity is a leak: the value reaches the provider, silently, and
//! cannot be recalled. A **false** detection is a damaged prompt: the model
//! answers a different question, loudly, and the operator can see it and fix the
//! policy. The two are not symmetric, so this layer is not tuned symmetrically:
//!
//! - Where a **published total rule** exists (IBAN, TCKN, VKN, card), the rule is
//!   applied and a value that fails it is **not** masked. Spec section 3.1
//!   requires exactly this. Erring toward detection here would mask most of the
//!   numbers in most prompts.
//! - Where **no** total rule exists (API key, e-mail, phone, URL), the gate is
//!   deliberately generous and the layer errs toward detection. A provider
//!   credential in a request log is the most expensive single outcome in this
//!   component's threat model.
//! - Where the value **identifies nobody** (loopback addresses, the documentation
//!   ranges this crate's own aliases come from), nothing is masked. That is not a
//!   miss; there is no entity.
//!
//! Every miss that follows from a gate is a line in `docs/05-quality/known-gaps.md`,
//! and the tests below name them.

pub mod gate;

use regex::Regex;
use std::sync::OnceLock;

use crate::alias::checksum;
use crate::alias::EntityType;

use super::span::{sort_candidates, Candidate};

/// One shape, its type, and the gate that decides whether a hit is real.
struct Detector {
    entity: EntityType,
    expression: &'static str,
    /// Runs over the matched text. `Some(range)` narrows the candidate to a
    /// sub-range of the match (`URL` keeps only its host), `None` rejects it.
    admit: fn(&str) -> Option<(usize, usize)>,
}

/// The shapes, in the order `proxy/spec.md` section 3.1's table lists them.
///
/// Order is not precedence. Overlaps are resolved in `detect::merge`, which is
/// the only place that decision is written, so that adding a detector here
/// cannot quietly change which type wins an argument.
fn detectors() -> &'static [Detector] {
    &[
        Detector {
            entity: EntityType::Iban,
            // Two letters, two check digits, then groups of up to four
            // alphanumerics with an optional single space **or hyphen**, which is
            // how an IBAN is printed. The gate compacts and applies mod 97.
            //
            // The hyphen is here because `checksum::compact_iban` already strips
            // one, so `TR33-0006-...` is a valid IBAN by every rule in this crate
            // and the shape was the only thing that never offered it. A format the
            // validator accepts and the detector never sees is an account number
            // reaching the provider with nothing to say so, and the two halves
            // disagreeing is worse than either choice: whoever reads the validator
            // concludes the format is covered.
            expression: r"\b[A-Z]{2}[0-9]{2}(?:[ -]?[A-Z0-9]{1,4}){2,8}\b",
            admit: admit_iban,
        },
        Detector {
            entity: EntityType::Tckn,
            expression: r"\b[1-9][0-9]{10}\b",
            admit: admit_tckn,
        },
        Detector {
            entity: EntityType::CreditCard,
            // Thirteen to nineteen digits with optional single space or hyphen
            // separators. Placed before VKN so the longer claim exists when
            // merge resolves the overlap.
            expression: r"\b[0-9]{4}(?:[ -]?[0-9]{1,6}){1,4}\b",
            admit: admit_card,
        },
        Detector {
            entity: EntityType::Vkn,
            expression: r"\b[0-9]{10}\b",
            admit: admit_vkn,
        },
        Detector {
            entity: EntityType::Email,
            // The RFC 5322 subset spec section 3.1 asks for: an unquoted local
            // part, a dotted domain, an alphabetic top level label. The letter
            // classes are Unicode rather than ASCII, which is KG-030: RFC 6531
            // allows UTF-8 in the local part and an internationalised domain is
            // written in its own script, so both are legitimate addresses. The
            // ASCII classes did not miss them cleanly. `ünal@ornek.com` matched
            // from the `n`, so `nal@ornek.com` was replaced and the `ü` stayed in
            // the prompt: a partial mask, counted as a success, which is a leak
            // wearing the report of one.
            //
            // Opening the classes costs almost nothing in the other direction
            // because the skeleton still decides: an `@`, a dotted domain and an
            // alphabetic final label. A Turkish word beside an `@` acquires none
            // of those by being spelled with a `ş`.
            expression: r"[\p{L}\p{N}._%+\-]+@[\p{L}\p{N}](?:[\p{L}\p{N}\-]*[\p{L}\p{N}])?(?:\.[\p{L}\p{N}](?:[\p{L}\p{N}\-]*[\p{L}\p{N}])?)*\.\p{L}{2,24}",
            admit: admit_email,
        },
        Detector {
            entity: EntityType::Url,
            // Scheme and authority. The candidate is narrowed to the host by the
            // gate; see `admit_url`.
            expression: r"(?i)\bhttps?://[A-Za-z0-9\-._~%]+(?::[0-9]{1,5})?",
            admit: admit_url,
        },
        Detector {
            entity: EntityType::Phone,
            // E.164 with optional separators, or the Turkish local forms spec
            // section 3.1 names: `0(5xx) ...` and `+90 ...`.
            expression: r"(?:\+|00)[1-9][0-9 ()\-]{6,18}[0-9]|\b0 ?\(?5[0-9]{2}\)? ?[0-9]{3} ?[0-9]{2} ?[0-9]{2}\b",
            admit: admit_phone,
        },
        Detector {
            entity: EntityType::Ipv4,
            expression: r"\b[0-9]{1,3}(?:\.[0-9]{1,3}){3}\b",
            admit: admit_ipv4,
        },
        Detector {
            entity: EntityType::Ipv6,
            // Any run of hex groups and colons long enough to be an address.
            // `Ipv6Addr::from_str` in the gate is the real parser; this only has
            // to find the run.
            expression: r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b|::[0-9A-Fa-f]{1,4}",
            admit: admit_ipv6,
        },
        Detector {
            entity: EntityType::ApiKey,
            // Published provider prefixes. The list is the same one
            // `tests/p0_invariants.rs` holds the alias generator against, so a
            // prefix family added in one place is visible in the other.
            expression: r"(?:sk-|sk_live_|sk_test_|rk_live_|rk_test_|pk_live_|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|xox[baprs]-|AKIA|ASIA|AIza|npm_|dop_v1_|SG\.)[A-Za-z0-9_\-]+",
            admit: admit_api_key,
        },
        Detector {
            entity: EntityType::Date,
            // ISO 8601 first, then the Turkish and English numeric forms. A four
            // digit year is required in every one of them, which is what keeps a
            // version string out.
            expression: r"\b[0-9]{4}-[0-9]{2}-[0-9]{2}\b|\b[0-9]{1,2}[./][0-9]{1,2}[./][0-9]{4}\b|\b[0-9]{4}/[0-9]{1,2}/[0-9]{1,2}\b",
            admit: admit_date,
        },
    ]
}

/// The compiled expressions, built once.
///
/// Compilation is not free and the set is fixed at compile time, so it happens
/// on first use rather than per request. `OnceLock` and not a `static mut`: this
/// crate forbids `unsafe`.
fn compiled() -> &'static [Regex] {
    static COMPILED: OnceLock<Vec<Regex>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        detectors()
            .iter()
            .filter_map(|detector| Regex::new(detector.expression).ok())
            .collect()
    })
}

/// Whether every shape in the table compiled.
///
/// A detector whose expression failed to compile would silently stop detecting
/// its type, which is the exact failure mode this product exists to expose. The
/// scan refuses to run in that state rather than under-reporting.
///
/// **Who asks.** `http::gateway::Gateway::new`, before it accepts anything, and
/// a `false` there stops the proxy from starting. It said `detect::merge` turned
/// the refusal into a declared degradation, and merge did no such thing: nothing
/// called this function outside its own test and `DegradedReason` has no value
/// for it, so one bad edit to one expression produced a proxy that masked
/// nothing on every request with no header, no event and no error. The
/// declaration route stayed shut because `proxy-event.schema.json`'s
/// `degraded_reasons` is a closed dictionary this role does not extend; refusing
/// to start is the stronger answer anyway, and the request for a declared reason
/// is filed in `hub/memory/interfaces.md`.
pub fn shapes_are_loadable() -> bool {
    compiled().len() == detectors().len()
}

/// What one region of the text yielded, and where scanning resumes.
struct Admission {
    /// The candidate's byte range in the whole text.
    start: usize,
    end: usize,
    /// First byte the next search may look at. Never inside an admitted
    /// candidate, so the walk terminates, and never past a region the gate
    /// refused only in part, so a second value in the same region is still
    /// reachable.
    resume: usize,
}

/// The longest region the retry walk below is allowed to take apart.
///
/// The walk is quadratic in the number of runs inside a region, and the region
/// comes from text somebody else wrote, so its cost needs a bound that is not the
/// input's length. Every shape that can actually need the retry sits far below
/// this: ISO 13616 caps a printed IBAN at 34 characters in 9 groups, ISO/IEC 7812
/// caps a card at 19 digits in 5, and E.164 caps a phone at 15 digits. A region
/// longer than this is scanned exactly as before, which is the behaviour this
/// whole function replaces and therefore no worse than the previous build.
const RETRY_MAX_BYTES: usize = 128;

/// The most alphanumeric runs the retry walk takes apart in one region.
///
/// Bounds the pair walk at `(RETRY_MAX_RUNS + 1)^2`. Nine covers an IBAN's
/// groups; twelve leaves room without letting a crafted region turn a linear scan
/// into a quadratic one.
const RETRY_MAX_RUNS: usize = 12;

/// Scans `text` and returns every candidate layer A stands behind.
///
/// Sorted by [`sort_candidates`], overlaps included: resolving them is
/// `detect::merge`'s job and doing it here would hide the decision inside a
/// detector.
///
/// # Why this is a walk and not a `find_iter`
///
/// Every shape here repeats greedily, so a match runs on past the value and
/// swallows whatever token comes next: the expiry after a card, the account
/// holder's name after an IBAN, the second number after the first. The gate then
/// refuses the over-long string, correctly, and with one pass per match that is
/// the end of it: `find_iter` has already consumed the region, no shorter reading
/// is ever tried, and the real value is offered to nobody. It reaches the
/// provider in full, which is the one outcome this component exists to prevent.
///
/// So a refusal is not the end of the region. [`admit_region`] looks for the
/// **longest** reading inside it that the shape itself accepts and the gate
/// admits, and the walk then resumes at the end of what was admitted rather than
/// at the end of the match, so a value sitting in the swallowed tail is still
/// found. When nothing in the region passes, the region is skipped whole: trying
/// every offset instead would make the scan quadratic in the length of a prompt
/// an attacker chooses.
///
/// Making the expressions lazy instead would not do: the short reading can be the
/// wrong one just as easily as the long one, and only the gate knows which.
pub fn scan(text: &str) -> Vec<Candidate> {
    let mut found = Vec::new();
    if !shapes_are_loadable() {
        return found;
    }
    for (detector, expression) in detectors().iter().zip(compiled()) {
        let mut from = 0usize;
        while from <= text.len() {
            let Some(hit) = expression.find_at(text, from) else {
                break;
            };
            let region = hit.start()..hit.end();
            match admit_region(detector, expression, text, region.clone()) {
                Some(admission) => {
                    if text.is_char_boundary(admission.start)
                        && text.is_char_boundary(admission.end)
                    {
                        found.push(Candidate::new(
                            detector.entity,
                            admission.start,
                            admission.end,
                        ));
                    }
                    from = admission.resume.max(region.start.saturating_add(1));
                }
                // Nothing in the region is an entity. Past it, not one byte on:
                // rescanning from the next byte is what turns a crafted prompt
                // into a quadratic scan of a fail closed component.
                None => from = region.end.max(region.start.saturating_add(1)),
            }
        }
    }
    sort_candidates(&mut found);
    found
}

/// Decides what, if anything, one match's region contributes.
///
/// The whole match first, because that is the ordinary case and it has to stay
/// free. Only a refusal pays for the retry walk.
///
/// # The known cost of trying the whole match first
///
/// Trying the whole region before any shorter reading is what makes this cheap,
/// and it is also a measured source of **over**-masking. When a greedy shape has
/// swallowed a trailing token and the gate still admits the resulting string, the
/// admission covers the value and the token, and no shorter reading is ever
/// offered: [`longest_admitted_reading`] runs on a refusal and not on a success.
/// The alias then stands for slightly more text than the entity did. The second
/// closing audit measured this at 8 regions in 676, near one in ninety.
///
/// It is left this way on purpose rather than left unnoticed. The error is
/// entirely in the false positive direction: more of the prompt is replaced than
/// strictly had to be, and nothing that should have been masked crosses. The only
/// reading order that would trim it is preferring the **shortest** admitted
/// reading, and that trades a cosmetic loss for a real one, because the short
/// reading of a card number or an IBAN is a prefix of it and masking a prefix
/// leaves the tail in the prompt. For a component whose whole rule is that it
/// refuses rather than under-masks, biased long is the correct bias.
///
/// The limit belongs in `docs/05-quality/known-gaps.md` as a catalogued escape
/// case, and this role does not write that file; the owned row is on
/// `hub/task-board.md`.
fn admit_region(
    detector: &Detector,
    expression: &Regex,
    text: &str,
    region: std::ops::Range<usize>,
) -> Option<Admission> {
    let whole = text.get(region.clone())?;
    if let Some((from, to)) = (detector.admit)(whole) {
        let start = region.start.checked_add(from)?;
        let end = region.start.checked_add(to)?;
        return (end > start).then_some(Admission {
            start,
            end,
            resume: region.end,
        });
    }

    let (base, reading) = longest_admitted_reading(detector, expression, whole)?;
    let (from, to) = (detector.admit)(reading)?;
    let start = region.start.checked_add(base)?.checked_add(from)?;
    let end = region.start.checked_add(base)?.checked_add(to)?;
    (end > start).then_some(Admission {
        start,
        end,
        // The end of the reading, not the end of the region: the tail the shape
        // swallowed may hold a second value, and the phone case is not
        // hypothetical.
        resume: region.start.saturating_add(base + reading.len()),
    })
}

/// The longest sub-range of `region` that is both the shape and an entity.
///
/// Returns its offset inside `region` and the text itself. Longest first, then
/// leftmost, so the answer does not depend on the order the walk happens to take.
///
/// Two conditions, and the first is what keeps this from inventing entities. A
/// reading has to be a **whole match of the detector's own expression**, so a
/// shorter reading is a shorter way of writing the same kind of thing and not an
/// arbitrary substring that happens to satisfy a checksum. `a_region_where_
/// nothing_passes_the_gate_is_still_refused` is the test that holds this side.
fn longest_admitted_reading<'r>(
    detector: &Detector,
    expression: &Regex,
    region: &'r str,
) -> Option<(usize, &'r str)> {
    if region.len() > RETRY_MAX_BYTES {
        return None;
    }
    let (starts, ends) = reading_bounds(region)?;

    let mut best: Option<(usize, usize)> = None;
    for &begin in &starts {
        for &stop in &ends {
            if stop <= begin {
                continue;
            }
            let length = stop - begin;
            // Cheap ordering test before the two expensive ones, so a region
            // with many bounds does not run the expression once per pair.
            let improves = best.is_none_or(|(had_begin, had_stop)| {
                length > had_stop - had_begin
                    || (length == had_stop - had_begin && begin < had_begin)
            });
            if !improves {
                continue;
            }
            let Some(reading) = region.get(begin..stop) else {
                continue;
            };
            if !is_whole_match(expression, reading) {
                continue;
            }
            if (detector.admit)(reading).is_none() {
                continue;
            }
            best = Some((begin, stop));
        }
    }

    let (begin, stop) = best?;
    Some((begin, region.get(begin..stop)?))
}

/// Where inside a region a shorter reading may begin and end.
///
/// The region's own edges plus the edges of every alphanumeric run in it.
/// Cutting inside a run would produce a different number rather than a shorter
/// reading of the same one, and a detector that masked `4242 4242 4242 424` would
/// leave the last digit in the prompt.
///
/// `None` when the region has more runs than the walk is allowed to take apart.
fn reading_bounds(region: &str) -> Option<(Vec<usize>, Vec<usize>)> {
    let mut starts = vec![0usize];
    let mut ends = vec![region.len()];
    let mut runs = 0usize;
    let mut inside = false;
    for (index, character) in region.char_indices() {
        if character.is_alphanumeric() {
            if !inside {
                runs += 1;
                if runs > RETRY_MAX_RUNS {
                    return None;
                }
                starts.push(index);
                inside = true;
            }
        } else if inside {
            ends.push(index);
            inside = false;
        }
    }
    starts.sort_unstable();
    starts.dedup();
    ends.sort_unstable();
    ends.dedup();
    Some((starts, ends))
}

/// Whether `reading` is a match of `expression` from its first byte to its last.
///
/// A partial match means the shape only accepts part of this reading, so the
/// reading is not a candidate of this type at all.
fn is_whole_match(expression: &Regex, reading: &str) -> bool {
    expression
        .find(reading)
        .is_some_and(|found| found.start() == 0 && found.end() == reading.len())
}

/// Trailing bytes that a shape may swallow but an entity does not own.
///
/// A URL at the end of a sentence takes the full stop with it, and an e-mail in
/// parentheses takes the bracket. Trimming here rather than in the expression
/// keeps the expressions readable and the rule in one place.
fn trim_trailing_punctuation(text: &str) -> usize {
    let mut end = text.len();
    while let Some(last) = text.get(..end).and_then(|slice| slice.chars().next_back()) {
        if matches!(
            last,
            '.' | ',' | ';' | ':' | ')' | ']' | '}' | '!' | '?' | '\'' | '"'
        ) {
            end -= last.len_utf8();
        } else {
            break;
        }
    }
    end
}

fn admit_iban(text: &str) -> Option<(usize, usize)> {
    // Spec section 3.1: the mod 97 rule is mandatory. A string that shapes like
    // an IBAN and fails it is not an account, so it is not masked.
    checksum::iban_is_valid(text).then_some((0, text.len()))
}

fn admit_tckn(text: &str) -> Option<(usize, usize)> {
    checksum::tckn_is_valid(text).then_some((0, text.len()))
}

fn admit_vkn(text: &str) -> Option<(usize, usize)> {
    checksum::vkn_is_valid(text).then_some((0, text.len()))
}

fn admit_card(text: &str) -> Option<(usize, usize)> {
    let digits: String = text.chars().filter(char::is_ascii_digit).collect();
    gate::card_is_detectable(&digits).then_some((0, text.len()))
}

fn admit_email(text: &str) -> Option<(usize, usize)> {
    let end = trim_trailing_punctuation(text);
    let candidate = text.get(..end)?;
    let (local, domain) = candidate.split_once('@')?;
    // RFC 5321 section 4.5.3.1 length limits, which is the only part of the
    // grammar cheap enough to check and useful enough to matter.
    //
    // Counted in **characters**, not bytes. The limits are stated in octets for an
    // ASCII local part, and measuring a UTF-8 local part the same way makes the
    // ceiling arrive early: `ö` is two bytes, so a thirty-three letter Turkish
    // address would be refused at a limit it is nowhere near. Refusing here means
    // not masking, so the wrong unit is a leak rather than a rounding error.
    if local.is_empty() || local.chars().count() > 64 || domain.chars().count() > 255 {
        return None;
    }
    Some((0, end))
}

/// Narrows a URL match to its **host component**.
///
/// `proxy/spec.md` section 4.4 is explicit: a URL is not aliased as a whole, only
/// its host is, and the path and query keep their structure so that entities
/// inside them are masked in their own types. Emitting a candidate over the whole
/// URL would swallow an e-mail in a query string and mask it as part of a URL,
/// which loses both the type and the restoration.
fn admit_url(text: &str) -> Option<(usize, usize)> {
    let scheme_end = text.find("://")? + 3;
    let rest = text.get(scheme_end..)?;
    // Strip userinfo if present, and stop the host at a port.
    let host_start = scheme_end + rest.find('@').map_or(0, |at| at + 1);
    let host = text.get(host_start..)?;
    let host_len = host.find(':').unwrap_or(host.len());
    let host_len = trim_trailing_punctuation(host.get(..host_len)?);
    (host_len > 0).then_some((host_start, host_start + host_len))
}

fn admit_phone(text: &str) -> Option<(usize, usize)> {
    let end = trim_trailing_punctuation(text);
    let candidate = text.get(..end)?;
    let digits = candidate.chars().filter(char::is_ascii_digit).count();
    // E.164 allows at most fifteen digits and needs at least seven to name a
    // subscriber anywhere. A run outside that is a number, not a phone number.
    (7..=15).contains(&digits).then_some((0, end))
}

fn admit_ipv4(text: &str) -> Option<(usize, usize)> {
    match gate::ipv4_class(text) {
        Some(gate::AddressClass::Global | gate::AddressClass::Private) => Some((0, text.len())),
        // A loopback or documentation address names nobody. Not a miss.
        Some(gate::AddressClass::NotAnEntity) | None => None,
    }
}

fn admit_ipv6(text: &str) -> Option<(usize, usize)> {
    match gate::ipv6_class(text) {
        Some(gate::AddressClass::Global | gate::AddressClass::Private) => Some((0, text.len())),
        Some(gate::AddressClass::NotAnEntity) | None => None,
    }
}

fn admit_api_key(text: &str) -> Option<(usize, usize)> {
    let end = trim_trailing_punctuation(text);
    let candidate = text.get(..end)?;
    // The body is everything after the published prefix. Splitting on the last
    // separator inside the prefix would mis-split `sk-proj-...`; instead the
    // body is measured from the first character that is not part of any prefix
    // shape, which is the first run of drawn looking characters.
    let body_start = candidate
        .char_indices()
        .position(|(_, character)| character.is_ascii_digit() || character.is_ascii_uppercase())
        .map_or(0, |_| prefix_end(candidate));
    let body = candidate.get(body_start..)?;
    gate::key_body_is_high_entropy(body).then_some((0, end))
}

/// Where a published provider prefix stops.
///
/// Everything up to and including the last `_` or `-` in the first twelve bytes,
/// which covers `sk_live_`, `github_pat_`, `xoxb-` and `glpat-`. A shape with no
/// separator there (`AKIA`, `AIza`) contributes its four fixed bytes.
fn prefix_end(text: &str) -> usize {
    const WINDOW: usize = 12;
    let window_end = text
        .char_indices()
        .map(|(index, character)| index + character.len_utf8())
        .take_while(|end| *end <= WINDOW)
        .last()
        .unwrap_or(0);
    let window = text.get(..window_end).unwrap_or_default();
    match window.rfind(['_', '-']) {
        Some(at) => at + 1,
        None => 4.min(text.len()),
    }
}

fn admit_date(text: &str) -> Option<(usize, usize)> {
    let numbers: Vec<i64> = text
        .split(['-', '.', '/'])
        .filter_map(|part| part.parse::<i64>().ok())
        .collect();
    let [first, second, third] = numbers.as_slice() else {
        return None;
    };
    // Year first when the leading field is four digits, day first otherwise:
    // `2026-08-05` and `2026/08/05` against `05.08.2026`.
    let (year, month, day) = if *first > 31 {
        (*first, *second, *third)
    } else {
        (*third, *second, *first)
    };
    let month = u32::try_from(month).ok()?;
    let day = u32::try_from(day).ok()?;
    gate::date_is_real(year, month, day).then_some((0, text.len()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Types found in `text`, as tags, for readable assertions.
    fn types_in(text: &str) -> BTreeSet<&'static str> {
        scan(text)
            .into_iter()
            .map(|candidate| candidate.entity.tag())
            .collect()
    }

    fn spans_of(text: &str, entity: EntityType) -> Vec<&str> {
        scan(text)
            .into_iter()
            .filter(|candidate| candidate.entity == entity)
            .filter_map(|candidate| candidate.text_of(text))
            .collect()
    }

    #[test]
    fn every_shape_in_the_table_compiles() {
        // A detector whose expression does not compile stops detecting its type
        // and nothing else changes. The scan refuses to run in that state; this
        // is what proves it does not have to.
        assert!(shapes_are_loadable());
        assert_eq!(compiled().len(), detectors().len());
    }

    #[test]
    fn every_type_this_layer_owns_has_a_detector() {
        // The counting gate: a type assigned to layer A with no shape here is a
        // type nothing scans for, and the operator would only learn it from the
        // output.
        let owned: BTreeSet<&str> = EntityType::ALL
            .into_iter()
            .filter(|entity| {
                super::super::layer::owning_layer(*entity)
                    == super::super::layer::DetectionLayer::Pattern
            })
            .map(EntityType::tag)
            .collect();
        let implemented: BTreeSet<&str> = detectors()
            .iter()
            .map(|detector| detector.entity.tag())
            .collect();
        assert_eq!(owned, implemented);
    }

    // ---- TCKN: positive, negative, escape --------------------------------

    #[test]
    fn positive_a_valid_tckn_is_detected() {
        assert!(types_in("Kimlik numaram 10000000146, teşekkürler.").contains("TCKN"));
        assert_eq!(
            spans_of("Kimlik: 10000000146.", EntityType::Tckn),
            vec!["10000000146"]
        );
    }

    #[test]
    fn negative_an_eleven_digit_number_whose_checksum_fails_is_not_a_tckn() {
        // Spec section 3.1, stated as a test. This is the assertion the mutation
        // run breaks: remove the checksum call in `admit_tckn` and this goes red.
        for impostor in ["10000000147", "12345678901", "99999999999", "10000000156"] {
            assert!(
                !checksum::tckn_is_valid(impostor),
                "test vector {impostor} is actually valid"
            );
            assert!(
                !types_in(&format!("numara {impostor} burada")).contains("TCKN"),
                "{impostor} was masked as a TCKN"
            );
        }
    }

    #[test]
    fn escape_a_tckn_written_with_separators_is_not_detected() {
        // Known gap: `100 000 001 46` is a TCKN a human reads and this layer does
        // not. Closing it means accepting separated digit runs, which multiplies
        // the eleven-digit false positive surface across every prompt.
        assert!(!types_in("100 000 001 46").contains("TCKN"));
    }

    // ---- IBAN ------------------------------------------------------------

    #[test]
    fn positive_an_iban_is_detected_spaced_or_not() {
        assert_eq!(
            spans_of("Hesap: TR330006100519786457841326", EntityType::Iban),
            vec!["TR330006100519786457841326"]
        );
        assert_eq!(
            spans_of("IBAN GB82 WEST 1234 5698 7654 32 ile", EntityType::Iban),
            vec!["GB82 WEST 1234 5698 7654 32"]
        );
    }

    #[test]
    fn negative_an_iban_shaped_string_that_fails_mod_97_is_not_masked() {
        for impostor in ["TR340006100519786457841326", "GB83WEST12345698765432"] {
            assert!(!checksum::iban_is_valid(impostor));
            assert!(
                !types_in(impostor).contains("IBAN"),
                "{impostor} was masked"
            );
        }
    }

    /// The detector and the validator have to agree on what an IBAN looks like.
    ///
    /// `checksum::compact_iban` strips a hyphen as readily as a space, so
    /// `TR33-0006-...` is a **valid** IBAN as far as every rule in this crate is
    /// concerned; the shape allowed only a single space, so no candidate was ever
    /// offered and the gate that would have admitted it was never asked. A format
    /// the validator accepts and the detector never sees is an account number
    /// crossing to the provider with nothing to say so.
    #[test]
    fn positive_an_iban_printed_with_hyphens_is_detected_because_the_rule_accepts_one() {
        for printed in [
            "TR33-0006-1005-1978-6457-8413-26",
            "GB82-WEST-1234-5698-7654-32",
            // Mixed separators, which is what a value pasted out of two places
            // looks like.
            "TR33 0006-1005 1978-6457 8413-26",
        ] {
            assert!(
                checksum::iban_is_valid(printed),
                "the fixture {printed} is not a valid IBAN, so the test proves nothing"
            );
            assert_eq!(
                spans_of(&format!("Hesap: {printed} lütfen"), EntityType::Iban),
                vec![printed],
                "{printed} passes mod 97 and was never offered as a candidate"
            );
        }
    }

    /// The other direction: a hyphenated string that is not an account is still
    /// not an account. The mod 97 gate is what does this, and widening the shape
    /// must not turn every hyphenated upper case token into a candidate that
    /// passes.
    #[test]
    fn negative_a_hyphenated_string_that_fails_mod_97_is_not_an_iban() {
        // Chosen so that no shorter reading inside them passes either, which is a
        // separate escape (KG-031, below) and would otherwise make this test pass
        // or fail for the wrong reason.
        for impostor in [
            "GB83-WEST-1234-5698-7654-32",
            "PO12-3456-7890",
            "XX00-AAAA-BBBB-CCCC",
            "ZZ11-1111-1111-1111",
        ] {
            assert!(!checksum::iban_is_valid(impostor), "{impostor}");
            assert!(
                !types_in(&format!("kod {impostor} burada")).contains("IBAN"),
                "{impostor} was masked as an IBAN"
            );
        }
    }

    /// KG-031, and it is older than the hyphen: a **truncation** of a printed
    /// IBAN can satisfy mod 97 on its own.
    ///
    /// `TR34 0006 1005 1978 6457 8413 26` fails the rule, so the whole match is
    /// refused and the retry walk looks for the longest shorter reading that is
    /// both the shape and an entity. `TR34 0006 1005 1978 6457` is one: twenty
    /// characters, `iban_shape_is_plausible` allows five to thirty-four, and one
    /// prefix in ninety-seven passes mod 97 by arithmetic. So a prefix is masked
    /// and the last two groups stay in the prompt.
    ///
    /// Written as a test of the **current** behaviour rather than of the wanted
    /// one, with both separators, so that whoever closes it sees it go red here
    /// first. It is a false detection and not a leak: a real IBAN is admitted
    /// whole on the first try and never reaches the retry, and the longest reading
    /// wins, so no valid account is truncated. Closing it needs ISO 13616's per
    /// country length register, which is published data this build does not carry
    /// and does not guess at.
    #[test]
    fn escape_a_truncation_of_an_invalid_iban_can_pass_mod_97_and_be_masked() {
        for (printed, truncated) in [
            (
                "TR34-0006-1005-1978-6457-8413-26",
                "TR34-0006-1005-1978-6457",
            ),
            (
                "TR34 0006 1005 1978 6457 8413 26",
                "TR34 0006 1005 1978 6457",
            ),
        ] {
            assert!(!checksum::iban_is_valid(printed), "{printed}");
            assert!(checksum::iban_is_valid(truncated), "{truncated}");
            assert_eq!(
                spans_of(&format!("kod {printed} burada"), EntityType::Iban),
                vec![truncated],
                "the truncation behaviour changed and KG-031 needs rewriting"
            );
        }
    }

    #[test]
    fn escape_a_lower_case_iban_is_not_detected() {
        // ISO 13616 prints an IBAN in upper case and this layer follows it.
        // Accepting lower case would collide with ordinary words: `tr33` in a
        // sentence, or a hex identifier.
        assert!(!types_in("tr330006100519786457841326").contains("IBAN"));
    }

    // ---- VKN -------------------------------------------------------------

    #[test]
    fn positive_and_negative_a_vkn_needs_its_check_digit() {
        let body = [4, 9, 8, 0, 3, 1, 2, 2, 0];
        let check = checksum::vkn_check_digit(&body);
        let valid = format!("498031220{check}");
        assert!(types_in(&format!("VKN {valid} ")).contains("VKN"));
        let wrong = format!("498031220{}", (check + 1) % 10);
        assert!(!checksum::vkn_is_valid(&wrong));
        assert!(!types_in(&format!("VKN {wrong} ")).contains("VKN"));
    }

    #[test]
    fn escape_a_ten_digit_number_that_happens_to_pass_the_vkn_rule_is_masked() {
        // The declared false positive, written down rather than hidden. One in
        // ten arbitrary ten digit runs satisfies the rule, and this layer cannot
        // tell an order reference from a tax number. It masks, because the value
        // is masked either way when it is a real one, and the cost here is a
        // damaged prompt rather than a leak.
        let mut found = None;
        for candidate in 1_000_000_000u64..1_000_000_010 {
            if checksum::vkn_is_valid(&candidate.to_string()) {
                found = Some(candidate.to_string());
                break;
            }
        }
        let number = found.unwrap();
        assert!(types_in(&format!("Sipariş {number} kayıtlı")).contains("VKN"));
    }

    // ---- CREDIT_CARD -----------------------------------------------------

    #[test]
    fn positive_a_published_test_card_is_detected_grouped_or_not() {
        assert!(types_in("kart 4242424242424242 ile").contains("CREDIT_CARD"));
        assert!(types_in("kart 4242 4242 4242 4242 ile").contains("CREDIT_CARD"));
        assert!(types_in("kart 3782-822463-10005 ile").contains("CREDIT_CARD"));
    }

    #[test]
    fn negative_luhn_or_the_issuer_range_failing_keeps_it_unmasked() {
        assert!(!types_in("4242424242424243").contains("CREDIT_CARD"));
        // Luhn holds but no scheme issues in the 1 range.
        assert!(!types_in("1234567812345670").contains("CREDIT_CARD"));
    }

    #[test]
    fn escape_a_card_split_across_a_line_break_is_not_detected() {
        // Known gap: the shape does not cross a newline, because a rule that did
        // would join two unrelated digit runs on adjacent lines.
        assert!(!types_in("4242 4242\n4242 4242").contains("CREDIT_CARD"));
    }

    // ---- EMAIL, URL, PHONE, IP, API_KEY, DATE ----------------------------

    #[test]
    fn positive_an_email_is_detected_and_trailing_punctuation_stays_out() {
        assert_eq!(
            spans_of(
                "Bana ahmet.yilmaz@ornek.com.tr adresinden yaz.",
                EntityType::Email
            ),
            vec!["ahmet.yilmaz@ornek.com.tr"]
        );
        assert_eq!(
            spans_of("(bilgi@ornek.com).", EntityType::Email),
            vec!["bilgi@ornek.com"]
        );
    }

    #[test]
    fn negative_a_string_with_an_at_sign_but_no_domain_is_not_an_email() {
        assert!(!types_in("@kullanici bir mention").contains("EMAIL"));
        assert!(!types_in("fiyat 5@kg").contains("EMAIL"));
    }

    /// KG-030, and the half of it that is worse than a miss.
    ///
    /// With an ASCII-only local part the match starts **after** the accented
    /// letter: `nal@ornek.com` is replaced and `ü` stays in the prompt, so the
    /// address is reassembled by whoever reads it and the request is counted as
    /// one more masked entity. A partial mask is a leak wearing the report of a
    /// success, which is why this is asserted as a whole-span equality rather than
    /// as "something was found".
    #[test]
    fn positive_an_accented_local_part_is_masked_whole_and_leaves_no_letter_behind() {
        for address in [
            "ünal@ornek.com",
            "ömer.çelik@ornek.com.tr",
            "işıl_gür@ornek.com",
        ] {
            assert_eq!(
                spans_of(&format!("Bana {address} yaz."), EntityType::Email),
                vec![address],
                "the local part of {address} was only partly detected"
            );
        }
    }

    /// The other half of KG-030: an internationalised domain produced no
    /// candidate at all, so the whole address crossed to the provider.
    #[test]
    fn positive_an_internationalised_domain_is_detected() {
        for address in ["bilgi@örnek.com", "info@şirket.com.tr", "a@ornek.köy"] {
            assert_eq!(
                spans_of(&format!("adres {address} burada"), EntityType::Email),
                vec![address],
                "{address} produced no candidate"
            );
        }
    }

    /// The false positive cost of opening the classes above, measured rather than
    /// asserted to be small.
    ///
    /// The skeleton still decides: an `@` with a dotted domain and an alphabetic
    /// final label. Turkish prose is full of `@` in mentions and of accented words
    /// beside punctuation, and none of it acquires a domain by being spelled with
    /// a `ş`.
    #[test]
    fn negative_opening_the_classes_to_unicode_letters_finds_no_address_in_prose() {
        const PROSE: &[&str] = &[
            "@kullanıcı bir mention",
            "fiyat 5@kg",
            "Şirket@ ile ilgili değil",
            "ödeme@ yapıldı",
            "toplantı @ 14:00",
            "e-posta: (yok)",
            "ürün@depo raf 3",
            "çalışan@ izinli",
            "@öğrenci listesi güncellendi",
            "birim@ müdürlüğü",
        ];
        let found: Vec<&str> = PROSE
            .iter()
            .filter(|line| types_in(line).contains("EMAIL"))
            .copied()
            .collect();
        assert!(
            found.is_empty(),
            "opening the local part to Unicode letters cost {} false positives: {found:?}",
            found.len()
        );
    }

    #[test]
    fn escape_a_quoted_local_part_is_not_detected() {
        // RFC 5322 allows `"ad soyad"@ornek.com`. This layer implements the
        // unquoted subset spec section 3.1 asks for; the quoted form is a
        // declared miss.
        assert!(!types_in("\"ad soyad\"@ornek.com").contains("EMAIL"));
    }

    #[test]
    fn a_url_candidate_covers_only_its_host_so_the_path_keeps_its_entities() {
        let text = "Bkz https://api.ornek.com/v1/users?mail=ali@ornek.com adresi";
        assert_eq!(spans_of(text, EntityType::Url), vec!["api.ornek.com"]);
        // The e-mail in the query string is still its own candidate, in its own
        // type, which is what spec section 4.4 requires.
        assert_eq!(spans_of(text, EntityType::Email), vec!["ali@ornek.com"]);
    }

    #[test]
    fn phone_numbers_in_the_forms_the_spec_names_are_detected() {
        assert!(types_in("Ara: +90 532 123 45 67").contains("PHONE"));
        assert!(types_in("Ara: 0(532) 123 45 67").contains("PHONE"));
        assert!(types_in("Call +1 415 555 0132 today").contains("PHONE"));
        // Too few digits to name a subscriber anywhere.
        assert!(!types_in("+90 12").contains("PHONE"));
    }

    #[test]
    fn addresses_that_identify_nobody_are_left_alone() {
        assert!(types_in("sunucu 8.8.8.8").contains("IPV4"));
        assert!(types_in("sunucu 10.1.2.3").contains("IPV4"));
        assert!(!types_in("localhost 127.0.0.1").contains("IPV4"));
        assert!(types_in("adres 2606:4700::1111").contains("IPV6"));
        assert!(!types_in("adres ::1").contains("IPV6"));
        // A version string is not an address.
        assert!(!types_in("sürüm 1.2.3").contains("IPV4"));
    }

    #[test]
    fn a_provider_key_is_detected_and_a_placeholder_is_not() {
        let stripe = crate::detect::sample::stripe_key();
        let github = crate::detect::sample::github_token();
        assert!(types_in(&format!("export STRIPE={stripe}")).contains("API_KEY"));
        assert!(types_in(&format!("token {github}")).contains("API_KEY"));
        assert!(types_in("AKIAIOSFODNN7EXAMPLE").contains("API_KEY"));
        // The shapes people write in documentation.
        assert!(!types_in("sk-YOUR-KEY-HERE").contains("API_KEY"));
        assert!(!types_in("ghp_xxxx").contains("API_KEY"));
    }

    #[test]
    fn dates_are_detected_only_when_the_day_exists() {
        assert!(types_in("teslim 2026-08-05 tarihinde").contains("DATE"));
        assert!(types_in("teslim 05.08.2026 tarihinde").contains("DATE"));
        assert!(!types_in("sürüm 1.2.3 çıktı").contains("DATE"));
        assert!(!types_in("tarih 31.02.2026 yok").contains("DATE"));
    }

    // ---- A value with a neighbour beside it (K-1) ------------------------
    //
    // The shapes repeat greedily, so a match can swallow the token that follows
    // the value. When it does, the gate refuses the over-long string, and
    // without a retry the region is consumed and the real value is never offered
    // to any detector again. Every assertion below is a leak if it fails: the
    // value reaches the provider in full.

    #[test]
    fn a_card_keeps_its_type_when_an_expiry_follows_it() {
        assert_eq!(
            spans_of("kart 4242 4242 4242 4242 06 26", EntityType::CreditCard),
            vec!["4242 4242 4242 4242"]
        );
        assert_eq!(
            spans_of(
                "kart 4242 4242 4242 4242 06/26 cvc 123",
                EntityType::CreditCard
            ),
            vec!["4242 4242 4242 4242"]
        );
        // A neighbour that is itself a long digit run, which is the case a
        // prefix-only retry would still get wrong.
        assert_eq!(
            spans_of("kart 4111 1111 1111 1111 123456", EntityType::CreditCard),
            vec!["4111 1111 1111 1111"]
        );
    }

    #[test]
    fn an_iban_keeps_its_type_whatever_token_follows_it() {
        // Four shapes of neighbour: a name, a currency code, a year, and a
        // second number. All four are swallowed by the IBAN group repetition.
        for tail in ["AHMET YILMAZ", "TRY", "EUR", "2026", "1234"] {
            let text = format!("IBAN TR33 0006 1005 1978 6457 8413 26 {tail}");
            assert_eq!(
                spans_of(&text, EntityType::Iban),
                vec!["TR33 0006 1005 1978 6457 8413 26"],
                "tail `{tail}` swallowed the IBAN"
            );
        }
    }

    #[test]
    fn two_phone_numbers_written_side_by_side_are_both_found() {
        // The E.164 alternative runs over separators, so one match covers both
        // numbers and eighteen digits fail the 7..=15 gate. Both numbers leak.
        assert_eq!(
            spans_of("+90 5321234567 05321234567", EntityType::Phone),
            vec!["+90 5321234567", "05321234567"]
        );
    }

    #[test]
    fn every_shape_still_finds_its_value_with_a_neighbour_beside_it() {
        // One case per type, so a retry written for one shape is not mistaken
        // for a retry that works everywhere.
        let key = crate::detect::sample::stripe_key();
        // Computed rather than written down, so the fixture cannot drift from
        // the rule the gate applies.
        let vkn = format!(
            "498031220{}",
            checksum::vkn_check_digit(&[4, 9, 8, 0, 3, 1, 2, 2, 0])
        );
        for (text, entity, expected) in [
            (
                "TCKN 10000000146 2026".to_owned(),
                EntityType::Tckn,
                "10000000146",
            ),
            (format!("VKN {vkn} 2026"), EntityType::Vkn, vkn.as_str()),
            (
                "kart 4242 4242 4242 4242 06 26".to_owned(),
                EntityType::CreditCard,
                "4242 4242 4242 4242",
            ),
            (
                "IBAN TR33 0006 1005 1978 6457 8413 26 TRY".to_owned(),
                EntityType::Iban,
                "TR33 0006 1005 1978 6457 8413 26",
            ),
            (
                "mail ali@ornek.com 2026".to_owned(),
                EntityType::Email,
                "ali@ornek.com",
            ),
            (
                "bkz https://ornek.com/a 2026".to_owned(),
                EntityType::Url,
                "ornek.com",
            ),
            (
                "+90 5321234567 05321234567".to_owned(),
                EntityType::Phone,
                "+90 5321234567",
            ),
            (
                "sunucu 8.8.8.8 2026".to_owned(),
                EntityType::Ipv4,
                "8.8.8.8",
            ),
            (
                "adres 2606:4700::1111 2026".to_owned(),
                EntityType::Ipv6,
                "2606:4700::1111",
            ),
            (format!("key {key} 2026"), EntityType::ApiKey, key.as_str()),
            (
                "teslim 2026-08-05 2026".to_owned(),
                EntityType::Date,
                "2026-08-05",
            ),
        ] {
            let found = spans_of(&text, entity);
            assert!(
                found.contains(&expected),
                "{entity} was lost in `{text}`, found {found:?}"
            );
        }
    }

    #[test]
    fn a_region_where_nothing_passes_the_gate_is_still_refused() {
        // The other half: the retry may not turn a rejection into a detection.
        // Without this, "try shorter candidates until one passes" would mask a
        // prefix of every long digit run in every prompt.
        assert!(!types_in("numara 10000000147 2026").contains("TCKN"));
        assert!(!types_in("TR340006100519786457841326 TRY").contains("IBAN"));
        assert!(!types_in("kart 1234567812345670 06 26").contains("CREDIT_CARD"));
        assert!(!types_in("localhost 127.0.0.1 2026").contains("IPV4"));
        assert!(!types_in("tarih 31.02.2026 yok").contains("DATE"));
        // And the reading has to be the shape, not merely something the gate
        // tolerates. `admit_phone` measures nothing but a digit count, so a bare
        // twelve digit run satisfies it; what refuses it is that no phone shape
        // accepts a run with neither `+` nor a leading `0`. Drop the shape
        // re-check in `longest_admitted_reading` and this masks long digit runs
        // as phone numbers in every prompt.
        assert!(!types_in("Ara +1 23456 789012345678 son").contains("PHONE"));
    }

    // ---- The complementarity that keeps aliases out of the scanner -------

    #[test]
    fn an_empty_input_produces_nothing_and_does_not_fail() {
        // The exhausted case: a layer with nothing to find still has to run.
        assert!(scan("").is_empty());
        assert!(scan("   \n\t  ").is_empty());
    }

    #[test]
    fn the_candidates_are_sorted_and_deterministic() {
        let text = "TCKN 10000000146, IBAN TR330006100519786457841326, mail a1@b.com";
        let once = scan(text);
        let twice = scan(text);
        assert_eq!(once, twice);
        assert!(once.windows(2).all(|pair| pair[0].start <= pair[1].start));
    }
}
