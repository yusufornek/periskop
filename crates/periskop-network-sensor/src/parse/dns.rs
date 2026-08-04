//! Reading `ip -> hostname` out of a DNS response.
//!
//! This is the first of the two signals ADR-008 allows the sensor to classify a
//! destination with, and the component spec fixes what may be read: **answers
//! only**. A query says what a process was about to do; an answer says what an
//! address means. The sensor needs the second and has no business keeping the
//! first, so a message without the response bit set is rejected here rather
//! than filtered somewhere downstream.
//!
//! The parse is a free function over a byte slice with no kernel, no socket and
//! no clock in it. That is deliberate: the eBPF side of this milestone cannot
//! run in CI, and if the DNS reading lived inside the loader it could not be
//! tested at all. Everything that decides what a report says about a
//! destination is in here, and all of it is exercised on the machine you are
//! reading this on.
//!
//! A malformed message is an error and never an empty answer set. The
//! difference matters: "this response mapped no addresses" and "this response
//! could not be read" are different facts about coverage, and collapsing them
//! would hide a parser that stopped working.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::cursor::Cursor;

/// Header is id, flags and four section counts, two bytes each.
const HEADER_BYTES: usize = 12;

/// `QR` bit: set on a response, clear on a query.
const FLAG_RESPONSE: u16 = 0x8000;

/// Class `IN`. Anything else is not internet addressing and is skipped.
const CLASS_IN: u16 = 1;

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;

/// Longest a DNS name may be on the wire, in bytes including length octets.
const MAX_NAME_BYTES: usize = 255;
const MAX_LABEL_BYTES: usize = 63;

/// Compression pointers may point anywhere in the message, including at each
/// other. A jump budget is what keeps a crafted response from looping forever
/// inside a sensor that is supposed to cost under one percent of a core.
const MAX_POINTER_JUMPS: u32 = 16;

/// Records a single response may declare before the parse gives up.
///
/// A count field is two bytes, so a message can claim sixty five thousand
/// records it does not carry. Truncation alone would catch that, but only after
/// the loop had run. The cap makes the cost of a hostile header constant.
const MAX_RECORDS: usize = 64;

/// How far an alias chain is followed when mapping an address back to the name
/// that was asked for.
const MAX_CNAME_DEPTH: usize = 8;

/// Why a response could not be read.
///
/// A fixed vocabulary rather than a message, because these are counted in a
/// coverage statement and a reader has to be able to compare occurrences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsParseError {
    /// The response bit was clear. The sensor does not read queries.
    NotAResponse,
    /// The message ended inside a field the format requires.
    Truncated,
    /// A length, a pointer or a label the format does not allow.
    Malformed,
    /// More records than the parse budget admits.
    TooManyRecords,
}

impl DnsParseError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAResponse => "dns_not_a_response",
            Self::Truncated => "dns_truncated",
            Self::Malformed => "dns_malformed",
            Self::TooManyRecords => "dns_too_many_records",
        }
    }
}

/// One address, and a name a response said it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DnsMapping {
    pub ip: IpAddr,
    pub name: String,
    /// How long the answer said the mapping holds. Kept rather than applied
    /// here, because expiry needs an observation clock and this function has
    /// none.
    pub ttl_secs: u32,
}

/// What one response established.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsAnswers {
    /// The name the question section carried, when it carried a readable one.
    /// This is the name the application asked for, which is not always the name
    /// the address record is filed under (see the alias chain below).
    pub query_name: Option<String>,
    /// Address to name mappings, ordered and deduplicated so that two captures
    /// of the same response produce the same record.
    pub mappings: Vec<DnsMapping>,
    /// Set when the server flagged the answer as cut short. The mappings that
    /// were read are still true; the set is simply not the whole one, and a
    /// caller that treats it as complete would understate what a destination
    /// resolves to.
    pub truncated_by_server: bool,
}

impl DnsAnswers {
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

/// Reads the address mappings a response established.
///
/// Fails rather than returning a partial set, except where the server itself
/// declared the answer cut short, which is reported as data.
pub fn parse_response(message: &[u8]) -> Result<DnsAnswers, DnsParseError> {
    if message.len() < HEADER_BYTES {
        return Err(DnsParseError::Truncated);
    }
    let mut cursor = Cursor::new(message);
    cursor.skip(2).ok_or(DnsParseError::Truncated)?; // transaction id
    let flags = cursor.u16().ok_or(DnsParseError::Truncated)?;
    if flags & FLAG_RESPONSE == 0 {
        return Err(DnsParseError::NotAResponse);
    }
    let question_count = cursor.u16().ok_or(DnsParseError::Truncated)?;
    let answer_count = cursor.u16().ok_or(DnsParseError::Truncated)?;
    cursor.skip(4).ok_or(DnsParseError::Truncated)?; // authority and additional counts

    if usize::from(question_count) + usize::from(answer_count) > MAX_RECORDS {
        return Err(DnsParseError::TooManyRecords);
    }

    let query_name = read_question_section(message, &mut cursor, question_count)?;
    let records = read_answer_section(message, &mut cursor, answer_count)?;

    Ok(DnsAnswers {
        mappings: resolve_mappings(&records, query_name.as_deref()),
        query_name,
        // Bit 9 of the flags word, set when the answer did not fit the
        // transport. Reported rather than treated as a parse failure: what was
        // read is still true.
        truncated_by_server: flags & 0x0200 != 0,
    })
}

/// The question section, read for its name and then skipped.
///
/// Only the first question's name is kept. A multi question message is legal on
/// paper and effectively unused, and picking one of several names as "the"
/// query would be a guess.
fn read_question_section(
    message: &[u8],
    cursor: &mut Cursor<'_>,
    count: u16,
) -> Result<Option<String>, DnsParseError> {
    let mut query_name = None;
    for index in 0..count {
        let (name, next) = read_name(message, cursor.at())?;
        cursor.seek(next).ok_or(DnsParseError::Truncated)?;
        cursor.skip(4).ok_or(DnsParseError::Truncated)?; // qtype and qclass
        if index == 0 && !name.is_empty() {
            query_name = Some(name);
        }
    }
    Ok(query_name)
}

/// A record of the three types that carry addressing, with the rest skipped.
enum Record {
    Address { owner: String, ip: IpAddr, ttl: u32 },
    Alias { owner: String, target: String },
}

fn read_answer_section(
    message: &[u8],
    cursor: &mut Cursor<'_>,
    count: u16,
) -> Result<Vec<Record>, DnsParseError> {
    let mut records = Vec::new();
    for _ in 0..count {
        let (owner, next) = read_name(message, cursor.at())?;
        cursor.seek(next).ok_or(DnsParseError::Truncated)?;
        let record_type = cursor.u16().ok_or(DnsParseError::Truncated)?;
        let class = cursor.u16().ok_or(DnsParseError::Truncated)?;
        let ttl = cursor.u32().ok_or(DnsParseError::Truncated)?;
        let rdlength = usize::from(cursor.u16().ok_or(DnsParseError::Truncated)?);
        let rdata_at = cursor.at();
        let rdata = cursor.take(rdlength).ok_or(DnsParseError::Truncated)?;

        if class != CLASS_IN {
            continue;
        }
        match record_type {
            TYPE_A => records.push(Record::Address {
                owner,
                ip: IpAddr::V4(Ipv4Addr::from(
                    read_octets::<4>(rdata).ok_or(DnsParseError::Malformed)?,
                )),
                ttl,
            }),
            TYPE_AAAA => records.push(Record::Address {
                owner,
                ip: IpAddr::V6(Ipv6Addr::from(
                    read_octets::<16>(rdata).ok_or(DnsParseError::Malformed)?,
                )),
                ttl,
            }),
            TYPE_CNAME => {
                // The alias target may itself be compressed against the rest of
                // the message, so it is read against the whole buffer.
                let (target, _) = read_name(message, rdata_at)?;
                if !target.is_empty() {
                    records.push(Record::Alias { owner, target });
                }
            }
            _ => {}
        }
    }
    Ok(records)
}

fn read_octets<const N: usize>(rdata: &[u8]) -> Option<[u8; N]> {
    let mut octets = [0u8; N];
    let source = rdata.get(..N)?;
    if rdata.len() != N {
        // A record whose length disagrees with its type is not an address the
        // sensor may report; guessing which half is right would invent data.
        return None;
    }
    octets.copy_from_slice(source);
    Some(octets)
}

/// Turns the records into address to name mappings.
///
/// Each address is filed under the name of the record that carried it, and
/// under the name that was asked for when an alias chain connects the two. A
/// CDN answer reads `api.example.com CNAME edge.cdn.net` then
/// `edge.cdn.net A 1.2.3.4`, and only the second name is on the address record.
/// Recording both is what lets a later classification match the name a human
/// would recognise without the sensor having to choose one and discard the
/// other.
fn resolve_mappings(records: &[Record], query_name: Option<&str>) -> Vec<DnsMapping> {
    let aliases: BTreeMap<&str, &str> = records
        .iter()
        .filter_map(|record| match record {
            Record::Alias { owner, target } => Some((owner.as_str(), target.as_str())),
            Record::Address { .. } => None,
        })
        .collect();

    // Keyed so that the same pair seen twice keeps the longer lifetime rather
    // than whichever record happened to be last.
    let mut best: BTreeMap<(IpAddr, String), u32> = BTreeMap::new();
    for record in records {
        let Record::Address { owner, ip, ttl } = record else {
            continue;
        };
        insert_mapping(&mut best, *ip, owner.clone(), *ttl);

        if let Some(query) = query_name {
            if query != owner && chain_reaches(&aliases, query, owner) {
                insert_mapping(&mut best, *ip, query.to_owned(), *ttl);
            }
        }
    }

    best.into_iter()
        .map(|((ip, name), ttl_secs)| DnsMapping { ip, name, ttl_secs })
        .collect()
}

fn insert_mapping(best: &mut BTreeMap<(IpAddr, String), u32>, ip: IpAddr, name: String, ttl: u32) {
    best.entry((ip, name))
        .and_modify(|existing| *existing = (*existing).max(ttl))
        .or_insert(ttl);
}

fn chain_reaches(aliases: &BTreeMap<&str, &str>, from: &str, to: &str) -> bool {
    let mut at = from;
    for _ in 0..MAX_CNAME_DEPTH {
        match aliases.get(at) {
            Some(next) if *next == to => return true,
            Some(next) => at = next,
            None => return false,
        }
    }
    false
}

/// Reads a name, following compression pointers, and reports where the name
/// ended in the stream.
///
/// The returned offset is the position after the name as it was written at
/// `start`, not after whatever a pointer jumped to. That distinction is the
/// whole reason this is not a method on the cursor: a compressed name is two
/// bytes long in the stream however many labels it expands to.
fn read_name(message: &[u8], start: usize) -> Result<(String, usize), DnsParseError> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut at = start;
    let mut resume: Option<usize> = None;
    let mut jumps = 0u32;
    let mut consumed = 0usize;

    loop {
        let length = *message.get(at).ok_or(DnsParseError::Truncated)?;
        match length & 0xc0 {
            0x00 => {
                let after_length = at.checked_add(1).ok_or(DnsParseError::Malformed)?;
                if length == 0 {
                    let end = resume.unwrap_or(after_length);
                    return Ok((join_labels(&labels)?, end));
                }
                let label_len = usize::from(length);
                if label_len > MAX_LABEL_BYTES {
                    return Err(DnsParseError::Malformed);
                }
                let end = after_length
                    .checked_add(label_len)
                    .ok_or(DnsParseError::Malformed)?;
                let label = message
                    .get(after_length..end)
                    .ok_or(DnsParseError::Truncated)?;
                consumed = consumed
                    .checked_add(label_len + 1)
                    .ok_or(DnsParseError::Malformed)?;
                if consumed > MAX_NAME_BYTES {
                    return Err(DnsParseError::Malformed);
                }
                labels.push(label);
                at = end;
            }
            0xc0 => {
                let low = *message
                    .get(at.checked_add(1).ok_or(DnsParseError::Malformed)?)
                    .ok_or(DnsParseError::Truncated)?;
                let target = (usize::from(length & 0x3f) << 8) | usize::from(low);
                if resume.is_none() {
                    resume = Some(at.checked_add(2).ok_or(DnsParseError::Malformed)?);
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return Err(DnsParseError::Malformed);
                }
                at = target;
            }
            // 0x40 and 0x80 are reserved label forms. A message using one is
            // not something this parser may guess its way through.
            _ => return Err(DnsParseError::Malformed),
        }
    }
}

/// Joins labels into a lowercase name, rejecting bytes a host name may not
/// contain.
///
/// These strings are written into a report and matched against provider
/// signatures, so a label carrying control bytes or a separator is refused
/// rather than escaped. Case is folded because DNS is case insensitive on the
/// wire and a report that compares equal across runs cannot be.
fn join_labels(labels: &[&[u8]]) -> Result<String, DnsParseError> {
    let mut name = String::new();
    for label in labels {
        if !name.is_empty() {
            name.push('.');
        }
        for &byte in *label {
            if !is_name_byte(byte) {
                return Err(DnsParseError::Malformed);
            }
            name.push(char::from(byte).to_ascii_lowercase());
        }
    }
    Ok(name)
}

/// Underscore is allowed because service names such as `_dns.resolver.arpa`
/// use it. The wildcard byte is not: a wildcard cannot be a destination.
fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;

    /// Encodes a name in wire form, so the fixtures below read as names.
    pub(crate) fn encoded_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(u8::try_from(label.len()).unwrap_or(0));
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    struct Answer {
        name: Vec<u8>,
        record_type: u16,
        ttl: u32,
        rdata: Vec<u8>,
    }

    fn a(name: &str, ip: [u8; 4], ttl: u32) -> Answer {
        Answer {
            name: encoded_name(name),
            record_type: TYPE_A,
            ttl,
            rdata: ip.to_vec(),
        }
    }

    fn aaaa(name: &str, ip: Ipv6Addr, ttl: u32) -> Answer {
        Answer {
            name: encoded_name(name),
            record_type: TYPE_AAAA,
            ttl,
            rdata: ip.octets().to_vec(),
        }
    }

    fn cname(name: &str, target: &str) -> Answer {
        Answer {
            name: encoded_name(name),
            record_type: TYPE_CNAME,
            ttl: 60,
            rdata: encoded_name(target),
        }
    }

    /// A response with one question and the given answers.
    fn response(question: &str, answers: Vec<Answer>) -> Vec<u8> {
        let mut out = vec![0x12, 0x34, 0x81, 0x80];
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&u16::try_from(answers.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&encoded_name(question));
        out.extend_from_slice(&1u16.to_be_bytes()); // qtype A
        out.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
        for answer in answers {
            out.extend_from_slice(&answer.name);
            out.extend_from_slice(&answer.record_type.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&answer.ttl.to_be_bytes());
            out.extend_from_slice(&u16::try_from(answer.rdata.len()).unwrap_or(0).to_be_bytes());
            out.extend_from_slice(&answer.rdata);
        }
        out
    }

    pub(crate) fn one_answer(question: &str, ip: [u8; 4], ttl: u32) -> Vec<u8> {
        response(question, vec![a(question, ip, ttl)])
    }

    fn names_for(answers: &DnsAnswers, ip: IpAddr) -> Vec<&str> {
        answers
            .mappings
            .iter()
            .filter(|mapping| mapping.ip == ip)
            .map(|mapping| mapping.name.as_str())
            .collect()
    }

    #[test]
    fn a_plain_answer_maps_the_address_to_the_name_that_was_asked_for() {
        let answers = parse_response(&one_answer("api.openai.com", [104, 18, 7, 1], 300)).unwrap();
        assert_eq!(answers.query_name.as_deref(), Some("api.openai.com"));
        assert_eq!(
            answers.mappings,
            vec![DnsMapping {
                ip: IpAddr::from([104, 18, 7, 1]),
                name: "api.openai.com".to_owned(),
                ttl_secs: 300,
            }]
        );
    }

    #[test]
    fn a_query_is_refused_because_the_sensor_does_not_keep_what_was_asked() {
        // The spec allows answers only. A query carries intent, and the sensor
        // has no business storing it.
        let mut query = one_answer("api.openai.com", [104, 18, 7, 1], 300);
        // Clear the response bit and keep everything else identical.
        query[2] = 0x01;
        assert_eq!(
            parse_response(&query),
            Err(DnsParseError::NotAResponse),
            "a message without the response bit must not be parsed"
        );
    }

    #[test]
    fn several_answers_all_reach_the_map() {
        let message = response(
            "api.openai.com",
            vec![
                a("api.openai.com", [104, 18, 7, 1], 300),
                a("api.openai.com", [104, 18, 7, 2], 300),
                a("api.openai.com", [104, 18, 7, 3], 60),
            ],
        );
        let answers = parse_response(&message).unwrap();
        assert_eq!(answers.mappings.len(), 3);
        assert!(answers
            .mappings
            .iter()
            .all(|mapping| mapping.name == "api.openai.com"));
    }

    #[test]
    fn an_ipv6_answer_is_read_like_any_other() {
        // AAAA is the common case for a modern client and would be a silent
        // hole in classification if only A were read.
        let ip: Ipv6Addr = "2606:4700::6810:701".parse().unwrap();
        let message = response("api.openai.com", vec![aaaa("api.openai.com", ip, 120)]);
        let answers = parse_response(&message).unwrap();
        assert_eq!(
            answers.mappings,
            vec![DnsMapping {
                ip: IpAddr::V6(ip),
                name: "api.openai.com".to_owned(),
                ttl_secs: 120,
            }]
        );
    }

    #[test]
    fn an_alias_chain_files_the_address_under_both_names() {
        // The CDN shape. Only `edge.cdn.example` is on the address record, and
        // a report that showed only that would hide which service was reached.
        let message = response(
            "api.openai.com",
            vec![
                cname("api.openai.com", "edge.cdn.example"),
                a("edge.cdn.example", [104, 18, 7, 1], 300),
            ],
        );
        let answers = parse_response(&message).unwrap();
        let names = names_for(&answers, IpAddr::from([104, 18, 7, 1]));
        assert_eq!(names, vec!["api.openai.com", "edge.cdn.example"]);
    }

    #[test]
    fn a_two_step_alias_chain_still_reaches_the_query_name() {
        let message = response(
            "api.openai.com",
            vec![
                cname("api.openai.com", "one.cdn.example"),
                cname("one.cdn.example", "two.cdn.example"),
                a("two.cdn.example", [104, 18, 7, 1], 300),
            ],
        );
        let answers = parse_response(&message).unwrap();
        assert!(names_for(&answers, IpAddr::from([104, 18, 7, 1])).contains(&"api.openai.com"));
    }

    #[test]
    fn an_unrelated_alias_does_not_lend_its_name_to_an_address() {
        // The failure this guards: filing an address under a name no chain
        // connects it to would put a destination in the report that the
        // response never claimed.
        let message = response(
            "api.openai.com",
            vec![
                cname("something.else.example", "edge.cdn.example"),
                a("edge.cdn.example", [104, 18, 7, 1], 300),
            ],
        );
        let answers = parse_response(&message).unwrap();
        assert_eq!(
            names_for(&answers, IpAddr::from([104, 18, 7, 1])),
            vec!["edge.cdn.example"]
        );
    }

    #[test]
    fn a_compression_pointer_is_followed() {
        // Real resolvers compress the answer name against the question, so a
        // parser that cannot do this reads almost nothing in production.
        let mut message = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        message.extend_from_slice(&encoded_name("api.openai.com"));
        message.extend_from_slice(&[0, 1, 0, 1]);
        message.extend_from_slice(&[0xc0, 0x0c]); // pointer to offset 12
        message.extend_from_slice(&TYPE_A.to_be_bytes());
        message.extend_from_slice(&CLASS_IN.to_be_bytes());
        message.extend_from_slice(&300u32.to_be_bytes());
        message.extend_from_slice(&4u16.to_be_bytes());
        message.extend_from_slice(&[104, 18, 7, 1]);

        let answers = parse_response(&message).unwrap();
        assert_eq!(answers.mappings.len(), 1);
        assert_eq!(
            answers.mappings.first().map(|m| m.name.as_str()),
            Some("api.openai.com")
        );
    }

    #[test]
    fn a_pointer_that_loops_is_refused_instead_of_hanging() {
        // A pointer at offset 12 that points at itself. Without the jump budget
        // this is an unbounded loop inside a sensor with a CPU budget.
        let mut message = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        message.extend_from_slice(&[0xc0, 0x0c]);
        message.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(parse_response(&message), Err(DnsParseError::Malformed));
    }

    #[test]
    fn a_message_cut_short_is_an_error_and_not_an_empty_answer() {
        // The distinction the coverage statement depends on: nothing resolved
        // and nothing readable are different facts.
        let full = one_answer("api.openai.com", [104, 18, 7, 1], 300);
        for cut in [4, 10, 20, full.len() - 1] {
            assert_eq!(
                parse_response(full.get(..cut).unwrap_or_default()),
                Err(DnsParseError::Truncated),
                "a message cut at {cut} must not read as a clean empty answer"
            );
        }
    }

    #[test]
    fn a_header_claiming_more_records_than_it_carries_is_capped() {
        let mut message = vec![0x12, 0x34, 0x81, 0x80];
        message.extend_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&u16::MAX.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(parse_response(&message), Err(DnsParseError::TooManyRecords));
    }

    #[test]
    fn an_address_record_whose_length_disagrees_with_its_type_is_refused() {
        // Four bytes is what an A record means. A five byte one is either a
        // different format or a probe, and neither may become an address.
        let message = response(
            "api.openai.com",
            vec![Answer {
                name: encoded_name("api.openai.com"),
                record_type: TYPE_A,
                ttl: 300,
                rdata: vec![104, 18, 7, 1, 9],
            }],
        );
        assert_eq!(parse_response(&message), Err(DnsParseError::Malformed));
    }

    #[test]
    fn a_label_carrying_bytes_a_host_name_cannot_have_is_refused() {
        // These names are written into a report and matched against provider
        // signatures. A label with a control byte in it must not get there.
        let mut message = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        message.extend_from_slice(&[3, b'a', 0x00, b'c', 0]);
        message.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(parse_response(&message), Err(DnsParseError::Malformed));
    }

    #[test]
    fn a_reserved_label_form_is_refused_rather_than_guessed_at() {
        let mut message = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        message.extend_from_slice(&[0x80, 0x00]);
        assert_eq!(parse_response(&message), Err(DnsParseError::Malformed));
    }

    #[test]
    fn a_response_with_no_answers_reads_as_empty_and_not_as_a_failure() {
        // NXDOMAIN and an empty answer section are normal. They mean the map
        // learns nothing, which is different from the parse breaking.
        let message = response("nowhere.example", Vec::new());
        let answers = parse_response(&message).unwrap();
        assert!(answers.is_empty());
        assert_eq!(answers.query_name.as_deref(), Some("nowhere.example"));
    }

    #[test]
    fn a_server_truncated_answer_is_reported_rather_than_treated_as_complete() {
        let mut message = one_answer("api.openai.com", [104, 18, 7, 1], 300);
        if let Some(byte) = message.get_mut(2) {
            *byte |= 0x02; // TC
        }
        let answers = parse_response(&message).unwrap();
        assert!(answers.truncated_by_server);
        assert_eq!(answers.mappings.len(), 1);
    }

    #[test]
    fn a_name_is_folded_to_lower_case_so_two_captures_compare_equal() {
        let answers = parse_response(&one_answer("API.OpenAI.COM", [104, 18, 7, 1], 300)).unwrap();
        assert_eq!(answers.query_name.as_deref(), Some("api.openai.com"));
    }

    #[test]
    fn a_record_in_another_class_is_skipped_without_failing_the_message() {
        let mut message = vec![0x12, 0x34, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0];
        message.extend_from_slice(&encoded_name("chaos.example"));
        message.extend_from_slice(&TYPE_A.to_be_bytes());
        message.extend_from_slice(&3u16.to_be_bytes()); // class CH
        message.extend_from_slice(&300u32.to_be_bytes());
        message.extend_from_slice(&4u16.to_be_bytes());
        message.extend_from_slice(&[1, 2, 3, 4]);
        assert!(parse_response(&message).unwrap().is_empty());
    }

    #[test]
    fn an_empty_sample_fails_instead_of_reading_as_a_response() {
        assert_eq!(parse_response(&[]), Err(DnsParseError::Truncated));
        assert_eq!(
            parse_response(&[0u8; HEADER_BYTES - 1]),
            Err(DnsParseError::Truncated)
        );
    }

    #[test]
    fn every_parse_failure_has_its_own_label() {
        let failures = [
            DnsParseError::NotAResponse,
            DnsParseError::Truncated,
            DnsParseError::Malformed,
            DnsParseError::TooManyRecords,
        ];
        let labels: std::collections::BTreeSet<&str> =
            failures.iter().map(|f| f.as_str()).collect();
        assert_eq!(labels.len(), failures.len());
    }
}
