//! Reading the server name out of a TLS ClientHello.
//!
//! This is the second and stronger of the two classification signals, and it is
//! the one that most needs its limits written down. ADR-008 forbids TLS
//! interception outright: the sensor never terminates a session, never holds a
//! key and never decrypts. What it reads here is the part of the handshake that
//! travels in clear text before any key exchange has happened, and the parse
//! stops at the extension list. There is no code path in this module that
//! reaches application data, and no type in it that could carry one.
//!
//! Two behaviours are worth reading twice, because both are places where a
//! convenient answer would be a false one.
//!
//! **Encrypted ClientHello wins over any name in the same message.** A hello
//! that carries the ECH extension also carries a `server_name`, and that name is
//! the ECH public name, which identifies the provider fronting the destination
//! rather than the destination. Reporting it would name the wrong host with full
//! confidence. So ECH is checked over the whole extension list and, when
//! present, the name is discarded.
//!
//! **A hello cut short is a failure even when the name was already read.** The
//! ECH extension can sit after the `server_name` extension, so a name read from
//! a sample that ended early cannot be known to be the real one. Returning it
//! would be exactly the "looks observed and is not" record the crate exists to
//! prevent.

use std::net::IpAddr;

use super::cursor::Cursor;

/// A TLS record of type handshake.
const RECORD_HANDSHAKE: u8 = 0x16;

/// Handshake message type `client_hello`.
const CLIENT_HELLO: u8 = 0x01;

/// `server_name`, RFC 6066.
const EXT_SERVER_NAME: u16 = 0x0000;

/// `encrypted_client_hello`, the code point ECH shipped on.
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

/// `host_name`, the only `server_name` entry type ever defined.
const NAME_TYPE_HOST_NAME: u8 = 0x00;

/// A TLS record may not declare more than this, so a larger length is a
/// malformed sample rather than a big handshake.
const MAX_RECORD_BYTES: usize = 16_384;

/// The `client_random` field, fixed width and skipped.
const RANDOM_BYTES: usize = 32;

const MAX_HOST_NAME_BYTES: usize = 253;
const MAX_LABEL_BYTES: usize = 63;

/// What the clear text part of a handshake established about the destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientHelloFacts {
    /// A readable server name.
    ServerName(String),
    /// The name is encrypted and this build cannot and will not recover it.
    Encrypted,
    /// The handshake offered no name. Different from [`Self::Encrypted`]: one
    /// is a client that did not send one, the other is a measured blind spot.
    NoServerName,
}

/// Why a sample could not be read as a ClientHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsParseError {
    /// Not a handshake record. The first packet of a plain TCP connection.
    NotHandshake,
    /// A handshake, but some other message. A ServerHello, for instance.
    NotClientHello,
    /// The sample ended inside the message, so the extension list is unknown.
    Truncated,
    /// A length the format does not allow.
    Malformed,
    /// A server name that is not a host name a report may carry.
    MalformedServerName,
}

impl TlsParseError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotHandshake => "tls_not_handshake",
            Self::NotClientHello => "tls_not_client_hello",
            Self::Truncated => "tls_truncated",
            Self::Malformed => "tls_malformed",
            Self::MalformedServerName => "tls_malformed_server_name",
        }
    }
}

/// Reads the clear text facts out of the first packet of a TLS connection.
pub fn parse_client_hello(sample: &[u8]) -> Result<ClientHelloFacts, TlsParseError> {
    let mut cursor = Cursor::new(sample);

    if cursor.u8().ok_or(TlsParseError::Truncated)? != RECORD_HANDSHAKE {
        return Err(TlsParseError::NotHandshake);
    }
    cursor.skip(2).ok_or(TlsParseError::Truncated)?; // legacy record version
    let record_len = usize::from(cursor.u16().ok_or(TlsParseError::Truncated)?);
    if record_len == 0 || record_len > MAX_RECORD_BYTES {
        return Err(TlsParseError::Malformed);
    }

    // The record may be longer than the sample: a hello can be fragmented, and
    // a capture is bounded on purpose. Parse what is here and remember that the
    // end was not seen, because that decides whether a name may be trusted.
    let body = cursor.rest();
    let whole_record_present = body.len() >= record_len;

    let scan = scan_hello(body)?;
    let complete = whole_record_present && scan.complete;

    if scan.encrypted {
        // Decided before completeness: ECH seen anywhere in the list settles
        // the question, and nothing later in the message could unsettle it.
        return Ok(ClientHelloFacts::Encrypted);
    }
    if !complete {
        return Err(TlsParseError::Truncated);
    }
    Ok(match scan.server_name {
        Some(name) => ClientHelloFacts::ServerName(name),
        None => ClientHelloFacts::NoServerName,
    })
}

/// What the extension list said, and whether it was read to its end.
#[derive(Debug, Default)]
struct HelloScan {
    server_name: Option<String>,
    encrypted: bool,
    complete: bool,
}

fn scan_hello(body: &[u8]) -> Result<HelloScan, TlsParseError> {
    let mut cursor = Cursor::new(body);

    if cursor.u8().ok_or(TlsParseError::Truncated)? != CLIENT_HELLO {
        return Err(TlsParseError::NotClientHello);
    }
    let declared = cursor.u24().ok_or(TlsParseError::Truncated)?;
    let declared = usize::try_from(declared).map_err(|_| TlsParseError::Malformed)?;
    if declared > MAX_RECORD_BYTES {
        return Err(TlsParseError::Malformed);
    }

    // Anything before the extension list has a fixed shape, so a sample that
    // ends inside it tells us nothing at all and is a plain truncation.
    cursor.skip(2).ok_or(TlsParseError::Truncated)?; // legacy_version
    cursor.skip(RANDOM_BYTES).ok_or(TlsParseError::Truncated)?;
    skip_vector_u8(&mut cursor).ok_or(TlsParseError::Truncated)?; // legacy_session_id
    skip_vector_u16(&mut cursor).ok_or(TlsParseError::Truncated)?; // cipher_suites
    skip_vector_u8(&mut cursor).ok_or(TlsParseError::Truncated)?; // legacy_compression_methods

    if cursor.is_empty() {
        // A hello with no extension block at all. Legal in TLS 1.0 and 1.1, and
        // it names no server, which is a fact rather than a failure.
        return Ok(HelloScan {
            complete: declared_body_seen(declared, body),
            ..HelloScan::default()
        });
    }

    let extensions_len = usize::from(cursor.u16().ok_or(TlsParseError::Truncated)?);
    let available = cursor.rest();
    let mut scan = scan_extensions(available.get(..extensions_len).unwrap_or(available))?;
    scan.complete = available.len() >= extensions_len && scan.complete;
    Ok(scan)
}

/// Whether the sample carried the whole handshake message the header declared.
fn declared_body_seen(declared: usize, body: &[u8]) -> bool {
    // Four bytes of handshake header precede the declared body.
    body.len() >= declared.saturating_add(4)
}

fn scan_extensions(block: &[u8]) -> Result<HelloScan, TlsParseError> {
    let mut scan = HelloScan {
        complete: true,
        ..HelloScan::default()
    };
    let mut cursor = Cursor::new(block);

    while !cursor.is_empty() {
        let (Some(kind), Some(length)) = (cursor.u16(), cursor.u16()) else {
            scan.complete = false;
            break;
        };
        let Some(data) = cursor.take(usize::from(length)) else {
            scan.complete = false;
            break;
        };
        match kind {
            EXT_SERVER_NAME => {
                // First entry wins. A hello with two server_name extensions is
                // malformed by RFC 6066; taking the first is what a stack does
                // and inventing a merge would be a guess.
                if scan.server_name.is_none() {
                    scan.server_name = read_server_name(data)?;
                }
            }
            EXT_ENCRYPTED_CLIENT_HELLO => scan.encrypted = true,
            // Everything else, including the GREASE code points a modern client
            // sprinkles through the list, is skipped by length.
            _ => {}
        }
    }
    Ok(scan)
}

fn read_server_name(data: &[u8]) -> Result<Option<String>, TlsParseError> {
    if data.is_empty() {
        // A zero length server_name is how a server echoes the extension back.
        // Nothing to read, and not an error.
        return Ok(None);
    }
    let mut cursor = Cursor::new(data);
    let list_len = usize::from(cursor.u16().ok_or(TlsParseError::MalformedServerName)?);
    let list = cursor.rest();
    let list = list
        .get(..list_len)
        .ok_or(TlsParseError::MalformedServerName)?;

    let mut cursor = Cursor::new(list);
    while !cursor.is_empty() {
        let name_type = cursor.u8().ok_or(TlsParseError::MalformedServerName)?;
        let length = usize::from(cursor.u16().ok_or(TlsParseError::MalformedServerName)?);
        let bytes = cursor
            .take(length)
            .ok_or(TlsParseError::MalformedServerName)?;
        if name_type == NAME_TYPE_HOST_NAME {
            return validate_host_name(bytes)
                .map(Some)
                .ok_or(TlsParseError::MalformedServerName);
        }
    }
    Ok(None)
}

/// Accepts a host name a report may carry, and nothing else.
///
/// The value is attacker controlled: whoever opened the connection chose it, and
/// it ends up in a report, in a provider match and in a file a human reads. So
/// the shape is checked rather than escaped, and an address literal is refused
/// because RFC 6066 forbids one and a numeric "host name" would collide with
/// the address column next to it.
fn validate_host_name(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() > MAX_HOST_NAME_BYTES {
        return None;
    }
    let mut name = String::with_capacity(bytes.len());
    for label in bytes.split(|byte| *byte == b'.') {
        if label.is_empty() || label.len() > MAX_LABEL_BYTES {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        for byte in label {
            if !(byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_') {
                return None;
            }
            name.push(char::from(*byte).to_ascii_lowercase());
        }
    }
    if name.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(name)
}

fn skip_vector_u8(cursor: &mut Cursor<'_>) -> Option<()> {
    let length = usize::from(cursor.u8()?);
    cursor.skip(length)
}

fn skip_vector_u16(cursor: &mut Cursor<'_>) -> Option<()> {
    let length = usize::from(cursor.u16()?);
    cursor.skip(length)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;

    /// Builds a `server_name` extension carrying one host name.
    fn server_name_extension(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        let mut entry = vec![NAME_TYPE_HOST_NAME];
        entry.extend_from_slice(&u16::try_from(host.len()).unwrap_or(0).to_be_bytes());
        entry.extend_from_slice(host);

        let mut data = Vec::new();
        data.extend_from_slice(&u16::try_from(entry.len()).unwrap_or(0).to_be_bytes());
        data.extend_from_slice(&entry);
        extension(EXT_SERVER_NAME, &data)
    }

    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&u16::try_from(data.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    /// A complete ClientHello record carrying the given extensions.
    fn client_hello(extensions: &[Vec<u8>]) -> Vec<u8> {
        let mut block = Vec::new();
        for ext in extensions {
            block.extend_from_slice(ext);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        body.extend_from_slice(&[0x11; RANDOM_BYTES]);
        body.push(0); // empty legacy_session_id
        body.extend_from_slice(&2u16.to_be_bytes()); // one cipher suite
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1); // one compression method
        body.push(0);
        body.extend_from_slice(&u16::try_from(block.len()).unwrap_or(0).to_be_bytes());
        body.extend_from_slice(&block);

        let mut handshake = vec![CLIENT_HELLO];
        let length = u32::try_from(body.len()).unwrap_or(0);
        handshake.extend_from_slice(length.to_be_bytes().get(1..).unwrap_or_default());
        handshake.extend_from_slice(&body);

        let mut record = vec![RECORD_HANDSHAKE, 0x03, 0x01];
        record.extend_from_slice(&u16::try_from(handshake.len()).unwrap_or(0).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    pub(crate) fn hello_for(host: &str) -> Vec<u8> {
        client_hello(&[server_name_extension(host)])
    }

    pub(crate) fn ech_hello() -> Vec<u8> {
        client_hello(&[
            server_name_extension("public.cloudflare-ech.com"),
            extension(EXT_ENCRYPTED_CLIENT_HELLO, &[0x00, 0x01, 0x02]),
        ])
    }

    #[test]
    fn a_plain_hello_yields_the_server_name() {
        assert_eq!(
            parse_client_hello(&hello_for("api.openai.com")),
            Ok(ClientHelloFacts::ServerName("api.openai.com".to_owned()))
        );
    }

    #[test]
    fn an_encrypted_hello_never_reports_the_public_name_as_the_destination() {
        // The trap this module is most careful about. The ECH outer hello does
        // carry a server_name, and it names the fronting provider. A sensor
        // that reported it would state the wrong destination with no hedge at
        // all, which is worse than saying nothing.
        assert_eq!(
            parse_client_hello(&ech_hello()),
            Ok(ClientHelloFacts::Encrypted)
        );
    }

    #[test]
    fn ech_wins_wherever_it_sits_in_the_list() {
        let before = client_hello(&[
            extension(EXT_ENCRYPTED_CLIENT_HELLO, &[0x00]),
            server_name_extension("public.example"),
        ]);
        assert_eq!(parse_client_hello(&before), Ok(ClientHelloFacts::Encrypted));
    }

    #[test]
    fn a_hello_cut_short_after_the_name_is_a_failure_and_not_that_name() {
        // The second trap. ECH can follow server_name, so a name read from a
        // sample that ended early cannot be known to be the real destination.
        let full = client_hello(&[
            server_name_extension("api.openai.com"),
            extension(EXT_ENCRYPTED_CLIENT_HELLO, &[0x00, 0x01]),
        ]);
        // Cut exactly where the ECH extension would have begun: four header
        // bytes and two of payload.
        let cut = full.get(..full.len() - 6).unwrap_or_default();

        // The name is physically present in the bytes that were kept.
        assert!(cut.windows(14).any(|w| w == b"api.openai.com"));
        assert_eq!(parse_client_hello(cut), Err(TlsParseError::Truncated));
    }

    #[test]
    fn a_sample_that_ends_before_the_extensions_is_truncated() {
        let full = hello_for("api.openai.com");
        for cut in [1, 5, 6, 20, 45] {
            assert_eq!(
                parse_client_hello(full.get(..cut).unwrap_or_default()),
                Err(TlsParseError::Truncated),
                "a sample cut at {cut} must not read as a complete hello"
            );
        }
    }

    #[test]
    fn a_hello_offering_no_name_is_not_the_same_as_one_that_hid_it() {
        // `absent` and `encrypted_client_hello` are separate values in the
        // contract precisely so these two do not arrive looking alike.
        assert_eq!(
            parse_client_hello(&client_hello(&[])),
            Ok(ClientHelloFacts::NoServerName)
        );
    }

    #[test]
    fn unknown_extensions_are_skipped_by_length() {
        // A real hello from a browser is mostly extensions this sensor has no
        // interest in, including GREASE code points chosen to break parsers
        // that special case what they know.
        let hello = client_hello(&[
            extension(0x0a0a, &[0x00; 4]), // GREASE
            extension(0x002b, &[0x02, 0x03, 0x04]),
            server_name_extension("api.anthropic.com"),
            extension(0x0033, &[0x09; 32]),
        ]);
        assert_eq!(
            parse_client_hello(&hello),
            Ok(ClientHelloFacts::ServerName("api.anthropic.com".to_owned()))
        );
    }

    #[test]
    fn a_record_that_is_not_a_handshake_says_so_rather_than_failing_vaguely() {
        // Application data on port 443 from a connection the sensor joined
        // late. Distinguishing it from a broken hello is what keeps the
        // coverage counters meaningful.
        assert_eq!(
            parse_client_hello(&[0x17, 0x03, 0x03, 0x00, 0x10]),
            Err(TlsParseError::NotHandshake)
        );
    }

    #[test]
    fn a_handshake_that_is_not_a_client_hello_says_so() {
        let mut record = vec![RECORD_HANDSHAKE, 0x03, 0x03];
        record.extend_from_slice(&4u16.to_be_bytes());
        record.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // ServerHello
        assert_eq!(
            parse_client_hello(&record),
            Err(TlsParseError::NotClientHello)
        );
    }

    #[test]
    fn a_record_length_the_format_does_not_allow_is_refused() {
        assert_eq!(
            parse_client_hello(&[RECORD_HANDSHAKE, 0x03, 0x03, 0x00, 0x00]),
            Err(TlsParseError::Malformed)
        );
        assert_eq!(
            parse_client_hello(&[RECORD_HANDSHAKE, 0x03, 0x03, 0xff, 0xff]),
            Err(TlsParseError::Malformed)
        );
    }

    #[test]
    fn a_server_name_that_is_not_a_host_name_is_refused() {
        // These strings reach a report and a provider match. A name with a
        // path, a space or a control byte in it must not get there.
        for bad in ["api.openai.com/x", "api openai com", "api..openai.com", ""] {
            assert_eq!(
                parse_client_hello(&hello_for(bad)),
                Err(TlsParseError::MalformedServerName),
                "{bad:?} must not be accepted as a server name"
            );
        }
    }

    #[test]
    fn an_address_literal_is_refused_as_a_server_name() {
        // RFC 6066 forbids it, and a numeric name would sit in the report next
        // to the address column claiming to be something else.
        assert_eq!(
            parse_client_hello(&hello_for("104.18.7.1")),
            Err(TlsParseError::MalformedServerName)
        );
    }

    #[test]
    fn a_name_is_folded_to_lower_case_so_two_captures_compare_equal() {
        assert_eq!(
            parse_client_hello(&hello_for("API.OpenAI.Com")),
            Ok(ClientHelloFacts::ServerName("api.openai.com".to_owned()))
        );
    }

    #[test]
    fn an_over_long_name_is_refused() {
        let long = format!("{}.example", "a".repeat(250));
        assert_eq!(
            parse_client_hello(&hello_for(&long)),
            Err(TlsParseError::MalformedServerName)
        );
    }

    #[test]
    fn an_over_long_label_is_refused() {
        let long = format!("{}.example", "a".repeat(64));
        assert_eq!(
            parse_client_hello(&hello_for(&long)),
            Err(TlsParseError::MalformedServerName)
        );
    }

    #[test]
    fn an_empty_sample_is_truncated_rather_than_anything_else() {
        assert_eq!(parse_client_hello(&[]), Err(TlsParseError::Truncated));
    }

    #[test]
    fn a_server_name_list_length_that_overruns_its_extension_is_refused() {
        let mut data = Vec::new();
        data.extend_from_slice(&0xffffu16.to_be_bytes());
        data.extend_from_slice(&[NAME_TYPE_HOST_NAME, 0x00, 0x03, b'a', b'b', b'c']);
        let hello = client_hello(&[extension(EXT_SERVER_NAME, &data)]);
        assert_eq!(
            parse_client_hello(&hello),
            Err(TlsParseError::MalformedServerName)
        );
    }

    #[test]
    fn every_parse_failure_has_its_own_label() {
        let failures = [
            TlsParseError::NotHandshake,
            TlsParseError::NotClientHello,
            TlsParseError::Truncated,
            TlsParseError::Malformed,
            TlsParseError::MalformedServerName,
        ];
        let labels: std::collections::BTreeSet<&str> =
            failures.iter().map(|f| f.as_str()).collect();
        assert_eq!(labels.len(), failures.len());
    }
}
