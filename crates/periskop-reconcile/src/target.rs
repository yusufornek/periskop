//! Target identity: the one thing both sources can name.
//!
//! The code says where a call is meant to go and a hook says where it went. Those
//! two strings are written by different authors under different rules, so they
//! have to be reduced to a comparable form before anything can be concluded from
//! their difference. Every step of that reduction removes a spelling difference
//! and none of them removes a real one: a normalisation that folded two genuinely
//! different destinations together would erase a drift finding rather than
//! produce it.
//!
//! Two normalisations named in the spec are deliberately absent. IDN to punycode
//! needs a table this workspace does not carry, and a reverse DNS lookup would
//! make the result depend on the network the report was produced on. Both are
//! recorded as gaps rather than approximated: an approximate host identity would
//! quietly change which findings are produced.

use std::fmt;

use serde::Serialize;

/// Ports dropped during normalisation.
///
/// A destination written with its default port and one written without it are
/// the same destination, and a drift finding raised on that difference would be
/// noise. A non-default port is kept, because moving a call to another port is a
/// real change of destination.
const DEFAULT_PORTS: [u16; 2] = [80, 443];

/// A destination, reduced to the form both sources can be compared in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct TargetId {
    host: String,
    /// Absent when the destination used a default port or named none.
    port: Option<u16>,
}

impl TargetId {
    /// Reduces a destination as written to the form comparisons run on.
    ///
    /// Accepts what either side may hand over: a bare host, a host with a port,
    /// or a whole URL, since the static rules read literal endpoints out of
    /// source and a hook records the host on its own. Returns `None` when there
    /// is no host in the value at all, which is a different fact from an empty
    /// host and must not be represented by one.
    pub fn parse(value: &str, port_hint: Option<u16>) -> Option<Self> {
        let authority = authority_of(value.trim());
        let (host, parsed_port) = split_port(authority);

        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }

        // A port inside the value wins over the hint: the hint describes the
        // record, the value describes the destination that record names.
        let port = parsed_port
            .or(port_hint)
            .filter(|p| !DEFAULT_PORTS.contains(p));
        Some(Self { host, port })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Whether the destination is an address rather than a name.
    ///
    /// Reported because a call that names a host in code and reaches a bare
    /// address at runtime has lost the one part of the destination a reader can
    /// check, and that is a different kind of drift from reaching another name.
    pub fn is_address_literal(&self) -> bool {
        if self.host.contains(':') {
            return true;
        }
        let mut octets = 0;
        for label in self.host.split('.') {
            if label.is_empty() || !label.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
            octets += 1;
        }
        octets == 4
    }

    /// Whether `self` sits under `other` in the same name, or the other way round.
    ///
    /// Suffix containment only. Deciding that `api.openai.com` and
    /// `api.example.co.uk` share a registrable domain would need a public suffix
    /// list, and guessing at one produces a confident claim about a relationship
    /// that may not exist.
    pub fn shares_name_with(&self, other: &Self) -> bool {
        let (long, short) = if self.host.len() >= other.host.len() {
            (&self.host, &other.host)
        } else {
            (&other.host, &self.host)
        };
        long.strip_suffix(short.as_str())
            .is_some_and(|prefix| prefix.ends_with('.'))
    }
}

impl fmt::Display for TargetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.port {
            Some(port) => write!(f, "{}:{port}", self.host),
            None => f.write_str(&self.host),
        }
    }
}

/// The host and port part of a value, with scheme, credentials and path removed.
fn authority_of(value: &str) -> &str {
    let after_scheme = match value.find("://") {
        Some(index) => &value[index + 3..],
        None => value,
    };
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Credentials belong to nobody's identity and would put a secret into a
    // report if they reached one.
    match authority.rfind('@') {
        Some(index) => &authority[index + 1..],
        None => authority,
    }
}

/// Splits a trailing `:port`, leaving a bracketed address intact.
fn split_port(authority: &str) -> (&str, Option<u16>) {
    if let Some(end) = authority
        .strip_prefix('[')
        .and_then(|_| authority.find(']'))
    {
        let host = &authority[1..end];
        let port = authority[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok());
        return (host, port);
    }
    // More than one colon and no brackets is an address written without them.
    // Reading its last group as a port would invent a destination nobody wrote.
    if authority.matches(':').count() > 1 {
        return (authority, None);
    }
    match authority.rsplit_once(':') {
        // An unparsable port is not a port. Dropping the segment silently would
        // let `host:not-a-number` compare equal to `host`, so the whole value
        // keeps its shape instead and simply fails to match anything.
        Some((host, port)) => match port.parse() {
            Ok(port) => (host, Some(port)),
            Err(_) => (authority, None),
        },
        None => (authority, None),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn host(value: &str) -> TargetId {
        TargetId::parse(value, None).unwrap()
    }

    #[test]
    fn spelling_differences_are_removed() {
        let expected = host("api.openai.com");
        for written in [
            "API.OpenAI.com",
            "api.openai.com.",
            "https://api.openai.com/v1/chat/completions",
            "https://api.openai.com:443/v1",
            "http://api.openai.com:80",
            "https://user:secret@api.openai.com/v1",
        ] {
            assert_eq!(host(written), expected, "{written}");
        }
    }

    #[test]
    fn credentials_never_survive_into_an_identity() {
        assert!(!host("https://user:secret@api.openai.com/v1")
            .to_string()
            .contains("secret"));
    }

    #[test]
    fn a_non_default_port_is_a_different_destination() {
        assert_ne!(host("api.openai.com:8443"), host("api.openai.com"));
        assert_eq!(host("api.openai.com:8443").port(), Some(8443));
    }

    #[test]
    fn a_hint_fills_in_only_what_the_value_did_not_say() {
        assert_eq!(
            TargetId::parse("api.openai.com", Some(8443))
                .unwrap()
                .port(),
            Some(8443)
        );
        assert_eq!(
            TargetId::parse("api.openai.com:9000", Some(8443))
                .unwrap()
                .port(),
            Some(9000)
        );
        assert_eq!(
            TargetId::parse("api.openai.com", Some(443)).unwrap().port(),
            None
        );
    }

    #[test]
    fn a_value_with_no_host_yields_nothing() {
        for empty in ["", "   ", "https://", "/v1/chat"] {
            assert!(TargetId::parse(empty, None).is_none(), "{empty:?}");
        }
    }

    #[test]
    fn addresses_are_told_apart_from_names() {
        assert!(host("10.2.3.4").is_address_literal());
        assert!(host("[2001:db8::1]:8443").is_address_literal());
        assert!(!host("api.openai.com").is_address_literal());
        // Four labels that are not four numbers.
        assert!(!host("a.b.c.d").is_address_literal());
    }

    #[test]
    fn a_subdomain_is_recognised_and_a_lookalike_is_not() {
        assert!(host("eu.api.openai.com").shares_name_with(&host("api.openai.com")));
        assert!(host("api.openai.com").shares_name_with(&host("eu.api.openai.com")));
        // The suffix matches as text but not as a name boundary. Treating this
        // as the same name would call a phishing host a subdomain.
        assert!(!host("evilopenai.com").shares_name_with(&host("openai.com")));
        assert!(!host("api.openai.com").shares_name_with(&host("api.anthropic.com")));
    }

    #[test]
    fn an_unparsable_port_does_not_collapse_into_no_port() {
        let odd = host("api.openai.com:not-a-port");
        assert_ne!(odd, host("api.openai.com"));
        assert_eq!(odd.port(), None);
    }
}
