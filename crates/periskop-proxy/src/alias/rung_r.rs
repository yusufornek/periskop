//! Rung `R`: aliases drawn from ranges a standards body took out of allocation.
//!
//! This is the strongest rung, and the reason is that the evidence is somebody
//! else's published decision rather than an argument of ours. `.invalid` is
//! never delegated (RFC 2606). `203.0.113.0/24` is documentation only
//! (RFC 5737). `2001:db8::/32` is the same for IPv6 (RFC 3849). An alias from
//! one of these cannot be a host, an address or a mailbox that belongs to
//! anybody, and a reader can check that claim without trusting this file: the
//! citation is in [`super::catalog`].
//!
//! # The pools are finite, and running out is reported
//!
//! A documentation /24 holds 256 addresses and this build registers three of
//! them. A session that masks more distinct IPv4 addresses than the pool holds
//! cannot stay on this rung, and the alternative is not to step outside the
//! documented range: it is to fall to rung `O` and say so through
//! `alias_stats.alias_pool_exhausted`. The `.invalid` pools are large enough
//! that this is theoretical for hosts and mailboxes; for IPv4 it is reachable.
//!
//! # URL
//!
//! A URL is not aliased as a whole (ADR-010 section 2). [`host_span`] finds the
//! host inside one, and that host is aliased here as any other host would be, so
//! no alias ever carries the length of a source URL. The path and query survive
//! untouched, and entities inside them are the detection layer's business.

use super::catalog::{EXAMPLE_LABELS, INVALID_TLD, IPV4_DOCUMENTATION};
use super::derive::SeedStream;

/// Digits in the local part of a mailbox alias: `userNNNNN@...`.
const MAILBOX_DIGITS: usize = 5;

/// Digits in the label of a host alias: `hostNNN....`.
const HOST_DIGITS: usize = 3;

/// `userNNNNN@example-x.invalid` (RFC 2606 section 2).
pub fn email(stream: &mut SeedStream) -> String {
    let digits = stream.digits(MAILBOX_DIGITS);
    let label = stream.pick(&EXAMPLE_LABELS);
    format!("user{digits}@{label}{INVALID_TLD}")
}

/// `hostNNN.example-x.invalid` (RFC 2606 section 2).
pub fn host(stream: &mut SeedStream) -> String {
    let digits = stream.digits(HOST_DIGITS);
    let label = stream.pick(&EXAMPLE_LABELS);
    format!("host{digits}.{label}{INVALID_TLD}")
}

/// An address from one of RFC 5737's documentation blocks.
pub fn ipv4(stream: &mut SeedStream) -> String {
    let block = &IPV4_DOCUMENTATION[stream.below(IPV4_DOCUMENTATION.len() as u32) as usize];
    let host_part = stream.below(256);
    format!(
        "{}.{}.{}.{host_part}",
        block.network[0], block.network[1], block.network[2]
    )
}

/// An address from `2001:db8::/32` (RFC 3849).
pub fn ipv6(stream: &mut SeedStream) -> String {
    let first = stream.hex(4);
    let second = stream.hex(4);
    let last = stream.hex(4);
    format!("2001:db8:{first}:{second}::{last}")
}

/// Where the host lives inside a URL, as a byte range.
///
/// Deliberately small: it finds the authority, drops any userinfo and any port,
/// and hands back a range. It is not a URL parser and does not want to be, since
/// the only question here is which bytes get replaced by a host alias.
///
/// An address literal in brackets (`http://[2001:db8::1]/x`) is reported as the
/// bracketed span's interior, so the caller replaces the address and leaves the
/// brackets in place.
pub fn host_span(url: &str) -> Option<(usize, usize)> {
    let after_scheme = match url.find("://") {
        Some(at) => at + 3,
        // A bare authority ("example.com/path") is still something a detector
        // can hand over, so it is accepted rather than refused.
        None => 0,
    };
    let rest = url.get(after_scheme..)?;
    let authority_end = rest
        .find(['/', '?', '#'])
        .map_or(rest.len(), |offset| offset);
    let authority = rest.get(..authority_end)?;

    let host_start = authority.rfind('@').map_or(0, |at| at + 1);
    let host_part = authority.get(host_start..)?;

    let (start, end) = if let Some(open) = host_part.find('[') {
        let close = host_part.find(']')?;
        if close <= open + 1 {
            return None;
        }
        (open + 1, close)
    } else {
        let end = host_part.find(':').unwrap_or(host_part.len());
        (0, end)
    };

    if end <= start {
        return None;
    }
    let absolute = after_scheme + host_start;
    Some((absolute + start, absolute + end))
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
    fn every_generator_here_stays_inside_its_documented_range() {
        // The rung R invariant, over a sweep of the seed space rather than one
        // example: a generator that leaves the range for one seed in a thousand
        // is a generator that hands somebody a real address once a day.
        for byte in 0..=255u8 {
            let mut source = stream(byte);
            let mailbox = email(&mut source);
            let name = host(&mut source);
            let four = ipv4(&mut source);
            let six = ipv6(&mut source);

            assert!(catalog::email_is_documented(&mailbox), "{mailbox}");
            assert!(catalog::host_is_documented(&name), "{name}");
            assert!(catalog::ipv4_is_documented(&four), "{four}");
            assert!(catalog::ipv6_is_documented(&six), "{six}");
        }
    }

    #[test]
    fn the_shapes_are_the_ones_the_adr_prints() {
        let mut source = stream(0x5A);
        let mailbox = email(&mut source);
        assert!(mailbox.starts_with("user"));
        assert!(mailbox.contains("@example-"));
        assert!(mailbox.ends_with(".invalid"));

        let name = host(&mut source);
        assert!(name.starts_with("host"));
        assert!(name.ends_with(".invalid"));

        let six = ipv6(&mut source);
        assert!(six.starts_with("2001:db8:"));
        assert!(six.contains("::"));
    }

    #[test]
    fn a_url_gives_up_its_host_and_nothing_else() {
        let cases = [
            ("https://api.example.com/v1/users?id=7", "api.example.com"),
            ("http://user:pw@internal.corp:8443/health", "internal.corp"),
            ("example.com/path", "example.com"),
            ("https://[2001:db8::1]:443/x", "2001:db8::1"),
            ("https://api.example.com", "api.example.com"),
        ];
        for (url, expected) in cases {
            let (start, end) = host_span(url).unwrap_or_else(|| panic!("no host in {url}"));
            assert_eq!(&url[start..end], expected, "{url}");
        }
        assert_eq!(host_span(""), None);
        assert_eq!(host_span("https:///path"), None);
    }
}
