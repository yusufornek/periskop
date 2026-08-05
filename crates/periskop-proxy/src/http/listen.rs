//! Where the proxy listens, and why that is the loopback interface until somebody
//! says otherwise in as many words.
//!
//! Everything in this crate before this module was a library. From here there is a
//! socket, and behind that socket are the vault keys, the session to alias map and
//! the request bodies before they are masked (`threat-model.md`, "proxy": the
//! highest value target in the system). A default that binds every interface would
//! publish all three to whatever can route to this host.
//!
//! There is a second reason, and it is the one that makes this a correctness rule
//! rather than a preference. F4 is a **single tenant, local** deployment: the
//! roadmap's phase boundary item 3 strikes the multi tenant proxy and the session
//! authorisation model from this phase entirely. That means there is no
//! per-caller authorisation on this surface at all, and `x-periskop-session` is
//! honoured from whoever sends it. On loopback that is exactly right, because the
//! only sender is the user themselves. On `0.0.0.0` the same code hands any host
//! on the network another user's alias scope. The listening default is where that
//! assumption is either kept or quietly broken, so it is enforced here rather than
//! documented somewhere a deployment guide could contradict.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// The port `proxy/spec.md` section 2.1 puts in the two `base_url` lines an
/// operator copies.
pub const DEFAULT_PORT: u16 = 8787;

/// Whether the operator has said, explicitly, that a non loopback bind is meant.
///
/// A two variant type rather than a `bool` parameter: `listen(address, true)` at a
/// call site says nothing about what the `true` permits, and this decision is one
/// that has to be readable at the place it is taken.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Exposure {
    /// The default. Only loopback addresses are accepted.
    #[default]
    LoopbackOnly,
    /// The operator asked for a reachable interface and accepted what that means.
    ExternalInterfaceAllowed,
}

/// Why an address was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenRefusal {
    /// The text is not `host:port`.
    Unparsable { given: String },
    /// A routable address without [`Exposure::ExternalInterfaceAllowed`].
    ExternalWithoutConsent { given: SocketAddr },
}

impl fmt::Display for ListenRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unparsable { given } => {
                write!(f, "`{given}` is not an address of the form host:port")
            }
            Self::ExternalWithoutConsent { given } => write!(
                f,
                "refusing to listen on {given}: it is reachable from outside this \
                 host, and this build has no per-caller authorisation on the proxy \
                 surface (F4 is a single tenant, local deployment). Pass the \
                 external interface option if that is really what is wanted"
            ),
        }
    }
}

/// A bind address that has been through the rule above.
///
/// Constructed only by [`ListenAddress::loopback`] and [`ListenAddress::parse`],
/// so a `ListenAddress` in hand is an address somebody was allowed to bind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenAddress(SocketAddr);

impl Default for ListenAddress {
    fn default() -> Self {
        Self::loopback()
    }
}

impl ListenAddress {
    /// The default: `127.0.0.1:8787`.
    pub const fn loopback() -> Self {
        Self(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            DEFAULT_PORT,
        ))
    }

    /// Reads an operator supplied address, refusing a reachable one unless the
    /// operator also said they meant it.
    ///
    /// The unspecified address (`0.0.0.0`, `[::]`) is treated as external, which
    /// it is: it binds every interface the host has, including the loopback one,
    /// and "it includes loopback" is how a default like that gets defended.
    pub fn parse(text: &str, exposure: Exposure) -> Result<Self, ListenRefusal> {
        let address: SocketAddr = text.parse().map_err(|_| ListenRefusal::Unparsable {
            given: text.to_owned(),
        })?;
        Self::checked(address, exposure)
    }

    /// The rule itself, over an address that is already parsed.
    pub fn checked(address: SocketAddr, exposure: Exposure) -> Result<Self, ListenRefusal> {
        if is_loopback(&address) || exposure == Exposure::ExternalInterfaceAllowed {
            return Ok(Self(address));
        }
        Err(ListenRefusal::ExternalWithoutConsent { given: address })
    }

    pub const fn socket_addr(self) -> SocketAddr {
        self.0
    }

    /// Whether this address is only reachable from this host.
    pub fn is_loopback(self) -> bool {
        is_loopback(&self.0)
    }
}

impl fmt::Display for ListenAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Loopback, and nothing that merely looks like it.
///
/// `Ipv4Addr::is_loopback` is the whole of `127.0.0.0/8` and `Ipv6Addr::is_loopback`
/// is `::1`. The unspecified address is excluded on purpose: it is not a loopback
/// address, it is every address.
fn is_loopback(address: &SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The default is on the loopback interface, asserted as an address rather
    /// than as a property.
    ///
    /// Written as the literal `127.0.0.1:8787` on purpose. Asserting
    /// `default().is_loopback()` would pass for `[::1]`, and asserting a property
    /// computed by the same function that produced the value is the shape of test
    /// that survives the mutation it exists to catch. This one does not: change
    /// [`ListenAddress::loopback`] to the unspecified address and this line is the
    /// first thing that goes red.
    #[test]
    fn the_default_bind_address_is_localhost() {
        assert_eq!(
            ListenAddress::default().socket_addr(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8787)
        );
        assert_eq!(ListenAddress::default(), ListenAddress::loopback());
        assert_eq!(ListenAddress::default().to_string(), "127.0.0.1:8787");
        // And the default exposure is the restrictive one, so that a build which
        // kept the address but flipped the consent is caught too.
        assert_eq!(Exposure::default(), Exposure::LoopbackOnly);
    }

    #[test]
    fn every_interface_is_refused_without_an_explicit_choice() {
        for text in [
            "0.0.0.0:8787",
            "[::]:8787",
            "192.168.1.20:8787",
            "[2001:db8::1]:8787",
        ] {
            let refusal = ListenAddress::parse(text, Exposure::LoopbackOnly)
                .expect_err(&format!("{text} was accepted on the default exposure"));
            assert!(
                matches!(refusal, ListenRefusal::ExternalWithoutConsent { .. }),
                "{text}: {refusal:?}"
            );
            // The message has to name the address, or an operator reading it
            // cannot tell which of several configured listeners was refused.
            assert!(
                refusal
                    .to_string()
                    .contains(text.trim_start_matches('[').trim_end_matches(":8787"))
                    || refusal.to_string().contains(text),
                "{refusal}"
            );
        }
    }

    #[test]
    fn a_loopback_address_needs_no_consent_and_an_external_one_is_taken_when_given() {
        for text in ["127.0.0.1:8787", "127.0.0.5:9000", "[::1]:8787"] {
            let bound = ListenAddress::parse(text, Exposure::LoopbackOnly)
                .unwrap_or_else(|refusal| panic!("{text}: {refusal}"));
            assert!(bound.is_loopback(), "{text}");
        }

        let external = ListenAddress::parse("0.0.0.0:8787", Exposure::ExternalInterfaceAllowed)
            .unwrap_or_else(|refusal| panic!("{refusal}"));
        assert!(!external.is_loopback());
        assert_eq!(external.to_string(), "0.0.0.0:8787");
    }

    #[test]
    fn an_address_that_is_not_an_address_is_refused_rather_than_defaulted() {
        // Falling back to the default here would be the failure mode this whole
        // module exists to avoid, in reverse: an operator who typed a reachable
        // address with a typo would get a listener they did not ask for and would
        // read the log line as confirmation that their address was taken.
        for text in ["", "8787", "localhost:8787", "127.0.0.1", "127.0.0.1:99999"] {
            assert_eq!(
                ListenAddress::parse(text, Exposure::ExternalInterfaceAllowed),
                Err(ListenRefusal::Unparsable {
                    given: text.to_owned()
                }),
                "{text}"
            );
        }
    }
}
