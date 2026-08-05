//! Where a forwarded request is allowed to go.
//!
//! `threat-model.md` names SSRF by its cause: "`base_url` yönlendirmesi". The proxy
//! takes a target out of configuration and connects to it while holding the
//! client's provider credential and the decrypted contents of the request. A
//! target nobody vetted turns the component that exists to stop egress into the
//! most convenient egress channel on the machine, and it does it with the
//! organisation's own API key attached.
//!
//! So the destination is decided here, from an allow list, before anything is
//! sent, and the rules are deliberately strict rather than clever:
//!
//! - the host must be on the list **exactly**; no suffix matching, because
//!   `api.openai.com.attacker.example` ends with the string an operator would have
//!   written;
//! - the scheme must be `https`, with one named exception for a loopback host that
//!   is itself on the list, which is the only shape a local recorded upstream can
//!   take;
//! - a URL carrying userinfo is refused outright: `https://api.openai.com@evil.example`
//!   is read by a human as the first host and by a parser as the second;
//! - redirects are never followed, so a permitted host cannot hand the request on
//!   to one that is not.

use std::collections::BTreeSet;

use super::errors::{ProxyError, Refusal};
use super::route::Provider;

/// The providers a stock build talks to.
///
/// Two entries, matching the two `base_url` lines in `proxy/spec.md` section 2.1.
/// An organisation with a gateway of its own adds it here rather than the proxy
/// learning to trust whatever it is pointed at.
const SHIPPED: &[&str] = &["api.openai.com", "api.anthropic.com"];

/// The hosts this build may connect to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowList {
    hosts: BTreeSet<String>,
}

impl Default for AllowList {
    fn default() -> Self {
        Self::shipped()
    }
}

impl AllowList {
    pub fn shipped() -> Self {
        Self {
            hosts: SHIPPED.iter().map(|host| (*host).to_owned()).collect(),
        }
    }

    /// An allow list an operator wrote. Empty means nothing is permitted, which is
    /// the fail closed reading: an operator who cleared the list did not mean
    /// "anything".
    pub fn of(hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            hosts: hosts
                .into_iter()
                .map(|host| host.into().to_ascii_lowercase())
                .collect(),
        }
    }

    /// Exact match on the host, lowercased.
    ///
    /// Not `ends_with`, and that is the whole function: suffix matching is how
    /// `api.openai.com.attacker.example` gets permitted by a list that names
    /// `api.openai.com`.
    pub fn permits(&self, host: &str) -> bool {
        self.hosts.contains(&host.to_ascii_lowercase())
    }

    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.hosts.iter().map(String::as_str)
    }
}

/// A vetted upstream base.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
    /// A path prefix, without a trailing slash. Usually empty.
    prefix: String,
}

impl BaseUrl {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The `Host` header value: host, and the port when it is not the default.
    pub fn authority(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{}", self.host, port),
            None => self.host.clone(),
        }
    }

    /// The absolute URL one request goes to.
    ///
    /// Built from the base and from the route table's own literal `upstream_path`,
    /// never from the client's path. The client's path decided **which** route
    /// this is, in `route::resolve`, and it does not get a second say here: that
    /// is what keeps a percent encoded traversal in a request line from becoming a
    /// different URL at the provider.
    pub fn target(&self, upstream_path: &str, query: Option<&str>) -> String {
        let mut url = format!(
            "{}://{}{}{}",
            self.scheme,
            self.authority(),
            self.prefix,
            upstream_path
        );
        if let Some(query) = query.filter(|query| !query.is_empty()) {
            url.push('?');
            url.push_str(query);
        }
        url
    }
}

/// Reads a configured base URL and checks it against the allow list.
pub fn resolve_base_url(text: &str, allow: &AllowList) -> Result<BaseUrl, Refusal> {
    let refuse = |why: String| Refusal::new(ProxyError::EndpointUnsupported, why);

    let (scheme, rest) = text
        .split_once("://")
        .ok_or_else(|| refuse(format!("`{text}` is not an absolute URL")))?;
    let scheme = scheme.to_ascii_lowercase();

    let (authority, prefix) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, ""),
    };

    // Before anything else, because everything after this reads the authority and
    // a human reads it wrongly when it carries userinfo.
    if authority.contains('@') {
        return Err(refuse(format!(
            "`{text}` carries userinfo in its authority, which names one host to a \
             reader and another to a parser"
        )));
    }
    if authority.contains('?') || authority.contains('#') {
        return Err(refuse(format!("`{text}` is not a base URL")));
    }

    let (host, port) = split_authority(authority).ok_or_else(|| {
        refuse(format!(
            "`{text}` does not have a host and an optional numeric port"
        ))
    })?;
    let host = host.to_ascii_lowercase();

    if host.is_empty() {
        return Err(refuse(format!("`{text}` has no host")));
    }

    // The allow list decision comes before the scheme decision, so that the
    // refusal an operator reads names the thing they got wrong most often.
    if !allow.permits(&host) {
        return Err(refuse(format!(
            "upstream host `{host}` is not on the allow list ({}). Refusing to \
             forward a request carrying the caller's provider credential to a host \
             nobody vetted",
            allow.hosts().collect::<Vec<&str>>().join(", ")
        )));
    }

    let loopback = is_loopback_host(&host);
    match scheme.as_str() {
        "https" => {}
        // The one exception, and it is narrow on purpose: a recorded or stubbed
        // upstream on this machine. Plaintext to anywhere else would put the
        // request body and the credential on the wire in the clear, which is the
        // failure this component exists to prevent.
        "http" if loopback => {}
        "http" => {
            return Err(refuse(format!(
                "`{text}` is plaintext to a host that is not loopback: the request \
                 body and the caller's credential would leave this machine unencrypted"
            )))
        }
        other => {
            return Err(refuse(format!(
                "`{other}` is not a scheme this proxy speaks"
            )))
        }
    }

    if prefix.contains("..") {
        return Err(refuse(format!(
            "`{text}` has a path prefix containing `..`"
        )));
    }

    Ok(BaseUrl {
        scheme,
        host,
        port,
        prefix: prefix.trim_end_matches('/').to_owned(),
    })
}

/// The default base for a provider, used when the operator configured none.
pub fn shipped_base(provider: Provider, allow: &AllowList) -> Result<BaseUrl, Refusal> {
    let host = match provider {
        Provider::OpenAi => "api.openai.com",
        Provider::Anthropic => "api.anthropic.com",
    };
    resolve_base_url(&format!("https://{host}"), allow)
}

/// Splits `host` or `host:port`, refusing anything else.
///
/// Returns `None` for a port that is not a number, rather than ignoring it: a
/// target with a malformed port is a target nobody meant.
fn split_authority(authority: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        // An IPv6 literal. Kept parseable so that the allow list check sees the
        // address rather than a string it cannot compare.
        let (address, tail) = rest.split_once(']')?;
        let port = match tail {
            "" => None,
            with_port => Some(with_port.strip_prefix(':')?.parse().ok()?),
        };
        return Some((address, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host, Some(port.parse().ok()?))),
        None => Some((authority, None)),
    }
}

/// Whether a host names this machine.
///
/// Textual, because that is what a configuration file holds. Nothing here
/// resolves a name: a proxy that trusted DNS would trust whatever answers today,
/// and the allow list would mean "hosts whose names currently point somewhere
/// acceptable" rather than "these hosts".
fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn shipped() -> AllowList {
        AllowList::shipped()
    }

    #[test]
    fn the_shipped_allow_list_is_the_two_providers_and_nothing_else() {
        let list = shipped();
        let hosts: Vec<&str> = list.hosts().collect();
        assert_eq!(hosts, vec!["api.anthropic.com", "api.openai.com"]);
    }

    /// Task 85's criterion, and the SSRF the threat model names.
    #[test]
    fn a_base_url_off_the_allow_list_is_refused() {
        for text in [
            "https://evil.example",
            "https://169.254.169.254",
            "https://10.0.0.5:8080",
            "http://localhost:9000",
            "https://metadata.google.internal/computeMetadata/v1",
        ] {
            let refusal = resolve_base_url(text, &shipped())
                .expect_err(&format!("{text} was accepted as an upstream"));
            assert_eq!(refusal.status(), 400);
            assert!(
                refusal.detail().contains("allow list"),
                "{text}: {}",
                refusal.detail()
            );
        }
    }

    /// The rule that makes the list an allow list rather than a hint.
    #[test]
    fn a_host_that_merely_ends_with_a_permitted_one_is_not_permitted() {
        for text in [
            "https://api.openai.com.attacker.example",
            "https://notapi.openai.com",
            "https://api.openai.com.evil.tld/v1",
        ] {
            assert!(
                resolve_base_url(text, &shipped()).is_err(),
                "{text} was accepted by a suffix match"
            );
        }
        // And the permitted host itself still resolves, so the strictness above is
        // not a check that refuses everything.
        assert!(resolve_base_url("https://api.openai.com", &shipped()).is_ok());
    }

    #[test]
    fn userinfo_in_the_authority_is_refused_before_the_host_is_read() {
        // `https://api.openai.com@evil.example/v1` is read by a person as the
        // provider and connected by a parser to the attacker.
        for text in [
            "https://api.openai.com@evil.example/v1",
            "https://user:secret@api.openai.com/v1",
        ] {
            let refusal =
                resolve_base_url(text, &shipped()).expect_err(&format!("{text} was accepted"));
            assert!(
                refusal.detail().contains("userinfo"),
                "{}",
                refusal.detail()
            );
        }
    }

    #[test]
    fn plaintext_is_refused_except_to_this_machine() {
        let refusal = resolve_base_url("http://api.openai.com", &shipped())
            .expect_err("plaintext to a provider was accepted");
        assert!(
            refusal.detail().contains("plaintext"),
            "{}",
            refusal.detail()
        );

        // A local stub upstream, and only when the operator put it on the list.
        let local = AllowList::of(["127.0.0.1"]);
        let base = resolve_base_url("http://127.0.0.1:9099", &local).unwrap();
        assert_eq!(base.authority(), "127.0.0.1:9099");
        assert_eq!(base.scheme(), "http");
    }

    #[test]
    fn a_scheme_this_proxy_does_not_speak_is_refused() {
        for text in [
            "file:///etc/passwd",
            "gopher://api.openai.com",
            "ftp://api.openai.com",
        ] {
            assert!(
                resolve_base_url(text, &AllowList::of(["api.openai.com", ""])).is_err(),
                "{text}"
            );
        }
    }

    #[test]
    fn an_empty_allow_list_permits_nothing() {
        // The fail closed reading of a cleared list. The alternative, treating
        // empty as "no restriction", is the configuration mistake that turns this
        // check off without anybody editing the check.
        let nothing = AllowList::of(Vec::<String>::new());
        assert!(resolve_base_url("https://api.openai.com", &nothing).is_err());
        assert!(!nothing.permits("api.openai.com"));
    }

    #[test]
    fn the_target_url_is_built_from_the_route_s_path_and_not_the_client_s() {
        let base = resolve_base_url("https://api.anthropic.com", &shipped()).unwrap();
        assert_eq!(
            base.target("/v1/messages", None),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(
            base.target("/v1/models", Some("limit=5")),
            "https://api.anthropic.com/v1/models?limit=5"
        );

        // A gateway with a prefix, which is the shape a corporate proxy takes.
        let prefixed = resolve_base_url("https://api.openai.com/gateway/", &shipped()).unwrap();
        assert_eq!(
            prefixed.target("/v1/models", None),
            "https://api.openai.com/gateway/v1/models"
        );
    }

    #[test]
    fn a_prefix_that_climbs_out_of_itself_is_refused() {
        assert!(resolve_base_url("https://api.openai.com/../admin", &shipped()).is_err());
    }

    #[test]
    fn a_malformed_port_is_refused_rather_than_dropped() {
        // Dropping it would silently connect to 443 on a host the operator meant
        // to reach on another port, which is a different service.
        assert!(resolve_base_url("https://api.openai.com:https", &shipped()).is_err());
        assert!(resolve_base_url("https://api.openai.com:99999", &shipped()).is_err());
    }

    #[test]
    fn the_shipped_base_for_each_provider_is_on_the_shipped_list() {
        assert_eq!(
            shipped_base(Provider::OpenAi, &shipped()).unwrap().host(),
            "api.openai.com"
        );
        assert_eq!(
            shipped_base(Provider::Anthropic, &shipped())
                .unwrap()
                .host(),
            "api.anthropic.com"
        );
        // And an operator who narrowed the list is not overruled by the default.
        let narrowed = AllowList::of(["api.openai.com"]);
        assert!(shipped_base(Provider::Anthropic, &narrowed).is_err());
    }
}
