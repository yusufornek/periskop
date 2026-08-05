//! What crosses each way in a header, and what does not.
//!
//! `threat-model.md`'s proxy paragraph names header redaction as a **mandatory,
//! tested** mitigation, and the reason is that the proxy sits between two parties
//! that hold different things about the user. Upstream is untrusted (GS-0): it may
//! not learn the alias scope, because the session identifier is the salt every
//! alias in the conversation was derived under, and it is therefore the join key
//! that makes two masked prompts linkable again. Downstream is the user's own
//! process, but the bytes reaching it were written by the untrusted side, so a
//! provider must not be able to author a `x-periskop-*` header and have the client
//! read it as something periskop said.
//!
//! Two asymmetries follow, and both are deliberate:
//!
//! | | to the provider | to the client |
//! |---|---|---|
//! | `authorization`, `x-api-key` | **unchanged** (`proxy/spec.md` section 2.3) | dropped |
//! | `x-periskop-*` from the other side | dropped | dropped, then written by us |
//! | `x-periskop-alias-scope` | never | always (`proxy-api.md` header table) |
//! | `accept-encoding` | **replaced** by `identity` | the client's own, untouched |
//!
//! The credential going up unchanged is not an oversight either: authentication is
//! explicitly not periskop's business, and a proxy that rewrote the header would be
//! a proxy that has to hold a key. It goes up untouched and is dropped on the way
//! back, because a provider that echoed it would be reflecting a credential into a
//! response body's neighbourhood for no reason anybody wants.
//!
//! The fourth row is the one thing here that is neither a redaction nor a
//! forwarding, and [`CONTENT_CODING_NEGOTIATION`] says why: this proxy has to read
//! the answer to put the conversation's values back into it, so the coding of that
//! answer is not the client's to negotiate.

use std::collections::BTreeSet;

use crate::detect::DegradedReason;

use super::errors::ProxyError;

/// Headers hop-by-hop by definition (RFC 9110 section 7.6.1).
///
/// They describe **this** connection, so forwarding one describes the wrong
/// connection to the wrong party. `content-length` and `host` are here for a
/// different reason: masking changes the body's length and the upstream is a
/// different host, so both are recomputed rather than copied.
const CONNECTION_SCOPED: &[&str] = &[
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Headers that carry a credential and must not travel back to the client.
///
/// `proxy-authorization` is in [`CONNECTION_SCOPED`] already; the rest are here
/// because an upstream is free to put anything in a response, and a reflected
/// `authorization` is a credential in a place nothing expects to find one.
const CREDENTIAL_BEARING: &[&str] = &[
    "authorization",
    "api-key",
    "x-api-key",
    "x-goog-api-key",
    "cookie",
    "set-cookie",
];

/// periskop's own header namespace.
const OURS: &str = "x-periskop-";

/// The content coding negotiation, which this proxy does on its own behalf.
///
/// It is not the client's to conduct, and that is a consequence of what the
/// response path is for. Putting a conversation's values back into an answer means
/// **reading** the answer, and a `gzip` body is bytes with no aliases visible in
/// them: the walk finds nothing, forwards the coded bytes whole, and the user
/// reads `PSK_EMAIL_1` while `restore_stats.aliases_leaked` says zero. The one
/// counter that exists to report an unrestored alias reports a clean run, which is
/// the silent failure this component exists to make impossible.
///
/// Deleting the header would be worse than leaving it: RFC 9110 section 12.5.3
/// says an absent `Accept-Encoding` means **any** coding is acceptable, so
/// stripping it invites exactly the answer it was meant to prevent. It is replaced
/// by [`READABLE_CODING`] instead, which is the same section's way of saying "no
/// coding".
const CONTENT_CODING_NEGOTIATION: &str = "accept-encoding";

/// The only content coding this build can read.
///
/// `identity` rather than a list, because every entry in such a list would be a
/// decoder this crate does not have and a promise the response path could not
/// keep.
pub const READABLE_CODING: &str = "identity";

/// The client header that names the conversation (`proxy/spec.md` section 2.4
/// step 1).
pub const SESSION_HEADER: &str = "x-periskop-session";

/// The `/admin/*` version declaration (`proxy-api.md`, "Sürüm ve uyumluluk").
pub const API_VERSION: &str = "1.0";

/// A header list, names lowercased.
///
/// Lowercased at construction because HTTP field names are case insensitive and
/// every rule in this module is a name comparison: a redaction that missed
/// `Authorization` because it looked for `authorization` would be a redaction
/// that a client bypasses by pressing shift.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeaderList(Vec<(String, String)>);

impl HeaderList {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, name: &str, value: impl Into<String>) {
        self.0.push((name.to_ascii_lowercase(), value.into()));
    }

    pub fn with(mut self, name: &str, value: impl Into<String>) -> Self {
        self.push(name, value);
        self
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let wanted = name.to_ascii_lowercase();
        self.0
            .iter()
            .find(|(held, _)| *held == wanted)
            .map(|(_, value)| value.as_str())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Every name in this list, for assertions over the set rather than over a
    /// remembered example.
    pub fn names(&self) -> Vec<&str> {
        self.0.iter().map(|(name, _)| name.as_str()).collect()
    }
}

/// The names a `Connection:` header nominates for removal.
///
/// RFC 9110 lets a hop list its own single-hop headers there, and honouring it is
/// not politeness: a client that writes `Connection: x-api-key` is asking this hop
/// to strip the credential, and a proxy that ignored it would forward a header the
/// sender explicitly scoped to this connection.
fn connection_options(headers: &HeaderList) -> BTreeSet<String> {
    let mut named = BTreeSet::new();
    for (name, value) in headers.iter() {
        if name != "connection" {
            continue;
        }
        for option in value.split(',') {
            let option = option.trim().to_ascii_lowercase();
            if !option.is_empty() {
                named.insert(option);
            }
        }
    }
    named
}

/// The headers that go to the provider.
///
/// A deny list rather than an allow list, and that choice is load bearing in both
/// directions. `proxy-api.md`'s versioning section says the proxy forwards fields
/// it has never seen, because the provider's schema is not periskop's to freeze; an
/// allow list would silently drop next month's `anthropic-beta` and turn a
/// transparent proxy into one that breaks features nobody has heard of yet. The
/// deny list is small and every entry names something periskop knows the provider
/// must not receive.
pub fn to_upstream(client: &HeaderList, upstream_host: &str) -> HeaderList {
    let nominated = connection_options(client);
    let mut out = HeaderList::new();
    // Recomputed, never copied: this is a different connection to a different
    // host, and after masking it is a different body length.
    out.push("host", upstream_host);
    // Stated once, whatever the client wrote, because the client is negotiating a
    // representation for a hop it is not the far end of: this proxy has to read
    // the answer to put the conversation's values back into it.
    out.push(CONTENT_CODING_NEGOTIATION, READABLE_CODING);

    for (name, value) in client.iter() {
        if CONNECTION_SCOPED.contains(&name) || nominated.contains(name) {
            continue;
        }
        // Dropped here so the declaration above is the only one on the wire. Two
        // `Accept-Encoding` fields are one comma separated list per RFC 9110
        // section 5.2, so keeping the client's would put `gzip` back into the
        // value periskop just narrowed.
        if name == CONTENT_CODING_NEGOTIATION {
            continue;
        }
        // periskop's own namespace never crosses GS-0. `x-periskop-session` is the
        // whole reason: it is the alias scope, and the provider holding it can
        // join two conversations that were deliberately derived apart (ADR-007's
        // per session key). The rest of the namespace is excluded with it so that
        // a client cannot hand the provider a forged `x-periskop-degraded` and
        // have it come back looking like ours.
        if name.starts_with(OURS) {
            continue;
        }
        out.push(name, value);
    }
    out
}

/// What periskop itself says on a response (`proxy-api.md`'s single normative
/// header table).
///
/// Every field is a counter, an identifier or a value from a closed vocabulary.
/// There is no field here that can hold a masked value or its original, which is
/// the table's own closing sentence turned into a type.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Marks {
    /// `x-periskop-masked-entities`.
    pub masked_entities: u32,
    /// `x-periskop-policy-id`.
    pub policy_id: String,
    /// `x-periskop-alias-scope`: the session identifier, opaque.
    pub alias_scope: String,
    /// `x-periskop-degraded`, comma separated, sorted and deduplicated.
    pub degraded: Vec<DegradedReason>,
    /// `x-periskop-stream-truncated`, only ever the string `true`.
    pub stream_truncated: bool,
    /// `x-periskop-error`, only on a fail closed refusal.
    pub error: Option<ProxyError>,
    /// `x-periskop-api-version`, only on `/admin/*`.
    pub api_version: bool,
}

impl Marks {
    /// The header table's rows, in the table's order.
    ///
    /// `x-periskop-derived-dates` has no arm here and cannot: it is the one row
    /// the table marks **yok** for F4, because `date_policy = "shift"` is not
    /// implemented and a counter for a mode that does not run would be a zero that
    /// looks like a measurement.
    fn render(&self) -> HeaderList {
        let mut out = HeaderList::new();
        if self.masked_entities > 0 || !self.alias_scope.is_empty() {
            out.push(
                "x-periskop-masked-entities",
                self.masked_entities.to_string(),
            );
        }
        if !self.policy_id.is_empty() {
            out.push("x-periskop-policy-id", self.policy_id.clone());
        }
        if !self.alias_scope.is_empty() {
            out.push("x-periskop-alias-scope", self.alias_scope.clone());
        }
        if !self.degraded.is_empty() {
            let mut reasons: Vec<&'static str> =
                self.degraded.iter().map(|reason| reason.as_str()).collect();
            reasons.sort_unstable();
            reasons.dedup();
            out.push("x-periskop-degraded", reasons.join(","));
        }
        if self.stream_truncated {
            out.push("x-periskop-stream-truncated", "true");
        }
        if let Some(error) = self.error {
            out.push("x-periskop-error", error.as_str());
        }
        if self.api_version {
            out.push("x-periskop-api-version", API_VERSION);
        }
        out
    }
}

/// The headers that go back to the client.
///
/// The upstream's own headers first, redacted; periskop's afterwards, so that the
/// last writer of any `x-periskop-*` name is periskop. A provider that emits
/// `x-periskop-masked-entities: 9999` gets it dropped rather than merged, because a
/// count the client trusts must not be authored by the party the count is about.
pub fn to_downstream(upstream: &HeaderList, marks: &Marks) -> HeaderList {
    let nominated = connection_options(upstream);
    let mut out = HeaderList::new();

    for (name, value) in upstream.iter() {
        if CONNECTION_SCOPED.contains(&name) || nominated.contains(name) {
            continue;
        }
        if CREDENTIAL_BEARING.contains(&name) {
            continue;
        }
        if name.starts_with(OURS) {
            continue;
        }
        out.push(name, value);
    }

    for (name, value) in marks.render().iter() {
        out.push(name, value);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A credential shaped like a provider key, assembled at run time.
    ///
    /// Written out as a literal it would be a continuous match for a secret
    /// scanner, which `tests/no_credential_literals.rs` fails the build over. The
    /// rule and the reason are in that file; this is the `detect::sample` pattern
    /// it points at.
    fn api_key() -> String {
        format!("sk-{}-{}", "proj", "9RhQ2wKmT4vLbN7xZaCdEfGh")
    }

    fn client_request() -> HeaderList {
        HeaderList::new()
            .with("Authorization", format!("Bearer {}", api_key()))
            .with("X-Api-Key", api_key())
            .with("Content-Type", "application/json")
            .with("Anthropic-Version", "2023-06-01")
            .with("Accept", "text/event-stream")
            .with(SESSION_HEADER, "the-user-s-conversation-name")
            .with("Host", "127.0.0.1:8787")
            .with("Content-Length", "412")
    }

    /// `proxy/spec.md` section 2.3: the client's credential reaches the provider
    /// **unchanged**. periskop stores no key, mints no key and rewrites no key.
    #[test]
    fn the_client_s_credential_reaches_the_provider_byte_for_byte() {
        let sent = to_upstream(&client_request(), "api.openai.com");
        assert_eq!(
            sent.get("authorization").unwrap(),
            format!("Bearer {}", api_key())
        );
        assert_eq!(sent.get("x-api-key").unwrap(), api_key());
        // And the headers the provider needs to understand the request survive.
        assert_eq!(sent.get("anthropic-version").unwrap(), "2023-06-01");
        assert_eq!(sent.get("accept").unwrap(), "text/event-stream");
    }

    /// The asymmetry this module exists for.
    ///
    /// The alias scope is the HKDF salt every alias in the conversation was
    /// derived under. A provider holding it can join two prompts that ADR-007
    /// spent a per-session derivation to keep apart, so it may not cross GS-0 in
    /// any form.
    #[test]
    fn no_periskop_header_and_no_session_identity_reaches_the_provider() {
        let sent = to_upstream(&client_request(), "api.anthropic.com");
        for (name, value) in sent.iter() {
            assert!(
                !name.starts_with(OURS),
                "{name} crossed to the provider: {value}"
            );
            assert!(
                !value.contains("the-user-s-conversation-name"),
                "the session name crossed to the provider in {name}"
            );
        }
        assert!(!sent.contains(SESSION_HEADER));
    }

    #[test]
    fn a_forged_periskop_header_from_the_client_does_not_survive_either_direction() {
        let forged = HeaderList::new()
            .with("x-periskop-masked-entities", "9999")
            .with("x-periskop-error", "vault_unavailable")
            .with("x-periskop-degraded", "ner_disabled");

        assert!(to_upstream(&forged, "api.openai.com")
            .names()
            .iter()
            .all(|name| !name.starts_with(OURS)));

        // From the upstream side the same forgery is more serious: a client reads
        // these as periskop's own statement about what was masked.
        let back = to_downstream(&forged, &Marks::default());
        assert!(back.is_empty(), "{back:?}");
    }

    #[test]
    fn hop_by_hop_headers_and_the_ones_the_sender_scoped_do_not_cross() {
        let client = HeaderList::new()
            .with("Connection", "keep-alive, X-Api-Key")
            .with("Keep-Alive", "timeout=5")
            .with("Transfer-Encoding", "chunked")
            .with("Upgrade", "websocket")
            .with("X-Api-Key", api_key())
            .with("User-Agent", "openai-python/1.0");

        let sent = to_upstream(&client, "api.openai.com");
        for name in ["connection", "keep-alive", "transfer-encoding", "upgrade"] {
            assert!(!sent.contains(name), "{name} crossed");
        }
        // Nominated by the sender's own `Connection` header, so it is a header
        // scoped to the hop that ends here.
        assert!(
            !sent.contains("x-api-key"),
            "a header the sender scoped to this connection was forwarded on"
        );
        assert_eq!(sent.get("user-agent").unwrap(), "openai-python/1.0");
    }

    #[test]
    fn the_host_is_the_upstream_s_and_the_length_is_not_the_client_s() {
        let sent = to_upstream(&client_request(), "api.anthropic.com");
        assert_eq!(sent.get("host").unwrap(), "api.anthropic.com");
        // Masking changes the body's length. A copied `content-length` describes
        // the body before masking, which is a body that is not being sent.
        assert!(!sent.contains("content-length"));
    }

    /// The response side of the credential rule.
    #[test]
    fn a_credential_the_provider_echoes_does_not_reach_the_client() {
        let upstream = HeaderList::new()
            .with("Content-Type", "application/json")
            .with("Authorization", format!("Bearer {}", api_key()))
            .with("X-Api-Key", api_key())
            .with("Set-Cookie", "session=abc; HttpOnly")
            .with("x-request-id", "req_012");

        let back = to_downstream(&upstream, &Marks::default());
        let rendered = format!("{back:?}");
        assert!(
            !rendered.contains(&api_key()),
            "a credential was reflected to the client: {rendered}"
        );
        for name in ["authorization", "x-api-key", "set-cookie"] {
            assert!(!back.contains(name), "{name} reached the client");
        }
        // And the provider's ordinary headers are still there, because this is a
        // redaction and not a rewrite.
        assert_eq!(back.get("content-type").unwrap(), "application/json");
        assert_eq!(back.get("x-request-id").unwrap(), "req_012");
    }

    #[test]
    fn the_marks_are_exactly_the_rows_of_the_contract_s_table() {
        let marks = Marks {
            masked_entities: 3,
            policy_id: "org-default".to_owned(),
            alias_scope: "9f2c".to_owned(),
            degraded: vec![DegradedReason::NerDisabled, DegradedReason::NerDisabled],
            stream_truncated: true,
            error: Some(ProxyError::VaultUnavailable),
            api_version: true,
        };
        let rendered = to_downstream(&HeaderList::new(), &marks);

        assert_eq!(
            rendered.names(),
            vec![
                "x-periskop-masked-entities",
                "x-periskop-policy-id",
                "x-periskop-alias-scope",
                "x-periskop-degraded",
                "x-periskop-stream-truncated",
                "x-periskop-error",
                "x-periskop-api-version",
            ]
        );
        assert_eq!(rendered.get("x-periskop-masked-entities").unwrap(), "3");
        // Deduplicated, so the value is deterministic whatever order the reasons
        // were raised in.
        assert_eq!(rendered.get("x-periskop-degraded").unwrap(), "ner_disabled");
        assert_eq!(rendered.get("x-periskop-stream-truncated").unwrap(), "true");
        assert_eq!(rendered.get("x-periskop-api-version").unwrap(), API_VERSION);
    }

    /// The table's one **yok** row, asserted as an absence.
    #[test]
    fn no_header_outside_the_table_is_produced_and_derived_dates_is_never_one() {
        const TABLE: &[&str] = &[
            "x-periskop-masked-entities",
            "x-periskop-policy-id",
            "x-periskop-alias-scope",
            "x-periskop-api-version",
            "x-periskop-degraded",
            "x-periskop-stream-truncated",
            "x-periskop-error",
        ];

        // Every combination of the flags, so the assertion is over what the type
        // can emit rather than over one example.
        for error in [None, Some(ProxyError::AliasLimitExceeded)] {
            for truncated in [false, true] {
                for api_version in [false, true] {
                    let marks = Marks {
                        masked_entities: 1,
                        policy_id: "p".to_owned(),
                        alias_scope: "s".to_owned(),
                        degraded: DegradedReason::ALL.to_vec(),
                        stream_truncated: truncated,
                        error,
                        api_version,
                    };
                    for name in to_downstream(&HeaderList::new(), &marks).names() {
                        assert!(TABLE.contains(&name), "{name} is not in the table");
                        assert_ne!(name, "x-periskop-derived-dates");
                    }
                }
            }
        }
    }

    #[test]
    fn a_request_that_masked_nothing_still_names_its_scope_and_its_policy() {
        // Zero is a measurement, not an absence: a client that sees no
        // `x-periskop-masked-entities` cannot tell "nothing matched" from "this
        // response did not come through periskop".
        let marks = Marks {
            masked_entities: 0,
            policy_id: "org-default".to_owned(),
            alias_scope: "9f2c".to_owned(),
            ..Marks::default()
        };
        let rendered = to_downstream(&HeaderList::new(), &marks);
        assert_eq!(rendered.get("x-periskop-masked-entities").unwrap(), "0");
    }

    /// The response path can only put values back into bytes it can read.
    ///
    /// A client that asks for `gzip` gets a coded answer, the restore walk cannot
    /// parse it, and `PSK_EMAIL_1` reaches the screen while the record says
    /// `aliases_leaked: 0`. Removing the header is **not** the fix and is worse
    /// than doing nothing: RFC 9110 section 12.5.3 says an absent
    /// `Accept-Encoding` means every coding is acceptable, so a stripped header
    /// invites the coding it was meant to prevent. The negotiation is replaced
    /// rather than dropped.
    #[test]
    fn the_provider_is_asked_for_a_coding_this_proxy_can_read() {
        for asked in ["gzip, deflate, br", "gzip;q=1.0, *;q=0.5", "br"] {
            let sent = to_upstream(
                &HeaderList::new().with("Accept-Encoding", asked),
                "api.x.com",
            );
            assert_eq!(
                sent.get("accept-encoding"),
                Some("identity"),
                "the client asked for `{asked}` and the provider was allowed to answer with it"
            );
        }
        // And a client that asked for nothing still gets the declaration, because
        // silence is the permissive answer here rather than the safe one.
        let sent = to_upstream(&HeaderList::new(), "api.x.com");
        assert_eq!(sent.get("accept-encoding"), Some("identity"));
        // Exactly one, whatever the client wrote: two of these is a contradiction
        // the provider resolves however it likes.
        assert_eq!(
            to_upstream(
                &HeaderList::new()
                    .with("Accept-Encoding", "gzip")
                    .with("accept-encoding", "br"),
                "api.x.com"
            )
            .names()
            .iter()
            .filter(|name| **name == "accept-encoding")
            .count(),
            1
        );
    }

    #[test]
    fn header_names_are_matched_without_regard_to_case() {
        let shouted = HeaderList::new()
            .with("AUTHORIZATION", format!("Bearer {}", api_key()))
            .with("X-PERISKOP-SESSION", "s")
            .with("CONNECTION", "keep-alive");
        let sent = to_upstream(&shouted, "api.openai.com");
        assert!(sent.contains("authorization"));
        assert!(!sent.contains("x-periskop-session"));
        assert!(!sent.contains("connection"));
    }
}
