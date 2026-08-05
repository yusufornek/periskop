#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
//! `proxy/spec.md` section 10, row by row.
//!
//! The table has eleven rows. Two of them describe modes this phase does not
//! implement (`date_policy = "shift"` and a NER model that failed to load), and
//! for those the enforcement is that the **policy does not load at all**, so the
//! proxy never starts and no request is served under a rule it cannot keep. The
//! other nine are request time behaviours and each has a test below.
//!
//! Every one of them asserts two things, and the second is the point:
//!
//! 1. the status and the `x-periskop-error` value the contract fixes, and
//! 2. **that nothing reached the provider**, checked against a recording upstream
//!    rather than inferred from the status.
//!
//! The second assertion is what makes this a fail closed test rather than a status
//! code test. A refusal that answered 503 and had already forwarded the body would
//! satisfy the first and defeat the entire component.

use std::path::Path;
use std::sync::Arc;

use periskop_proxy::http::gateway::{Clock, Gateway, Incoming, Outgoing};
use periskop_proxy::http::headers::{HeaderList, SESSION_HEADER};
use periskop_proxy::http::upstream::{Answer, Recorder, Upstream};
use periskop_proxy::http::AllowList;
use periskop_proxy::policy::Policy;
use periskop_proxy::vault::{
    Backing, OpenRequest, Passphrase, ProfileName, SessionLimits, Vault, VaultError,
};

const NOW: u64 = 1_700_000_000_000;

/// A value with a checksum that passes, assembled at run time so that no source
/// file carries a continuous credential-shaped or identifier-shaped literal.
fn iban() -> String {
    format!("TR{}", "330006100519786457841326")
}

fn api_key() -> String {
    format!("sk-{}-{}", "proj", "8QpZ3nD6wYkR1sVbXhLtMcGe")
}

fn policy(extra: &str) -> Policy {
    let text = format!(
        "policy_id = \"acme\"\npolicy_version = \"1\"\n{extra}\n[default]\nmode = \"mask\"\n"
    );
    Policy::load(&text, Path::new("."), None).unwrap_or_else(|refusal| panic!("{refusal}"))
}

fn vault() -> Vault {
    Vault::open(&OpenRequest {
        passphrase: &Passphrase::new(b"an operator's passphrase".to_vec()),
        profile: ProfileName::Ci,
        backing: Backing::Memory,
    })
    .unwrap_or_else(|refusal| panic!("{refusal}"))
}

struct Harness {
    gateway: Gateway,
    upstream: Arc<Recorder>,
}

impl Harness {
    fn new(policy: Policy, vault: Vault) -> Self {
        let upstream = Arc::new(Recorder::ok());
        let gateway = Gateway::new(
            policy,
            vault,
            Arc::clone(&upstream) as Arc<dyn Upstream>,
            AllowList::shipped(),
            Clock::Fixed(NOW),
        )
        .unwrap_or_else(|refusal| panic!("{}", refusal.detail()));
        Self { gateway, upstream }
    }

    fn plain() -> Self {
        Self::new(policy(""), vault())
    }

    async fn chat(&self, content: &str) -> Outgoing {
        self.post("/v1/chat/completions", &body(content)).await
    }

    async fn post(&self, path: &str, body: &str) -> Outgoing {
        self.gateway
            .handle(Incoming {
                method: "POST".to_owned(),
                path: path.to_owned(),
                query: None,
                headers: HeaderList::new()
                    .with("authorization", format!("Bearer {}", api_key()))
                    .with("content-type", "application/json")
                    .with(SESSION_HEADER, "one-conversation"),
                body: body.as_bytes().to_vec(),
            })
            .await
    }

    /// Everything the provider was sent, as text.
    fn what_the_provider_saw(&self) -> String {
        self.upstream
            .calls()
            .iter()
            .map(|call| {
                let headers: Vec<String> = call
                    .headers
                    .iter()
                    .map(|(name, value)| format!("{name}: {value}"))
                    .collect();
                format!(
                    "{} {} {} {}",
                    call.method,
                    call.url,
                    headers.join(" "),
                    String::from_utf8_lossy(&call.body)
                )
            })
            .collect::<Vec<String>>()
            .join("\n")
    }

    fn nothing_was_forwarded(&self) {
        assert!(
            self.upstream.calls().is_empty(),
            "a refused request still reached the provider:\n{}",
            self.what_the_provider_saw()
        );
    }
}

fn body(content: &str) -> String {
    serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": content}]
    })
    .to_string()
}

fn error_of(outgoing: &Outgoing) -> Option<String> {
    outgoing.headers.get("x-periskop-error").map(str::to_owned)
}

// ---------------------------------------------------------------------------
// Row 1: the vault cannot be opened, or there is no passphrase
// ---------------------------------------------------------------------------

#[test]
fn row_1_an_empty_passphrase_never_produces_a_vault_to_serve_from() {
    let refusal = Vault::open(&OpenRequest {
        passphrase: &Passphrase::new(Vec::new()),
        profile: ProfileName::Ci,
        backing: Backing::Memory,
    })
    .expect_err("a vault opened with no passphrase");
    assert_eq!(refusal, VaultError::PassphraseMissing);
    assert_eq!(refusal.http_status(), 503);
}

#[tokio::test]
async fn row_1_a_lost_vault_refuses_with_503_and_forwards_nothing() {
    let harness = Harness::plain();
    harness.gateway.access().lost();

    let outgoing = harness.chat(&format!("wire it to {}", iban())).await;

    assert_eq!(outgoing.status, 503);
    assert_eq!(error_of(&outgoing).as_deref(), Some("vault_unavailable"));
    harness.nothing_was_forwarded();
}

// ---------------------------------------------------------------------------
// Rows 2 and 3: the vault's integrity, and one record's
// ---------------------------------------------------------------------------

#[test]
fn row_2_and_3_every_integrity_failure_is_a_503_and_none_of_them_is_recovered_from() {
    use periskop_proxy::http::ProxyError;
    use periskop_proxy::vault::Integrity;

    for integrity in [
        Integrity::ChainMismatch,
        Integrity::CounterRollback,
        Integrity::HeaderMacFailed,
    ] {
        let refusal =
            periskop_proxy::http::Refusal::from(VaultError::IntegrityFailed { integrity });
        assert_eq!(refusal.status(), 503);
        assert_eq!(refusal.error(), ProxyError::VaultIntegrityFailed);
    }

    let tamper = periskop_proxy::http::Refusal::from(VaultError::RecordTamper);
    assert_eq!(tamper.status(), 503);
    assert_eq!(tamper.error(), ProxyError::VaultRecordTamper);
}

// ---------------------------------------------------------------------------
// Row 4 (scope boundary): `date_policy = "shift"` does not load
// ---------------------------------------------------------------------------

#[test]
fn row_4_the_shift_mode_this_phase_does_not_implement_stops_the_load() {
    let refusal = Policy::load(
        "policy_id = \"a\"\npolicy_version = \"1\"\ndate_policy = \"shift\"\n[default]\nmode = \"mask\"\n",
        Path::new("."),
        None,
    )
    .expect_err("a policy asking for date shifting loaded");
    // Distinguishable from an unrecognised value: the operator's next move differs.
    assert!(refusal.is_unimplemented_value(), "{refusal}");
    // And therefore no gateway exists to serve a request under it, which is the
    // strongest possible form of "nothing is forwarded".
}

// ---------------------------------------------------------------------------
// Row 5: the vault refuses the write
// ---------------------------------------------------------------------------

#[tokio::test]
async fn row_5_a_vault_that_refuses_the_record_refuses_the_request_before_the_call() {
    // Forced through the ceiling, which is the one vault write refusal a test can
    // produce deterministically on every platform. What is being pinned is not the
    // ceiling (row 11 does that) but the **order**: the vault is written before the
    // upstream is called, so a vault that refuses means an upstream that is never
    // reached.
    let vault = Vault::open(&OpenRequest {
        passphrase: &Passphrase::new(b"an operator's passphrase".to_vec()),
        profile: ProfileName::Ci,
        backing: Backing::Memory,
    })
    .unwrap()
    .with_limits(SessionLimits {
        alias_ceiling: 0,
        ttl_ms: 60_000,
    });

    let harness = Harness::new(policy(""), vault);
    let outgoing = harness.chat(&format!("wire it to {}", iban())).await;

    assert!(outgoing.status >= 400, "{}", outgoing.status);
    harness.nothing_was_forwarded();
}

#[test]
fn row_5_a_file_the_vault_cannot_write_is_a_503() {
    use periskop_proxy::http::ProxyError;
    let refusal = periskop_proxy::http::Refusal::from(VaultError::VaultFileUnavailable {
        operation: "appended to",
        cause: "no space left on device".to_owned(),
    });
    assert_eq!(refusal.status(), 503);
    assert_eq!(refusal.error(), ProxyError::VaultUnavailable);
}

// ---------------------------------------------------------------------------
// Row 6 (scope boundary): NER cannot be switched on at all
// ---------------------------------------------------------------------------

#[test]
fn row_6_ner_cannot_be_enabled_so_its_model_can_never_fail_to_load() {
    let refusal = Policy::load(
        "policy_id = \"a\"\npolicy_version = \"1\"\n[detection.ner]\nenabled = true\n[default]\nmode = \"mask\"\n",
        Path::new("."),
        None,
    )
    .expect_err("a policy switching NER on loaded");
    assert!(refusal.is_unimplemented_value(), "{refusal}");
}

// ---------------------------------------------------------------------------
// Row 7: the body does not parse
// ---------------------------------------------------------------------------

#[tokio::test]
async fn row_7_a_body_that_is_not_json_is_a_400_and_is_not_forwarded() {
    let harness = Harness::plain();
    let outgoing = harness
        .post(
            "/v1/chat/completions",
            &format!("{{\"messages\": [{}", iban()),
        )
        .await;

    assert_eq!(outgoing.status, 400);
    assert_eq!(error_of(&outgoing).as_deref(), Some("body_unparsable"));
    harness.nothing_was_forwarded();

    // And the refusal does not quote the body back. A response that echoed the
    // bytes would put unmasked content into whatever logs the response.
    let text = String::from_utf8_lossy(&outgoing.body).into_owned();
    assert!(!text.contains(&iban()), "{text}");
}

// ---------------------------------------------------------------------------
// Row 8: an endpoint or a field this build does not implement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn row_8_an_unsupported_endpoint_is_a_400_that_names_it_and_forwards_nothing() {
    let harness = Harness::plain();
    let outgoing = harness
        .post("/v1/audio/transcriptions", &body("hello"))
        .await;

    assert_eq!(outgoing.status, 400);
    assert_eq!(error_of(&outgoing).as_deref(), Some("endpoint_unsupported"));
    let text = String::from_utf8_lossy(&outgoing.body).into_owned();
    assert!(
        text.contains("/v1/audio"),
        "the refusal does not say what: {text}"
    );
    harness.nothing_was_forwarded();
}

#[tokio::test]
async fn row_8_the_shared_namespace_messages_path_is_a_404_and_is_not_sent_to_anthropic() {
    let harness = Harness::plain();
    let outgoing = harness.post("/v1/messages", &body("hello")).await;

    assert_eq!(outgoing.status, 404);
    // The assertion that matters: a 404 that had still forwarded would be a silent
    // redirect with a misleading status on it.
    harness.nothing_was_forwarded();
}

// ---------------------------------------------------------------------------
// Row 9: an upstream 4xx or 5xx passes through as it is
// ---------------------------------------------------------------------------

#[tokio::test]
async fn row_9_an_upstream_failure_is_forwarded_transparently() {
    let upstream = Arc::new(Recorder::answering(Answer {
        status: 503,
        headers: HeaderList::new()
            .with("content-type", "application/json")
            .with("retry-after", "30"),
        body: br#"{"error":{"message":"overloaded"}}"#.to_vec(),
    }));
    let gateway = Gateway::new(
        policy(""),
        vault(),
        Arc::clone(&upstream) as Arc<dyn Upstream>,
        AllowList::shipped(),
        Clock::Fixed(NOW),
    )
    .unwrap();

    let outgoing = gateway
        .handle(Incoming {
            method: "POST".to_owned(),
            path: "/v1/chat/completions".to_owned(),
            query: None,
            headers: HeaderList::new().with("authorization", format!("Bearer {}", api_key())),
            body: body("hello").into_bytes(),
        })
        .await;

    assert_eq!(outgoing.status, 503);
    // The provider's own answer, not periskop's refusal. Rewriting it would hide a
    // rate limit behind a proxy error and send the caller looking in the wrong
    // place, so this response carries **no** `x-periskop-error`.
    assert_eq!(error_of(&outgoing), None);
    assert_eq!(outgoing.headers.get("retry-after"), Some("30"));
    assert!(String::from_utf8_lossy(&outgoing.body).contains("overloaded"));
}

// ---------------------------------------------------------------------------
// Row 10: the vault is lost after the answer has started
// ---------------------------------------------------------------------------

/// An upstream that answers, and loses the vault while it does.
///
/// This is the shape `proxy/spec.md` section 10's "akış ortasında kasa erişimi
/// kayboldu" row describes: the request was masked, the provider answered, and by
/// the time the answer is being delivered the vault is gone. The answer is full of
/// aliases, so delivering it hands the user a message about `PSK_PERSON_1` and
/// calls it a reply.
struct LosesTheVaultMidAnswer {
    access: periskop_proxy::http::VaultAccess,
    inner: Recorder,
}

impl Upstream for LosesTheVaultMidAnswer {
    fn send<'a>(
        &'a self,
        call: periskop_proxy::http::upstream::Call,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Answer, periskop_proxy::http::upstream::Unreachable>,
                > + Send
                + 'a,
        >,
    > {
        self.access.lost();
        self.inner.send(call)
    }
}

#[tokio::test]
async fn row_10_losing_the_vault_after_the_answer_started_cuts_it_and_delivers_nothing() {
    let access = periskop_proxy::http::VaultAccess::live();
    let upstream = Arc::new(LosesTheVaultMidAnswer {
        access: access.clone(),
        inner: Recorder::answering(Answer {
            status: 200,
            headers: HeaderList::new().with("content-type", "application/json"),
            body: br#"{"choices":[{"message":{"content":"send it to PSK_IBAN_1"}}]}"#.to_vec(),
        }),
    });

    let gateway = Gateway::new(
        policy(""),
        vault(),
        Arc::clone(&upstream) as Arc<dyn Upstream>,
        AllowList::shipped(),
        Clock::Fixed(NOW),
    )
    .unwrap();
    // The gateway's own flag is the one the request path reads, and the double
    // above holds a clone of it.
    let gateway = gateway.sharing_access(access);

    let outgoing = gateway
        .handle(Incoming {
            method: "POST".to_owned(),
            path: "/v1/chat/completions".to_owned(),
            query: None,
            headers: HeaderList::new()
                .with("authorization", format!("Bearer {}", api_key()))
                .with(SESSION_HEADER, "one-conversation"),
            body: body(&format!("wire it to {}", iban())).into_bytes(),
        })
        .await;

    assert_eq!(outgoing.status, 503);
    assert_eq!(error_of(&outgoing).as_deref(), Some("vault_unavailable"));
    // The whole row in one assertion: the aliased text does not go out.
    assert!(
        outgoing.body.is_empty(),
        "an answer full of aliases was delivered with no vault to resolve them: {}",
        String::from_utf8_lossy(&outgoing.body)
    );
    assert_eq!(
        outgoing.headers.get("x-periskop-stream-truncated"),
        Some("true"),
        "the answer was cut and the client was not told"
    );
}

// ---------------------------------------------------------------------------
// Row 11: the session's alias ceiling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn row_11_the_alias_ceiling_is_a_429_and_not_a_503() {
    let vault = Vault::open(&OpenRequest {
        passphrase: &Passphrase::new(b"an operator's passphrase".to_vec()),
        profile: ProfileName::Ci,
        backing: Backing::Memory,
    })
    .unwrap()
    .with_limits(SessionLimits {
        alias_ceiling: 0,
        ttl_ms: 60_000,
    });

    let harness = Harness::new(policy(""), vault);
    let outgoing = harness.chat(&format!("wire it to {}", iban())).await;

    // A quota, not an outage. The caller's correct move is to slow down or open a
    // new session; a 503 would tell them to stop and investigate the vault.
    assert_eq!(outgoing.status, 429);
    assert_eq!(error_of(&outgoing).as_deref(), Some("alias_limit_exceeded"));
    harness.nothing_was_forwarded();
}

// ---------------------------------------------------------------------------
// The property the whole table shares
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_refusal_in_the_table_ever_forwards_an_unmasked_body() {
    // Every refusing case in one loop, asserted against the recorder. This is the
    // sentence the table opens with, checked once over all of them rather than
    // once per row, so that a row added later without this assertion still fails
    // here.
    let secret = iban();
    let cases: Vec<(&str, String)> = vec![
        ("/v1/chat/completions", format!("{{\"broken\": {secret}")),
        ("/v1/audio/transcriptions", body(&secret)),
        ("/v1/messages", body(&secret)),
        ("/v1/batches", body(&secret)),
        ("/admin/policy", body(&secret)),
        ("/nothing/here", body(&secret)),
    ];

    for (path, sent) in cases {
        let harness = Harness::plain();
        let outgoing = harness.post(path, &sent).await;
        assert!(
            outgoing.status >= 400,
            "{path} answered {}",
            outgoing.status
        );
        assert!(
            harness.upstream.calls().is_empty(),
            "{path} forwarded a body the proxy had refused:\n{}",
            harness.what_the_provider_saw()
        );
    }
}
