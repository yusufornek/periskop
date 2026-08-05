#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
//! The HTTP surface as a running component: what crosses, what does not, and what
//! is left behind.
//!
//! Three claims are made here that no unit test can make, because each one is
//! about **every** artefact a request produces rather than about one function's
//! return value:
//!
//! 1. the caller's provider credential reaches the provider unchanged and appears
//!    in no response header, no response body and no log line (task 85);
//! 2. two turns naming the same session see the same aliases, and the vault holds
//!    what the provider was told (task 86);
//! 3. `/admin/*` projects no secret, has no write method, and is served over a real
//!    socket bound where `listen.rs` says (tasks 85 and 87).

use std::path::Path;
use std::sync::Arc;

use periskop_proxy::http::gateway::{Clock, Gateway, Incoming, Outgoing};
use periskop_proxy::http::headers::{HeaderList, SESSION_HEADER};
use periskop_proxy::http::listen::{Exposure, ListenAddress};
use periskop_proxy::http::route::Provider;
use periskop_proxy::http::serve::Listener;
use periskop_proxy::http::upstream::{Recorder, Upstream};
use periskop_proxy::http::AllowList;
use periskop_proxy::policy::Policy;
use periskop_proxy::vault::{Backing, OpenRequest, Passphrase, ProfileName, Vault};

const NOW: u64 = 1_700_000_000_000;

/// Values planted in one request, hunted for afterwards on every surface.
///
/// Assembled at run time, not written out: `tests/no_credential_literals.rs` fails
/// the build over a continuous credential shaped literal in a source file, and the
/// reason is in that file. Each one is distinctive enough that a chance match in a
/// ciphertext is not a thing that happens.
fn api_key() -> String {
    format!("sk-{}-{}", "proj", "8QpZ3nD6wYkR1sVbXhLtMcGe")
}

fn iban() -> String {
    format!("TR{}", "330006100519786457841326")
}

fn email() -> String {
    format!("{}@{}", "zeynep.kucukates", "ornek-firma-a.invalid")
}

fn session_name() -> String {
    "acme-payroll-conversation".to_owned()
}

fn policy() -> Policy {
    Policy::load(
        "policy_id = \"acme\"\npolicy_version = \"1\"\n[default]\nmode = \"mask\"\n",
        Path::new("."),
        None,
    )
    .unwrap_or_else(|refusal| panic!("{refusal}"))
}

fn vault() -> Vault {
    Vault::open(&OpenRequest {
        passphrase: &Passphrase::new(b"an operator's passphrase".to_vec()),
        profile: ProfileName::Ci,
        backing: Backing::Memory,
    })
    .unwrap_or_else(|refusal| panic!("{refusal}"))
}

fn gateway(upstream: &Arc<Recorder>) -> Gateway {
    Gateway::new(
        policy(),
        vault(),
        Arc::clone(upstream) as Arc<dyn Upstream>,
        AllowList::shipped(),
        Clock::Fixed(NOW),
    )
    .unwrap_or_else(|refusal| panic!("{}", refusal.detail()))
}

fn chat(content: &str) -> Incoming {
    Incoming {
        method: "POST".to_owned(),
        path: "/v1/chat/completions".to_owned(),
        query: None,
        headers: HeaderList::new()
            .with("authorization", format!("Bearer {}", api_key()))
            .with("x-api-key", api_key())
            .with("content-type", "application/json")
            .with(SESSION_HEADER, session_name()),
        body: serde_json::json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": content}]
        })
        .to_string()
        .into_bytes(),
    }
}

fn rendered(outgoing: &Outgoing) -> String {
    let headers: Vec<String> = outgoing
        .headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}"))
        .collect();
    format!(
        "{}\n{}\n{}",
        outgoing.status,
        headers.join("\n"),
        String::from_utf8_lossy(&outgoing.body)
    )
}

// ---------------------------------------------------------------------------
// Task 85: the credential
// ---------------------------------------------------------------------------

/// The provider gets the key. Nothing else does.
///
/// `proxy/spec.md` section 2.3 is two sentences and they pull in opposite
/// directions on purpose: the credential goes upstream **unchanged**, and periskop
/// "API anahtarı saklamaz, üretmez, **günlüğe yazmaz**". This asserts both halves
/// at once, over every artefact one request produces.
#[tokio::test]
async fn the_api_key_reaches_the_provider_and_appears_on_no_other_surface() {
    let upstream = Arc::new(Recorder::ok());
    let gateway = gateway(&upstream);

    let outgoing = gateway
        .handle(chat(&format!("pay {} at {}", iban(), email())))
        .await;
    assert_eq!(outgoing.status, 200);

    // The positive control: the same search has to find the key where it belongs,
    // or the searches below are searching nothing.
    let calls = upstream.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].headers.get("authorization"),
        Some(format!("Bearer {}", api_key()).as_str()),
        "the credential did not reach the provider unchanged"
    );
    assert_eq!(calls[0].headers.get("x-api-key"), Some(api_key().as_str()));

    // And now the claim.
    let surfaces: Vec<(&str, String)> = vec![
        ("the response to the client", rendered(&outgoing)),
        (
            "the log",
            gateway
                .log()
                .iter()
                .map(periskop_proxy::http::observe::RequestRecord::to_line)
                .collect::<Vec<String>>()
                .join("\n"),
        ),
        ("the metrics", gateway.metrics_snapshot().render()),
    ];

    for (name, surface) in &surfaces {
        assert!(!surface.is_empty(), "{name} is empty, so it proves nothing");
        assert!(
            !surface.contains(&api_key()),
            "the caller's API key is on {name}:\n{surface}"
        );
        // And neither are the values the request was masking.
        for planted in [iban(), email()] {
            assert!(
                !surface.contains(&planted),
                "a masked value is on {name}:\n{surface}"
            );
        }
        // Nor the name the client gave its conversation.
        assert!(
            !surface.contains(&session_name()),
            "the client's session name is on {name}:\n{surface}"
        );
    }
}

#[tokio::test]
async fn the_masked_body_is_what_the_provider_receives() {
    let upstream = Arc::new(Recorder::ok());
    let gateway = gateway(&upstream);
    gateway
        .handle(chat(&format!("pay {} at {}", iban(), email())))
        .await;

    let calls = upstream.calls();
    let sent = String::from_utf8_lossy(&calls[0].body).into_owned();
    for planted in [iban(), email()] {
        assert!(
            !sent.contains(&planted),
            "an original value crossed: {sent}"
        );
    }
    // Two distinct values, two aliases, and the request still parses as the
    // request the client wrote.
    let parsed: serde_json::Value = serde_json::from_str(&sent).expect("the masked body is JSON");
    assert_eq!(parsed["model"], "gpt-4o");
    assert!(parsed["messages"][0]["content"]
        .as_str()
        .unwrap_or_default()
        .starts_with("pay "));

    // The session identity does not cross to the provider, and the count does come
    // back to the client.
    assert!(!calls[0].headers.contains(SESSION_HEADER));
}

#[tokio::test]
async fn the_response_declares_the_scope_the_policy_and_the_count() {
    let upstream = Arc::new(Recorder::ok());
    let gateway = gateway(&upstream);
    let outgoing = gateway
        .handle(chat(&format!("pay {} at {}", iban(), email())))
        .await;

    assert_eq!(
        outgoing.headers.get("x-periskop-masked-entities"),
        Some("2")
    );
    assert_eq!(outgoing.headers.get("x-periskop-policy-id"), Some("acme"));
    let scope = outgoing
        .headers
        .get("x-periskop-alias-scope")
        .expect("every passthrough response names its alias scope");
    assert_eq!(scope.len(), 32);
    assert!(scope.chars().all(|c| c.is_ascii_hexdigit()));
    // The build's standing declaration: no NER ran, so unlisted person names were
    // not masked. K-11 makes this true of every response this build produces.
    assert_eq!(
        outgoing.headers.get("x-periskop-degraded"),
        Some("ner_disabled")
    );
}

// ---------------------------------------------------------------------------
// Task 85: SSRF
// ---------------------------------------------------------------------------

#[test]
fn a_base_url_off_the_allow_list_is_refused_when_it_is_configured() {
    let upstream = Arc::new(Recorder::ok());
    let refusal = gateway(&upstream)
        .with_base(Provider::OpenAi, "https://attacker.example/v1")
        .err()
        .expect("a gateway was pointed at a host nobody vetted");
    assert_eq!(refusal.status(), 400);
    assert!(
        refusal.detail().contains("allow list"),
        "{}",
        refusal.detail()
    );
}

#[tokio::test]
async fn a_provider_with_no_permitted_upstream_refuses_rather_than_dialling() {
    // The operator narrowed the list to OpenAI. An Anthropic request then has no
    // vetted destination, and the answer is a refusal rather than a connection to
    // whatever the default happened to be.
    let upstream = Arc::new(Recorder::ok());
    let gateway = Gateway::new(
        policy(),
        vault(),
        Arc::clone(&upstream) as Arc<dyn Upstream>,
        AllowList::of(["api.openai.com"]),
        Clock::Fixed(NOW),
    )
    .unwrap();

    let outgoing = gateway
        .handle(Incoming {
            method: "POST".to_owned(),
            path: "/anthropic/v1/messages".to_owned(),
            query: None,
            headers: HeaderList::new().with("authorization", format!("Bearer {}", api_key())),
            body: br#"{"messages":[{"role":"user","content":"hello"}]}"#.to_vec(),
        })
        .await;

    assert_eq!(outgoing.status, 400);
    assert!(upstream.calls().is_empty());
}

// ---------------------------------------------------------------------------
// Task 86: one conversation, two turns
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_turns_naming_the_same_session_see_the_same_aliases() {
    let upstream = Arc::new(Recorder::ok());
    let gateway = gateway(&upstream);

    let first = gateway.handle(chat(&format!("pay {}", iban()))).await;
    let second = gateway
        .handle(chat(&format!("and again, pay {}", iban())))
        .await;
    assert_eq!(first.status, 200);
    assert_eq!(second.status, 200);

    let calls = upstream.calls();
    assert_eq!(calls.len(), 2);
    let alias_in = |body: &[u8]| -> String {
        let parsed: serde_json::Value = serde_json::from_slice(body).expect("JSON");
        parsed["messages"][0]["content"]
            .as_str()
            .unwrap_or_default()
            .split_whitespace()
            .last()
            .unwrap_or_default()
            .to_owned()
    };

    assert_eq!(
        alias_in(&calls[0].body),
        alias_in(&calls[1].body),
        "the same value got two names in one conversation, which is exactly what \
         makes a multi turn masked chat stop making sense"
    );
    // And the two responses name the same scope, so a client can tell.
    assert_eq!(
        first.headers.get("x-periskop-alias-scope"),
        second.headers.get("x-periskop-alias-scope")
    );
}

#[tokio::test]
async fn two_different_conversations_do_not_share_an_alias_space() {
    let upstream = Arc::new(Recorder::ok());
    let gateway = gateway(&upstream);

    // Built from scratch rather than by amending `chat`: `HeaderList::get` returns
    // the first value under a name, so appending a second session header would
    // leave the original one deciding and the test asserting nothing.
    let request = |name: &str| Incoming {
        method: "POST".to_owned(),
        path: "/v1/chat/completions".to_owned(),
        query: None,
        headers: HeaderList::new()
            .with("authorization", format!("Bearer {}", api_key()))
            .with(SESSION_HEADER, name),
        body: serde_json::json!({
            "messages": [{"role": "user", "content": format!("pay {}", iban())}]
        })
        .to_string()
        .into_bytes(),
    };

    let one = gateway.handle(request("mine")).await;
    let two = gateway.handle(request("theirs")).await;

    assert_ne!(
        one.headers.get("x-periskop-alias-scope"),
        two.headers.get("x-periskop-alias-scope"),
        "two conversations shared a scope, so a provider could join them"
    );
}

// ---------------------------------------------------------------------------
// Task 87: the administrative surface
// ---------------------------------------------------------------------------

async fn admin(gateway: &Gateway, path: &str) -> Outgoing {
    gateway
        .handle(Incoming {
            method: "GET".to_owned(),
            path: path.to_owned(),
            query: None,
            headers: HeaderList::new(),
            body: Vec::new(),
        })
        .await
}

#[tokio::test]
async fn no_admin_endpoint_projects_a_secret_and_all_of_them_declare_their_version() {
    let upstream = Arc::new(Recorder::ok());
    let gateway = gateway(&upstream);
    // Put something in the vault first, so that these endpoints are answering
    // about a vault that holds records rather than an empty one.
    gateway
        .handle(chat(&format!("pay {} at {}", iban(), email())))
        .await;

    for path in ["/admin/policy", "/admin/vault/status", "/admin/metrics"] {
        let outgoing = admin(&gateway, path).await;
        assert_eq!(outgoing.status, 200, "{path}");
        assert_eq!(
            outgoing.headers.get("x-periskop-api-version"),
            Some("1.0"),
            "{path} does not declare its version"
        );

        let text = rendered(&outgoing);
        assert!(!text.is_empty(), "{path} answered nothing");
        for planted in [iban(), email(), api_key(), session_name()] {
            assert!(
                !text.contains(&planted),
                "{path} projected something it may never carry:\n{text}"
            );
        }
        // The alias is not secret, but this endpoint has no business carrying one
        // either: a mapping needs both halves and this is the half that is easier
        // to leak.
        assert!(!text.contains("PSK_"), "{path} returned an alias:\n{text}");
    }
}

#[tokio::test]
async fn the_vault_status_endpoint_is_the_vault_s_own_projection() {
    let upstream = Arc::new(Recorder::ok());
    let gateway = gateway(&upstream);
    let outgoing = admin(&gateway, "/admin/vault/status").await;
    let body = String::from_utf8_lossy(&outgoing.body).into_owned();

    // The seven fields `VaultStatus` already closes over, served rather than
    // restated. A second renderer here would be a second place to add an eighth.
    for field in [
        "vault_state",
        "backend",
        "path",
        "aead",
        "integrity",
        "memory_locked",
        "entries_count",
    ] {
        assert!(body.contains(field), "{field} is missing from {body}");
    }
    assert!(body.contains("\"aead\":\"xchacha20poly1305\""), "{body}");
    assert!(body.contains("\"backend\":\"memory\""), "{body}");
}

#[tokio::test]
async fn there_is_no_way_to_write_a_policy_over_this_surface() {
    let upstream = Arc::new(Recorder::ok());
    let gateway = gateway(&upstream);
    let before = String::from_utf8_lossy(&admin(&gateway, "/admin/policy").await.body).into_owned();

    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        let outgoing = gateway
            .handle(Incoming {
                method: method.to_owned(),
                path: "/admin/policy".to_owned(),
                query: None,
                headers: HeaderList::new(),
                body: br#"{"policy_id":"attacker","default_mode":"allow"}"#.to_vec(),
            })
            .await;
        assert_eq!(outgoing.status, 405, "{method} /admin/policy");
    }

    let after = String::from_utf8_lossy(&admin(&gateway, "/admin/policy").await.body).into_owned();
    // The assertion that matters is not the status but that nothing moved: a write
    // endpoint that answered 405 and still applied the body would pass the first.
    assert_eq!(before, after);
}

// ---------------------------------------------------------------------------
// The socket itself
// ---------------------------------------------------------------------------

/// The server runs, on the interface `listen.rs` permits, and answers.
///
/// Bound on port 0 so that the test takes whatever is free, and on the loopback
/// address because that is the only address the default exposure allows: a test
/// that had to open the machine to the network to prove the proxy works would be
/// proving the wrong thing.
#[tokio::test]
async fn the_server_binds_loopback_and_answers_a_real_request() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = Arc::new(Recorder::ok());
    let gateway = Arc::new(gateway(&upstream));

    let address = ListenAddress::parse("127.0.0.1:0", Exposure::LoopbackOnly)
        .expect("loopback needs no consent");
    let listener = Listener::bind(address).await.expect("bound");
    let bound = listener.address();
    assert!(bound.ip().is_loopback());

    tokio::spawn(async move {
        let _serving = listener.serve(gateway).await;
    });

    let mut stream = tokio::net::TcpStream::connect(bound)
        .await
        .expect("connected");
    stream
        .write_all(
            b"GET /admin/vault/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("wrote the request");

    let mut answer = Vec::new();
    stream
        .read_to_end(&mut answer)
        .await
        .expect("read the answer");
    let text = String::from_utf8_lossy(&answer).into_owned();

    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains("x-periskop-api-version: 1.0"), "{text}");
    assert!(text.contains("\"aead\":\"xchacha20poly1305\""), "{text}");
}

#[test]
fn the_default_listen_address_is_not_reachable_from_the_network() {
    // The single tenant assumption, made concrete. There is no per-caller
    // authorisation on this surface in F4 (roadmap phase boundary item 3), so an
    // address that is reachable would hand any host on the network another user's
    // alias scope.
    assert_eq!(ListenAddress::default().to_string(), "127.0.0.1:8787");
    assert!(ListenAddress::parse("0.0.0.0:8787", Exposure::LoopbackOnly).is_err());
}
