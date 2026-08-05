#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
//! **Task 93.** Putting the values back, and the four ways that must not go wrong.
//!
//! This is F4's fourth exit criterion (`roadmap.md`): restoration failures do not
//! pass silently, and their rate is in `restore_stats`. The claims below are the
//! ones the criterion, `proxy/spec.md` section 6.2 and `threat-model.md` R5 make
//! together:
//!
//! 1. an alias becomes a value by **looking it up in the vault**, not by
//!    computing anything, and it does so even when the wire cut the alias in half;
//! 2. an alias that cannot be resolved goes back to the user **exactly as the
//!    model wrote it** and is counted; no value is invented for it, ever, and a
//!    session whose time to live has run out is the ordinary case of this;
//! 3. a string the user wrote themselves is never given somebody else's value;
//! 4. bytes are never reordered, and `usage` is forwarded as the provider sent it.
//!
//! The whole file runs against a **real vault**, because "look it up" is the
//! claim: a table stand-in would prove the plumbing and not the guarantee.

use std::path::Path;
use std::sync::Arc;

use periskop_proxy::alias::AliasStyle;
use periskop_proxy::http::gateway::{Clock, Gateway, Incoming, Outgoing};
use periskop_proxy::http::headers::{HeaderList, SESSION_HEADER};
use periskop_proxy::http::stream::automaton::Snapshot;
use periskop_proxy::http::stream::restore::SessionLookup;
use periskop_proxy::http::stream::{frame, Relay, Settings, Warning};
use periskop_proxy::http::upstream::{Answer, Call, Pending, Unreachable, Upstream};
use periskop_proxy::http::AllowList;
use periskop_proxy::policy::{HoldTimeout, Policy};
use periskop_proxy::vault::{
    AliasSeed, Backing, OpenRequest, Passphrase, ProfileName, SessionId, SessionLimits, Vault,
};

const NOW: u64 = 1_700_000_000_000;
const SESSION: SessionId = SessionId::from_bytes([0x3c; 16]);

/// A value whose checksum passes, assembled at run time so no source file in this
/// repository carries a continuous identifier-shaped literal.
fn iban() -> String {
    format!("TR{}", "330006100519786457841326")
}

fn person() -> String {
    "Zeynep Kucukates".to_owned()
}

// ---------------------------------------------------------------------------
// A vault that really holds records
// ---------------------------------------------------------------------------

fn vault(ttl_ms: u64) -> Vault {
    Vault::open(&OpenRequest {
        // The reduced profile: this file is about restoration, and spending
        // 256 MiB of Argon2id per case would slow the suite without widening it.
        passphrase: &Passphrase::new(b"an operator's passphrase".to_vec()),
        profile: ProfileName::Ci,
        backing: Backing::Memory,
    })
    .unwrap_or_else(|refusal| panic!("{refusal}"))
    .with_limits(SessionLimits {
        alias_ceiling: 10_000,
        ttl_ms,
    })
}

fn seed(byte: u8) -> AliasSeed {
    AliasSeed::from_bytes([byte; 32])
}

/// Files one alias in a real vault and returns the frozen snapshot for it.
fn filed(vault: &mut Vault, rows: &[(&str, &str)], at: u64) -> Arc<Snapshot> {
    for (index, (alias, value)) in rows.iter().enumerate() {
        vault
            .store_alias(
                &SESSION,
                seed(u8::try_from(index).unwrap_or(0) + 1),
                alias,
                value.as_bytes(),
                at,
            )
            .unwrap_or_else(|refusal| panic!("{alias}: {refusal}"));
    }
    Arc::new(Snapshot::frozen(
        rows.len() as u64,
        rows.iter().map(|(alias, _)| (*alias).to_owned()),
    ))
}

fn settings(snapshot: &Arc<Snapshot>, mode: HoldTimeout) -> Settings {
    Settings {
        snapshot: Arc::clone(snapshot),
        style: AliasStyle::TypePreserving,
        declared_l_max_session: None,
        hold_timeout_ms: 3_600_000,
        on_hold_timeout: mode,
    }
}

fn chunk(text: &str) -> Vec<u8> {
    let document = serde_json::json!({
        "choices": [{"index": 0, "delta": {"content": text}}]
    });
    format!("data: {document}\n\n").into_bytes()
}

fn delivered(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes).into_owned();
    let mut out = String::new();
    for line in text.lines() {
        let Some(payload) = line.strip_prefix("data: ") else {
            continue;
        };
        if payload.trim() == "[DONE]" {
            continue;
        }
        let Ok(document) = serde_json::from_str::<serde_json::Value>(payload) else {
            continue;
        };
        for (_, piece) in frame::text_slots(&document) {
            out.push_str(&piece);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 1. A lookup, across a cut
// ---------------------------------------------------------------------------

#[test]
fn an_alias_cut_in_half_by_the_wire_is_restored_from_the_vault() {
    let alias = "PSK_PERSON_1";
    let mut store = vault(60_000);
    let snapshot = filed(&mut store, &[(alias, &person())], NOW);

    for split in 1..alias.len() {
        let mut relay = Relay::new(&settings(&snapshot, HoldTimeout::Flush));
        let mut lookup = SessionLookup::new(&mut store, &snapshot, SESSION, NOW);
        let (head, tail) = alias.split_at(split);

        let mut out = relay.push(&chunk(&format!("Merhaba {head}")), &mut lookup, NOW);
        out.extend(relay.push(&chunk(&format!("{tail}, nasilsin?")), &mut lookup, NOW));
        out.extend(relay.finish(&mut lookup, NOW));

        assert_eq!(
            delivered(&out),
            format!("Merhaba {}, nasilsin?", person()),
            "split at {split}"
        );
        let measured = relay.measured();
        assert_eq!(measured.restore.aliases_seen_in_response, 1);
        assert_eq!(measured.restore.aliases_restored, 1);
        assert_eq!(measured.restore.aliases_leaked, 0);
        assert!(measured.warnings().is_empty());
    }
}

// ---------------------------------------------------------------------------
// 2. `masking_unresolved`: raw, counted, never invented
// ---------------------------------------------------------------------------

#[test]
fn a_session_whose_time_to_live_ran_out_forwards_the_alias_raw_and_warns() {
    let alias = "PSK_PERSON_1";
    let mut store = vault(1_000);
    let snapshot = filed(&mut store, &[(alias, &person())], NOW);

    // Long after the conversation was forgotten.
    let later = NOW + 5_000;
    let mut relay = Relay::new(&settings(&snapshot, HoldTimeout::Flush));
    let mut lookup = SessionLookup::new(&mut store, &snapshot, SESSION, later);
    let mut out = relay.push(&chunk(&format!("Merhaba {alias}.")), &mut lookup, later);
    out.extend(relay.finish(&mut lookup, later));

    assert_eq!(delivered(&out), format!("Merhaba {alias}."));
    assert!(
        !String::from_utf8_lossy(&out).contains(&person()),
        "an expired session produced a value anyway"
    );
    let measured = relay.measured();
    assert_eq!(measured.restore.aliases_seen_in_response, 1);
    assert_eq!(measured.restore.aliases_restored, 0);
    assert_eq!(measured.restore.aliases_leaked, 1);
    assert_eq!(measured.warnings(), vec![Warning::AliasesLeaked]);
}

#[test]
fn a_session_this_process_never_saw_invents_nothing() {
    // The restart case (`vault_memory_restart`) and the "model garbled the alias"
    // case land in the same place, and the same place is: hand it back untouched.
    let alias = "PSK_IBAN_1";
    let mut store = vault(60_000);
    let snapshot = Arc::new(Snapshot::frozen(1, [alias.to_owned()]));

    let mut relay = Relay::new(&settings(&snapshot, HoldTimeout::Flush));
    let mut lookup = SessionLookup::new(&mut store, &snapshot, SESSION, NOW);
    let mut out = relay.push(&chunk(&format!("wire it to {alias}")), &mut lookup, NOW);
    out.extend(relay.finish(&mut lookup, NOW));

    assert_eq!(delivered(&out), format!("wire it to {alias}"));
    assert_eq!(relay.measured().restore.aliases_leaked, 1);
}

#[test]
fn the_leak_rate_is_a_ratio_the_record_can_report() {
    // Exit criterion 4 says the **rate** is in `restore_stats`, so the three
    // counters have to add up. A build that counted only failures would report a
    // rate of one whatever happened.
    let mut store = vault(60_000);
    let _ = filed(
        &mut store,
        &[("PSK_PERSON_1", &person()), ("PSK_IBAN_1", &iban())],
        NOW,
    );
    // A third alias the session issued and the vault does not hold: the shape of
    // the torn append in KG-021, and of a model that garbled one it was given.
    let snapshot = Arc::new(Snapshot::frozen(
        3,
        [
            "PSK_PERSON_1".to_owned(),
            "PSK_IBAN_1".to_owned(),
            "PSK_PERSON_2".to_owned(),
        ],
    ));

    let mut relay = Relay::new(&settings(&snapshot, HoldTimeout::Flush));
    let mut lookup = SessionLookup::new(&mut store, &snapshot, SESSION, NOW);
    let mut out = relay.push(
        &chunk("PSK_PERSON_1 and PSK_IBAN_1 and PSK_PERSON_2"),
        &mut lookup,
        NOW,
    );
    out.extend(relay.finish(&mut lookup, NOW));

    let stats = relay.measured().restore;
    assert_eq!(stats.aliases_seen_in_response, 3);
    assert_eq!(stats.aliases_restored, 2);
    assert_eq!(stats.aliases_leaked, 1);
    assert_eq!(
        stats.aliases_restored + stats.aliases_leaked,
        stats.aliases_seen_in_response,
        "the counters do not add up, so no rate can be read off them"
    );
}

// ---------------------------------------------------------------------------
// 3. The user's own literal
// ---------------------------------------------------------------------------

#[test]
fn a_literal_the_user_wrote_is_never_given_another_value() {
    // F4-D established this on the request path: a `PSK_` shaped string the user
    // typed is withheld, so no value is minted under it. On the response path the
    // consequence is that it is not in the frozen snapshot, so the model echoing
    // it back gets the user's own string and not a stranger's data.
    let mut store = vault(60_000);
    let issued = filed(&mut store, &[("PSK_PERSON_1", &person())], NOW);

    let mut relay = Relay::new(&settings(&issued, HoldTimeout::Flush));
    let mut lookup = SessionLookup::new(&mut store, &issued, SESSION, NOW);
    let mut out = relay.push(
        &chunk("you asked about PSK_PERSON_2 and PSK_PERSON_1"),
        &mut lookup,
        NOW,
    );
    out.extend(relay.finish(&mut lookup, NOW));

    let text = delivered(&out);
    assert_eq!(
        text,
        format!("you asked about PSK_PERSON_2 and {}", person())
    );
    assert_eq!(
        relay.measured().restore.aliases_seen_in_response,
        1,
        "a string this session never issued was counted as an alias"
    );
}

// ---------------------------------------------------------------------------
// 4. Order, and the provider's own numbers
// ---------------------------------------------------------------------------

#[test]
fn nothing_is_reordered_however_the_stream_is_cut() {
    let mut store = vault(60_000);
    let snapshot = filed(
        &mut store,
        &[("PSK_PERSON_1", &person()), ("PSK_IBAN_1", &iban())],
        NOW,
    );
    let script = "first PSK_IBAN_1 then PSK_PERSON_1 last";
    let expected = format!("first {} then {} last", iban(), person());

    for width in 1..12usize {
        let mut relay = Relay::new(&settings(&snapshot, HoldTimeout::Flush));
        let mut lookup = SessionLookup::new(&mut store, &snapshot, SESSION, NOW);
        let mut out = Vec::new();
        let mut at = 0usize;
        while at < script.len() {
            let mut end = (at + width).min(script.len());
            while !script.is_char_boundary(end) {
                end += 1;
            }
            out.extend(relay.push(&chunk(&script[at..end]), &mut lookup, NOW));
            at = end;
        }
        out.extend(relay.finish(&mut lookup, NOW));
        assert_eq!(delivered(&out), expected, "cut every {width} bytes");
    }
}

// ---------------------------------------------------------------------------
// The whole gateway, end to end
// ---------------------------------------------------------------------------

/// An upstream that reads the alias out of the request and answers with it split
/// across two server sent events.
///
/// The split is where the risk is: an upstream that answered with the alias whole
/// would exercise none of the buffer.
struct SplitsTheAliasAcrossFrames {
    at: usize,
    streaming: bool,
}

impl Upstream for SplitsTheAliasAcrossFrames {
    fn send(&self, call: Call) -> Pending<'_> {
        let body: serde_json::Value =
            serde_json::from_slice(&call.body).expect("the masked body is JSON");
        let sent = body["messages"][0]["content"]
            .as_str()
            .expect("a masked message")
            .to_owned();
        let alias = sent
            .split_whitespace()
            .last()
            .expect("something was masked")
            .to_owned();
        assert!(
            !sent.contains(&iban()),
            "the original crossed to the provider: {sent}"
        );
        let at = self.at.min(alias.len().saturating_sub(1)).max(1);
        let (head, tail) = alias.split_at(at);

        let answer = if self.streaming {
            Answer::in_pieces(
                200,
                HeaderList::new().with("content-type", "text/event-stream"),
                vec![
                    chunk("Havale "),
                    chunk(head),
                    chunk(&format!("{tail} hesabina gonderildi.")),
                    b"data: [DONE]\n\n".to_vec(),
                ],
            )
        } else {
            let document = serde_json::json!({
                "choices": [{"message": {"content": format!("Havale {alias} hesabina.")}}],
                "usage": {"prompt_tokens": 41, "completion_tokens": 9, "total_tokens": 50}
            });
            Answer::whole(
                200,
                HeaderList::new().with("content-type", "application/json"),
                document.to_string().into_bytes(),
            )
        };
        Box::pin(async move { Ok::<Answer, Unreachable>(answer) })
    }
}

fn gateway(upstream: Arc<dyn Upstream>) -> Gateway {
    let policy = Policy::load(
        "policy_id = \"acme\"\npolicy_version = \"1\"\n[default]\nmode = \"mask\"\n",
        Path::new("."),
        None,
    )
    .unwrap_or_else(|refusal| panic!("{refusal}"));
    Gateway::new(
        policy,
        vault(24 * 60 * 60 * 1_000),
        upstream,
        AllowList::shipped(),
        Clock::Fixed(NOW),
    )
    .unwrap_or_else(|refusal| panic!("{}", refusal.detail()))
}

async fn ask(gateway: &Gateway) -> Outgoing {
    let body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": format!("wire it to {}", iban())}]
    });
    gateway
        .handle(Incoming {
            method: "POST".to_owned(),
            path: "/v1/chat/completions".to_owned(),
            query: None,
            headers: HeaderList::new().with(SESSION_HEADER, "one-conversation"),
            body: body.to_string().into_bytes(),
        })
        .await
}

#[tokio::test]
async fn the_client_gets_its_own_value_back_out_of_a_split_stream() {
    for at in 1..8usize {
        let upstream = Arc::new(SplitsTheAliasAcrossFrames {
            at,
            streaming: true,
        });
        let gateway = gateway(Arc::clone(&upstream) as Arc<dyn Upstream>);
        let answer = ask(&gateway).await;

        assert_eq!(answer.status, 200);
        let text = delivered(&answer.body);
        assert_eq!(
            text,
            format!("Havale {} hesabina gonderildi.", iban()),
            "split at {at}"
        );

        let record = gateway.log().pop().expect("one request was recorded");
        assert_eq!(record.measured.restore.aliases_restored, 1, "split at {at}");
        assert_eq!(record.measured.restore.aliases_leaked, 0, "split at {at}");
        assert_eq!(
            record.measured.stream.partial_alias_flushed, 0,
            "split at {at}"
        );
        assert!(record.warnings().is_empty(), "split at {at}");
        assert!(
            !record.to_line().contains(&iban()),
            "the value reached the record: {}",
            record.to_line()
        );
        assert_eq!(
            answer.headers.get("x-periskop-stream-truncated"),
            None,
            "a complete stream was marked truncated"
        );
    }
}

/// An upstream that streams the masked prompt back, cut every three bytes.
///
/// The cuts land inside aliases and inside the literal the user wrote, which is
/// the only way to exercise both halves of the invariant at once.
struct EchoesTheMaskedPromptInSmallPieces;

impl Upstream for EchoesTheMaskedPromptInSmallPieces {
    fn send(&self, call: Call) -> Pending<'_> {
        let body: serde_json::Value =
            serde_json::from_slice(&call.body).expect("the masked body is JSON");
        let masked = body["messages"][0]["content"]
            .as_str()
            .expect("a masked message")
            .to_owned();
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut at = 0usize;
        while at < masked.len() {
            let mut end = (at + 3).min(masked.len());
            while !masked.is_char_boundary(end) {
                end += 1;
            }
            chunks.push(chunk(&masked[at..end]));
            at = end;
        }
        chunks.push(b"data: [DONE]\n\n".to_vec());
        let answer = Answer::in_pieces(
            200,
            HeaderList::new().with("content-type", "text/event-stream"),
            chunks,
        );
        Box::pin(async move { Ok::<Answer, Unreachable>(answer) })
    }
}

#[tokio::test]
async fn an_alias_shaped_string_the_user_typed_comes_back_as_the_user_typed_it() {
    // The F4-D invariant, end to end and through the stream. The user writes
    // `PSK_PERSON_9` themselves; the minter withholds it, so no value is ever
    // given that name, so the frozen set does not hold it, so the model echoing
    // it back gets the user's own string. A build that put withheld literals in
    // the set would answer with somebody else's data here.
    let upstream = Arc::new(EchoesTheMaskedPromptInSmallPieces);
    let gateway = gateway(Arc::clone(&upstream) as Arc<dyn Upstream>);

    let body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{
            "role": "user",
            "content": format!("PSK_PERSON_9 asked about {}", iban())
        }]
    });
    let answer = gateway
        .handle(Incoming {
            method: "POST".to_owned(),
            path: "/v1/chat/completions".to_owned(),
            query: None,
            headers: HeaderList::new().with(SESSION_HEADER, "one-conversation"),
            body: body.to_string().into_bytes(),
        })
        .await;

    let text = delivered(&answer.body);
    assert_eq!(
        text,
        format!("PSK_PERSON_9 asked about {}", iban()),
        "the user's own literal was rewritten, or their value was not restored"
    );
    let record = gateway.log().pop().expect("one request was recorded");
    assert_eq!(
        record.measured.restore.aliases_seen_in_response, 1,
        "the withheld literal was counted as one of this conversation's aliases"
    );
    assert_eq!(record.measured.restore.aliases_restored, 1);
    assert_eq!(record.measured.stream.partial_alias_flushed, 0);
}

#[tokio::test]
async fn a_buffered_answer_keeps_the_provider_s_own_token_counts() {
    let upstream = Arc::new(SplitsTheAliasAcrossFrames {
        at: 3,
        streaming: false,
    });
    let gateway = gateway(Arc::clone(&upstream) as Arc<dyn Upstream>);
    let answer = ask(&gateway).await;

    let document: serde_json::Value =
        serde_json::from_slice(&answer.body).expect("the answer is JSON");
    assert_eq!(
        document["choices"][0]["message"]["content"],
        serde_json::Value::String(format!("Havale {} hesabina.", iban()))
    );
    // Forwarded, never recomputed: the replacement changed the length of the
    // text, so a recount would be a number periskop made up.
    assert_eq!(document["usage"]["prompt_tokens"], 41);
    assert_eq!(document["usage"]["completion_tokens"], 9);
    assert_eq!(document["usage"]["total_tokens"], 50);

    let record = gateway.log().pop().expect("one request was recorded");
    assert_eq!(record.measured.restore.aliases_restored, 1);
}
