#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The F4 proxy gate (milestone 101): one real exchange, and the five claims the
//! phase is allowed to ship on.
//!
//! F2 proved a second source sees what reading code cannot. F3 proved a third
//! source sees what neither of the first two can. F4 claims something different
//! in kind: that a value can be sent to a model without the model receiving it,
//! and given back to the user whole. Every layer under that claim already has
//! its own tests, and every one of them passes on a value that never crossed a
//! socket. So this file crosses sockets.
//!
//! # What is real here
//!
//! Everything on the path. A blocking client writes an HTTP/1.1 request into a
//! loopback socket. A real [`Gateway`] behind a real [`Listener`] answers it,
//! with the shipped `hyper-rustls` client dialling out. A stub provider on a
//! second loopback socket records the bytes it was handed and answers with a
//! chunked server sent event stream it writes chunk by chunk. The vault is a
//! real `vault.psk` on a real disk, and restoration is a lookup in it. No
//! component on the path is stubbed except the provider, and the provider is
//! stubbed because periskop may not be an egress source (CLAUDE.md's third
//! prohibition) and because a test that reached a provider would be measuring
//! whether the machine had a network and a funded key.
//!
//! # The five claims (milestone 101)
//!
//! 1. the bytes the provider **recorded** contain none of the planted values;
//! 2. every alias the provider saw satisfies the invariant of the rung it was
//!    reported on, checked on the alias that actually crossed rather than on one
//!    a unit test minted;
//! 3. the stub gives the aliases back **cut between delta events**, one
//!    character at a time, and cut again by the transport in the middle of the
//!    `data:` lines that carry them, and the client still receives the original
//!    values, whole and in order;
//! 4. `restore_stats.aliases_leaked` and `stream_stats.partial_alias_flushed`
//!    are both zero;
//! 5. no planted value appears as bytes on any surface periskop leaves behind:
//!    the vault file, every other file in the vault's directory, the event
//!    record, the request log line, the response head, or this run's own
//!    artefact. The response **body** is deliberately not one of them, because
//!    it is the answer: a gate that demanded the values be absent from it would
//!    be demanding that restoration had failed.
//!
//! # What this run does not establish, and it is written into the artefact
//!
//! No provider was reached, so nothing here says anything about how a real model
//! answers a masked prompt. There is no NER layer in this build, so a person's
//! name is masked only because an operator's word list named it, and a name
//! nobody listed crosses. Answer quality is not measured; that is milestone 96's
//! offline benchmark and, for the numbers that matter, an operator's recorded
//! session. Coverage of **every** entity type's invariant belongs to
//! `crates/periskop-proxy/tests/p0_invariants.rs`, which counts the registry;
//! this file exercises the seven types it plants and says so.
//!
//! And the kernel half of F4 is not here at all. `roadmap.md` closes F4 on two
//! gates that cannot be traded for each other: this one and
//! `proof_f4_kernel.rs`, which is a separate wave on a privileged Linux runner.
//! A reader who finds `target/f4-proof.json` saying `proved` has read half of
//! what F4 needs.
//!
//! **If this test does not pass, F4's proxy half is not closed.** A run that
//! skipped it did not close it either: `PERISKOP_REQUIRE_PROOF` turns the skip
//! into a failure and continuous integration sets it.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use periskop_proxy::alias::catalog;
use periskop_proxy::alias::checksum::{self, Verdict};
use periskop_proxy::alias::entity::{EntityType, LadderRung};
use periskop_proxy::alias::limits::l_type_max;
use periskop_proxy::alias::rung_l;
use periskop_proxy::http::gateway::{Clock, Gateway};
use periskop_proxy::http::listen::{Exposure, ListenAddress};
use periskop_proxy::http::route::Provider;
use periskop_proxy::http::serve::Listener;
use periskop_proxy::http::upstream::{RustlsUpstream, Upstream};
use periskop_proxy::http::AllowList;
use periskop_proxy::policy::Policy;
use periskop_proxy::vault::{
    Backing, CounterFloor, OpenRequest, Passphrase, ProfileName, SessionLimits, Vault,
};

/// Set in continuous integration so a machine that cannot run the gate fails it
/// rather than skipping it. The same switch, and the same reasoning, as
/// `proof.rs` and `proof_f3.rs`: a hard failure for everybody teaches people to
/// pass `--skip proof`, which removes the gate for everybody.
const REQUIRE_PROOF: &str = "PERISKOP_REQUIRE_PROOF";

/// What sits in front of every planted value in the prompt.
///
/// A fixed lead and tail rather than a label naming the type, so that the stub
/// can read the alias back out of the masked body without the marker itself
/// being something a detector might claim. Prose on both sides also means the
/// alias is never at the start or the end of a delta, which is where an off by
/// one in the hold buffer would hide.
const LEAD: &str = "Fatura ";
const TAIL: &str = " adina.\n";

/// How many bytes of the answer go into one transport chunk.
///
/// Small and not a divisor of anything, so the cuts land inside `data:` lines,
/// inside the JSON documents and inside the alias characters they carry. This is
/// the cut the **frame** parser has to survive; the cut the **hold buffer** has
/// to survive is one delta event per character, built in [`answer_for`].
const TRANSPORT_CHUNK: usize = 13;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// ---------------------------------------------------------------------------
// A throwaway directory
// ---------------------------------------------------------------------------

/// Written out rather than pulled in, matching `proof.rs` and `proof_f3.rs`: a
/// test only dependency is still a dependency decision, and this needs a few
/// lines.
struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("periskop-f4-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a temporary directory");
        Self { root }
    }

    fn write(&self, relative: &str, contents: &str) -> PathBuf {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("a parent directory");
        }
        std::fs::write(&path, contents).expect("a file");
        path
    }

    fn dir(&self, relative: &str) -> PathBuf {
        let path = self.root.join(relative);
        std::fs::create_dir_all(&path).expect("a directory");
        path
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

// ---------------------------------------------------------------------------
// What is planted
// ---------------------------------------------------------------------------

/// One value the prompt carries and the provider may never see.
struct Planted {
    entity: EntityType,
    value: String,
}

/// The planted set: three rungs and the one type whose evidence is entropic.
///
/// Every value is assembled at run time rather than written out, which is the
/// rule `crates/periskop-proxy/tests/no_credential_literals.rs` enforces on its
/// own tree: a continuous credential shaped literal in a source file trips every
/// scanner downstream, and a published documentation key opens nothing but says
/// nothing about that either.
///
/// The set is not the whole registry and does not claim to be. It covers rung
/// `R` (a documented range), rung `I` (a validator failed on purpose), rung `L`
/// (a counted label, which needs the operator's word list) and the entropic pair
/// that reports `O` whatever it produced. `p0_invariants.rs` is what counts the
/// registry; this gate checks the aliases that crossed a socket.
fn planted() -> Vec<Planted> {
    vec![
        Planted {
            entity: EntityType::Iban,
            value: format!("TR{}", "330006100519786457841326"),
        },
        Planted {
            entity: EntityType::Tckn,
            value: format!("1{}", "0000000146"),
        },
        Planted {
            entity: EntityType::CreditCard,
            value: format!("{} {} {} {}", "4111", "1111", "1111", "1111"),
        },
        Planted {
            entity: EntityType::Email,
            value: "zeynep.kucukates@ornek-firma-a.invalid".to_owned(),
        },
        Planted {
            entity: EntityType::Phone,
            value: format!("+90 {} {} {} {}", "532", "123", "45", "67"),
        },
        Planted {
            entity: EntityType::ApiKey,
            value: format!("sk_{}_{}", "live", "4eC39HqLyjWDarjtT1zdp7dc"),
        },
        Planted {
            entity: EntityType::Person,
            value: PERSON.to_owned(),
        },
    ]
}

/// The one value layer B claims, and the word list that makes it claimable.
///
/// It is here rather than inline because the dictionary file and the prompt have
/// to agree exactly: layer B is an exact list, so a name the list does not hold
/// crosses, which is the F4 scope boundary this gate is not allowed to blur.
const PERSON: &str = "Zeynep Kucukates";

/// A date, planted on purpose and **not** in the masked set.
///
/// `DATE` mints no alias in this build (F4 scope boundary 2), and `date_policy`
/// defaults to `allow` (`proxy-policy.md` section 4), so this crosses to the
/// provider and is counted in `entities_allowed[]`. That is the contract, and it
/// is here because it was broken: until the request path read the key, an
/// ordinary prompt with a meeting date in it was refused with a `400`, and this
/// gate would have gone red on the refusal rather than on the leak.
const DATE: &str = "toplanti 2026-03-11 tarihinde";

/// The request body: one message per planted value, then the date.
fn request_body() -> (Vec<u8>, Vec<Planted>) {
    let values = planted();
    let mut messages: Vec<Value> = values
        .iter()
        .map(|planted| json!({"role": "user", "content": format!("{LEAD}{}{TAIL}", planted.value)}))
        .collect();
    messages.push(json!({"role": "user", "content": DATE}));

    let body = json!({
        "model": "gpt-4o",
        "stream": true,
        "messages": messages,
    })
    .to_string()
    .into_bytes();
    (body, values)
}

// ---------------------------------------------------------------------------
// The stub provider, on a real socket
// ---------------------------------------------------------------------------

/// What the provider saw, and what it sent back.
struct Upstreamed {
    /// Every byte of the request, head and body, as it arrived.
    received: Vec<u8>,
    /// The strings that stood where the planted values had been, in order.
    aliases: Vec<String>,
    /// Delta events in the answer, including the terminator.
    events: usize,
    /// Transport chunks the answer was written in.
    chunks: usize,
    /// Boundaries inside an alias that fell between two delta events.
    alias_split_points: usize,
}

/// The provider's answer, and where the transport cuts it.
struct Answer {
    body: Vec<u8>,
    cuts: Vec<usize>,
    events: usize,
    alias_split_points: usize,
}

/// Builds the answer that gives every alias back the hard way.
///
/// One delta event per **character** of every alias. A provider streams tokens,
/// so an alias arriving in pieces is the ordinary case rather than the adverse
/// one, and a character at a time makes every internal boundary of every alias a
/// boundary between two events: whatever the hold buffer would release early, it
/// has an opportunity to release here. Prose either side of the alias ends and
/// begins with a space, which is the shape D-14 removed the old flush rule for:
/// a buffer that treated a space as a safe release point would emit half an
/// alias on the very first one.
fn answer_for(aliases: &[String]) -> Answer {
    let mut events: Vec<String> = Vec::new();
    let mut alias_split_points = 0usize;
    for alias in aliases {
        events.push(LEAD.to_owned());
        for character in alias.chars() {
            events.push(character.to_string());
        }
        alias_split_points += alias.chars().count().saturating_sub(1);
        events.push(TAIL.to_owned());
    }

    let mut body = String::new();
    for text in &events {
        let document = json!({"choices": [{"index": 0, "delta": {"content": text}}]});
        body.push_str(&format!("data: {document}\n\n"));
    }
    body.push_str("data: [DONE]\n\n");

    let bytes = body.into_bytes();
    let cuts: Vec<usize> = (TRANSPORT_CHUNK..bytes.len())
        .step_by(TRANSPORT_CHUNK)
        .collect();
    Answer {
        body: bytes,
        cuts,
        // The terminator is an event too, and counting it here keeps the artefact
        // honest about how many the stub actually wrote.
        events: events.len() + 1,
        alias_split_points,
    }
}

/// Reads the aliases back out of the masked body.
///
/// The prompt put one planted value per message between a fixed lead and tail,
/// so whatever sits between them now is what the proxy sent in its place. The
/// stub learns the aliases from the bytes it was handed and from nothing else,
/// which is what makes the echo below an echo rather than a script.
fn aliases_in(body: &[u8], expected: usize) -> Vec<String> {
    let document: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    (0..expected)
        .map(|index| {
            document["messages"][index]["content"]
                .as_str()
                .unwrap_or_default()
                .strip_prefix(LEAD)
                .and_then(|rest| rest.strip_suffix(TAIL))
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

/// Starts the stub provider and returns where it is listening.
///
/// It serves one connection at a time, in order, and remembers the aliases it
/// read out of the first body it could read them from. That memory is what makes
/// the expired-record run possible: the second request has nothing to mask, so
/// the only way a provider could quote an alias back is by having seen it in an
/// earlier turn, which is exactly what a model does with a conversation history.
fn start_stub(expected: usize) -> (SocketAddr, Arc<Mutex<Vec<Upstreamed>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port is free");
    let address = listener.local_addr().expect("the stub is bound");
    let seen: Arc<Mutex<Vec<Upstreamed>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);

    std::thread::spawn(move || {
        let mut remembered: Vec<String> = Vec::new();
        for connection in listener.incoming() {
            let Ok(mut socket) = connection else {
                return;
            };
            let Some((head_end, length)) = read_head(&mut socket) else {
                return;
            };
            let Some(received) = read_body(&mut socket, head_end, length) else {
                return;
            };

            let read_back = aliases_in(&received[head_end..], expected);
            let aliases = if read_back.iter().any(|alias| !alias.is_empty()) {
                remembered = read_back.clone();
                read_back
            } else {
                remembered.clone()
            };
            let answer = answer_for(&aliases);
            let chunks = write_chunked(&mut socket, &answer);

            if let Ok(mut slot) = recorder.lock() {
                slot.push(Upstreamed {
                    received,
                    aliases,
                    events: answer.events,
                    chunks,
                    alias_split_points: answer.alias_split_points,
                });
            }
        }
    });

    (address, seen)
}

/// The one exchange this run recorded, taken out of the stub's list.
fn only_exchange(seen: &Arc<Mutex<Vec<Upstreamed>>>, policy: &str) -> Upstreamed {
    let mut recorded = seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(
        recorded.len(),
        1,
        "{policy}: the stub served {} requests and this run is about one",
        recorded.len()
    );
    recorded.remove(0)
}

/// Reads until the head is complete, returning where the body starts and how
/// long it is.
fn read_head(socket: &mut TcpStream) -> Option<(usize, usize)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = socket.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(at) = find(&buffer, b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&buffer[..at]).into_owned();
            let length = content_length(&headers)?;
            // The head is read into a throwaway buffer and then read again by the
            // caller, which cannot happen on a socket. So the bytes already taken
            // are handed on rather than re-read: `read_body` continues from here.
            PARTIAL.with(|held| *held.borrow_mut() = buffer.clone());
            return Some((at + 4, length));
        }
    }
}

thread_local! {
    /// The bytes [`read_head`] had to consume to find the end of the head.
    ///
    /// A socket cannot be rewound, so what was read while looking for the blank
    /// line is kept here rather than dropped. Thread local because the stub owns
    /// one connection on one thread, and a field on a struct would have to be
    /// threaded through two functions that are otherwise about bytes.
    static PARTIAL: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Reads the rest of the body, returning head and body together.
fn read_body(socket: &mut TcpStream, head_end: usize, length: usize) -> Option<Vec<u8>> {
    let mut buffer = PARTIAL.with(|held| held.borrow().clone());
    let mut chunk = [0u8; 4096];
    while buffer.len() < head_end + length {
        let read = socket.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    buffer.truncate(head_end + length);
    Some(buffer)
}

/// Writes the answer as a chunked stream, one write and one flush per chunk.
///
/// Chunked rather than a `content-length` body, and the reason is the claim: a
/// chunked decoder never merges two chunks into one frame, so the cuts this
/// function makes are cuts the proxy's client really sees. A `content-length`
/// body would let the transport coalesce them and the gate would quietly stop
/// testing the thing it says it tests.
fn write_chunked(socket: &mut TcpStream, answer: &Answer) -> usize {
    let head = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncache-control: no-cache\r\n\
                transfer-encoding: chunked\r\nconnection: close\r\n\r\n";
    if socket.write_all(head.as_bytes()).is_err() {
        return 0;
    }

    let mut written = 0usize;
    let mut at = 0usize;
    for cut in answer
        .cuts
        .iter()
        .copied()
        .chain(std::iter::once(answer.body.len()))
    {
        let Some(piece) = answer.body.get(at..cut) else {
            continue;
        };
        if piece.is_empty() {
            continue;
        }
        if socket
            .write_all(format!("{:x}\r\n", piece.len()).as_bytes())
            .is_err()
            || socket.write_all(piece).is_err()
            || socket.write_all(b"\r\n").is_err()
        {
            return written;
        }
        let _flushed = socket.flush();
        written += 1;
        at = cut;
    }
    let _terminated = socket.write_all(b"0\r\n\r\n");
    let _flushed = socket.flush();
    written
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn content_length(headers: &str) -> Option<usize> {
    headers
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|value| value.trim().parse().ok())
}

// ---------------------------------------------------------------------------
// The proxy, on a real socket
// ---------------------------------------------------------------------------

/// What the gate opened, so the surfaces can be read afterwards.
struct Running {
    address: SocketAddr,
    gateway: Arc<Gateway>,
    vault_directory: PathBuf,
    vault_file: PathBuf,
}

/// The policy: the default one, plus the word list layer B needs, plus whatever
/// rules the run under way adds.
///
/// Nothing about dates is written here, and that is the point. The shortest
/// policy an operator can write is `[default] mode = "mask"`, and a gate that
/// had to add a rule to survive its own prompt would be proving a configuration
/// nobody deploys.
fn policy_text(rules: &str) -> String {
    format!(
        "policy_id = \"f4-proof\"\npolicy_version = \"1\"\n\n\
         [dictionary]\nsource = \"dictionary.toml\"\n\n\
         [default]\nmode = \"mask\"\n{rules}"
    )
}

fn dictionary_text() -> String {
    format!(
        "schema_version = \"1.0\"\ndictionary_id = \"f4-proof\"\n\n\
         [[entries]]\nvalue = \"{PERSON}\"\ntype = \"PERSON\"\n"
    )
}

async fn start_proxy(
    tree: &TempTree,
    rules: &str,
    ttl_ms: u64,
    stub: SocketAddr,
    upstream: Arc<dyn Upstream>,
) -> Running {
    let configuration = tree.dir("policy");
    tree.write("policy/dictionary.toml", &dictionary_text());
    let policy = Policy::load(&policy_text(rules), &configuration, None)
        .unwrap_or_else(|refusal| panic!("the gate's own policy does not load: {refusal}"));

    let vault_directory = tree.dir("vault");
    let vault_file = vault_directory.join("vault.psk");
    let vault = Vault::open(&OpenRequest {
        passphrase: &Passphrase::new(b"the operator typed this".to_vec()),
        // The reduced profile. The shipped 256 MiB profile is exercised by
        // `crates/periskop-proxy/tests/vault_no_plaintext.rs`, which is the gate
        // that owns "the vault writes no plaintext" and runs under both. What
        // this file needs from the vault is that it is a real file on a real
        // disk, and the key derivation strength does not change what is in it.
        profile: ProfileName::Ci,
        backing: Backing::File {
            path: &vault_file,
            floor: CounterFloor::Unknown,
        },
    })
    .unwrap_or_else(|refusal| panic!("the vault did not open: {refusal}"))
    .with_limits(SessionLimits {
        alias_ceiling: 1_000,
        ttl_ms,
    });

    let gateway = Gateway::new(
        policy,
        vault,
        upstream,
        // The stub is on this machine, and it is on the list because the operator
        // put it there. `passthrough.rs` permits plaintext to a loopback host and
        // to nothing else, which is the only shape a local stub can take.
        AllowList::of(["127.0.0.1"]),
        // The system clock. A pinned clock would make every duration zero, and
        // the vault's own record expiry reads the same function.
        Clock::System,
    )
    .unwrap_or_else(|refusal| panic!("{}", refusal.detail()))
    .with_base(Provider::OpenAi, &format!("http://{stub}"))
    .unwrap_or_else(|refusal| panic!("{}", refusal.detail()));

    let gateway = Arc::new(gateway);
    let listener = Listener::bind(
        ListenAddress::checked(
            "127.0.0.1:0".parse().expect("a loopback address"),
            Exposure::LoopbackOnly,
        )
        .expect("loopback needs no consent"),
    )
    .await
    .expect("a loopback port is free");
    let address = listener.address();
    let serving = Arc::clone(&gateway);
    tokio::spawn(async move {
        let _served = listener.serve(serving).await;
    });

    Running {
        address,
        gateway,
        vault_directory,
        vault_file,
    }
}

/// One request, written into a socket by hand and read back the same way.
///
/// A blocking client on purpose: it is the shape of a caller, and it makes the
/// bytes in and the bytes out something this test holds rather than something a
/// library assembled on its behalf.
fn one_request(address: SocketAddr, payload: &[u8], session: &str) -> Vec<u8> {
    let mut socket = TcpStream::connect(address).expect("the proxy is listening");
    socket.set_nodelay(true).expect("nodelay");
    let head = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nhost: {address}\r\n\
         content-type: application/json\r\nauthorization: Bearer {}\r\n\
         x-periskop-session: {session}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        caller_credential(),
        payload.len()
    );
    socket.write_all(head.as_bytes()).expect("request head");
    socket.write_all(payload).expect("request body");
    socket.flush().expect("flush");

    let mut answer = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut expected: Option<usize> = None;
    loop {
        let read = socket.read(&mut chunk).expect("the answer");
        if read == 0 {
            break;
        }
        answer.extend_from_slice(&chunk[..read]);
        if expected.is_none() {
            if let Some(at) = find(&answer, b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&answer[..at]).into_owned();
                expected = content_length(&headers).map(|length| at + 4 + length);
            }
        }
        if expected.is_some_and(|whole| answer.len() >= whole) {
            break;
        }
    }
    answer
}

/// The caller's own provider credential, assembled rather than written.
///
/// It crosses to the provider unchanged (`proxy/spec.md` section 2.3) and is
/// dropped on the way back, so it is not one of the planted values. It is a
/// distinctive string all the same, because a gate that never sent one could not
/// notice a build that started echoing it.
fn caller_credential() -> String {
    format!("periskop-{}-{}", "gate", "0f4c1a9d22b7")
}

// ---------------------------------------------------------------------------
// Claim 2: P-0 on the alias that actually crossed
// ---------------------------------------------------------------------------

/// The invariant ADR-010 section 5.1 attaches to the rung an alias was reported
/// on, checked against the alias the provider received.
///
/// Returns how many claims it checked, so a body that stopped checking cannot
/// pass as a body that checked and found nothing wrong. That is the same guard
/// `p0_invariants.rs` uses and it is here for the same reason: the mutation this
/// catches is an assertion quietly deleted.
fn rung_invariant(entity: EntityType, rung: LadderRung, alias: &str, source: &str) -> usize {
    match rung {
        LadderRung::Reserved => assert!(
            catalog::is_in_documented_range(entity, alias),
            "{entity} sent {alias} upstream on rung R, outside every documented range"
        ),
        LadderRung::Invalid => assert_eq!(
            checksum::verdict(entity, alias),
            Verdict::Invalid,
            "{entity} sent {alias} upstream on rung I and its own validator accepts it"
        ),
        LadderRung::Opaque => {
            if entity.evidence_is_entropic() {
                // Threat model R14. These types are minted on rung `I` and
                // **reported** on `O`, because no provider publishes a checksum
                // this build could fail on purpose, so the evidence is a counting
                // argument rather than a rule. The report is the weaker of the
                // two on purpose, and the invariant that holds is that the type
                // claims no validator it does not have.
                assert_eq!(
                    checksum::verdict(entity, alias),
                    Verdict::NoDocumentedCheck,
                    "{entity} claims a validator it does not have"
                );
            } else {
                assert!(
                    alias.starts_with("PSK_"),
                    "{entity} sent {alias} upstream on rung O"
                );
            }
        }
        LadderRung::Label => assert!(
            rung_l::is_counted_label(alias),
            "{entity} sent {alias} upstream on rung L"
        ),
    }

    // The alias may not be the value, which nothing above would catch for a
    // generator that simply passed its input through.
    assert_ne!(alias, source, "{entity} sent its own input upstream");
    // The ceiling the streaming hold is built on. An alias past it makes the
    // lookahead window a lie, and the buffer would release a fragment.
    assert!(
        alias.len() <= l_type_max(entity),
        "{entity} sent {} bytes upstream over its {} ceiling",
        alias.len(),
        l_type_max(entity)
    );
    3 + published_claims(entity, alias)
}

/// The same claim again, from the publication rather than from this build.
///
/// Everything in [`rung_invariant`] above asks `periskop-proxy` whether the
/// alias it generated satisfies `periskop-proxy`'s idea of the rule. That is
/// worth checking and it is not sufficient, and mutation testing is how it was
/// found out: widening `catalog::INVALID_TLD` from `.invalid` to a registrable
/// domain moved the generator and the range check together, so a rung `R` alias
/// under a domain somebody can buy passed the gate. A check written from the
/// same constant as the thing it checks is a tautology however carefully it is
/// written.
///
/// So the rules below are restated here from their publications, by hand: RFC
/// 2606's `.invalid`, ISO 7064's mod 97, the Turkish identity number's check
/// digits, Luhn, the E.164 national number length, ADR-010's label shape, and
/// the structural run-length claim threat model R14 rests on. They duplicate
/// nothing in the crate, which is the point: a mutation has to break two
/// independent statements of the rule to pass, and one of them lives outside
/// the code it constrains.
fn published_claims(entity: EntityType, alias: &str) -> usize {
    match entity {
        // RFC 2606 section 2: `.invalid` is reserved and no registry may
        // allocate under it. An alias under anything else is a domain somebody
        // can own.
        EntityType::Email => {
            assert!(
                alias.ends_with(".invalid"),
                "{entity} sent {alias} upstream under a domain a registry can allocate"
            );
            1
        }
        // ISO 13616 defines no test IBAN space, so the proof is that the alias
        // fails ISO 7064 mod 97. Computed here rather than asked for.
        EntityType::Iban => {
            assert_ne!(
                iso7064_mod97(alias),
                Some(1),
                "{entity} sent {alias} upstream and it passes ISO 7064 mod 97, so it is an \
                 IBAN a bank could have issued"
            );
            1
        }
        // The published Turkish identity number check digits.
        EntityType::Tckn => {
            assert!(
                !tckn_check_digits_pass(alias),
                "{entity} sent {alias} upstream and it passes the published check digits"
            );
            1
        }
        // Either one of the card networks' published test numbers, or a number
        // that fails Luhn. There is no third possibility, and the third one is
        // what ADR-010 forbids: a Luhn valid number nobody published.
        //
        // Half of this is restated and half of it cannot be. Luhn is a
        // computation and it is written out below. "Published" is a finite list
        // somebody maintains, and no computation decides membership of it, so
        // the gate defers to the catalogue **and** requires the entry to carry a
        // filled in citation: a number added to the pool with nowhere to look it
        // up fails here, which is the failure mode that matters, because an
        // uncited entry is exactly what an unpublished number looks like.
        EntityType::CreditCard => {
            let cited = catalog::TEST_PANS
                .iter()
                .find(|pan| pan.digits == alias)
                .is_some_and(|pan| pan.citation.is_filled_in());
            assert!(
                cited || !luhn_passes(alias),
                "{entity} sent {alias} upstream: it passes Luhn and is not a test number this \
                 build can cite, so it is a card number that could have been issued"
            );
            1
        }
        // Turkey publishes no fiction range, so the alias is a national number
        // one digit past the plan (E.164 allows fifteen digits in total, and a
        // Turkish national number is ten). Twelve digits behind `+90` cannot be
        // dialled.
        EntityType::Phone => {
            let national = alias.trim_start_matches("+90");
            assert!(
                alias.starts_with("+90") && national.len() > 10,
                "{entity} sent {alias} upstream and it is short enough to be a real number"
            );
            1
        }
        // ADR-010 section 5.1's rung `L`: `TAG_index` and nothing else. No value
        // is drawn from the type's value space at all.
        EntityType::Person | EntityType::Org | EntityType::Loc | EntityType::Address => {
            let (tag, index) = alias.split_once('_').unwrap_or_default();
            assert!(
                !tag.is_empty()
                    && tag.chars().all(|c| c.is_ascii_uppercase())
                    && !index.is_empty()
                    && index.chars().all(|c| c.is_ascii_digit()),
                "{entity} sent {alias} upstream, which is not a counted label"
            );
            1
        }
        // Threat model R14's structural claim: every published scanner pattern
        // is a marker followed by an unbroken run of body characters, and the
        // shortest run any of them accepts is ten. A run that stops at eight
        // cannot complete one, whatever bytes the stream drew.
        EntityType::ApiKey | EntityType::Secret => {
            let longest = alias
                .split(|c: char| !(c.is_ascii_alphanumeric()))
                .map(str::len)
                .max()
                .unwrap_or_default();
            assert!(
                longest < 9,
                "{entity} sent {alias} upstream with a run of {longest} body characters, which \
                 is long enough for a published scanner pattern to complete"
            );
            1
        }
        // Nothing published to restate. `rung_invariant` above is the whole of
        // what these types claim, and the gate says so rather than counting a
        // check it did not perform.
        EntityType::Ipv4
        | EntityType::Ipv6
        | EntityType::Vkn
        | EntityType::Url
        | EntityType::Host
        | EntityType::Date => 0,
    }
}

/// ISO 7064 mod 97 over an IBAN, or `None` if it is not shaped like one.
///
/// `Some(1)` is a valid IBAN. Written out because the whole point of this
/// function is that it is not the one the crate uses.
fn iso7064_mod97(iban: &str) -> Option<u32> {
    let compact: String = iban.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() < 5 {
        return None;
    }
    let (head, tail) = compact.split_at(4);
    let rearranged = format!("{tail}{head}");
    let mut remainder: u32 = 0;
    for character in rearranged.chars() {
        let value = if character.is_ascii_digit() {
            character as u32 - '0' as u32
        } else if character.is_ascii_alphabetic() {
            character.to_ascii_uppercase() as u32 - 'A' as u32 + 10
        } else {
            return None;
        };
        remainder = if value > 9 {
            (remainder * 100 + value) % 97
        } else {
            (remainder * 10 + value) % 97
        };
    }
    Some(remainder)
}

/// The published Turkish identity number check digits.
///
/// The tenth digit is `(7 * odd - even) mod 10` over the first nine, and the
/// eleventh is the first ten summed, mod 10. Signed arithmetic because the
/// subtraction goes below zero for most inputs, and a wrapping unsigned version
/// would quietly accept a different set of numbers than the published rule.
fn tckn_check_digits_pass(number: &str) -> bool {
    let digits: Vec<i64> = number
        .chars()
        .filter_map(|c| c.to_digit(10))
        .map(i64::from)
        .collect();
    if digits.len() != 11 || number.len() != 11 || digits.first() == Some(&0) {
        return false;
    }
    let odd = digits[0] + digits[2] + digits[4] + digits[6] + digits[8];
    let even = digits[1] + digits[3] + digits[5] + digits[7];
    let tenth = ((odd * 7 - even) % 10 + 10) % 10;
    let eleventh = digits[..10].iter().sum::<i64>() % 10;
    digits[9] == tenth && digits[10] == eleventh
}

/// The restated rules accept the values they were restated from.
///
/// Without this, a checker that answered "not valid" for every input would make
/// every claim in [`published_claims`] pass over any alias at all, including
/// over the planted value itself. Each planted value is a published example that
/// satisfies its own rule, so each checker has to say so, and each has to reject
/// the same example with one digit changed.
#[test]
fn the_rules_restated_from_their_publications_accept_the_values_they_came_from() {
    let iban = format!("TR{}", "330006100519786457841326");
    assert_eq!(iso7064_mod97(&iban), Some(1));
    assert_ne!(
        iso7064_mod97(&format!("TR{}", "330006100519786457841327")),
        Some(1)
    );

    let tckn = format!("1{}", "0000000146");
    assert!(tckn_check_digits_pass(&tckn));
    assert!(!tckn_check_digits_pass(&format!("1{}", "0000000147")));

    assert!(luhn_passes(&format!("{}{}", "411111111111111", "1")));
    assert!(!luhn_passes(&format!("{}{}", "411111111111111", "2")));
}

/// Luhn, written out.
fn luhn_passes(number: &str) -> bool {
    let digits: Vec<u32> = number.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 2 {
        return false;
    }
    let mut total = 0u32;
    for (index, digit) in digits.iter().rev().enumerate() {
        let mut value = *digit;
        if index % 2 == 1 {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        total += value;
    }
    total % 10 == 0
}

// ---------------------------------------------------------------------------
// Claim 3: what the client was given
// ---------------------------------------------------------------------------

/// The text of a server sent event stream, reassembled by this test.
///
/// Parsed here rather than through `periskop_proxy::http::stream::frame`, and
/// deliberately: a gate that read its own output with the parser under test
/// would agree with itself about a stream neither of them delivered correctly.
fn delivered(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body).into_owned();
    let mut out = String::new();
    for line in text.lines() {
        let Some(payload) = line.strip_prefix("data: ") else {
            continue;
        };
        if payload.trim() == "[DONE]" {
            continue;
        }
        let Ok(document) = serde_json::from_str::<Value>(payload) else {
            continue;
        };
        if let Some(piece) = document["choices"][0]["delta"]["content"].as_str() {
            out.push_str(piece);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The artefact
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize)]
struct ProofRecord {
    gate: &'static str,
    status: &'static str,
    reason: String,
    vault_backend: &'static str,
    vault_kdf_profile: &'static str,
    /// What this run establishes.
    proves: Vec<&'static str>,
    /// What it does not, in as many words, so nobody has to infer it from what
    /// is missing.
    does_not_prove: Vec<&'static str>,
    caveat: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<Evidence>,
}

#[derive(Debug, serde::Serialize)]
struct Evidence {
    /// Two loopback listeners, one child of neither: the client, the proxy and
    /// the provider all wrote into real sockets.
    real_sockets: bool,
    /// One entry per policy the five claims were run under.
    ///
    /// Two of them, and the second is not decoration. Seven waves of mutation
    /// testing found five gates that were weaker than they read, and the last
    /// escape was on the **allow** path: `entities_allowed[].rule_scope` is the
    /// one field on this component's measurement surface that carries a string,
    /// and every gate ran with `mode = "mask"`, where nothing is ever allowed.
    /// So the claims run twice, once with everything masked and once with an
    /// entity the policy lets through.
    runs: Vec<RunEvidence>,
    /// Claim 4's zero, shown to be a measurement rather than a constant.
    unresolved_control: UnresolvedEvidence,
    /// The third mode, which no integration gate had ever run under.
    block_control: BlockEvidence,
}

/// The five claims, measured under one policy.
#[derive(Debug, serde::Serialize)]
struct RunEvidence {
    policy: &'static str,
    /// The rule the run adds to the default policy, empty for the default one.
    rule: &'static str,
    masking_profile: String,
    alias_style: String,
    upstream_request_bytes: usize,
    planted_values: usize,
    /// Values this policy masks, and therefore may not reach the provider.
    masked_values: usize,
    /// Claim 1, over the masked ones. A value the policy allows is meant to
    /// cross, and it is named here rather than quietly left out of the count.
    masked_values_absent_from_upstream_bytes: usize,
    allowed_value: Option<String>,
    allowed_rule_scope: Option<String>,
    /// Claim 2, one row per alias the provider saw.
    aliases_seen_by_upstream: Vec<AliasSeen>,
    p0_claims_checked: usize,
    /// Claim 3.
    answer_delta_events: usize,
    answer_transport_chunks: usize,
    alias_split_points: usize,
    values_restored_in_order: usize,
    /// Claim 4.
    aliases_seen_in_response: u64,
    aliases_restored: u64,
    aliases_leaked: u64,
    partial_alias_flushed: u64,
    /// Claim 5. Every planted value is searched for on every surface, including
    /// the one the policy allowed: an allowed value is meant to reach the
    /// provider and the user, and it is still not meant to be written into a
    /// measurement record or a log line.
    surfaces_scanned: Vec<&'static str>,
    vault_directory_other_files: usize,
    surface_bytes_scanned: usize,
    /// The other half of the request path, and the defect this gate was written
    /// beside: a date crosses under `date_policy` instead of refusing the
    /// request, and the crossing is counted rather than silent.
    date_crossed_under_date_policy: bool,
    date_rule_scope: String,
}

#[derive(Debug, serde::Serialize)]
struct AliasSeen {
    entity: String,
    ladder_rung: String,
    claims_checked: usize,
}

const CAVEAT: &str = "no provider was reached: the upstream is a stub on this machine, because \
                      periskop may not be an egress source and a run that needed a funded key \
                      would not be a gate. There is no NER layer in this build, so a name is \
                      masked only because an operator's word list holds it and a name nobody \
                      listed crosses. Answer quality is not measured here. This artefact covers \
                      the proxy half of F4 only: the kernel capture half is proof_f4_kernel.rs \
                      and its own artefact, and F4 does not close on one of them.";

const PROVES: &[&str] = &[
    "a real client, a real proxy over a real loopback socket and a real vault.psk on disk",
    "no value the policy masks appears in the bytes the provider recorded. The run that allows \
     an entity names it in allowed_value and asserts the opposite for that one, because an \
     allowance that did not cross would be a masking rule wearing the wrong label",
    "every alias the provider saw satisfies the invariant of the rung it was reported on",
    "an alias cut between delta events, one character at a time, and cut again by the \
     transport inside the data: lines, is given back to the client whole and in order",
    "restore_stats.aliases_leaked and stream_stats.partial_alias_flushed are both zero",
    "no planted value appears as bytes on the vault file, the vault directory's other files, \
     the event record, the request log line, the client response head or this artefact. The \
     response body is excluded on purpose: it is the answer, and the answer carrying the \
     user's own values back is the product working",
    "a date crosses under the default policy and is counted rather than refusing the request",
    "a request carrying an entity under `mode = \"block\"` is refused with 400 and \
     entity_blocked, and the stub provider recorded no request at all: the third mode of the \
     enum, which no integration gate had ever run under",
];

const DOES_NOT_PROVE: &[&str] = &[
    "that a real provider answers a masked prompt usefully: none was reached",
    "that a person's name is found without an operator's word list: layer C is not in this build",
    "how much answer quality masking costs: milestone 96 measures that offline and an \
     operator's recorded session measures the rest",
    "that every registered entity type keeps its invariant: this gate plants seven of them, \
     and crates/periskop-proxy/tests/p0_invariants.rs is what counts the registry",
    "that an alias containing whitespace survives a cut inside the whitespace: no generator \
     in this build emits one, so no minted alias could carry the case, and the declared \
     whitespace shapes are covered by crates/periskop-proxy/tests/flush_invariant.rs",
    "that the eBPF capture path works: that is proof_f4_kernel.rs, on a privileged Linux runner",
];

/// Writes the artefact this gate is read through, and fails the test if it
/// cannot.
///
/// The stale file is removed before the new one is written, for the reason
/// `proof_f3.rs` gives: between those two lines there must be no moment where an
/// old artefact could be mistaken for a new one.
fn record_outcome(record: &ProofRecord) -> Vec<u8> {
    let out = repo_root().join("target/f4-proof.json");
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|e| panic!("{} could not be created: {e}", parent.display()));
    }
    match std::fs::remove_file(&out) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!(
            "the artefact of an earlier run at {} could not be removed: {e}",
            out.display()
        ),
    }
    let text = serde_json::to_string_pretty(record).expect("a record of numbers and strings");
    std::fs::write(&out, &text)
        .unwrap_or_else(|e| panic!("{} could not be written: {e}", out.display()));
    text.into_bytes()
}

/// Records that the gate could not run, and fails when it was required to.
///
/// The same shape as `proof.rs` and `proof_f3.rs`, and for the reason those two
/// give: a machine that cannot run the gate should still be able to run
/// `cargo test`, because a hard failure for everybody is what teaches people to
/// pass `--skip proof`, and that removes the gate for everybody. The switch is
/// what makes the skip non-silent, and continuous integration sets it.
fn skip(reason: &str) {
    record_outcome(&ProofRecord {
        gate: "F4-101",
        status: "skipped",
        reason: reason.to_owned(),
        vault_backend: "file",
        vault_kdf_profile: "ci",
        proves: Vec::new(),
        does_not_prove: DOES_NOT_PROVE.to_vec(),
        caveat: CAVEAT,
        evidence: None,
    });
    assert!(
        std::env::var_os(REQUIRE_PROOF).is_none(),
        "{REQUIRE_PROOF} is set and the F4 proxy gate cannot run: {reason}"
    );
    eprintln!(
        "\n  SKIPPED: the F4 proxy gate did not run.\n  Reason: {reason}\n  \
         This run does not close F4's proxy half. Set {REQUIRE_PROOF}=1 to make the \
         missing\n  prerequisite a failure instead of a skip.\n"
    );
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// The two policies the five claims are run under.
///
/// The second one is the lesson of seven mutation waves. The last escaped
/// mutation put the matched text into `entities_allowed[].rule_scope`, and every
/// gate stayed green because every gate ran with `mode = "mask"`, under which
/// nothing is ever allowed and that field is never written. So the run below
/// happens twice, and the second time an entity crosses under a rule.
const POLICIES: &[(&str, &str, Option<EntityType>)] = &[
    ("default masking", "", None),
    (
        "phone allowed by rule",
        "\n[[rule]]\nentity = \"PHONE\"\nscope = \"messages[*].content\"\nmode = \"allow\"\n",
        Some(EntityType::Phone),
    ),
];

/// F4's proxy half is not closed while this does not pass.
#[test]
fn f4_gate_a_real_exchange_masks_restores_and_leaks_nothing() {
    let upstream = match RustlsUpstream::new() {
        Ok(client) => Arc::new(client) as Arc<dyn Upstream>,
        // The shipped client is what a running proxy dials with, so a gate that
        // swapped it for a recorder here would be proving a different program.
        Err(why) => {
            skip(&format!(
                "the shipped upstream client could not be built: {}",
                why.why
            ));
            return;
        }
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");

    let mut runs = Vec::new();
    for (name, rule, allowed) in POLICIES {
        runs.push(one_run(
            &runtime,
            Arc::clone(&upstream),
            name,
            rule,
            *allowed,
        ));
    }
    let unresolved_control =
        expired_records_are_counted_and_never_invented(&runtime, Arc::clone(&upstream));
    let block_control = nothing_crosses_when_a_rule_blocks(&runtime, Arc::clone(&upstream));

    let artefact = record_outcome(&ProofRecord {
        gate: "F4-101",
        status: "proved",
        reason: "a real client reached a real proxy over loopback, the stub provider recorded a \
                 request with none of the masked values in it, gave every alias back one \
                 character at a time across a chunked stream, and the client received the \
                 originals whole and in order. Run twice: once with everything masked and once \
                 with an entity the policy allows"
            .to_owned(),
        vault_backend: "file",
        vault_kdf_profile: "ci",
        proves: PROVES.to_vec(),
        does_not_prove: DOES_NOT_PROVE.to_vec(),
        caveat: CAVEAT,
        evidence: Some(Evidence {
            real_sockets: true,
            runs,
            unresolved_control,
            block_control,
        }),
    });

    // The artefact is a surface too. It carries counts and type names, and a
    // future field that carried a value would be a leak written by the very file
    // that claims there is none. The allowed value is checked here as well: it
    // may cross to the provider and back to the user and it still may not be
    // written into a record.
    for planted in planted() {
        assert!(
            find(&artefact, planted.value.as_bytes()).is_none(),
            "{} appears in the artefact this gate writes",
            planted.entity
        );
    }
    assert!(
        find(&artefact, caller_credential().as_bytes()).is_none(),
        "the caller's credential appears in the artefact"
    );
}

/// One exchange, and the five claims measured over it.
fn one_run(
    runtime: &tokio::runtime::Runtime,
    upstream: Arc<dyn Upstream>,
    policy: &'static str,
    rule: &'static str,
    allowed: Option<EntityType>,
) -> RunEvidence {
    let tree = TempTree::new(&policy.replace(' ', "-"));
    let (payload, values) = request_body();
    let (stub_address, upstreamed) = start_stub(values.len());
    let running = runtime.block_on(start_proxy(
        &tree,
        rule,
        LONG_TTL_MS,
        stub_address,
        upstream,
    ));

    let session = format!("f4-gate-{}", policy.replace(' ', "-"));
    let response = one_request(running.address, &payload, &session);
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{policy}: the exchange did not complete: {}",
        String::from_utf8_lossy(&response[..response.len().min(400)])
    );

    let seen = only_exchange(&upstreamed, policy);

    // -- Claim 1: the provider never saw a value this policy masks -----------
    //
    // Searched over the whole recorded request, head and body. The head is in
    // scope on purpose: a build that put the alias scope or a fragment of the
    // prompt into a header would fail here rather than in a review.
    let mut absent = 0usize;
    let mut masked_values = 0usize;
    for planted in &values {
        if allowed == Some(planted.entity) {
            // Named, not skipped. This one is meant to cross, and the artefact
            // says which one it was so that a run with everything allowed cannot
            // read as a run with everything masked.
            assert!(
                find(&seen.received, planted.value.as_bytes()).is_some(),
                "{policy}: {} was allowed by a rule and did not reach the provider",
                planted.entity
            );
            continue;
        }
        masked_values += 1;
        assert!(
            find(&seen.received, planted.value.as_bytes()).is_none(),
            "{policy}: {} reached the provider",
            planted.entity
        );
        absent += 1;
    }

    // -- The date, which crosses in both runs --------------------------------
    assert!(
        find(&seen.received, DATE.as_bytes()).is_some(),
        "{policy}: the date did not reach the provider, so either it was masked (this build \
         mints no date alias) or the request was refused; either way `date_policy = \"allow\"` \
         is not what ran"
    );

    // -- The event record, which claims 2, 4 and 5 all read -------------------
    let events = running.gateway.events();
    assert_eq!(
        events.len(),
        1,
        "{policy}: one exchange has to produce one measurement record"
    );
    let event = events[0].to_value();
    let event_json = events[0].to_json();

    // -- Claim 2: P-0 on the aliases that crossed ----------------------------
    assert_eq!(
        seen.aliases.len(),
        values.len(),
        "{policy}: the stub could not read a replacement back for every planted value: {:?}",
        seen.aliases
    );
    let rungs = reported_rungs(&event);
    let mut aliases_seen = Vec::new();
    let mut p0_claims = 0usize;
    for (planted, alias) in values.iter().zip(&seen.aliases) {
        if allowed == Some(planted.entity) {
            continue;
        }
        assert!(
            !alias.is_empty(),
            "{policy}: {} was not replaced by anything the stub could read",
            planted.entity
        );
        let rung = *rungs.get(planted.entity.tag()).unwrap_or_else(|| {
            panic!(
                "{policy}: the event record does not say which rung {} was minted on: \
                 {event_json}",
                planted.entity
            )
        });
        let checked = rung_invariant(planted.entity, rung, alias, &planted.value);
        p0_claims += checked;
        aliases_seen.push(AliasSeen {
            entity: planted.entity.tag().to_owned(),
            ladder_rung: rung.as_str().to_owned(),
            claims_checked: checked,
        });
    }
    assert_eq!(
        rungs.len(),
        masked_values,
        "{policy}: the run minted aliases for types this gate did not plant, so the invariants \
         above cover less than the run did: {event_json}"
    );

    // -- Claim 3: the values came back, whole and in order --------------------
    let body_at = find(&response, b"\r\n\r\n").expect("a response head") + 4;
    let delivered = delivered(&response[body_at..]);
    let expected: String = values
        .iter()
        .map(|planted| format!("{LEAD}{}{TAIL}", planted.value))
        .collect();
    assert_eq!(
        delivered, expected,
        "{policy}: the client did not receive the originals back in the order they were sent"
    );
    for (planted, alias) in values.iter().zip(&seen.aliases) {
        if allowed == Some(planted.entity) {
            continue;
        }
        assert!(
            !delivered.contains(alias.as_str()),
            "{policy}: an alias reached the client: {alias}"
        );
    }
    assert!(
        seen.alias_split_points > 0 && seen.chunks > 1,
        "{policy}: the answer was not actually cut, so claim 3 tested nothing: {} split points \
         over {} chunks",
        seen.alias_split_points,
        seen.chunks
    );

    // -- Claim 4: the two counters that may not be anything but zero ----------
    //
    // Read through `required_count`, so an absent counter fails here instead of
    // arriving as a zero that satisfies the two assertions below by itself.
    let leaked = required_count(
        &event,
        &["restore_stats", "aliases_leaked"],
        policy,
        &event_json,
    );
    let flushed = required_count(
        &event,
        &["stream_stats", "partial_alias_flushed"],
        policy,
        &event_json,
    );
    assert_eq!(
        leaked, 0,
        "{policy}: an alias was delivered unresolved: {event_json}"
    );
    assert_eq!(
        flushed, 0,
        "{policy}: part of an alias was flushed to the client: {event_json}"
    );
    // `aliases_seen_in_response` is asserted nowhere and goes straight into the
    // artefact, which is exactly why it needs the reader that refuses a default:
    // it was the one counter whose absence nothing at all would have noticed.
    let seen_in_response = required_count(
        &event,
        &["restore_stats", "aliases_seen_in_response"],
        policy,
        &event_json,
    );
    let restored = required_count(
        &event,
        &["restore_stats", "aliases_restored"],
        policy,
        &event_json,
    );
    assert_eq!(
        restored, masked_values as u64,
        "{policy}: the response side did not resolve every alias it was sent: {event_json}"
    );

    // -- The allowances, which are counted and never silent -------------------
    let allowances = event["entities_allowed"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let scope_of = |tag: &str| -> Option<String> {
        allowances
            .iter()
            .find(|row| row["type"] == tag)
            .and_then(|row| row["rule_scope"].as_str())
            .map(str::to_owned)
    };
    let date_rule_scope = scope_of("DATE").unwrap_or_else(|| {
        panic!("{policy}: a date crossed and was not counted in entities_allowed: {event_json}")
    });
    // An allowance whose deciding expression is an empty string reads in a
    // record as a missing field. The operator's next move after seeing a count
    // is to find the line that produced it, so the count without the line is
    // half a measurement.
    assert!(
        !date_rule_scope.is_empty(),
        "{policy}: the date allowance names no deciding expression: {event_json}"
    );
    let allowed_rule_scope = allowed.map(|entity| {
        scope_of(entity.tag()).unwrap_or_else(|| {
            panic!(
                "{policy}: {entity} crossed under a rule and was not counted in \
                 entities_allowed: {event_json}"
            )
        })
    });
    if let Some(scope) = &allowed_rule_scope {
        // The expression, never the text it matched. This is the assertion the
        // escaped mutation of the last wave would have failed, and it can only
        // exist on a run where something was allowed.
        assert_eq!(
            scope, "messages[*].content",
            "{policy}: the allowance does not name the rule that decided: {event_json}"
        );
    }

    // -- Claim 5: no planted value on any surface ----------------------------
    let log: String = running
        .gateway
        .log()
        .iter()
        .map(|record| format!("{}\n", record.to_line()))
        .collect();
    let vault_bytes = std::fs::read(&running.vault_file).expect("the vault file");
    // The response **head** and not the whole response. The body is the answer,
    // and the answer is the user's own data coming back: a claim that the
    // planted values are absent from it would be a claim that restoration did
    // not happen, which is the opposite of what this gate is for. What the head
    // may not carry is a value or the caller's credential, and that is what is
    // searched. `crates/periskop-proxy/tests/vault_no_plaintext.rs` scans a whole
    // response, and correctly: there the answer carries no restored value.
    let head_end = find(&response, b"\r\n\r\n").map_or(response.len(), |at| at + 4);
    let mut surfaces: Vec<(&'static str, Vec<u8>)> = vec![
        ("client_response_head", response[..head_end].to_vec()),
        ("vault_file", vault_bytes),
        ("proxy_event", event_json.clone().into_bytes()),
        ("request_log_line", log.into_bytes()),
    ];
    let mut other_files = 0usize;
    for entry in std::fs::read_dir(&running.vault_directory)
        .expect("the vault directory")
        .flatten()
    {
        let path = entry.path();
        if path == running.vault_file || !path.is_file() {
            continue;
        }
        other_files += 1;
        surfaces.push((
            "vault_directory_other_file",
            std::fs::read(&path).unwrap_or_default(),
        ));
    }

    let mut surface_bytes = 0usize;
    for (name, bytes) in &surfaces {
        surface_bytes += bytes.len();
        // Every planted value, including the one the policy allowed. An allowed
        // value is meant to reach the provider and the user; it is not meant to
        // be written into a measurement record or a log line, and the field that
        // could carry it only exists on this path.
        for planted in &values {
            assert!(
                find(bytes, planted.value.as_bytes()).is_none(),
                "{policy}: {} appears in {name}",
                planted.entity
            );
        }
        assert!(
            find(bytes, DATE.as_bytes()).is_none(),
            "{policy}: the allowed date appears in {name}"
        );
        // The caller's credential travels up unchanged and comes back nowhere
        // (`proxy/spec.md` section 2.3). It is checked on the same surfaces
        // because a build that started echoing it would put a live key into a
        // log line, which is the place nobody looks until it is quoted back.
        assert!(
            find(bytes, caller_credential().as_bytes()).is_none(),
            "{policy}: the caller's credential appears in {name}"
        );
    }
    // And it did reach the provider, or the check above passes because nothing
    // was ever sent.
    assert!(
        find(&seen.received, caller_credential().as_bytes()).is_some(),
        "{policy}: the caller's credential did not reach the provider, so the redaction claim \
         above is checking a header that was never on the wire"
    );

    let scanned: Vec<&'static str> = surfaces
        .iter()
        .map(|(name, _)| *name)
        .collect::<BTreeSet<&'static str>>()
        .into_iter()
        .chain(std::iter::once("f4_proof_artefact"))
        .collect();

    RunEvidence {
        policy,
        rule,
        // Read, not defaulted. `unwrap_or_default()` here turned a field the
        // record did not carry into an empty string, and the artefact then went
        // out saying `status: "proved"` beside `masking_profile: ""`. The field
        // is the run's statement about **what was masked at all**: a reader who
        // sees it empty cannot tell a build with no dictionary from a record
        // that lost the key, and the gate said proved for both. A gate that
        // cannot read its own evidence has not proved anything.
        masking_profile: required(&event, "masking_profile", policy, &event_json),
        alias_style: required(&event, "alias_style", policy, &event_json),
        upstream_request_bytes: seen.received.len(),
        planted_values: values.len(),
        masked_values,
        masked_values_absent_from_upstream_bytes: absent,
        allowed_value: allowed.map(|entity| entity.tag().to_owned()),
        allowed_rule_scope,
        aliases_seen_by_upstream: aliases_seen,
        p0_claims_checked: p0_claims,
        answer_delta_events: seen.events,
        answer_transport_chunks: seen.chunks,
        alias_split_points: seen.alias_split_points,
        values_restored_in_order: values.len(),
        aliases_seen_in_response: seen_in_response,
        aliases_restored: restored,
        aliases_leaked: leaked,
        partial_alias_flushed: flushed,
        surfaces_scanned: scanned,
        vault_directory_other_files: other_files,
        surface_bytes_scanned: surface_bytes,
        date_crossed_under_date_policy: true,
        date_rule_scope,
    }
}

/// One field of the measurement record, or the gate fails rather than guessing.
///
/// The rule this enforces: **no field of this artefact is filled in by a
/// default.** Every value here is a run's own statement about what it did, and a
/// missing one means the run and the record disagree about what was measured.
/// Writing an empty string in its place and going on to say `proved` is the
/// failure mode that made this function necessary, and it is worse than a red
/// gate because it is a green one that reads as evidence.
fn required(event: &Value, field: &str, policy: &str, event_json: &str) -> String {
    let value = event[field].as_str().unwrap_or_default();
    assert!(
        !value.is_empty(),
        "{policy}: the measurement record carries no `{field}`, so this run cannot say what \
         it did and the artefact may not say `proved`: {event_json}"
    );
    value.to_owned()
}

/// One counted field of the measurement record, on the same terms.
///
/// The numeric half of [`required`], and it was missing. The rule above is about
/// **fields**, not about strings, and it was enforced on the strings alone:
/// every counter came through `unwrap_or_default()`, which turns a renamed or
/// unwritten field into a measured zero. That is fatal in both directions here.
/// Two of this gate's claims assert that a counter **is** zero, so an absent
/// field satisfies them for free; and the counters go on into
/// `target/f4-proof.json`, where a zero nobody read is published beside
/// `status: proved` and reads as a measurement.
///
/// The path is a list because the counters sit under `restore_stats` and
/// `stream_stats`; indexing a `Value` with a missing key yields `Null`, so the
/// walk is the same failure at whichever depth it happens.
fn required_count(event: &Value, path: &[&str], policy: &str, event_json: &str) -> u64 {
    let mut cursor = event;
    for key in path {
        cursor = &cursor[*key];
    }
    match cursor.as_u64() {
        Some(count) => count,
        None => panic!(
            "{policy}: the measurement record carries no `{}` counter, so this run measured \
             nothing there and the artefact may not publish a number for it: {event_json}",
            path.join(".")
        ),
    }
}

/// How long a conversation's records live in the two ordinary runs.
const LONG_TTL_MS: u64 = 3_600_000;

/// And in the run that lets them expire on purpose.
const SHORT_TTL_MS: u64 = 60;

/// Claim 4's positive control: the counters can be something other than zero.
///
/// Mutation testing is why this exists. Deleting the line that increments
/// `aliases_leaked` left the whole gate green, because two of the five claims
/// are assertions that a counter **is zero** and a counter that can never be
/// anything else satisfies them for free. A zero is only evidence if the same
/// code path can produce a one.
///
/// So this run produces the one, over the same real sockets, through the case
/// the contract names: `masking_unresolved`. The conversation's records expire,
/// the provider quotes an alias from the earlier turn the way a model quotes its
/// own history, the vault has nothing to give back, and F4's fourth exit
/// criterion says what has to happen next. The alias goes to the user **exactly
/// as the model wrote it**, no value is invented for it (threat model R5), and
/// it is counted.
fn expired_records_are_counted_and_never_invented(
    runtime: &tokio::runtime::Runtime,
    upstream: Arc<dyn Upstream>,
) -> UnresolvedEvidence {
    let tree = TempTree::new("expired-records");
    let (payload, values) = request_body();
    let (stub_address, upstreamed) = start_stub(values.len());
    let running = runtime.block_on(start_proxy(&tree, "", SHORT_TTL_MS, stub_address, upstream));

    // Turn one: an ordinary masked exchange, which files the records.
    let session = "f4-gate-expiring-conversation";
    let first = one_request(running.address, &payload, session);
    assert!(first.starts_with(b"HTTP/1.1 200"), "the first turn failed");

    // Past the time to live. Slept rather than pinned, because the clock this
    // gate runs on is the system one: a fixed clock would make the expiry a
    // property of the test harness instead of of the vault.
    std::thread::sleep(std::time::Duration::from_millis(SHORT_TTL_MS * 3));

    // Turn two carries nothing to mask, so nothing is re-filed and the only
    // aliases in play are the expired ones. The provider quotes them back
    // because it saw them in the first turn.
    let follow_up = json!({
        "model": "gpt-4o",
        "stream": true,
        "messages": [{"role": "user", "content": "ozetle"}],
    })
    .to_string()
    .into_bytes();
    let second = one_request(running.address, &follow_up, session);
    assert!(
        second.starts_with(b"HTTP/1.1 200"),
        "the second turn failed: {}",
        String::from_utf8_lossy(&second[..second.len().min(400)])
    );

    let recorded = upstreamed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(
        recorded.len(),
        2,
        "the stub served {} turns",
        recorded.len()
    );
    let quoted = recorded[1].aliases.clone();
    drop(recorded);
    assert!(
        !quoted.is_empty(),
        "the provider quoted no alias back, so there is nothing that could have failed to \
         resolve"
    );

    let events = running.gateway.events();
    let event = events
        .last()
        .unwrap_or_else(|| panic!("the second turn produced no measurement record"))
        .to_value();
    // The same reader the ordinary runs use. `restored` is the one that made
    // this necessary: the assertion under it is `restored == 0`, so reading the
    // field with a default meant a renamed or unwritten counter passed the check
    // by being absent. An expired record could then have been resolved twice
    // over, `aliases_restored` could really have been two, and this positive
    // control would still have reported that nothing was restored.
    let policy = "expired-records";
    let event_json = event.to_string();
    let leaked = required_count(
        &event,
        &["restore_stats", "aliases_leaked"],
        policy,
        &event_json,
    );
    let restored = required_count(
        &event,
        &["restore_stats", "aliases_restored"],
        policy,
        &event_json,
    );

    assert_eq!(
        leaked,
        quoted.len() as u64,
        "the records had expired and the run did not count a single unresolved alias, so \
         `aliases_leaked` is a number this build cannot produce and claim 4's zero proves \
         nothing: {event}"
    );
    assert_eq!(
        restored, 0,
        "an expired record was resolved anyway: {event}"
    );

    // R5, and the reason this is the case worth running: what goes to the user is
    // the alias the model wrote, not a value somebody guessed.
    let body_at = find(&second, b"\r\n\r\n").expect("a response head") + 4;
    let delivered = delivered(&second[body_at..]);
    for alias in &quoted {
        assert!(
            delivered.contains(alias.as_str()),
            "an unresolvable alias was not delivered as the model wrote it: {alias}"
        );
    }
    for planted in &values {
        assert!(
            !delivered.contains(planted.value.as_str()),
            "a value was invented for an alias the vault could not resolve: {}",
            planted.entity
        );
    }

    UnresolvedEvidence {
        turns: 2,
        session_ttl_ms: SHORT_TTL_MS,
        aliases_quoted_after_expiry: quoted.len(),
        aliases_leaked: leaked,
        aliases_restored: restored,
        values_invented: 0,
    }
}

/// The one mode no integration gate had ever run under.
///
/// Three times now a defect has survived because every gate ran under one
/// configuration. `date_policy` refused ordinary prompts because no gate set it;
/// `entities_allowed[].rule_scope` carried the matched text because every gate
/// ran with `mode = "mask"`, under which nothing is ever allowed; and this is the
/// third: `mode = "block"` is a third of the mode enum and no request had ever
/// crossed a socket under it. What the block path does is refuse **before** the
/// provider is reached, so the thing worth proving is a negative that only a real
/// exchange can establish: the stub recorded nothing.
fn nothing_crosses_when_a_rule_blocks(
    runtime: &tokio::runtime::Runtime,
    upstream: Arc<dyn Upstream>,
) -> BlockEvidence {
    // Scoped to a rule rather than written into `[default]`, because that is the
    // shape an operator writes: everything is masked and one type is too
    // sensitive to send under any name.
    const RULE: &str =
        "\n[[rule]]\nentity = \"IBAN\"\nscope = \"messages[*].content\"\nmode = \"block\"\n";

    let tree = TempTree::new("blocked");
    let (payload, values) = request_body();
    let (stub_address, upstreamed) = start_stub(values.len());
    let running = runtime.block_on(start_proxy(
        &tree,
        RULE,
        LONG_TTL_MS,
        stub_address,
        upstream,
    ));

    let response = one_request(running.address, &payload, "f4-gate-blocked");
    let head_end = find(&response, b"\r\n\r\n").map_or(response.len(), |at| at + 4);
    let head = String::from_utf8_lossy(&response[..head_end])
        .to_ascii_lowercase()
        .replace("\r\n", "\n");

    assert!(
        response.starts_with(b"HTTP/1.1 400"),
        "a blocked entity did not refuse the request: {}",
        String::from_utf8_lossy(&response[..response.len().min(400)])
    );
    // The closed dictionary's own value, on the header a client branches on.
    // Without this the assertion above passes on any 400 at all, including the
    // one an unparsable body produces, and the run would prove that a broken
    // request is refused rather than that a blocked one is.
    assert!(
        head.contains("x-periskop-error: entity_blocked"),
        "the refusal does not say a blocked entity caused it: {head}"
    );

    // The claim. `proxy/spec.md` section 10: periskop never chooses "send it
    // unmasked" over "refuse", and under `block` there is no masked form to send
    // either, so the request stops here. A stub that recorded anything at all
    // means bytes crossed before the refusal was decided.
    let recorded = upstreamed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let reached_the_provider = recorded.len();
    drop(recorded);
    assert_eq!(
        reached_the_provider, 0,
        "a request carrying an entity under `mode = \"block\"` reached the provider"
    );

    // And the surfaces, on the path nothing else covers. A refusal writes a log
    // line and may file a measurement record, and both are written while the
    // whole prompt is in this process: the value that caused the refusal is the
    // one most likely to be quoted into the sentence explaining it.
    let log: String = running
        .gateway
        .log()
        .iter()
        .map(|record| format!("{}\n", record.to_line()))
        .collect();
    let events: String = running
        .gateway
        .events()
        .iter()
        .map(|event| format!("{}\n", event.to_json()))
        .collect();
    let surfaces: Vec<(&'static str, Vec<u8>)> = vec![
        // The whole response and not only its head: a refusal carries no restored
        // answer, so nothing in it is meant to be a planted value.
        ("blocked_client_response", response.clone()),
        (
            "blocked_vault_file",
            std::fs::read(&running.vault_file).unwrap_or_default(),
        ),
        ("blocked_request_log_line", log.into_bytes()),
        ("blocked_proxy_event", events.into_bytes()),
    ];
    let mut surface_bytes = 0usize;
    for (name, bytes) in &surfaces {
        surface_bytes += bytes.len();
        for planted in &values {
            assert!(
                find(bytes, planted.value.as_bytes()).is_none(),
                "block mode: {} appears in {name}",
                planted.entity
            );
        }
        assert!(
            find(bytes, caller_credential().as_bytes()).is_none(),
            "block mode: the caller's credential appears in {name}"
        );
    }
    // The refusal names the **type**, which is what an operator needs to find the
    // rule, and the assertions above are what keep it from naming the value.
    let body = String::from_utf8_lossy(&response[head_end..]).into_owned();
    assert!(
        body.contains("IBAN"),
        "the refusal does not say which type was blocked: {body}"
    );

    BlockEvidence {
        rule: RULE,
        blocked_entity: "IBAN",
        status: 400,
        proxy_error: "entity_blocked",
        upstream_requests_recorded: reached_the_provider,
        planted_values: values.len(),
        surfaces_scanned: surfaces.iter().map(|(name, _)| *name).collect(),
        surface_bytes_scanned: surface_bytes,
    }
}

/// What the run under `mode = "block"` measured.
#[derive(Debug, serde::Serialize)]
struct BlockEvidence {
    rule: &'static str,
    blocked_entity: &'static str,
    status: u16,
    proxy_error: &'static str,
    /// Zero, and it is the claim rather than a statistic: a refusal that still
    /// sent the prompt would be the fail-open this component exists to refuse.
    upstream_requests_recorded: usize,
    planted_values: usize,
    surfaces_scanned: Vec<&'static str>,
    surface_bytes_scanned: usize,
}

/// What the positive control measured.
#[derive(Debug, serde::Serialize)]
struct UnresolvedEvidence {
    turns: usize,
    session_ttl_ms: u64,
    aliases_quoted_after_expiry: usize,
    /// Not zero, and that is the point: the counter claim 4 reads as zero on a
    /// clean run is a counter this build can raise.
    aliases_leaked: u64,
    aliases_restored: u64,
    /// `threat-model.md` R5: an alias that cannot be resolved is delivered as
    /// the model wrote it and nothing is made up for it.
    values_invented: usize,
}

/// The rung each type was reported on, read out of the event record.
///
/// The record is the run's own statement about its evidence, so checking the
/// alias against it is checking the two agree. A build whose report drifted from
/// what it minted fails the invariant rather than passing with a rung nobody
/// verified.
fn reported_rungs(event: &Value) -> BTreeMap<String, LadderRung> {
    let mut out = BTreeMap::new();
    let Some(by_type) = event["alias_stats"]["by_type"].as_object() else {
        return out;
    };
    for (tag, stat) in by_type {
        let rung = match stat["ladder_rung"].as_str() {
            Some("R") => LadderRung::Reserved,
            Some("I") => LadderRung::Invalid,
            Some("O") => LadderRung::Opaque,
            Some("L") => LadderRung::Label,
            other => panic!("{tag} reports a rung nothing defines: {other:?}"),
        };
        out.insert(tag.clone(), rung);
    }
    out
}
