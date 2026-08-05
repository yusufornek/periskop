#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
//! **F4 exit criterion 3.** The vault writes nothing outside this process in the
//! clear, demonstrated by searching for planted values byte by byte.
//!
//! `roadmap.md`'s third exit criterion for F4 is one sentence: the vault is local
//! and encrypted by default, and that it puts no plaintext outside the process is
//! *verified by a security test*. This is that test, and milestone 73 fixes what
//! it has to cover.
//!
//! # The surfaces
//!
//! | Surface | What is scanned |
//! |---|---|
//! | the vault file | every byte of `vault.psk` after a full lifecycle |
//! | temporary files | every other file the vault's directory ever holds, including a compaction candidate left behind by a process that was killed |
//! | `TRACE` level output | every `Debug` and `Display` rendering of every vault type a caller can reach, plus every refusal message |
//! | `/admin/*` responses | the body of `GET /admin/vault/status`, and of `GET /admin/policy` and `GET /admin/metrics` |
//! | the `ProxyEvent` record | the counters the vault contributes to it |
//! | `stdout` and `stderr` | everything a real child process that opens, loads and compacts a vault wrote to either stream |
//! | the HTTP response to the client | status, every header and the body of a real masked request |
//! | the request record | the line the proxy leaves behind for one request |
//! | the **streamed** response body | the server sent events of a real answer whose aliases could not be resolved |
//! | the **streamed** request record | the line left behind by a request whose answer *was* restored |
//!
//! Rows seven and eight arrived with task 85, in the same change that opened a
//! port. Before it there was nothing outside this process to reach; after it there
//! is a response travelling back over a socket and a per request record, and
//! neither is covered by any row above. They also carry a second planted value the
//! vault rows do not: the **caller's API key**, which `proxy/spec.md` section 2.3
//! says periskop never logs and which task 85 requires this byte sweep to cover.
//!
//! The last two rows arrived with tasks 89 to 93, which gave the component two
//! output surfaces it did not have: a response body **assembled by this process**
//! rather than forwarded, and a record line carrying the stream and restore
//! counters. Both are searched, from two deliberately different runs. The streamed
//! **body** comes from an exchange whose aliases resolve to nothing, because that
//! is the shape in which a value could reach a stream by accident
//! (`masking_unresolved`: the buffer holds and releases with no value to put in).
//! The streamed **record** comes from an exchange whose aliases *do* resolve, so
//! the restored plaintext is in this process while the line is written, and a
//! counter that started carrying the value it counts is found here.
//!
//! The last row was missing, and its absence was a hole in this gate rather than a
//! narrower claim: a single `dbg!(plaintext)` added to `record::seal` writes every
//! masked value to `stderr`, and none of the five surfaces above would have seen a
//! byte of it. The stream is captured from the child that leaves the compaction
//! candidate, so it is a real process's real output rather than a description of
//! one, and it is backed by `no_vault_source_writes_to_a_process_stream` plus the
//! crate level `deny` in `src/lib.rs`, because a leak on a code path this lifecycle
//! does not reach would still be a leak.
//!
//! # Two profiles, because one would prove something narrower
//!
//! `milestones.md` is explicit: the run has to happen under the shipped Argon2id
//! profile **and** under `--vault-profile ci`, "aksi hâlde kanıt CI profiline özgü
//! olur". Both are run here and the artefact records which ones were covered. A
//! machine that cannot spare 256 MiB skips the shipped profile loudly, and with
//! `PERISKOP_REQUIRE_PROOF` set it fails instead: that is the setting continuous
//! integration uses, and it is what stops the gate from being quietly narrowed.
//!
//! # What this test cannot cover yet, said out loud
//!
//! Two of the five surfaces do not exist as running code in this crate. There is
//! no logging framework, so "every `TRACE` line" is approximated by every
//! rendering a log line could contain, and there is no `ProxyEvent` type, so its
//! vault contribution is approximated by the counters. Approximations rot, so both
//! are backed by a structural guard: this test reads the crate's own manifest and
//! its own sources, and it **fails** the moment a logging dependency or a
//! serialisation derive appears on a vault type. Whoever adds either has to widen
//! the surface list here in the same change.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use periskop_proxy::vault::{
    AliasSeed, Backing, CounterFloor, OpenRequest, Passphrase, ProfileName, Restored, SessionId,
    Vault, VaultError,
};

/// Set in continuous integration so that a machine that cannot run the shipped
/// profile fails the gate instead of narrowing it. The same switch, and the same
/// reasoning, as `crates/periskop-cli/tests/proof.rs`.
const REQUIRE_PROOF: &str = "PERISKOP_REQUIRE_PROOF";

/// Set by this test on the child it spawns: where the vault to compact lives.
const CHILD_DIRECTORY: &str = "PERISKOP_NO_PLAINTEXT_CHILD_DIR";
/// How long the child waits, in microseconds, before terminating itself.
const CHILD_DELAY_US: &str = "PERISKOP_NO_PLAINTEXT_CHILD_DELAY_US";
/// Which Argon2id profile the child opens under.
const CHILD_PROFILE: &str = "PERISKOP_NO_PLAINTEXT_CHILD_PROFILE";
const KILLED: i32 = 70;
/// What the child prints once it has run every path that handles a plaintext.
const CHILD_MARK: &str = "periskop-child-sealed-unsealed-and-projected";

/// The values planted in the vault, and hunted for afterwards.
///
/// Synthetic, and deliberately so: `benchmarks.md`'s data rule and CLAUDE.md's
/// prohibition on periskop being an egress source both mean that no real personal
/// data goes into this repository. Each one is a distinctive byte string, long
/// enough that a chance match in a key, a nonce or a ciphertext is not a thing
/// that happens.
const PLANTED: &[(&str, &str)] = &[
    ("PERSON", "Zeynep Kucukates Ozdemir"),
    ("EMAIL", "zeynep.kucukates@ornek-firma-a.invalid"),
    ("IBAN", "TR889999888877776666555544"),
    ("PHONE", "+90 532 000 44 55"),
    ("NATIONAL_ID", "99988877766"),
    ("SECRET", "sk-periskop-synthetic-3f9a2b7c1d4e"),
    ("ADDRESS", "Kucukayasofya Mahallesi 41/7 Fatih"),
];

/// The alias each planted value is stored under.
///
/// Aliases are not secret: they are the strings that were sent to the provider,
/// and `proxy/spec.md` section 9 lists `alias` among the four fields `TRACE` may
/// carry. They are used here as the **positive control**: the same search that
/// must never find a planted value has to find these, or it is searching nothing.
fn alias_for(kind: &str) -> String {
    format!("PSK_{kind}_1")
}

const NOW: u64 = 1_700_000_000_000;
const LIVE: SessionId = SessionId::from_bytes([0x01; 16]);
const EXPIRED: SessionId = SessionId::from_bytes([0x02; 16]);

// ---------------------------------------------------------------------------
// The child, which leaves a compaction candidate on the disk by dying
// ---------------------------------------------------------------------------

/// A compaction that is killed part way, so that this test has a real temporary
/// file to search rather than a description of one.
///
/// The only way a candidate survives is a process that dies before the rename:
/// every failure path in `vault::compaction` removes it. So the temporary file
/// surface is produced the only way it occurs in the wild.
#[test]
#[ignore = "spawned by the gate below; it terminates itself on purpose"]
fn compaction_child_terminates_itself_mid_run() {
    let Some(directory) = std::env::var_os(CHILD_DIRECTORY) else {
        return;
    };
    let directory = PathBuf::from(directory);
    let delay_us: u64 = std::env::var(CHILD_DELAY_US)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let profile = std::env::var(CHILD_PROFILE)
        .ok()
        .and_then(|name| ProfileName::parse(&name))
        .expect("the parent passes a profile this build knows");

    let mut vault = open_vault(&directory, profile).expect("the parent wrote a vault");
    let at = NOW + vault.limits().ttl_ms + 2;

    // The child runs the whole lifecycle and not only the compaction, because the
    // stream it is spawned to produce is a surface: sealing and unsealing are where
    // a plaintext would be printed, and output captured from a process that never
    // sealed anything would cover neither. Found by mutation, and by nothing else:
    // an `eprintln!` of the plaintext in `record::seal` left this gate green while
    // the child only opened and compacted.
    //
    // Before the killer thread starts, so the delay below is still measured against
    // the compaction and this cannot fail part way.
    for (kind, value) in PLANTED {
        let alias = format!("PSK_{kind}_3");
        vault
            .store_alias(
                &LIVE,
                AliasSeed::from_bytes(seed_for(kind, 3)),
                &alias,
                value.as_bytes(),
                at,
            )
            .expect("the child can seal a record");
        let restored = vault.restore(&LIVE, &alias, at).expect("and open it again");
        assert!(matches!(restored, Restored::Value(_)));
    }
    let status = vault.status().to_json();
    assert!(status.contains("\"backend\":\"file\""), "{status}");
    // The positive control for the stream surface, written by this process after it
    // has sealed, unsealed and projected. If this line is missing from what the
    // parent captured, the capture is not working and the search proves nothing.
    eprintln!("{CHILD_MARK}");

    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_micros(delay_us));
        std::process::exit(KILLED);
    });
    let _ = vault.compact(at);
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

#[test]
fn f4_gate_no_planted_value_reaches_any_surface_outside_this_process() {
    let required = std::env::var_os(REQUIRE_PROOF).is_some();
    let mut covered = Vec::new();
    let mut skipped = Vec::new();

    for profile in [ProfileName::Ci, ProfileName::Standard] {
        match sweep(profile) {
            Ok(surfaces) => {
                check(profile, &surfaces);
                covered.push(profile.as_str());
            }
            Err(reason) => {
                // The only legitimate reason is a machine that cannot give
                // Argon2id its memory. It is never a reason to call the gate
                // passed, so it is recorded and, in continuous integration, fatal.
                assert!(
                    !required,
                    "{REQUIRE_PROOF} is set and the {} profile could not run: {reason}",
                    profile.as_str()
                );
                eprintln!(
                    "\n  NARROWED: the F4 vault plaintext gate did not run under the {} \
                     profile.\n  Reason: {reason}\n  This run does not close F4 exit criterion \
                     3. Set {REQUIRE_PROOF}=1 to make it a failure instead.\n",
                    profile.as_str()
                );
                skipped.push(profile.as_str());
            }
        }
    }

    // Both structural guards run once: they are about the crate rather than about
    // a profile.
    no_logging_dependency_has_appeared();
    no_vault_type_can_serialise_itself();
    no_vault_source_writes_to_a_process_stream();

    record_outcome(&covered, &skipped);
    assert!(
        covered.contains(&"ci"),
        "the reduced profile must always be runnable"
    );
}

/// The credential a client sends, planted so that the sweep covers it.
///
/// Assembled at run time for the reason `tests/no_credential_literals.rs` gives.
fn planted_credential() -> String {
    format!("sk-{}-{}", "proj", "5TnW8kJ2xQeR7bZmVhLdAcGu")
}

/// The surfaces task 85 added: a real masked request, and everything it leaves.
///
/// Drives one request through the gateway with every planted value in its body and
/// the credential in its `Authorization` header, then returns the response, the
/// request record and the three administrative bodies. The upstream request is
/// **not** returned as a surface, because the credential belongs there by contract
/// (`proxy/spec.md` section 2.3: unchanged to the provider); it is asserted here
/// instead, as the positive control that keeps the searches below meaningful.
fn http_surfaces() -> Result<Vec<(String, Vec<u8>)>, String> {
    use std::sync::Arc;

    use periskop_proxy::http::gateway::{Clock, Gateway, Incoming};
    use periskop_proxy::http::headers::{HeaderList, SESSION_HEADER};
    use periskop_proxy::http::upstream::{Recorder, Upstream};
    use periskop_proxy::http::AllowList;
    use periskop_proxy::policy::Policy;

    let policy = Policy::load(
        "policy_id = \"acme\"\npolicy_version = \"1\"\n[default]\nmode = \"mask\"\n",
        Path::new("."),
        None,
    )
    .map_err(|refusal| format!("{refusal}"))?;

    // The reduced profile: this helper is about the HTTP surface, and spending
    // 256 MiB again here would slow the gate without widening it. The shipped
    // profile is exercised by the vault half of this same sweep.
    let vault = open_vault(&Scratch::new("http").directory(), ProfileName::Ci)
        .map_err(|refusal| format!("{refusal}"))?;

    let upstream = Arc::new(Recorder::ok());
    let gateway = Gateway::new(
        policy,
        vault,
        Arc::clone(&upstream) as Arc<dyn Upstream>,
        AllowList::shipped(),
        Clock::Fixed(NOW),
    )
    .map_err(|refusal| refusal.detail().to_owned())?;

    let prompt = PLANTED
        .iter()
        .map(|(kind, value)| format!("{kind}: {value}"))
        .collect::<Vec<String>>()
        .join("\n");
    let request = Incoming {
        method: "POST".to_owned(),
        path: "/v1/chat/completions".to_owned(),
        query: None,
        headers: HeaderList::new()
            .with("authorization", format!("Bearer {}", planted_credential()))
            .with("x-api-key", planted_credential())
            .with(SESSION_HEADER, "the-sweep-s-conversation"),
        body: serde_json::json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": prompt}]
        })
        .to_string()
        .into_bytes(),
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|why| format!("no runtime: {why}"))?;

    let response = runtime.block_on(async {
        let response = gateway.handle(request).await;
        let admin = |path: &'static str| {
            gateway.handle(Incoming {
                method: "GET".to_owned(),
                path: path.to_owned(),
                query: None,
                headers: HeaderList::new(),
                body: Vec::new(),
            })
        };
        let policy_body = admin("/admin/policy").await;
        let status_body = admin("/admin/vault/status").await;
        let metrics_body = admin("/admin/metrics").await;
        (response, policy_body, status_body, metrics_body)
    });
    let (response, policy_body, status_body, metrics_body) = response;

    // The positive control. Without it, a gateway that refused every request would
    // produce clean surfaces and this whole helper would prove nothing.
    let calls = upstream.calls();
    let call = calls
        .first()
        .ok_or_else(|| "the sweep's request never reached the provider".to_owned())?;
    if call.headers.get("authorization")
        != Some(format!("Bearer {}", planted_credential()).as_str())
    {
        return Err(
            "the credential did not reach the provider unchanged, so the \
                    searches below are searching for something that was never sent"
                .to_owned(),
        );
    }

    let render = |response: &periskop_proxy::http::gateway::Outgoing| -> Vec<u8> {
        let headers: Vec<String> = response
            .headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}"))
            .collect();
        format!(
            "{}\n{}\n{}",
            response.status,
            headers.join("\n"),
            String::from_utf8_lossy(&response.body)
        )
        .into_bytes()
    };

    let mut surfaces = vec![
        ("http_response".to_owned(), render(&response)),
        (
            "http_request_record".to_owned(),
            gateway
                .log()
                .iter()
                .map(periskop_proxy::http::observe::RequestRecord::to_line)
                .collect::<Vec<String>>()
                .join("\n")
                .into_bytes(),
        ),
        ("http_admin_policy".to_owned(), render(&policy_body)),
        ("http_admin_vault_status".to_owned(), render(&status_body)),
        ("http_admin_metrics".to_owned(), render(&metrics_body)),
    ];
    surfaces.extend(stream_surfaces(&prompt, &render)?);
    Ok(surfaces)
}

/// The two surfaces the response state machine added (tasks 89 to 93).
///
/// Two runs, because the leak they can carry is a different one in each. The
/// first restores nothing and its **body** is searched; the second restores
/// everything and its **record** is searched while the plaintext is in the
/// process. Each carries its own positive control, or the search below would be
/// looking through bytes that never went near a value.
fn stream_surfaces(
    prompt: &str,
    render: &dyn Fn(&periskop_proxy::http::gateway::Outgoing) -> Vec<u8>,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    use std::sync::Arc;

    use periskop_proxy::http::gateway::{Clock, Gateway, Incoming};
    use periskop_proxy::http::headers::{HeaderList, SESSION_HEADER};
    use periskop_proxy::http::upstream::{Answer, Call, Pending, Recorder, Unreachable, Upstream};
    use periskop_proxy::http::AllowList;
    use periskop_proxy::policy::Policy;

    /// An upstream that streams the masked prompt back, cut every few bytes.
    ///
    /// The cuts are the point: they land inside aliases, so the hold buffer runs
    /// and the restored values are assembled by this process rather than
    /// forwarded from the provider.
    struct EchoesTheMaskedTextInSmallPieces;

    impl Upstream for EchoesTheMaskedTextInSmallPieces {
        fn send(&self, call: Call) -> Pending<'_> {
            let body: serde_json::Value =
                serde_json::from_slice(&call.body).unwrap_or(serde_json::Value::Null);
            let masked = body["messages"][0]["content"]
                .as_str()
                .unwrap_or_default()
                .replace('\n', " ");
            let mut chunks: Vec<Vec<u8>> = Vec::new();
            let mut at = 0usize;
            while at < masked.len() {
                let mut end = (at + 3).min(masked.len());
                while !masked.is_char_boundary(end) {
                    end += 1;
                }
                let piece = serde_json::json!({
                    "choices": [{"index": 0, "delta": {"content": masked[at..end]}}]
                });
                chunks.push(format!("data: {piece}\n\n").into_bytes());
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

    let build = |upstream: Arc<dyn Upstream>| -> Result<Gateway, String> {
        let policy = Policy::load(
            "policy_id = \"acme\"\npolicy_version = \"1\"\n[default]\nmode = \"mask\"\n",
            Path::new("."),
            None,
        )
        .map_err(|refusal| format!("{refusal}"))?;
        let vault = open_vault(&Scratch::new("stream").directory(), ProfileName::Ci)
            .map_err(|refusal| format!("{refusal}"))?;
        Gateway::new(
            policy,
            vault,
            upstream,
            AllowList::shipped(),
            Clock::Fixed(NOW),
        )
        .map_err(|refusal| refusal.detail().to_owned())
    };

    let request = |body: String| Incoming {
        method: "POST".to_owned(),
        path: "/v1/chat/completions".to_owned(),
        query: None,
        headers: HeaderList::new()
            .with("authorization", format!("Bearer {}", planted_credential()))
            .with(SESSION_HEADER, "the-sweep-s-stream"),
        body: body.into_bytes(),
    };
    let ask = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": prompt}]
    })
    .to_string();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|why| format!("no runtime: {why}"))?;

    // Run one: nothing resolves, and the body is the surface. The stub answers
    // with alias shaped strings this conversation never issued, which is the
    // `masking_unresolved` path.
    let unresolved_gateway = build(Arc::new(Recorder::streaming(vec![
        b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"about PSK_PER\"}}]}\n\n".to_vec(),
        b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"SON_1 and PSK_EMAIL_1\"}}]}\n\n"
            .to_vec(),
        b"data: [DONE]\n\n".to_vec(),
    ])) as Arc<dyn Upstream>)?;
    let unresolved =
        runtime.block_on(async { unresolved_gateway.handle(request(ask.clone())).await });

    // Run two: everything resolves, so the restored plaintext is in this process
    // while the record line is written.
    let restoring_gateway = build(Arc::new(EchoesTheMaskedTextInSmallPieces) as Arc<dyn Upstream>)?;
    let restored = runtime.block_on(async { restoring_gateway.handle(request(ask)).await });

    let restored_body = String::from_utf8_lossy(&restored.body).into_owned();
    let planted_in_the_stream = PLANTED
        .iter()
        .filter(|(_, value)| restored_body.contains(value))
        .count();
    if planted_in_the_stream == 0 {
        return Err(
            "no planted value came back out of the streamed answer, so the record \
             below was written by a run that restored nothing and searching it \
             proves nothing"
                .to_owned(),
        );
    }

    let line = |gateway: &Gateway| -> Vec<u8> {
        gateway
            .log()
            .iter()
            .map(periskop_proxy::http::observe::RequestRecord::to_line)
            .collect::<Vec<String>>()
            .join("\n")
            .into_bytes()
    };

    Ok(vec![
        ("http_stream_response".to_owned(), render(&unresolved)),
        (
            "http_stream_request_record".to_owned(),
            line(&restoring_gateway),
        ),
    ])
}

/// Runs a whole vault lifetime under one profile and collects every surface.
fn sweep(profile: ProfileName) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let scratch = Scratch::new(profile.as_str());
    let mut vault = open_vault(&scratch.directory(), profile).map_err(|refusal| {
        // A machine without the memory for the shipped profile lands here, and so
        // would a real defect; the message carries the difference.
        format!("{refusal}")
    })?;

    // Plant every value twice: once in a session that stays live and once in one
    // that compaction will drop, so both the surviving and the discarded halves of
    // the file are covered.
    for (kind, value) in PLANTED {
        vault
            .store_alias(
                &LIVE,
                AliasSeed::from_bytes(seed_for(kind, 1)),
                &alias_for(kind),
                value.as_bytes(),
                NOW + vault.limits().ttl_ms + 1,
            )
            .map_err(|refusal| format!("{refusal}"))?;
        vault
            .store_alias(
                &EXPIRED,
                AliasSeed::from_bytes(seed_for(kind, 2)),
                &format!("PSK_{kind}_2"),
                value.as_bytes(),
                NOW,
            )
            .map_err(|refusal| format!("{refusal}"))?;
    }

    let mut surfaces = BTreeMap::new();

    // The file as `store_alias` left it, **before** anything is compacted away.
    // Reading it only after a compaction would scan the survivors and miss
    // everything the rewrite dropped, which is half the records and the half more
    // likely to be forgotten: a leak that compaction happens to clean up is still
    // a leak that was on the disk. This snapshot is what a mutation writing a
    // value into a frame is caught by.
    for (name, bytes) in scratch.files() {
        surfaces.insert(format!("appended_file:{name}"), bytes);
    }

    surfaces.insert("renderings".to_owned(), renderings(&mut vault).into_bytes());
    surfaces.insert(
        "admin_vault_status".to_owned(),
        vault.status().to_json().into_bytes(),
    );
    // The HTTP surface, which did not exist when this sweep was written. Task 85
    // opened a port and gave the process a request record; both are places a
    // planted value or the caller's API key could reach, and neither is covered by
    // any row above. The three surfaces are collected by driving a whole masked
    // request through the gateway.
    for (name, bytes) in http_surfaces()? {
        surfaces.insert(name, bytes);
    }
    surfaces.insert(
        "proxy_event_counters".to_owned(),
        format!("{:?}", vault.counters()).into_bytes(),
    );

    // A compaction, so that the file has been rewritten from `M_0` as well as
    // appended to: both shapes of write are covered.
    let at = NOW + vault.limits().ttl_ms + 2;
    vault.compact(at).map_err(|refusal| format!("{refusal}"))?;
    drop(vault);

    // And a compaction that was killed, so that a real leftover candidate is on
    // the disk when the directory is read.
    let Killed { candidate, output } = leave_a_candidate(&scratch, profile)?;
    for (name, bytes) in scratch.files() {
        surfaces.insert(format!("file:{name}"), bytes);
    }
    let candidate_bytes = scratch
        .files()
        .remove(&candidate)
        .ok_or_else(|| "the killed compaction left no candidate to search".to_owned())?;
    // Named separately from the `file:` sweep above so that `check` can apply the
    // positive control to this surface specifically. It is the file most likely to
    // hold a leak and the one whose contents this test controls least.
    surfaces.insert("candidate_file".to_owned(), candidate_bytes);

    // Everything that child wrote to either stream while it opened a vault, loaded
    // every record out of it and rebuilt the file from `M_0`.
    surfaces.insert("process_output".to_owned(), output);

    Ok(surfaces)
}

/// Asserts the claim, on every surface, for every planted value.
fn check(profile: ProfileName, surfaces: &BTreeMap<String, Vec<u8>>) {
    // A scan over nothing passes, so first: there is something to scan.
    assert!(
        surfaces.len() >= 5,
        "{} profile: only {} surfaces collected",
        profile.as_str(),
        surfaces.len()
    );
    for (name, bytes) in surfaces {
        assert!(
            !bytes.is_empty(),
            "{} profile: the {name} surface is empty",
            profile.as_str()
        );
    }

    // The positive control. The same search, on the same surfaces, has to find
    // the aliases: they are in the vault file in the clear by design, and a search
    // that could not find them could not find a plaintext either. Both snapshots
    // of the file are controlled, because a surface that turned out to be empty or
    // stale would make the claim below vacuous on exactly the bytes it covers.
    for name in ["file:vault.psk", "appended_file:vault.psk"] {
        let vault_file = surfaces
            .get(name)
            .unwrap_or_else(|| panic!("{name} is a surface"));
        for (kind, _) in PLANTED {
            assert!(
                contains(vault_file, alias_for(kind).as_bytes()),
                "{} profile: the search cannot find the alias {} in {name}, so it is proving nothing",
                profile.as_str(),
                alias_for(kind)
            );
        }
    }
    // The pre compaction snapshot has to hold the records compaction drops, or it
    // is not the snapshot it claims to be.
    assert!(
        contains(
            surfaces
                .get("appended_file:vault.psk")
                .expect("the appended file is a surface"),
            b"PSK_PERSON_2"
        ),
        "{} profile: the pre compaction snapshot is missing the records compaction drops",
        profile.as_str()
    );
    assert!(
        contains(
            surfaces
                .get("renderings")
                .expect("the renderings are a surface"),
            b"<redacted>"
        ),
        "the renderings surface is not what it claims to be"
    );

    // The temporary file surface, controlled the same way as the vault file. A
    // candidate holding only its 128 byte header is a file the kill landed before
    // any record reached it, and searching it proves nothing about the surface it
    // stands for; requiring an alias in it is what makes the search meaningful.
    let candidate = surfaces
        .get("candidate_file")
        .expect("the killed compaction's candidate is a surface");
    assert!(
        contains(candidate, alias_for("PERSON").as_bytes()),
        "{} profile: the compaction candidate carries no record, so scanning it proves nothing",
        profile.as_str()
    );

    // And the process output surface: the child's own harness line proves the
    // stream was captured rather than lost to an inherited descriptor.
    let output = surfaces
        .get("process_output")
        .expect("the child's output is a surface");
    assert!(
        contains(output, CHILD_MARK.as_bytes()),
        "{} profile: the child's own output was not captured, so scanning it proves \
         nothing. The harness buffers a test's output and `process::exit` discards \
         the buffer, so the child has to be run with --nocapture.",
        profile.as_str()
    );

    // The four HTTP surfaces task 85 added. Controlled the same way as the rest:
    // a response with no headers or an empty log would pass every search below
    // without carrying anything.
    for (name, marker) in [
        ("http_response", &b"x-periskop-alias-scope"[..]),
        ("http_request_record", b"alias_scope="),
        ("http_admin_policy", b"masking_profile"),
        ("http_admin_vault_status", b"vault_state"),
        ("http_admin_metrics", b"periskop_proxy_requests_total"),
        // The streaming rows. The body has to be a stream that actually carried
        // an unresolved alias, and the record has to carry the restore counters,
        // or neither is the surface it claims to be.
        ("http_stream_response", b"data: "),
        ("http_stream_request_record", b"aliases_restored="),
    ] {
        let surface = surfaces
            .get(name)
            .unwrap_or_else(|| panic!("{name} is a surface"));
        assert!(
            contains(surface, marker),
            "{} profile: the {name} surface is not what it claims to be, so searching \
             it proves nothing",
            profile.as_str()
        );
    }

    // The claim.
    for (kind, value) in PLANTED {
        for (name, bytes) in surfaces {
            assert!(
                !contains(bytes, value.as_bytes()),
                "{} profile: the planted {kind} value reached the {name} surface in the clear",
                profile.as_str()
            );
        }
    }

    // And the same claim for the caller's credential, which task 85 requires this
    // sweep to cover. It is checked against every surface rather than only the new
    // ones: a key that ended up in a vault record or in a `Debug` rendering would
    // be exactly as leaked as one in a log line.
    for (name, bytes) in surfaces {
        assert!(
            !contains(bytes, planted_credential().as_bytes()),
            "{} profile: the caller's API key reached the {name} surface. \
             `proxy/spec.md` section 2.3: periskop does not store, mint or log a key",
            profile.as_str()
        );
    }
}

/// Every rendering of every vault type a caller can reach.
///
/// This stands in for `TRACE` level output: there is no logging framework in this
/// crate yet, so what a log line could carry is exactly what these produce.
/// `proxy/spec.md` section 9 allows four fields at `TRACE` (`entity_type`,
/// `alias`, `offset`, `confidence`) and puts vault content outside every level.
fn renderings(vault: &mut Vault) -> String {
    let mut out = String::new();
    let mut push = |value: String| {
        out.push_str(&value);
        out.push('\n');
    };

    push(format!("{vault:?}"));
    push(format!("{:?}", vault.status()));
    push(format!("{:?}", vault.counters()));
    push(format!("{:?}", vault.storage()));
    push(format!("{:?}", vault.limits()));
    push(format!("{:?}", vault.notes()));
    for note in vault.notes() {
        push(note.to_string());
    }
    push(format!(
        "{:?}",
        Passphrase::new(PLANTED[0].1.as_bytes().to_vec())
    ));

    // A session and the key alias derivation runs under.
    if let Ok(session) = vault.open_session(&LIVE, NOW) {
        push(format!("{session:?}"));
        push(format!("{:?}", session.session_key()));
    }

    // Both answers a restore can give, including the one that carries a value.
    for (kind, _) in PLANTED {
        match vault.restore(&LIVE, &alias_for(kind), NOW) {
            Ok(answer) => {
                if let Restored::Value(value) = &answer {
                    push(format!("{value:?}"));
                }
                push(format!("{answer:?}"));
            }
            Err(refusal) => {
                push(format!("{refusal:?}"));
                push(refusal.to_string());
            }
        }
    }
    push(format!(
        "{:?}",
        vault.restore(&LIVE, "PSK_PERSON_NOBODY", NOW)
    ));

    // Every refusal the vault can produce, rendered both ways. An error message is
    // a log line and a response body at the same time.
    for refusal in refusals() {
        push(format!("{refusal:?}"));
        push(refusal.to_string());
    }
    out
}

/// One of every `VaultError`, so the scan covers all of them rather than the ones
/// this lifecycle happened to produce.
fn refusals() -> Vec<VaultError> {
    vec![
        VaultError::PassphraseMissing,
        VaultError::KeyDerivationFailed,
        VaultError::EntropyUnavailable,
        VaultError::RecordTamper,
        VaultError::AliasCollision,
        VaultError::AliasCeilingReached { ceiling: 10_000 },
        VaultError::KdfParameterOutOfRange {
            parameter: "memory",
            claimed: 1,
            floor: 2,
            ceiling: 3,
        },
        VaultError::IntegrityFailed {
            integrity: periskop_proxy::vault::Integrity::ChainMismatch,
        },
        VaultError::VaultFileMalformed {
            field: periskop_proxy::vault::VaultField::Magic,
        },
        VaultError::VaultFileUnsupported {
            field: periskop_proxy::vault::VaultField::LayoutVersion,
            found: 2000,
        },
        VaultError::VaultFileUnavailable {
            operation: "opened",
            cause: "PermissionDenied".to_owned(),
        },
    ]
}

// ---------------------------------------------------------------------------
// The structural guards
// ---------------------------------------------------------------------------

/// The surface list above is complete only while there is no logger.
///
/// The moment one is added, `TRACE` output stops being "whatever a `Debug` would
/// have printed" and becomes a real stream with its own sinks and its own files.
/// This fails then, on purpose, so that the person adding it extends the sweep
/// rather than inheriting a gate that quietly covers less than it says.
fn no_logging_dependency_has_appeared() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("this crate has a manifest");
    let named = dependency_names(&manifest);

    // A parser that read nothing would pass this guard for every logger ever
    // added, so first: it reads this manifest. `zeroize` is declared here in the
    // `name = { workspace = true }` form, and the two forms the previous reading
    // missed are covered by `the_manifest_reader_sees_every_form_a_dependency_is_written_in`.
    assert!(
        named.contains("zeroize"),
        "the manifest reader found no dependency it should have: {named:?}"
    );

    for logger in [
        "tracing",
        "log",
        "slog",
        "env_logger",
        "fern",
        "tracing-subscriber",
    ] {
        assert!(
            !named.contains(logger),
            "`{logger}` is a dependency of this crate now, so TRACE output is a real \
             surface. Add its sink to the sweep in this test before removing this check."
        );
    }
}

/// The names of the crates a manifest depends on, in every form Cargo accepts.
///
/// This used to be `line.split_once('=')` over every line, and that reading was
/// wrong in the two ways this repository actually writes manifests. `tracing.workspace
/// = true` produced the name `"tracing.workspace"`, which matches no entry in the
/// list above; and `[dependencies.tracing]` contains no `=` at all, so the line was
/// discarded before it was compared. Both are idiomatic Cargo and the first is the
/// form `periskop-proxy/Cargo.toml` already uses for every one of its dependencies,
/// so the way past the gate was the ordinary way to add a dependency.
///
/// Renames are read too: `quiet = { package = "tracing" }` declares `tracing` under
/// another name, and a guard that missed that would be asking the next person to
/// pick a different key rather than to widen the sweep.
fn dependency_names(manifest: &str) -> BTreeSet<String> {
    /// The table headers under which a name is a crate this build links.
    const KINDS: &[&str] = &["dependencies", "dev-dependencies", "build-dependencies"];

    let mut names = BTreeSet::new();
    let mut inside_a_dependency_table = false;

    for line in manifest.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(header) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            let segments: Vec<&str> = header
                .trim_matches('[')
                .trim_matches(']')
                .split('.')
                .collect();
            let last = segments.last().copied().unwrap_or_default();
            let second_last = segments.iter().rev().nth(1).copied().unwrap_or_default();

            // `[dependencies]`, `[dev-dependencies]`, `[target.'cfg(unix)'.dependencies]`:
            // what follows is one key per crate.
            inside_a_dependency_table = KINDS.contains(&last);
            // `[dependencies.tracing]`: the header itself names the crate, and what
            // follows are that crate's own settings rather than more crates.
            if KINDS.contains(&second_last) {
                names.insert(unquote(last).to_owned());
            }
            continue;
        }

        if !inside_a_dependency_table {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        // `tracing.workspace = true` is a key path, and the crate is its first
        // segment. `"tracing" = "0.1"` is the quoted form of the same thing.
        let name = unquote(key.trim().split('.').next().unwrap_or_default());
        if !name.is_empty() {
            names.insert(name.to_owned());
        }
        if let Some(renamed) = package_name(value) {
            names.insert(renamed.to_owned());
        }
    }
    names
}

/// The crate a `package = "..."` key inside an inline table renames.
fn package_name(value: &str) -> Option<&str> {
    let after = value.split_once("package")?.1;
    let quoted = after.split_once('"')?.1;
    quoted.split_once('"').map(|(name, _)| name)
}

fn unquote(text: &str) -> &str {
    text.trim().trim_matches('"').trim_matches('\'')
}

/// Nothing under `src/vault/` writes to a process stream.
///
/// This is the guard the `stdout` and `stderr` row of the table above stands on.
/// The sweep can only search the output of the paths it happens to run, and a
/// `dbg!` left in a branch this lifecycle does not reach would leak on somebody
/// else's request while every surface here stayed clean. `src/lib.rs` denies these
/// lints for the whole crate, which is the enforcement; this scan is what catches
/// the `#[allow]` that would turn the denial off again, and it reads the same
/// sources the vault's other boundary test reads.
fn no_vault_source_writes_to_a_process_stream() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/vault");
    let mut sources = Vec::new();
    collect_sources(&root, &mut sources);
    assert!(
        sources.len() >= 8,
        "only {} vault sources found under {}",
        sources.len(),
        root.display()
    );

    // `panic!` is absent from this list because the workspace already denies
    // `clippy::panic` outside test modules, which is a stronger check than a name
    // scan. Everything here is a macro or a call clippy does not deny by default.
    const STREAMS: &[&str] = &[
        "println!",
        "print!",
        "eprintln!",
        "eprint!",
        "dbg!",
        "io::stdout",
        "io::stderr",
        "allow(clippy::print_stdout",
        "allow(clippy::print_stderr",
        "allow(clippy::dbg_macro",
    ];

    let mut offences = Vec::new();
    for source in &sources {
        let text = std::fs::read_to_string(source).expect("a vault source");
        for (number, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            for stream in STREAMS {
                if code.contains(stream) {
                    offences.push(format!(
                        "{}:{} names {stream}",
                        source.file_name().unwrap_or_default().to_string_lossy(),
                        number + 1
                    ));
                }
            }
        }
    }
    assert!(
        offences.is_empty(),
        "a vault source writes to a process stream, which is a surface this gate \
         searches only where the lifecycle above happens to reach: {offences:#?}"
    );
}

/// The `ProxyEvent` surface is a projection, and it stays one only while no vault
/// type can serialise itself.
///
/// The event record is written by a later task. If a vault type ever derives
/// `Serialize`, an event could carry a record without anybody deciding to, which
/// is exactly the shape of accident this gate exists to catch.
fn no_vault_type_can_serialise_itself() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/vault");
    let mut sources = Vec::new();
    collect_sources(&root, &mut sources);
    assert!(
        sources.len() >= 8,
        "only {} vault sources found under {}",
        sources.len(),
        root.display()
    );

    let mut offences = Vec::new();
    for source in &sources {
        let text = std::fs::read_to_string(source).expect("a vault source");
        for (number, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            for marker in ["Serialize", "Deserialize", "serde"] {
                if code.contains(marker) {
                    offences.push(format!(
                        "{}:{} names {marker}",
                        source.file_name().unwrap_or_default().to_string_lossy(),
                        number + 1
                    ));
                }
            }
        }
    }
    assert!(
        offences.is_empty(),
        "a vault type can serialise itself, so a ProxyEvent could carry one: {offences:#?}"
    );
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

fn open_vault(directory: &Path, profile: ProfileName) -> Result<Vault, VaultError> {
    Vault::open(&OpenRequest {
        passphrase: &Passphrase::new(b"the operator typed this".to_vec()),
        profile,
        backing: Backing::File {
            path: &directory.join("vault.psk"),
            floor: CounterFloor::Unknown,
        },
    })
}

fn seed_for(kind: &str, salt: u8) -> [u8; 32] {
    let mut seed = [salt; 32];
    for (at, byte) in kind.bytes().enumerate().take(31) {
        seed[at + 1] = byte;
    }
    seed
}

/// What a killed compaction run left behind.
struct Killed {
    /// The name of the candidate file it did not get to rename.
    candidate: String,
    /// Everything it wrote to `stdout` and `stderr`, in that order.
    output: Vec<u8>,
}

/// Kills a compaction until a usable candidate is left behind.
///
/// Retried rather than timed: the window is short and a machine under load may
/// miss it, and a gate that skipped a surface because the timing did not work out
/// would be a gate that covers less on a busy day than on a quiet one.
///
/// "Usable" is the load bearing word. A candidate is only accepted once it carries
/// a record, because the surface this produces is searched for planted values and
/// a file holding nothing but a header would make that search pass while covering
/// no record at all. `LOOKED_FOR` is an alias, which is in the candidate in the
/// clear by design and is therefore the positive control the caller re-checks.
fn leave_a_candidate(scratch: &Scratch, profile: ProfileName) -> Result<Killed, String> {
    // The alias of a record that survives compaction, so it has to be in any
    // candidate that got as far as writing records at all.
    let looked_for = alias_for("PERSON");
    let before: Vec<String> = scratch.files().into_keys().collect();

    for delay_us in [100u64, 250, 500, 900, 1_400, 2_200, 3_500, 5_000, 8_000] {
        let run = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "compaction_child_terminates_itself_mid_run",
                "--ignored",
                // Without this the harness buffers the child's own output and
                // `process::exit` throws the buffer away, so the stream this test
                // captures would be the harness's summary and never a line the
                // vault wrote. Found by mutation: an `eprintln!` of the plaintext
                // in `record::seal` went straight past a capture without it.
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_DIRECTORY, scratch.directory())
            .env(CHILD_DELAY_US, delay_us.to_string())
            .env(CHILD_PROFILE, profile.as_str())
            .output()
            .map_err(|cause| format!("{cause}"))?;
        assert_eq!(
            run.status.code(),
            Some(KILLED),
            "the child ended some other way: {}",
            String::from_utf8_lossy(&run.stderr)
        );

        // A candidate that holds no record is a file the kill landed before the
        // records reached it. It is a real outcome and a useless surface, so the
        // search keeps going until there is a record to look through.
        let found = scratch
            .files()
            .into_iter()
            .find(|(name, bytes)| !before.contains(name) && contains(bytes, looked_for.as_bytes()));
        if let Some((candidate, _)) = found {
            let mut output = run.stdout;
            output.extend_from_slice(&run.stderr);
            return Ok(Killed { candidate, output });
        }

        // Whatever this run left is not a surface; clear it so the next attempt
        // starts from the same place.
        for name in scratch.files().into_keys() {
            if !before.contains(&name) {
                std::fs::remove_file(scratch.directory().join(&name)).map_err(|cause| {
                    format!("a stale candidate {name} could not be cleared: {cause}")
                })?;
            }
        }
    }
    Err("no run of the killed compaction left a candidate holding a record".to_owned())
}

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "periskop-vault-plaintext-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("vault")).unwrap();
        Self { root }
    }

    fn directory(&self) -> PathBuf {
        self.root.join("vault")
    }

    /// Every file under the vault's directory, by name and by content.
    fn files(&self) -> BTreeMap<String, Vec<u8>> {
        let mut found = BTreeMap::new();
        collect_files(&self.directory(), &mut found);
        found
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn collect_files(root: &Path, found: &mut BTreeMap<String, Vec<u8>>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, found);
        } else if let Ok(bytes) = std::fs::read(&path) {
            found.insert(
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                bytes,
            );
        }
    }
}

fn collect_sources(root: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_sources(&path, found);
        } else if path.extension().is_some_and(|kind| kind == "rs") {
            found.push(path);
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// What this run established, written where a release check can read it.
///
/// A gate that ran under one profile and a gate that ran under both leave the same
/// green line in the test output, so the difference goes in a file. The planted
/// values are counted rather than listed: an artefact that carried them would be
/// the leak this test is about.
fn record_outcome(covered: &[&str], skipped: &[&str]) {
    let status = if skipped.is_empty() {
        "passed"
    } else {
        "narrowed"
    };
    let list = |names: &[&str]| {
        names
            .iter()
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(",")
    };

    let record = format!(
        "{{\n  \"gate\": \"F4-73\",\n  \"criterion\": \"roadmap.md F4 exit criterion 3\",\n  \
         \"status\": \"{status}\",\n  \"profiles_covered\": [{}],\n  \"profiles_skipped\": [{}],\n  \
         \"planted_values\": {},\n  \"surfaces\": [\"vault_file\",\"temporary_files\",\
         \"renderings\",\"admin_vault_status\",\"proxy_event_counters\",\
         \"process_stdout_and_stderr\",\"http_response\",\"http_request_record\",\
         \"http_stream_response\",\"http_stream_request_record\"],\n  \
         \"caveat\": \"There is no logging framework and no ProxyEvent type in this crate yet. \
         The TRACE surface is approximated by every Debug and Display rendering a log line could \
         contain, and the event surface by the counters the vault contributes. Both are held in \
         place by structural guards that fail when a logger or a serialisation derive appears.\"\n}}\n",
        list(covered),
        list(skipped),
        PLANTED.len()
    );

    let out =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/f4-vault-no-plaintext-proof.json");
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|cause| panic!("{} could not be created: {cause}", parent.display()));
    }
    // Not a discarded result. The whole reason this file exists is that a run
    // covering one profile and a run covering both leave the same green line in
    // the output, so a write that failed and said nothing would put the gate back
    // exactly where it was before the artefact was added.
    std::fs::write(&out, record)
        .unwrap_or_else(|cause| panic!("{} could not be written: {cause}", out.display()));
}

/// The control for the reader above: every way this workspace writes a dependency
/// is a way it is seen.
///
/// Each of these is a manifest that declares `tracing`, and each of the last three
/// went straight past the previous reading. The first two are the forms
/// `periskop-proxy/Cargo.toml` and the workspace root already use, which is what
/// made the escape route the idiomatic route rather than an exotic one.
#[test]
fn the_manifest_reader_sees_every_form_a_dependency_is_written_in() {
    for manifest in [
        "[dependencies]\ntracing = \"0.1\"\n",
        "[dependencies]\ntracing = { workspace = true }\n",
        "[dependencies]\ntracing.workspace = true\n",
        "[dependencies]\ntracing.version = \"0.1\"\ntracing.features = []\n",
        "[dependencies.tracing]\nworkspace = true\n",
        "[dev-dependencies.tracing]\nversion = \"0.1\"\n",
        "[target.'cfg(unix)'.dependencies]\ntracing.workspace = true\n",
        "[target.'cfg(unix)'.dependencies.tracing]\nworkspace = true\n",
        "[dependencies]\nquiet = { package = \"tracing\", version = \"0.1\" }\n",
    ] {
        assert!(
            dependency_names(manifest).contains("tracing"),
            "this manifest declares tracing and the reader did not see it:\n{manifest}"
        );
    }

    // And it does not invent one. A guard that answered yes to everything would
    // fail the moment anybody touched the manifest, and a guard that cries wolf is
    // a guard somebody deletes.
    for manifest in [
        "# tracing would be a dependency here\n[dependencies]\nzeroize.workspace = true\n",
        "[package]\nname = \"tracing\"\n",
        "[features]\ntracing = []\n",
        "[dependencies.zeroize]\nworkspace = true\n",
    ] {
        assert!(
            !dependency_names(manifest).contains("tracing"),
            "the reader invented a dependency:\n{manifest}"
        );
    }
}
