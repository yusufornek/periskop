#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
//! **Milestone 94.** The `ProxyEvent` record: shaped by the contract, carrying no
//! value, and with no way out of this process.
//!
//! Four claims, and each one is checked against something outside this file
//! rather than against a copy of it:
//!
//! | Claim | Checked against |
//! |---|---|
//! | the record satisfies `proxy-event.schema.json` | the schema file itself, read at test time |
//! | the same request twice produces the same bytes | two runs on a pinned clock |
//! | the body carries no wall clock and no float | the produced document |
//! | nothing sends the record anywhere | the crate's own sources, plus a recorded upstream |
//!
//! # Why the schema is read rather than restated
//!
//! There is no JSON Schema validator in this workspace and adding one needs an
//! ADR (CLAUDE.md, "Dil ve teknoloji sınırları"). The alternative that was **not**
//! taken is a list of expected field names written out here: that list is a copy
//! of the contract, it drifts the first time the schema changes, and it drifts
//! silently because both files stay green. So this file reads
//! `schemas/proxy-event.schema.json` and walks it. The subset it implements is
//! the subset that schema uses, and `the_validator_rejects_what_the_schema_says_it_should`
//! is the control that stops the walk from becoming a function that returns
//! `Ok(())`.
//!
//! # The egress claim
//!
//! `proxy-events.md`: "Olay kayıtları hiçbir koşulda dışarı gönderilmez." Two
//! halves. The structural half is a source scan: `ProxyEvent` is named in three
//! files under `src/` and a fourth means somebody wired it into something, which
//! is the change that has to be looked at. The behavioural half drives a real
//! masked request and asserts the record's own field names appear in neither the
//! bytes that went to the provider nor the bytes that went back to the client.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use regex::Regex;
use serde_json::Value;

use periskop_proxy::http::gateway::{Clock, Gateway, Incoming};
use periskop_proxy::http::headers::{HeaderList, SESSION_HEADER};
use periskop_proxy::http::upstream::{Recorder, Upstream};
use periskop_proxy::http::AllowList;
use periskop_proxy::policy::Policy;
use periskop_proxy::vault::{Backing, OpenRequest, Passphrase, ProfileName, Vault};

const NOW: u64 = 1_700_000_000_000;

/// Synthetic values planted in the prompt, and hunted for in the record.
///
/// The same discipline as `tests/vault_no_plaintext.rs`: distinctive byte strings
/// long enough that a chance match in a hash or an alias is not a thing that
/// happens, and invented rather than borrowed from anybody. Each one is a type
/// layer A actually claims, checksum included, because a value the detector walks
/// past is a value that never enters this record and searching for it would prove
/// nothing.
///
/// Assembled at run time for the reason `tests/no_credential_literals.rs` gives.
fn planted() -> Vec<String> {
    vec![
        format!("TR{}", "330006100519786457841326"),
        "zeynep.kucukates@ornek-firma-a.invalid".to_owned(),
        format!("+90 {} {} {}", "532", "000", "4455"),
    ]
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn policy(extra: &str) -> Policy {
    let text = format!(
        "policy_id = \"acme\"\npolicy_version = \"2026.08.1\"\n{extra}\n[default]\nmode = \"mask\"\n"
    );
    Policy::load(&text, Path::new("."), None).unwrap_or_else(|refusal| panic!("{refusal}"))
}

fn vault() -> Vault {
    Vault::open(&OpenRequest {
        passphrase: &Passphrase::new(b"an operator's passphrase".to_vec()),
        // The reduced profile: this file is about the shape of a record, and
        // spending 256 MiB on key derivation would slow it without widening it.
        // The shipped profile is exercised by the byte sweep.
        profile: ProfileName::Ci,
        backing: Backing::Memory,
    })
    .unwrap_or_else(|refusal| panic!("{refusal}"))
}

fn prompt() -> String {
    planted().join(" and ")
}

fn ask(prompt: &str) -> Incoming {
    Incoming {
        method: "POST".to_owned(),
        path: "/v1/chat/completions".to_owned(),
        query: None,
        headers: HeaderList::new()
            .with("authorization", "Bearer not-a-real-key")
            .with(SESSION_HEADER, "the-event-test-s-conversation"),
        body: serde_json::json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": prompt}]
        })
        .to_string()
        .into_bytes(),
    }
}

/// One masked round trip, and everything it left behind.
struct Run {
    events: Vec<Value>,
    upstream: Arc<Recorder>,
    response: Vec<u8>,
}

fn run(extra: &str) -> Run {
    let upstream = Arc::new(Recorder::ok());
    let gateway = Gateway::new(
        policy(extra),
        vault(),
        Arc::clone(&upstream) as Arc<dyn Upstream>,
        AllowList::shipped(),
        // Pinned, which is what makes the determinism claim checkable: the phase
        // timings and the total are read off this clock.
        Clock::Fixed(NOW),
    )
    .unwrap_or_else(|refusal| panic!("{}", refusal.detail()));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let response = runtime.block_on(async { gateway.handle(ask(&prompt())).await });

    Run {
        events: gateway
            .events()
            .iter()
            .map(|event| serde_json::from_str(&event.to_json()).unwrap())
            .collect(),
        upstream,
        response: response.body,
    }
}

fn one_event(extra: &str) -> Value {
    let run = run(extra);
    assert_eq!(
        run.events.len(),
        1,
        "one masked request produced {} records",
        run.events.len()
    );
    run.events.into_iter().next().unwrap()
}

// ---------------------------------------------------------------------------
// The claims
// ---------------------------------------------------------------------------

#[test]
fn a_masked_round_trip_produces_a_record_the_schema_accepts() {
    let event = one_event("");
    let schema = schema();
    validate(&schema, &event, "$").unwrap_or_else(|why| {
        panic!("the record does not satisfy proxy-event.schema.json: {why}\n{event:#}")
    });

    // And it is the record of the request that was made, not an empty shell that
    // would satisfy the schema while measuring nothing.
    assert_eq!(event["masking_profile"], "pattern+dictionary");
    assert_eq!(event["policy_version"], "2026.08.1");
    assert!(
        event["entities_masked"]
            .as_array()
            .is_some_and(|masked| !masked.is_empty()),
        "the run masked nothing, so every search below is searching an empty record: {event:#}"
    );
    assert!(event["degraded_reasons"]
        .as_array()
        .unwrap()
        .contains(&Value::String("ner_disabled".to_owned())));
}

#[test]
fn an_allowed_entity_is_counted_with_the_rule_that_let_it_through() {
    // `proxy-events.md`: mode = allow is not silent. The count and the expression
    // arrive together, or the operator learns that something crossed and not
    // which line said it could.
    let event =
        one_event("[[rule]]\nentity = \"IBAN\"\nmode = \"allow\"\nscope = \"messages[*].content\"");
    let allowed = event["entities_allowed"].as_array().unwrap();
    let iban = allowed
        .iter()
        .find(|entry| entry["type"] == "IBAN")
        .unwrap_or_else(|| panic!("an allowed IBAN was not counted: {event:#}"));
    assert_eq!(iban["count"], 1);
    assert_eq!(iban["rule_scope"], "messages[*].content");

    // The default answers with a name nobody can mistake for a scope expression.
    let default = one_event("[[rule]]\nentity = \"IBAN\"\nmode = \"allow\"");
    let iban = default["entities_allowed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["type"] == "IBAN")
        .unwrap();
    assert_eq!(iban["rule_scope"], "*");
}

#[test]
fn the_same_request_twice_produces_the_same_bytes() {
    // Two separate gateways, two separate vaults, one pinned clock. The vault's
    // key material and its nonces are random per run, so anything of the vault
    // that reached this record would show up here as a diff.
    let one = one_event("");
    let other = one_event("");
    assert_eq!(
        serde_json::to_string_pretty(&one).unwrap(),
        serde_json::to_string_pretty(&other).unwrap()
    );
}

#[test]
fn the_record_carries_no_wall_clock_and_no_floating_point() {
    let event = one_event("");
    let mut floats = Vec::new();
    let mut suspicious = Vec::new();
    walk(&event, "$", &mut |path, node| {
        if node.as_f64().is_some() && !node.is_i64() && !node.is_u64() {
            floats.push(path.to_owned());
        }
    });
    for key in ["generated_at", "timestamp", "host", "started_at", "at"] {
        if event.get(key).is_some() {
            suspicious.push(key);
        }
    }
    assert!(floats.is_empty(), "a duration is a float: {floats:?}");
    assert!(
        suspicious.is_empty(),
        "the body carries a wall clock field: {suspicious:?}"
    );

    // The one number that is a duration on a pinned clock, checked rather than
    // assumed: a record whose timings came from `SystemTime` would be non zero
    // here on a machine slow enough, and the determinism test above would go
    // flaky rather than red.
    assert_eq!(event["latency_ms"]["total"], 0);
    assert_eq!(event["latency_ms"]["detect"], 0);
}

#[test]
fn a_request_that_belongs_to_no_conversation_leaves_no_record() {
    // An administrative endpoint is a request and is not a request **and
    // response pair** in the sense this record measures. It produces no event,
    // and nothing is lost: `RequestRecord` still covers it. The alternative is a
    // placeholder `session_scope`, which is a measurement of a conversation that
    // did not happen.
    let upstream = Arc::new(Recorder::ok());
    let gateway = Gateway::new(
        policy(""),
        vault(),
        Arc::clone(&upstream) as Arc<dyn Upstream>,
        AllowList::shipped(),
        Clock::Fixed(NOW),
    )
    .unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        for path in ["/admin/policy", "/admin/vault/status", "/admin/metrics"] {
            gateway
                .handle(Incoming {
                    method: "GET".to_owned(),
                    path: path.to_owned(),
                    query: None,
                    headers: HeaderList::new(),
                    body: Vec::new(),
                })
                .await;
        }
    });
    assert!(
        gateway.events().is_empty(),
        "an administrative request was measured as a conversation"
    );
    assert_eq!(
        gateway.log().len(),
        3,
        "and the requests themselves went unrecorded, which is the other failure"
    );
}

#[test]
fn no_planted_value_reaches_any_field_of_the_record() {
    // The byte sweep in `tests/vault_no_plaintext.rs` covers this surface under
    // both Argon2id profiles and against seven planted values. This is the same
    // claim, kept beside the type it is about, so that somebody adding a field to
    // `ProxyEvent` sees it fail here first.
    let event = one_event("");
    let rendered = serde_json::to_string(&event).unwrap();
    for value in planted() {
        assert!(
            !rendered.contains(&value),
            "a planted value reached the event record: {value}\n{event:#}"
        );
    }
    // The positive control: every planted value was masked, so the search above
    // ran over a record that had something to leak.
    let by_type = event["alias_stats"]["by_type"].as_object().unwrap();
    assert_eq!(
        by_type.len(),
        planted().len(),
        "the run did not mask every planted value, so the search proves less than it \
         claims: {event:#}"
    );

    // And again with an allowance, which is the other way a value gets into this
    // record. The masked path has no field a string could travel in;
    // `entities_allowed[].rule_scope` **is** a string field, it sits next to the
    // text that was let through, and "the scope expression, never the matched
    // content" is a sentence in the contract rather than a property of the type.
    // Found by mutation: passing the matched text there instead of the expression
    // compiles, reads plausibly, and puts an unmasked value in the record, and
    // the search above never sees it because the default policy allows nothing.
    let allowing = one_event("[[rule]]\nentity = \"IBAN\"\nmode = \"allow\"");
    let rendered = serde_json::to_string(&allowing).unwrap();
    assert!(
        !allowing["entities_allowed"]
            .as_array()
            .unwrap_or(&Vec::new())
            .is_empty(),
        "nothing was allowed, so the search below covers nothing: {allowing:#}"
    );
    for value in planted() {
        assert!(
            !rendered.contains(&value),
            "a value that crossed under `mode = allow` reached the event record: {value}\n\
             {allowing:#}"
        );
    }
}

#[test]
fn nothing_carries_the_record_out_of_this_process() {
    let run = run("");
    let event = serde_json::to_string(&run.events[0]).unwrap();

    // The behavioural half. Names that exist only in this record, searched in
    // everything that crossed a boundary in either direction.
    let call = run.upstream.calls();
    let call = call.first().expect("the request reached the provider");
    let outbound = format!(
        "{} {} {} {}",
        call.method,
        call.url,
        call.headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}"))
            .collect::<Vec<String>>()
            .join(" "),
        String::from_utf8_lossy(&call.body)
    );
    let inbound = String::from_utf8_lossy(&run.response).into_owned();

    for marker in [
        "ruleset_hash",
        "alias_stats",
        "l_max_static",
        "ladder_rung",
        "unmasked_candidates",
        "entities_masked",
    ] {
        assert!(
            event.contains(marker),
            "the marker {marker} is not in the record, so searching for it proves nothing"
        );
        assert!(
            !outbound.contains(marker),
            "the event record reached the provider: {marker}"
        );
        assert!(
            !inbound.contains(marker),
            "the event record reached the client: {marker}"
        );
    }
}

#[test]
fn the_record_is_named_in_three_source_files_and_a_fourth_is_a_decision() {
    // The structural half of the local-only claim, and the reason it is a scan
    // rather than a comment: the test above can only search the paths one request
    // happens to take. A writer added to a branch this file does not exercise
    // would send every record somewhere while every assertion above stayed green.
    //
    // Three files: the record's own module, the gateway that builds and keeps it,
    // and the module tree that re-exports it. A fourth file naming `ProxyEvent`
    // in **code** is somebody wiring it into something, which is exactly the
    // change that has to be read rather than merged. Comments are skipped: half
    // this crate refers to `ProxyEvent.stream_stats` in prose because that is
    // where the counters are defined, and a scan that counted those would fire on
    // every documentation edit and be deleted by the third person it annoyed.
    const EXPECTED: [&str; 3] = ["event.rs", "gateway.rs", "mod.rs"];

    let mut sources = Vec::new();
    collect_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    assert!(sources.len() >= 20, "only {} sources found", sources.len());

    let mut naming: BTreeSet<String> = BTreeSet::new();
    for source in &sources {
        let text = std::fs::read_to_string(source).unwrap();
        let in_code = text
            .lines()
            .map(str::trim_start)
            .any(|line| !line.starts_with("//") && line.contains("ProxyEvent"));
        if in_code {
            naming.insert(
                source
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
    let expected: BTreeSet<String> = EXPECTED.iter().map(|name| (*name).to_owned()).collect();
    assert_eq!(
        naming, expected,
        "the set of sources that know about the event record changed. If a file was added \
         because the record is now written, sent or exported, `proxy-events.md` says it may not \
         be: the records are local. Widen this list only for a reader inside this process."
    );
}

// ---------------------------------------------------------------------------
// The schema walk
// ---------------------------------------------------------------------------

fn schema() -> Value {
    let path = repo_root().join("schemas/proxy-event.schema.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{} could not be read: {why}", path.display()));
    serde_json::from_str(&text).unwrap()
}

/// Checks one document against the subset of JSON Schema this contract uses.
///
/// `type`, `required`, `properties`, `additionalProperties` (both the `false`
/// form and the schema form), `propertyNames.pattern`, `items`, `enum`,
/// `pattern`, `minLength` and `minimum`. Anything else in the schema is a
/// keyword this walk does not know, and
/// `the_walk_knows_every_keyword_the_schema_uses` fails rather than letting it
/// pass unchecked.
fn validate(schema: &Value, node: &Value, at: &str) -> Result<(), String> {
    if let Some(kind) = schema.get("type").and_then(Value::as_str) {
        let matches = match kind {
            "object" => node.is_object(),
            "array" => node.is_array(),
            "string" => node.is_string(),
            "integer" => node.is_i64() || node.is_u64(),
            "number" => node.is_number(),
            "boolean" => node.is_boolean(),
            other => return Err(format!("{at}: the walk does not know type {other}")),
        };
        if !matches {
            return Err(format!("{at}: expected {kind}, found {node}"));
        }
    }

    if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
        if !allowed.contains(node) {
            return Err(format!("{at}: {node} is not one of {allowed:?}"));
        }
    }

    if let Some(text) = node.as_str() {
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
            let compiled = Regex::new(pattern).map_err(|why| format!("{at}: {pattern}: {why}"))?;
            if !compiled.is_match(text) {
                return Err(format!("{at}: {text:?} does not match {pattern}"));
            }
        }
        if let Some(least) = schema.get("minLength").and_then(Value::as_u64) {
            if (text.len() as u64) < least {
                return Err(format!("{at}: {text:?} is shorter than {least}"));
            }
        }
    }

    if let Some(number) = node.as_i64() {
        if let Some(least) = schema.get("minimum").and_then(Value::as_i64) {
            if number < least {
                return Err(format!("{at}: {number} is below {least}"));
            }
        }
        if let Some(most) = schema.get("maximum").and_then(Value::as_i64) {
            if number > most {
                return Err(format!("{at}: {number} is above {most}"));
            }
        }
    }

    if let Some(items) = schema.get("items") {
        for (index, element) in node.as_array().into_iter().flatten().enumerate() {
            validate(items, element, &format!("{at}[{index}]"))?;
        }
    }

    let Some(object) = node.as_object() else {
        return Ok(());
    };
    for name in schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !object.contains_key(name) {
            return Err(format!("{at}: the required field {name} is missing"));
        }
    }

    let properties = schema.get("properties").and_then(Value::as_object);
    let extra = schema.get("additionalProperties");
    if let Some(pattern) = schema
        .get("propertyNames")
        .and_then(|names| names.get("pattern"))
        .and_then(Value::as_str)
    {
        let compiled = Regex::new(pattern).map_err(|why| format!("{at}: {pattern}: {why}"))?;
        for name in object.keys() {
            if !compiled.is_match(name) {
                return Err(format!("{at}: the key {name:?} does not match {pattern}"));
            }
        }
    }

    for (name, value) in object {
        let path = format!("{at}.{name}");
        match properties.and_then(|properties| properties.get(name)) {
            Some(declared) => validate(declared, value, &path)?,
            None => match extra {
                Some(Value::Bool(false)) | None => {
                    return Err(format!("{path}: no property of this name is declared"))
                }
                Some(Value::Bool(true)) => {}
                Some(declared) => validate(declared, value, &path)?,
            },
        }
    }
    Ok(())
}

#[test]
fn the_validator_rejects_what_the_schema_says_it_should() {
    // A walk that returned `Ok(())` would make every assertion above vacuous, so
    // here is one broken document per rule the schema leans on. The third is the
    // record's whole reason for existing: `alias_samples` is the field the
    // repository's own negative example carries, and it holds two values.
    let schema = schema();
    let good = one_event("");

    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("ruleset_hash");
    assert!(validate(&schema, &missing, "$").is_err());

    let mut wrong_hash = good.clone();
    wrong_hash["policy_hash"] = Value::String("not-a-hash".to_owned());
    assert!(validate(&schema, &wrong_hash, "$").is_err());

    let mut carries_a_value = good.clone();
    carries_a_value.as_object_mut().unwrap().insert(
        "alias_samples".to_owned(),
        serde_json::json!(["TR330006100519786457841326", "PERSON_1"]),
    );
    let refusal = validate(&schema, &carries_a_value, "$").expect_err(
        "a field carrying two values was accepted, which is the one thing \
         additionalProperties: false exists to stop",
    );
    assert!(refusal.contains("alias_samples"), "{refusal}");

    let mut wrong_enum = good.clone();
    wrong_enum["alias_style"] = Value::String("type-preserving-ish".to_owned());
    assert!(validate(&schema, &wrong_enum, "$").is_err());

    let mut wrong_type = good.clone();
    wrong_type["derived_dates_seen"] = Value::String("none".to_owned());
    assert!(validate(&schema, &wrong_type, "$").is_err());

    let mut nested = good.clone();
    nested["stream_stats"]["l_max_static"] = serde_json::json!(64);
    assert!(
        validate(&schema, &nested, "$").is_err(),
        "the walk does not descend into nested objects"
    );

    let mut bad_key = good;
    bad_key["alias_stats"]["by_type"]["not a tag"] =
        serde_json::json!({"count": 1, "ladder_rung": "O"});
    assert!(validate(&schema, &bad_key, "$").is_err());
}

#[test]
fn the_walk_knows_every_keyword_the_schema_uses() {
    // The other half of the control. A keyword the schema starts using and this
    // walk ignores is a rule that stops being checked, and nothing would say so.
    const KNOWN: &[&str] = &[
        "$schema",
        "$id",
        "title",
        "description",
        "type",
        "required",
        "properties",
        "additionalProperties",
        "propertyNames",
        "items",
        "enum",
        "pattern",
        "minLength",
        "minimum",
        "maximum",
    ];

    let mut unknown: BTreeSet<String> = BTreeSet::new();
    keywords(&schema(), &mut unknown);
    unknown.retain(|word| !KNOWN.contains(&word.as_str()));
    assert!(
        unknown.is_empty(),
        "proxy-event.schema.json now uses keywords this walk ignores, so those rules are no \
         longer checked against the produced record: {unknown:?}"
    );
}

/// Every schema keyword used anywhere in the document.
///
/// Keys under `properties` and `$defs` are field names rather than keywords, so
/// they are descended into without being collected.
fn keywords(schema: &Value, found: &mut BTreeSet<String>) {
    let Some(object) = schema.as_object() else {
        if let Some(array) = schema.as_array() {
            for element in array {
                keywords(element, found);
            }
        }
        return;
    };
    for (name, value) in object {
        found.insert(name.clone());
        if name == "properties" || name == "$defs" {
            for nested in value.as_object().into_iter().flatten().map(|(_, v)| v) {
                keywords(nested, found);
            }
        } else if name != "enum" && name != "required" {
            keywords(value, found);
        }
    }
}

fn walk(node: &Value, at: &str, visit: &mut impl FnMut(&str, &Value)) {
    visit(at, node);
    match node {
        Value::Object(map) => {
            for (name, value) in map {
                walk(value, &format!("{at}.{name}"), visit);
            }
        }
        Value::Array(items) => {
            for (index, value) in items.iter().enumerate() {
                walk(value, &format!("{at}[{index}]"), visit);
            }
        }
        _ => {}
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
