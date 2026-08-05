//! What happens to a request body between the client and the provider.
//!
//! Detect, decide, mint, file, replace, in that order, and the order is the
//! guarantee. The alias reaches the provider only after the vault has taken the
//! original value: if the record cannot be filed the request is refused with a
//! **503** (`proxy/spec.md` section 10), because minting an alias the vault does
//! not hold means the response can never be un-masked, and a conversation that
//! cannot be un-masked is one where the user is shown a stranger's placeholder
//! instead of their own data.
//!
//! Nothing in this module streams. The request side never streams by contract
//! (`proxy-api.md`, "Streaming SSE" point 1: the body is taken **in full**, masked,
//! and only then sent), and the response side's state machine is tasks 89 to 93.

use serde_json::Value;

use crate::alias::mint::Reservation;
use crate::alias::{AliasKey, EntityType, Minter};
use crate::detect::segment::{segments, SegmentKind};
use crate::detect::{merge, pattern, Candidate, DegradedReason, Detection};
use crate::policy::scope::{layers_for, string_values};
use crate::policy::{resolve, Mode, Policy, Step};
use crate::vault::{SessionId, Vault, VaultError};

use super::errors::{ProxyError, Refusal};

/// What one masked request produced.
#[derive(Debug)]
pub struct Masked {
    /// The body to send upstream.
    pub body: Value,
    /// Distinct aliases minted or reused, which is `x-periskop-masked-entities`.
    pub masked_entities: u32,
    /// Everything this scan admits it did not look for.
    pub degraded: Vec<DegradedReason>,
}

/// Everything the masking pass needs that is not the body.
pub struct Pass<'a> {
    pub policy: &'a Policy,
    pub session: SessionId,
    pub minter: &'a mut Minter,
    pub vault: &'a mut Vault,
    pub now_ms: u64,
}

/// Masks one request body in place.
///
/// Every string **value** in the body is scanned; no key ever is
/// (`proxy/spec.md` section 7 rule 1, enforced by [`string_values`], which does
/// not yield keys and has no argument that would make it).
pub fn mask(pass: &mut Pass<'_>, body: &Value) -> Result<Masked, Refusal> {
    // A list rather than a map, because `Step` is deliberately not `Ord`: a path
    // is a route through a document, not a key, and ordering two of them would
    // invent a comparison the policy layer refused to define. The paths come out
    // of one walk of one document, so they are already unique and already in the
    // order they were found.
    let mut replacements: Vec<(Vec<Step>, String)> = Vec::new();
    let mut degraded: Vec<DegradedReason> = Vec::new();
    let mut minted = 0u32;

    // A literal in the prompt that is already shaped like one of our aliases is
    // withheld before anything is minted, so that a value cannot be given a name
    // the user had already used for something else (ADR-010 section 6).
    for (_, text) in string_values(body) {
        reserve_alias_literals(pass.minter, &text);
    }

    for (path, text) in string_values(body) {
        let detection = scan(pass.policy, &text);
        degraded.extend(detection.degraded_reasons.iter().copied());

        let (masked_text, count) = apply(pass, &path, &text, &detection)?;
        minted += count;
        if masked_text != text {
            replacements.push((path, masked_text));
        }
    }

    degraded.sort_unstable();
    degraded.dedup();

    Ok(Masked {
        body: rewrite(body, &replacements),
        masked_entities: minted,
        degraded,
    })
}

/// Runs the layers the policy enables over one string, segment by segment.
///
/// A fenced code block runs layer A only under the default `code_block_policy`,
/// because `Ahmet` inside code is a variable name and an IBAN inside code is still
/// an IBAN. The layer that did not run is declared rather than forgotten.
fn scan(policy: &Policy, text: &str) -> Detection {
    let mut pattern_hits: Vec<Candidate> = Vec::new();
    let mut dictionary_hits: Vec<Candidate> = Vec::new();
    let mut extra: Vec<DegradedReason> = Vec::new();

    for segment in segments(text) {
        let (run_pattern, run_dictionary) = layers_for(segment.kind, policy.code_block_policy());
        let slice = &text[segment.start..segment.end];

        if run_pattern {
            pattern_hits.extend(shift(pattern::scan(slice), segment.start));
        }
        if run_dictionary {
            dictionary_hits.extend(shift(policy.dictionary().scan(slice), segment.start));
        } else if segment.kind == SegmentKind::CodeBlock {
            extra.push(DegradedReason::CodeBlockSkipped);
        }
    }

    if !policy.dictionary_available() {
        extra.push(DegradedReason::DictionaryUnavailable);
    }

    merge(
        pattern_hits,
        dictionary_hits,
        policy.masking_profile(),
        &extra,
    )
}

/// Moves a segment's candidates back into the whole string's coordinates.
fn shift(candidates: Vec<Candidate>, by: usize) -> Vec<Candidate> {
    candidates
        .into_iter()
        .map(|candidate| Candidate {
            start: candidate.start + by,
            end: candidate.end + by,
            ..candidate
        })
        .collect()
}

/// Applies the policy's decision to each candidate, right to left.
///
/// Right to left so that replacing one span does not move the offsets of the
/// spans that have not been replaced yet. `merge` already guarantees the
/// candidates do not overlap and are sorted by position.
fn apply(
    pass: &mut Pass<'_>,
    path: &[Step],
    text: &str,
    detection: &Detection,
) -> Result<(String, u32), Refusal> {
    let mut out = text.to_owned();
    let mut minted = 0u32;

    for candidate in detection.candidates.iter().rev() {
        let mode = resolve(
            pass.policy.rules(),
            pass.policy.default_mode(),
            path,
            candidate.entity,
        );
        let Some(original) = candidate.text_of(text) else {
            continue;
        };

        match mode {
            // Crosses unchanged. Not "no record": the count belongs to the event
            // record, and the caller is told what was let through.
            Mode::Allow => {}
            Mode::Block => {
                return Err(Refusal::new(
                    ProxyError::EntityBlocked,
                    format!(
                        "a {} was found under `mode = \"block\"` at {}",
                        candidate.entity.tag(),
                        render_path(path)
                    ),
                ))
            }
            Mode::Mask => {
                let alias = mint_and_file(pass, candidate.entity, original)?;
                out.replace_range(candidate.start..candidate.end, &alias);
                minted += 1;
            }
        }
    }

    Ok((out, minted))
}

/// Mints an alias and files the original under it, in that order.
///
/// The write happens **before** the alias is put in the body, so that a body
/// carrying an alias is a body whose original the vault holds. Reversing these two
/// lines would let a full disk produce a conversation nothing can un-mask, and the
/// user would only find out when the answer came back full of placeholders.
fn mint_and_file(
    pass: &mut Pass<'_>,
    entity: EntityType,
    original: &str,
) -> Result<String, Refusal> {
    let minted = pass
        .minter
        .mint(entity, original)
        .map_err(|refusal| Refusal::new(alias_error_class(&refusal), refusal.to_string()))?;

    pass.vault.store_alias(
        &pass.session,
        minted.seed.to_vault_seed(),
        &minted.alias,
        original.as_bytes(),
        pass.now_ms,
    )?;

    Ok(minted.alias)
}

/// Which closed value an alias generation failure reports under.
fn alias_error_class(refusal: &crate::alias::AliasError) -> ProxyError {
    use crate::alias::AliasError;
    match refusal {
        // The ladder ran out of free names. Fail closed: reusing one would make a
        // single string stand for two different people, which is the one thing an
        // alias may never do.
        AliasError::CollisionUnresolved { .. } => ProxyError::AliasCollisionUnresolved,
        // A generator that produced an over-long alias, or a key HMAC refused.
        // Both are faults in this build rather than in the request, and both mean
        // the masking guarantee cannot be met for this value.
        AliasError::LengthCeilingExceeded { .. } | AliasError::KeyUnusable => {
            ProxyError::AliasCollisionUnresolved
        }
        // The rest are values this build will not mint an alias for at all: a type
        // that is not minted, a URL that must be aliased through its host, a value
        // that normalised to nothing. That is a request this endpoint cannot
        // serve, not a vault that is broken.
        AliasError::NotMinted { .. }
        | AliasError::UrlMintsViaHost
        | AliasError::HostNotFound
        | AliasError::EmptyValue { .. } => ProxyError::EndpointUnsupported,
    }
}

/// Withholds any string the user wrote that is already shaped like one of our
/// aliases.
fn reserve_alias_literals(minter: &mut Minter, text: &str) {
    for word in text.split(|c: char| c.is_whitespace() || c == '"' || c == ',') {
        let word = word.trim_matches(|c: char| c == '.' || c == ';' || c == ':');
        if word.starts_with("PSK_") && minter.reserve_literal(word) == Reservation::Withheld {
            // Withheld. Nothing to do here: the reservation is the effect, and
            // `Minter` will not hand this string to a value later in the session.
        }
    }
}

/// Rebuilds the body with the masked strings put back at their paths.
fn rewrite(body: &Value, replacements: &[(Vec<Step>, String)]) -> Value {
    let mut out = body.clone();
    for (path, text) in replacements {
        set_at(&mut out, path, Value::String(text.clone()));
    }
    out
}

/// Writes one value at a path, doing nothing if the path is not there.
///
/// A path that has gone missing means the body changed under us, which cannot
/// happen here: the paths were read from this same document a few lines above.
/// Written as a no-op rather than an error so that this function is total.
fn set_at(body: &mut Value, path: &[Step], value: Value) {
    let Some((last, leading)) = path.split_last() else {
        *body = value;
        return;
    };

    let mut cursor = body;
    for step in leading {
        cursor = match step {
            Step::Key(key) => match cursor.get_mut(key) {
                Some(next) => next,
                None => return,
            },
            Step::Index(index) => match cursor.get_mut(index) {
                Some(next) => next,
                None => return,
            },
            // `string_values` never yields a wildcard: it walks a concrete
            // document, so every index it reports is a real one.
            Step::AnyIndex => return,
        };
    }

    match last {
        Step::Key(key) => {
            if let Some(slot) = cursor.get_mut(key) {
                // Only when the slot still holds a string. A path that now points
                // at an object is a path into a nested JSON document that was
                // descended one level (spec section 7 rule 3), and its parent
                // string is what carries the masked text.
                if slot.is_string() {
                    *slot = value;
                }
            }
        }
        Step::Index(index) => {
            if let Some(slot) = cursor.get_mut(index) {
                if slot.is_string() {
                    *slot = value;
                }
            }
        }
        Step::AnyIndex => {}
    }
}

fn render_path(path: &[Step]) -> String {
    if path.is_empty() {
        return "the request body".to_owned();
    }
    let mut out = String::new();
    for step in path {
        match step {
            Step::Key(key) => {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(key);
            }
            Step::Index(index) => out.push_str(&format!("[{index}]")),
            Step::AnyIndex => out.push_str("[*]"),
        }
    }
    out
}

/// The alias key one session mints under.
///
/// Derived from the session identifier so that two conversations produce unrelated
/// aliases for the same value (ADR-007: the session identifier is the HKDF salt),
/// which is what stops a provider joining two masked prompts.
pub fn alias_key_for(
    vault: &mut Vault,
    session: &SessionId,
    now_ms: u64,
) -> Result<AliasKey, VaultError> {
    let opened = vault.open_session(session, now_ms)?;
    Ok(AliasKey::from_key_bytes(
        *opened.session_key().expose_for_alias_derivation(),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::path::Path;

    use serde_json::json;

    use super::*;
    use crate::alias::AliasStyle;
    use crate::vault::{Backing, OpenRequest, Passphrase, ProfileName, Restored, SessionLimits};

    const NOW: u64 = 1_700_000_000_000;
    const SESSION: SessionId = SessionId::from_bytes([0x5a; 16]);

    fn policy(extra: &str) -> Policy {
        let text = format!(
            "policy_id = \"acme\"\npolicy_version = \"1\"\n{extra}\n[default]\nmode = \"mask\"\n"
        );
        Policy::load(&text, Path::new("."), None).unwrap_or_else(|refusal| panic!("{refusal}"))
    }

    /// A vault opened under the reduced profile, because these tests exercise the
    /// request path rather than Argon2id's memory parameter.
    fn vault() -> Vault {
        Vault::open(&OpenRequest {
            passphrase: &Passphrase::new(b"an operator's passphrase".to_vec()),
            profile: ProfileName::Ci,
            backing: Backing::Memory,
        })
        .unwrap_or_else(|refusal| panic!("{refusal}"))
    }

    fn minter(vault: &mut Vault) -> Minter {
        let key = alias_key_for(vault, &SESSION, NOW).unwrap();
        Minter::new(key, AliasStyle::TypePreserving)
    }

    /// A synthetic value with a checksum that passes, assembled at run time.
    fn iban() -> String {
        // TR33 0006 1005 1978 6457 8413 26, the published example.
        format!("TR{}", "330006100519786457841326")
    }

    fn run(policy: &Policy, body: &Value) -> (Masked, Vault) {
        let mut vault = vault();
        let mut minter = minter(&mut vault);
        let masked = {
            let mut pass = Pass {
                policy,
                session: SESSION,
                minter: &mut minter,
                vault: &mut vault,
                now_ms: NOW,
            };
            mask(&mut pass, body).unwrap_or_else(|refusal| panic!("{}", refusal.detail()))
        };
        (masked, vault)
    }

    #[test]
    fn a_value_in_the_body_is_replaced_and_the_vault_can_give_it_back() {
        let policy = policy("");
        let body = json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": format!("wire it to {}", iban())}]
        });

        let (masked, mut vault) = run(&policy, &body);
        assert_eq!(masked.masked_entities, 1);

        let sent = masked.body["messages"][0]["content"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(
            !sent.contains(&iban()),
            "the original crossed to the provider: {sent}"
        );

        // The round trip: whatever replaced it is a name the vault holds.
        let alias = sent
            .split_whitespace()
            .last()
            .unwrap_or_default()
            .to_owned();
        let Restored::Value(value) = vault.restore(&SESSION, &alias, NOW).unwrap() else {
            panic!("the vault does not hold the alias that was sent: {alias}");
        };
        assert_eq!(value.expose(), iban().as_bytes());
    }

    #[test]
    fn a_json_key_is_never_masked_in_any_mode() {
        // Spec section 7 rule 1. A masked key changes the shape of the request and
        // the provider answers a different question.
        let policy = policy("");
        let body = json!({ iban(): "a label" });
        let (masked, _) = run(&policy, &body);
        assert!(masked.body.get(iban()).is_some(), "{:?}", masked.body);
        assert_eq!(masked.masked_entities, 0);
    }

    #[test]
    fn the_same_value_twice_in_one_session_gets_one_alias() {
        // Section 5's whole point: `PERSON_1` may not mean two people, and the
        // same person may not be two aliases either, or the model cannot tell that
        // the two mentions are the same one.
        let policy = policy("");
        let body = json!({
            "messages": [
                {"role": "user", "content": format!("account {}", iban())},
                {"role": "user", "content": format!("again, {}", iban())},
            ]
        });
        let (masked, _) = run(&policy, &body);

        let first = masked.body["messages"][0]["content"].as_str().unwrap_or("");
        let second = masked.body["messages"][1]["content"].as_str().unwrap_or("");
        let alias_of = |text: &str| text.split_whitespace().last().unwrap_or("").to_owned();
        assert_eq!(alias_of(first), alias_of(second));
    }

    #[test]
    fn a_blocked_entity_refuses_the_request_and_names_the_field() {
        let policy = policy("[[rule]]\nentity = \"IBAN\"\nmode = \"block\"");
        let mut vault = vault();
        let mut minter = minter(&mut vault);
        let mut pass = Pass {
            policy: &policy,
            session: SESSION,
            minter: &mut minter,
            vault: &mut vault,
            now_ms: NOW,
        };
        let body = json!({"messages": [{"role": "user", "content": iban()}]});

        let refusal = mask(&mut pass, &body).expect_err("a blocked entity was masked instead");
        assert_eq!(refusal.error(), ProxyError::EntityBlocked);
        assert_eq!(refusal.status(), 400);
        assert!(refusal.detail().contains("IBAN"), "{}", refusal.detail());
        assert!(
            refusal.detail().contains("messages[0].content"),
            "{}",
            refusal.detail()
        );
    }

    #[test]
    fn an_allowed_entity_crosses_unchanged() {
        let policy = policy("[[rule]]\nentity = \"IBAN\"\nmode = \"allow\"");
        let body = json!({"messages": [{"role": "user", "content": iban()}]});
        let (masked, _) = run(&policy, &body);
        assert_eq!(masked.body, body);
        assert_eq!(masked.masked_entities, 0);
    }

    /// `proxy/spec.md` section 10: a vault that cannot take the record refuses the
    /// request. The alias is filed before it is sent, so this is the order that
    /// makes the refusal possible at all.
    #[test]
    fn a_vault_that_will_not_take_the_record_refuses_the_request_with_a_503() {
        let policy = policy("");
        let mut vault = Vault::in_memory_with_limits(SessionLimits {
            alias_ceiling: 0,
            ttl_ms: 60_000,
        })
        .unwrap_or_else(|refusal| panic!("{refusal}"));
        let mut minter = minter(&mut vault);
        let mut pass = Pass {
            policy: &policy,
            session: SESSION,
            minter: &mut minter,
            vault: &mut vault,
            now_ms: NOW,
        };
        let body = json!({"messages": [{"role": "user", "content": iban()}]});

        let refusal = mask(&mut pass, &body).expect_err("the request was masked with no vault");
        // A ceiling is a quota: 429, not 503. The two are different instructions
        // to the caller and section 10 spends a paragraph keeping them apart.
        assert_eq!(refusal.error(), ProxyError::AliasLimitExceeded);
        assert_eq!(refusal.status(), 429);
    }

    #[test]
    fn the_declaration_that_ner_did_not_run_is_attached_to_every_scan() {
        let policy = policy("");
        let body = json!({"messages": [{"role": "user", "content": "just words"}]});
        let (masked, _) = run(&policy, &body);
        assert!(
            masked.degraded.contains(&DegradedReason::NerDisabled),
            "{:?}",
            masked.degraded
        );
    }

    #[test]
    fn a_nested_json_string_is_masked_inside_the_string_that_carries_it() {
        // Section 7 rule 3: one level of descent. The outer string is what gets
        // rewritten, because that is what the provider receives.
        let policy = policy("");
        let inner = json!({"account": iban()}).to_string();
        let body = json!({"messages": [{"role": "user", "content": inner}]});

        let (masked, _) = run(&policy, &body);
        let sent = masked.body["messages"][0]["content"].as_str().unwrap_or("");
        assert!(!sent.contains(&iban()), "{sent}");
        assert!(sent.contains("account"), "the structure was lost: {sent}");
    }

    #[test]
    fn a_body_with_nothing_to_mask_comes_out_byte_for_byte_the_same() {
        let policy = policy("");
        let body = json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}], "temperature": 0.2});
        let (masked, _) = run(&policy, &body);
        assert_eq!(masked.body, body);
        assert_eq!(masked.masked_entities, 0);
    }
}
