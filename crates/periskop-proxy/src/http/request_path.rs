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

use std::collections::BTreeMap;

use serde_json::Value;

use crate::alias::mint::{AliasStats, Minted, Reservation};
use crate::alias::{AliasKey, EntityType, LadderRung, Minter};
use crate::detect::segment::{segments, SegmentKind};
use crate::detect::{
    merge, owning_layer, pattern, Candidate, DegradedReason, Detection, DetectionLayer,
};
use crate::policy::scope::{layers_for, string_values};
use crate::policy::{decide, DatePolicy, Decision, Mode, Policy, Rule, Step};
use crate::vault::{SessionId, Vault, VaultError};

use super::errors::{ProxyError, Refusal};

/// One entity type's masked count, in the shape `ProxyEvent.entities_masked[]`
/// carries it.
///
/// The type, how many of them, which layer claimed them. No offset and no text:
/// an offset plus a body somebody else has is the value, and this record is
/// written on the assumption that nobody has the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaskedType {
    pub entity: EntityType,
    pub count: u32,
    pub layer: DetectionLayer,
}

/// One entity type that crossed unmasked because the policy said so.
///
/// `proxy-events.md`: "mode=allow is not silent: every one of them is counted
/// here". The scope expression rides along so the count can be traced back to
/// the line that produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedType {
    pub entity: EntityType,
    pub count: u32,
    pub rule_scope: String,
}

/// What one masked request produced.
#[derive(Debug)]
pub struct Masked {
    /// The body to send upstream.
    pub body: Value,
    /// Distinct aliases minted or reused, which is `x-periskop-masked-entities`.
    pub masked_entities: u32,
    /// Everything this scan admits it did not look for.
    pub degraded: Vec<DegradedReason>,
    /// Per type masked counts, sorted by type.
    pub by_type: Vec<MaskedType>,
    /// Per type allowed counts, sorted by type.
    pub allowed: Vec<AllowedType>,
    /// Alias generation counters **for this request**, not for the session.
    ///
    /// The minter's own [`AliasStats`] accumulate over a conversation, and an
    /// event record is written per request and response pair, so the two are
    /// taken apart here rather than at the reader's end.
    pub alias_stats: AliasStats,
    /// Milliseconds spent deciding what to mask (`latency_ms.detect`).
    pub detect_ms: u64,
    /// Milliseconds spent minting aliases and filing records
    /// (`latency_ms.alias`).
    pub alias_ms: u64,
}

/// Where the masking pass reads the clock.
///
/// A function rather than a single timestamp because the pass is now measured in
/// two parts (`latency_ms.detect` and `latency_ms.alias`), and injected rather
/// than taken from the system so that a fixed clock produces a byte identical
/// event record. `proxy-events.md`'s determinism rule is what makes that a
/// requirement rather than a convenience.
pub type Now<'a> = &'a dyn Fn() -> u64;

/// Everything the masking pass needs that is not the body.
pub struct Pass<'a> {
    pub policy: &'a Policy,
    pub session: SessionId,
    pub minter: &'a mut Minter,
    pub vault: &'a mut Vault,
    /// The one clock. Vault record expiry and the phase timings read the same
    /// function, so a test that pins it pins both.
    pub now: Now<'a>,
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
    let mut tally = Tally::default();
    // The session's counters as they stood before this request, so that what is
    // reported below is this request's share and not the conversation's total.
    let before = pass.minter.stats();

    // A literal in the prompt that is already shaped like one of our aliases is
    // withheld before anything is minted, so that a value cannot be given a name
    // the user had already used for something else (ADR-010 section 6).
    for (_, text) in string_values(body) {
        reserve_alias_literals(pass.minter, &text);
    }

    for (path, text) in string_values(body) {
        let at = (pass.now)();
        let detection = scan(pass.policy, &text);
        tally.detect_ms = tally
            .detect_ms
            .saturating_add((pass.now)().saturating_sub(at));
        degraded.extend(detection.degraded_reasons.iter().copied());

        let at = (pass.now)();
        let masked_text = apply(pass, &path, &text, &detection, &mut tally)?;
        tally.alias_ms = tally
            .alias_ms
            .saturating_add((pass.now)().saturating_sub(at));
        if masked_text != text {
            replacements.push((path, masked_text));
        }
    }

    degraded.sort_unstable();
    degraded.dedup();

    let after = pass.minter.stats();
    Ok(Masked {
        body: rewrite(body, &replacements),
        masked_entities: tally.minted,
        degraded,
        by_type: tally.masked_by_type(),
        allowed: tally.allowed_by_type(),
        alias_stats: AliasStats {
            by_type: tally.aliases.by_type.clone(),
            // A difference rather than the session total. The two scalars are
            // kept on the minter because they are properties of generation, so
            // this request's share is what generation did while it ran.
            alias_pool_exhausted: after
                .alias_pool_exhausted
                .saturating_sub(before.alias_pool_exhausted),
            alias_length_class_capped: after
                .alias_length_class_capped
                .saturating_sub(before.alias_length_class_capped),
        },
        detect_ms: tally.detect_ms,
        alias_ms: tally.alias_ms,
    })
}

/// What one request's masking pass counted, before it becomes an event record.
///
/// Kept as maps keyed by type so the output is sorted by type on every run, and
/// as counts alone so there is nothing here that a value could be recovered
/// from. This is the whole of what [`Masked`] reports beyond the body.
#[derive(Debug, Default)]
struct Tally {
    minted: u32,
    /// Occurrences replaced, per type. Not the same number as the alias count
    /// below and deliberately so: one value written twice in one prompt is two
    /// masked entities and one alias, and `proxy-events.md` reports both.
    masked: BTreeMap<EntityType, u32>,
    /// Distinct aliases and their rungs, folded through the one implementation
    /// of the R14 downgrade.
    aliases: AliasStats,
    /// Count, and the expression of the rule that let them through.
    allowed: BTreeMap<EntityType, (u32, String)>,
    detect_ms: u64,
    alias_ms: u64,
}

impl Tally {
    fn masked(&mut self, entity: EntityType, rung: LadderRung, reused: bool) {
        self.minted = self.minted.saturating_add(1);
        *self.masked.entry(entity).or_insert(0) += 1;
        if !reused {
            self.aliases.fold(entity, rung);
        }
    }

    fn allowed(&mut self, entity: EntityType, rule_scope: String) {
        self.allowed
            .entry(entity)
            .and_modify(|(count, _)| *count += 1)
            .or_insert((1, rule_scope));
    }

    fn masked_by_type(&self) -> Vec<MaskedType> {
        self.masked
            .iter()
            .map(|(entity, count)| MaskedType {
                entity: *entity,
                count: *count,
                layer: owning_layer(*entity),
            })
            .collect()
    }

    fn allowed_by_type(&self) -> Vec<AllowedType> {
        self.allowed
            .iter()
            .map(|(entity, (count, rule_scope))| AllowedType {
                entity: *entity,
                count: *count,
                rule_scope: rule_scope.clone(),
            })
            .collect()
    }
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
    tally: &mut Tally,
) -> Result<String, Refusal> {
    let mut out = text.to_owned();

    for candidate in detection.candidates.iter().rev() {
        let decision = date_aware(
            pass.policy,
            path,
            candidate.entity,
            decide(
                pass.policy.rules(),
                pass.policy.default_mode(),
                path,
                candidate.entity,
            ),
        );
        let Some(original) = candidate.text_of(text) else {
            continue;
        };

        match decision.mode {
            // Crosses unchanged. Not "no record": `proxy-events.md` puts every
            // one of these in `entities_allowed[]` with the expression of the
            // rule that decided, because an allowance nobody can trace back to a
            // line of policy is indistinguishable from a detector that missed.
            Mode::Allow => tally.allowed(candidate.entity, decision.rule_scope),
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
                let minted = mint_and_file(pass, candidate.entity, original)?;
                out.replace_range(candidate.start..candidate.end, &minted.alias);
                tally.masked(candidate.entity, minted.rung, minted.reused);
            }
        }
    }

    Ok(out)
}

/// What `entities_allowed[].rule_scope` says when `date_policy` decided.
///
/// Parenthesised, in the shape [`Decision::DEFAULT_SCOPE`] already uses, because
/// it is not a scope expression somebody can go and find in a `[[rule]]` block.
/// It names the key the operator has to edit, which is the whole reason
/// `proxy-events.md` carries the deciding expression beside the count.
const DATE_POLICY_SCOPE: &str = "(date_policy)";

/// Lets `date_policy` answer for a `DATE` that would otherwise be masked.
///
/// This build mints no date alias. F4's scope boundary 2 struck date shifting
/// out entirely, so [`EntityType::Date`] is `Minting::NotMinted`, and until this
/// function existed a date under the default `[default] mode = "mask"` refused
/// the **whole request** with `endpoint_unsupported`. A meeting date, a release
/// day or a date in a SQL query is an ordinary thing to write to a model, so the
/// default configuration refused ordinary prompts, and the operator had no way
/// to read the reason off the refusal. `proxy-policy.md` section 4 defaults
/// `date_policy` to `allow` and `proxy/spec.md` section 4.5 spends a section on
/// why, so the refusal was this build ignoring a key rather than the contract
/// asking for it.
///
/// Only `mask` is redirected, and only when no rule named `DATE`:
///
/// - a rule that names `entity = "DATE"` is the operator speaking about dates,
///   and it is honoured exactly as written. `proxy/spec.md` section 8's own
///   example writes that rule to block them, and a `mask` written there still
///   refuses the request rather than being quietly turned into a pass;
/// - an `allow` or a `block` from anywhere else is honoured too.
///   `proxy-policy.md` section 3 forbids a precedence rule in the relaxing
///   direction, and letting a date through a scope the operator blocked would be
///   one.
///
/// What is left is the one mode this build provably cannot honour for a date,
/// and `date_policy` is the key the contract put there to answer it.
fn date_aware(policy: &Policy, path: &[Step], entity: EntityType, decision: Decision) -> Decision {
    if entity != EntityType::Date
        || decision.mode != Mode::Mask
        || names_dates(policy.rules(), path)
    {
        return decision;
    }
    Decision {
        mode: match policy.date_policy() {
            DatePolicy::Allow => Mode::Allow,
            DatePolicy::Block => Mode::Block,
        },
        rule_scope: DATE_POLICY_SCOPE.to_owned(),
    }
}

/// Whether a rule at this path names `DATE` itself.
///
/// Only the naming matters, not which mode it chose: a rule that says `DATE` is
/// an operator who has thought about dates, and their sentence is not rewritten
/// by a key that exists to answer for the ones who have not.
fn names_dates(rules: &[Rule], path: &[Step]) -> bool {
    rules
        .iter()
        .any(|rule| rule.entity == Some(EntityType::Date) && rule.scope.covers(path))
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
) -> Result<Minted, Refusal> {
    let minted = pass
        .minter
        .mint(entity, original)
        .map_err(|refusal| Refusal::new(alias_error_class(&refusal), refusal.to_string()))?;

    pass.vault.store_alias(
        &pass.session,
        minted.seed.to_vault_seed(),
        &minted.alias,
        original.as_bytes(),
        (pass.now)(),
    )?;

    Ok(minted)
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
                now: &|| NOW,
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
            now: &|| NOW,
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

    /// A prompt with a date in it.
    ///
    /// The shortest policy the loader accepts is `[default] mode = "mask"`, and
    /// under it this body used to come back as a `400`, because `DATE` mints
    /// nothing and nothing read `date_policy`. Meeting dates, release days and
    /// dates inside SQL are ordinary things to write to a model, so that refusal
    /// made the default configuration refuse ordinary work.
    #[test]
    fn a_date_crosses_under_the_default_policy_instead_of_refusing_the_request() {
        let policy = policy("");
        let body =
            json!({"messages": [{"role": "user", "content": "toplanti 2026-03-11 tarihinde"}]});
        let (masked, _) = run(&policy, &body);

        assert_eq!(masked.body, body, "the date did not cross unchanged");
        assert_eq!(masked.masked_entities, 0);
        // Crossing is not silence (`proxy-events.md`): the date is counted, and
        // the count names the key an operator would edit rather than a rule
        // expression they would go looking for and not find.
        assert_eq!(masked.allowed.len(), 1, "{:?}", masked.allowed);
        assert_eq!(masked.allowed[0].entity, EntityType::Date);
        assert_eq!(masked.allowed[0].count, 1);
        // Written out rather than compared against the constant it came from: a
        // comparison with `DATE_POLICY_SCOPE` would pass whatever that constant
        // said, including an empty string, which reads in a record as a missing
        // field rather than as the key that decided.
        assert_eq!(masked.allowed[0].rule_scope, "(date_policy)");
    }

    /// The other value of the key, and the whole reason it is a key.
    #[test]
    fn date_policy_block_refuses_the_request_that_carries_a_date() {
        let policy = policy("date_policy = \"block\"");
        let mut vault = vault();
        let mut minter = minter(&mut vault);
        let mut pass = Pass {
            policy: &policy,
            session: SESSION,
            minter: &mut minter,
            vault: &mut vault,
            now: &|| NOW,
        };
        let body = json!({"messages": [{"role": "user", "content": "teslim 2026-03-11"}]});

        let refusal = mask(&mut pass, &body).expect_err("a date crossed under date_policy block");
        assert_eq!(refusal.error(), ProxyError::EntityBlocked);
        assert_eq!(refusal.status(), 400);
        assert!(refusal.detail().contains("DATE"), "{}", refusal.detail());
    }

    /// `proxy/spec.md` section 8 writes this rule as the correct way to keep
    /// dates out of a flow, so the key may not overrule it in either direction.
    #[test]
    fn a_rule_that_names_dates_decides_and_the_key_does_not_overrule_it() {
        let blocking = policy("[[rule]]\nentity = \"DATE\"\nmode = \"block\"");
        let mut vault = vault();
        let mut minter = minter(&mut vault);
        let mut pass = Pass {
            policy: &blocking,
            session: SESSION,
            minter: &mut minter,
            vault: &mut vault,
            now: &|| NOW,
        };
        let body = json!({"messages": [{"role": "user", "content": "teslim 2026-03-11"}]});
        let refusal = mask(&mut pass, &body).expect_err("a rule naming DATE was overruled");
        assert_eq!(refusal.error(), ProxyError::EntityBlocked);

        // And the reverse: the key refuses dates, the rule permits them, and the
        // rule is the narrower sentence so it wins. The record names the rule's
        // own expression rather than the key.
        let permitting = policy(
            "date_policy = \"block\"\n[[rule]]\nentity = \"DATE\"\nscope = \"messages[*].content\"\nmode = \"allow\"",
        );
        let (masked, _) = run(&permitting, &body);
        assert_eq!(masked.body, body);
        assert_eq!(masked.allowed.len(), 1, "{:?}", masked.allowed);
        assert_eq!(masked.allowed[0].rule_scope, "messages[*].content");
    }

    /// The relaxation that may not happen.
    ///
    /// `proxy-policy.md` section 3: no precedence rule in the relaxing
    /// direction. An operator who blocked a field blocked it for every type, and
    /// a date is not an exception carved out by the key that answers for the
    /// default.
    #[test]
    fn a_date_in_a_scope_the_operator_blocked_is_still_refused() {
        let policy = policy("[[rule]]\nscope = \"messages[*].content\"\nmode = \"block\"");
        let mut vault = vault();
        let mut minter = minter(&mut vault);
        let mut pass = Pass {
            policy: &policy,
            session: SESSION,
            minter: &mut minter,
            vault: &mut vault,
            now: &|| NOW,
        };
        let body = json!({"messages": [{"role": "user", "content": "teslim 2026-03-11"}]});

        let refusal = mask(&mut pass, &body).expect_err("a blocked scope let a date through");
        assert_eq!(refusal.error(), ProxyError::EntityBlocked);
    }

    /// An operator who asks for a masked date is told, rather than quietly given
    /// the opposite.
    ///
    /// `mask` is the one mode this build cannot honour for a date, and a rule
    /// that names `DATE` is somebody who meant it. Turning that into a pass would
    /// be a rule dropped in silence, which is the failure the whole policy loader
    /// is built to avoid.
    #[test]
    fn a_rule_that_asks_for_a_masked_date_refuses_rather_than_being_relaxed() {
        let policy = policy("[[rule]]\nentity = \"DATE\"\nmode = \"mask\"");
        let mut vault = vault();
        let mut minter = minter(&mut vault);
        let mut pass = Pass {
            policy: &policy,
            session: SESSION,
            minter: &mut minter,
            vault: &mut vault,
            now: &|| NOW,
        };
        let body = json!({"messages": [{"role": "user", "content": "teslim 2026-03-11"}]});

        let refusal = mask(&mut pass, &body).expect_err("a date was masked");
        assert_eq!(refusal.error(), ProxyError::EndpointUnsupported);
        assert!(
            refusal.detail().contains("date policy"),
            "the refusal does not point at the key that answers dates: {}",
            refusal.detail()
        );
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
            now: &|| NOW,
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
