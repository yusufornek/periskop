//! Which conversation a request belongs to, decided in the three steps
//! `proxy/spec.md` section 2.4 lists and in that order.
//!
//! 1. the client's `x-periskop-session` header,
//! 2. otherwise a fingerprint of the conversation's opening,
//! 3. otherwise a fresh, single request session.
//!
//! The order is the whole of it. Alias consistency is defined inside a session
//! (section 5): the same value has to get the same alias for as long as the
//! conversation lasts, because `PERSON_1` meaning somebody else on turn two makes
//! the conversation nonsense. Step 1 is exact and step 2 is a guess, so step 2
//! never runs when step 1 answered.
//!
//! # Step 2 does not always work, and that is written down rather than hidden
//!
//! `proxy/spec.md`'s open question 1 is about this module: a client that injects
//! the current date into its system prompt writes a different opening on every
//! turn, so the fingerprint differs on every turn, so every turn opens a new
//! session and alias consistency is lost. That is a real loss, it is not fixed
//! here, and `a_client_that_rewrites_its_system_prompt_loses_consistency_every_turn`
//! demonstrates it on purpose so that nobody has to discover it from a masked
//! conversation that stopped making sense.
//!
//! # Single tenant, and why the derivation may be unkeyed by a secret
//!
//! The identifier is derived, not taken: a client that sends
//! `x-periskop-session: default` must not be able to name the vault record space
//! directly. The derivation is keyed by the **policy hash**, which is stable
//! across restarts (so a `file` vault's records survive one) and changes when the
//! policy changes (so aliases minted under one rule set are not resumed under
//! another). It is deliberately not keyed by a per-process secret: that would make
//! every restart forget every conversation, which is the cost `listen.rs` refuses
//! to pay silently. Nothing here authorises one caller against another, because
//! F4 is single tenant and local by roadmap decision, which is the assumption
//! `listen.rs` keeps by binding loopback.

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

use crate::vault::{SessionId, VaultError};

/// Domain separation, so that a fingerprint and a header derived identifier can
/// never collide even if a client sends its own opening as a session name.
const HEADER_DOMAIN: &[u8] = b"periskop/session/header/v1";
const FINGERPRINT_DOMAIN: &[u8] = b"periskop/session/fingerprint/v1";

/// The bytes a [`SessionId`] is built from, kept so that the same value can be
/// rendered as the opaque `x-periskop-alias-scope` the header table requires.
const SCOPE_BYTES: usize = 16;

/// How a session was identified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Step 1: the client said so.
    ClientHeader,
    /// Step 2: derived from the conversation's opening.
    ConversationFingerprint,
    /// Step 3: nothing to go on, so this request only.
    Ephemeral,
}

impl Origin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientHeader => "client_header",
            Self::ConversationFingerprint => "conversation_fingerprint",
            Self::Ephemeral => "ephemeral",
        }
    }
}

/// A session, and how it was arrived at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    scope: [u8; SCOPE_BYTES],
    origin: Origin,
}

impl Identity {
    pub fn id(&self) -> SessionId {
        SessionId::from_bytes(self.scope)
    }

    pub const fn origin(&self) -> Origin {
        self.origin
    }

    /// The `x-periskop-alias-scope` value: opaque, and the same string the
    /// `/_periskop/session/{id}` endpoint answers under.
    ///
    /// Hex of the derived identifier rather than the client's own header value.
    /// The client gets back a handle it can pin the next turn with, and the string
    /// it sent is not echoed anywhere, which matters because clients name sessions
    /// after the thing they are about.
    pub fn scope(&self) -> String {
        let mut out = String::with_capacity(SCOPE_BYTES * 2);
        for byte in self.scope {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

/// The keyed derivation every session identifier in one policy generation shares.
#[derive(Clone, Debug)]
pub struct Binding {
    key: [u8; 32],
}

impl Binding {
    /// Keys the derivation with the policy hash.
    ///
    /// The hash is 64 hex characters of blake3-256 (`proxy-policy.md` section 6),
    /// and a policy that failed to load never reaches this constructor, so a short
    /// or malformed value is padded rather than refused: this is a domain
    /// separator, not an authentication key, and refusing here would turn a
    /// cosmetic problem into a proxy that serves nothing.
    pub fn from_policy_hash(policy_hash: &str) -> Self {
        let mut key = [0u8; 32];
        for (slot, byte) in key.iter_mut().zip(policy_hash.as_bytes()) {
            *slot = *byte;
        }
        Self { key }
    }

    /// Runs the three steps in order.
    ///
    /// `body` is the parsed request body, or `None` for an endpoint that has no
    /// conversation in it (a model list, an administrative read).
    pub fn identify(
        &self,
        header: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Identity, VaultError> {
        if let Some(name) = header.map(str::trim).filter(|name| !name.is_empty()) {
            return Ok(Identity {
                scope: self.derive(HEADER_DOMAIN, name.as_bytes())?,
                origin: Origin::ClientHeader,
            });
        }

        if let Some(anchor) = body.and_then(conversation_anchor) {
            return Ok(Identity {
                scope: self.derive(FINGERPRINT_DOMAIN, anchor.as_bytes())?,
                origin: Origin::ConversationFingerprint,
            });
        }

        Ok(Identity {
            scope: fresh()?,
            origin: Origin::Ephemeral,
        })
    }

    /// HMAC-SHA256, truncated to the identifier's width.
    ///
    /// The primitive `proxy/spec.md` section 2.4 names. Truncation is to 128 bits,
    /// which is the width [`SessionId`] holds and far past the point where two
    /// conversations on one workstation collide.
    ///
    /// Fallible rather than infallible even though HMAC accepts every key length,
    /// because the alternative in a crate that denies `unwrap` is a silent
    /// fallback key, and a session identifier derived under a key nobody chose is
    /// worse than a request that refuses.
    fn derive(&self, domain: &[u8], input: &[u8]) -> Result<[u8; SCOPE_BYTES], VaultError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|_| VaultError::KeyDerivationFailed)?;
        mac.update(domain);
        // A separator no input can contain unescaped, so that "ab" ‖ "c" and
        // "a" ‖ "bc" are different messages. Unit separator, the same byte the
        // hook identity derivation uses.
        mac.update(&[0x1f]);
        mac.update(input);

        let digest = mac.finalize().into_bytes();
        let mut scope = [0u8; SCOPE_BYTES];
        scope.copy_from_slice(&digest[..SCOPE_BYTES]);
        Ok(scope)
    }
}

/// A single request session, drawn from the operating system's entropy source.
fn fresh() -> Result<[u8; SCOPE_BYTES], VaultError> {
    let mut bytes = [0u8; SCOPE_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| VaultError::EntropyUnavailable)?;
    Ok(bytes)
}

/// The opening of a conversation: the first system message and the first user
/// message (`proxy/spec.md` section 2.4 step 2).
///
/// Both provider shapes are read, because the fingerprint has to work on the
/// endpoint the client actually used: OpenAI puts the system turn in
/// `messages[]` with `role = "system"`, Anthropic puts it in a top level `system`
/// field which is either a string or a list of blocks.
///
/// `None` when there is no user turn at all. A fingerprint over a system prompt
/// alone would put every conversation that shares a system prompt into one
/// session, which is the opposite mistake to the one open question 1 describes and
/// a worse one: two users' values would share an alias space.
fn conversation_anchor(body: &Value) -> Option<String> {
    let system = anthropic_system(body).or_else(|| first_message_of_role(body, "system"));
    let user = first_message_of_role(body, "user")?;
    Some(match system {
        Some(system) => format!("{system}\u{1f}{user}"),
        None => format!("\u{1f}{user}"),
    })
}

fn anthropic_system(body: &Value) -> Option<String> {
    match body.get("system")? {
        Value::String(text) => Some(text.clone()),
        blocks @ Value::Array(_) => Some(text_of(blocks)),
        _ => None,
    }
}

fn first_message_of_role(body: &Value, role: &str) -> Option<String> {
    let messages = body.get("messages")?.as_array()?;
    messages
        .iter()
        .find(|message| message.get("role").and_then(Value::as_str) == Some(role))
        .map(|message| message.get("content").map(text_of).unwrap_or_default())
}

/// The text of a content field in either shape: a plain string, or a list of
/// blocks each of which may carry a `text`.
fn text_of(content: &Value) -> String {
    match content {
        Value::String(text) => text.clone(),
        Value::Array(blocks) => blocks
            .iter()
            .filter_map(|block| match block {
                Value::String(text) => Some(text.clone()),
                other => other.get("text").and_then(Value::as_str).map(str::to_owned),
            })
            .collect::<Vec<String>>()
            .join("\n"),
        _ => String::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    fn binding() -> Binding {
        Binding::from_policy_hash(&"a1b2c3d4".repeat(8))
    }

    fn openai_body(system: &str, user: &str) -> Value {
        json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ]
        })
    }

    /// Task 86's first criterion: two turns under the same header see the same
    /// session, so they see the same aliases.
    #[test]
    fn two_turns_under_the_same_header_are_the_same_session() {
        let binding = binding();
        let first = binding
            .identify(
                Some("weekly-report"),
                Some(&openai_body("you are helpful", "hello")),
            )
            .unwrap();
        let second = binding
            .identify(
                Some("weekly-report"),
                // A completely different body: the header decides, so the body is
                // not consulted at all.
                Some(&openai_body("you are terse", "goodbye")),
            )
            .unwrap();

        assert_eq!(first.id(), second.id());
        assert_eq!(first.scope(), second.scope());
        assert_eq!(first.origin(), Origin::ClientHeader);
    }

    #[test]
    fn two_clients_that_named_their_sessions_differently_do_not_share_one() {
        let binding = binding();
        let mine = binding.identify(Some("mine"), None).unwrap();
        let theirs = binding.identify(Some("theirs"), None).unwrap();
        assert_ne!(mine.id(), theirs.id());
    }

    #[test]
    fn the_scope_is_a_handle_and_not_the_name_the_client_sent() {
        let identity = binding().identify(Some("acme-payroll-2026"), None).unwrap();
        let scope = identity.scope();
        assert_eq!(scope.len(), SCOPE_BYTES * 2);
        assert!(scope.chars().all(|c| c.is_ascii_hexdigit()));
        // The header value is often the name of the thing the conversation is
        // about, and the response goes back over the same wire the request came
        // in on. Echoing it would put that name in a header for no reason.
        assert!(!scope.contains("acme"));
    }

    #[test]
    fn without_a_header_the_conversation_s_opening_decides() {
        let binding = binding();
        let turn_one = binding
            .identify(None, Some(&openai_body("you are helpful", "who is Ada?")))
            .unwrap();
        // Turn two: same opening, a further message appended. The anchor is the
        // **first** system and the **first** user message, so it does not move.
        let mut turn_two_body = openai_body("you are helpful", "who is Ada?");
        if let Some(messages) = turn_two_body
            .get_mut("messages")
            .and_then(Value::as_array_mut)
        {
            messages.push(json!({"role": "assistant", "content": "a mathematician"}));
            messages.push(json!({"role": "user", "content": "and her mother?"}));
        }
        let turn_two = binding.identify(None, Some(&turn_two_body)).unwrap();

        assert_eq!(turn_one.id(), turn_two.id());
        assert_eq!(turn_one.origin(), Origin::ConversationFingerprint);
    }

    /// `proxy/spec.md` open question 1, demonstrated rather than described.
    ///
    /// A client that injects today's date (or a request id, or a clock) into its
    /// system prompt writes a different opening every turn. Step 2 then produces a
    /// different session every turn and alias consistency is gone: the same person
    /// gets `PERSON_1` on turn one and, in a fresh alias space, `PERSON_1` again
    /// standing for somebody else on turn two.
    ///
    /// This is not a bug in this function and it is not fixed here. It is the
    /// reason step 1 exists, and the reason the loss is a question in the spec
    /// rather than an assumption in the code.
    #[test]
    fn a_client_that_rewrites_its_system_prompt_loses_consistency_every_turn() {
        let binding = binding();
        let mut seen = std::collections::BTreeSet::new();
        for turn in 0..4 {
            let system = format!("You are helpful. The current time is 10:0{turn}.");
            let identity = binding
                .identify(None, Some(&openai_body(&system, "who is Ada?")))
                .unwrap();
            assert_eq!(identity.origin(), Origin::ConversationFingerprint);
            seen.insert(identity.scope());
        }
        assert_eq!(
            seen.len(),
            4,
            "the fingerprint absorbed a changing system prompt, which would make \
             this test pass by hiding open question 1 rather than by fixing it"
        );

        // And the fix that does exist: the same four turns with a header are one
        // session. This is what the spec means by asking whether the header should
        // be mandatory.
        let mut with_header = std::collections::BTreeSet::new();
        for turn in 0..4 {
            let system = format!("You are helpful. The current time is 10:0{turn}.");
            with_header.insert(
                binding
                    .identify(
                        Some("one-conversation"),
                        Some(&openai_body(&system, "who is Ada?")),
                    )
                    .unwrap()
                    .scope(),
            );
        }
        assert_eq!(with_header.len(), 1);
    }

    #[test]
    fn the_anthropic_shape_fingerprints_too() {
        let binding = binding();
        let body = json!({
            "model": "claude-sonnet-4",
            "system": [{"type": "text", "text": "you are helpful"}],
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}]
        });
        let identity = binding.identify(None, Some(&body)).unwrap();
        assert_eq!(identity.origin(), Origin::ConversationFingerprint);

        // The same opening written in the other shape is the same conversation:
        // the anchor is the text, not the JSON.
        let flat = json!({
            "model": "claude-sonnet-4",
            "system": "you are helpful",
            "messages": [{"role": "user", "content": "hello"}]
        });
        assert_eq!(
            identity.id(),
            binding.identify(None, Some(&flat)).unwrap().id()
        );
    }

    #[test]
    fn a_body_with_no_user_turn_falls_through_to_a_single_request_session() {
        let binding = binding();
        let no_user = json!({"messages": [{"role": "system", "content": "shared prompt"}]});

        let first = binding.identify(None, Some(&no_user)).unwrap();
        let second = binding.identify(None, Some(&no_user)).unwrap();

        assert_eq!(first.origin(), Origin::Ephemeral);
        // Two requests, two sessions. A fingerprint over a system prompt alone
        // would have made these one, and two different users sharing a system
        // prompt would then share an alias space.
        assert_ne!(first.id(), second.id());
    }

    #[test]
    fn no_body_at_all_is_a_single_request_session() {
        let identity = binding().identify(None, None).unwrap();
        assert_eq!(identity.origin(), Origin::Ephemeral);
    }

    #[test]
    fn an_empty_header_is_not_a_session_name() {
        // Otherwise every client that sets the header to "" would share one alias
        // space, which is the collision the derivation exists to prevent.
        for header in [Some(""), Some("   "), None] {
            assert_eq!(
                binding().identify(header, None).unwrap().origin(),
                Origin::Ephemeral
            );
        }
    }

    #[test]
    fn a_different_policy_generation_derives_a_different_session() {
        // Aliases minted under one rule set are not resumed under another: the
        // policy decides what is masked, so the same value can be an alias in one
        // generation and pass through in the next.
        let under_one = Binding::from_policy_hash(&"aa".repeat(32))
            .identify(Some("shared"), None)
            .unwrap();
        let under_two = Binding::from_policy_hash(&"bb".repeat(32))
            .identify(Some("shared"), None)
            .unwrap();
        assert_ne!(under_one.id(), under_two.id());
    }

    #[test]
    fn a_header_named_after_a_conversation_opening_does_not_collide_with_it() {
        // Domain separation, checked rather than assumed: without it a client
        // could name its session with another conversation's opening text and land
        // in that conversation's alias space.
        let binding = binding();
        let anchor = "you are helpful\u{1f}hello".to_owned();
        let by_header = binding.identify(Some(&anchor), None).unwrap();
        let by_fingerprint = binding
            .identify(None, Some(&openai_body("you are helpful", "hello")))
            .unwrap();
        assert_ne!(by_header.id(), by_fingerprint.id());
    }
}
