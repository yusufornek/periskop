//! One request, end to end.
//!
//! The order below is the fail closed matrix (`proxy/spec.md` section 10) written
//! as control flow, and every step that can refuse does so **before** anything
//! reaches the provider. That is the single rule the whole component is built
//! around: periskop never chooses "send it unmasked" over "refuse".
//!
//! ```text
//! route ──▶ vault reachable? ──▶ body parses? ──▶ session ──▶ tool arguments?
//!    │            503                 400            │             400 or declared
//!    └── 400/404/405                                 ▼
//!                                            mask (mint, file, replace)
//!                                              429 / 503 / 400
//!                                                    │
//!                                            redact headers ──▶ provider
//!                                                    │
//!                              vault still reachable? ── no ──▶ cut, deliver nothing
//!                                                    │
//!                                            redact headers ──▶ client
//! ```

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::alias::Minter;

use crate::policy::{Policy, ToolCallPolicy};
use crate::vault::{SessionId, Vault, VaultError};

use super::admin::{Metrics, PolicyProjection};
use super::declare::{rejected, Declared, Gap, Subject};
use super::errors::{ProxyError, Refusal};
use super::event::{Measurement, Parts, ProxyEvent};
use super::headers::{HeaderList, Marks, SESSION_HEADER};
use super::observe::RequestRecord;
use super::passthrough::{shipped_base, AllowList, BaseUrl};
use super::request_path::{alias_key_for, mask, Pass};
use super::route::{self, Admin, Periskop, Provider, Resolved, Route, Treatment};
use super::session::Binding;
use super::stream::automaton::Snapshot;
use super::stream::restore::{Lookup, SessionLookup};
use super::stream::{
    is_event_stream, is_json, restore_body, window_stats, Measured, Relay, Settings,
};
use super::upstream::{Answer, Call, Upstream};

/// How many conversations keep a minter in memory.
///
/// Bounded because this is a long lived process: a map with one entry per session
/// and no ceiling is a memory leak that grows at the rate the organisation talks
/// to its models. When the bound is reached the least recently used conversation
/// loses its minter, which costs alias consistency for that conversation and
/// nothing else, because the vault still holds every record.
const MINTERS_KEPT: usize = 4096;

/// Whether the vault handle is still good.
///
/// Shared and atomic because the answer can change **after** a request has been
/// sent upstream, which is the case `proxy/spec.md` section 10's "akış ortasında
/// kasa erişimi kayboldu" row is about. Once it is lost it stays lost: the same
/// section says a tampered or rolled back vault is not recovered from, so a proxy
/// that reopened it on the next request would be retrying a security event.
#[derive(Clone, Debug, Default)]
pub struct VaultAccess(Arc<AtomicBool>);

impl VaultAccess {
    pub fn live() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }

    pub fn is_live(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// Records that the vault can no longer be used.
    pub fn lost(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Where "now" comes from.
///
/// Injected so that a test can pin the clock. Sessions expire on wall clock time
/// and a test that waited for a day would not be a test.
#[derive(Clone, Copy, Debug)]
pub enum Clock {
    System,
    Fixed(u64),
}

impl Clock {
    fn now_ms(self) -> u64 {
        match self {
            Self::Fixed(at) => at,
            Self::System => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
                // Before the epoch means a clock nobody set. Zero is wrong, and it
                // is wrong in the safe direction: every session looks expired.
                .unwrap_or(0),
        }
    }
}

/// One request as it arrived.
#[derive(Clone, Debug)]
pub struct Incoming {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: HeaderList,
    pub body: Vec<u8>,
}

/// One response as it leaves.
#[derive(Clone, Debug)]
pub struct Outgoing {
    pub status: u16,
    pub headers: HeaderList,
    pub body: Vec<u8>,
}

impl Outgoing {
    fn json(status: u16, body: String, marks: &Marks) -> Self {
        let headers = super::headers::to_downstream(
            &HeaderList::new().with("content-type", "application/json"),
            marks,
        );
        Self {
            status,
            headers,
            body: body.into_bytes(),
        }
    }
}

struct Slot {
    minter: Minter,
    /// The conversation's alias set, frozen (ADR-010 section 4).
    ///
    /// Rebuilt only when the session has issued an alias since it was taken, so
    /// two requests that minted nothing new share one automaton through the
    /// version counter rather than paying to build the same trie twice. Nothing
    /// on the response path may replace it: a stream holds an `Arc` of the one it
    /// started with, so a rebuild here cannot reach a stream in flight.
    snapshot: Arc<Snapshot>,
    last_used_ms: u64,
    /// The opaque handle the client holds for this conversation, kept so that
    /// `/_periskop/session/{id}` can answer without reconstructing it from the
    /// session identifier, whose bytes are the vault's HKDF salt and are not
    /// readable outside the vault.
    scope: String,
}

/// The proxy, minus the socket.
pub struct Gateway {
    policy: Policy,
    binding: Binding,
    allow: AllowList,
    bases: BTreeMap<Provider, BaseUrl>,
    vault: Mutex<Vault>,
    access: VaultAccess,
    minters: Mutex<BTreeMap<SessionId, Slot>>,
    metrics: Mutex<Metrics>,
    log: Mutex<Vec<RequestRecord>>,
    /// The measurement records, kept in this process and written nowhere.
    ///
    /// `proxy-events.md`: "Olay kayıtları hiçbir koşulda dışarı gönderilmez."
    /// A bounded vector rather than a sink, for the same reason [`MINTERS_KEPT`]
    /// exists: this is a long lived process, and an unbounded list of anything
    /// per request is a leak that grows at the rate the organisation talks to its
    /// models.
    events: Mutex<Vec<ProxyEvent>>,
    /// The `unmasked_passthrough` findings this process has produced, newest last.
    ///
    /// The third leg of `proxy-api.md`'s three legged declaration, and it is a
    /// field here because a leg nothing keeps is a leg nothing made: the
    /// declaration type built a finding and handed it back through an accessor no
    /// source file called, so the contract's "declared in three places at once"
    /// was true in two of them. Bounded like [`Self::events`], for the same reason.
    findings: Mutex<Vec<Value>>,
    upstream: Arc<dyn Upstream>,
    clock: Clock,
}

/// How many event records stay in memory.
///
/// The oldest are dropped first. Losing an old measurement costs a data point in
/// a local benchmark; keeping every one of them costs the process.
const EVENTS_KEPT: usize = 4096;

/// How many declared gaps stay in memory, oldest dropped first.
///
/// Smaller than [`EVENTS_KEPT`] because a finding is only written when a request
/// actually crossed unmasked, so a process producing four thousand of them has a
/// policy problem rather than a memory problem.
const FINDINGS_KEPT: usize = 1024;

impl Gateway {
    /// Builds a gateway around a loaded policy and an open vault.
    ///
    /// Both are required rather than optional: a policy that did not load and a
    /// vault that did not open are the two conditions under which the proxy
    /// accepts no request at all (`proxy-api.md`, "Hata davranışı"), and a type
    /// that could hold neither would push that check into the request path.
    pub fn new(
        policy: Policy,
        vault: Vault,
        upstream: Arc<dyn Upstream>,
        allow: AllowList,
        clock: Clock,
    ) -> Result<Self, Refusal> {
        if let Some(refusal) =
            Self::detection_refusal(crate::detect::pattern::shapes_are_loadable())
        {
            return Err(refusal);
        }
        let mut bases = BTreeMap::new();
        for provider in [Provider::OpenAi, Provider::Anthropic] {
            // A provider whose default host the operator took off the allow list
            // is simply not configured; the route for it then refuses rather than
            // dialling a host nobody vetted.
            if let Ok(base) = shipped_base(provider, &allow) {
                bases.insert(provider, base);
            }
        }

        Ok(Self {
            binding: Binding::from_policy_hash(policy.policy_hash()),
            policy,
            allow,
            bases,
            vault: Mutex::new(vault),
            access: VaultAccess::live(),
            minters: Mutex::new(BTreeMap::new()),
            metrics: Mutex::new(Metrics::default()),
            log: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
            findings: Mutex::new(Vec::new()),
            upstream,
            clock,
        })
    }

    /// Points one provider at a base URL an operator configured.
    pub fn with_base(mut self, provider: Provider, base_url: &str) -> Result<Self, Refusal> {
        let base = super::passthrough::resolve_base_url(base_url, &self.allow)?;
        self.bases.insert(provider, base);
        Ok(self)
    }

    /// The vault access flag, so that a test can reproduce a loss and a caller can
    /// see one.
    pub fn access(&self) -> VaultAccess {
        self.access.clone()
    }

    /// Adopts an access flag somebody else already holds.
    ///
    /// The seam the "vault lost after the answer started" case needs: an upstream
    /// that loses the vault while answering has to hold the same flag this gateway
    /// reads, and a flag handed out after construction would be read too late.
    pub fn sharing_access(mut self, access: VaultAccess) -> Self {
        self.access = access;
        self
    }

    /// Every request this gateway has recorded, in order.
    ///
    /// This is the log surface: it is what a logging framework would emit, and
    /// `tests/vault_no_plaintext.rs` scans it for planted values and for the
    /// caller's API key.
    pub fn log(&self) -> Vec<RequestRecord> {
        lock(&self.log).clone()
    }

    pub fn metrics_snapshot(&self) -> Metrics {
        lock(&self.metrics).clone()
    }

    /// Every `ProxyEvent` this gateway has measured, oldest first.
    ///
    /// The only way out of the process, and it is a caller in this process
    /// asking. There is no sink, no writer and no exporter: `proxy-events.md`
    /// keeps these local, and `tests/proxy_event.rs` fails if a third source file
    /// in `src/` learns the type's name.
    pub fn events(&self) -> Vec<ProxyEvent> {
        lock(&self.events).clone()
    }

    /// Every `unmasked_passthrough` finding this gateway has produced, oldest
    /// first, as the documents `finding.schema.json` describes.
    ///
    /// The reader of the declaration's third leg. It exists so the leg is
    /// **produced** rather than merely constructible: what a caller cannot read is
    /// indistinguishable from what was never written, and that is exactly the
    /// state this was in.
    pub fn findings(&self) -> Vec<Value> {
        lock(&self.findings).clone()
    }

    /// Files one finding, dropping the oldest once the bound is reached.
    ///
    /// The drop is **counted**. It used to be silent, and a silent drop is the
    /// one thing this repository does not allow a loss to be: a reader of
    /// [`Self::findings`] saw a list with no way to tell whether it was the whole
    /// of what this process produced or the most recent thousand of it. The
    /// count goes to `periskop_proxy_findings_evicted_total`, so the answer is on
    /// the same endpoint an operator is already watching.
    ///
    /// The metrics lock is taken **after** the findings lock is released rather
    /// than inside it. Nesting is what makes a lock order, and a lock order that
    /// only exists on one path is the kind that is reversed by the next caller.
    fn file_finding(&self, document: Value) {
        let evicted = {
            let mut findings = lock(&self.findings);
            let mut evicted = 0u64;
            while findings.len() >= FINDINGS_KEPT {
                findings.remove(0);
                evicted += 1;
            }
            findings.push(document);
            evicted
        };
        if evicted > 0 {
            lock(&self.metrics).record_findings_evicted(evicted);
        }
    }

    /// Handles one request.
    pub async fn handle(&self, incoming: Incoming) -> Outgoing {
        let started = self.clock.now_ms();
        let (outgoing, mut record) = self.dispatch(incoming).await;
        record.added_latency_ms = self.clock.now_ms().saturating_sub(started);

        {
            let mut metrics = lock(&self.metrics);
            if record.error.is_some() {
                metrics.record_refusal();
            } else {
                metrics.record_request(record.masked_entities, record.added_latency_ms);
            }
            // `periskop_proxy_stream_reassembly_errors_total` used to be called
            // from its own unit test and from nowhere else, so the endpoint
            // reported a permanent zero and an operator watching it would have
            // read "no stream ever failed to reassemble" off a counter no
            // request could raise. It is raised here, on the one condition
            // `proxy-api.md` calls a reassembly error: the stream ended with
            // bytes that never completed a frame or with text still held back.
            if record.measured.truncated {
                metrics.record_stream_reassembly_error();
            }
        }
        if let Some(event) = self.event_for(&record) {
            // Counted for the reason `file_finding` gives: the buffer is bounded
            // on purpose and the eviction was invisible, so a reader of the event
            // list could not tell a complete measurement series from a window on
            // one. Locks are not nested here either.
            let evicted = {
                let mut events = lock(&self.events);
                let mut evicted = 0u64;
                while events.len() >= EVENTS_KEPT {
                    events.remove(0);
                    evicted += 1;
                }
                events.push(event);
                evicted
            };
            if evicted > 0 {
                lock(&self.metrics).record_events_evicted(evicted);
            }
        }
        lock(&self.log).push(record);
        outgoing
    }

    /// The measurement record for one finished request, when there is one.
    ///
    /// `None` for a request that never reached a conversation, which
    /// [`ProxyEvent::of`] decides rather than this function: the rule belongs to
    /// the record's own contract, not to the caller that happens to build it.
    fn event_for(&self, record: &RequestRecord) -> Option<ProxyEvent> {
        ProxyEvent::of(&Parts {
            session_scope: &record.alias_scope,
            policy_version: self.policy.policy_version(),
            policy_hash: self.policy.policy_hash(),
            ruleset_hash: self.policy.ruleset_hash(),
            masking_profile: record.masking_profile,
            alias_style: self.policy.alias_style(),
            measurement: &record.measurement,
            stream: record.measured.stream,
            restore: record.measured.restore,
            record_tamper: record.measured.record_tamper,
            degraded: &record.degraded,
            total_ms: record.added_latency_ms,
        })
    }

    async fn dispatch(&self, incoming: Incoming) -> (Outgoing, RequestRecord) {
        let mut record = self.blank_record();

        match route::resolve(&incoming.method, &incoming.path) {
            Resolved::Route(Route::Admin(endpoint)) => {
                record.endpoint = "admin";
                (self.admin(endpoint, &mut record), record)
            }
            Resolved::Route(Route::Periskop { endpoint, argument }) => {
                record.endpoint = "periskop";
                (self.periskop(endpoint, &argument, &mut record), record)
            }
            Resolved::Route(Route::Passthrough {
                provider,
                treatment,
                upstream_path,
            }) => {
                record.endpoint = endpoint_name(treatment);
                record.provider = Some(provider.as_str());
                self.passthrough(incoming, provider, treatment, &upstream_path, record)
                    .await
            }
            Resolved::Unsupported(refusal) => {
                record.endpoint = "unsupported";
                (self.refuse(&refusal, &mut record), record)
            }
            Resolved::NotFound => {
                record.endpoint = "not_found";
                record.status = 404;
                (
                    Outgoing::json(
                        404,
                        detail("no endpoint of this proxy answers this path"),
                        &Marks::default(),
                    ),
                    record,
                )
            }
            Resolved::MethodNotAllowed => {
                record.endpoint = "method_not_allowed";
                record.status = 405;
                (
                    Outgoing::json(
                        405,
                        detail("this path answers a different method"),
                        &Marks::default(),
                    ),
                    record,
                )
            }
        }
    }

    fn blank_record(&self) -> RequestRecord {
        RequestRecord {
            endpoint: "unrouted",
            provider: None,
            session_origin: super::session::Origin::Ephemeral,
            alias_scope: String::new(),
            policy_id: self.policy.policy_id().to_owned(),
            masking_profile: self.policy.masking_profile(),
            masked_entities: 0,
            degraded: Vec::new(),
            status: 0,
            upstream_status: None,
            error: None,
            added_latency_ms: 0,
            measured: Measured::default(),
            measurement: Measurement::default(),
        }
    }

    fn refuse(&self, refusal: &Refusal, record: &mut RequestRecord) -> Outgoing {
        record.status = refusal.status();
        record.error = Some(refusal.error());
        Outgoing::json(
            refusal.status(),
            refusal.to_json(),
            &Marks {
                policy_id: self.policy.policy_id().to_owned(),
                error: Some(refusal.error()),
                ..Marks::default()
            },
        )
    }

    fn admin(&self, endpoint: Admin, record: &mut RequestRecord) -> Outgoing {
        let marks = Marks {
            api_version: true,
            ..Marks::default()
        };
        record.status = 200;

        let (content_type, body) = match endpoint {
            Admin::Policy => (
                "application/json",
                PolicyProjection::of(&self.policy).to_json(),
            ),
            // Bound, not restated. `VaultStatus` is already a closed set of seven
            // metadata fields with no field capable of carrying an alias to value
            // mapping; a second renderer here would be a second place to add an
            // eighth field to.
            Admin::VaultStatus => ("application/json", lock(&self.vault).status().to_json()),
            Admin::Metrics => (Metrics::CONTENT_TYPE, lock(&self.metrics).render()),
        };

        Outgoing {
            status: 200,
            headers: super::headers::to_downstream(
                &HeaderList::new().with("content-type", content_type),
                &marks,
            ),
            body: body.into_bytes(),
        }
    }

    fn periskop(&self, endpoint: Periskop, argument: &str, record: &mut RequestRecord) -> Outgoing {
        record.status = 200;
        let body = match endpoint {
            Periskop::Health => {
                let status = lock(&self.vault).status();
                format!(
                    "{{\"status\":\"{}\",\"vault_state\":\"{}\"}}",
                    if self.access.is_live() {
                        "ok"
                    } else {
                        "degraded"
                    },
                    status.state().as_str()
                )
            }
            // Counts, never aliases and never values (`proxy/spec.md` section
            // 2.2). The endpoint answers for a scope handle the client already
            // holds, so it discloses nothing the client did not have.
            Periskop::Session => {
                let count = lock(&self.minters)
                    .values()
                    .find(|slot| slot.scope == argument)
                    .map_or(0, |slot| slot.minter.issued_count());
                format!("{{\"alias_count\":{count}}}")
            }
        };
        Outgoing::json(200, body, &Marks::default())
    }

    async fn passthrough(
        &self,
        incoming: Incoming,
        provider: Provider,
        treatment: Treatment,
        upstream_path: &str,
        mut record: RequestRecord,
    ) -> (Outgoing, RequestRecord) {
        // Fail closed at the door. A vault that is gone means no request crosses,
        // and that is checked before the body is even parsed so that no code path
        // can reach the provider through an error branch.
        if !self.access.is_live() {
            let refusal = Refusal::new(
                ProxyError::VaultUnavailable,
                "the vault is not available, so nothing is forwarded",
            );
            let outgoing = self.refuse(&refusal, &mut record);
            return (outgoing, record);
        }

        let parsed = match parse_body(&incoming.body) {
            Ok(parsed) => parsed,
            Err(refusal) => {
                let outgoing = self.refuse(&refusal, &mut record);
                return (outgoing, record);
            }
        };

        let identity = match self
            .binding
            .identify(incoming.headers.get(SESSION_HEADER), parsed.as_ref())
        {
            Ok(identity) => identity,
            Err(refusal) => {
                let refusal = Refusal::from(refusal);
                let outgoing = self.refuse(&refusal, &mut record);
                return (outgoing, record);
            }
        };
        record.session_origin = identity.origin();
        record.alias_scope = identity.scope();

        let prepared = self.prepare_body(treatment, parsed, &identity, provider, &mut record);
        let (body, snapshot) = match prepared {
            Ok(prepared) => prepared,
            Err(refusal) => {
                let outgoing = self.refuse(&refusal, &mut record);
                return (outgoing, record);
            }
        };

        let Some(base) = self.bases.get(&provider) else {
            let refusal = Refusal::new(
                ProxyError::EndpointUnsupported,
                format!(
                    "no upstream is configured for {} that is on the allow list",
                    provider.as_str()
                ),
            );
            let outgoing = self.refuse(&refusal, &mut record);
            return (outgoing, record);
        };

        let call = Call {
            method: incoming.method.clone(),
            url: base.target(upstream_path, incoming.query.as_deref()),
            headers: super::headers::to_upstream(&incoming.headers, &base.authority()),
            body,
        };

        let answer = match self.upstream.send(call).await {
            Ok(answer) => answer,
            Err(unreachable) => {
                // The provider was not reached. Not a periskop error value: the
                // closed vocabulary is about periskop's own refusals, and inventing
                // a value for somebody else's outage would put a word on the wire
                // that no contract defines. So it does not travel under the `error`
                // key either, which is where the invented word used to sit.
                record.status = 502;
                let body = detail(&format!(
                    "the provider was not reached: {}",
                    unreachable.why
                ));
                return (Outgoing::json(502, body, &Marks::default()), record);
            }
        };
        record.upstream_status = Some(answer.status);

        // `proxy/spec.md` section 10, the row about losing the vault after the
        // answer has started. The upstream body is full of aliases; delivering it
        // with no vault to resolve them would hand the user a message about
        // `PSK_PERSON_1` and call it an answer. The answer is cut instead and
        // nothing of it is written.
        if !self.access.is_live() {
            record.status = 503;
            record.error = Some(ProxyError::VaultUnavailable);
            return (
                Outgoing {
                    status: 503,
                    headers: super::headers::to_downstream(
                        &HeaderList::new(),
                        &Marks {
                            policy_id: self.policy.policy_id().to_owned(),
                            alias_scope: record.alias_scope.clone(),
                            error: Some(ProxyError::VaultUnavailable),
                            // The answer was begun and did not finish, which is
                            // exactly what this header says.
                            stream_truncated: true,
                            ..Marks::default()
                        },
                    ),
                    body: Vec::new(),
                },
                record,
            );
        }

        // An upstream 4xx or 5xx is forwarded transparently (`proxy-api.md`,
        // "Hata davranışı"). It is the provider's answer, not periskop's refusal,
        // and rewriting it would hide a rate limit behind a proxy error. Its body
        // still goes through restoration, because a masked value can be quoted in
        // an error message as easily as in an answer.
        record.status = answer.status;
        let body = match self.restore_answer(&answer, &snapshot, &identity, &mut record) {
            Ok(body) => body,
            // The answer was begun and is not finished, so it is cut the same way
            // a vault lost mid stream cuts it: nothing of the provider's body is
            // written, because parts of it stand for values this vault can no
            // longer vouch for.
            Err(refusal) => {
                record.status = refusal.status();
                record.error = Some(refusal.error());
                return (
                    Outgoing {
                        status: refusal.status(),
                        headers: super::headers::to_downstream(
                            &HeaderList::new(),
                            &Marks {
                                policy_id: self.policy.policy_id().to_owned(),
                                alias_scope: record.alias_scope.clone(),
                                error: Some(refusal.error()),
                                stream_truncated: true,
                                ..Marks::default()
                            },
                        ),
                        body: Vec::new(),
                    },
                    record,
                );
            }
        };

        // The two window facts, written whether or not a stream ran. They are
        // configuration rather than outcome: `l_max_static` is the compile time
        // constant this alias style chose, `l_max_session` is what this
        // conversation's frozen set makes of it, and both are as true of a
        // buffered JSON answer that never held a byte as of a streamed one. Left
        // at their defaults they are zeros, and `proxy-event.schema.json` rejects
        // a zero here because a zero reads as a window of nothing.
        let (l_max_static, l_max_session) = window_stats(
            &snapshot,
            self.policy.alias_style(),
            self.policy.l_max_session(),
        );
        record.measured.stream.l_max_static = l_max_static;
        record.measured.stream.l_max_session = l_max_session;

        let marks = Marks {
            masked_entities: record.masked_entities,
            policy_id: self.policy.policy_id().to_owned(),
            alias_scope: record.alias_scope.clone(),
            degraded: record.degraded.clone(),
            stream_truncated: record.measured.truncated,
            ..Marks::default()
        };
        (
            Outgoing {
                status: answer.status,
                headers: super::headers::to_downstream(&answer.headers, &marks),
                body,
            },
            record,
        )
    }

    /// Puts this conversation's values back into the provider's answer.
    ///
    /// Two shapes, one state machine. A server sent event stream is driven
    /// through [`Relay`] chunk by chunk, in the pieces the transport delivered,
    /// so that an alias cut in half by the wire is held rather than emitted. A
    /// buffered JSON answer is the degenerate case of the same walk. Anything
    /// else crosses untouched: this build rewrites text it can find through a
    /// contract, never bytes it guessed at.
    fn restore_answer(
        &self,
        answer: &Answer,
        snapshot: &Arc<Snapshot>,
        identity: &super::session::Identity,
        record: &mut RequestRecord,
    ) -> Result<Vec<u8>, Refusal> {
        let content_type = answer.headers.get("content-type");
        if snapshot.is_empty() {
            // Nothing to put back, so the provider's bytes cross as they are.
            // The stream is still read for the one fact that is true of it
            // whether or not this proxy rewrote a byte: whether it ended in the
            // middle of a frame. Returning here without asking was how a
            // conversation that masked nothing turned a provider dying mid frame
            // into a clean `200`.
            record.measured.truncated |=
                super::stream::untouched_answer_was_cut(content_type, &answer.body);
            return Ok(answer.body.clone());
        }
        if !is_event_stream(content_type) && !is_json(content_type) {
            return Ok(answer.body.clone());
        }

        let now_ms = self.clock.now_ms();
        let session = identity.id();
        let mut vault = lock(&self.vault);
        let mut lookup = SessionLookup::new(&mut vault, snapshot, session, now_ms);
        self.restore_with(answer, snapshot, &mut lookup, record, now_ms)
    }

    /// The half of [`Self::restore_answer`] that does the work, over any
    /// [`Lookup`].
    ///
    /// Split out so that the rule below can be held by a test with a lookup that
    /// reports a tampered record, rather than only by a corrupted vault file that
    /// no in-memory test can produce.
    fn restore_with(
        &self,
        answer: &Answer,
        snapshot: &Arc<Snapshot>,
        lookup: &mut dyn Lookup,
        record: &mut RequestRecord,
        now_ms: u64,
    ) -> Result<Vec<u8>, Refusal> {
        // Before anything is read, whether it **can** be read. A conversation with
        // no aliases has nothing to put back, so a coded answer is the provider's
        // business and crosses untouched; one with aliases is an answer whose
        // words this proxy owes the user, and it cannot owe them out of bytes it
        // cannot open.
        if !snapshot.is_empty() {
            if let Some(refusal) = Self::coding_refusal(answer.headers.get("content-encoding")) {
                return Err(refusal);
            }
        }

        let content_type = answer.headers.get("content-type");
        let body = self.restored_bytes(answer, snapshot, lookup, record, now_ms, content_type);

        // `proxy/spec.md` section 10, the `vault_record_tamper` row, and
        // `proxy-event.schema.json`'s own description of the field: "every non
        // zero value is a security event and ended in a 503". The lookup answers
        // a tampered record with `None`, so that one span goes back as the raw
        // alias, which is safe **for the span** and not for the answer: the rest
        // of the body is a message written about values this vault can no longer
        // vouch for, and section 10 says the value behind a swapped record is
        // given to the user under no circumstances. Counting it and delivering a
        // 200 put the decision in a field nobody reads.
        if let Some(refusal) = Self::tamper_refusal(record.measured.record_tamper) {
            return Err(refusal);
        }
        Ok(body)
    }

    fn restored_bytes(
        &self,
        answer: &Answer,
        snapshot: &Arc<Snapshot>,
        lookup: &mut dyn Lookup,
        record: &mut RequestRecord,
        now_ms: u64,
        content_type: Option<&str>,
    ) -> Vec<u8> {
        if is_event_stream(content_type) {
            let mut relay = Relay::new(&Settings {
                snapshot: Arc::clone(snapshot),
                style: self.policy.alias_style(),
                declared_l_max_session: self.policy.l_max_session(),
                hold_timeout_ms: self.policy.hold_timeout_ms(),
                on_hold_timeout: self.policy.on_hold_timeout(),
            });
            let mut out = Vec::new();
            for piece in answer.pieces() {
                out.extend(relay.push(piece, lookup, now_ms));
            }
            out.extend(relay.finish(lookup, now_ms));
            // Both kinds of leftover come off the relay now: the bytes it was
            // holding in a lane and the bytes the reader could not complete into
            // a frame. They used to be `|=`d together here, which left every
            // answer that never reached a relay reporting a clean ending.
            record.measured = relay.measured();
            return out;
        }

        match restore_body(snapshot, lookup, &answer.body) {
            Some((body, stats)) => {
                record.measured.restore = stats;
                record.measured.record_tamper = lookup.tampered();
                body
            }
            // A body that does not parse is the provider's, not ours to rewrite.
            // The tamper count still has to be read off the lookup, or a record
            // that failed verification while a stream was walked would be
            // forgotten by the one branch that does not rewrite anything.
            None => {
                record.measured.record_tamper = lookup.tampered();
                answer.body.clone()
            }
        }
    }

    /// The refusal a build owes when detection layer A did not load.
    ///
    /// ADR-011 section 1 and `proxy/spec.md` section 3.1 make layer A mandatory
    /// and always on, and `detect::pattern` compiles its shapes with
    /// `filter_map(...ok())`: one malformed expression is dropped and the scan
    /// then returns an empty vector for the **whole** layer. Nothing declared it.
    /// A single bad edit to one regular expression therefore produced a proxy
    /// that masked no IBAN, no card and no API key, on every request, with no
    /// header, no event and no error, while `x-periskop-masked-entities: 0`
    /// looked like a prompt with nothing in it.
    ///
    /// This is a refusal to **start** rather than a per-request declaration for
    /// one reason: `proxy-event.schema.json`'s `degraded_reasons` is a closed
    /// dictionary with no value for it, and that file is a contract this role
    /// does not change (CLAUDE.md, E1). Refusing to start is also the stronger
    /// answer of the two, and the closed error vocabulary's value for "fix the
    /// configuration and restart, no request is accepted at all" is
    /// `policy_unloadable`. The detail names the real cause; the request for a
    /// declared reason is filed in `hub/memory/interfaces.md`.
    fn detection_refusal(shapes_are_loadable: bool) -> Option<Refusal> {
        (!shapes_are_loadable).then(|| {
            Refusal::new(
                ProxyError::PolicyUnloadable,
                "detection layer A did not load: at least one of its shapes failed to compile, \
                 so nothing this build promises to mask would be masked. No request is served.",
            )
        })
    }

    /// The refusal an answer owes when it arrives in a coding this build cannot
    /// read.
    ///
    /// `None` for every ordinary answer, because [`super::headers::to_upstream`]
    /// asks the provider for `identity` and a provider that honours RFC 9110
    /// answers in it. This is the second lock: a provider is free to ignore the
    /// negotiation, and what happened when one did was the failure this whole
    /// component is built to make impossible. The coded bytes parsed as no JSON,
    /// the branch for "a body that does not parse is the provider's, not ours to
    /// rewrite" forwarded them whole, the user read `PSK_EMAIL_1` off the screen
    /// and `restore_stats.aliases_leaked` said `0`. Restoration had not run and
    /// nothing in the record said so.
    ///
    /// **The value is the closest one the vocabulary holds, and it is not exact.**
    /// `proxy-api.md` fixes ten values and none of them names a representation
    /// this build cannot decode; `endpoint_unsupported` is the entry for "an
    /// endpoint or a field this build does not implement", and a content coding
    /// with no decoder here is a field of the exchange this build does not
    /// implement. Its 400 reads as a client error and this is nearer the
    /// provider's, which is the inexactness: it is recorded rather than papered
    /// over, and the request for a dedicated value is filed in
    /// `hub/memory/interfaces.md`. Inventing an eleventh value here would put a
    /// word on the wire that no contract defines, which the closed vocabulary
    /// exists to prevent.
    fn coding_refusal(content_encoding: Option<&str>) -> Option<Refusal> {
        if super::stream::is_readable_coding(content_encoding) {
            return None;
        }
        // The declared coding is a token from a registry, not content, so it can
        // travel in the detail the way a field name does.
        let declared = content_encoding.unwrap_or_default();
        Some(Refusal::new(
            ProxyError::EndpointUnsupported,
            format!(
                "the provider answered in the content coding \"{declared}\", which this build \
                 cannot read, so this conversation's values could not be put back into the \
                 answer. The answer is not delivered rather than delivered with its aliases \
                 still in it."
            ),
        ))
    }

    /// The refusal a restored answer owes when a vault record did not verify.
    ///
    /// `None` when nothing was tampered with, which is every ordinary request.
    /// The threshold is "any", not "many": `proxy/spec.md` section 11 makes a
    /// single non zero count a security event, and a second opinion about how
    /// many is enough would be this component deciding for the operator how much
    /// tampering is acceptable.
    fn tamper_refusal(count: u32) -> Option<Refusal> {
        (count > 0).then(|| {
            Refusal::new(
                ProxyError::VaultRecordTamper,
                format!(
                    "{count} vault record(s) failed AAD or tag verification while this answer \
                     was restored, so the answer is not delivered"
                ),
            )
        })
    }

    /// Masks the body, or declares why it was not masked.
    ///
    /// Returns the bytes to send **and** the alias set the answer will be read
    /// against, frozen here because here is where the request is accepted
    /// (ADR-010 section 4). Freezing it any later would mean a stream could be
    /// read against a set that changed while it was arriving.
    fn prepare_body(
        &self,
        treatment: Treatment,
        parsed: Option<Value>,
        identity: &super::session::Identity,
        provider: Provider,
        record: &mut RequestRecord,
    ) -> Result<(Vec<u8>, Arc<Snapshot>), Refusal> {
        let session = &identity.id();
        let empty = || Arc::new(Snapshot::empty());
        let Some(parsed) = parsed else {
            // No body: a model list. Nothing to scan and nothing to declare.
            return Ok((Vec::new(), empty()));
        };
        let subject = Subject {
            scope: &record.alias_scope,
            provider: provider.as_str(),
        };

        if treatment == Treatment::UnmaskedAndDeclared {
            let declared = Declared::make(Gap::UnsupportedEndpoint, true, true, subject)?;
            record.degraded.push(declared.reason());
            self.file_finding(declared.finding().to_value());
            return Ok((parsed.to_string().into_bytes(), empty()));
        }
        if treatment == Treatment::NoUserText {
            return Ok((parsed.to_string().into_bytes(), empty()));
        }

        if carries_tool_arguments(&parsed) {
            match self.policy.tool_call_policy() {
                ToolCallPolicy::Reject => return Err(rejected()),
                ToolCallPolicy::PassThrough => {
                    let declared = Declared::make(Gap::ToolArguments, true, true, subject)?;
                    record.degraded.push(declared.reason());
                    // The third leg, written where a caller can read it. Filed
                    // beside the reason rather than after the request completes,
                    // so that the leg exists before the unmasked body is handed to
                    // the upstream and not after it has already crossed.
                    self.file_finding(declared.finding().to_value());
                }
            }
        }

        let now_ms = self.clock.now_ms();
        let mut vault = lock(&self.vault);
        let mut minters = lock(&self.minters);

        let key = alias_key_for(&mut vault, session, now_ms).map_err(|refusal| {
            self.note_vault_failure(&refusal);
            Refusal::from(refusal)
        })?;
        let slot = minters.entry(*session).or_insert_with(|| Slot {
            minter: Minter::new(key, self.policy.alias_style()),
            snapshot: Arc::new(Snapshot::empty()),
            last_used_ms: now_ms,
            scope: identity.scope(),
        });
        slot.last_used_ms = now_ms;

        let masked = {
            let clock = self.clock;
            let mut pass = Pass {
                policy: &self.policy,
                session: *session,
                minter: &mut slot.minter,
                vault: &mut vault,
                // The gateway's own clock, so that a pinned clock pins the phase
                // timings in the event record too and the same request twice
                // produces the same bytes.
                now: &move || clock.now_ms(),
            };
            mask(&mut pass, &parsed)
        };
        prune(&mut minters);

        let masked = masked.inspect_err(|refusal| {
            if matches!(
                refusal.error(),
                ProxyError::VaultUnavailable
                    | ProxyError::VaultIntegrityFailed
                    | ProxyError::VaultRecordTamper
            ) {
                self.access.lost();
            }
        })?;

        record.masked_entities = masked.masked_entities;
        record.degraded.extend(masked.degraded.iter().copied());
        record.degraded.sort_unstable();
        record.degraded.dedup();
        record.measurement = Measurement {
            masked: masked.by_type.clone(),
            allowed: masked.allowed.clone(),
            aliases: masked.alias_stats.clone(),
            detect_ms: masked.detect_ms,
            alias_ms: masked.alias_ms,
        };

        let snapshot = {
            let Some(slot) = minters.get_mut(session) else {
                // The slot was inserted a few lines above and pruning keeps the
                // most recently used; written as a fallback rather than an unwrap
                // so that a future bound change cannot turn this into a panic.
                return Ok((
                    masked.body.to_string().into_bytes(),
                    Arc::new(Snapshot::empty()),
                ));
            };
            slot.snapshot = refreshed(&slot.snapshot, &slot.minter);
            Arc::clone(&slot.snapshot)
        };
        Ok((masked.body.to_string().into_bytes(), snapshot))
    }

    /// A vault failure that means the vault may not be used again.
    ///
    /// Integrity and tamper are not retried: `proxy/spec.md` section 10 says no
    /// recovery is attempted, and a proxy that reopened the vault on the next
    /// request would turn a security event into a transient blip in a graph.
    fn note_vault_failure(&self, refusal: &VaultError) {
        if matches!(
            ProxyError::from(refusal),
            ProxyError::VaultIntegrityFailed | ProxyError::VaultRecordTamper
        ) {
            self.access.lost();
        }
    }
}

/// The conversation's frozen alias set, rebuilt only when it has changed.
///
/// ADR-010 section 4: "Oturuma yeni takma ad eklenmediyse bir sonraki istek aynı
/// otomatı sürüm sayacıyla paylaşır." The version is the number of aliases the
/// session has issued, which only ever grows, so an unchanged count is an
/// unchanged set. Sharing is not only a saving: it is what makes "the automaton
/// was not rebuilt" a checkable property rather than an intention.
fn refreshed(current: &Arc<Snapshot>, minter: &Minter) -> Arc<Snapshot> {
    let version = minter.issued_count() as u64;
    if current.version() == version {
        return Arc::clone(current);
    }
    Arc::new(Snapshot::frozen(
        version,
        minter.issued_aliases().map(str::to_owned),
    ))
}

fn endpoint_name(treatment: Treatment) -> &'static str {
    match treatment {
        Treatment::MaskedRoundTrip => "masked_round_trip",
        Treatment::MaskedOneWay => "masked_one_way",
        Treatment::NoUserText => "no_user_text",
        Treatment::UnmaskedAndDeclared => "unmasked_declared",
    }
}

/// The body of an answer that is **not** one of periskop's refusals.
///
/// A routing outcome and an upstream outage are both real answers with no entry
/// in `proxy-api.md`'s closed error dictionary, and all three of them used to be
/// written as `{"error":"<invented word>"}`. A client cannot write a total match
/// over a dictionary that grows a word whenever a handler needs one, and that is
/// the whole reason the dictionary is closed: `error` is the key those ten values
/// travel under, so an answer that has none of them says so by carrying no
/// `error` key at all. What it does carry is the same `detail` field
/// [`Refusal::to_json`] writes, because the sentence explaining the answer is
/// useful either way.
///
/// `the_error_key_never_leaves_the_closed_dictionary` is what holds this: it
/// walks every answer this gateway can produce and reads the key back out.
fn detail(sentence: &str) -> String {
    format!("{{\"detail\":{}}}", super::json::quote(sentence))
}

/// Parses the request body, refusing anything that is not JSON.
///
/// An empty body is `None` rather than an error: `GET /v1/models` has no body and
/// refusing it would make a supported endpoint unusable.
fn parse_body(bytes: &[u8]) -> Result<Option<Value>, Refusal> {
    if bytes.is_empty() {
        return Ok(None);
    }
    serde_json::from_slice(bytes).map(Some).map_err(|why| {
        Refusal::new(
            ProxyError::BodyUnparsable,
            // The parser's own message: a line and column, never the bytes. A
            // refusal that quoted the body would put unmasked content into a
            // response and, through it, into whatever logs the response.
            format!("the request body is not JSON: {why}"),
        )
    })
}

/// Whether this body carries structured tool-call or tool-result arguments.
///
/// Both provider shapes: OpenAI's `tools`/`functions`/`tool_calls`, Anthropic's
/// `tool_use` and `tool_result` content blocks.
fn carries_tool_arguments(body: &Value) -> bool {
    for key in ["tools", "functions", "tool_choice", "function_call"] {
        if body.get(key).is_some_and(|value| !value.is_null()) {
            return true;
        }
    }
    let Some(messages) = body.get("messages").and_then(Value::as_array) else {
        return false;
    };
    messages.iter().any(|message| {
        message.get("tool_calls").is_some()
            || message.get("function_call").is_some()
            || message
                .get("content")
                .and_then(Value::as_array)
                .is_some_and(|blocks| {
                    blocks.iter().any(|block| {
                        matches!(
                            block.get("type").and_then(Value::as_str),
                            Some("tool_use" | "tool_result")
                        )
                    })
                })
    })
}

/// Drops the least recently used conversations once the map is over its bound.
fn prune(minters: &mut BTreeMap<SessionId, Slot>) {
    while minters.len() > MINTERS_KEPT {
        let Some(oldest) = minters
            .iter()
            .min_by_key(|(_, slot)| slot.last_used_ms)
            .map(|(id, _)| *id)
        else {
            return;
        };
        minters.remove(&oldest);
    }
}

/// Takes a lock, recovering from poisoning.
///
/// A panic in one request must not make the proxy answer every later request with
/// a lock error: fail closed means refusing the request that went wrong, not
/// bricking the process. The data behind these locks is a counter map, a log
/// vector and the vault handle, none of which a panic can leave half written in a
/// way that matters here.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::alias::{AliasKey, AliasStyle, EntityType};

    use super::*;

    fn minter() -> Minter {
        Minter::new(
            AliasKey::from_key_bytes([0x91; 32]),
            AliasStyle::TypePreserving,
        )
    }

    /// ADR-010 section 4, the sharing half.
    #[test]
    fn a_session_that_minted_nothing_new_keeps_the_automaton_it_had() {
        let mut book = minter();
        book.mint(EntityType::Person, "Ahmet Yilmaz")
            .expect("a person is minted");

        let first = refreshed(&Arc::new(Snapshot::empty()), &book);
        assert_eq!(first.alias_count(), 1);
        assert_eq!(first.version(), 1);

        // Same conversation, next request, nothing new masked.
        let again = refreshed(&first, &book);
        assert!(
            Arc::ptr_eq(&first, &again),
            "the automaton was rebuilt for a session whose alias set did not change"
        );
    }

    /// And the other half: a set that did change is not reused.
    #[test]
    fn a_session_that_minted_something_gets_an_automaton_that_holds_it() {
        let mut book = minter();
        book.mint(EntityType::Person, "Ahmet Yilmaz")
            .expect("a person is minted");
        let first = refreshed(&Arc::new(Snapshot::empty()), &book);

        book.mint(EntityType::Loc, "Kadikoy").expect("a place");
        let second = refreshed(&first, &book);
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(second.alias_count(), 2);
        assert_eq!(second.version(), 2);
    }

    /// The literal the user wrote is not in the automaton, on any path.
    #[test]
    fn a_withheld_literal_never_enters_the_frozen_set() {
        let mut book = minter();
        book.reserve_literal("PSK_PERSON_9");
        book.mint(EntityType::Person, "Ahmet Yilmaz")
            .expect("a person is minted");

        let snapshot = refreshed(&Arc::new(Snapshot::empty()), &book);
        assert!(
            !snapshot.holds("PSK_PERSON_9"),
            "a string the user wrote is in the set the response is read against"
        );
        assert_eq!(snapshot.alias_count(), 1);
    }

    /// A lookup that reports every alias as a record that failed verification.
    ///
    /// The only way to reach this state in a test: an in-memory vault's records
    /// cannot be corrupted from outside the process, which is exactly why the
    /// rule had no test and stayed fail open.
    struct Tampered {
        seen: u32,
    }

    impl Lookup for Tampered {
        fn value_for(&mut self, _alias: &str) -> Option<String> {
            self.seen = self.seen.saturating_add(1);
            None
        }

        fn tampered(&self) -> u32 {
            self.seen
        }
    }

    /// `proxy/spec.md` section 10: a record whose AAD or tag did not verify ends
    /// the request with a **503**, and the value behind it is given to the user
    /// under no circumstances.
    ///
    /// What happened instead: the count was written into the event record and the
    /// provider's answer went back with a 200. A swapped record produced a
    /// delivered answer and a number in a field nobody reads.
    #[test]
    fn a_record_that_failed_verification_ends_the_answer_instead_of_being_counted() {
        assert!(Gateway::tamper_refusal(0).is_none());
        let refusal =
            Gateway::tamper_refusal(1).expect("a record that failed verification was let through");
        assert_eq!(refusal.status(), 503);
        assert_eq!(refusal.error(), ProxyError::VaultRecordTamper);

        // And the same rule where it is actually applied, over a lookup that
        // reports the tamper, so that removing the check from the restore path
        // and not just from the helper is caught.
        let gateway = tamper_gateway();
        let mut book = minter();
        let alias = book
            .mint(EntityType::Person, "Ahmet Yilmaz")
            .expect("a person is minted")
            .alias;
        let snapshot = refreshed(&Arc::new(Snapshot::empty()), &book);

        let answer = Answer {
            status: 200,
            headers: HeaderList::new().with("content-type", "application/json"),
            body: serde_json::json!({ "content": alias })
                .to_string()
                .into_bytes(),
            chunks: Vec::new(),
        };
        let mut record = gateway.blank_record();
        let mut lookup = Tampered { seen: 0 };
        let refusal = gateway
            .restore_with(&answer, &snapshot, &mut lookup, &mut record, 0)
            .expect_err("an answer restored against a tampered record was delivered");
        assert_eq!(refusal.status(), 503);
        assert_eq!(refusal.error(), ProxyError::VaultRecordTamper);
        // The count still reaches the event record, because it is a security
        // event whether or not the request was refused.
        assert_eq!(record.measured.record_tamper, 1);
    }

    /// A coded answer is bytes the restore walk cannot read, and reading is the
    /// whole job.
    ///
    /// What happened before this test: `restore_body` parsed the gzip bytes as
    /// JSON, `serde_json::from_slice(...).ok()?` said `None`, and the branch that
    /// handles a body "the provider's, not ours to rewrite" forwarded it whole.
    /// The user saw `PSK_EMAIL_1` and the event record said `aliases_leaked: 0`,
    /// so the one counter that exists to report an unrestored alias reported a
    /// clean run. The answer is refused instead: a body this proxy cannot read is
    /// a body it cannot vouch for, and section 10's rule is that it refuses rather
    /// than delivering what it did not check.
    #[test]
    fn an_answer_in_a_coding_this_build_cannot_read_is_refused_instead_of_forwarded() {
        let gateway = tamper_gateway();
        let mut book = minter();
        let alias = book
            .mint(EntityType::Email, "ali@ornek.com")
            .expect("an address is minted")
            .alias;
        let snapshot = refreshed(&Arc::new(Snapshot::empty()), &book);

        // The bytes are irrelevant: what decides is the declared coding, because
        // deciding on the bytes would mean guessing at a format.
        let answer = Answer {
            status: 200,
            headers: HeaderList::new()
                .with("content-type", "application/json")
                .with("content-encoding", "gzip"),
            body: b"\x1f\x8b\x08\x00\x00\x00\x00\x00".to_vec(),
            chunks: Vec::new(),
        };
        let mut record = gateway.blank_record();
        let mut lookup = Table::of(&[(alias.as_str(), "ali@ornek.com")]);
        let refusal = gateway
            .restore_with(&answer, &snapshot, &mut lookup, &mut record, 0)
            .expect_err("a coded answer was delivered with its aliases unrestored");
        assert_eq!(refusal.error(), ProxyError::EndpointUnsupported);
        assert!(refusal.detail().contains("gzip"), "{}", refusal.detail());

        // The two codings that mean "no coding" are read, or every ordinary
        // answer would be refused and the rule would be a denial of service.
        for readable in [None, Some("identity"), Some("")] {
            let mut headers = HeaderList::new().with("content-type", "application/json");
            if let Some(coding) = readable {
                headers.push("content-encoding", coding);
            }
            let plain = Answer {
                status: 200,
                headers,
                body: serde_json::json!({ "content": alias })
                    .to_string()
                    .into_bytes(),
                chunks: Vec::new(),
            };
            let mut record = gateway.blank_record();
            let body = gateway
                .restore_with(&plain, &snapshot, &mut lookup, &mut record, 0)
                .unwrap_or_else(|refusal| panic!("{}", refusal.detail()));
            assert!(
                String::from_utf8_lossy(&body).contains("ali@ornek.com"),
                "{readable:?} was treated as unreadable"
            );
        }

        // A conversation that minted nothing has nothing to put back, so a coded
        // answer is the provider's business and crosses untouched. Without this
        // half the rule would refuse every compressed answer to a prompt that
        // held no entity, which is most of them.
        let empty = Arc::new(Snapshot::empty());
        let mut record = gateway.blank_record();
        assert!(gateway
            .restore_with(&answer, &empty, &mut lookup, &mut record, 0)
            .is_ok());
    }

    /// A stand-in table, so the assertions above are about the coding rule rather
    /// than about Argon2id.
    struct Table {
        rows: BTreeMap<String, String>,
    }

    impl Table {
        fn of(rows: &[(&str, &str)]) -> Self {
            Self {
                rows: rows
                    .iter()
                    .map(|(alias, value)| ((*alias).to_owned(), (*value).to_owned()))
                    .collect(),
            }
        }
    }

    impl Lookup for Table {
        fn value_for(&mut self, alias: &str) -> Option<String> {
            self.rows.get(alias).cloned()
        }
    }

    /// Ö-5: layer A failing to load stops the proxy instead of masking nothing.
    #[test]
    fn a_detection_layer_that_did_not_load_refuses_to_start_rather_than_running_empty() {
        // Both directions, because a rule that always refused would also make
        // `is_none` true for the shipped build and prove nothing.
        assert!(Gateway::detection_refusal(true).is_none());
        let refusal = Gateway::detection_refusal(false)
            .expect("a build with no pattern layer was allowed to start");
        assert_eq!(refusal.status(), 503);
        assert_eq!(refusal.error(), ProxyError::PolicyUnloadable);
        assert!(refusal.detail().contains("layer A"), "{}", refusal.detail());

        // And the shipped build does load, so the gateway above was buildable
        // for the reason this claims and not by accident.
        assert!(crate::detect::pattern::shapes_are_loadable());
    }

    /// `proxy-api.md`, "Tool-call argümanları": "geçiş vardır ama sessiz geçiş
    /// yoktur", declared in three places **at once**.
    ///
    /// What was true before this test: two of the three. The header carried
    /// `tool_arguments_unmasked`, the event record carried it in
    /// `degraded_reasons[]`, and the finding was built by `Declared::make` and
    /// handed back through an accessor that no file under `src/` ever called. So
    /// the type looked like it enforced the contract's "üçünden biri
    /// üretilemiyorsa istek reddedilir" while the third leg was produced by
    /// nothing and refused by nothing.
    ///
    /// Driven through `handle` rather than through `prepare_body`, because the
    /// claim is about what a running proxy emits and a unit test on the builder is
    /// what was already passing.
    #[tokio::test]
    async fn a_tool_call_that_crosses_unmasked_is_declared_in_all_three_places() {
        let gateway = tamper_gateway();
        let outgoing = gateway.handle(tool_call_request()).await;

        // 1. the response header. It carries every reason this request raised, so
        // the assertion is that this one is among them rather than that it is the
        // only one: `ner_disabled` is on every request by construction.
        let declared_header = outgoing
            .headers
            .get("x-periskop-degraded")
            .unwrap_or_default();
        assert!(
            declared_header
                .split(',')
                .any(|reason| reason == "tool_arguments_unmasked"),
            "{declared_header}"
        );

        // 2. the event record.
        let event = gateway
            .events()
            .pop()
            .expect("a masked round trip produced no event record");
        let reasons = event.to_value()["degraded_reasons"].clone();
        assert!(
            reasons
                .as_array()
                .is_some_and(|list| list.iter().any(|r| r == "tool_arguments_unmasked")),
            "{reasons}"
        );

        // 3. the finding, which is the leg that was missing.
        let findings = gateway.findings();
        assert_eq!(findings.len(), 1, "{findings:#?}");
        let finding = &findings[0];
        assert_eq!(finding["kind"], "unmasked_passthrough");
        assert_eq!(finding["detector"]["component"], "proxy");
        assert_eq!(
            finding["detector"]["rule_id"],
            "proxy.tool-call.unmasked-arguments"
        );
        assert_eq!(finding["provider_ref"], "openai");
        assert!(!outgoing
            .headers
            .get("x-periskop-alias-scope")
            .unwrap_or_default()
            .is_empty());

        // The exchange reference names the **conversation**, so the same gap in
        // the same conversation is one reference and a different conversation is a
        // different one. Without the second half a report would fold two
        // organisations' gaps into one row.
        gateway.handle(tool_call_request()).await;
        let again = gateway.findings();
        assert_eq!(again.len(), 2);
        assert_eq!(again[0], again[1]);

        let elsewhere = Incoming {
            headers: HeaderList::new()
                .with("content-type", "application/json")
                .with(SESSION_HEADER, "a-different-conversation"),
            ..tool_call_request()
        };
        gateway.handle(elsewhere).await;
        let third = gateway.findings();
        assert_ne!(
            third[2]["refs"][0]["ref_id"], third[0]["refs"][0]["ref_id"],
            "two conversations produced one exchange reference"
        );

        // And a request with no structured arguments declares nothing, or the
        // three legs above would be noise rather than a signal.
        let quiet = tamper_gateway();
        let plain = quiet
            .handle(Incoming {
                body: serde_json::json!({
                    "model": "gpt-4o",
                    "messages": [{ "role": "user", "content": "merhaba" }],
                })
                .to_string()
                .into_bytes(),
                ..tool_call_request()
            })
            .await;
        let quiet_header = plain
            .headers
            .get("x-periskop-degraded")
            .unwrap_or_default()
            .to_owned();
        assert!(
            !quiet_header
                .split(',')
                .any(|reason| reason == "tool_arguments_unmasked"),
            "{quiet_header}"
        );
        assert!(quiet.findings().is_empty(), "{:#?}", quiet.findings());
    }

    /// The other half of the same rule: a leg that cannot be produced refuses the
    /// request instead of forwarding it.
    #[tokio::test]
    async fn a_gap_that_cannot_be_declared_is_refused_and_nothing_reaches_the_provider() {
        let recorder = Arc::new(super::super::upstream::Recorder::ok());
        let gateway =
            gateway_over(Arc::clone(&recorder) as Arc<dyn super::super::upstream::Upstream>);

        // A provider name the finding schema cannot hold is the reachable shape
        // of "the third leg could not be produced": `Subject::is_nameable` is
        // what decides, and it asks the schema's own question.
        let refusal = Declared::make(
            Gap::ToolArguments,
            true,
            true,
            Subject {
                scope: "9f2c",
                provider: "OpenAI",
            },
        )
        .expect_err("a gap with no nameable provider was declared");
        assert_eq!(refusal.error(), ProxyError::ToolArgumentsRejected);
        assert_eq!(refusal.status(), 400);

        // And the policy that refuses outright still refuses through the running
        // path, so the two roads to a 400 are both walked.
        let outgoing = gateway.handle(tool_call_request()).await;
        assert_eq!(
            outgoing.status, 200,
            "the shipped policy passes and declares"
        );
        assert_eq!(recorder.calls().len(), 1);
    }

    fn tool_call_request() -> Incoming {
        Incoming {
            method: "POST".to_owned(),
            path: "/v1/chat/completions".to_owned(),
            query: None,
            headers: HeaderList::new()
                .with("content-type", "application/json")
                .with(SESSION_HEADER, "the-user-s-conversation"),
            body: serde_json::json!({
                "model": "gpt-4o",
                "messages": [{ "role": "user", "content": "faturayi olustur" }],
                "tools": [{
                    "type": "function",
                    "function": { "name": "create_invoice" },
                }],
            })
            .to_string()
            .into_bytes(),
        }
    }

    /// A gateway with nothing behind it, for the rule above.
    fn tamper_gateway() -> Gateway {
        gateway_over(Arc::new(super::super::upstream::Recorder::ok())
            as Arc<dyn super::super::upstream::Upstream>)
    }

    /// An upstream that is never reached, so the `502` answer can be read.
    struct NeverReached;

    impl super::super::upstream::Upstream for NeverReached {
        fn send(&self, _call: Call) -> super::super::upstream::Pending<'_> {
            Box::pin(async {
                Err(super::super::upstream::Unreachable {
                    why: "the stub refuses every connection".to_owned(),
                })
            })
        }
    }

    fn blocking(gateway: &Gateway, incoming: Incoming) -> Outgoing {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(gateway.handle(incoming))
    }

    fn get(path: &str) -> Incoming {
        Incoming {
            method: "GET".to_owned(),
            path: path.to_owned(),
            query: None,
            headers: HeaderList::new(),
            body: Vec::new(),
        }
    }

    fn ask(content: &str) -> Incoming {
        Incoming {
            method: "POST".to_owned(),
            path: "/v1/chat/completions".to_owned(),
            query: None,
            headers: HeaderList::new().with(SESSION_HEADER, "one-conversation"),
            body: serde_json::json!({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": content}]
            })
            .to_string()
            .into_bytes(),
        }
    }

    /// The `error` key a body carries, when it carries one.
    fn error_key(body: &[u8]) -> Option<String> {
        serde_json::from_slice::<Value>(body)
            .ok()?
            .get("error")?
            .as_str()
            .map(str::to_owned)
    }

    /// A closed dictionary means nothing outside it, on every answer.
    ///
    /// `proxy-api.md` fixes ten values so that a client branching on periskop's
    /// refusals can write a total match. Three answers used to put a word of
    /// their own under the same key: `not_found`, `method_not_allowed` and
    /// `upstream_unreachable`. None of them is a refusal of periskop's and none
    /// of them is in the dictionary, so a client matching on the key had three
    /// values no contract defines and no version of the contract would ever add.
    ///
    /// Walked over the answers rather than over the source, because what a source
    /// scan proves is that a literal is absent and what this proves is that the
    /// bytes on the wire carry nothing else.
    #[test]
    fn the_error_key_never_leaves_the_closed_dictionary() {
        let dictionary: Vec<&str> = ProxyError::ALL.iter().map(|error| error.as_str()).collect();

        let unreachable = gateway_over(Arc::new(NeverReached) as Arc<dyn Upstream>);
        let ordinary = tamper_gateway();
        let answers = vec![
            // The three that carried an invented word.
            ("not found", blocking(&ordinary, get("/nowhere"))),
            (
                "method not allowed",
                blocking(
                    &ordinary,
                    Incoming {
                        method: "POST".to_owned(),
                        ..get("/admin/policy")
                    },
                ),
            ),
            (
                "upstream unreachable",
                blocking(&unreachable, ask("nothing to mask here")),
            ),
            // And a real refusal, which is the positive control: without one the
            // loop below would pass on a build that stopped answering at all.
            (
                "body unparsable",
                blocking(
                    &ordinary,
                    Incoming {
                        body: b"{ this is not json".to_vec(),
                        ..ask("")
                    },
                ),
            ),
        ];

        let mut from_the_dictionary = 0usize;
        for (name, answer) in &answers {
            if let Some(value) = error_key(&answer.body) {
                assert!(
                    dictionary.contains(&value.as_str()),
                    "the {name} answer carries error=\"{value}\", which no contract defines"
                );
                from_the_dictionary += 1;
            }
            // The header is drawn from the same dictionary, and it is the field a
            // client is told to branch on.
            if let Some(value) = answer.headers.get("x-periskop-error") {
                assert!(
                    dictionary.contains(&value),
                    "the {name} answer's header carries {value}"
                );
            }
        }
        assert_eq!(
            from_the_dictionary, 1,
            "no answer carried a dictionary value, so this walked over bodies with no error \
             key in them and proved nothing"
        );

        // The statuses are still the ones the routing contract fixes: dropping
        // the invented word is not permission to answer 400 to a wrong path.
        assert_eq!(answers[0].1.status, 404);
        assert_eq!(answers[1].1.status, 405);
        assert_eq!(answers[2].1.status, 502);
        // And the sentence survives, because it is the half of the body that was
        // ever useful.
        for (name, answer) in &answers {
            let body: Value = serde_json::from_slice(&answer.body).unwrap_or(Value::Null);
            assert!(
                body["detail"].as_str().is_some_and(|text| !text.is_empty()),
                "the {name} answer says nothing about itself"
            );
        }
    }

    /// A stream that ends inside a frame is marked and counted.
    ///
    /// Two defects in one place. The frame reader dropped a leftover that carried
    /// no `data:` field, so the client lost those bytes and nothing said so; and
    /// `periskop_proxy_stream_reassembly_errors_total` was incremented by its own
    /// unit test and by no request, so the endpoint reported a permanent zero.
    /// Asserted over a real request through `handle`, because both of them were
    /// reachable from a unit test and neither was reachable from the path a
    /// request takes.
    #[test]
    fn a_stream_that_ends_inside_a_frame_is_marked_truncated_and_counted() {
        let cut = gateway_over(Arc::new(super::super::upstream::Recorder::streaming(vec![
            b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Fatura \"}}]}\n\n".to_vec(),
            // The provider died here: a cut before the payload's colon leaves
            // bytes no frame parses out of.
            b"event: content_block_".to_vec(),
        ])) as Arc<dyn Upstream>);

        let answer = blocking(&cut, ask("ali@ornek.com"));
        assert_eq!(answer.status, 200);
        assert_eq!(
            answer.headers.get("x-periskop-stream-truncated"),
            Some("true"),
            "a stream that ended inside a frame was delivered as a complete one"
        );
        assert!(
            String::from_utf8_lossy(&answer.body).contains("event: content_block_"),
            "the tail the provider did send was dropped: {}",
            String::from_utf8_lossy(&answer.body)
        );
        assert!(
            cut.metrics_snapshot()
                .render()
                .contains("periskop_proxy_stream_reassembly_errors_total 1"),
            "{}",
            cut.metrics_snapshot().render()
        );

        // The other direction, or the assertions above would pass on a build that
        // marked every stream truncated and counted every request.
        let whole = gateway_over(Arc::new(super::super::upstream::Recorder::streaming(vec![
            b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Fatura \"}}]}\n\n".to_vec(),
            b"data: [DONE]\n\n".to_vec(),
        ])) as Arc<dyn Upstream>);
        let answer = blocking(&whole, ask("ali@ornek.com"));
        assert_eq!(answer.headers.get("x-periskop-stream-truncated"), None);
        assert!(
            whole
                .metrics_snapshot()
                .render()
                .contains("periskop_proxy_stream_reassembly_errors_total 0"),
            "{}",
            whole.metrics_snapshot().render()
        );
    }

    /// The same mark, on a conversation that masked nothing.
    ///
    /// The gap the test above could not see. `restore_answer` returns early for a
    /// conversation with an empty snapshot, because there are no values to put
    /// back, and the truncation mark used to be added after that return by the
    /// branch that relays a stream. So a prompt containing nothing detectable
    /// went out, the provider died in the middle of a frame, and the client got a
    /// `200` with no `x-periskop-stream-truncated` and a reassembly counter that
    /// stayed at zero. Whether this proxy had anything to rewrite is not what
    /// decides whether the provider finished talking.
    #[test]
    fn a_cut_stream_is_marked_even_when_the_conversation_masked_nothing() {
        let cut = gateway_over(Arc::new(super::super::upstream::Recorder::streaming(vec![
            b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"two\"}}]}\n\n".to_vec(),
            // The provider died here.
            b"event: content_block_".to_vec(),
        ])) as Arc<dyn Upstream>);

        let answer = blocking(&cut, ask("what is one plus one"));
        assert_eq!(answer.status, 200);
        // The premise: nothing in that prompt was masked, or this would be the
        // case the test above already covers.
        assert_eq!(
            answer.headers.get("x-periskop-masked-entities"),
            Some("0"),
            "the prompt was supposed to carry nothing detectable"
        );
        assert_eq!(
            answer.headers.get("x-periskop-stream-truncated"),
            Some("true"),
            "a cut stream was delivered as a complete one because nothing was masked"
        );
        assert!(
            cut.metrics_snapshot()
                .render()
                .contains("periskop_proxy_stream_reassembly_errors_total 1"),
            "{}",
            cut.metrics_snapshot().render()
        );

        // The other direction on the same unmasked conversation, so the assertion
        // above cannot pass on a build that marks every stream.
        let whole = gateway_over(Arc::new(super::super::upstream::Recorder::streaming(vec![
            b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"two\"}}]}\n\n".to_vec(),
            b"data: [DONE]\n\n".to_vec(),
        ])) as Arc<dyn Upstream>);
        let answer = blocking(&whole, ask("what is one plus one"));
        assert_eq!(answer.headers.get("x-periskop-stream-truncated"), None);
        assert!(
            whole
                .metrics_snapshot()
                .render()
                .contains("periskop_proxy_stream_reassembly_errors_total 0"),
            "{}",
            whole.metrics_snapshot().render()
        );

        // And a buffered answer of the same conversation is not a cut stream:
        // a JSON body has no frame terminators, so a scan that ran over it would
        // call every one of them truncated.
        let buffered = gateway_over(Arc::new(super::super::upstream::Recorder::answering(
            super::super::upstream::Answer::whole(
                200,
                HeaderList::new().with("content-type", "application/json"),
                b"{\"choices\":[{\"message\":{\"content\":\"two\"}}]}".to_vec(),
            ),
        )) as Arc<dyn Upstream>);
        let answer = blocking(&buffered, ask("what is one plus one"));
        assert_eq!(answer.headers.get("x-periskop-stream-truncated"), None);
        assert!(
            buffered
                .metrics_snapshot()
                .render()
                .contains("periskop_proxy_stream_reassembly_errors_total 0"),
            "{}",
            buffered.metrics_snapshot().render()
        );
    }

    /// A bounded buffer that drops the oldest says how many it dropped.
    ///
    /// The gap this closes: both buffers were bounded on purpose and both
    /// dropped their oldest entry with `remove(0)` and no record of it, so a
    /// reader of `findings()` or `events()` had a list and no way to tell a
    /// complete one from a window. A day that produced more findings than the
    /// bound showed the bound's worth and read as if the rest had never
    /// happened, which is exactly the "a loss is never discarded silently" rule
    /// this component applies to everything else it measures.
    #[test]
    fn a_finding_dropped_by_the_bound_is_counted_where_an_operator_reads_it() {
        let gateway = tamper_gateway();

        // Under the bound: nothing is dropped, so the counter is zero. Without
        // this half a build that counted every filing would pass the half below.
        for _ in 0..8 {
            gateway.file_finding(serde_json::json!({ "kind": "unmasked_passthrough" }));
        }
        assert_eq!(gateway.findings().len(), 8);
        assert_eq!(gateway.metrics_snapshot().findings_evicted_total(), 0);
        assert!(
            gateway
                .metrics_snapshot()
                .render()
                .contains("periskop_proxy_findings_evicted_total 0"),
            "{}",
            gateway.metrics_snapshot().render()
        );

        // Over it: the buffer stays at its bound and every entry that left is on
        // the endpoint.
        let over = 5usize;
        for _ in 0..(FINDINGS_KEPT - 8 + over) {
            gateway.file_finding(serde_json::json!({ "kind": "unmasked_passthrough" }));
        }
        assert_eq!(gateway.findings().len(), FINDINGS_KEPT);
        assert_eq!(
            gateway.metrics_snapshot().findings_evicted_total(),
            over as u64,
            "the buffer dropped {over} findings and the count disagrees"
        );
        assert!(
            gateway
                .metrics_snapshot()
                .render()
                .contains(&format!("periskop_proxy_findings_evicted_total {over}")),
            "{}",
            gateway.metrics_snapshot().render()
        );
    }

    /// The same rule for the event buffer, driven through `handle`.
    ///
    /// Through the running path rather than over the buffer, because what was
    /// missing is the call site: a counter raised only by its own unit test is
    /// the defect `record_stream_reassembly_error` already had once in this file.
    #[test]
    fn an_event_dropped_by_the_bound_is_counted_where_an_operator_reads_it() {
        let gateway = tamper_gateway();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");

        let over = 3usize;
        runtime.block_on(async {
            for _ in 0..(EVENTS_KEPT + over) {
                gateway.handle(ask("what is one plus one")).await;
            }
        });

        assert_eq!(gateway.events().len(), EVENTS_KEPT);
        assert_eq!(
            gateway.metrics_snapshot().events_evicted_total(),
            over as u64
        );
        assert!(
            gateway
                .metrics_snapshot()
                .render()
                .contains(&format!("periskop_proxy_events_evicted_total {over}")),
            "{}",
            gateway.metrics_snapshot().render()
        );

        // And the other direction on a process that stayed under the bound, or
        // the assertion above would pass on a build that counted every request.
        let quiet = tamper_gateway();
        blocking(&quiet, ask("what is one plus one"));
        assert_eq!(quiet.metrics_snapshot().events_evicted_total(), 0);
        assert!(
            quiet
                .metrics_snapshot()
                .render()
                .contains("periskop_proxy_events_evicted_total 0"),
            "{}",
            quiet.metrics_snapshot().render()
        );
    }

    fn gateway_over(upstream: Arc<dyn super::super::upstream::Upstream>) -> Gateway {
        use crate::vault::{Backing, OpenRequest, Passphrase, ProfileName, Vault};
        let vault = Vault::open(&OpenRequest {
            passphrase: &Passphrase::new(b"an operator's passphrase".to_vec()),
            profile: ProfileName::Ci,
            backing: Backing::Memory,
        })
        .unwrap_or_else(|refusal| panic!("{refusal}"));
        let policy = crate::policy::Policy::load(
            "policy_id = \"acme\"\npolicy_version = \"1\"\n[default]\nmode = \"mask\"\n",
            std::path::Path::new("."),
            None,
        )
        .unwrap_or_else(|refusal| panic!("{refusal}"));
        Gateway::new(
            policy,
            vault,
            upstream,
            crate::http::AllowList::shipped(),
            Clock::Fixed(1_700_000_000_000),
        )
        .unwrap_or_else(|refusal| panic!("{}", refusal.detail()))
    }
}
