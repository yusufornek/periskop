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
use super::declare::{rejected, Declared, Gap};
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
    upstream: Arc<dyn Upstream>,
    clock: Clock,
}

/// How many event records stay in memory.
///
/// The oldest are dropped first. Losing an old measurement costs a data point in
/// a local benchmark; keeping every one of them costs the process.
const EVENTS_KEPT: usize = 4096;

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
        }
        if let Some(event) = self.event_for(&record) {
            let mut events = lock(&self.events);
            while events.len() >= EVENTS_KEPT {
                events.remove(0);
            }
            events.push(event);
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
                        "{\"error\":\"not_found\"}".to_owned(),
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
                        "{\"error\":\"method_not_allowed\"}".to_owned(),
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

        let prepared = self.prepare_body(treatment, parsed, &identity, &mut record);
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
                // that no contract defines.
                record.status = 502;
                let body = format!(
                    "{{\"error\":\"upstream_unreachable\",\"detail\":{}}}",
                    super::json::quote(&unreachable.why)
                );
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
        let body = self.restore_answer(&answer, &snapshot, &identity, &mut record);

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
    ) -> Vec<u8> {
        if snapshot.is_empty() {
            return answer.body.clone();
        }
        let content_type = answer.headers.get("content-type");
        if !is_event_stream(content_type) && !is_json(content_type) {
            return answer.body.clone();
        }

        let now_ms = self.clock.now_ms();
        let session = identity.id();
        let mut vault = lock(&self.vault);
        let mut lookup = SessionLookup::new(&mut vault, snapshot, session, now_ms);

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
                out.extend(relay.push(piece, &mut lookup, now_ms));
            }
            out.extend(relay.finish(&mut lookup, now_ms));
            record.measured = relay.measured();
            return out;
        }

        match restore_body(snapshot, &mut lookup, &answer.body) {
            Some((body, stats)) => {
                record.measured.restore = stats;
                record.measured.record_tamper = lookup.tampered();
                body
            }
            // A body that does not parse is the provider's, not ours to rewrite.
            None => answer.body.clone(),
        }
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
        record: &mut RequestRecord,
    ) -> Result<(Vec<u8>, Arc<Snapshot>), Refusal> {
        let session = &identity.id();
        let empty = || Arc::new(Snapshot::empty());
        let Some(parsed) = parsed else {
            // No body: a model list. Nothing to scan and nothing to declare.
            return Ok((Vec::new(), empty()));
        };

        if treatment == Treatment::UnmaskedAndDeclared {
            let declared = Declared::make(Gap::UnsupportedEndpoint, true, true)?;
            record.degraded.push(declared.reason());
            return Ok((parsed.to_string().into_bytes(), empty()));
        }
        if treatment == Treatment::NoUserText {
            return Ok((parsed.to_string().into_bytes(), empty()));
        }

        if carries_tool_arguments(&parsed) {
            match self.policy.tool_call_policy() {
                ToolCallPolicy::Reject => return Err(rejected()),
                ToolCallPolicy::PassThrough => {
                    let declared = Declared::make(Gap::ToolArguments, true, true)?;
                    record.degraded.push(declared.reason());
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
}
