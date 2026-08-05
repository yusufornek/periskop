//! The response path: frames in, text held, aliases put back, bytes out.
//!
//! `proxy/spec.md` section 6 calls this the hardest part of the component and
//! ADR-004 calls it the reason the component exists. The modules below are the
//! four questions it decomposes into, and each one is answerable on its own:
//!
//! | module | question |
//! |---|---|
//! | [`frame`] | which complete SSE frames are in the bytes so far, and where is the model's text inside them |
//! | [`automaton`] | is the tail of what I am holding the beginning of an alias this conversation issued |
//! | [`buffer`] | which bytes are settled, and which alias occurrences are decided |
//! | [`flush`] | may these bytes leave, and what proves it |
//! | [`hold_timeout`] | how long a byte may wait, and what is declared when it waits too long |
//! | [`restore`] | what does this alias stand for, looked up and never computed |
//!
//! [`Relay`] is the only thing that puts them together, and it adds one rule of
//! its own: **order**. Text leaves in the order the model wrote it, and a frame
//! this proxy does not rewrite (a `ping`, a `message_start`, the `usage` block)
//! never overtakes text that is still held. A frame that arrives while a lane
//! holds bytes waits behind them, because emitting it first would put a later
//! event in front of an earlier word.

pub mod automaton;
pub mod buffer;
pub mod flush;
pub mod frame;
pub mod hold_timeout;
pub mod restore;

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::Value;

use crate::alias::{l_max_static, AliasStyle};
use crate::policy::HoldTimeout;

use automaton::Snapshot;
use buffer::{Buffer, Piece, Window};
use flush::Trigger;
use frame::{Frame, Frames, Lane, Slot};
use hold_timeout::{HoldClock, StreamStats};
use restore::{Lookup, RestoreStats};

/// How a stream is set up before a byte of it arrives.
pub struct Settings {
    pub snapshot: Arc<Snapshot>,
    pub style: AliasStyle,
    pub declared_l_max_session: Option<usize>,
    pub hold_timeout_ms: u64,
    pub on_hold_timeout: HoldTimeout,
}

/// One lane's held text and its clock.
struct LaneState {
    buffer: Buffer,
    clock: HoldClock,
    /// The last frame that carried text for this lane, used as the shape a
    /// rewritten frame is built from.
    template: Option<(Frame, Slot)>,
}

/// What a finished relay measured.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Measured {
    pub stream: StreamStats,
    pub restore: RestoreStats,
    /// Bytes were still held when the stream ended
    /// (`x-periskop-stream-truncated`).
    pub truncated: bool,
    /// Records that could not be opened: `vault_record_tamper`.
    pub record_tamper: u32,
}

impl Measured {
    /// The WARN producing counters of `proxy-events.md`, as a closed list.
    pub fn warnings(&self) -> Vec<Warning> {
        let mut out = Vec::new();
        if self.stream.warns() {
            out.push(Warning::PartialAliasFlushed);
        }
        if self.restore.warns() {
            out.push(Warning::AliasesLeaked);
        }
        out
    }
}

/// A counter that crossed the line `proxy-events.md` draws under it.
///
/// A closed vocabulary rather than a message, so that it can be written into a
/// log line without any chance of a value travelling with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Warning {
    /// `stream_stats.partial_alias_flushed > 0`: an un-masked alias fragment may
    /// have reached the client.
    PartialAliasFlushed,
    /// `restore_stats.aliases_leaked > 0`: an alias in the answer could not be
    /// resolved and went out as it stood.
    AliasesLeaked,
}

impl Warning {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PartialAliasFlushed => "partial_alias_flushed",
            Self::AliasesLeaked => "aliases_leaked",
        }
    }
}

/// One response stream.
pub struct Relay {
    snapshot: Arc<Snapshot>,
    window: Window,
    hold_timeout_ms: u64,
    on_hold_timeout: HoldTimeout,
    frames: Frames,
    lanes: BTreeMap<Lane, LaneState>,
    /// Frames waiting behind held text, in arrival order.
    deferred: Vec<Vec<u8>>,
    stats: StreamStats,
    restore: RestoreStats,
    tamper: u32,
    ended: bool,
}

impl Relay {
    pub fn new(settings: &Settings) -> Self {
        let window = Window::of(
            Some(settings.snapshot.longest()).filter(|_| !settings.snapshot.is_empty()),
            settings.declared_l_max_session,
            settings.style,
        );
        let stats = StreamStats {
            l_max_static: u32::try_from(l_max_static(settings.style)).unwrap_or(u32::MAX),
            l_max_session: u32::try_from(window.l_max_session()).unwrap_or(u32::MAX),
            ..StreamStats::default()
        };

        Self {
            snapshot: Arc::clone(&settings.snapshot),
            window,
            hold_timeout_ms: settings.hold_timeout_ms,
            on_hold_timeout: settings.on_hold_timeout,
            frames: Frames::new(),
            lanes: BTreeMap::new(),
            deferred: Vec::new(),
            stats,
            restore: RestoreStats::default(),
            tamper: 0,
            ended: false,
        }
    }

    /// The frozen automaton this relay runs on.
    ///
    /// Exposed so a test can assert it is the **same** one from the first chunk to
    /// the last: ADR-010 section 4 forbids rebuilding it mid stream, and a claim
    /// nobody can check is a claim.
    pub fn snapshot(&self) -> &Arc<Snapshot> {
        &self.snapshot
    }

    /// One chunk of upstream bytes in, whatever may leave out.
    pub fn push(&mut self, bytes: &[u8], lookup: &mut dyn Lookup, now_ms: u64) -> Vec<u8> {
        self.stats.chunks = self.stats.chunks.saturating_add(1);
        let mut out = Vec::new();

        for frame in self.frames.push(bytes) {
            self.take(frame, lookup, now_ms, &mut out);
        }

        // F2 is checked after the frames of this chunk, so a chunk that resolved
        // the hold is not charged a timeout it no longer needs.
        self.check_timeouts(lookup, now_ms, &mut out);
        self.drain_deferred(&mut out);
        self.note_buffers();
        out
    }

    /// The end of the stream (rule F1), and everything still held.
    pub fn finish(&mut self, lookup: &mut dyn Lookup, now_ms: u64) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(frame) = self.frames.finish() {
            self.take(frame, lookup, now_ms, &mut out);
        }
        self.flush_all(Trigger::StreamEnd, lookup, now_ms, &mut out);
        self.drain_deferred(&mut out);
        self.note_buffers();
        self.ended = true;
        out
    }

    /// Rule F4: the upstream failed, so what is held is delivered and the error
    /// goes with it rather than behind it.
    pub fn fail(&mut self, lookup: &mut dyn Lookup, now_ms: u64) -> Vec<u8> {
        let mut out = Vec::new();
        self.flush_all(Trigger::StreamError, lookup, now_ms, &mut out);
        self.drain_deferred(&mut out);
        self.note_buffers();
        self.ended = true;
        out
    }

    /// Everything this stream measured.
    pub fn measured(&self) -> Measured {
        Measured {
            stream: self.stats,
            restore: self.restore,
            truncated: self.holding(),
            record_tamper: self.tamper,
        }
    }

    fn holding(&self) -> bool {
        self.lanes.values().any(|lane| !lane.buffer.is_empty())
    }

    fn take(&mut self, frame: Frame, lookup: &mut dyn Lookup, now_ms: u64, out: &mut Vec<u8>) {
        let ends = frame.ends_the_stream();
        let slots = frame
            .document()
            .map(|document| frame::text_slots(&document))
            .unwrap_or_default();

        if ends {
            // Everything held belongs before the ending, so F1 runs first and the
            // ending frame is emitted after it.
            self.flush_all(Trigger::StreamEnd, lookup, now_ms, out);
            self.drain_deferred(out);
            out.extend_from_slice(&frame.bytes());
            return;
        }

        if slots.is_empty() {
            // A frame this proxy does not rewrite. It waits behind held text so
            // that nothing overtakes a word that has not left yet.
            self.emit_or_defer(frame.bytes(), out);
            return;
        }

        for (slot, text) in slots {
            let lane = slot.lane();
            let state = self.lanes.entry(lane).or_insert_with(|| LaneState {
                buffer: Buffer::new(self.window),
                clock: HoldClock::new(self.hold_timeout_ms, self.on_hold_timeout),
                template: None,
            });
            state.template = Some((frame.clone(), slot));
            if !text.is_empty() {
                state.buffer.push(&text);
                self.stats.hold_events = self.stats.hold_events.saturating_add(1);
            }

            let released =
                state
                    .buffer
                    .release(&self.snapshot, Trigger::Settled, self.on_hold_timeout);
            let holding = !state.buffer.is_empty();
            state.clock.observe(holding, now_ms);

            let (rendered, restored) =
                render(&frame, slot, released.pieces, lookup, &mut self.restore);
            self.tamper = self.tamper.max(lookup.tampered());
            let _ = restored;
            if let Some(bytes) = rendered {
                // Straight out, never deferred: text that is being released is
                // older than anything already waiting, because a frame only ever
                // waits behind text that was already held when it arrived.
                out.extend_from_slice(&bytes);
            }
        }
    }

    /// F2, once per lane whose oldest byte has waited too long.
    fn check_timeouts(&mut self, lookup: &mut dyn Lookup, now_ms: u64, out: &mut Vec<u8>) {
        let expired: Vec<Lane> = self
            .lanes
            .iter()
            .filter(|(_, state)| !state.buffer.is_empty() && state.clock.expired(now_ms))
            .map(|(lane, _)| *lane)
            .collect();
        for lane in expired {
            self.flush_lane(lane, Trigger::HoldTimeout, lookup, now_ms, out);
        }
    }

    fn flush_all(
        &mut self,
        trigger: Trigger,
        lookup: &mut dyn Lookup,
        now_ms: u64,
        out: &mut Vec<u8>,
    ) {
        let lanes: Vec<Lane> = self.lanes.keys().copied().collect();
        for lane in lanes {
            self.flush_lane(lane, trigger, lookup, now_ms, out);
        }
    }

    fn flush_lane(
        &mut self,
        lane: Lane,
        trigger: Trigger,
        lookup: &mut dyn Lookup,
        now_ms: u64,
        out: &mut Vec<u8>,
    ) {
        let Some(state) = self.lanes.get_mut(&lane) else {
            return;
        };
        if state.buffer.is_empty() {
            return;
        }
        let depth = state.buffer.live_prefix(&self.snapshot);
        let waited = state.clock.waited_ms(now_ms);
        let released = state
            .buffer
            .release(&self.snapshot, trigger, self.on_hold_timeout);

        if trigger == Trigger::HoldTimeout {
            self.stats.timed_out(depth, released.verdict.partial_alias);
            self.stats.hold_total_ms = self.stats.hold_total_ms.saturating_add(waited);
        }
        let holding = !state.buffer.is_empty();
        state.clock.observe(holding, now_ms);

        let Some((template, slot)) = state.template.clone() else {
            return;
        };
        let (rendered, _) = render(&template, slot, released.pieces, lookup, &mut self.restore);
        self.tamper = self.tamper.max(lookup.tampered());
        if let Some(bytes) = rendered {
            out.extend_from_slice(&bytes);
        }
    }

    /// A frame this proxy does not rewrite.
    ///
    /// It goes out now if nothing is held, and waits otherwise. Waiting is the
    /// order guarantee: the held bytes are words the model wrote **before** this
    /// frame, and letting a heartbeat past them would deliver a later event in
    /// front of an earlier word.
    fn emit_or_defer(&mut self, bytes: Vec<u8>, out: &mut Vec<u8>) {
        if self.holding() || !self.deferred.is_empty() {
            self.deferred.push(bytes);
        } else {
            out.extend_from_slice(&bytes);
        }
    }

    fn drain_deferred(&mut self, out: &mut Vec<u8>) {
        if self.holding() {
            return;
        }
        for bytes in self.deferred.drain(..) {
            out.extend_from_slice(&bytes);
        }
    }

    fn note_buffers(&mut self) {
        let high = self
            .lanes
            .values()
            .map(|lane| lane.buffer.high_water())
            .max()
            .unwrap_or(0);
        self.stats.max_buffer_bytes = self
            .stats
            .max_buffer_bytes
            .max(u32::try_from(high).unwrap_or(u32::MAX));
    }
}

/// Turns released pieces into one frame, restoring every alias among them.
///
/// `None` when nothing was released: an empty delta frame would be noise between
/// two halves of a word.
fn render(
    template: &Frame,
    slot: Slot,
    pieces: Vec<Piece>,
    lookup: &mut dyn Lookup,
    stats: &mut RestoreStats,
) -> (Option<Vec<u8>>, usize) {
    let mut text = String::new();
    let mut restored = 0usize;
    for piece in pieces {
        match piece {
            Piece::Text(part) => text.push_str(&part),
            Piece::Alias(alias) => match lookup.value_for(&alias) {
                Some(value) => {
                    stats.aliases_seen_in_response =
                        stats.aliases_seen_in_response.saturating_add(1);
                    stats.aliases_restored = stats.aliases_restored.saturating_add(1);
                    restored += 1;
                    text.push_str(&value);
                }
                None => {
                    stats.aliases_seen_in_response =
                        stats.aliases_seen_in_response.saturating_add(1);
                    stats.aliases_leaked = stats.aliases_leaked.saturating_add(1);
                    // Raw, as the model wrote it. `threat-model.md` R5.
                    text.push_str(&alias);
                }
            },
        }
    }

    if text.is_empty() {
        return (None, restored);
    }
    let Some(document) = template.document() else {
        return (None, restored);
    };
    let rewritten = frame::with_text(&document, slot, &text);
    (Some(template.render(&rewritten.to_string())), restored)
}

/// Whether an answer's headers say it is a server sent event stream.
pub fn is_event_stream(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|value| {
        value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("text/event-stream")
    })
}

/// Whether an answer's headers say it is JSON.
pub fn is_json(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|value| {
        let kind = value.split(';').next().unwrap_or_default().trim();
        kind.eq_ignore_ascii_case("application/json") || kind.ends_with("+json")
    })
}

/// Puts the values back into a buffered JSON answer.
pub fn restore_body(
    snapshot: &Snapshot,
    lookup: &mut dyn Lookup,
    body: &[u8],
) -> Option<(Vec<u8>, RestoreStats)> {
    let document: Value = serde_json::from_slice(body).ok()?;
    let (out, stats) = restore::restore_json(snapshot, lookup, &document);
    Some((out.to_string().into_bytes(), stats))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

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

    fn settings(aliases: &[&str], mode: HoldTimeout) -> Settings {
        Settings {
            snapshot: Arc::new(Snapshot::frozen(
                aliases.len() as u64,
                aliases.iter().map(|alias| (*alias).to_owned()),
            )),
            style: AliasStyle::TypePreserving,
            declared_l_max_session: None,
            hold_timeout_ms: hold_timeout::DEFAULT_HOLD_MS,
            on_hold_timeout: mode,
        }
    }

    fn chunk(text: &str) -> String {
        let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
        format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{escaped}\"}}}}]}}\n\n"
        )
    }

    /// Every delta text the relay wrote, in order.
    fn deltas(bytes: &[u8]) -> String {
        let text = String::from_utf8_lossy(bytes).into_owned();
        let mut out = String::new();
        for block in text.split("\n\n") {
            for line in block.lines() {
                let Some(payload) = line.strip_prefix("data: ") else {
                    continue;
                };
                if payload.trim() == "[DONE]" {
                    continue;
                }
                let Ok(document) = serde_json::from_str::<Value>(payload) else {
                    continue;
                };
                for (_, piece) in frame::text_slots(&document) {
                    out.push_str(&piece);
                }
            }
        }
        out
    }

    #[test]
    fn an_alias_split_across_frames_reaches_the_client_as_one_value() {
        let mut relay = Relay::new(&settings(&["PSK_PERSON_1"], HoldTimeout::Flush));
        let mut table = Table::of(&[("PSK_PERSON_1", "Ahmet Yilmaz")]);
        let stream = format!(
            "{}{}{}data: [DONE]\n\n",
            chunk("Fatura "),
            chunk("PSK_PER"),
            chunk("SON_1 adina")
        );

        let mut out = relay.push(stream.as_bytes(), &mut table, 1_000);
        out.extend(relay.finish(&mut table, 1_000));
        assert_eq!(deltas(&out), "Fatura Ahmet Yilmaz adina");
        assert_eq!(relay.measured().stream.partial_alias_flushed, 0);
        assert_eq!(relay.measured().restore.aliases_restored, 1);
        assert!(!relay.measured().truncated);
    }

    #[test]
    fn the_automaton_is_the_same_one_from_the_first_chunk_to_the_last() {
        // ADR-010 section 4. The relay holds the frozen snapshot; nothing in the
        // response path may swap it.
        let settings = settings(&["PSK_PERSON_1"], HoldTimeout::Flush);
        let mut relay = Relay::new(&settings);
        let before = Arc::clone(relay.snapshot());
        let mut table = Table::of(&[("PSK_PERSON_1", "Ahmet")]);
        relay.push(chunk("PSK_PER").as_bytes(), &mut table, 1);
        relay.push(chunk("SON_1").as_bytes(), &mut table, 2);
        relay.finish(&mut table, 3);
        assert!(Arc::ptr_eq(&before, relay.snapshot()));
        assert!(Arc::ptr_eq(&settings.snapshot, relay.snapshot()));
    }

    #[test]
    fn a_frame_this_proxy_does_not_rewrite_never_overtakes_held_text() {
        let mut relay = Relay::new(&settings(&["PSK_PERSON_1"], HoldTimeout::Flush));
        let mut table = Table::of(&[("PSK_PERSON_1", "Ahmet")]);
        let mut out = relay.push(chunk("hi PSK_PER").as_bytes(), &mut table, 1);
        // A heartbeat arrives while the alias is half here.
        out.extend(relay.push(b"event: ping\ndata: {\"type\":\"ping\"}\n\n", &mut table, 2));
        assert!(
            !String::from_utf8_lossy(&out).contains("ping"),
            "the ping overtook the held word: {}",
            String::from_utf8_lossy(&out)
        );
        out.extend(relay.push(chunk("SON_1!").as_bytes(), &mut table, 3));
        out.extend(relay.finish(&mut table, 4));

        let text = String::from_utf8_lossy(&out).into_owned();
        let at_text = text.find("Ahmet").expect("the value was delivered");
        let at_ping = text.find("ping").expect("the ping was delivered");
        assert!(at_text < at_ping, "{text}");
    }

    #[test]
    fn the_hold_timeout_in_flush_mode_declares_the_fragment_it_lets_out() {
        let mut relay = Relay::new(&settings(&["PSK_PERSON_1"], HoldTimeout::Flush));
        let mut table = Table::of(&[("PSK_PERSON_1", "Ahmet")]);
        let out = relay.push(chunk("PSK_PER").as_bytes(), &mut table, 1_000);
        assert_eq!(deltas(&out), "");

        // Nothing more arrives for longer than T_hold.
        let late = relay.push(b": keep-alive\n\n", &mut table, 1_000 + 41);
        assert_eq!(deltas(&late), "PSK_PER");
        let measured = relay.measured();
        assert_eq!(measured.stream.hold_timeout_flush, 1);
        assert_eq!(measured.stream.partial_alias_flushed, 1);
        assert_eq!(measured.stream.hold_timeout_flush_depth_max, 7);
        assert_eq!(measured.warnings(), vec![Warning::PartialAliasFlushed]);
    }

    #[test]
    fn the_hold_timeout_in_wait_mode_lets_nothing_partial_out() {
        let mut relay = Relay::new(&settings(&["PSK_PERSON_1"], HoldTimeout::Wait));
        let mut table = Table::of(&[("PSK_PERSON_1", "Ahmet")]);
        relay.push(chunk("PSK_PER").as_bytes(), &mut table, 1_000);
        let late = relay.push(b": keep-alive\n\n", &mut table, 1_000 + 5_000);
        assert_eq!(deltas(&late), "", "a fragment left under wait");
        assert_eq!(relay.measured().stream.partial_alias_flushed, 0);
        assert!(relay.measured().warnings().is_empty());

        // And the stream that resumes still delivers the whole value.
        let mut out = relay.push(chunk("SON_1").as_bytes(), &mut table, 1_000 + 5_001);
        out.extend(relay.finish(&mut table, 1_000 + 5_002));
        assert_eq!(deltas(&out), "Ahmet");
    }

    #[test]
    fn an_alias_the_vault_cannot_resolve_is_forwarded_raw_and_warns() {
        let mut relay = Relay::new(&settings(&["PSK_PERSON_1"], HoldTimeout::Flush));
        let mut table = Table::of(&[]);
        let mut out = relay.push(chunk("hi PSK_PERSON_1").as_bytes(), &mut table, 1);
        out.extend(relay.finish(&mut table, 2));
        assert_eq!(deltas(&out), "hi PSK_PERSON_1");
        let measured = relay.measured();
        assert_eq!(measured.restore.aliases_leaked, 1);
        assert_eq!(measured.restore.aliases_restored, 0);
        assert_eq!(measured.warnings(), vec![Warning::AliasesLeaked]);
    }

    #[test]
    fn a_stream_that_ends_with_bytes_still_held_is_marked_truncated() {
        let mut relay = Relay::new(&settings(&["PSK_PERSON_1"], HoldTimeout::Wait));
        let mut table = Table::of(&[("PSK_PERSON_1", "Ahmet")]);
        relay.push(chunk("PSK_PER").as_bytes(), &mut table, 1);
        assert!(relay.measured().truncated, "held bytes were not noticed");
        let out = relay.finish(&mut table, 2);
        // F1 releases them as they stand: an alias that never completed is not an
        // alias, it is the text the model wrote.
        assert_eq!(deltas(&out), "PSK_PER");
    }

    #[test]
    fn the_content_type_decides_which_path_an_answer_takes() {
        assert!(is_event_stream(Some("text/event-stream")));
        assert!(is_event_stream(Some("text/event-stream; charset=utf-8")));
        assert!(!is_event_stream(Some("application/json")));
        assert!(!is_event_stream(None));
        assert!(is_json(Some("application/json; charset=utf-8")));
        assert!(is_json(Some("application/vnd.api+json")));
        assert!(!is_json(Some("text/event-stream")));
    }

    #[test]
    fn the_two_warning_names_are_the_event_contract_s_own() {
        assert_eq!(
            Warning::PartialAliasFlushed.as_str(),
            "partial_alias_flushed"
        );
        assert_eq!(Warning::AliasesLeaked.as_str(), "aliases_leaked");
    }
}
