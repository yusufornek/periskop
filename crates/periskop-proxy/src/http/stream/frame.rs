//! Raw bytes to SSE frames to JSON to the text a model actually wrote.
//!
//! Four layers, and the order is the point (`proxy/spec.md` section 6.1). A
//! provider's answer arrives as a byte stream that is cut wherever the network
//! decided; the cuts fall inside `data:` lines, inside JSON strings and inside
//! the words the model is writing, and none of those boundaries mean anything.
//! Renaming an alias is done on the **text**, after all three lower layers have
//! been reassembled, because an alias split across two TCP segments is not a
//! thing a byte level search can find and a byte level replacement inside a JSON
//! string would produce a document the client cannot parse.
//!
//! So this module answers exactly one question: given the bytes so far, which
//! **complete** frames are there, and where inside each of them is the model's
//! text. Everything above it works on `String`s and never sees a byte offset.
//!
//! # The end of a stream has two spellings
//!
//! OpenAI closes with `data: [DONE]`; Anthropic closes with an
//! `event: message_stop` frame whose payload is a JSON object of that type. Both
//! are recognised, because the end of the stream is when the hold buffer is
//! flushed (rule F1) and a proxy that recognised one provider's ending would hold
//! the other's last few bytes for ever.

use serde_json::Value;

/// Which text slot in a frame a piece of text came out of.
///
/// A stream can carry more than one independent text sequence: OpenAI's `n > 1`
/// puts one `choices[i]` per index and Anthropic numbers its content blocks. They
/// are separate sequences of words, so they get separate hold buffers; feeding
/// them into one would let the tail of one block and the head of another look
/// like an alias that neither of them contains.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Lane {
    OpenAi(usize),
    Anthropic(usize),
}

/// Where in a frame's document a piece of text sits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// `choices[at].delta.content`. `at` is where the choice sits in **this**
    /// frame's array and `index` is the choice's own number, which is what a
    /// client reassembles by. They differ whenever a provider sends one choice
    /// per frame under `n > 1`, and confusing them would braid two answers into
    /// one hold buffer.
    OpenAiDelta { at: usize, index: usize },
    /// `delta.text` of a `content_block_delta` with index `i`.
    AnthropicDelta(usize),
    /// `content_block.text` of a `content_block_start` with index `i`.
    AnthropicBlockStart(usize),
}

impl Slot {
    pub fn lane(self) -> Lane {
        match self {
            Self::OpenAiDelta { index, .. } => Lane::OpenAi(index),
            Self::AnthropicDelta(at) | Self::AnthropicBlockStart(at) => Lane::Anthropic(at),
        }
    }
}

/// One server sent event.
///
/// The prelude is kept verbatim rather than reduced to the fields this build
/// understands. `event: content_block_delta` is what an Anthropic client
/// dispatches on, and a proxy that dropped the lines it does not read would break
/// a client for a reason that has nothing to do with masking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    prelude: Vec<String>,
    data: String,
    /// Whether the payload lines carried a trailing `\r`, so a frame this proxy
    /// rewrites comes back in the line ending it arrived in.
    crlf: bool,
    /// The bytes verbatim, when this is the unterminated tail of a stream.
    ///
    /// `None` for every frame read between two terminators, which is every
    /// ordinary frame. It is `Some` only for what [`Frames::finish`] was holding
    /// when the connection ended, and only when those bytes carry no `data:`
    /// field: they are then a frame nothing can be parsed out of, and this field
    /// is what keeps them from being dropped. Rendering them back through
    /// [`Frame::render`] would invent a `data:` line the provider never wrote, so
    /// they go out exactly as they arrived and are marked
    /// (`x-periskop-stream-truncated`) rather than rewritten.
    tail: Option<String>,
}

impl Frame {
    pub fn data(&self) -> &str {
        &self.data
    }

    /// The `event:` field, when there is one.
    pub fn event_name(&self) -> Option<&str> {
        self.prelude
            .iter()
            .find_map(|line| line.strip_prefix("event:"))
            .map(str::trim)
    }

    /// The payload parsed as JSON, or `None` when it is not JSON.
    ///
    /// `[DONE]` is the ordinary case of "not JSON", which is why this is an
    /// option rather than an error: the sentinel is part of the protocol.
    pub fn document(&self) -> Option<Value> {
        serde_json::from_str(self.data.trim()).ok()
    }

    /// Whether this frame ends the stream, in either provider's spelling.
    pub fn ends_the_stream(&self) -> bool {
        if self.data.trim() == "[DONE]" {
            return true;
        }
        if self.event_name() == Some("message_stop") {
            return true;
        }
        self.document()
            .and_then(|document| {
                document
                    .get("type")
                    .and_then(Value::as_str)
                    .map(|kind| kind == "message_stop")
            })
            .unwrap_or(false)
    }

    /// The frame as it arrived.
    pub fn bytes(&self) -> Vec<u8> {
        match &self.tail {
            Some(raw) => raw.clone().into_bytes(),
            None => self.render(&self.data),
        }
    }

    /// Whether this frame is the tail a stream ended in the middle of.
    ///
    /// Exposed so a caller can tell "the provider finished" from "the connection
    /// stopped part way through a frame", which `proxy-api.md`'s fifth streaming
    /// point calls an error to be marked.
    pub const fn is_unterminated_tail(&self) -> bool {
        self.tail.is_some()
    }

    /// The same frame carrying a different payload.
    pub fn render(&self, data: &str) -> Vec<u8> {
        let end = if self.crlf { "\r\n" } else { "\n" };
        let mut out = String::new();
        for line in &self.prelude {
            out.push_str(line);
            out.push_str(end);
        }
        // Multi line payloads keep their shape: the wire format is one `data:`
        // line per line of payload, joined with a newline by the reader.
        for line in data.split('\n') {
            out.push_str("data: ");
            out.push_str(line);
            out.push_str(end);
        }
        out.push_str(end);
        out.into_bytes()
    }
}

/// The frame reader.
///
/// Holds whatever bytes have not yet completed a frame. That is the whole of the
/// first layer's job: a caller that fed this one byte at a time and a caller that
/// fed it the whole response get the same frames out, which is what
/// `every_split_of_a_frame_produces_the_same_events` fixes.
#[derive(Debug, Default)]
pub struct Frames {
    pending: Vec<u8>,
}

impl Frames {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads whatever complete frames the bytes so far contain.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Frame> {
        self.pending.extend_from_slice(bytes);
        let mut frames = Vec::new();
        while let Some((frame, consumed)) = self.next_frame() {
            self.pending.drain(..consumed);
            if let Some(frame) = frame {
                frames.push(frame);
            }
        }
        frames
    }

    /// What is left when the connection closed without a terminator.
    ///
    /// Returned rather than dropped: `proxy-api.md` point 5 calls leftover bytes
    /// at the end of a stream an error to be **marked**, not one to be silently
    /// discarded, and discarding them here would lose the last words of an answer
    /// as well as the mark.
    ///
    /// The second branch is the one that was missing. [`parse`] answers `None`
    /// for a block carrying no `data:` field, and a cut that lands anywhere
    /// before the payload's colon produces exactly that: `event: content_block_`
    /// or `dat` is a leftover nothing parses out of. Those bytes used to be
    /// cleared here and the stream then looked complete to every layer above,
    /// which is the silent half of a truncation. They are handed back verbatim
    /// now, so the client receives what arrived and
    /// [`ends_mid_frame`] is what puts the mark on it.
    pub fn finish(&mut self) -> Option<Frame> {
        if self.pending.iter().all(u8::is_ascii_whitespace) {
            self.pending.clear();
            return None;
        }
        let text = String::from_utf8_lossy(&self.pending).into_owned();
        self.pending.clear();
        if let Some(frame) = parse(&text) {
            return Some(frame);
        }
        Some(Frame {
            prelude: Vec::new(),
            data: String::new(),
            crlf: text.contains("\r\n"),
            tail: Some(text),
        })
    }

    /// Whether any byte is still waiting for its terminator.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// The next complete frame and how many bytes it occupied.
    fn next_frame(&self) -> Option<(Option<Frame>, usize)> {
        let at = boundary(&self.pending)?;
        let (block, consumed) = at;
        let text = String::from_utf8_lossy(&self.pending[..block]).into_owned();
        Some((parse(&text), consumed))
    }
}

/// Finds the end of the first frame: the payload length and the bytes consumed.
///
/// A frame ends at a blank line, in either line ending. Searched over bytes
/// rather than over a decoded string because the buffer can end part way through
/// a multi byte character, and decoding it early would replace those bytes with a
/// replacement character that never goes back.
fn boundary(pending: &[u8]) -> Option<(usize, usize)> {
    for (at, window) in pending.windows(2).enumerate() {
        if window == b"\n\n" {
            return Some((at, at + 2));
        }
    }
    for (at, window) in pending.windows(4).enumerate() {
        if window == b"\r\n\r\n" {
            return Some((at, at + 4));
        }
    }
    None
}

/// One block of lines into a frame, or `None` for a block with no payload.
///
/// A comment only block (`: keep-alive`) is a heartbeat with nothing in it. It is
/// dropped rather than forwarded because it carries no text and no field, and
/// forwarding it would put an empty frame between two halves of an alias for no
/// reason.
fn parse(block: &str) -> Option<Frame> {
    let crlf = block.contains("\r\n");
    let mut prelude = Vec::new();
    let mut data: Vec<&str> = Vec::new();

    for line in block.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        match line.strip_prefix("data:") {
            // The single space after the colon is part of the field syntax and
            // not part of the value.
            Some(value) => data.push(value.strip_prefix(' ').unwrap_or(value)),
            None => prelude.push(line.to_owned()),
        }
    }

    if data.is_empty() {
        return None;
    }
    Some(Frame {
        prelude,
        data: data.join("\n"),
        crlf,
        tail: None,
    })
}

/// Whether these bytes end without completing a frame.
///
/// The answer `x-periskop-stream-truncated` is written from, and the reason it
/// is a function over the whole body rather than a flag on the reader: the
/// reader is drained frame by frame as the stream arrives, so by the time
/// anybody asks it what it is holding it is holding the tail and nothing that
/// says a tail is what it is.
///
/// Read at the same two terminators [`boundary`] reads, and
/// `the_boundary_scan_and_the_reader_agree_on_where_a_stream_ends` is what stops
/// the two drifting: a scan that answered a different question would put the
/// mark on complete streams or leave it off truncated ones, and both are worse
/// than not marking at all.
pub fn ends_mid_frame(body: &[u8]) -> bool {
    let after = last_terminator_end(body);
    !body[after..].iter().all(u8::is_ascii_whitespace)
}

/// Where the last complete frame in these bytes ends.
///
/// One left to right pass, unlike [`boundary`], which restarts at the front of
/// what is still pending. That matters here because this walks a whole answer
/// rather than one reader's buffer, and a rescan per frame would make the cost
/// of marking a stream quadratic in the number of events it carried.
fn last_terminator_end(body: &[u8]) -> usize {
    let mut end = 0;
    let mut at = 0;
    while at < body.len() {
        if body[at..].starts_with(b"\n\n") {
            at += 2;
            end = at;
        } else if body[at..].starts_with(b"\r\n\r\n") {
            at += 4;
            end = at;
        } else {
            at += 1;
        }
    }
    end
}

/// Every text slot a frame's document carries, in document order.
///
/// Only the fields that hold **model prose**. Tool call arguments
/// (`delta.partial_json`) are deliberately absent: `proxy-api.md`'s tool call
/// decision is that structured arguments cross unmasked and declared, so rewriting
/// them here would apply masking on the way back that never happened on the way
/// out.
pub fn text_slots(document: &Value) -> Vec<(Slot, String)> {
    let mut found = Vec::new();

    if let Some(choices) = document.get("choices").and_then(Value::as_array) {
        for (at, choice) in choices.iter().enumerate() {
            let index = choice
                .get("index")
                .and_then(Value::as_u64)
                .and_then(|index| usize::try_from(index).ok())
                .unwrap_or(at);
            if let Some(text) = choice
                .get("delta")
                .and_then(|delta| delta.get("content"))
                .and_then(Value::as_str)
            {
                found.push((Slot::OpenAiDelta { at, index }, text.to_owned()));
            }
        }
    }

    let index = document
        .get("index")
        .and_then(Value::as_u64)
        .and_then(|index| usize::try_from(index).ok())
        .unwrap_or(0);
    match document.get("type").and_then(Value::as_str) {
        Some("content_block_delta") => {
            if let Some(text) = document
                .get("delta")
                .and_then(|delta| delta.get("text"))
                .and_then(Value::as_str)
            {
                found.push((Slot::AnthropicDelta(index), text.to_owned()));
            }
        }
        Some("content_block_start") => {
            if let Some(text) = document
                .get("content_block")
                .and_then(|block| block.get("text"))
                .and_then(Value::as_str)
            {
                found.push((Slot::AnthropicBlockStart(index), text.to_owned()));
            }
        }
        _ => {}
    }

    found
}

/// The same document with one slot's text replaced.
///
/// Returns the document unchanged when the slot is not there, which cannot happen
/// for a slot [`text_slots`] just reported and is written as a no-op so that this
/// function is total.
pub fn with_text(document: &Value, slot: Slot, text: &str) -> Value {
    let mut out = document.clone();
    let replacement = Value::String(text.to_owned());
    match slot {
        Slot::OpenAiDelta { at, .. } => {
            if let Some(field) = out
                .get_mut("choices")
                .and_then(|choices| choices.get_mut(at))
                .and_then(|choice| choice.get_mut("delta"))
                .and_then(|delta| delta.get_mut("content"))
            {
                *field = replacement;
            }
        }
        Slot::AnthropicDelta(_) => {
            if let Some(field) = out.get_mut("delta").and_then(|delta| delta.get_mut("text")) {
                *field = replacement;
            }
        }
        Slot::AnthropicBlockStart(_) => {
            if let Some(field) = out
                .get_mut("content_block")
                .and_then(|block| block.get_mut("text"))
            {
                *field = replacement;
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn openai_chunk(text: &str) -> String {
        format!("data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{text}\"}}}}]}}\n\n")
    }

    fn collect(bytes: &[u8], step: usize) -> Vec<Frame> {
        let mut reader = Frames::new();
        let mut frames = Vec::new();
        for piece in bytes.chunks(step.max(1)) {
            frames.extend(reader.push(piece));
        }
        frames.extend(reader.finish());
        frames
    }

    /// Task 89's criterion, mechanically: **every** byte boundary, not one.
    #[test]
    fn every_split_of_a_frame_produces_the_same_events() {
        let stream = format!(
            "{}{}data: [DONE]\n\n",
            openai_chunk("Fatura "),
            openai_chunk("PSK_PERSON_1 adina")
        );
        let whole = collect(stream.as_bytes(), stream.len());
        assert_eq!(whole.len(), 3, "{whole:?}");

        for split in 1..stream.len() {
            let mut reader = Frames::new();
            let mut frames = reader.push(&stream.as_bytes()[..split]);
            frames.extend(reader.push(&stream.as_bytes()[split..]));
            frames.extend(reader.finish());
            assert_eq!(
                frames, whole,
                "a split after byte {split} produced a different event sequence"
            );
        }

        // And one byte at a time, which is the worst case of the same claim.
        assert_eq!(collect(stream.as_bytes(), 1), whole);
    }

    /// The layering claim: what is replaced is text, reached through JSON,
    /// reached through a frame. A byte level rename would find the alias in the
    /// raw `data:` line; this asserts the route instead.
    #[test]
    fn the_text_is_reached_through_the_frame_and_the_json_and_not_off_the_wire() {
        let frames = collect(openai_chunk("PSK_PERSON_1 adina").as_bytes(), 3);
        let frame = frames.first().expect("one frame");
        let document = frame.document().expect("the payload is JSON");
        let slots = text_slots(&document);
        assert_eq!(slots.len(), 1);
        let (slot, text) = slots.first().cloned().expect("one slot");
        assert_eq!(slot.lane(), Lane::OpenAi(0));
        assert_eq!(text, "PSK_PERSON_1 adina");

        let rewritten = with_text(&document, slot, "Ahmet Yilmaz adina");
        let bytes = frame.render(&rewritten.to_string());
        let text = String::from_utf8_lossy(&bytes).into_owned();
        assert!(text.contains("Ahmet Yilmaz adina"), "{text}");
        assert!(text.starts_with("data: "), "{text}");
        assert!(text.ends_with("\n\n"), "{text}");
        // The document round trips as JSON rather than as an edited string.
        let reparsed: Value = serde_json::from_str(text.trim_start_matches("data: ").trim())
            .expect("the rewritten frame is still JSON");
        assert_eq!(
            reparsed["choices"][0]["delta"]["content"],
            "Ahmet Yilmaz adina"
        );
    }

    #[test]
    fn both_providers_endings_are_recognised() {
        let openai = collect(b"data: [DONE]\n\n", 1);
        assert!(openai.first().expect("a frame").ends_the_stream());

        let anthropic = collect(
            b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            1,
        );
        let frame = anthropic.first().expect("a frame");
        assert!(frame.ends_the_stream());
        assert_eq!(frame.event_name(), Some("message_stop"));

        // And an ordinary frame is not an ending, or every stream would be cut
        // after its first token.
        let ordinary = collect(openai_chunk("hello").as_bytes(), 1);
        assert!(!ordinary.first().expect("a frame").ends_the_stream());
    }

    #[test]
    fn an_anthropic_text_delta_is_found_and_put_back() {
        let frame = collect(
            b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\
              \"delta\":{\"type\":\"text_delta\",\"text\":\"PSK_IBAN_1\"}}\n\n",
            5,
        );
        let frame = frame.first().expect("one frame").clone();
        let document = frame.document().expect("JSON");
        let (slot, text) = text_slots(&document).first().cloned().expect("one slot");
        assert_eq!(slot.lane(), Lane::Anthropic(0));
        assert_eq!(text, "PSK_IBAN_1");

        let rewritten = with_text(&document, slot, "TR33 0006");
        assert_eq!(rewritten["delta"]["text"], "TR33 0006");
        // The event line survives, because that is what the client dispatches on.
        let bytes = frame.render(&rewritten.to_string());
        assert!(String::from_utf8_lossy(&bytes).starts_with("event: content_block_delta\n"));
    }

    #[test]
    fn tool_call_arguments_are_not_a_text_slot() {
        // `proxy-api.md`'s tool call decision: arguments cross unmasked and
        // declared. Rewriting them on the way back would un-mask something that
        // was never masked, and it would do it inside a JSON string the model is
        // still building.
        let document: Value = serde_json::from_str(
            "{\"type\":\"content_block_delta\",\"index\":0,\
             \"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"a\\\":1\"}}",
        )
        .expect("JSON");
        assert!(text_slots(&document).is_empty());
    }

    #[test]
    fn a_comment_only_heartbeat_carries_no_frame() {
        let mut reader = Frames::new();
        assert!(reader.push(b": keep-alive\n\n").is_empty());
        assert!(reader.is_empty());
    }

    #[test]
    fn a_multi_line_payload_is_joined_and_rendered_back_line_by_line() {
        let frames = collect(b"data: one\ndata: two\n\n", 1);
        let frame = frames.first().expect("one frame");
        assert_eq!(frame.data(), "one\ntwo");
        assert_eq!(frame.bytes(), b"data: one\ndata: two\n\n".to_vec());
    }

    #[test]
    fn carriage_returns_survive_the_round_trip() {
        let frames = collect(b"event: ping\r\ndata: {}\r\n\r\n", 2);
        let frame = frames.first().expect("one frame");
        assert_eq!(frame.event_name(), Some("ping"));
        assert_eq!(frame.bytes(), b"event: ping\r\ndata: {}\r\n\r\n".to_vec());
    }

    #[test]
    fn bytes_with_no_terminator_are_handed_back_rather_than_dropped() {
        let mut reader = Frames::new();
        assert!(reader.push(b"data: {\"choices\":[]}").is_empty());
        let leftover = reader.finish().expect("the truncated frame is returned");
        assert_eq!(leftover.data(), "{\"choices\":[]}");
        assert!(!leftover.is_unterminated_tail());
    }

    /// The half of the rule above that was missing.
    ///
    /// A cut before the payload's colon leaves bytes no `data:` line can be read
    /// out of, and those used to be cleared without a trace: the client lost the
    /// bytes, no header said so, and the stream read as complete everywhere
    /// above. Every one of these is a real cut of a real Anthropic frame.
    #[test]
    fn a_tail_that_parses_as_no_frame_is_still_handed_back() {
        for cut in [
            "event: content_block_",
            "event: content_block_delta\n",
            "dat",
            ": keep-ali",
        ] {
            let mut reader = Frames::new();
            assert!(reader.push(cut.as_bytes()).is_empty(), "{cut}");
            let leftover = reader
                .finish()
                .unwrap_or_else(|| panic!("{cut} was dropped"));
            assert!(leftover.is_unterminated_tail(), "{cut}");
            // Verbatim, because rendering it would invent a `data:` line the
            // provider never wrote and hand the client a frame it did not send.
            assert_eq!(leftover.bytes(), cut.as_bytes(), "{cut}");
            assert!(!leftover.ends_the_stream(), "{cut}");
            assert!(leftover.document().is_none(), "{cut}");
        }
    }

    /// The mark and the reader answer the same question about the same bytes.
    ///
    /// [`ends_mid_frame`] walks a whole answer in one pass and [`Frames`] walks
    /// it a frame at a time; they read the same two terminators and this is what
    /// fails if one of them stops. A scan that drifted would either mark complete
    /// streams truncated or leave the mark off a stream that lost its last words,
    /// and the second is the silent failure this whole rule exists for.
    #[test]
    fn the_boundary_scan_and_the_reader_agree_on_where_a_stream_ends() {
        let complete = format!("{}data: [DONE]\n\n", openai_chunk("Fatura "));
        let cases: &[(&str, bool)] = &[
            (&complete, false),
            ("data: one\n\ndata: two", true),
            ("event: ping\r\ndata: {}\r\n\r\n", false),
            ("event: ping\r\ndata: {}\r\n\r\nevent: pi", true),
            ("", false),
            ("\n\n", false),
            // Trailing whitespace after the last terminator is the shape a
            // provider's keep alive newline leaves, and it is not a truncation.
            ("data: one\n\n\n", false),
        ];
        for (stream, truncated) in cases {
            assert_eq!(
                ends_mid_frame(stream.as_bytes()),
                *truncated,
                "ends_mid_frame disagrees on {stream:?}"
            );

            let mut reader = Frames::new();
            let _complete = reader.push(stream.as_bytes());
            assert_eq!(
                reader.finish().is_some(),
                *truncated,
                "the reader disagrees with ends_mid_frame on {stream:?}"
            );
        }
    }
}
