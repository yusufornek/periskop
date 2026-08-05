//! The hold buffer: `PASS`, `HOLD`, `MATCH` (`proxy/spec.md` section 6.2).
//!
//! Text arrives in pieces that mean nothing. This holds the tail of it for as long
//! as the frozen automaton says the tail could still turn into an alias, and hands
//! back the part that is settled. Every byte it hands back went through
//! [`super::flush::decide`]; this module has no other way to shorten itself, and
//! that is deliberate.
//!
//! # The window
//!
//! `W = min(L_max_session, L_MAX_STATIC) - 1` and the buffer is `W + 1` bytes at
//! most, because a complete alias that might still grow into a longer one is held
//! whole. `L_max_session` is **derived** from the session's own alias set: it is a
//! fact about the conversation, not a setting. `proxy-policy.md` lets an operator
//! write `stream.l_max_session`, and that value is taken as a floor rather than a
//! cap, because ADR-010 is explicit that `L_max_session` is a latency optimisation
//! and that the optimisation failing may never become a correctness error. A
//! configured value below the session's real longest alias would cut aliases in
//! half; a configured value above it only costs latency.
//!
//! When there is no snapshot to derive from, `W = L_MAX_STATIC - 1`, which is the
//! same rule with the optimisation switched off.

use crate::alias::{l_max_static, AliasStyle, L_MAX_STATIC};
use crate::policy::HoldTimeout;

use super::automaton::Snapshot;
use super::flush::{decide, Trigger, Verdict};

/// The lower bound on the lookahead, in bytes (`proxy/spec.md` section 6.2).
///
/// A floor, never a ceiling: [`Window::of`] caps it at `L_MAX_STATIC` so that no
/// configuration can make the buffer larger than the compile time bound the worst
/// case latency analysis is built on.
pub const MIN_LOOKAHEAD: usize = 24;

/// Which of the three states the buffer is in.
///
/// Reported rather than stored: the state is a function of the automaton and the
/// buffer, so keeping a copy of it would be a second source of truth that can
/// disagree with the first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Nothing held; text flows straight through.
    Pass,
    /// The tail could be the beginning of an alias.
    Hold,
    /// An alias was matched and replaced in this step.
    Match,
}

/// The lookahead window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    /// `W`.
    lookahead: usize,
    /// `W + 1`: the most bytes one alias can occupy, which is what the buffer is
    /// allowed to hold.
    ceiling: usize,
}

impl Window {
    /// The window for one conversation.
    ///
    /// `observed` is the longest alias the frozen snapshot holds, or `None` when
    /// there is no snapshot to ask. `declared` is `stream.l_max_session`.
    pub fn of(observed: Option<usize>, declared: Option<usize>, style: AliasStyle) -> Self {
        let bound = l_max_static(style);
        let floor = MIN_LOOKAHEAD.min(bound);
        let ceiling = match observed {
            // The optimisation: hold no more than this conversation can need.
            Some(longest) => longest.max(declared.unwrap_or(0)).max(floor).min(bound),
            // The optimisation is unavailable, so it is switched off rather than
            // guessed at. `W_max = L_MAX_STATIC - 1`.
            None => bound,
        };
        Self {
            lookahead: ceiling.saturating_sub(1),
            ceiling,
        }
    }

    /// `W`.
    pub fn lookahead(self) -> usize {
        self.lookahead
    }

    /// The most bytes the buffer may hold.
    pub fn ceiling(self) -> usize {
        self.ceiling
    }

    /// `stream_stats.l_max_session`, which the schema bounds at 1..=128.
    pub fn l_max_session(self) -> usize {
        self.ceiling.clamp(1, L_MAX_STATIC)
    }
}

/// One alias occurrence the scan committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hit {
    pub start: usize,
    pub end: usize,
}

/// What one pass of the automaton over the buffer found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scan {
    /// Committed occurrences, in source order, never overlapping.
    pub hits: Vec<Hit>,
    /// A **complete** alias at the end of the buffer that a further byte could
    /// still turn into a longer one. It is not committed while more text may
    /// arrive, and it is committed the moment the buffer is released past its
    /// end, which is what makes an alias at the very end of a stream a restored
    /// value rather than the letters the model happened to stop on.
    pub pending: Option<Hit>,
    /// How many trailing bytes are still undecided.
    pub live_prefix: usize,
}

/// Runs the frozen automaton over a buffer.
///
/// Leftmost longest, and an occurrence is **committed only when it can no longer
/// grow**: with `PSK_PERSON_1` and `PSK_PERSON_11` both in the session, seeing the
/// first is not a decision until the next byte says which of the two arrived.
/// That delay is the same delay the hold buffer applies, which is why the two are
/// the same mechanism rather than two.
pub fn scan(snapshot: &Snapshot, held: &[u8]) -> Scan {
    if snapshot.is_empty() {
        return Scan::default();
    }

    let mut hits: Vec<Hit> = Vec::new();
    let mut cursor = 0usize;
    let mut at = 0usize;
    let mut state = snapshot.root();
    let mut best: Option<Hit> = None;

    while at < held.len() {
        state = snapshot.step(state, held[at]);
        at += 1;

        if let Some(alias) = snapshot.hit(state) {
            let start = at.saturating_sub(alias.len());
            if start >= cursor {
                let candidate = Hit { start, end: at };
                best = Some(match best {
                    None => candidate,
                    Some(current) => {
                        if candidate.start < current.start
                            || (candidate.start == current.start && candidate.end > current.end)
                        {
                            candidate
                        } else {
                            current
                        }
                    }
                });
            }
        }

        // Can the occupant still grow? Only while the automaton's live prefix
        // still reaches back to where it started.
        if let Some(current) = best {
            if snapshot.depth(state) < at - current.start {
                hits.push(current);
                cursor = current.end;
                best = None;
                // Restart at the root after a committed occurrence, which is what
                // makes the occurrences non overlapping and the live prefix below
                // measured from the right place.
                at = cursor;
                state = snapshot.root();
            }
        }
    }

    let live_prefix = match best {
        // A complete alias that might still grow. All of it stays.
        Some(current) => held.len() - current.start,
        None => snapshot.depth(state).min(held.len() - cursor),
    };

    Scan {
        hits,
        pending: best,
        live_prefix,
    }
}

/// What one release produced.
#[derive(Debug)]
pub struct Released {
    /// The pieces, in source order: text to pass through and aliases to restore.
    pub pieces: Vec<Piece>,
    /// How many buffer bytes left.
    pub bytes: usize,
    pub phase: Phase,
    pub verdict: Verdict,
}

/// One piece of released output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Piece {
    /// Text that carries no alias of this conversation.
    Text(String),
    /// An alias the automaton matched whole. The caller looks it up; this module
    /// never invents a value for one.
    Alias(String),
}

/// The hold buffer of one lane.
#[derive(Debug)]
pub struct Buffer {
    held: Vec<u8>,
    window: Window,
    max_seen: usize,
}

impl Buffer {
    pub fn new(window: Window) -> Self {
        Self {
            held: Vec::new(),
            window,
            max_seen: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// The largest this buffer has ever been: `stream_stats.max_buffer_bytes`.
    pub fn high_water(&self) -> usize {
        self.max_seen
    }

    pub fn window(&self) -> Window {
        self.window
    }

    /// Adds text to the buffer. Nothing leaves here.
    pub fn push(&mut self, text: &str) {
        self.held.extend_from_slice(text.as_bytes());
        self.max_seen = self.max_seen.max(self.held.len());
    }

    /// Takes whatever the flush rule allows out of the buffer.
    pub fn release(
        &mut self,
        snapshot: &Snapshot,
        trigger: Trigger,
        on_timeout: HoldTimeout,
    ) -> Released {
        let scan = scan(snapshot, &self.held);
        let verdict = decide(
            self.held.len(),
            scan.live_prefix,
            self.window.ceiling(),
            trigger,
            on_timeout,
        );

        // The one guard against splitting a character: a release boundary is
        // moved **back** to the nearest one, never forward. Aliases are ASCII, so
        // a boundary inside a multi byte character can only appear under a
        // ceiling clamp, and holding one more byte is always the safe direction.
        let release = floor_to_boundary(&self.held, verdict.release);

        // A complete alias the scan left undecided becomes a decision the moment
        // the release reaches past its end. Without this the last alias of a
        // stream would leave as the letters it is spelled with rather than as the
        // value it stands for.
        let mut occurrences = scan.hits.clone();
        if let Some(pending) = scan.pending {
            if pending.end <= release {
                occurrences.push(pending);
            }
        }

        let mut pieces = Vec::new();
        let mut last = 0usize;
        let mut matched = false;
        for hit in &occurrences {
            if hit.end > release {
                break;
            }
            push_text(&mut pieces, &self.held[last..hit.start]);
            pieces.push(Piece::Alias(
                String::from_utf8_lossy(&self.held[hit.start..hit.end]).into_owned(),
            ));
            matched = true;
            last = hit.end;
        }
        push_text(&mut pieces, &self.held[last..release]);

        self.held.drain(..release);
        let phase = if matched {
            Phase::Match
        } else if self.held.is_empty() {
            Phase::Pass
        } else {
            Phase::Hold
        };

        Released {
            pieces,
            bytes: release,
            phase,
            verdict,
        }
    }

    /// How many trailing bytes are the beginning of an alias, right now.
    ///
    /// The number the timeout path reports as `hold_timeout_flush_depth_max`.
    pub fn live_prefix(&self, snapshot: &Snapshot) -> usize {
        scan(snapshot, &self.held).live_prefix
    }
}

fn push_text(pieces: &mut Vec<Piece>, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    pieces.push(Piece::Text(String::from_utf8_lossy(bytes).into_owned()));
}

/// Moves an index back to the nearest UTF-8 character boundary.
fn floor_to_boundary(bytes: &[u8], mut at: usize) -> usize {
    if at >= bytes.len() {
        return bytes.len();
    }
    while at > 0 && (bytes[at] & 0b1100_0000) == 0b1000_0000 {
        at -= 1;
    }
    at
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn snapshot(aliases: &[&str]) -> Snapshot {
        Snapshot::frozen(
            aliases.len() as u64,
            aliases.iter().map(|alias| (*alias).to_owned()),
        )
    }

    fn text_of(released: &Released) -> String {
        released
            .pieces
            .iter()
            .map(|piece| match piece {
                Piece::Text(text) => text.clone(),
                Piece::Alias(alias) => format!("<{alias}>"),
            })
            .collect()
    }

    fn buffer(aliases: &[&str]) -> (Snapshot, Buffer) {
        let snapshot = snapshot(aliases);
        let window = Window::of(Some(snapshot.longest()), None, AliasStyle::TypePreserving);
        (snapshot, Buffer::new(window))
    }

    #[test]
    fn text_with_no_alias_passes_straight_through() {
        let (snapshot, mut held) = buffer(&["PSK_PERSON_1"]);
        held.push("hello there");
        let out = held.release(&snapshot, Trigger::Settled, HoldTimeout::Flush);
        assert_eq!(text_of(&out), "hello there");
        assert_eq!(out.phase, Phase::Pass);
    }

    #[test]
    fn an_alias_split_across_two_pushes_is_matched_whole() {
        let (snapshot, mut held) = buffer(&["PSK_PERSON_1"]);
        held.push("Fatura PSK_PER");
        let first = held.release(&snapshot, Trigger::Settled, HoldTimeout::Flush);
        assert_eq!(text_of(&first), "Fatura ");
        assert_eq!(first.phase, Phase::Hold);

        held.push("SON_1 adina");
        let second = held.release(&snapshot, Trigger::Settled, HoldTimeout::Flush);
        assert_eq!(text_of(&second), "<PSK_PERSON_1> adina");
        assert_eq!(second.phase, Phase::Match);
    }

    #[test]
    fn a_longer_alias_is_not_decided_by_the_shorter_one_inside_it() {
        let (snapshot, mut held) = buffer(&["PSK_PERSON_1", "PSK_PERSON_11"]);
        held.push("PSK_PERSON_1");
        let first = held.release(&snapshot, Trigger::Settled, HoldTimeout::Flush);
        // Nothing decided: the next byte still chooses between the two.
        assert_eq!(text_of(&first), "");
        held.push("1 x");
        let second = held.release(&snapshot, Trigger::Settled, HoldTimeout::Flush);
        assert_eq!(text_of(&second), "<PSK_PERSON_11> x");
    }

    #[test]
    fn a_space_inside_an_alias_does_not_release_it() {
        // The F3 regression, in the smallest shape. A phone alias contains
        // spaces; a buffer that flushed at one would emit `+44 7700` unmasked.
        let (snapshot, mut held) = buffer(&["+44 7700 900123"]);
        held.push("call +44 7700");
        let out = held.release(&snapshot, Trigger::Settled, HoldTimeout::Flush);
        assert_eq!(text_of(&out), "call ");
        held.push(" 900123 now");
        let out = held.release(&snapshot, Trigger::Settled, HoldTimeout::Flush);
        assert_eq!(text_of(&out), "<+44 7700 900123> now");
    }

    #[test]
    fn the_buffer_never_holds_more_than_the_ceiling() {
        let (snapshot, mut held) = buffer(&["PSK_PERSON_1"]);
        for _ in 0..64 {
            held.push("PSK_PERSON_");
            let _ = held.release(&snapshot, Trigger::Settled, HoldTimeout::Flush);
            assert!(
                held.len() <= held.window().ceiling(),
                "the buffer grew past its ceiling: {} > {}",
                held.len(),
                held.window().ceiling()
            );
        }
    }

    #[test]
    fn the_window_falls_back_to_the_compile_time_bound_when_it_cannot_be_derived() {
        // Task 90: a failed optimisation may not become a correctness error.
        let unknown = Window::of(None, None, AliasStyle::TypePreserving);
        assert_eq!(unknown.lookahead(), L_MAX_STATIC - 1);
        assert_eq!(unknown.ceiling(), L_MAX_STATIC);

        let opaque = Window::of(None, None, AliasStyle::Opaque);
        assert_eq!(opaque.ceiling(), l_max_static(AliasStyle::Opaque));
    }

    #[test]
    fn the_minimum_lookahead_never_exceeds_the_compile_time_bound() {
        // Task 90's criterion. It is a floor, and a floor above the ceiling would
        // be a buffer larger than the worst case analysis allows. Checked through
        // the window rather than as a comparison of two constants, which the
        // compiler folds away.
        for style in [AliasStyle::TypePreserving, AliasStyle::Opaque] {
            let tiny = Window::of(Some(1), None, style);
            assert!(tiny.ceiling() <= l_max_static(style));
            assert_eq!(tiny.ceiling(), MIN_LOOKAHEAD.min(l_max_static(style)));
        }
    }

    #[test]
    fn a_declared_l_max_session_raises_the_window_and_never_lowers_it() {
        // ADR-010: `L_max_session` is a latency optimisation. Letting a configured
        // value cut below the session's real longest alias would turn a tuning
        // knob into a masking leak.
        let long = Window::of(Some(90), Some(30), AliasStyle::TypePreserving);
        assert_eq!(long.ceiling(), 90);
        let raised = Window::of(Some(30), Some(90), AliasStyle::TypePreserving);
        assert_eq!(raised.ceiling(), 90);
        // And never past the compile time bound.
        let capped = Window::of(Some(200), Some(200), AliasStyle::TypePreserving);
        assert_eq!(capped.ceiling(), L_MAX_STATIC);
    }

    #[test]
    fn an_empty_snapshot_holds_nothing() {
        let snapshot = Snapshot::empty();
        let mut held = Buffer::new(Window::of(None, None, AliasStyle::TypePreserving));
        held.push("PSK_PERSON_1 is just text here");
        let out = held.release(&snapshot, Trigger::Settled, HoldTimeout::Flush);
        assert_eq!(text_of(&out), "PSK_PERSON_1 is just text here");
        assert!(held.is_empty());
    }

    #[test]
    fn multi_byte_characters_are_never_split_by_a_release() {
        let (snapshot, mut held) = buffer(&["PSK_PERSON_1"]);
        held.push("çğüşöİ PSK_PER");
        let out = held.release(&snapshot, Trigger::Settled, HoldTimeout::Flush);
        assert_eq!(text_of(&out), "çğüşöİ ");
        assert!(!text_of(&out).contains('\u{fffd}'));
    }

    #[test]
    fn two_aliases_in_one_push_come_out_in_source_order() {
        let (snapshot, mut held) = buffer(&["PSK_PERSON_1", "PSK_IBAN_1"]);
        held.push("PSK_PERSON_1 owes PSK_IBAN_1.");
        let out = held.release(&snapshot, Trigger::Settled, HoldTimeout::Flush);
        assert_eq!(text_of(&out), "<PSK_PERSON_1> owes <PSK_IBAN_1>.");
    }
}
