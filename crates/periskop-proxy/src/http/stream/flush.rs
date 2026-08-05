//! The one place a byte is allowed to leave the hold buffer.
//!
//! # The three things that have to be true at once
//!
//! Streaming breaks every assumption masking makes. In a whole body `PSK_PERSON_1`
//! is one string; in a stream `PSK_PER` can arrive in one frame and `SON_1` in the
//! next. Three claims must hold together:
//!
//! 1. no alias reaches the client split across a chunk boundary
//!    (`stream_stats.partial_alias_flushed` stays zero, and that is one of the
//!    five assertions of the F4 gate);
//! 2. no un-masked value is emitted, which means the buffer may not release a
//!    byte before it knows whether the next byte continues an entity;
//! 3. the latency budget is not spent, which rules out the trivial way of
//!    satisfying 1 and 2, namely holding everything to the end of the stream.
//!
//! They pull against each other, so the resolution is written here as code rather
//! than as a comment somewhere: **every** release goes through [`decide`], and
//! [`decide`] returns the proof that covers the bytes it releases. There is no
//! second function that shortens the buffer, which is what makes "no character
//! class may trigger a flush" checkable instead of remembered.
//!
//! # The invariant
//!
//! > While the automaton is off its root node, no byte leaves the buffer except
//! > under F1 (end of stream), F2 (the hold timeout) or F4 (a stream error).
//! > Nothing else may release a held byte: not a space, not a newline, not a
//! > closing brace, not any other syntactic hunch.
//!
//! That last sentence is the removed F3 rule (D-14, D-10 finding 22) and its
//! removal is the reason this module exists. F3 said "flush when the held prefix
//! ends in a space or a newline or a `}`", which assumed aliases contain none of
//! those characters. They do: phone aliases are `+44 7700 900123`, IBANs are
//! written in groups, and a stream split inside one of those spaces made F3 emit
//! an un-masked fragment. [`Safety`] has no variant for a character class, so the
//! rule cannot come back without adding one, and
//! `tests/flush_invariant.rs` fails if it does.
//!
//! # F2 is the one release that is not proved
//!
//! Under `on_hold_timeout = "flush"` a byte that has waited longer than `T_hold`
//! is released whether or not it is part of an alias, because a masking proxy that
//! freezes a slow model's stream is one an operator turns off. That release is
//! **declared**, not silent: [`Verdict::partial_alias`] is true exactly when the
//! automaton was off its root, and the counter it feeds produces a WARN. Under
//! `on_hold_timeout = "wait"` the timeout releases nothing, the stream visibly
//! pauses, and no partial alias can leave. There is no third option: silently
//! flushing and not counting is what `proxy/spec.md` section 6.2 rules out, and
//! `proxy-policy.md` accepts no such value.

use crate::policy::HoldTimeout;

/// What made the buffer consider releasing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// The ordinary case: more text arrived and the automaton settled.
    Settled,
    /// F1. `[DONE]` / `message_stop`, or the connection closed.
    StreamEnd,
    /// F2. A byte has been held longer than `T_hold`.
    HoldTimeout,
    /// F4. The upstream sent an error frame.
    StreamError,
}

/// Why the bytes a [`Verdict`] releases are safe to release.
///
/// There is deliberately no variant naming a character, a delimiter or a token
/// boundary. Adding one is how the F3 leak comes back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Safety {
    /// Nothing is held: the automaton is at its root and no alias can begin in
    /// the released bytes and end after them.
    AutomatonAtRoot,
    /// The released bytes sit **before** the live prefix. An alias occurrence that
    /// is still undecided starts inside the bytes that stay behind, so none of it
    /// can be in the bytes that go.
    BeforeLivePrefix,
    /// The live prefix is longer than any alias in this conversation can be, so
    /// the excess cannot be part of one (`proxy/spec.md` section 6.2 step 4).
    BeyondCeiling,
    /// F1: the stream ended, so an incomplete prefix will never be completed and
    /// is therefore not an alias.
    StreamEnded,
    /// F2 under `on_hold_timeout = "flush"`: not proved. Declared instead.
    HoldTimedOut,
    /// F4: the stream failed and the error is being delivered.
    StreamFailed,
}

/// One release decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// How many bytes, counted from the front of the buffer, may leave.
    pub release: usize,
    /// The proof, or the declaration when there is no proof.
    pub safety: Safety,
    /// Whether an un-masked alias fragment is in the released bytes.
    ///
    /// True only under F2 with the automaton off its root. This is
    /// `stream_stats.partial_alias_flushed` and it is a WARN.
    pub partial_alias: bool,
}

/// The only function that shortens a hold buffer.
///
/// * `held` — bytes in the buffer.
/// * `live_prefix` — the automaton's depth at the end of the buffer: how many
///   trailing bytes are the beginning of an alias that has not been decided.
/// * `ceiling` — the longest an alias in this conversation can be, in bytes.
pub fn decide(
    held: usize,
    live_prefix: usize,
    ceiling: usize,
    trigger: Trigger,
    on_timeout: HoldTimeout,
) -> Verdict {
    // A prefix longer than any alias cannot be one, so the part beyond the
    // ceiling is settled whatever the caller was told. Clamping here rather than
    // trusting the caller keeps the buffer bounded even if a snapshot and a
    // ceiling ever disagree, which is the bound the latency budget rests on.
    let clamped = live_prefix.min(ceiling).min(held);
    let beyond_ceiling = live_prefix > clamped;
    let settled = held - clamped;

    match trigger {
        Trigger::Settled => Verdict {
            release: settled,
            safety: safety_of(clamped, beyond_ceiling),
            partial_alias: false,
        },
        // F1. An alias that never completed is not an alias, so what is left goes
        // out as it stands. The caller marks the stream truncated when anything
        // was still held (`proxy-api.md` point 5); that is a declaration about the
        // stream, not a second flush rule.
        Trigger::StreamEnd => Verdict {
            release: held,
            safety: if clamped == 0 {
                safety_of(clamped, beyond_ceiling)
            } else {
                Safety::StreamEnded
            },
            partial_alias: false,
        },
        // F4. The error is delivered rather than held behind a prefix that will
        // never be completed, for the same reason as F1.
        Trigger::StreamError => Verdict {
            release: held,
            safety: if clamped == 0 {
                safety_of(clamped, beyond_ceiling)
            } else {
                Safety::StreamFailed
            },
            partial_alias: false,
        },
        Trigger::HoldTimeout => match on_timeout {
            // The declared, counted, WARN producing release.
            HoldTimeout::Flush => Verdict {
                release: held,
                safety: if clamped == 0 {
                    safety_of(clamped, beyond_ceiling)
                } else {
                    Safety::HoldTimedOut
                },
                partial_alias: clamped > 0,
            },
            // The stream pauses instead. Nothing beyond what was already settled
            // leaves, so no partial alias can.
            HoldTimeout::Wait => Verdict {
                release: settled,
                safety: safety_of(clamped, beyond_ceiling),
                partial_alias: false,
            },
        },
    }
}

fn safety_of(live_prefix: usize, beyond_ceiling: bool) -> Safety {
    if beyond_ceiling {
        Safety::BeyondCeiling
    } else if live_prefix == 0 {
        Safety::AutomatonAtRoot
    } else {
        Safety::BeforeLivePrefix
    }
}

/// The invariant, as a predicate over one decision.
///
/// A release that reaches into the live prefix is only allowed under F1, F2 or
/// F4, and under F2 it has to be declared. Exported so the integration test can
/// assert it over the whole input space rather than over the cases this module
/// happened to write a unit test for.
pub fn honours_the_invariant(
    verdict: &Verdict,
    held: usize,
    live_prefix: usize,
    ceiling: usize,
    trigger: Trigger,
) -> bool {
    let clamped = live_prefix.min(ceiling).min(held);
    if verdict.release <= held - clamped {
        // Nothing of the live prefix left, so no rule was needed.
        return !verdict.partial_alias;
    }
    match trigger {
        Trigger::Settled => false,
        Trigger::StreamEnd | Trigger::StreamError => !verdict.partial_alias,
        Trigger::HoldTimeout => verdict.partial_alias == (clamped > 0),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_settled_buffer_keeps_its_live_prefix_and_releases_the_rest() {
        let verdict = decide(20, 7, 128, Trigger::Settled, HoldTimeout::Flush);
        assert_eq!(verdict.release, 13);
        assert_eq!(verdict.safety, Safety::BeforeLivePrefix);
        assert!(!verdict.partial_alias);
    }

    #[test]
    fn a_root_automaton_releases_everything_and_says_why() {
        let verdict = decide(20, 0, 128, Trigger::Settled, HoldTimeout::Flush);
        assert_eq!(verdict.release, 20);
        assert_eq!(verdict.safety, Safety::AutomatonAtRoot);
    }

    #[test]
    fn nothing_but_the_three_rules_can_reach_into_the_live_prefix() {
        // The invariant, over the whole small input space rather than over an
        // example. `Settled` may never reach in; the other three may, and the
        // timeout has to declare it.
        for held in 0..24usize {
            for live in 0..=held {
                for ceiling in [1usize, 8, 128] {
                    for trigger in [
                        Trigger::Settled,
                        Trigger::StreamEnd,
                        Trigger::HoldTimeout,
                        Trigger::StreamError,
                    ] {
                        for mode in [HoldTimeout::Flush, HoldTimeout::Wait] {
                            let verdict = decide(held, live, ceiling, trigger, mode);
                            assert!(verdict.release <= held, "{verdict:?}");
                            assert!(
                                honours_the_invariant(&verdict, held, live, ceiling, trigger),
                                "held={held} live={live} ceiling={ceiling} {trigger:?} {mode:?} \
                                 produced {verdict:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_timeout_declares_a_partial_alias_only_when_there_is_one() {
        let off_root = decide(10, 4, 128, Trigger::HoldTimeout, HoldTimeout::Flush);
        assert_eq!(off_root.release, 10);
        assert!(off_root.partial_alias);
        assert_eq!(off_root.safety, Safety::HoldTimedOut);

        let at_root = decide(10, 0, 128, Trigger::HoldTimeout, HoldTimeout::Flush);
        assert!(!at_root.partial_alias);
        assert_eq!(at_root.safety, Safety::AutomatonAtRoot);
    }

    #[test]
    fn wait_mode_never_lets_a_partial_alias_out() {
        for live in 1..12usize {
            let verdict = decide(12, live, 128, Trigger::HoldTimeout, HoldTimeout::Wait);
            assert!(!verdict.partial_alias);
            assert_eq!(verdict.release, 12 - live);
        }
    }

    #[test]
    fn the_end_of_a_stream_releases_a_prefix_that_will_never_be_completed() {
        let verdict = decide(6, 6, 128, Trigger::StreamEnd, HoldTimeout::Wait);
        assert_eq!(verdict.release, 6);
        assert_eq!(verdict.safety, Safety::StreamEnded);
        // Not counted as a partial alias: an incomplete prefix at the end of a
        // stream is not an alias, it is the text the model wrote.
        assert!(!verdict.partial_alias);
    }

    #[test]
    fn a_prefix_longer_than_any_alias_is_released_down_to_the_ceiling() {
        // Section 6.2 step 4. It cannot happen while the ceiling is derived from
        // the same snapshot the depth comes from, and it is the bound that keeps
        // the buffer finite if the two ever disagree.
        let verdict = decide(40, 30, 8, Trigger::Settled, HoldTimeout::Flush);
        assert_eq!(verdict.release, 32);
        assert_eq!(verdict.safety, Safety::BeyondCeiling);
    }

    #[test]
    fn no_safety_variant_names_a_character_class() {
        // The regression lock in the shape the type allows: `Safety` is the
        // vocabulary of reasons a byte may leave, and F3 came back as soon as
        // somebody could write down "it ended in a space".
        let named = format!(
            "{:?} {:?} {:?} {:?} {:?} {:?}",
            Safety::AutomatonAtRoot,
            Safety::BeforeLivePrefix,
            Safety::BeyondCeiling,
            Safety::StreamEnded,
            Safety::HoldTimedOut,
            Safety::StreamFailed
        );
        for forbidden in [
            "Space",
            "Whitespace",
            "Newline",
            "Delimiter",
            "Brace",
            "Punctuation",
            "Boundary",
            "Token",
        ] {
            assert!(
                !named.contains(forbidden),
                "a flush reason named {forbidden} exists again; that is the F3 leak"
            );
        }
    }
}
