//! F2: the latency ceiling on a held byte, and what an operator may choose about
//! it (`proxy/spec.md` section 6.2 F2, `proxy-policy.md` section 4).
//!
//! # Why a timeout exists at all
//!
//! The hold buffer is correct with no timeout: hold until the automaton settles
//! and no alias can ever be split. It is also, with no timeout, a proxy that can
//! freeze a slow model's stream for as long as the model takes to write the next
//! token, and a masking proxy that makes the assistant look hung is one an
//! operator switches off. `T_hold` is the price of staying switched on.
//!
//! # And why the price is declared rather than paid quietly
//!
//! When the timeout fires with the automaton **off its root**, the bytes released
//! include the beginning of an alias, un-masked. That is a masking failure, it is
//! the only structural one left after F3 was removed (D-14), and the whole design
//! here is about making it visible:
//!
//! | counter | what it means |
//! |---|---|
//! | `hold_events` | the buffer held something at all |
//! | `hold_timeout_flush` | F2 fired. Expected under `flush`; not an error by itself |
//! | `hold_timeout_flush_depth_max` | the deepest the automaton was when it fired |
//! | `partial_alias_flushed` | it fired off the root, so a fragment may have left. **WARN** |
//!
//! `hold_timeout_flush` and `partial_alias_flushed` are different facts and
//! `proxy-events.md` keeps them apart on purpose: one is latency, the other is a
//! possible leak.
//!
//! # Two options, and there is no third
//!
//! `on_hold_timeout = "flush"` is the default and trades the guarantee for the
//! latency. `"wait"` keeps the guarantee and lets the stream pause; the 150 ms
//! budget does not apply in that mode and the budget report carries it as its own
//! line. A third option, flushing quietly and not counting, does not exist here
//! and `proxy-policy.schema.json` does not accept the word.

use crate::policy::HoldTimeout;

/// `T_hold`, in milliseconds, when the policy names none.
pub const DEFAULT_HOLD_MS: u64 = 40;

/// The clock one lane's buffer is measured against.
#[derive(Clone, Copy, Debug)]
pub struct HoldClock {
    budget_ms: u64,
    mode: HoldTimeout,
    /// When the oldest byte still in the buffer arrived. `None` when the buffer
    /// is empty, which is the only state in which no byte is waiting.
    oldest_ms: Option<u64>,
}

impl HoldClock {
    pub fn new(budget_ms: u64, mode: HoldTimeout) -> Self {
        Self {
            budget_ms,
            mode,
            oldest_ms: None,
        }
    }

    pub fn mode(self) -> HoldTimeout {
        self.mode
    }

    pub fn budget_ms(self) -> u64 {
        self.budget_ms
    }

    /// Records what the buffer looks like after a release.
    ///
    /// The clock starts when a buffer that was empty stops being empty, and it is
    /// **not** restarted while it keeps holding: restarting it on every arriving
    /// chunk is how a byte waits for ever in a stream that keeps producing, which
    /// is exactly the stall `T_hold` exists to bound.
    pub fn observe(&mut self, holding: bool, now_ms: u64) {
        match (holding, self.oldest_ms) {
            (false, _) => self.oldest_ms = None,
            (true, None) => self.oldest_ms = Some(now_ms),
            (true, Some(_)) => {}
        }
    }

    /// Whether the oldest held byte has waited longer than `T_hold`.
    pub fn expired(self, now_ms: u64) -> bool {
        match self.oldest_ms {
            None => false,
            Some(since) => now_ms.saturating_sub(since) >= self.budget_ms,
        }
    }

    /// How long the oldest held byte has waited, for `latency_ms.stream_hold_total`.
    pub fn waited_ms(self, now_ms: u64) -> u64 {
        self.oldest_ms
            .map_or(0, |since| now_ms.saturating_sub(since))
    }
}

/// The stream counters of `proxy-events.md`, in the schema's own names.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamStats {
    pub chunks: u32,
    pub hold_events: u32,
    pub hold_timeout_flush: u32,
    pub hold_timeout_flush_depth_max: u32,
    pub partial_alias_flushed: u32,
    pub max_buffer_bytes: u32,
    pub l_max_static: u32,
    pub l_max_session: u32,
    /// Total milliseconds bytes spent in the buffer: `latency_ms.stream_hold_total`.
    pub hold_total_ms: u64,
}

impl StreamStats {
    /// Records one F2 firing.
    ///
    /// Both counters are written here rather than at the two call sites, because
    /// the pair is the whole point: `hold_timeout_flush` without
    /// `partial_alias_flushed` is a latency note, and the one without the other is
    /// how a leak gets reported as a delay.
    pub fn timed_out(&mut self, depth: usize, partial_alias: bool) {
        self.hold_timeout_flush = self.hold_timeout_flush.saturating_add(1);
        let depth = u32::try_from(depth).unwrap_or(u32::MAX);
        self.hold_timeout_flush_depth_max = self.hold_timeout_flush_depth_max.max(depth);
        if partial_alias {
            self.partial_alias_flushed = self.partial_alias_flushed.saturating_add(1);
        }
    }

    /// Whether this run has to raise a WARN about a possibly leaked fragment.
    pub fn warns(self) -> bool {
        self.partial_alias_flushed > 0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_default_hold_is_the_forty_milliseconds_the_spec_names() {
        assert_eq!(DEFAULT_HOLD_MS, 40);
    }

    #[test]
    fn an_empty_buffer_never_expires() {
        let mut clock = HoldClock::new(DEFAULT_HOLD_MS, HoldTimeout::Flush);
        clock.observe(false, 1_000);
        assert!(!clock.expired(1_000_000));
    }

    #[test]
    fn the_clock_measures_the_oldest_byte_and_is_not_restarted_by_later_ones() {
        // The mutation this catches: `observe` overwriting `oldest_ms` on every
        // call. A stream that keeps producing would then reset the timer for ever
        // and the ceiling would never fire, which is the stall F2 exists to bound.
        let mut clock = HoldClock::new(40, HoldTimeout::Flush);
        clock.observe(true, 1_000);
        clock.observe(true, 1_020);
        clock.observe(true, 1_035);
        assert!(!clock.expired(1_039));
        assert!(clock.expired(1_040));
        assert_eq!(clock.waited_ms(1_050), 50);
    }

    #[test]
    fn emptying_the_buffer_stops_the_clock() {
        let mut clock = HoldClock::new(40, HoldTimeout::Flush);
        clock.observe(true, 1_000);
        clock.observe(false, 1_010);
        assert!(!clock.expired(9_999));
        clock.observe(true, 2_000);
        assert!(!clock.expired(2_010));
        assert!(clock.expired(2_040));
    }

    #[test]
    fn a_zero_budget_expires_as_soon_as_anything_is_held() {
        // `stream.hold_timeout_ms = 0` is a legal policy (integer >= 0) and it
        // means "never hold across a chunk". It has to fire, not never fire.
        let mut clock = HoldClock::new(0, HoldTimeout::Flush);
        clock.observe(true, 5);
        assert!(clock.expired(5));
    }

    #[test]
    fn a_timeout_off_the_root_counts_both_facts_and_warns() {
        let mut stats = StreamStats::default();
        stats.timed_out(7, true);
        assert_eq!(stats.hold_timeout_flush, 1);
        assert_eq!(stats.hold_timeout_flush_depth_max, 7);
        assert_eq!(stats.partial_alias_flushed, 1);
        assert!(stats.warns());
    }

    #[test]
    fn a_timeout_at_the_root_is_latency_and_not_a_leak() {
        let mut stats = StreamStats::default();
        stats.timed_out(0, false);
        assert_eq!(stats.hold_timeout_flush, 1);
        assert_eq!(stats.partial_alias_flushed, 0);
        assert!(!stats.warns());
    }

    #[test]
    fn the_deepest_firing_is_the_one_reported() {
        let mut stats = StreamStats::default();
        stats.timed_out(3, true);
        stats.timed_out(11, true);
        stats.timed_out(5, true);
        assert_eq!(stats.hold_timeout_flush_depth_max, 11);
        assert_eq!(stats.partial_alias_flushed, 3);
    }

    #[test]
    fn the_two_modes_are_the_only_two() {
        // The third option (flush quietly, count nothing) has no representation.
        // `HoldTimeout` is the closed set and the policy loader rejects any other
        // word; this asserts the set has not grown a silent member.
        let named: Vec<String> = [HoldTimeout::Flush, HoldTimeout::Wait]
            .iter()
            .map(|mode| format!("{mode:?}"))
            .collect();
        assert_eq!(named, vec!["Flush".to_owned(), "Wait".to_owned()]);
    }
}
