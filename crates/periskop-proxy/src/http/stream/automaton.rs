//! The alias set of one conversation, frozen, as an Aho-Corasick automaton.
//!
//! # Why this is built by hand rather than taken from the crate
//!
//! `aho_corasick::AhoCorasick` is already a dependency and detection layer B uses
//! it. It answers "where are the matches", which is the question a scan over a
//! finished string asks. The streaming buffer asks a different one
//! (`proxy/spec.md` section 6.2 step 3): **is the tail of what I am holding the
//! beginning of an alias?** That is the automaton's active node, and the crate
//! does not expose it. Answering it any other way means comparing the tail
//! against every alias on every byte, which is the quadratic scan the automaton
//! exists to replace, or guessing from a character class, which is the removed F3
//! rule and a leak (D-14).
//!
//! So the trie, the fail links and the node depth are here, and the depth is the
//! whole reason: `depth(state)` is exactly how many trailing bytes are still
//! undecided, and the flush rule reads that number and nothing else.
//!
//! # Frozen, and what freezing buys
//!
//! ADR-010 section 4: the automaton is built when a request is accepted and is
//! not rebuilt while the answer streams. Aliases are minted on the **request**
//! path only, so a conversation's alias set cannot change while its answer is
//! arriving; rebuilding mid stream would spend the cost for no new alias and, in
//! doing so, would change the meaning of a hold buffer half way through it.
//!
//! [`Snapshot::version`] is what lets the next request in the same conversation
//! reuse this one: the version is the number of aliases the session has issued, so
//! an unchanged count means an unchanged set.
//!
//! # What is in it, and what is deliberately not
//!
//! Only the aliases this session **actually issued**. A string the user wrote
//! that merely looks like one of ours was withheld by the minter (ADR-010 section
//! 6) and is not in here, so it is never matched and never replaced. That is the
//! invariant F4-D established on the request side, holding on the response side:
//! the user's own `PSK_PERSON_1` comes back as the user wrote it.

use std::collections::BTreeMap;

/// A node of the automaton.
struct Node {
    /// Trie edges only. Everything else is reached through [`Node::fail`].
    next: BTreeMap<u8, u32>,
    fail: u32,
    depth: u32,
    /// The longest alias ending exactly here, following fail links.
    out: Option<u32>,
}

impl Node {
    fn new(depth: u32) -> Self {
        Self {
            next: BTreeMap::new(),
            fail: ROOT,
            depth,
            out: None,
        }
    }
}

const ROOT: u32 = 0;

/// Where the automaton is.
///
/// Opaque so that no caller can invent one: a state from another snapshot would
/// index another automaton's nodes, and the flush decision would be taken on a
/// depth that means nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State(u32);

/// One conversation's alias set, frozen.
pub struct Snapshot {
    version: u64,
    aliases: Vec<String>,
    nodes: Vec<Node>,
    longest: usize,
}

impl core::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Counts, never the strings. An alias is not a secret, but
        // `proxy/spec.md` section 9 keeps the set out of every rendering that a
        // log line could pick up, and a `Debug` is exactly such a rendering.
        f.debug_struct("Snapshot")
            .field("version", &self.version)
            .field("aliases", &self.aliases.len())
            .field("longest", &self.longest)
            .finish()
    }
}

impl Snapshot {
    /// Freezes an alias set.
    ///
    /// `version` is the caller's own counter for "has this set changed"; the
    /// gateway uses the number of aliases the session has issued.
    pub fn frozen(version: u64, aliases: impl IntoIterator<Item = String>) -> Self {
        let mut kept: Vec<String> = aliases.into_iter().filter(|s| !s.is_empty()).collect();
        kept.sort_unstable();
        kept.dedup();

        let mut nodes = vec![Node::new(0)];
        for (id, alias) in kept.iter().enumerate() {
            let mut at = ROOT;
            for byte in alias.as_bytes() {
                let next = match nodes[at as usize].next.get(byte) {
                    Some(next) => *next,
                    None => {
                        let depth = nodes[at as usize].depth + 1;
                        nodes.push(Node::new(depth));
                        let created = u32::try_from(nodes.len() - 1).unwrap_or(ROOT);
                        nodes[at as usize].next.insert(*byte, created);
                        created
                    }
                };
                at = next;
            }
            // The longest alias ending here wins, and `kept` is sorted, so a
            // shorter one never overwrites a longer one at the same node.
            let id = u32::try_from(id).unwrap_or(0);
            let replace = match nodes[at as usize].out {
                None => true,
                Some(existing) => kept[id as usize].len() > kept[existing as usize].len(),
            };
            if replace {
                nodes[at as usize].out = Some(id);
            }
        }

        link_failures(&mut nodes);
        let longest = kept.iter().map(String::len).max().unwrap_or(0);
        Self {
            version,
            aliases: kept,
            nodes,
            longest,
        }
    }

    /// An automaton with nothing in it.
    pub fn empty() -> Self {
        Self::frozen(0, Vec::new())
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    /// The longest alias in this conversation, in bytes.
    ///
    /// This is `L_max_session` (`proxy/spec.md` section 6.2), and it is derived
    /// here rather than configured, because it is a fact about the session.
    pub fn longest(&self) -> usize {
        self.longest
    }

    pub fn alias_count(&self) -> usize {
        self.aliases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.aliases.is_empty()
    }

    pub fn root(&self) -> State {
        State(ROOT)
    }

    /// One byte.
    pub fn step(&self, state: State, byte: u8) -> State {
        let mut at = state.0;
        loop {
            if let Some(next) = self.nodes[at as usize].next.get(&byte) {
                return State(*next);
            }
            if at == ROOT {
                return State(ROOT);
            }
            at = self.nodes[at as usize].fail;
        }
    }

    /// How many trailing bytes of the input so far are the beginning of an alias.
    ///
    /// Zero means the automaton is at its root, which is the condition the flush
    /// invariant is written in.
    pub fn depth(&self, state: State) -> usize {
        self.nodes[state.0 as usize].depth as usize
    }

    /// The longest alias that ends at this state, if any.
    pub fn hit(&self, state: State) -> Option<&str> {
        self.nodes[state.0 as usize]
            .out
            .map(|id| self.aliases[id as usize].as_str())
    }

    /// Whether this exact string is one of the aliases the session issued.
    ///
    /// Used by the restore path's own guard rather than by matching: a string the
    /// automaton did not produce may never be looked up in the vault.
    pub fn holds(&self, alias: &str) -> bool {
        self.aliases.binary_search(&alias.to_owned()).is_ok()
    }
}

/// Breadth first fail links, and the output propagation that goes with them.
fn link_failures(nodes: &mut [Node]) {
    let mut queue: Vec<u32> = Vec::new();
    let children: Vec<(u8, u32)> = nodes[ROOT as usize]
        .next
        .iter()
        .map(|(byte, next)| (*byte, *next))
        .collect();
    for (_, child) in children {
        nodes[child as usize].fail = ROOT;
        queue.push(child);
    }

    let mut head = 0;
    while head < queue.len() {
        let at = queue[head];
        head += 1;

        let children: Vec<(u8, u32)> = nodes[at as usize]
            .next
            .iter()
            .map(|(byte, next)| (*byte, *next))
            .collect();
        for (byte, child) in children {
            let mut fallback = nodes[at as usize].fail;
            let target = loop {
                if let Some(next) = nodes[fallback as usize].next.get(&byte) {
                    break *next;
                }
                if fallback == ROOT {
                    break ROOT;
                }
                fallback = nodes[fallback as usize].fail;
            };
            nodes[child as usize].fail = if target == child { ROOT } else { target };

            // A node with no output of its own inherits the one its fail link
            // reaches, which is how a shorter alias ending inside a longer one is
            // still found.
            if nodes[child as usize].out.is_none() {
                let inherited = nodes[nodes[child as usize].fail as usize].out;
                nodes[child as usize].out = inherited;
            }
            queue.push(child);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn run(snapshot: &Snapshot, text: &str) -> Vec<(usize, usize, String)> {
        let mut state = snapshot.root();
        let mut hits = Vec::new();
        for (at, byte) in text.as_bytes().iter().enumerate() {
            state = snapshot.step(state, *byte);
            if let Some(alias) = snapshot.hit(state) {
                hits.push((at + 1 - alias.len(), at + 1, alias.to_owned()));
            }
        }
        hits
    }

    #[test]
    fn the_depth_is_the_length_of_the_live_prefix() {
        let snapshot = Snapshot::frozen(1, ["PSK_PERSON_1".to_owned()]);
        let mut state = snapshot.root();
        for (at, byte) in b"PSK_PER".iter().enumerate() {
            state = snapshot.step(state, *byte);
            assert_eq!(
                snapshot.depth(state),
                at + 1,
                "after {} bytes the automaton is not that deep",
                at + 1
            );
        }
        // A byte that breaks the prefix drops it to the root, which is the whole
        // of the removed F3 rule done correctly: the automaton decides, not a
        // character class.
        let broken = snapshot.step(state, b'!');
        assert_eq!(snapshot.depth(broken), 0);
    }

    #[test]
    fn a_space_inside_an_alias_is_an_ordinary_transition() {
        // D-14: aliases contain spaces (phone, grouped IBAN). The automaton has
        // to stay off its root across one, or the buffer flushes mid alias.
        let snapshot = Snapshot::frozen(1, ["+44 7700 900123".to_owned()]);
        let mut state = snapshot.root();
        for byte in b"+44 7700 9001" {
            state = snapshot.step(state, *byte);
        }
        assert_eq!(snapshot.depth(state), 13);
        assert!(snapshot.hit(state).is_none());
    }

    #[test]
    fn the_longest_alias_ending_at_a_position_is_the_one_reported() {
        let snapshot = Snapshot::frozen(2, ["PSK_PERSON_1".to_owned(), "PSK_PERSON_11".to_owned()]);
        let hits = run(&snapshot, "PSK_PERSON_11");
        assert_eq!(
            hits,
            vec![
                (0, 12, "PSK_PERSON_1".to_owned()),
                (0, 13, "PSK_PERSON_11".to_owned())
            ]
        );
    }

    #[test]
    fn an_alias_ending_inside_another_is_still_found() {
        let snapshot = Snapshot::frozen(2, ["abcd".to_owned(), "bc".to_owned()]);
        let hits = run(&snapshot, "abcd");
        assert!(hits.contains(&(1, 3, "bc".to_owned())), "{hits:?}");
        assert!(hits.contains(&(0, 4, "abcd".to_owned())), "{hits:?}");
    }

    #[test]
    fn a_string_the_session_never_issued_is_not_in_the_automaton() {
        // ADR-010 section 6, on the response side. A test IBAN the model wrote of
        // its own accord is not an alias of this conversation and must not become
        // a lookup.
        let snapshot = Snapshot::frozen(1, ["PSK_IBAN_1".to_owned()]);
        assert!(!snapshot.holds("PSK_IBAN_2"));
        assert!(snapshot.holds("PSK_IBAN_1"));
        assert!(run(&snapshot, "PSK_IBAN_2").is_empty());
    }

    #[test]
    fn an_empty_snapshot_never_leaves_its_root() {
        let snapshot = Snapshot::empty();
        let mut state = snapshot.root();
        for byte in b"PSK_PERSON_1 and anything else" {
            state = snapshot.step(state, *byte);
            assert_eq!(snapshot.depth(state), 0);
            assert!(snapshot.hit(state).is_none());
        }
        assert_eq!(snapshot.longest(), 0);
    }

    #[test]
    fn the_longest_alias_is_derived_from_the_set_rather_than_declared() {
        let snapshot = Snapshot::frozen(3, ["ab".to_owned(), "abcdefgh".to_owned()]);
        assert_eq!(snapshot.longest(), 8);
        assert_eq!(snapshot.alias_count(), 2);
    }

    #[test]
    fn a_duplicate_alias_is_stored_once() {
        let snapshot = Snapshot::frozen(1, ["x".to_owned(), "x".to_owned()]);
        assert_eq!(snapshot.alias_count(), 1);
    }
}
