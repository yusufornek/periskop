//! What a layer hands back: a byte range, a type, and who claimed it.
//!
//! Ranges are **byte** offsets into the scanned string, not character indices.
//! Turkish text is not ASCII and the replacement step splices strings by byte
//! range; a character index would be a silent off by n on every prompt with a
//! `ş` before the match. Every constructor here therefore keeps its range on
//! character boundaries and `text_of` is the only sanctioned way to read one
//! back.

use crate::alias::EntityType;

use super::layer::DetectionLayer;

/// One thing a detection layer believes it found.
///
/// Deliberately not "a masking decision": a candidate is a claim about the text.
/// Whether it is masked, blocked or allowed is `policy::scope`'s answer, and
/// whether two overlapping claims can both stand is `detect::merge`'s.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// The type claimed. Its [`super::layer::owning_layer`] is `layer`, always.
    pub entity: EntityType,
    /// First byte of the match, inclusive.
    pub start: usize,
    /// One past the last byte of the match, exclusive.
    pub end: usize,
    /// Which layer claimed it. Carried rather than recomputed so that a merge
    /// decision can be explained without asking the registry again.
    pub layer: DetectionLayer,
}

impl Candidate {
    /// A candidate for `entity` over `start..end`.
    ///
    /// The layer is derived from the type rather than passed in, so a detector
    /// cannot claim a type another layer owns even by accident.
    pub fn new(entity: EntityType, start: usize, end: usize) -> Self {
        Self {
            entity,
            start,
            end,
            layer: super::layer::owning_layer(entity),
        }
    }

    /// Bytes covered.
    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether the range covers nothing. A zero width candidate is always a bug
    /// in a detector, and `merge` drops it rather than minting an alias for the
    /// empty string.
    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    /// Whether two candidates claim any byte in common.
    ///
    /// Touching is not overlapping: `0..4` and `4..8` are two adjacent entities,
    /// which is the ordinary case for `TR33...` immediately followed by a comma
    /// and another number.
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// The matched text, or `None` when the range is not on character boundaries
    /// or runs past the end.
    ///
    /// `None` rather than a slice panic: this crate denies `panic` in production
    /// code, and a detector that produced a bad range must fail visibly at the
    /// call site rather than take the process down mid request.
    pub fn text_of<'t>(&self, text: &'t str) -> Option<&'t str> {
        text.get(self.start..self.end)
    }
}

/// Sorts candidates into the one order every later stage assumes: by start, then
/// longest first, then by the confidence order, then by type.
///
/// Determinism is the requirement (README principle 7). Two detectors that
/// report in a different order on two runs would produce two different alias
/// numberings for the same prompt, and `PERSON_1` would mean different people in
/// two otherwise identical event records.
pub fn sort_candidates(candidates: &mut [Candidate]) {
    candidates.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(b.len().cmp(&a.len()))
            .then(b.layer.cmp(&a.layer))
            .then(a.entity.cmp(&b.entity))
    });
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_candidate_carries_the_layer_that_owns_its_type() {
        assert_eq!(
            Candidate::new(EntityType::Tckn, 0, 11).layer,
            DetectionLayer::Pattern
        );
        assert_eq!(
            Candidate::new(EntityType::Person, 0, 5).layer,
            DetectionLayer::Dictionary
        );
    }

    #[test]
    fn touching_ranges_do_not_overlap_but_shared_bytes_do() {
        let first = Candidate::new(EntityType::Tckn, 0, 4);
        let touching = Candidate::new(EntityType::Vkn, 4, 8);
        let sharing = Candidate::new(EntityType::Vkn, 3, 8);
        assert!(!first.overlaps(&touching));
        assert!(first.overlaps(&sharing));
        assert!(sharing.overlaps(&first));
    }

    #[test]
    fn a_range_off_a_character_boundary_reads_back_as_none_rather_than_panicking() {
        let text = "şirket";
        // `ş` is two bytes; 1 is inside it.
        let bad = Candidate::new(EntityType::Org, 1, 3);
        assert_eq!(bad.text_of(text), None);
        let past_end = Candidate::new(EntityType::Org, 0, 999);
        assert_eq!(past_end.text_of(text), None);
        let good = Candidate::new(EntityType::Org, 0, 2);
        assert_eq!(good.text_of(text), Some("ş"));
    }

    #[test]
    fn sorting_is_total_so_the_same_input_numbers_aliases_the_same_way() {
        let mut candidates = vec![
            Candidate::new(EntityType::Person, 10, 15),
            Candidate::new(EntityType::Tckn, 0, 11),
            Candidate::new(EntityType::Email, 0, 20),
            Candidate::new(EntityType::Org, 10, 15),
        ];
        let mut reversed = candidates.clone();
        reversed.reverse();
        sort_candidates(&mut candidates);
        sort_candidates(&mut reversed);
        assert_eq!(candidates, reversed);
        // Longest first at the same start, so the merge step sees the widest
        // claim before the narrower one it swallows.
        assert_eq!(candidates[0].entity, EntityType::Email);
    }
}
