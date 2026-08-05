//! Splitting text into prose and fenced code, so `code_block_policy` has
//! something to apply to.
//!
//! # Why this is a separate concern
//!
//! `proxy/spec.md` section 7 calls itself "bilerek alınmış bir risk kaydı", a
//! deliberately taken risk. Inside a fenced block, masking a name breaks code
//! that has to compile; outside it, not masking a name is a leak. The two want
//! opposite defaults, so the split has to exist before any policy can be applied
//! to it.
//!
//! # What the spec admits, and this module admits with it
//!
//! Section 7 rule 5: "Markdown ayrıştırması **kusurludur**". An unclosed fence,
//! a nested fence, a block with no language tag: all of them can be classified
//! wrongly. That is written into the tests here rather than left to be discovered,
//! and the direction of the error is chosen: an **unclosed** fence closes at the
//! end of the text, so the tail is treated as code and the dictionary layer is
//! skipped over it. That is the miss-shaped error, and it is the one taken
//! knowingly because the alternative, treating an unterminated ``` as prose,
//! would run the dictionary over a code body the user meant as code and rewrite
//! identifiers in it.
//!
//! Rule 4: inline code, one backtick, is **not** a code block. A name in
//! backticks in a sentence is still a name.

/// What kind of text a range is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentKind {
    /// Ordinary text. Every layer the policy enables runs.
    Prose,
    /// Inside a fenced block. `code_block_policy` decides what runs.
    CodeBlock,
}

/// A run of text of one kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub kind: SegmentKind,
    pub start: usize,
    pub end: usize,
}

/// The fence marker. Three backticks, per CommonMark and per spec section 7.
const FENCE: &str = "```";

/// Splits `text` into alternating prose and fenced code segments.
///
/// The fence line itself belongs to the code segment: it carries no entity and
/// putting it in prose would make a language tag like `python` a dictionary
/// candidate.
pub fn segments(text: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(offset) = text.get(cursor..).and_then(|rest| rest.find(FENCE)) {
        let open = cursor + offset;
        if open > cursor {
            out.push(Segment {
                kind: SegmentKind::Prose,
                start: cursor,
                end: open,
            });
        }
        let after_open = open + FENCE.len();
        let close = text
            .get(after_open..)
            .and_then(|rest| rest.find(FENCE))
            .map_or(text.len(), |at| after_open + at + FENCE.len());
        out.push(Segment {
            kind: SegmentKind::CodeBlock,
            start: open,
            end: close,
        });
        cursor = close;
        if cursor >= text.len() {
            break;
        }
    }
    if cursor < text.len() {
        out.push(Segment {
            kind: SegmentKind::Prose,
            start: cursor,
            end: text.len(),
        });
    }
    if out.is_empty() && !text.is_empty() {
        out.push(Segment {
            kind: SegmentKind::Prose,
            start: 0,
            end: text.len(),
        });
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<(SegmentKind, &str)> {
        segments(text)
            .into_iter()
            .filter_map(|segment| {
                text.get(segment.start..segment.end)
                    .map(|slice| (segment.kind, slice))
            })
            .collect()
    }

    #[test]
    fn plain_text_is_one_prose_segment() {
        assert_eq!(
            kinds("Ahmet geldi"),
            vec![(SegmentKind::Prose, "Ahmet geldi")]
        );
        assert!(segments("").is_empty());
    }

    #[test]
    fn a_fenced_block_is_its_own_segment_and_the_fence_lines_go_with_it() {
        let text = "Önce şu:\n```python\nx = 1\n```\nSonra Ahmet.";
        assert_eq!(
            kinds(text),
            vec![
                (SegmentKind::Prose, "Önce şu:\n"),
                (SegmentKind::CodeBlock, "```python\nx = 1\n```"),
                (SegmentKind::Prose, "\nSonra Ahmet."),
            ]
        );
    }

    #[test]
    fn inline_code_is_not_a_code_block() {
        // Spec section 7 rule 4. A name in single backticks is still a name.
        let text = "Değişken `ahmet` burada";
        assert_eq!(kinds(text), vec![(SegmentKind::Prose, text)]);
    }

    #[test]
    fn an_unclosed_fence_closes_at_the_end_of_the_text() {
        // The admitted imperfection of spec section 7 rule 5, with its direction
        // chosen: the tail is code, so the dictionary layer does not rewrite
        // identifiers in a block the user meant as code.
        let text = "before\n```\nx = 1\nAhmet";
        assert_eq!(
            kinds(text),
            vec![
                (SegmentKind::Prose, "before\n"),
                (SegmentKind::CodeBlock, "```\nx = 1\nAhmet"),
            ]
        );
    }

    #[test]
    fn two_blocks_do_not_swallow_the_prose_between_them() {
        let text = "```\na\n```\nAhmet\n```\nb\n```";
        assert_eq!(
            kinds(text),
            vec![
                (SegmentKind::CodeBlock, "```\na\n```"),
                (SegmentKind::Prose, "\nAhmet\n"),
                (SegmentKind::CodeBlock, "```\nb\n```"),
            ]
        );
    }

    #[test]
    fn the_segments_tile_the_input_exactly() {
        // No byte belongs to two segments and none belongs to none: a hole here
        // would be text nothing scans.
        for text in [
            "",
            "abc",
            "```x```",
            "a```b```c",
            "```",
            "a\n```py\nkod\n```\nb\n```\nc",
        ] {
            let found = segments(text);
            let mut cursor = 0;
            for segment in &found {
                assert_eq!(segment.start, cursor, "gap or overlap in {text:?}");
                cursor = segment.end;
            }
            assert_eq!(cursor, text.len(), "tail missing in {text:?}");
        }
    }
}
