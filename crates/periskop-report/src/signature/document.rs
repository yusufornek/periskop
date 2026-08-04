//! What a signature covers, derived from the bytes of a report as they sit on
//! disk.
//!
//! This module exists because of one failure mode. The obvious way to verify a
//! signed report is to read the file, deserialize it into the program's own
//! report type, serialize that back out and hash the result. That verifies a
//! round trip through this program's idea of a report, not the document the
//! reader is looking at: an unknown field, a duplicated key, a re-indented file
//! or a number spelled differently all vanish in the round trip, and the
//! signature then attests to something nobody has seen.
//!
//! So the derivation starts from the bytes and refuses to guess. The document is
//! parsed into a generic value, that value is written back out in the one
//! canonical form this crate defines, and the result must equal the bytes that
//! came in, byte for byte. Only then is the body hash taken. After that check the
//! hash is a function of the file, because canonicalization has been shown to be
//! the identity on it, and nothing can be laundered through the parser.
//!
//! One boundary is worth stating plainly rather than leaving to be discovered.
//! `signature-envelope.md` puts the report's `envelope` block outside the hashed
//! scope, because it carries the wall clock and the machine name and a scan that
//! ran twice has to hash the same. A change confined to that block is therefore
//! not detected by a signature, by contract. Everything else in the file is.

use periskop_core::ids::ReportId;

use super::error::{Result, SignatureError};

/// Domain separation tag, prefixed to the signed bytes.
///
/// `signature-envelope.md`: the tag is prepended to what is signed and does not
/// enter the `body_hash` value itself. Without it a signature over a periskop
/// report could be replayed as a signature over any other structure that happens
/// to present the same 64 characters.
pub const DOMAIN_TAG: &str = "periskop/report-sig/v1";

/// A report document, reduced to the two facts a signature needs.
///
/// Holding the derived values rather than the text is deliberate: once this type
/// exists, the canonical form check has passed, so nothing downstream has to
/// remember to perform it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDocument {
    report_id: String,
    body_hash: String,
}

impl SignedDocument {
    /// Derives what a signature covers from a report exactly as it was written.
    ///
    /// Takes bytes rather than a `ScanReport` so that a caller cannot hand in a
    /// structure that never touched a disk. The signer and the verifier walk the
    /// same path, which is what makes the two agree.
    pub fn from_bytes(document: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(document).map_err(|_| SignatureError::DocumentNotUtf8)?;
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|e| SignatureError::DocumentNotJson(e.to_string()))?;

        // The whole claim of this module. Duplicate keys, unsorted keys, other
        // indentation, a missing or doubled trailing newline and any number
        // spelled in a second way all fail here rather than being normalized
        // away into a signature that speaks for a file nobody has.
        if crate::serialize::to_canonical_json(&value)? != text {
            return Err(SignatureError::DocumentNotCanonical);
        }

        let object = value
            .as_object()
            .ok_or(SignatureError::DocumentNotAnObject)?;
        let report_id = object
            .get("report_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(SignatureError::DocumentWithoutReportId)?;
        // Parsed rather than merely read, so a document whose identifier could
        // never appear in an envelope is refused at the door instead of
        // producing an envelope that fails its own schema.
        let report_id =
            ReportId::parse(report_id).map_err(|_| SignatureError::DocumentReportIdMalformed)?;

        Ok(Self {
            report_id: report_id.as_str().to_owned(),
            body_hash: crate::serialize::body_hash(&value)?,
        })
    }

    pub fn report_id(&self) -> &str {
        &self.report_id
    }

    pub fn body_hash(&self) -> &str {
        &self.body_hash
    }

    /// The exact byte string an ed25519 signature is taken over.
    ///
    /// The tag and the 64 hex characters of the body hash, concatenated, which is
    /// what the contract writes as `"periskop/report-sig/v1" ‖ body_hash`. The
    /// hash goes in as the characters an independent verifier reads out of the
    /// envelope, not as the 32 bytes behind them, so an implementation written
    /// from the contract alone reaches the same bytes.
    pub(super) fn signing_input(&self) -> Vec<u8> {
        let mut input = Vec::with_capacity(DOMAIN_TAG.len() + self.body_hash.len());
        input.extend_from_slice(DOMAIN_TAG.as_bytes());
        input.extend_from_slice(self.body_hash.as_bytes());
        input
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn document(report_id: &str) -> String {
        let value = serde_json::json!({
            "report_id": report_id,
            "envelope": { "generated_at": "2026-08-04T09:00:00Z", "tool_version": "0.1.0" },
            "verdict": "PASS",
            "findings": []
        });
        crate::serialize::to_canonical_json(&value).unwrap()
    }

    const REPORT_ID: &str = "rpt_0123456789abcdef";

    #[test]
    fn a_canonical_document_yields_a_hash_and_an_identity() {
        let derived = SignedDocument::from_bytes(document(REPORT_ID).as_bytes()).unwrap();
        assert_eq!(derived.report_id(), REPORT_ID);
        assert_eq!(derived.body_hash().len(), 64);
        assert!(derived.body_hash().bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn one_changed_byte_changes_the_hash() {
        let base = document(REPORT_ID);
        let changed = base.replace("PASS", "FAIL");
        assert_eq!(base.len(), changed.len());
        assert_ne!(
            SignedDocument::from_bytes(base.as_bytes())
                .unwrap()
                .body_hash(),
            SignedDocument::from_bytes(changed.as_bytes())
                .unwrap()
                .body_hash()
        );
    }

    #[test]
    fn a_document_that_is_not_in_canonical_form_is_refused() {
        // The bug this pins: re-serializing the parsed value would have quietly
        // repaired the indentation and produced a signature over a document that
        // exists nowhere.
        let compact = r#"{"envelope":{},"report_id":"rpt_0123456789abcdef"}"#;
        assert!(matches!(
            SignedDocument::from_bytes(compact.as_bytes()),
            Err(SignatureError::DocumentNotCanonical)
        ));
    }

    #[test]
    fn a_document_with_a_duplicated_key_is_refused() {
        // Left to the parser, the last value would win and the reader's first
        // value would be signed away.
        let doubled = "{\n  \"envelope\": {},\n  \"report_id\": \"rpt_0123456789abcdef\",\n  \"verdict\": \"PASS\",\n  \"verdict\": \"FAIL\"\n}\n";
        assert!(matches!(
            SignedDocument::from_bytes(doubled.as_bytes()),
            Err(SignatureError::DocumentNotCanonical)
        ));
    }

    #[test]
    fn a_document_with_a_trailing_newline_removed_is_refused() {
        let mut text = document(REPORT_ID);
        assert!(text.ends_with('\n'));
        text.pop();
        assert!(matches!(
            SignedDocument::from_bytes(text.as_bytes()),
            Err(SignatureError::DocumentNotCanonical)
        ));
    }

    #[test]
    fn a_document_without_a_report_id_is_refused() {
        let text =
            crate::serialize::to_canonical_json(&serde_json::json!({ "envelope": {} })).unwrap();
        assert!(matches!(
            SignedDocument::from_bytes(text.as_bytes()),
            Err(SignatureError::DocumentWithoutReportId)
        ));
    }

    #[test]
    fn a_document_with_an_unusable_report_id_is_refused() {
        let text = document("rpt_NOT-HEX");
        assert!(matches!(
            SignedDocument::from_bytes(text.as_bytes()),
            Err(SignatureError::DocumentReportIdMalformed)
        ));
    }

    #[test]
    fn a_document_that_is_not_json_is_refused() {
        assert!(matches!(
            SignedDocument::from_bytes(b"not json"),
            Err(SignatureError::DocumentNotJson(_))
        ));
    }

    #[test]
    fn a_document_that_is_not_utf8_is_refused() {
        assert!(matches!(
            SignedDocument::from_bytes(&[0xff, 0xfe, 0x00]),
            Err(SignatureError::DocumentNotUtf8)
        ));
    }

    #[test]
    fn the_envelope_block_is_the_only_part_outside_the_hash() {
        // Stated as a test rather than only in prose, because it is the one
        // place where "one changed byte fails verification" does not hold, and a
        // limitation nobody wrote down is a limitation nobody knows about.
        let morning = SignedDocument::from_bytes(document(REPORT_ID).as_bytes()).unwrap();
        let evening_text = document(REPORT_ID).replace("09:00:00", "21:30:00");
        let evening = SignedDocument::from_bytes(evening_text.as_bytes()).unwrap();
        assert_eq!(morning.body_hash(), evening.body_hash());
    }

    #[test]
    fn the_signed_bytes_are_the_tag_followed_by_the_hash_characters() {
        let derived = SignedDocument::from_bytes(document(REPORT_ID).as_bytes()).unwrap();
        let expected = format!("{DOMAIN_TAG}{}", derived.body_hash());
        assert_eq!(derived.signing_input(), expected.as_bytes());
    }
}
