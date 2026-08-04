//! Canonical serialization.
//!
//! Two reports of the same tree have to be byte identical, so serialization is
//! not left to whatever order a struct happens to declare its fields in. The
//! report is converted to a generic value first, where every object is a sorted
//! map, and written from there.
//!
//! The body hash follows the same path with the envelope removed. That block
//! carries the clock and the machine name, and including it would mean the same
//! scan hashed differently depending on when it ran.

use periskop_core::ids::short_hash;
use serde::Serialize;

/// Serializes with sorted keys, two space indent and a trailing newline.
pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let as_value = serde_json::to_value(value)?;
    canonical_text(&as_value)
}

/// The one canonical form. Everything that writes or hashes a report goes here.
///
/// Two spellings of "canonical" used to exist: the file on disk ended in a
/// newline and the hash was taken over the same text without it. The byte string
/// the signature covered therefore appeared nowhere, and an independent verifier
/// written the obvious way, read the report, drop the envelope, hash what is
/// left, computed a different digest and failed a valid signature.
fn canonical_text(value: &serde_json::Value) -> Result<String, serde_json::Error> {
    // serde_json's Map is a BTreeMap unless the preserve_order feature is on, so
    // going through Value is what applies the ordering. Serializing the struct
    // directly would emit fields in declaration order instead.
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    Ok(text)
}

/// blake3 over the canonical body, with the envelope excluded.
pub fn body_hash<T: Serialize>(report: &T) -> Result<String, serde_json::Error> {
    let mut as_value = serde_json::to_value(report)?;
    // A value that is not an object carries no envelope, so there is nothing to
    // remove and hashing it whole is the same operation. Reports are objects; the
    // branch exists because the function is generic, not because a report might
    // arrive in some other shape.
    if let Some(object) = as_value.as_object_mut() {
        object.remove("envelope");
    }
    Ok(short_hash_full(&canonical_text(&as_value)?))
}

/// Full 64 character hash, as the signature envelope requires.
fn short_hash_full(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex().to_string()
}

/// Domain separated identity helper, re-exported so callers do not reach past
/// this module for hashing.
pub fn identity(domain_tag: &str, fields: &[&str]) -> String {
    short_hash(domain_tag, fields)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_come_out_sorted_whatever_order_they_went_in() {
        let value = json!({ "zebra": 1, "alpha": 2, "middle": 3 });
        let text = to_canonical_json(&value).unwrap();
        let alpha = text.find("alpha").unwrap();
        let middle = text.find("middle").unwrap();
        let zebra = text.find("zebra").unwrap();
        assert!(alpha < middle && middle < zebra);
    }

    #[test]
    fn output_ends_with_exactly_one_newline() {
        let text = to_canonical_json(&json!({ "a": 1 })).unwrap();
        assert!(text.ends_with("}\n"));
        assert!(!text.ends_with("\n\n"));
    }

    #[test]
    fn indentation_is_two_spaces() {
        let text = to_canonical_json(&json!({ "a": 1 })).unwrap();
        assert!(text.contains("\n  \"a\""), "{text}");
    }

    #[test]
    fn the_body_hash_ignores_the_envelope() {
        // The property the whole reproducibility claim rests on: the same scan at
        // a different time hashes the same.
        let morning = json!({
            "envelope": { "generated_at": "2026-08-04T09:00:00Z", "host": "runner-1" },
            "findings": []
        });
        let evening = json!({
            "envelope": { "generated_at": "2026-08-04T21:30:00Z", "host": "runner-9" },
            "findings": []
        });
        assert_eq!(body_hash(&morning).unwrap(), body_hash(&evening).unwrap());
    }

    #[test]
    fn the_body_hash_notices_a_real_change() {
        let before = json!({ "envelope": {}, "findings": [] });
        let after = json!({ "envelope": {}, "findings": ["fnd_0000000000000001"] });
        assert_ne!(body_hash(&before).unwrap(), body_hash(&after).unwrap());
    }

    #[test]
    fn an_outside_verifier_reaches_the_same_hash_from_the_written_document() {
        // Written the way an independent implementation would: read the report as
        // it was serialized, drop the envelope, canonicalize the rest the same
        // way and hash it. The two paths used to differ by the trailing newline,
        // so the bytes the signature covered existed in no file anywhere.
        let report = json!({
            "envelope": { "generated_at": "2026-08-04T09:00:00Z" },
            "findings": ["fnd_0000000000000001"],
            "verdict": "PASS"
        });

        let document = to_canonical_json(&report).unwrap();
        let mut parsed: serde_json::Value = serde_json::from_str(&document).unwrap();
        parsed.as_object_mut().unwrap().remove("envelope");
        let recomputed = to_canonical_json(&parsed).unwrap();

        assert_eq!(
            body_hash(&report).unwrap(),
            blake3::hash(recomputed.as_bytes()).to_hex().to_string()
        );
    }

    #[test]
    fn the_hash_is_the_full_width_the_envelope_schema_requires() {
        let hash = body_hash(&json!({ "envelope": {} })).unwrap();
        assert_eq!(hash.len(), 64);
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
