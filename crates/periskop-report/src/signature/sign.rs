//! Producing a detached signature over a report as it was written.

use super::base64url;
use super::document::SignedDocument;
use super::envelope::{Algorithm, SignatureEnvelope, ENVELOPE_SCHEMA_VERSION};
use super::error::Result;
use super::key::SigningKey;

/// Signs a report document.
///
/// The input is the bytes of the report, not a report structure. A caller that
/// holds a `ScanReport` serializes it first and signs the same text it writes to
/// disk; what gets signed and what gets read are then the same object by
/// construction rather than by care.
///
/// `signed_at` is passed in rather than read from a clock here. Left to a clock,
/// two signings of one report would produce two different envelopes and the
/// natural way to compare them, byte equality, would stop working. A caller that
/// wants the timestamp states it.
pub fn sign(
    document: &[u8],
    signing_key: &SigningKey,
    signed_at: Option<String>,
) -> Result<SignatureEnvelope> {
    let derived = SignedDocument::from_bytes(document)?;
    let signature = signing_key.sign(&derived.signing_input())?;

    Ok(SignatureEnvelope {
        schema_version: ENVELOPE_SCHEMA_VERSION.to_owned(),
        report_id: derived.report_id().to_owned(),
        body_hash: derived.body_hash().to_owned(),
        algorithm: Algorithm::Ed25519,
        key_id: signing_key.key_id().to_owned(),
        value: base64url::encode(&signature),
        signed_at,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::signature::key::SIGNATURE_BYTES;
    use crate::signature::verify::{verify, KeyRing};

    fn document() -> String {
        crate::serialize::to_canonical_json(&serde_json::json!({
            "report_id": "rpt_0123456789abcdef",
            "envelope": { "generated_at": "2026-08-04T09:00:00Z" },
            "verdict": "PASS"
        }))
        .unwrap()
    }

    fn key() -> SigningKey {
        SigningKey::from_key_file(&SigningKey::generate().unwrap().to_key_file()).unwrap()
    }

    #[test]
    fn the_envelope_names_the_report_and_the_key_it_came_from() {
        let key = key();
        let envelope = sign(document().as_bytes(), &key, None).unwrap();

        assert_eq!(envelope.report_id, "rpt_0123456789abcdef");
        assert_eq!(envelope.key_id, key.key_id());
        assert_eq!(envelope.algorithm, Algorithm::Ed25519);
        assert_eq!(envelope.schema_version, ENVELOPE_SCHEMA_VERSION);
        assert_eq!(
            base64url::decode(&envelope.value).unwrap().len(),
            SIGNATURE_BYTES
        );
    }

    #[test]
    fn the_same_report_and_key_produce_the_same_envelope_bytes() {
        // Ed25519 is deterministic and no clock is read, so a signed report is
        // as diffable as an unsigned one.
        let key = key();
        let first = sign(document().as_bytes(), &key, None).unwrap();
        let second = sign(document().as_bytes(), &key, None).unwrap();
        assert_eq!(
            first.to_canonical_json().unwrap(),
            second.to_canonical_json().unwrap()
        );
    }

    #[test]
    fn a_signature_made_here_verifies_there() {
        let key = key();
        let envelope = sign(document().as_bytes(), &key, None).unwrap();
        let ring = KeyRing::new(vec![key.verifying_key()]);

        let verified = verify(
            document().as_bytes(),
            envelope.to_canonical_json().unwrap().as_bytes(),
            &ring,
        )
        .unwrap();
        assert_eq!(verified.key_id, key.key_id());
    }

    #[test]
    fn a_timestamp_is_recorded_only_when_one_is_supplied() {
        let key = key();
        let stamped = sign(
            document().as_bytes(),
            &key,
            Some("2026-08-04T09:00:00Z".to_owned()),
        )
        .unwrap();
        let bare = sign(document().as_bytes(), &key, None).unwrap();

        assert_eq!(stamped.signed_at.as_deref(), Some("2026-08-04T09:00:00Z"));
        assert_eq!(bare.signed_at, None);
        // The stamp sits outside the signed bytes, so it does not change the
        // signature. That is what lets one report carry two envelopes.
        assert_eq!(stamped.value, bare.value);
    }

    #[test]
    fn a_document_that_is_not_canonical_is_not_signed() {
        // Signing it would produce an envelope for a byte string that exists
        // nowhere, and the reader's file would fail verification with no visible
        // cause.
        let compact = r#"{"envelope":{},"report_id":"rpt_0123456789abcdef"}"#;
        assert!(sign(compact.as_bytes(), &key(), None).is_err());
    }
}
