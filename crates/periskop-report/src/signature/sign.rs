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

    let envelope = SignatureEnvelope {
        schema_version: ENVELOPE_SCHEMA_VERSION.to_owned(),
        report_id: derived.report_id().to_owned(),
        body_hash: derived.body_hash().to_owned(),
        algorithm: Algorithm::Ed25519,
        key_id: signing_key.key_id().to_owned(),
        value: base64url::encode(&signature),
        signed_at,
    };

    // The writing side is held to what the reading side accepts, by walking the
    // reader's own path over the bytes this would produce. Every other field
    // comes from a source that has already been checked; `signed_at` arrives
    // from a caller and is the one piece of an envelope a command line hands
    // over as free text. Without this, `--signed-at "yesterday, probably"`
    // exited zero and wrote a file `verify` refuses, so the mistake made at
    // signing time was delivered to the reader of the report as a signature that
    // does not hold, which reads as tampering.
    SignatureEnvelope::parse(envelope.to_canonical_json()?.as_bytes())?;

    Ok(envelope)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::signature::error::SignatureError;
    use crate::signature::key::SIGNATURE_BYTES;
    use crate::signature::verify::{verify, KeyRing};

    /// A private key this test owns, written out rather than generated.
    ///
    /// Pinning the file text rather than a seed pins the key file format as
    /// well, and a key file this build can no longer read is an archived key
    /// nothing can be loaded from.
    const FIXED_KEY_FILE: &str =
        "periskop-ed25519-secret-key-v1 BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\n";

    /// The document the vector below is taken over, spelled out as bytes rather
    /// than built from a structure, because bytes are what a signature speaks
    /// for and a builder would follow the code it is meant to hold still.
    const FIXED_REPORT: &str = "{\n  \"envelope\": {\n    \"generated_at\": \"2026-08-04T09:00:00Z\"\n  },\n  \"findings\": [],\n  \"report_id\": \"rpt_0123456789abcdef\",\n  \"verdict\": \"PASS\"\n}\n";

    /// The envelope this build produces for [`FIXED_REPORT`] under
    /// [`FIXED_KEY_FILE`], produced once by running this code and then frozen.
    ///
    /// The only assertion in the signing path that compares against something
    /// other than the code that produced it, which is the whole point of it.
    /// `DOMAIN_TAG`, the order of the bytes in `signing_input`, the two space
    /// indent in `serialize.rs`, the exclusion of the `envelope` block from the
    /// body hash and the derivation of `key_id` all decide this string. Change
    /// any one of them and every envelope ever archived stops verifying, while a
    /// suite that only checks the code against itself stays green throughout.
    ///
    /// So a failure here is not a constant to refresh. It says the signature
    /// format moved, which `signature-envelope.md` calls a MAJOR change.
    const GOLDEN_ENVELOPE: &str = "{\n  \"algorithm\": \"ed25519\",\n  \"body_hash\": \"11ad12e486860220eb526722a3d3419d292e0c727c5f218dbcd9895ab0b6d3d5\",\n  \"key_id\": \"key_0824fd9b7f690d5c\",\n  \"report_id\": \"rpt_0123456789abcdef\",\n  \"schema_version\": \"1.0\",\n  \"value\": \"gSAdtomchG1EweL_mrHQMPXM4swLRvWMGYJZ5tdFca6qlqUqQ4UvMPsmK9R5T-W7XSPa6Tg45zlSl7xLfbVsCw\"\n}\n";

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
    fn a_fixed_key_over_a_fixed_report_produces_the_envelope_it_always_has() {
        let key = SigningKey::from_key_file(FIXED_KEY_FILE).unwrap();
        let envelope = sign(FIXED_REPORT.as_bytes(), &key, None).unwrap();
        assert_eq!(envelope.to_canonical_json().unwrap(), GOLDEN_ENVELOPE);
    }

    #[test]
    fn a_timestamp_the_reader_would_refuse_is_not_signed() {
        // The failure this closes: the writing side took any text at all here
        // and produced a file its own verifier rejects, exiting zero. The
        // mistake was made at signing time and delivered to the reader of the
        // report as a signature that does not hold, which reads as tampering.
        for bad in [
            "yesterday, probably",
            "",
            "2026-08-04",
            "2026-08-04 09:00:00Z",
            "2026-08-04T09:00:00",
        ] {
            assert!(
                matches!(
                    sign(document().as_bytes(), &key(), Some(bad.to_owned())),
                    Err(SignatureError::EnvelopeField {
                        field: "signed_at",
                        ..
                    })
                ),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn every_envelope_this_signs_is_one_the_verifier_reads_back() {
        // Stated over the whole envelope rather than over the one field that
        // was wrong, so a second field that stops satisfying the schema is
        // caught by the same rule instead of needing its own test.
        let key = key();
        for stamp in [None, Some("2026-08-04T09:00:00+03:00".to_owned())] {
            let envelope = sign(document().as_bytes(), &key, stamp).unwrap();
            let text = envelope.to_canonical_json().unwrap();
            assert_eq!(SignatureEnvelope::parse(text.as_bytes()).unwrap(), envelope);
        }
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
