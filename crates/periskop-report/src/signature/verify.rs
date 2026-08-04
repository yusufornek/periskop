//! Checking a detached signature, in the order `signature-envelope.md` fixes.
//!
//! Every path out of this module that is not `Ok` is a refusal, and the type
//! system is what keeps it that way: there is no "verified with warnings". A
//! report whose envelope is missing, malformed, hashed against a different body,
//! signed by a key nobody named, or signed badly, all leave by the same door.
//!
//! The order is not an implementation detail. The body hash is checked before the
//! signature, so a document that does not match its envelope is refused without
//! the signature being consulted at all, and an unknown key is refused before any
//! cryptography runs. A verifier that checked the signature first and the binding
//! afterwards could be talked into reporting "the signature is valid" about a
//! document the signature was never taken over.

use super::base64url;
use super::document::SignedDocument;
use super::envelope::SignatureEnvelope;
use super::error::{Result, SignatureError};
use super::key::{VerifyingKey, SIGNATURE_BYTES};

/// The keys a verification is willing to trust.
///
/// Trust is the caller's decision and it has to be stated. There is no ambient
/// key store and no default key: an empty ring verifies nothing, which is the
/// honest answer to "verify this" when nobody has said whose signature counts.
#[derive(Debug, Clone, Default)]
pub struct KeyRing {
    keys: Vec<VerifyingKey>,
}

impl KeyRing {
    pub fn new(keys: Vec<VerifyingKey>) -> Self {
        Self { keys }
    }

    /// Resolves a key id.
    ///
    /// The id is derived from the public key rather than typed beside it, so a
    /// name in an envelope cannot be pointed at a key that does not match it. The
    /// worst a colliding id could do is resolve the wrong key, and the signature
    /// check that follows would then refuse: the failure direction is closed.
    fn find(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.iter().find(|key| key.key_id() == key_id)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// What a successful verification establishes, and nothing more.
///
/// Read the field names literally. This says a holder of the private key behind
/// `key_id` signed a body that hashes to `body_hash`, and that the document
/// handed in hashes to the same value. It says nothing about whether the scan
/// that produced the report was complete, honest or correct; those are claims the
/// report makes about itself, and a signature cannot promote a claim into a fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub report_id: String,
    pub body_hash: String,
    pub key_id: String,
}

/// Verifies a detached signature over a report document.
pub fn verify(document: &[u8], envelope: &[u8], keys: &KeyRing) -> Result<Verified> {
    let envelope = SignatureEnvelope::parse(envelope)?;
    let derived = SignedDocument::from_bytes(document)?;

    // Step one and a half. The contract binds an envelope to a report by
    // `report_id` as well as by `body_hash`; checking only the hash would let an
    // envelope for one report be filed beside another whose body happened to
    // match, and the pairing on disk would be a lie the verifier agreed with.
    if envelope.report_id != derived.report_id() {
        return Err(SignatureError::ReportMismatch {
            envelope: envelope.report_id,
            document: derived.report_id().to_owned(),
        });
    }

    // Step two. Hash first, signature never.
    if envelope.body_hash != derived.body_hash() {
        return Err(SignatureError::BodyHashMismatch {
            envelope: envelope.body_hash,
            document: derived.body_hash().to_owned(),
        });
    }

    // Step three. An unknown key is not a weaker kind of trusted.
    let key = keys
        .find(&envelope.key_id)
        .ok_or_else(|| SignatureError::UnknownKey(envelope.key_id.clone()))?;

    // Step four.
    let decoded =
        base64url::decode(&envelope.value).map_err(SignatureError::SignatureValueEncoding)?;
    let signature: [u8; SIGNATURE_BYTES] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| SignatureError::SignatureValueLength(decoded.len()))?;
    key.verify(&derived.signing_input(), &signature)?;

    Ok(Verified {
        report_id: derived.report_id().to_owned(),
        body_hash: derived.body_hash().to_owned(),
        key_id: key.key_id().to_owned(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::signature::key::SigningKey;
    use crate::signature::sign::sign;

    fn document(verdict: &str) -> String {
        crate::serialize::to_canonical_json(&serde_json::json!({
            "report_id": "rpt_0123456789abcdef",
            "envelope": { "generated_at": "2026-08-04T09:00:00Z" },
            "verdict": verdict
        }))
        .unwrap()
    }

    fn key(seed: u8) -> SigningKey {
        let file = format!(
            "{} {}",
            crate::signature::key::SECRET_KEY_TAG,
            base64url::encode(&[seed; 32])
        );
        SigningKey::from_key_file(&file).unwrap()
    }

    fn envelope_bytes(document: &str, signing_key: &SigningKey) -> String {
        sign(document.as_bytes(), signing_key, None)
            .unwrap()
            .to_canonical_json()
            .unwrap()
    }

    fn ring(signing_key: &SigningKey) -> KeyRing {
        KeyRing::new(vec![signing_key.verifying_key()])
    }

    #[test]
    fn a_signature_over_the_written_bytes_verifies() {
        let key = key(1);
        let document = document("PASS");
        let verified = verify(
            document.as_bytes(),
            envelope_bytes(&document, &key).as_bytes(),
            &ring(&key),
        )
        .unwrap();

        assert_eq!(verified.report_id, "rpt_0123456789abcdef");
        assert_eq!(verified.key_id, key.key_id());
    }

    #[test]
    fn one_changed_byte_in_the_body_fails_verification() {
        // The property the whole feature rests on. `PASS` and `FAIL` are the same
        // length, so the document stays canonical and nothing but the content has
        // moved.
        let key = key(1);
        let signed = document("PASS");
        let envelope = envelope_bytes(&signed, &key);
        let tampered = document("FAIL");

        assert_eq!(signed.len(), tampered.len());
        assert!(matches!(
            verify(tampered.as_bytes(), envelope.as_bytes(), &ring(&key)),
            Err(SignatureError::BodyHashMismatch { .. })
        ));
    }

    #[test]
    fn a_reindented_document_fails_verification() {
        // Re-serializing the parsed report would have accepted this, because the
        // structure survives. The reader's file did not.
        let key = key(1);
        let signed = document("PASS");
        let envelope = envelope_bytes(&signed, &key);
        let compact =
            serde_json::to_string(&serde_json::from_str::<serde_json::Value>(&signed).unwrap())
                .unwrap();

        assert!(matches!(
            verify(compact.as_bytes(), envelope.as_bytes(), &ring(&key)),
            Err(SignatureError::DocumentNotCanonical)
        ));
    }

    #[test]
    fn a_signature_from_another_key_is_refused() {
        let signer = key(1);
        let stranger = key(2);
        let document = document("PASS");
        // The envelope names the signer, so the stranger's ring does not even
        // resolve the id: an unknown key is refused before any curve arithmetic.
        assert!(matches!(
            verify(
                document.as_bytes(),
                envelope_bytes(&document, &signer).as_bytes(),
                &ring(&stranger)
            ),
            Err(SignatureError::UnknownKey(_))
        ));
    }

    #[test]
    fn a_signature_relabelled_with_a_trusted_key_id_is_refused() {
        // The attack the previous test does not cover: the envelope is edited to
        // name a key the verifier trusts, so the lookup succeeds and only the
        // cryptography can say no.
        let signer = key(1);
        let trusted = key(2);
        let document = document("PASS");
        let mut envelope = sign(document.as_bytes(), &signer, None).unwrap();
        envelope.key_id = trusted.key_id().to_owned();

        assert!(matches!(
            verify(
                document.as_bytes(),
                envelope.to_canonical_json().unwrap().as_bytes(),
                &ring(&trusted)
            ),
            Err(SignatureError::SignatureDoesNotVerify)
        ));
    }

    #[test]
    fn an_envelope_for_a_different_report_is_refused() {
        let key = key(1);
        let document = document("PASS");
        let mut envelope = sign(document.as_bytes(), &key, None).unwrap();
        envelope.report_id = "rpt_fedcba9876543210".to_owned();

        assert!(matches!(
            verify(
                document.as_bytes(),
                envelope.to_canonical_json().unwrap().as_bytes(),
                &ring(&key)
            ),
            Err(SignatureError::ReportMismatch { .. })
        ));
    }

    #[test]
    fn a_body_hash_that_does_not_match_stops_before_the_signature() {
        let key = key(1);
        let document = document("PASS");
        let mut envelope = sign(document.as_bytes(), &key, None).unwrap();
        envelope.body_hash = "b".repeat(64);

        // Not `SignatureDoesNotVerify`: the run must stop at the binding, so the
        // reason a reader is given is the true one.
        assert!(matches!(
            verify(
                document.as_bytes(),
                envelope.to_canonical_json().unwrap().as_bytes(),
                &ring(&key)
            ),
            Err(SignatureError::BodyHashMismatch { .. })
        ));
    }

    #[test]
    fn a_flipped_bit_in_the_signature_value_is_refused() {
        let key = key(1);
        let document = document("PASS");
        let mut envelope = sign(document.as_bytes(), &key, None).unwrap();
        let flipped = if envelope.value.starts_with('A') {
            'B'
        } else {
            'A'
        };
        envelope.value = format!("{flipped}{}", envelope.value.get(1..).unwrap());

        assert!(matches!(
            verify(
                document.as_bytes(),
                envelope.to_canonical_json().unwrap().as_bytes(),
                &ring(&key)
            ),
            Err(SignatureError::SignatureDoesNotVerify)
        ));
    }

    #[test]
    fn a_truncated_signature_value_is_refused() {
        let key = key(1);
        let document = document("PASS");
        let mut envelope = sign(document.as_bytes(), &key, None).unwrap();
        envelope.value = "AAAA".to_owned();

        assert!(matches!(
            verify(
                document.as_bytes(),
                envelope.to_canonical_json().unwrap().as_bytes(),
                &ring(&key)
            ),
            Err(SignatureError::SignatureValueLength(3))
        ));
    }

    #[test]
    fn an_empty_key_ring_verifies_nothing() {
        let key = key(1);
        let document = document("PASS");
        let ring = KeyRing::default();
        assert!(ring.is_empty());
        assert!(matches!(
            verify(
                document.as_bytes(),
                envelope_bytes(&document, &key).as_bytes(),
                &ring
            ),
            Err(SignatureError::UnknownKey(_))
        ));
    }

    #[test]
    fn a_ring_holding_several_keys_picks_the_one_that_signed() {
        // Key rotation: the old and the new public key sit side by side and a
        // report signed under either still verifies, without the report being
        // reproduced. That is the reason the envelope is detached at all.
        let old = key(1);
        let new = key(2);
        let ring = KeyRing::new(vec![
            old.verifying_key(),
            new.verifying_key(),
            // The same key listed twice is not a problem, because the id is
            // derived from the key rather than typed beside it.
            new.verifying_key(),
        ]);
        let document = document("PASS");

        for signer in [&old, &new] {
            let verified = verify(
                document.as_bytes(),
                envelope_bytes(&document, signer).as_bytes(),
                &ring,
            )
            .unwrap();
            assert_eq!(verified.key_id, signer.key_id());
        }
    }

    #[test]
    fn a_malformed_envelope_is_refused() {
        let key = key(1);
        let document = document("PASS");
        assert!(matches!(
            verify(document.as_bytes(), b"not json", &ring(&key)),
            Err(SignatureError::EnvelopeMalformed(_))
        ));
    }
}
