//! Ed25519 key material, and the smallest file format that can carry it.
//!
//! Three rules shape this module and each one is enforced rather than described.
//!
//! The private half never reaches a log, an error message or a report. The
//! `Debug` implementation below is written by hand and prints a placeholder;
//! there is no `Display`, no `Serialize` and no accessor that hands out the
//! bytes. A derived `Debug` would have put the key into the first `{:?}` anyone
//! reached for during a bad afternoon, and from there into a build log.
//!
//! Generating a key writes nothing. [`SigningKey::generate`] returns a value and
//! [`SigningKey::to_key_file`] returns text; choosing a path is the caller's job
//! and the caller is the command line, where the user names it. A tool that
//! quietly drops a private key into a default location leaves key material in a
//! place its owner did not choose and may never look at.
//!
//! A key file says which half it holds. The two tags differ, so handing a public
//! key where a private one belongs fails at the door instead of producing a
//! signature nobody can verify.

use std::fmt;

use ed25519_dalek::Signer as _;
use zeroize::Zeroizing;

use super::base64url;
use super::error::{Result, SignatureError};

/// First word of a private key file.
pub const SECRET_KEY_TAG: &str = "periskop-ed25519-secret-key-v1";
/// First word of a public key file.
pub const PUBLIC_KEY_TAG: &str = "periskop-ed25519-public-key-v1";

/// Length of an ed25519 key, both halves.
const KEY_BYTES: usize = 32;
/// Length of an ed25519 signature.
pub(super) const SIGNATURE_BYTES: usize = 64;

/// The private half. Signs, and gives up nothing else.
pub struct SigningKey {
    inner: ed25519_dalek::SigningKey,
    key_id: String,
}

/// Redacted by hand, and tested for.
///
/// The upstream type already hides its secret half, but relying on that would
/// make this repository's guarantee a property of somebody else's release notes.
impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("key_id", &self.key_id)
            .field("material", &"<redacted>")
            .finish()
    }
}

impl SigningKey {
    /// Draws a new key from the operating system's entropy source.
    ///
    /// Nothing is written anywhere. The seed lives in a buffer that clears itself
    /// on the way out, and the returned value clears its own copy on drop.
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; KEY_BYTES]);
        getrandom::fill(seed.as_mut_slice()).map_err(|_| SignatureError::EntropyUnavailable)?;
        Ok(Self::from_seed(&seed))
    }

    fn from_seed(seed: &[u8; KEY_BYTES]) -> Self {
        let inner = ed25519_dalek::SigningKey::from_bytes(seed);
        let key_id = derive_key_id(inner.verifying_key().as_bytes());
        Self { inner, key_id }
    }

    /// Reads a private key file.
    ///
    /// The text is consumed and nothing derived from it enters an error, so a
    /// malformed key file cannot print a key that was almost right.
    pub fn from_key_file(text: &str) -> Result<Self> {
        let body = key_file_body(text, SECRET_KEY_TAG)?;
        Ok(Self::from_seed(&body))
    }

    /// Renders the private key file, for a caller that has been told where to put
    /// it. The buffer clears itself once the caller drops it.
    pub fn to_key_file(&self) -> Zeroizing<String> {
        Zeroizing::new(render_key_file(
            SECRET_KEY_TAG,
            self.inner.as_bytes().as_slice(),
        ))
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            inner: self.inner.verifying_key(),
            key_id: self.key_id.clone(),
        }
    }

    /// Signs a message. Ed25519 is deterministic (RFC 8032 §5.1.6): the same key
    /// over the same bytes produces the same signature, on every machine and
    /// every run, which is what keeps a signed report diffable.
    pub(super) fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_BYTES]> {
        self.inner
            .try_sign(message)
            .map(|signature| signature.to_bytes())
            // Ed25519 signing has no failure mode that depends on the message,
            // but the fallible form is used anyway: the infallible one panics
            // internally, and a panic in a signing tool is an outage with no
            // diagnosis. The error says signing rather than verification: a
            // signer that reports somebody else's failure sends the reader to
            // the wrong file.
            .map_err(|_| SignatureError::SigningFailed)
    }
}

/// The public half. Names itself with the same key id the private half derives.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    inner: ed25519_dalek::VerifyingKey,
    key_id: String,
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl VerifyingKey {
    pub fn from_key_file(text: &str) -> Result<Self> {
        let body = key_file_body(text, PUBLIC_KEY_TAG)?;
        let inner = ed25519_dalek::VerifyingKey::from_bytes(&body)
            .map_err(|_| SignatureError::KeyNotOnCurve)?;
        let key_id = derive_key_id(inner.as_bytes());
        Ok(Self { inner, key_id })
    }

    pub fn to_key_file(&self) -> String {
        render_key_file(PUBLIC_KEY_TAG, self.inner.as_bytes().as_slice())
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Checks a signature under the strict rules.
    ///
    /// `verify_strict` rather than `verify`: it rejects small order public keys
    /// and non canonical encodings, which are the shapes that let one signature
    /// verify under more than one key. Nothing in this product needs the
    /// permissive reading, and a verifier that accepts more than it must is the
    /// thing this whole task exists to avoid.
    pub(super) fn verify(&self, message: &[u8], signature: &[u8; SIGNATURE_BYTES]) -> Result<()> {
        let signature = ed25519_dalek::Signature::from_bytes(signature);
        self.inner
            .verify_strict(message, &signature)
            .map_err(|_| SignatureError::SignatureDoesNotVerify)
    }
}

/// The key id both halves agree on.
///
/// Derived from the public key so that the envelope's `key_id` can be checked
/// against a key file rather than trusted as a label somebody typed. A key id
/// that is only a name is a key id that can be pointed at the wrong key.
fn derive_key_id(public: &[u8; KEY_BYTES]) -> String {
    format!(
        "key_{}",
        periskop_core::ids::short_hash("pk/v1", &[&base64url::encode(public)])
    )
}

fn render_key_file(tag: &str, key: &[u8]) -> String {
    format!("{tag} {}\n", base64url::encode(key))
}

/// Pulls the key bytes out of a key file, insisting on the right tag.
fn key_file_body(text: &str, expected_tag: &str) -> Result<[u8; KEY_BYTES]> {
    let (tag, body) = text
        .trim()
        .split_once(' ')
        .ok_or(SignatureError::KeyFileTag {
            expected: tag_name(expected_tag),
        })?;
    if tag != expected_tag {
        return Err(SignatureError::KeyFileTag {
            expected: tag_name(expected_tag),
        });
    }

    let decoded =
        Zeroizing::new(base64url::decode(body.trim()).map_err(SignatureError::KeyFileEncoding)?);
    let mut key = [0u8; KEY_BYTES];
    if decoded.len() != KEY_BYTES {
        return Err(SignatureError::KeyFileLength(decoded.len()));
    }
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// The tag as a `'static` string, so the error type never has to own text that
/// came out of a key file.
fn tag_name(tag: &str) -> &'static str {
    if tag == SECRET_KEY_TAG {
        SECRET_KEY_TAG
    } else {
        PUBLIC_KEY_TAG
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fixed_key() -> SigningKey {
        SigningKey::from_seed(&[7u8; KEY_BYTES])
    }

    #[test]
    fn the_private_key_is_absent_from_its_debug_rendering() {
        let key = fixed_key();
        let rendered = format!("{key:?}");
        let secret = base64url::encode(&[7u8; KEY_BYTES]);

        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains(&secret), "{rendered}");
        // The raw bytes in any obvious spelling, not only the base64url one.
        assert!(!rendered.contains("07070707"), "{rendered}");
        assert!(!rendered.contains(SECRET_KEY_TAG), "{rendered}");
    }

    #[test]
    fn the_private_key_is_absent_from_a_key_file_parse_error() {
        // A key file that is nearly right is the case where an implementation
        // is tempted to echo the input back "so the user can see the typo".
        let almost = format!("{PUBLIC_KEY_TAG} {}", base64url::encode(&[9u8; 32]));
        let error = SigningKey::from_key_file(&almost).unwrap_err();
        let rendered = format!("{error} {error:?}");
        assert!(
            !rendered.contains(&base64url::encode(&[9u8; 32])),
            "{rendered}"
        );
    }

    #[test]
    fn a_key_file_round_trips() {
        let key = fixed_key();
        let restored = SigningKey::from_key_file(&key.to_key_file()).unwrap();
        assert_eq!(restored.key_id(), key.key_id());
        assert_eq!(
            restored.verifying_key().to_key_file(),
            key.verifying_key().to_key_file()
        );
    }

    #[test]
    fn a_public_key_file_is_refused_where_a_private_one_belongs() {
        let public = fixed_key().verifying_key().to_key_file();
        assert!(matches!(
            SigningKey::from_key_file(&public),
            Err(SignatureError::KeyFileTag { .. })
        ));
    }

    #[test]
    fn a_private_key_file_is_refused_where_a_public_one_belongs() {
        let secret = fixed_key().to_key_file();
        assert!(matches!(
            VerifyingKey::from_key_file(&secret),
            Err(SignatureError::KeyFileTag { .. })
        ));
    }

    #[test]
    fn a_truncated_key_file_is_refused() {
        let short = format!("{SECRET_KEY_TAG} {}", base64url::encode(&[1u8; 16]));
        assert!(matches!(
            SigningKey::from_key_file(&short),
            Err(SignatureError::KeyFileLength(16))
        ));
    }

    #[test]
    fn a_key_file_with_no_tag_is_refused() {
        assert!(matches!(
            SigningKey::from_key_file("AAAAAAAA"),
            Err(SignatureError::KeyFileTag { .. })
        ));
    }

    #[test]
    fn the_key_id_is_derived_from_the_public_half() {
        // So a verifier can check the label against the key it was handed rather
        // than trusting a name that was typed.
        let key = fixed_key();
        let public = VerifyingKey::from_key_file(&key.verifying_key().to_key_file()).unwrap();
        assert_eq!(public.key_id(), key.key_id());
        assert!(key.key_id().starts_with("key_"));
    }

    #[test]
    fn two_keys_do_not_share_an_id() {
        let a = SigningKey::from_seed(&[1u8; KEY_BYTES]);
        let b = SigningKey::from_seed(&[2u8; KEY_BYTES]);
        assert_ne!(a.key_id(), b.key_id());
    }

    #[test]
    fn generation_draws_a_different_key_each_time() {
        let a = SigningKey::generate().unwrap();
        let b = SigningKey::generate().unwrap();
        assert_ne!(a.key_id(), b.key_id());
    }

    #[test]
    fn signing_is_deterministic() {
        // RFC 8032. This is what lets a signed report be byte comparable across
        // runs, so it is pinned rather than assumed.
        let key = fixed_key();
        assert_eq!(
            key.sign(b"periskop").unwrap(),
            key.sign(b"periskop").unwrap()
        );
    }

    #[test]
    fn a_signature_verifies_under_its_own_key_and_no_other() {
        let key = fixed_key();
        let other = SigningKey::from_seed(&[8u8; KEY_BYTES]);
        let signature = key.sign(b"periskop").unwrap();

        assert!(key.verifying_key().verify(b"periskop", &signature).is_ok());
        assert!(other
            .verifying_key()
            .verify(b"periskop", &signature)
            .is_err());
        assert!(key
            .verifying_key()
            .verify(b"periskop.", &signature)
            .is_err());
    }
}
