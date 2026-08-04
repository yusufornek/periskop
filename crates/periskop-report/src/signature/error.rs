//! Why a signature could not be produced, or could not be trusted.
//!
//! Every variant here is a refusal. There is deliberately no variant that means
//! "probably fine": `signature-envelope.md` says a report whose verification
//! fails is handled as an unsigned report, never as a partly accepted one, so
//! the type has no way to express a partial result and no caller can invent one.
//!
//! No variant carries private key material, and none carries the text of a key
//! file. A key that leaks through an error message is as leaked as one printed
//! on purpose, and error messages travel further: they end up in build logs.

use thiserror::Error;

use super::base64url::Base64Error;

pub type Result<T> = std::result::Result<T, SignatureError>;

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("the report document is not valid UTF-8")]
    DocumentNotUtf8,

    #[error("the report document is not valid JSON: {0}")]
    DocumentNotJson(String),

    #[error(
        "the report document is not in canonical form, so the bytes on disk are not the bytes a signature can speak for"
    )]
    DocumentNotCanonical,

    #[error("the report document is not a JSON object")]
    DocumentNotAnObject,

    #[error("the report document carries no `report_id`")]
    DocumentWithoutReportId,

    #[error("the report document carries a malformed `report_id`")]
    DocumentReportIdMalformed,

    #[error("the signature envelope is not valid UTF-8")]
    EnvelopeNotUtf8,

    #[error("the signature envelope does not match the contract: {0}")]
    EnvelopeMalformed(String),

    #[error("the signature envelope field `{field}` does not match the contract: {reason}")]
    EnvelopeField {
        field: &'static str,
        reason: &'static str,
    },

    #[error(
        "the signature envelope declares schema version `{0}`, which this build does not verify"
    )]
    EnvelopeSchemaVersion(String),

    #[error("the signature envelope names report `{envelope}`, the document is `{document}`")]
    ReportMismatch { envelope: String, document: String },

    #[error("the report body hashes to `{document}`, the signature envelope claims `{envelope}`")]
    BodyHashMismatch { envelope: String, document: String },

    #[error("no trusted public key carries the key id `{0}`")]
    UnknownKey(String),

    #[error("the signature value is not unpadded base64url: {0}")]
    SignatureValueEncoding(Base64Error),

    #[error("the signature value decodes to {0} bytes, an ed25519 signature is 64")]
    SignatureValueLength(usize),

    #[error("the ed25519 signature does not verify under the named key")]
    SignatureDoesNotVerify,

    #[error("the ed25519 signing operation failed")]
    SigningFailed,

    #[error("the key file does not open with the tag `{expected}`")]
    KeyFileTag { expected: &'static str },

    #[error("the key file body is not unpadded base64url: {0}")]
    KeyFileEncoding(Base64Error),

    #[error("the key file body decodes to {0} bytes, an ed25519 key is 32")]
    KeyFileLength(usize),

    #[error("the public key file does not hold a point on the ed25519 curve")]
    KeyNotOnCurve,

    #[error("the operating system refused to supply entropy, so no key was generated")]
    EntropyUnavailable,

    #[error("could not serialize: {0}")]
    Serialization(#[from] serde_json::Error),
}
