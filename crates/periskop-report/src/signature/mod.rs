//! Detached Ed25519 signatures over scan reports.
//!
//! What a signature here proves, stated once so that no caller has to infer it:
//! **the holder of a named private key signed a report body that hashes to a
//! named value, and the document in front of you hashes to that same value.**
//!
//! What it does not prove is the longer and more important list. It does not say
//! the scan was complete, that the scanner understood the code it read, that the
//! findings are right, or that nothing was left out. A report can be thoroughly
//! wrong and perfectly signed. The signature answers "did this come from that
//! key, unaltered", and answers nothing else; the report's own coverage statement
//! is where the reader looks for how much of the tree was actually read. ADR-015
//! records this distinction, because a signature described any more loosely turns
//! into a badge, and a badge is what this product exists to argue against.
//!
//! The layout follows the shape of the contract rather than the shape of the
//! code: [`document`] decides which bytes are covered, [`key`] holds the key
//! material, [`envelope`] is the record on disk, and [`sign`] and [`verify`] are
//! the two directions.

pub mod base64url;
pub mod document;
pub mod envelope;
pub mod error;
pub mod key;
pub mod sign;
pub mod verify;

pub use document::{SignedDocument, DOMAIN_TAG};
pub use envelope::{Algorithm, SignatureEnvelope, ENVELOPE_SCHEMA_VERSION};
pub use error::SignatureError;
pub use key::{SigningKey, VerifyingKey, PUBLIC_KEY_TAG, SECRET_KEY_TAG};
pub use sign::sign;
pub use verify::{verify, KeyRing, Verified};
