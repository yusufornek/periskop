//! The detached signature record, and the checks `signature-envelope.schema.json`
//! writes down.
//!
//! The schema is the contract; this type is its Rust spelling and nothing more.
//! Every constraint the schema states is checked here, including the ones a lax
//! reader would skip: `additionalProperties: false` becomes `deny_unknown_fields`,
//! the three patterns are checked rather than assumed, and the `algorithm` enum
//! has exactly one member so a document naming a second algorithm is refused
//! instead of being verified with ed25519 anyway.
//!
//! The reason for the strictness is narrow. An envelope that fails its own schema
//! but is verified anyway means the verifier and the contract disagree about what
//! a signature is, and the reader is told "verified" by a program that stopped
//! following the document that defines the word.

use serde::{Deserialize, Serialize};

use periskop_core::ids::ReportId;

use super::error::{Result, SignatureError};

/// Schema version this build writes and verifies.
pub const ENVELOPE_SCHEMA_VERSION: &str = "1.0";

/// The signature algorithm. One member on purpose: `signature-envelope.md` calls
/// extending it a MAJOR change, because a second algorithm splits verifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    #[serde(rename = "ed25519")]
    Ed25519,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    pub schema_version: String,
    pub report_id: String,
    pub body_hash: String,
    pub algorithm: Algorithm,
    pub key_id: String,
    /// The signature, unpadded base64url.
    pub value: String,
    /// When the signature was made. Outside the hashed scope, and omitted unless
    /// a caller supplies one, so that the same report signed with the same key
    /// produces the same envelope bytes twice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
}

impl SignatureEnvelope {
    /// Reads an envelope and holds it to the schema.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).map_err(|_| SignatureError::EnvelopeNotUtf8)?;
        let envelope: Self = serde_json::from_str(text)
            .map_err(|e| SignatureError::EnvelopeMalformed(e.to_string()))?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Writes the envelope in the same canonical form the report uses, so two
    /// envelopes over one report are comparable byte for byte.
    pub fn to_canonical_json(&self) -> Result<String> {
        Ok(crate::serialize::to_canonical_json(self)?)
    }

    /// Enforces what the JSON schema states beyond the shape.
    ///
    /// `serde` gives the required fields and the closed object; the patterns and
    /// the version gate are here.
    fn validate(&self) -> Result<()> {
        let (major, minor) =
            self.schema_version
                .split_once('.')
                .ok_or(SignatureError::EnvelopeField {
                    field: "schema_version",
                    reason: "expected MAJOR.MINOR",
                })?;
        if !is_decimal(major) || !is_decimal(minor) {
            return Err(SignatureError::EnvelopeField {
                field: "schema_version",
                reason: "expected MAJOR.MINOR",
            });
        }
        // A newer MAJOR is not something to attempt and hope. ADR-006 makes MAJOR
        // the version that splits readers, so a build that does not know the
        // version refuses rather than verifying under rules it has not read.
        let known_major = ENVELOPE_SCHEMA_VERSION.split_once('.').map(|(m, _)| m);
        if Some(major) != known_major {
            return Err(SignatureError::EnvelopeSchemaVersion(
                self.schema_version.clone(),
            ));
        }

        ReportId::parse(&self.report_id).map_err(|_| SignatureError::EnvelopeField {
            field: "report_id",
            reason: "expected rpt_ followed by 16 lowercase hex characters",
        })?;

        if self.body_hash.len() != 64 || !self.body_hash.bytes().all(is_lowercase_hex) {
            return Err(SignatureError::EnvelopeField {
                field: "body_hash",
                reason: "expected 64 lowercase hex characters",
            });
        }

        if self.key_id.is_empty() {
            return Err(SignatureError::EnvelopeField {
                field: "key_id",
                reason: "must not be empty",
            });
        }

        if self.value.is_empty() {
            return Err(SignatureError::EnvelopeField {
                field: "value",
                reason: "must not be empty",
            });
        }

        if let Some(signed_at) = &self.signed_at {
            if !looks_like_rfc3339(signed_at) {
                return Err(SignatureError::EnvelopeField {
                    field: "signed_at",
                    reason: "expected an RFC 3339 date-time",
                });
            }
        }

        Ok(())
    }
}

fn is_decimal(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

fn is_lowercase_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

/// A shape check for `format: date-time`, not a calendar check.
///
/// It rejects the mistakes that actually occur, an empty string, a bare date, a
/// local time with no offset, and says so plainly rather than claiming to
/// validate the value. A verifier that parsed calendars would be inventing a
/// dependency for a field that sits outside the signed bytes.
fn looks_like_rfc3339(text: &str) -> bool {
    let bytes = text.as_bytes();
    let shaped = |index: usize, expected: u8| bytes.get(index) == Some(&expected);
    let digits = |range: std::ops::Range<usize>| {
        bytes
            .get(range)
            .is_some_and(|slice| slice.iter().all(u8::is_ascii_digit))
    };

    if !(digits(0..4) && shaped(4, b'-') && digits(5..7) && shaped(7, b'-') && digits(8..10)) {
        return false;
    }
    if !(shaped(10, b'T') && digits(11..13) && shaped(13, b':') && digits(14..16)) {
        return false;
    }
    if !(shaped(16, b':') && digits(17..19)) {
        return false;
    }

    let rest = text.get(19..).unwrap_or_default();
    let rest = rest.strip_prefix('.').map_or(rest, |fraction| {
        let taken = fraction.bytes().take_while(u8::is_ascii_digit).count();
        fraction.get(taken..).unwrap_or_default()
    });
    rest == "Z" || rest == "z" || offset_shape(rest)
}

fn offset_shape(rest: &str) -> bool {
    let Some(body) = rest.strip_prefix('+').or_else(|| rest.strip_prefix('-')) else {
        return false;
    };
    let Some((hours, minutes)) = body.split_once(':') else {
        return false;
    };
    hours.len() == 2 && minutes.len() == 2 && is_decimal(hours) && is_decimal(minutes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn valid() -> SignatureEnvelope {
        SignatureEnvelope {
            schema_version: ENVELOPE_SCHEMA_VERSION.to_owned(),
            report_id: "rpt_0123456789abcdef".to_owned(),
            body_hash: "a".repeat(64),
            algorithm: Algorithm::Ed25519,
            key_id: "key_0123456789abcdef".to_owned(),
            value: "AAAA".to_owned(),
            signed_at: None,
        }
    }

    fn round_trip(envelope: &SignatureEnvelope) -> Result<SignatureEnvelope> {
        SignatureEnvelope::parse(envelope.to_canonical_json().unwrap().as_bytes())
    }

    #[test]
    fn a_valid_envelope_round_trips_through_its_canonical_form() {
        let envelope = valid();
        assert_eq!(round_trip(&envelope).unwrap(), envelope);
    }

    #[test]
    fn the_canonical_form_sorts_its_keys_and_ends_in_one_newline() {
        let text = valid().to_canonical_json().unwrap();
        let algorithm = text.find("\"algorithm\"").unwrap();
        let value = text.find("\"value\"").unwrap();
        assert!(algorithm < value, "{text}");
        assert!(text.ends_with("}\n") && !text.ends_with("\n\n"), "{text}");
    }

    #[test]
    fn an_absent_signed_at_is_absent_from_the_document() {
        assert!(!valid().to_canonical_json().unwrap().contains("signed_at"));
    }

    #[test]
    fn an_unknown_field_is_refused() {
        // `additionalProperties: false`. An envelope carrying a field this build
        // does not understand may be carrying the field that changes its meaning.
        let text = r#"{"schema_version":"1.0","report_id":"rpt_0123456789abcdef","body_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","algorithm":"ed25519","key_id":"k","value":"AAAA","scope":"partial"}"#;
        assert!(matches!(
            SignatureEnvelope::parse(text.as_bytes()),
            Err(SignatureError::EnvelopeMalformed(_))
        ));
    }

    #[test]
    fn a_missing_required_field_is_refused() {
        let text = r#"{"schema_version":"1.0","report_id":"rpt_0123456789abcdef","algorithm":"ed25519","key_id":"k","value":"AAAA"}"#;
        assert!(matches!(
            SignatureEnvelope::parse(text.as_bytes()),
            Err(SignatureError::EnvelopeMalformed(_))
        ));
    }

    #[test]
    fn an_unknown_algorithm_is_refused() {
        let text = r#"{"schema_version":"1.0","report_id":"rpt_0123456789abcdef","body_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","algorithm":"rsa","key_id":"k","value":"AAAA"}"#;
        assert!(matches!(
            SignatureEnvelope::parse(text.as_bytes()),
            Err(SignatureError::EnvelopeMalformed(_))
        ));
    }

    #[test]
    fn a_future_major_version_is_refused_rather_than_guessed_at() {
        let envelope = SignatureEnvelope {
            schema_version: "2.0".to_owned(),
            ..valid()
        };
        assert!(matches!(
            round_trip(&envelope),
            Err(SignatureError::EnvelopeSchemaVersion(_))
        ));
    }

    #[test]
    fn a_later_minor_version_is_accepted() {
        let envelope = SignatureEnvelope {
            schema_version: "1.7".to_owned(),
            ..valid()
        };
        assert!(round_trip(&envelope).is_ok());
    }

    #[test]
    fn a_malformed_pattern_field_is_refused() {
        for (envelope, field) in [
            (
                SignatureEnvelope {
                    report_id: "rpt_NOTHEX".to_owned(),
                    ..valid()
                },
                "report_id",
            ),
            (
                SignatureEnvelope {
                    body_hash: "A".repeat(64),
                    ..valid()
                },
                "body_hash",
            ),
            (
                SignatureEnvelope {
                    body_hash: "a".repeat(63),
                    ..valid()
                },
                "body_hash",
            ),
            (
                SignatureEnvelope {
                    key_id: String::new(),
                    ..valid()
                },
                "key_id",
            ),
            (
                SignatureEnvelope {
                    value: String::new(),
                    ..valid()
                },
                "value",
            ),
            (
                SignatureEnvelope {
                    schema_version: "1".to_owned(),
                    ..valid()
                },
                "schema_version",
            ),
        ] {
            match round_trip(&envelope) {
                Err(SignatureError::EnvelopeField { field: got, .. }) => assert_eq!(got, field),
                other => panic!("expected {field} to be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_signed_at_that_is_not_a_date_time_is_refused() {
        for bad in [
            "",
            "2026-08-04",
            "2026-08-04 09:00:00Z",
            "2026-08-04T09:00:00",
        ] {
            let envelope = SignatureEnvelope {
                signed_at: Some(bad.to_owned()),
                ..valid()
            };
            assert!(
                matches!(
                    round_trip(&envelope),
                    Err(SignatureError::EnvelopeField { .. })
                ),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn the_date_time_spellings_the_clock_produces_are_accepted() {
        for good in [
            "2026-08-04T09:00:00Z",
            "2026-08-04T09:00:00.123456Z",
            "2026-08-04T09:00:00+03:00",
            "2026-08-04T09:00:00-05:30",
        ] {
            let envelope = SignatureEnvelope {
                signed_at: Some(good.to_owned()),
                ..valid()
            };
            assert!(round_trip(&envelope).is_ok(), "{good:?} should be accepted");
        }
    }
}
