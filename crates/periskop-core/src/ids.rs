//! Content addressed identities.
//!
//! Every identity in periskop is derived from what a thing *is*, never from where
//! it happens to sit in a file. Inserting a line at the top of a source file must
//! not change a single identifier in the report, because a diff that lights up on
//! unrelated edits is a diff nobody reads.
//!
//! Two consequences follow, and both are enforced here rather than left to
//! convention. Line and column numbers never enter a hash input. Wall clock values
//! never do either, so the same tree scanned twice produces the same identities.

use std::fmt;

use crate::error::{Error, Result};

/// Short form of a hash: the first eight bytes, lowercase hex.
///
/// Eight bytes is not a cryptographic commitment and is not meant to be one. The
/// signature envelope covers integrity; this is a stable label for humans and
/// diffs, short enough to read in a terminal.
const SHORT_HASH_BYTES: usize = 8;
const SHORT_HASH_CHARS: usize = SHORT_HASH_BYTES * 2;

/// Field separator for hash inputs.
///
/// Without it, the inputs `("ab", "c")` and `("a", "bc")` would hash identically.
/// The byte is chosen to be one that cannot appear in any of the fields we feed in.
const FIELD_SEPARATOR: u8 = 0x1f;

macro_rules! define_id {
    ($name:ident, $prefix:literal, $human:literal) => {
        #[doc = concat!("A ", $human, " identity, rendered as `", $prefix, "` followed by 16 hex characters.")]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            /// Builds the identity from an already computed short hash.
            pub fn from_short_hash(short_hash: &str) -> Result<Self> {
                if short_hash.len() != SHORT_HASH_CHARS
                    || !short_hash.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                {
                    return Err(Error::MalformedId {
                        kind: $human,
                        what: short_hash.to_owned(),
                    });
                }
                Ok(Self(format!("{}{}", $prefix, short_hash)))
            }

            /// Parses a rendered identity, rejecting anything the schema would reject.
            pub fn parse(value: &str) -> Result<Self> {
                let rest = value.strip_prefix($prefix).ok_or_else(|| Error::MalformedId {
                    kind: $human,
                    what: value.to_owned(),
                })?;
                Self::from_short_hash(rest)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

define_id!(EgressPointId, "ep_", "egress point");
define_id!(EgressEventId, "ee_", "egress event");
define_id!(FlowId, "fl_", "flow");
define_id!(FindingId, "fnd_", "finding");
define_id!(ScanRunId, "scan_", "scan run");
define_id!(ReportId, "rpt_", "report");

/// Hashes a domain tag together with an ordered list of fields.
///
/// The tag keeps identity spaces apart: two different kinds of thing that happen
/// to carry the same field values must not collide.
pub fn short_hash(domain_tag: &str, fields: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain_tag.as_bytes());
    for field in fields {
        hasher.update(&[FIELD_SEPARATOR]);
        hasher.update(field.as_bytes());
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(SHORT_HASH_CHARS);
    for byte in &digest.as_bytes()[..SHORT_HASH_BYTES] {
        use fmt::Write as _;
        // Writing into a String cannot fail, and the lint config forbids unwrap,
        // so the result is discarded deliberately rather than unwrapped.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Derives a finding identity.
///
/// Inputs are fixed by the contract: kind, source, the primary reference and the
/// rule that produced the finding. Nothing else participates, which is what makes
/// the line insertion invariant hold.
pub fn derive_finding_id(
    kind: &str,
    source: &str,
    primary_ref: &str,
    rule_id: &str,
) -> Result<FindingId> {
    let hash = short_hash("fi/v1", &[kind, source, primary_ref, rule_id]);
    FindingId::from_short_hash(&hash)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rendered_id_matches_the_schema_pattern() {
        let id = derive_finding_id(
            "declared_egress_point",
            "declared",
            "ep_3f0a91c7d4e28b56",
            "python.static.openai-chat-completions",
        )
        .unwrap();

        assert!(id.as_str().starts_with("fnd_"));
        assert_eq!(id.as_str().len(), "fnd_".len() + SHORT_HASH_CHARS);
        assert!(id.as_str()["fnd_".len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }

    #[test]
    fn derivation_is_stable_across_calls() {
        let args = ("target_drift", "reconciled", "ep_0000000000000001", "r.id");
        let first = derive_finding_id(args.0, args.1, args.2, args.3).unwrap();
        let second = derive_finding_id(args.0, args.1, args.2, args.3).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn field_boundaries_are_not_ambiguous() {
        // Without a separator these two would hash to the same value, and two
        // unrelated findings would silently share an identity.
        let a = short_hash("fi/v1", &["ab", "c"]);
        let b = short_hash("fi/v1", &["a", "bc"]);
        assert_ne!(a, b);
    }

    #[test]
    fn domain_tag_separates_identity_spaces() {
        let same_fields = ["x", "y"];
        assert_ne!(
            short_hash("fi/v1", &same_fields),
            short_hash("ep/v1", &same_fields)
        );
    }

    #[test]
    fn parse_rejects_wrong_prefix() {
        assert!(FindingId::parse("ep_3f0a91c7d4e28b56").is_err());
    }

    #[test]
    fn parse_rejects_uppercase_hex() {
        // The schema pattern is lowercase only. Accepting uppercase here would let
        // two spellings of one identity into the report and break byte equality.
        assert!(FindingId::parse("fnd_3F0A91C7D4E28B56").is_err());
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(FindingId::parse("fnd_3f0a91c7").is_err());
    }

    #[test]
    fn parse_round_trips_a_derived_id() {
        let id = derive_finding_id("dormant_egress_point", "reconciled", "ep_1", "r").unwrap();
        assert_eq!(FindingId::parse(id.as_str()).unwrap(), id);
    }
}
