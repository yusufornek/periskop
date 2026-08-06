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
//!
//! A third follows from the same principle and is enforced here too: a hash input
//! is the composed (NFC) form of the text, never the bytes as they happened to
//! arrive. See [`short_hash`].

use std::fmt;

use unicode_normalization::{is_nfc_quick, IsNormalized, UnicodeNormalization};

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

/// Feeds one field into the hasher in its canonical composed form.
///
/// `data-model.md` section 2 fixes the canonical serialisation of identity inputs
/// as UTF-8 NFC, and this is the single place the whole workspace honours it. The
/// reason is not tidiness: Unicode lets one visible string be written as several
/// byte sequences, so a symbol name spelled with a composed `é` and the same name
/// spelled as `e` plus a combining accent would produce two identities for one
/// thing. That failure is silent. Nothing rejects either spelling; the report
/// simply carries two entries where one call exists, or a declared point and its
/// observation never join, and the coverage statement has nothing to report
/// because nothing failed. macOS is the concrete source: paths read back from the
/// filesystem arrive decomposed, so a path that enters an identity on a Mac and
/// the same path typed into a rule file already differ today.
///
/// The quick check is not an optimisation detour: it is the common case. Every
/// ASCII input, which is nearly all of them, is already NFC and is hashed without
/// allocating. Only text that is not certainly normalised pays for a rewrite.
fn update_normalized(hasher: &mut blake3::Hasher, field: &str) {
    match is_nfc_quick(field.chars()) {
        IsNormalized::Yes => {
            hasher.update(field.as_bytes());
        }
        // `Maybe` means the quick check cannot decide from character properties
        // alone, so it is treated exactly like `No`: compose and hash that.
        IsNormalized::No | IsNormalized::Maybe => {
            let composed: String = field.nfc().collect();
            hasher.update(composed.as_bytes());
        }
    }
}

/// Hashes a domain tag together with an ordered list of fields.
///
/// The tag keeps identity spaces apart: two different kinds of thing that happen
/// to carry the same field values must not collide.
///
/// Fields are normalised to NFC on the way in (see [`update_normalized`]). The
/// domain tag is not, because it is a literal fixed in this file and in the
/// contract, never text that reached us from a filesystem or a payload.
pub fn short_hash(domain_tag: &str, fields: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain_tag.as_bytes());
    for field in fields {
        hasher.update(&[FIELD_SEPARATOR]);
        update_normalized(&mut hasher, field);
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

    /// The same symbol name in the two spellings Unicode allows for it.
    ///
    /// Composed: U+00E9. Decomposed: `e` followed by U+0301 COMBINING ACUTE
    /// ACCENT. They render identically and a reader cannot tell them apart, which
    /// is why an identity that distinguishes them fails silently.
    const COMPOSED_SYMBOL: &str = "hesapla_ödeme_bilgisi_é";
    const DECOMPOSED_SYMBOL: &str = "hesapla_o\u{0308}deme_bilgisi_e\u{0301}";

    #[test]
    fn two_spellings_of_one_name_derive_one_identity() {
        // The bytes really do differ; without that this test would pass for the
        // wrong reason and prove nothing about normalisation.
        assert_ne!(COMPOSED_SYMBOL.as_bytes(), DECOMPOSED_SYMBOL.as_bytes());
        assert_eq!(
            short_hash("ep/v1", &["src/billing.py", COMPOSED_SYMBOL, "shape", "0"]),
            short_hash(
                "ep/v1",
                &["src/billing.py", DECOMPOSED_SYMBOL, "shape", "0"]
            ),
        );
    }

    #[test]
    fn a_decomposed_path_and_a_composed_one_join() {
        // The macOS case: the scanner reads the path back from the filesystem
        // decomposed while a rule file or a hook carries it composed. If these
        // two derived different identities, a declared point and its observation
        // would never reconcile and nothing would report the miss.
        let composed =
            derive_finding_id("declared_egress_point", "declared", "ödeme/v.py", "r").unwrap();
        let decomposed = derive_finding_id(
            "declared_egress_point",
            "declared",
            "o\u{0308}deme/v.py",
            "r",
        )
        .unwrap();
        assert_eq!(composed, decomposed);
    }

    #[test]
    fn normalisation_does_not_merge_genuinely_different_text() {
        // NFC composes; it does not fold case, strip accents or collapse
        // lookalikes. A guard against reaching for NFKC or a casefold later,
        // which would merge two different symbols into one identity.
        assert_ne!(
            short_hash("fi/v1", &["ödeme"]),
            short_hash("fi/v1", &["odeme"]),
        );
        assert_ne!(
            short_hash("fi/v1", &["Ödeme"]),
            short_hash("fi/v1", &["ödeme"]),
        );
    }

    #[test]
    fn ascii_identities_are_unchanged_by_normalisation() {
        // Pins the blast radius of the change that introduced NFC. ASCII is
        // already NFC, so every identity derived from ASCII inputs, which is
        // nearly all of them, keeps the value it had before.
        assert_eq!(
            derive_finding_id(
                "declared_egress_point",
                "declared",
                "ep_3f0a91c7d4e28b56",
                "python.static.openai-chat-completions",
            )
            .unwrap()
            .as_str(),
            "fnd_eec43f700d0666e0",
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
