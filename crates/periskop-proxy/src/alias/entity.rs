//! The registry: which types get an alias, and on which rung of the ladder.
//!
//! The variant list is the closed set of `proxy-policy.schema.json`'s
//! `entity_type`, in that file's order, and it may not drift from it: the loader
//! stops on a type it does not recognise, so a type this module knows and the
//! policy schema does not is a rule an operator can never write, and the reverse
//! is a rule the loader accepts and nothing masks.
//!
//! Two entries are deliberately not ordinary generators, and both say so in the
//! type system rather than in a comment somewhere downstream:
//!
//! - `URL` mints nothing of its own. ADR-010 section 2 narrowed it to the host
//!   component, because an alias built from a whole URL carries the source URL's
//!   length and the streaming state machine's lookahead is then unbounded.
//! - `DATE` mints nothing at all. ADR-010 section 7 turned date shifting off by
//!   default, and F4 does not implement it at all, so there is no date alias to
//!   produce. `date_policy` decides between `allow` and `block` instead.

use core::fmt;

/// Which rung of the ADR-010 section 5.1 ladder produced an alias.
///
/// Reported per type in `alias_stats.by_type[].ladder_rung`, where it is the
/// runtime evidence for P-0: it says which class of proof each type fell back to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LadderRung {
    /// A published reserved or fiction range, cited in the rule file.
    Reserved,
    /// The type's shape, with its validator deliberately failed.
    Invalid,
    /// Type preservation switched off: `PSK_<TAG>_<16 hex>`.
    Opaque,
    /// A counted label. No value is drawn from the type's value space.
    Label,
}

impl LadderRung {
    /// The single letter the event contract carries (`proxy-events.md`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "R",
            Self::Invalid => "I",
            Self::Opaque => "O",
            Self::Label => "L",
        }
    }
}

impl fmt::Display for LadderRung {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a type produces an alias, decided at compile time (ADR-010 section 5.1:
/// "Basamak seçimi derleme zamanında sabittir").
///
/// A generator may fall *down* the ladder at run time when its evidence runs out
/// (an exhausted card pool, a country with no published numbering citation). It
/// may never climb: a value cannot become better proven than the rung its type
/// was admitted at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Minting {
    /// The type mints its own alias, entering the ladder at this rung.
    EntersAt(LadderRung),
    /// Only the host component is aliased, under [`EntityType::Host`].
    HostComponent,
    /// No alias exists for this type in this phase.
    NotMinted,
}

/// Which alias style the policy selected (`proxy-policy.md`, ADR-010 section 5.2).
///
/// `Opaque` drops **every** type straight to rung `O`. P-0 holds in both styles;
/// the style only decides how much shape survives.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AliasStyle {
    /// The default: shape is preserved as far as the ladder can prove it.
    #[default]
    TypePreserving,
    /// `PSK_<TAG>_<16 hex>` for everything.
    Opaque,
}

impl AliasStyle {
    /// The spelling in `policy.toml` and in the event record.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TypePreserving => "type-preserving",
            Self::Opaque => "opaque",
        }
    }
}

/// An entity type the proxy can mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntityType {
    Iban,
    Tckn,
    Vkn,
    CreditCard,
    Email,
    Phone,
    Ipv4,
    Ipv6,
    ApiKey,
    Secret,
    Url,
    Host,
    Date,
    Person,
    Org,
    Loc,
    Address,
}

impl EntityType {
    /// Every registered type.
    ///
    /// This array is what the P-0 gate counts against: a type added here without
    /// an invariant test fails `tests/p0_invariants.rs` rather than slipping in
    /// with no proof obligation.
    pub const ALL: [Self; 17] = [
        Self::Iban,
        Self::Tckn,
        Self::Vkn,
        Self::CreditCard,
        Self::Email,
        Self::Phone,
        Self::Ipv4,
        Self::Ipv6,
        Self::ApiKey,
        Self::Secret,
        Self::Url,
        Self::Host,
        Self::Date,
        Self::Person,
        Self::Org,
        Self::Loc,
        Self::Address,
    ];

    /// The tag, in the contract's UPPER_SNAKE spelling.
    ///
    /// It is not only a label: the opaque alias is built out of it
    /// (`PSK_CREDIT_CARD_<16 hex>`), so its length is part of every type's length
    /// ceiling and the longest tag decides `L_MAX_STATIC` in the opaque style.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Iban => "IBAN",
            Self::Tckn => "TCKN",
            Self::Vkn => "VKN",
            Self::CreditCard => "CREDIT_CARD",
            Self::Email => "EMAIL",
            Self::Phone => "PHONE",
            Self::Ipv4 => "IPV4",
            Self::Ipv6 => "IPV6",
            Self::ApiKey => "API_KEY",
            Self::Secret => "SECRET",
            Self::Url => "URL",
            Self::Host => "HOST",
            Self::Date => "DATE",
            Self::Person => "PERSON",
            Self::Org => "ORG",
            Self::Loc => "LOC",
            Self::Address => "ADDRESS",
        }
    }

    /// Reads a tag back, refusing one this build does not know.
    ///
    /// `None` rather than a default, for the reason the policy schema gives: a
    /// type identifier nobody recognises is a rule the operator believes is
    /// masking something.
    pub fn from_tag(tag: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|entity| entity.tag() == tag)
    }

    /// How this type produces an alias (ADR-010 section 5.2, the binding table).
    pub const fn minting(self) -> Minting {
        match self {
            // Labels. Nothing is drawn from the value space, so there is nothing
            // that could belong to anybody. An invented address is a real address
            // somewhere, which is why ADDRESS is here and not on rung I.
            Self::Person | Self::Org | Self::Loc | Self::Address => {
                Minting::EntersAt(LadderRung::Label)
            }
            // Documented ranges: .invalid (RFC 2606), TEST-NET (RFC 5737),
            // 2001:db8::/32 (RFC 3849).
            Self::Email | Self::Host | Self::Ipv4 | Self::Ipv6 => {
                Minting::EntersAt(LadderRung::Reserved)
            }
            // Published test PANs first, a Luhn breaking card when they run out.
            Self::CreditCard => Minting::EntersAt(LadderRung::Reserved),
            // A published fiction range where the country has one, a number one
            // digit past the plan's maximum where it does not, opaque where the
            // country is unknown (KG-011).
            Self::Phone => Minting::EntersAt(LadderRung::Reserved),
            // Check digits, deliberately failed.
            Self::Iban | Self::Tckn | Self::Vkn => Minting::EntersAt(LadderRung::Invalid),
            // Shape and length class kept, body drawn from the seed. See
            // `reported_rung`: what this type *claims* is weaker than what it
            // produces, and the claim is the honest one.
            Self::ApiKey | Self::Secret => Minting::EntersAt(LadderRung::Invalid),
            Self::Url => Minting::HostComponent,
            Self::Date => Minting::NotMinted,
        }
    }

    /// The rung a value of this type may enter the ladder at, if it mints at all.
    pub const fn entry_rung(self) -> Option<LadderRung> {
        match self.minting() {
            Minting::EntersAt(rung) => Some(rung),
            // The host component is minted under HOST, which enters at R.
            Minting::HostComponent => Some(LadderRung::Reserved),
            Minting::NotMinted => None,
        }
    }

    /// Whether P-0's evidence for this type is documentary or merely statistical.
    ///
    /// True for exactly the two key types, and threat model R14 is the reason:
    /// every other type can point at a publication (rung `R`) or at a validator
    /// it provably fails (rung `I`). An API key format has neither. What is left
    /// is a counting argument: a body drawn from at least 128 bits of session
    /// keyed material collides with a real key with probability at most 2^-128.
    ///
    /// That is a good argument and it is not the same *kind* of argument, so it
    /// is marked rather than blended in. The P-0 gate counts the marked types and
    /// fails if the mark spreads.
    pub const fn evidence_is_entropic(self) -> bool {
        matches!(self, Self::ApiKey | Self::Secret)
    }

    /// The rung reported in `alias_stats.by_type[].ladder_rung` for an alias that
    /// was actually produced at `achieved`.
    ///
    /// The two are the same everywhere except the entropic types, where the
    /// report is downgraded to `O` on purpose (threat model R14: "`ladder_rung`
    /// bu türde `O` olarak raporlanır, `R`/`I` iddiası edilmez"). The measurement
    /// is what an operator reads to see how much of a run rests on weak evidence,
    /// so it may not read stronger than the evidence is.
    pub const fn reported_rung(self, achieved: LadderRung) -> LadderRung {
        if self.evidence_is_entropic() {
            LadderRung::Opaque
        } else {
            achieved
        }
    }
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_type_has_a_distinct_tag_and_reads_back() {
        let mut seen = std::collections::BTreeSet::new();
        for entity in EntityType::ALL {
            assert!(seen.insert(entity.tag()), "duplicate tag {}", entity.tag());
            assert_eq!(EntityType::from_tag(entity.tag()), Some(entity));
        }
        assert_eq!(seen.len(), EntityType::ALL.len());
    }

    #[test]
    fn a_tag_this_build_does_not_know_is_refused_rather_than_defaulted() {
        assert_eq!(EntityType::from_tag("PASSPORT"), None);
        assert_eq!(EntityType::from_tag("iban"), None);
        assert_eq!(EntityType::from_tag(""), None);
    }

    #[test]
    fn the_registry_matches_the_closed_set_of_the_policy_schema() {
        // Read from the schema rather than restated here, so that the two lists
        // cannot drift apart without this failing. The schema is the contract and
        // this module is the implementation; the implementation is what moves.
        let schema = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../schemas/proxy-policy.schema.json"),
        )
        .unwrap();
        let start = schema.find("\"entity_type\"").unwrap();
        let enum_at = schema[start..].find("\"enum\"").unwrap() + start;
        let open = schema[enum_at..].find('[').unwrap() + enum_at;
        let close = schema[open..].find(']').unwrap() + open;

        let in_schema: std::collections::BTreeSet<String> = schema[open + 1..close]
            .split(',')
            .map(|entry| entry.trim().trim_matches('"').to_owned())
            .filter(|entry| !entry.is_empty())
            .collect();
        let in_code: std::collections::BTreeSet<String> = EntityType::ALL
            .iter()
            .map(|entity| entity.tag().to_owned())
            .collect();

        assert!(!in_schema.is_empty(), "the schema enum failed to parse");
        assert_eq!(in_code, in_schema);
    }

    #[test]
    fn the_two_types_that_mint_nothing_of_their_own_say_so_in_the_type_system() {
        assert_eq!(EntityType::Date.minting(), Minting::NotMinted);
        assert_eq!(EntityType::Date.entry_rung(), None);
        assert_eq!(EntityType::Url.minting(), Minting::HostComponent);
        // Every other type mints.
        for entity in EntityType::ALL {
            if matches!(entity, EntityType::Date) {
                continue;
            }
            assert!(entity.entry_rung().is_some(), "{entity} mints nothing");
        }
    }

    #[test]
    fn only_the_key_types_rest_on_entropic_evidence_and_they_report_opaque() {
        let entropic: Vec<EntityType> = EntityType::ALL
            .into_iter()
            .filter(|entity| entity.evidence_is_entropic())
            .collect();
        assert_eq!(entropic, vec![EntityType::ApiKey, EntityType::Secret]);

        // Threat model R14: the report may not claim R or I for these two, no
        // matter which rung the generator actually walked.
        for entity in entropic {
            for achieved in [
                LadderRung::Reserved,
                LadderRung::Invalid,
                LadderRung::Opaque,
                LadderRung::Label,
            ] {
                assert_eq!(entity.reported_rung(achieved), LadderRung::Opaque);
            }
        }

        // And every other type reports exactly what it achieved, or the
        // measurement would be describing a different run than the one that
        // happened.
        for entity in EntityType::ALL {
            if entity.evidence_is_entropic() {
                continue;
            }
            assert_eq!(
                entity.reported_rung(LadderRung::Invalid),
                LadderRung::Invalid
            );
            assert_eq!(
                entity.reported_rung(LadderRung::Reserved),
                LadderRung::Reserved
            );
        }
    }

    #[test]
    fn the_rung_letters_are_the_ones_the_event_contract_carries() {
        assert_eq!(LadderRung::Reserved.as_str(), "R");
        assert_eq!(LadderRung::Invalid.as_str(), "I");
        assert_eq!(LadderRung::Opaque.as_str(), "O");
        assert_eq!(LadderRung::Label.as_str(), "L");
        assert_eq!(AliasStyle::default(), AliasStyle::TypePreserving);
        assert_eq!(AliasStyle::Opaque.as_str(), "opaque");
    }
}
