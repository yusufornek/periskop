//! Deriving the vault's keys, and refusing the parameters that would derive them.
//!
//! One passphrase becomes one master key (Argon2id), and every key with a job is
//! expanded from that master key with HKDF-SHA256 under its own info string
//! (ADR-007 "Anahtar türetme", ADR-016 section 2). Nothing here is hand written:
//! CLAUDE.md forbids hand written crypto and this is the part of the product where
//! that rule earns its keep.
//!
//! # Why the bounds are checked before anything is derived
//!
//! Argon2id's parameters are stored beside the vault they protect, so an attacker
//! who can write to a vault file can also claim its parameters. ADR-007 section 4
//! answers the obvious attack, weakening the parameters, with a header MAC: the
//! key is derived from the parameters the header *claims*, and the header MAC is
//! then verified under that key, so weakened parameters produce a key whose MAC
//! does not check out.
//!
//! That answer has an order of operations problem, and it is the reason this
//! module exists as a separate step. Verifying the MAC requires deriving the key
//! first. A header claiming `m = 64 GiB, t = 10` would therefore consume 64 GiB
//! and minutes of CPU **on the way to** discovering it was forged: a memory and
//! CPU exhaustion attack that needs no valid passphrase and no valid MAC. So the
//! claimed parameters pass through [`KdfProfile::validate`] first, and
//! [`derive_master_key`] takes a [`KdfProfile`], which has no other constructor.
//! Rejecting a forged header costs a few comparisons.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::error::VaultError;
use super::secret::{
    random_bytes, ChainKey, DerivedPurpose, Key, MasterKey, Passphrase, RecordKey, SessionKey,
    KEY_BYTES,
};
use super::session::SessionId;

/// Hard ceiling on the memory parameter, in KiB: 1 GiB (ADR-007 section 4).
pub const MEMORY_CEILING_KIB: u32 = 1024 * 1024;
/// Hard ceiling on the iteration count (ADR-007 section 4).
pub const ITERATION_CEILING: u32 = 10;
/// Hard ceiling on the lane count (ADR-007 section 4).
pub const PARALLELISM_CEILING: u32 = 8;

/// Floor on the memory parameter, in KiB: the `ci` profile's 64 MiB.
///
/// ADR-007 says the floors may not be crossed but does not put numbers on them.
/// The number chosen here is the lowest profile the product itself ships: below
/// it, the vault would be running at a strength nobody declared and no document
/// describes. Recorded as open question 24.
pub const MEMORY_FLOOR_KIB: u32 = 64 * 1024;
/// Floor on the iteration count: what both shipped profiles use.
pub const ITERATION_FLOOR: u32 = 3;
/// Floor on the lane count.
///
/// One, and not the four both profiles use, because lanes divide the same work
/// rather than reducing it: Argon2's cost is set by memory and iterations, and a
/// single lane computes the same amount more slowly. Refusing `p = 1` would
/// refuse a configuration that is not weaker.
pub const PARALLELISM_FLOOR: u32 = 1;

/// Length of the Argon2id salt (ADR-007: 16 random bytes).
pub const SALT_BYTES: usize = 16;

/// The Argon2id salt.
///
/// In `memory` mode it is drawn fresh every time the process opens its vault:
/// nothing is stored, so nothing has to agree with a previous run. The `file`
/// backend will read it out of the vault header instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Salt([u8; SALT_BYTES]);

impl Salt {
    pub fn generate() -> Result<Self, VaultError> {
        Ok(Self(random_bytes()?))
    }

    pub fn from_bytes(bytes: [u8; SALT_BYTES]) -> Self {
        Self(bytes)
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Which shipped Argon2id profile to derive under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileName {
    /// `m = 256 MiB, t = 3, p = 4` (ADR-007).
    Standard,
    /// `m = 64 MiB, t = 3, p = 4`, for machines that cannot spare 256 MiB.
    ///
    /// Weaker, and never silently: see [`VaultNote::ReducedKdfProfile`].
    Ci,
}

impl Default for ProfileName {
    /// The strong profile. A default that has to be argued down is the only
    /// default worth shipping for a key derivation function.
    fn default() -> Self {
        Self::Standard
    }
}

impl ProfileName {
    /// Reads the `--vault-profile` value.
    ///
    /// `None` rather than a fallback to the default: a misspelled profile that
    /// quietly ran under some other strength is exactly the surprise this whole
    /// module is written to avoid.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "default" => Some(Self::Standard),
            "ci" => Some(Self::Ci),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "default",
            Self::Ci => "ci",
        }
    }

    /// What the operator has to be told about this choice, if anything.
    pub fn note(self) -> Option<VaultNote> {
        note_for(&KdfProfile::named(self))
    }
}

/// What the operator has to be told about the strength a vault is actually
/// protected at.
///
/// Keyed off the parameters rather than off the profile *name*, because a vault
/// file carries its own parameters: an operator who asks for the shipped profile
/// and opens a file created under the reduced one is running at the reduced one,
/// and a note that followed the name would say the opposite.
pub fn note_for(profile: &KdfProfile) -> Option<VaultNote> {
    let standard = KdfProfile::named(ProfileName::Standard).memory_kib;
    if profile.memory_kib >= standard {
        return None;
    }
    Some(VaultNote::ReducedKdfProfile {
        memory_kib: profile.memory_kib,
        standard_memory_kib: standard,
    })
}

/// Something the operator has to see, because it changes what the vault is worth.
///
/// A note is not a warning about a mistake. It is a fact about the run that the
/// output would otherwise hide, and README principle 4 puts the burden on us:
/// the difference between "protected at the shipped strength" and "protected at a
/// reduced one" may not be invisible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultNote {
    /// The vault key was derived below the shipped strength.
    ReducedKdfProfile {
        memory_kib: u32,
        standard_memory_kib: u32,
    },
}

impl fmt::Display for VaultNote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The numbers rather than a profile name. A vault file carries its own
            // Argon2id parameters, so this note is also produced for a file whose
            // header says something the shipped profiles never say, and naming the
            // `ci` profile there would be a false statement in a note whose whole
            // job is to be true.
            Self::ReducedKdfProfile {
                memory_kib,
                standard_memory_kib,
            } => write!(
                f,
                "vault key derivation ran at Argon2id memory {} MiB instead of the shipped {} MiB. \
                 Guessing the passphrase offline is correspondingly cheaper.",
                memory_kib / 1024,
                standard_memory_kib / 1024
            ),
        }
    }
}

/// Argon2id parameters as *claimed* by something we do not trust: a command line
/// flag, or the header of a vault file an attacker may have rewritten.
///
/// A separate type from [`KdfProfile`] so that "these numbers have been checked"
/// is a fact the compiler carries rather than a comment somebody has to believe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimedKdfParameters {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// Argon2id parameters that are inside the bounds.
///
/// Constructible two ways and no third: from a shipped profile name, or by
/// validating a claim. [`derive_master_key`] takes this type, which is what makes
/// "checked before derived" a property of the code rather than of its ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfProfile {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl KdfProfile {
    /// The parameters of a shipped profile.
    ///
    /// Not routed through [`Self::validate`]: these are constants, and a
    /// constructor that could fail would push a meaningless error onto every
    /// caller. `the_shipped_profiles_are_inside_their_own_bounds` is the test that
    /// keeps them honest, and it fails if a bound is ever moved past a profile.
    pub fn named(name: ProfileName) -> Self {
        match name {
            // ADR-007: m = 256 MiB, t = 3, p = 4.
            ProfileName::Standard => Self {
                memory_kib: 256 * 1024,
                iterations: 3,
                parallelism: 4,
            },
            // proxy/spec.md section 9: the `ci` profile lowers memory alone.
            ProfileName::Ci => Self {
                memory_kib: 64 * 1024,
                iterations: 3,
                parallelism: 4,
            },
        }
    }

    /// Checks claimed parameters against the bounds.
    ///
    /// Pure, cheap, and the only door to derivation. Nothing here touches the
    /// passphrase, allocates, or calls Argon2id: a forged header costs three
    /// comparisons rather than its claimed memory.
    pub fn validate(claimed: &ClaimedKdfParameters) -> Result<Self, VaultError> {
        check(
            "memory",
            claimed.memory_kib,
            MEMORY_FLOOR_KIB,
            MEMORY_CEILING_KIB,
        )?;
        check(
            "iterations",
            claimed.iterations,
            ITERATION_FLOOR,
            ITERATION_CEILING,
        )?;
        check(
            "parallelism",
            claimed.parallelism,
            PARALLELISM_FLOOR,
            PARALLELISM_CEILING,
        )?;

        Ok(Self {
            memory_kib: claimed.memory_kib,
            iterations: claimed.iterations,
            parallelism: claimed.parallelism,
        })
    }

    /// The same numbers, on their way into a vault file header.
    ///
    /// Written back out as a claim rather than as a profile, because that is what
    /// they become the moment they leave this process: the next reader has to
    /// bound them again before deriving anything from them.
    pub(super) fn claimed(&self) -> ClaimedKdfParameters {
        ClaimedKdfParameters {
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
        }
    }
}

fn check(
    parameter: &'static str,
    claimed: u32,
    floor: u32,
    ceiling: u32,
) -> Result<(), VaultError> {
    if claimed < floor || claimed > ceiling {
        return Err(VaultError::KdfParameterOutOfRange {
            parameter,
            claimed,
            floor,
            ceiling,
        });
    }
    Ok(())
}

/// Derives the master key from the operator's passphrase.
///
/// The only way into the vault in F4: ADR-016 section 4 struck the operating
/// system keyring path, so there is no passwordless mode and no key file to read.
/// The cost is written down in KG-020 rather than worked around here.
pub fn derive_master_key(
    profile: &KdfProfile,
    passphrase: &Passphrase,
    salt: &Salt,
) -> Result<MasterKey, VaultError> {
    // Fail closed at the door. Deriving a key from an empty passphrase produces a
    // vault that looks encrypted and opens for anyone who knows it was empty.
    if passphrase.is_empty() {
        return Err(VaultError::PassphraseMissing);
    }

    let params = Params::new(
        profile.memory_kib,
        profile.iterations,
        profile.parallelism,
        Some(KEY_BYTES),
    )
    .map_err(|_| VaultError::KeyDerivationFailed)?;

    let mut material = Zeroizing::new([0u8; KEY_BYTES]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(
            passphrase.as_bytes(),
            salt.as_bytes(),
            material.as_mut_slice(),
        )
        .map_err(|_| VaultError::KeyDerivationFailed)?;

    Ok(Key::from_bytes(*material))
}

/// Expands the per session key (ADR-007: salt is the session id).
///
/// The salt is what makes aliases unlinkable across sessions. Two sessions that
/// mask the same value derive different keys, so they derive different aliases,
/// so a provider cannot join them.
pub fn derive_session_key(
    master: &MasterKey,
    session: &SessionId,
) -> Result<SessionKey, VaultError> {
    expand(master, Some(session.as_bytes()))
}

/// Expands the key records are sealed under, `K_vault` in ADR-007.
pub(super) fn derive_record_key(master: &MasterKey) -> Result<RecordKey, VaultError> {
    expand(master, None)
}

/// Expands the key the vault file's integrity chain runs under, `K_chain` in
/// ADR-007 section "3. Dosya bütünlüğü".
///
/// A sibling of the record key rather than a child of it, which is what the ADR
/// means by "kayıt anahtarından ayrı": both come from the master key under their
/// own info string, so neither can be computed from the other.
pub(super) fn derive_chain_key(master: &MasterKey) -> Result<ChainKey, VaultError> {
    expand(master, None)
}

/// HKDF-SHA256, once, for every derived key in this vault.
fn expand<P: DerivedPurpose>(
    master: &MasterKey,
    salt: Option<&[u8]>,
) -> Result<Key<P>, VaultError> {
    let mut material = Zeroizing::new([0u8; KEY_BYTES]);
    Hkdf::<Sha256>::new(salt, master.as_bytes())
        .expand(P::INFO, material.as_mut_slice())
        // HKDF-SHA256 only refuses lengths above 255 * 32 bytes, and this one is
        // a constant 32. Mapped rather than unwrapped because a panic in the
        // vault is an outage with no diagnosis.
        .map_err(|_| VaultError::KeyDerivationFailed)?;

    Ok(Key::from_bytes(*material))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    /// How long a rejection may take before it stops being a rejection.
    ///
    /// Far above the cost of three comparisons and far below the cost of the
    /// derivation being refused, so it is not a performance assertion and belongs
    /// to no latency budget.
    const REFUSAL_BUDGET: Duration = Duration::from_secs(5);

    fn claim(memory_kib: u32, iterations: u32, parallelism: u32) -> ClaimedKdfParameters {
        ClaimedKdfParameters {
            memory_kib,
            iterations,
            parallelism,
        }
    }

    fn passphrase() -> Passphrase {
        Passphrase::new(b"a passphrase the operator typed".to_vec())
    }

    fn salt() -> Salt {
        Salt::from_bytes([0x11; SALT_BYTES])
    }

    /// The `ci` profile, for tests that need a real derivation but not a slow one.
    fn ci() -> KdfProfile {
        KdfProfile::named(ProfileName::Ci)
    }

    #[test]
    fn the_shipped_profiles_are_inside_their_own_bounds() {
        // If a bound is ever moved past a shipped profile, the product would
        // refuse its own default, and it would find out at an operator's terminal
        // rather than here.
        for name in [ProfileName::Standard, ProfileName::Ci] {
            let profile = KdfProfile::named(name);
            let claimed = claim(profile.memory_kib, profile.iterations, profile.parallelism);
            assert_eq!(KdfProfile::validate(&claimed), Ok(profile), "{name:?}");
        }
    }

    #[test]
    fn the_shipped_profiles_carry_the_values_the_adr_fixes() {
        let standard = KdfProfile::named(ProfileName::Standard);
        assert_eq!(standard.memory_kib, 256 * 1024);
        assert_eq!(standard.iterations, 3);
        assert_eq!(standard.parallelism, 4);

        let reduced = KdfProfile::named(ProfileName::Ci);
        assert_eq!(reduced.memory_kib, 64 * 1024);
        assert_eq!(reduced.iterations, 3);
        assert_eq!(reduced.parallelism, 4);
    }

    /// The resource exhaustion test ADR-007 section 4 asks for.
    ///
    /// The claim below is what a forged vault header looks like: 3.8 GiB of
    /// memory, ten passes. If validation ran after derivation, or after the
    /// header MAC that derivation feeds, this test would not fail an assertion.
    /// It would allocate 3.8 GiB and grind for minutes, which is the attack. The
    /// budget is here so that failure arrives as a message rather than as a
    /// continuous integration job somebody kills an hour later.
    #[test]
    fn parameters_above_the_hard_ceiling_are_refused_before_any_derivation_runs() {
        let forged = claim(4_000_000, 10, 8);

        let started = Instant::now();
        let refusal = KdfProfile::validate(&forged).unwrap_err();
        let took = started.elapsed();

        assert_eq!(
            refusal,
            VaultError::KdfParameterOutOfRange {
                parameter: "memory",
                claimed: 4_000_000,
                floor: MEMORY_FLOOR_KIB,
                ceiling: MEMORY_CEILING_KIB,
            }
        );
        assert!(took < REFUSAL_BUDGET, "refusal took {took:?}");
        assert_eq!(refusal.http_status(), 503);
    }

    #[test]
    fn each_parameter_is_bounded_from_both_sides_and_says_which_one_it_was() {
        let cases = [
            (claim(MEMORY_CEILING_KIB + 1, 3, 4), "memory"),
            (claim(MEMORY_FLOOR_KIB - 1, 3, 4), "memory"),
            (claim(256 * 1024, ITERATION_CEILING + 1, 4), "iterations"),
            (claim(256 * 1024, ITERATION_FLOOR - 1, 4), "iterations"),
            (claim(256 * 1024, 3, PARALLELISM_CEILING + 1), "parallelism"),
            (claim(256 * 1024, 3, PARALLELISM_FLOOR - 1), "parallelism"),
        ];

        for (claimed, expected) in cases {
            match KdfProfile::validate(&claimed) {
                Err(VaultError::KdfParameterOutOfRange { parameter, .. }) => {
                    assert_eq!(parameter, expected, "{claimed:?}");
                }
                other => panic!("{claimed:?} was not refused: {other:?}"),
            }
        }
    }

    #[test]
    fn the_reduced_profile_produces_a_visible_note_and_the_default_produces_none() {
        assert_eq!(ProfileName::Standard.note(), None);

        let note = ProfileName::Ci.note().unwrap();
        let rendered = note.to_string();
        // The operator has to be able to read what changed and what it costs.
        assert!(rendered.contains("64 MiB"), "{rendered}");
        assert!(rendered.contains("256 MiB"), "{rendered}");
        assert!(rendered.contains("Guessing"), "{rendered}");
    }

    /// The note follows the parameters, not the name somebody typed.
    ///
    /// A vault file carries its own Argon2id parameters, so a run that asked for
    /// the shipped profile can still end up deriving at a reduced strength. The
    /// note has to say so, or the difference between "protected at the shipped
    /// strength" and "protected at a reduced one" becomes invisible exactly when
    /// it matters (README principle 4).
    #[test]
    fn a_reduced_parameter_set_from_a_file_produces_the_note_too() {
        let from_file = KdfProfile::validate(&claim(100 * 1024, 3, 4)).unwrap();
        let note = note_for(&from_file).unwrap();
        assert!(note.to_string().contains("100 MiB"), "{note}");

        // And a file at or above the shipped strength produces none.
        assert_eq!(note_for(&KdfProfile::named(ProfileName::Standard)), None);
        assert_eq!(
            note_for(&KdfProfile::validate(&claim(MEMORY_CEILING_KIB, 3, 4)).unwrap()),
            None
        );
    }

    #[test]
    fn a_misspelled_profile_is_refused_rather_than_defaulted() {
        assert_eq!(ProfileName::parse("default"), Some(ProfileName::Standard));
        assert_eq!(ProfileName::parse("ci"), Some(ProfileName::Ci));
        assert_eq!(ProfileName::parse("CI"), None);
        assert_eq!(ProfileName::parse("fast"), None);
        assert_eq!(ProfileName::parse(""), None);
    }

    #[test]
    fn the_default_profile_is_the_strong_one() {
        assert_eq!(ProfileName::default(), ProfileName::Standard);
        assert_eq!(ProfileName::default().as_str(), "default");
    }

    #[test]
    fn an_empty_passphrase_refuses_before_argon2_is_called() {
        let started = Instant::now();
        let refusal = derive_master_key(
            &KdfProfile::named(ProfileName::Standard),
            &Passphrase::new(Vec::new()),
            &salt(),
        )
        .unwrap_err();

        assert_eq!(refusal, VaultError::PassphraseMissing);
        assert!(started.elapsed() < REFUSAL_BUDGET);
    }

    #[test]
    fn the_same_passphrase_and_salt_derive_the_same_key() {
        let first = derive_master_key(&ci(), &passphrase(), &salt()).unwrap();
        let second = derive_master_key(&ci(), &passphrase(), &salt()).unwrap();
        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn a_different_salt_or_profile_derives_a_different_key() {
        let base = derive_master_key(&ci(), &passphrase(), &salt()).unwrap();

        let other_salt =
            derive_master_key(&ci(), &passphrase(), &Salt::from_bytes([0x22; SALT_BYTES])).unwrap();
        assert_ne!(base.as_bytes(), other_salt.as_bytes());

        // Not a security property in itself, but it pins that the parameters
        // reach Argon2id rather than being carried and ignored.
        let stronger = KdfProfile::validate(&claim(MEMORY_FLOOR_KIB, 4, 4)).unwrap();
        let other_profile = derive_master_key(&stronger, &passphrase(), &salt()).unwrap();
        assert_ne!(base.as_bytes(), other_profile.as_bytes());
    }

    /// The shipped default has to actually run, once, somewhere.
    ///
    /// 256 MiB is the parameter ADR-007 records as a problem in small containers,
    /// and a product whose default is only ever exercised on an operator's machine
    /// finds that out from the operator.
    #[test]
    fn the_shipped_default_profile_derives_a_key() {
        let key = derive_master_key(
            &KdfProfile::named(ProfileName::Standard),
            &passphrase(),
            &salt(),
        )
        .unwrap();
        assert_ne!(key.as_bytes(), &[0u8; KEY_BYTES]);
    }

    #[test]
    fn session_keys_repeat_for_one_session_id_and_differ_between_two() {
        let master = derive_master_key(&ci(), &passphrase(), &salt()).unwrap();
        let first = SessionId::from_bytes([1u8; 16]);
        let second = SessionId::from_bytes([2u8; 16]);

        let a = derive_session_key(&master, &first).unwrap();
        let a_again = derive_session_key(&master, &first).unwrap();
        let b = derive_session_key(&master, &second).unwrap();

        // Deterministic within a session: the same value has to mask to the same
        // alias all conversation long (ADR-007).
        assert_eq!(a.as_bytes(), a_again.as_bytes());
        // Unlinkable across sessions: this is the whole reason the session id is
        // the HKDF salt.
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn the_record_key_is_neither_the_master_key_nor_a_session_key() {
        let master = derive_master_key(&ci(), &passphrase(), &salt()).unwrap();
        let record = derive_record_key(&master).unwrap();
        let session = derive_session_key(&master, &SessionId::from_bytes([3u8; 16])).unwrap();

        assert_ne!(record.as_bytes(), master.as_bytes());
        assert_ne!(record.as_bytes(), session.as_bytes());
        // Stable, so the same vault opens the same records for as long as the
        // passphrase does not change.
        assert_eq!(
            record.as_bytes(),
            derive_record_key(&master).unwrap().as_bytes()
        );
    }

    /// ADR-007 puts the chain key beside the record key rather than under it.
    ///
    /// If these two were ever the same bytes, the key that seals every record
    /// would also be the key that authenticates the file, so a leak of the busy
    /// one would let an attacker write a vault file this process opens.
    #[test]
    fn the_chain_key_is_separate_from_the_record_key_and_stable() {
        let master = derive_master_key(&ci(), &passphrase(), &salt()).unwrap();
        let chain = derive_chain_key(&master).unwrap();

        assert_ne!(chain.as_bytes(), master.as_bytes());
        assert_ne!(
            chain.as_bytes(),
            derive_record_key(&master).unwrap().as_bytes()
        );
        assert_eq!(
            chain.as_bytes(),
            derive_chain_key(&master).unwrap().as_bytes()
        );

        // And it follows the master key: a different passphrase cannot verify a
        // header this one wrote.
        let elsewhere = derive_master_key(
            &ci(),
            &Passphrase::new(b"a different operator".to_vec()),
            &salt(),
        )
        .unwrap();
        assert_ne!(
            chain.as_bytes(),
            derive_chain_key(&elsewhere).unwrap().as_bytes()
        );
    }

    #[test]
    fn two_generated_salts_differ() {
        assert_ne!(Salt::generate().unwrap(), Salt::generate().unwrap());
    }
}
