//! Reading `periskop-policy.toml`.
//!
//! The half of the policy contract that was missing. `schemas/policy.schema.json`
//! and `docs/04-contracts/policy-schema.md` fixed where a threshold may be
//! declared; until this module existed nothing read the file, so
//! `[reconciliation].volume_band` could be written and had no effect, and
//! `volume_anomaly` could not be produced by any real pipeline run. The engine
//! side was already finished and tested; what was missing was the door.
//!
//! Four rules shape everything below, and each one is the contract's, not this
//! module's invention.
//!
//! **No file means no band.** A project with no policy behaves exactly as it did
//! before this module was written: engine defaults for the two thresholds that
//! have one, no volume band, and `volume_anomaly` reported as suppressed with the
//! reason `volume_band_not_declared`. There is no built in band and there must
//! never be one: a batch job and a chat endpoint disagree about a normal ratio by
//! orders of magnitude, so any constant here would be wrong for most workloads
//! while looking authoritative in every report.
//!
//! **A file that exists and cannot be used is never skipped.** It becomes a
//! `POLICY_LOAD_ERROR` diagnostic and a failing rule hit, so the run cannot exit
//! zero on a policy nobody applied. Falling back to defaults quietly would be the
//! exact defect this product exists to find elsewhere: a control that is present,
//! inert, and reported as fine.
//!
//! **The policy that was read is named in the report.** Without
//! `policy_ref.policy_id`, `policy_version` and `policy_hash` an auditor cannot
//! say which rules produced a verdict.
//!
//! **A rule block this build does not evaluate is declared.** The three rule
//! blocks ADR-006 closes are parsed here and evaluated nowhere yet. Swallowing
//! them would let a user write a `fail` condition, see a passing report, and
//! believe the condition held.

use std::path::{Path, PathBuf};

use periskop_reconcile::settings::{ReconcileSettings, VolumeBand};
use periskop_report::report::{
    Diagnostic, DiagnosticCode, DiagnosticComponent, PolicyRef, RuleHit, Verdict,
};
use serde::Deserialize;

/// Where a project's policy lives when the caller does not say.
///
/// Fixed by `docs/02-components/reporting/spec.md` §2.1 and repeated in the
/// policy contract: the project root, under this name.
pub const POLICY_FILE_NAME: &str = "periskop-policy.toml";

/// Rule id recorded when a policy file was present and could not be applied.
///
/// A sibling of the rule set gate in [`crate::scan`], and load bearing for the
/// same reason: the verdict is computed from rule hits alone, so a run whose
/// policy did not load has to record one here or it exits zero with a report
/// that looks clean.
const POLICY_GATE: &str = "engine.policy-loaded";

/// Identity of the policy a run had none of.
///
/// A report has to name a policy even when there was no file, because the block
/// is required and a reader still has to be able to tell two runs apart. This is
/// the honest spelling of "the engine's own defaults": it names no document, and
/// its hash is over that name rather than over any file's bytes.
const NO_POLICY_ID: &str = "engine-default";
const NO_POLICY_VERSION: &str = "1.0.0";

/// What went wrong with a policy file that was there.
///
/// Every variant names one cause. There is no catch all, because a run that
/// cannot say why it refused a policy leaves the reader nothing to fix.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("the file could not be read: {source}")]
    NotReadable {
        #[source]
        source: std::io::Error,
    },

    #[error("the file is not valid TOML, or carries a field this build does not know: {source}")]
    Malformed {
        #[source]
        source: toml::de::Error,
    },

    /// `max_basis_points` below `min_basis_points`.
    ///
    /// Refused rather than reordered. An inverted band admits nothing, so every
    /// matched flow would be an anomaly; swapping the edges would produce a
    /// working band nobody wrote and hide the typo that produced it.
    #[error("volume_band is inverted: max_basis_points is below min_basis_points")]
    InvertedVolumeBand,

    /// A dormancy window of zero.
    ///
    /// The schema refuses it and so does this: a zero window would let a run
    /// that watched nothing report every egress point in the repository as dead
    /// code. Clamping it to one millisecond, which the engine's own setter does,
    /// would honour a value the policy author did not write.
    #[error("min_dormant_window_ms is zero, which would let a run that watched nothing report every egress point as dead code")]
    ZeroDormantWindow,
}

/// The policy file, as this build reads it.
///
/// `deny_unknown_fields` is the contract's rule 2 made structural: a table this
/// build does not know is a load error rather than a silent no-op. A policy
/// author who misspells `reconciliation` has to be told, not quietly given the
/// defaults.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    policy: DocumentIdentity,
    #[serde(default)]
    defaults: Option<Defaults>,
    #[serde(default)]
    reconciliation: Option<Reconciliation>,
    // The three rule blocks ADR-006 closes. Read so they can be named in the
    // report, evaluated nowhere in this build.
    #[serde(default)]
    threshold: Vec<RuleBlock>,
    #[serde(default)]
    condition: Vec<RuleBlock>,
    #[serde(default)]
    coverage_condition: Vec<RuleBlock>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentIdentity {
    name: String,
    version: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Defaults {
    #[serde(default)]
    severity: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reconciliation {
    #[serde(default)]
    volume_band: Option<Band>,
    #[serde(default)]
    min_dormant_window_ms: Option<u64>,
    #[serde(default)]
    join_tolerance_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Band {
    min_basis_points: u64,
    max_basis_points: u64,
}

/// One rule block, read for its name alone.
///
/// Deliberately not `deny_unknown_fields`: the rest of a rule block is the part
/// this build does not evaluate, and refusing to parse it would turn "not
/// evaluated" into "not loadable" for every policy that carries one.
#[derive(Debug, Deserialize)]
struct RuleBlock {
    id: String,
}

/// What a policy file said, and what a run does when there was none.
///
/// Carried as one value rather than three arguments so a caller cannot pass the
/// settings from one policy and the identity of another.
#[derive(Debug, Clone)]
pub struct ScanPolicy {
    settings: ReconcileSettings,
    policy_id: String,
    policy_version: String,
    policy_hash: String,
    /// Things the run has to say about the policy itself: a file it refused, or
    /// rules it read and did not evaluate.
    notices: Vec<PolicyNotice>,
    /// Whether the verdict must be held down because a policy was present and
    /// not applied.
    refused: bool,
}

/// One statement about the policy, in the shape the report takes.
#[derive(Debug, Clone)]
struct PolicyNotice {
    code: DiagnosticCode,
    detail: String,
}

impl Default for ScanPolicy {
    /// The run with no policy file: engine defaults and no band.
    fn default() -> Self {
        Self::of(ReconcileSettings::default())
    }
}

impl From<ReconcileSettings> for ScanPolicy {
    fn from(settings: ReconcileSettings) -> Self {
        Self::of(settings)
    }
}

impl ScanPolicy {
    /// Settings a caller states directly, with no document behind them.
    ///
    /// The library entry points take this shape, so a caller that has no policy
    /// file is not made to invent one.
    fn of(settings: ReconcileSettings) -> Self {
        Self {
            settings,
            policy_id: NO_POLICY_ID.to_owned(),
            policy_version: NO_POLICY_VERSION.to_owned(),
            policy_hash: hash_of(format!("{NO_POLICY_ID}/{NO_POLICY_VERSION}").as_bytes()),
            notices: Vec::new(),
            refused: false,
        }
    }

    /// The run that found a policy file it could not use.
    ///
    /// Keeps the engine defaults, because there is nothing else to run with, and
    /// records both halves of what happened: a diagnostic naming the cause and a
    /// failing rule hit, so no pipeline reads the run as a pass.
    ///
    /// The file name travels, never the path. An absolute path would put the
    /// build machine into a report two machines are supposed to compare byte for
    /// byte.
    fn refused(file_name: &str, error: &PolicyError) -> Self {
        let mut policy = Self::of(ReconcileSettings::default());
        policy.refused = true;
        policy.notices.push(PolicyNotice {
            code: DiagnosticCode::PolicyLoadError,
            detail: format!("policy file {file_name} was not applied: {error}"),
        });
        policy
    }

    pub fn settings(&self) -> &ReconcileSettings {
        &self.settings
    }

    /// The diagnostics this policy owes the report.
    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        self.notices
            .iter()
            .map(|notice| Diagnostic {
                code: notice.code,
                component: DiagnosticComponent::Reporting,
                detail: Some(notice.detail.clone()),
            })
            .collect()
    }

    /// The rule hit that stops a run with an unapplied policy from passing.
    pub fn rule_hits(&self) -> Vec<RuleHit> {
        if !self.refused {
            return Vec::new();
        }
        vec![RuleHit {
            rule_id: POLICY_GATE.to_owned(),
            verdict: Verdict::Fail,
            finding_ids: None,
            coverage_condition: None,
        }]
    }

    /// The block that lets a reader say which rules produced this verdict.
    pub fn policy_ref(&self, rule_hits: Vec<RuleHit>) -> PolicyRef {
        PolicyRef {
            policy_id: self.policy_id.clone(),
            policy_version: self.policy_version.clone(),
            policy_hash: self.policy_hash.clone(),
            rule_hits,
        }
    }
}

/// Where this run's policy file is, if it has one.
///
/// An explicit path that is not there is an error for the caller to report, the
/// same way a missing `--events` directory is: a mistyped policy path must not
/// silently become the default policy. The project root is only looked in when
/// the caller named nothing, and finding no file there is the ordinary case.
pub fn resolve(explicit: Option<PathBuf>, project_root: &Path) -> Result<Option<PathBuf>, PathBuf> {
    match explicit {
        Some(path) if path.is_file() => Ok(Some(path)),
        Some(path) => Err(path),
        None => {
            let default = project_root.join(POLICY_FILE_NAME);
            Ok(default.is_file().then_some(default))
        }
    }
}

/// Reads a policy file into the shape the scan takes.
///
/// Never fails: a file this build cannot use produces a [`ScanPolicy`] that says
/// so and fails the verdict, which is what keeps the refusal in the report
/// instead of on somebody's terminal.
pub fn load(path: &Path) -> ScanPolicy {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(POLICY_FILE_NAME)
        .to_owned();

    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(source) => {
            return ScanPolicy::refused(&file_name, &PolicyError::NotReadable { source })
        }
    };

    match parse(&bytes) {
        Ok(mut policy) => {
            // The hash is over the file's bytes rather than over the values this
            // build understood, so a policy that gains a block this build
            // ignores still changes the identity in the report.
            policy.policy_hash = hash_of(&bytes);
            policy
        }
        Err(error) => ScanPolicy::refused(&file_name, &error),
    }
}

/// The document, validated into settings.
fn parse(bytes: &[u8]) -> Result<ScanPolicy, PolicyError> {
    let text = String::from_utf8_lossy(bytes);
    let document: PolicyDocument =
        toml::from_str(&text).map_err(|source| PolicyError::Malformed { source })?;

    let mut settings = ReconcileSettings::default();
    if let Some(reconciliation) = &document.reconciliation {
        if let Some(band) = &reconciliation.volume_band {
            let declared = VolumeBand::declared(band.min_basis_points, band.max_basis_points)
                .map_err(|_| PolicyError::InvertedVolumeBand)?;
            settings = settings.with_volume_band(declared);
        }
        if let Some(window_ms) = reconciliation.min_dormant_window_ms {
            // Checked here rather than handed to the setter, which clamps a zero
            // up to one millisecond. Clamping would honour a threshold the
            // author did not write and leave no trace of the substitution.
            if window_ms == 0 {
                return Err(PolicyError::ZeroDormantWindow);
            }
            settings = settings.with_min_dormant_window_ms(window_ms);
        }
        if let Some(tolerance_ms) = reconciliation.join_tolerance_ms {
            settings = settings.with_join_tolerance_ms(tolerance_ms);
        }
    }

    let mut policy = ScanPolicy::of(settings);
    policy.policy_id = document.policy.name.clone();
    policy.policy_version = document.policy.version.to_string();
    policy.notices = unevaluated_notices(&document);
    Ok(policy)
}

/// What the file asked for that this build does not do.
///
/// Two claims, and both would otherwise be invisible. A rule block is a verdict
/// the author expects and this build never evaluates, and `[defaults].severity`
/// is the severity of a finding no rule matched, which needs the same evaluator.
/// A user who writes a `fail` condition and reads a passing report has been told
/// something untrue, and that is the defect this product exists to find in other
/// people's systems.
fn unevaluated_notices(document: &PolicyDocument) -> Vec<PolicyNotice> {
    let mut named: Vec<String> = Vec::new();
    for (block, rules) in [
        ("threshold", &document.threshold),
        ("condition", &document.condition),
        ("coverage_condition", &document.coverage_condition),
    ] {
        named.extend(rules.iter().map(|rule| format!("{block}:{}", rule.id)));
    }
    // Sorted, because the order rules appear in a file must not decide the bytes
    // of a report two runs are supposed to compare equal.
    named.sort();

    let mut notices = Vec::new();
    if !named.is_empty() {
        notices.push(PolicyNotice {
            code: DiagnosticCode::PolicyLoadError,
            detail: format!(
                "policy rule blocks are not evaluated by this build, so they decided nothing in \
                 this report: {}",
                named.join(", ")
            ),
        });
    }
    if document
        .defaults
        .as_ref()
        .is_some_and(|defaults| defaults.severity.is_some())
    {
        notices.push(PolicyNotice {
            code: DiagnosticCode::PolicyLoadError,
            detail: "policy [defaults].severity is not evaluated by this build, so the severity \
                     of an unmatched finding came from the engine rather than from the policy"
                .to_owned(),
        });
    }
    notices
}

fn hash_of(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn policy_from(text: &str) -> ScanPolicy {
        parse(text.as_bytes()).unwrap()
    }

    const MINIMAL: &str = r#"
[policy]
name = "acme-egress"
version = 3
"#;

    #[test]
    fn a_declared_band_reaches_the_engine_settings() {
        // The whole point of the module: before it existed the field could be
        // written and nothing read it, so `volume_anomaly` could not be produced
        // by any real pipeline run.
        let policy = policy_from(
            r#"
[policy]
name = "acme-egress"
version = 3

[reconciliation]
volume_band = { min_basis_points = 5000, max_basis_points = 30000 }
"#,
        );
        let band = policy.settings().volume_band().expect("band declared");
        assert_eq!(band.min_basis_points(), 5_000);
        assert_eq!(band.max_basis_points(), 30_000);
    }

    #[test]
    fn a_policy_without_a_band_leaves_the_engine_with_none() {
        // Not a default band, and not a zero one. The absence is the reason a
        // kind is missing from the report, and inventing a number here would put
        // an authoritative looking threshold in every report that has none.
        assert_eq!(policy_from(MINIMAL).settings().volume_band(), None);
    }

    #[test]
    fn the_two_thresholds_that_have_defaults_are_replaced_when_declared() {
        let policy = policy_from(
            r#"
[policy]
name = "acme-egress"
version = 3

[reconciliation]
min_dormant_window_ms = 900000
join_tolerance_ms = 2000
"#,
        );
        assert_eq!(policy.settings().min_dormant_window_ms(), 900_000);
        assert_eq!(policy.settings().join_tolerance_ms(), 2_000);
    }

    #[test]
    fn an_inverted_band_is_refused_rather_than_reordered() {
        let error = parse(
            r#"
[policy]
name = "acme-egress"
version = 3

[reconciliation]
volume_band = { min_basis_points = 30000, max_basis_points = 5000 }
"#
            .as_bytes(),
        )
        .unwrap_err();
        assert!(matches!(error, PolicyError::InvertedVolumeBand));
    }

    #[test]
    fn a_zero_dormant_window_is_refused_rather_than_clamped() {
        // The engine's setter clamps it to one millisecond. Clamping here would
        // honour a threshold the author did not write.
        let error = parse(
            r#"
[policy]
name = "acme-egress"
version = 3

[reconciliation]
min_dormant_window_ms = 0
"#
            .as_bytes(),
        )
        .unwrap_err();
        assert!(matches!(error, PolicyError::ZeroDormantWindow));
    }

    #[test]
    fn a_misspelled_table_is_a_load_error_rather_than_a_silent_default() {
        // The failure this prevents: a policy author writes `reconcilliation`,
        // reads a report with no volume findings, and concludes the traffic was
        // within the band they declared.
        let error = parse(
            r#"
[policy]
name = "acme-egress"
version = 3

[reconcilliation]
min_dormant_window_ms = 60000
"#
            .as_bytes(),
        )
        .unwrap_err();
        assert!(matches!(error, PolicyError::Malformed { .. }));
    }

    #[test]
    fn a_floating_point_band_is_a_load_error() {
        // ADR-006 takes no floating point: 0.5 is a load error rather than a
        // value the loader interprets as fifty percent.
        let error = parse(
            r#"
[policy]
name = "acme-egress"
version = 3

[reconciliation]
volume_band = { min_basis_points = 0.5, max_basis_points = 3.0 }
"#
            .as_bytes(),
        )
        .unwrap_err();
        assert!(matches!(error, PolicyError::Malformed { .. }));
    }

    #[test]
    fn a_refused_policy_fails_the_verdict_and_names_the_file() {
        let policy = ScanPolicy::refused("periskop-policy.toml", &PolicyError::InvertedVolumeBand);
        let hits = policy.rule_hits();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].verdict, Verdict::Fail);
        let diagnostics = policy.diagnostics();
        assert_eq!(diagnostics[0].code, DiagnosticCode::PolicyLoadError);
        assert!(diagnostics[0]
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("periskop-policy.toml")));
    }

    #[test]
    fn a_policy_that_loaded_cleanly_holds_nothing_down() {
        let policy = policy_from(MINIMAL);
        assert!(policy.rule_hits().is_empty());
        assert!(policy.diagnostics().is_empty());
        assert_eq!(policy.policy_ref(Vec::new()).policy_id, "acme-egress");
        assert_eq!(policy.policy_ref(Vec::new()).policy_version, "3");
    }

    #[test]
    fn rule_blocks_this_build_does_not_evaluate_are_declared_rather_than_swallowed() {
        // A user who writes a `fail` condition and reads a passing report has
        // been told something untrue.
        let policy = policy_from(
            r#"
[policy]
name = "acme-egress"
version = 3

[[condition]]
id = "no-unmatched-traffic"
when = { field = "kind", equals = "unmatched_wire_traffic" }
severity = "fail"

[[threshold]]
id = "at-most-ten-points"
applies = { kind = "declared_egress_point" }
max = 10
on_exceed = "warn"
"#,
        );
        let detail = policy.diagnostics()[0].detail.clone().unwrap();
        assert!(
            detail.contains("condition:no-unmatched-traffic"),
            "{detail}"
        );
        assert!(detail.contains("threshold:at-most-ten-points"), "{detail}");
        // Declared, not fatal: the policy still loaded and its thresholds apply.
        assert!(policy.rule_hits().is_empty());
    }

    #[test]
    fn an_unevaluated_default_severity_is_declared_too() {
        let policy = policy_from(
            r#"
[policy]
name = "acme-egress"
version = 3

[defaults]
severity = "fail"
"#,
        );
        assert!(policy.diagnostics()[0]
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("[defaults].severity")));
    }

    #[test]
    fn two_policies_with_different_bytes_get_different_identities() {
        // The hash is over the file rather than over the fields this build read,
        // so a block this build ignores still changes what the report says it
        // ran under.
        assert_ne!(
            hash_of(MINIMAL.as_bytes()),
            hash_of(b"[policy]\nname=\"a\"\nversion=1\n")
        );
        assert_eq!(hash_of(MINIMAL.as_bytes()).len(), 64);
    }

    #[test]
    fn a_run_with_no_policy_still_names_something_a_reader_can_compare() {
        let policy = ScanPolicy::default();
        let reference = policy.policy_ref(Vec::new());
        assert_eq!(reference.policy_id, NO_POLICY_ID);
        assert_eq!(reference.policy_hash.len(), 64);
        assert_eq!(policy.settings().volume_band(), None);
    }
}
