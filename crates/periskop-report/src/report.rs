//! Building and serializing a scan report.
//!
//! The report is meant to be diffed. Two runs over an unchanged tree must produce
//! identical bytes, so that a diff shows a change in the code rather than a change
//! in the weather.
//!
//! Three things follow from that and each is enforced here rather than left to
//! the caller. Arrays are ordered when the report is built. Object keys are
//! emitted in a fixed order at serialization. And every value that varies between
//! runs for reasons unrelated to the code, the clock and the machine name, lives
//! in the envelope, which is the one block excluded from the body hash.

use serde::{Deserialize, Serialize};

use periskop_core::finding::{Confidence, Finding};

use crate::coverage::CoverageStatement;

/// The three outcomes a run may report, ordered from weakest to strongest.
///
/// One enum, not two. A second copy existed only to carry an `Ord` derive for
/// sorting rule hits, and the schema binds both `RuleHit.verdict` and
/// `ScanReport.verdict` to the same list: a fourth value added to one copy and
/// not the other would have given the two fields different vocabularies while
/// the contract said they shared one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Verdict {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "WARN")]
    Warn,
    #[serde(rename = "FAIL")]
    Fail,
}

/// Time and environment. Deliberately outside the hashed body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub generated_at: String,
    pub tool_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RuleHit {
    pub rule_id: String,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_ids: Option<Vec<String>>,
    /// Present when the hit came from a coverage threshold rather than a finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage_condition: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRef {
    pub policy_id: String,
    pub policy_version: String,
    pub policy_hash: String,
    pub rule_hits: Vec<RuleHit>,
}

/// The thresholds a verdict is allowed to come from.
///
/// Held as data rather than buried in a branch, because the report has to name
/// the threshold that fired and the value it fired on. A verdict a reader cannot
/// trace back to a declared rule is not auditable, and an unauditable gate is one
/// nobody can argue with when it is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// How many confirmed findings before the scan fails. `None` by default.
    ///
    /// Finding a confirmed egress point is what this tool is for, not evidence
    /// that something is wrong. A repository that calls a model provider on
    /// purpose would fail every build, and a gate that fires on the intended case
    /// gets switched off, taking the real signal with it. What the default does
    /// instead is record the confirmed findings it saw and pass on them
    /// deliberately, so the pass is a decision in the report rather than an
    /// absence of one. An operator who wants the gate sets a number here.
    pub confirmed_findings_fail: Option<u64>,
    /// How many suspect findings before the scan warns.
    ///
    /// One is enough. A suspect finding is the scanner saying it saw something it
    /// could not prove structurally, which is precisely the case that needs a
    /// human. This is a finding threshold, not a coverage gap, so K-20 does not
    /// speak to it; report-schema.md lists it as a warning source directly.
    pub suspect_findings_warn: Option<u64>,
    /// Unreadable share of the code surface, in basis points, before the scan
    /// warns. `None` by default.
    ///
    /// K-20: a coverage gap never warns on its own. A default low enough to be
    /// useful would fire nearly everywhere, because the ratio counts every file
    /// the scanner has no grammar for, and a run that is always yellow teaches
    /// the reader to stop reading yellow. The gap stays fully visible in the
    /// coverage block regardless, the rule hit below records the ratio that was
    /// observed, and the CLI already offers `--max-unparsed-ratio` for an operator
    /// who wants a hard gate with its own exit code.
    pub unparsed_ratio_warn: Option<u64>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            confirmed_findings_fail: None,
            suspect_findings_warn: Some(1),
            unparsed_ratio_warn: None,
        }
    }
}

/// What the run was pointed at.
///
/// `scan_run_id` is derived from the canonical form of the scan inputs
/// (`data-model.md` §2). A caller that knows which tree it walked and which rule
/// set it loaded declares them here. A caller that does not leaves them empty,
/// and the identity rests on the digest of what the run produced, which is a
/// function of the same inputs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanInputs {
    /// Stable identity of the scanned tree. Never an absolute path: that would
    /// put the build machine into an identity that has to compare equal across
    /// machines.
    pub scan_root_id: String,
    /// Digest of the rule set that was loaded.
    pub rule_set_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DiagnosticCode {
    #[serde(rename = "UNSUPPORTED_SCHEMA_VERSION")]
    UnsupportedSchemaVersion,
    #[serde(rename = "CORE_UNAVAILABLE")]
    CoreUnavailable,
    #[serde(rename = "RULE_LOAD_ERROR")]
    RuleLoadError,
    #[serde(rename = "POLICY_LOAD_ERROR")]
    PolicyLoadError,
    #[serde(rename = "INTERNAL")]
    Internal,
}

impl DiagnosticCode {
    /// The spelling the contract uses.
    ///
    /// Written out rather than left to `{:?}`, because the debug spelling is the
    /// Rust variant name and the report says `RULE_LOAD_ERROR`. A reader who saw
    /// `RuleLoadError` on the terminal and searched the JSON for it found
    /// nothing, which turns one fact into two vocabularies for no gain.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedSchemaVersion => "UNSUPPORTED_SCHEMA_VERSION",
            Self::CoreUnavailable => "CORE_UNAVAILABLE",
            Self::RuleLoadError => "RULE_LOAD_ERROR",
            Self::PolicyLoadError => "POLICY_LOAD_ERROR",
            Self::Internal => "INTERNAL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticComponent {
    StaticScanner,
    RuntimeHooks,
    NetworkSensor,
    Reconciliation,
    Reporting,
}

impl DiagnosticComponent {
    /// The spelling the contract uses. Kebab case here, and that is not a typo:
    /// it is the documented exception recorded as K-09.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaticScanner => "static-scanner",
            Self::RuntimeHooks => "runtime-hooks",
            Self::NetworkSensor => "network-sensor",
            Self::Reconciliation => "reconciliation",
            Self::Reporting => "reporting",
        }
    }
}

/// An engine, rule or schema problem.
///
/// Kept strictly out of the coverage statement. Coverage counts what the scan
/// could not read; a rule that failed to load is a different thing, and mixing
/// the two makes any threshold over coverage meaningless.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: DiagnosticCode,
    pub component: DiagnosticComponent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: String,
    pub report_id: String,
    pub scan_run_id: String,
    pub envelope: Envelope,
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
    pub suspect_findings: Vec<Finding>,
    pub coverage: CoverageStatement,
    pub policy_ref: PolicyRef,
    pub diagnostics: Vec<Diagnostic>,
}

/// Version of the report document this build writes.
///
/// The coverage statement has no version of its own by contract: it is a sub
/// object of the report and inherits this one, so every field added there moves
/// this number.
///
/// `1.1` added `in_scope_flows`, the denominator the other flow buckets are read
/// against, and `unresolved_event_targets`, the calls whose destination the hook
/// could not read. Without them a 1.0 reader cannot compute the attribution ratio
/// K-15 states.
///
/// `1.2` added `rule_set_source`, which says whether the detectors that decided
/// the run were the shipped ones or a directory the caller named. A 1.1 reader
/// loses no field; what it cannot do is tell an archived report produced by the
/// set we ship apart from one produced by a local directory.
///
/// Every step here is a MINOR addition, so a reader of an older document keeps
/// everything it had.
pub const SCHEMA_VERSION: &str = "1.2";

/// Collects findings and produces a report.
///
/// The coverage statement is not held here. It is an argument to [`build`], so a
/// caller that forgets it does not compile. It used to default to an invented
/// statement claiming nought files read and nothing skipped, which reads as a
/// full clean scan of an empty tree and is indistinguishable from a caller that
/// never produced a statement at all.
///
/// [`build`]: ReportBuilder::build
#[derive(Debug, Default)]
pub struct ReportBuilder {
    findings: Vec<Finding>,
    diagnostics: Vec<Diagnostic>,
    policy: Policy,
    inputs: ScanInputs,
}

impl ReportBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the thresholds the verdict may come from.
    pub fn policy(&mut self, policy: Policy) -> &mut Self {
        self.policy = policy;
        self
    }

    /// Declares what the run was pointed at, so the run identity can rest on it.
    pub fn scan_inputs(&mut self, inputs: ScanInputs) -> &mut Self {
        self.inputs = inputs;
        self
    }

    pub fn add_findings(&mut self, findings: impl IntoIterator<Item = Finding>) -> &mut Self {
        self.findings.extend(findings);
        self
    }

    pub fn add_diagnostic(&mut self, diagnostic: Diagnostic) -> &mut Self {
        self.diagnostics.push(diagnostic);
        self
    }

    /// Produces the report.
    ///
    /// Confirmed and suspected findings are split into separate lists. A heuristic
    /// match sitting in the same list as a structural one would let a reader treat
    /// them as equally certain, which is exactly the collapse this product argues
    /// against.
    pub fn build(
        mut self,
        envelope: Envelope,
        policy_ref: PolicyRef,
        mut coverage: CoverageStatement,
    ) -> ScanReport {
        self.findings
            .sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
        self.findings.dedup_by(|a, b| a.finding_id == b.finding_id);

        let (suspect, confirmed): (Vec<Finding>, Vec<Finding>) = self
            .findings
            .into_iter()
            .partition(|f| f.confidence == Confidence::Suspect);

        coverage.normalize();

        let coverage_digest = match coverage_digest(&coverage) {
            Ok(digest) => digest,
            Err(e) => {
                // A missing digest weakens the run identity, so it is reported
                // rather than absorbed. An identity that quietly lost one of its
                // inputs looks exactly like one that did not.
                self.diagnostics.push(Diagnostic {
                    code: DiagnosticCode::Internal,
                    component: DiagnosticComponent::Reporting,
                    detail: Some(format!("coverage digest unavailable: {e}")),
                });
                String::new()
            }
        };

        self.diagnostics.sort();
        self.diagnostics.dedup();

        let mut policy_ref = policy_ref;
        policy_ref.rule_hits.extend(evaluate_policy(
            &self.policy,
            &confirmed,
            &suspect,
            &coverage,
        ));
        policy_ref.rule_hits.sort();
        policy_ref.rule_hits.dedup();

        let scan_run_id = derive_scan_run_id(
            &self.inputs,
            &confirmed,
            &suspect,
            &coverage_digest,
            &policy_ref.policy_hash,
        );
        let report_id = format!(
            "rpt_{}",
            periskop_core::ids::short_hash(
                "rp/v1",
                &[&scan_run_id, &policy_ref.policy_hash, SCHEMA_VERSION],
            )
        );

        let verdict = decide_verdict(&policy_ref);

        ScanReport {
            schema_version: SCHEMA_VERSION.to_owned(),
            report_id,
            scan_run_id,
            envelope,
            verdict,
            findings: confirmed,
            suspect_findings: suspect,
            coverage,
            policy_ref,
            diagnostics: self.diagnostics,
        }
    }
}

/// Evaluates the policy and records what it decided, rule by rule.
///
/// Every declared rule produces a hit, including the ones that pass. A report
/// that records only violations cannot be audited: an empty `rule_hits` reads the
/// same whether the policy passed everything or never ran at all, and the second
/// is what F1 shipped, with every verdict PASS and the findings never consulted.
/// `report-schema.md` makes the same point for coverage, where a PASS over a
/// known gap is only valid if a hit acknowledges the gap.
fn evaluate_policy(
    policy: &Policy,
    confirmed: &[Finding],
    suspect: &[Finding],
    coverage: &CoverageStatement,
) -> Vec<RuleHit> {
    let confirmed_ids: Vec<String> = confirmed.iter().map(|f| f.finding_id.clone()).collect();
    let fails = policy
        .confirmed_findings_fail
        .is_some_and(|limit| confirmed.len() as u64 >= limit);

    let suspect_ids: Vec<String> = suspect.iter().map(|f| f.finding_id.clone()).collect();
    let warns = policy
        .suspect_findings_warn
        .is_some_and(|limit| suspect.len() as u64 >= limit);

    // The coverage condition is written whether or not it fired. It is the only
    // place a reader can see which ratio the policy weighed and against what, and
    // a threshold that is invisible until it trips cannot be reviewed beforehand.
    let ratio = coverage.unparsed_ratio_basis_points();
    let (coverage_verdict, condition) = match policy.unparsed_ratio_warn {
        Some(limit) if ratio > limit => (
            Verdict::Warn,
            format!("coverage_unparsed_ratio {ratio} greater_than {limit}"),
        ),
        Some(limit) => (
            Verdict::Pass,
            format!("coverage_unparsed_ratio {ratio} within declared limit {limit}"),
        ),
        None => (
            Verdict::Pass,
            format!("coverage_unparsed_ratio {ratio}, policy declares no limit"),
        ),
    };

    vec![
        RuleHit {
            rule_id: "policy.confirmed-egress".to_owned(),
            verdict: if fails { Verdict::Fail } else { Verdict::Pass },
            finding_ids: (!confirmed_ids.is_empty()).then_some(confirmed_ids),
            coverage_condition: None,
        },
        RuleHit {
            rule_id: "policy.suspect-egress".to_owned(),
            verdict: if warns { Verdict::Warn } else { Verdict::Pass },
            finding_ids: (!suspect_ids.is_empty()).then_some(suspect_ids),
            coverage_condition: None,
        },
        RuleHit {
            rule_id: "policy.coverage-unparsed-ratio".to_owned(),
            verdict: coverage_verdict,
            finding_ids: None,
            coverage_condition: Some(condition),
        },
    ]
}

/// Decides the verdict from the rules that fired.
///
/// A coverage gap on its own never produces a warning. Warnings come from a
/// threshold the policy declared and a rule hit that records it. Wiring every gap
/// straight to a warning would leave the reader looking at a yellow screen on
/// every run, and a warning that is always on is a warning nobody reads.
///
/// Reading the hits rather than the findings is deliberate. Every input to this
/// decision has already been written into the report by the time it runs, so the
/// verdict can be recomputed from the report alone by anyone who doubts it.
fn decide_verdict(policy: &PolicyRef) -> Verdict {
    if policy.rule_hits.iter().any(|h| h.verdict == Verdict::Fail) {
        return Verdict::Fail;
    }
    if policy.rule_hits.iter().any(|h| h.verdict == Verdict::Warn) {
        return Verdict::Warn;
    }
    Verdict::Pass
}

/// The one coverage field the run identity is taken without.
///
/// Named here rather than written inline because it is a documented exception,
/// and an exception spelled as a bare string in the middle of a hash is one
/// nobody finds when they go looking for why two runs share an id.
const SOURCE_FIELD_OUTSIDE_IDENTITY: &str = "rule_set_source";

/// Digest of the coverage statement, as an input to the run identity.
///
/// Coverage is part of what makes one run different from another: the same
/// findings over a tree the scanner read in full and over one it barely read are
/// not the same run, and an identity that cannot tell them apart is worthless for
/// storing or diffing reports.
///
/// `rule_set_source` is the one field left out, and only out of this digest. What
/// the identity has to pin about the detectors is which ones ran, and
/// `rule_set_hash` already pins that by content. Where those same bytes were read
/// from is provenance for the reader, not an input to the analysis, so folding it
/// in would give two runs with identical detectors and identical findings two
/// different `scan_run_id`s. A reader comparing the two reports would see the
/// identity move and read it as "what was analysed changed", when the only
/// difference is a sentence about origin the body already states plainly.
///
/// The exclusion stops here. `body_hash` still covers the field, so a signature
/// covers it too: it does not rename the run, and nobody can edit it unnoticed.
/// The precedent is `envelope`, excluded from the body hash because a clock is
/// not a claim about the code.
fn coverage_digest(coverage: &CoverageStatement) -> Result<String, serde_json::Error> {
    let mut as_value = serde_json::to_value(coverage)?;
    if let Some(object) = as_value.as_object_mut() {
        object.remove(SOURCE_FIELD_OUTSIDE_IDENTITY);
    }
    let text = crate::serialize::to_canonical_json(&as_value)?;
    Ok(periskop_core::ids::short_hash("cv/v1", &[&text]))
}

/// Derives the run identity from what the run was pointed at and what it saw.
///
/// The contract derives this from the canonical form of the scan inputs. The two
/// declared inputs are used when a caller supplies them, and the digest of the
/// findings and the coverage statement is folded in either way, because the
/// report body is a total function of the tree and the rule set: two different
/// trees cannot reach the same digest.
///
/// What this replaces mattered. The identity used to be hashed from the *count*
/// of findings, so two unrelated repositories that each produced three findings
/// received the same `scan_run_id` and the same `report_id`, and a store keyed on
/// either one would overwrite one report with the other. Changing a finding from
/// one provider to another, or coverage from full to nearly none, left both
/// identifiers untouched.
fn derive_scan_run_id(
    inputs: &ScanInputs,
    confirmed: &[Finding],
    suspect: &[Finding],
    coverage_digest: &str,
    policy_hash: &str,
) -> String {
    let mut ids: Vec<&str> = Vec::with_capacity(confirmed.len() + suspect.len());
    ids.extend(confirmed.iter().map(|f| f.finding_id.as_str()));
    ids.extend(suspect.iter().map(|f| f.finding_id.as_str()));
    let findings_digest = periskop_core::ids::short_hash("sf/v1", &ids);

    let canonical_inputs = periskop_core::ids::short_hash(
        "si/v1",
        &[&inputs.scan_root_id, &findings_digest, coverage_digest],
    );
    format!(
        "scan_{}",
        periskop_core::ids::short_hash(
            "sr/v1",
            &[&canonical_inputs, &inputs.rule_set_hash, policy_hash],
        )
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::coverage::RuleSetSource;
    use periskop_core::finding::{
        Component, Detector, EntityRef, Evidence, EvidenceType, Kind, RefType,
    };

    /// The printed spelling and the serialized one are the same word.
    ///
    /// Pinned against `serde` rather than against a second literal list, because
    /// a second list is exactly the thing that drifts. A terminal that names a
    /// diagnostic `RuleLoadError` while the JSON beside it says
    /// `RULE_LOAD_ERROR` gives the reader two vocabularies for one fact and no
    /// way to search from one to the other.
    #[test]
    fn a_diagnostic_is_printed_in_the_words_the_contract_uses() {
        for code in [
            DiagnosticCode::UnsupportedSchemaVersion,
            DiagnosticCode::CoreUnavailable,
            DiagnosticCode::RuleLoadError,
            DiagnosticCode::PolicyLoadError,
            DiagnosticCode::Internal,
        ] {
            assert_eq!(
                serde_json::to_string(&code).unwrap(),
                format!("\"{}\"", code.as_str()),
                "{code:?}"
            );
        }

        for component in [
            DiagnosticComponent::StaticScanner,
            DiagnosticComponent::RuntimeHooks,
            DiagnosticComponent::NetworkSensor,
            DiagnosticComponent::Reconciliation,
            DiagnosticComponent::Reporting,
        ] {
            assert_eq!(
                serde_json::to_string(&component).unwrap(),
                format!("\"{}\"", component.as_str()),
                "{component:?}"
            );
        }
    }

    fn finding(confidence: Confidence, rule: &str) -> Finding {
        Finding::new(
            Kind::DeclaredEgressPoint,
            confidence,
            "openai",
            EntityRef {
                ref_type: RefType::EgressPoint,
                ref_id: "ep_0000000000000001".into(),
            },
            Evidence {
                evidence_type: EvidenceType::AstNode,
                r#ref: "call@a.py".into(),
                hash: None,
            },
            Detector {
                component: Component::StaticScanner,
                rule_id: rule.into(),
                rule_version: "1.0.0".into(),
                rule_hash: "0".repeat(64),
            },
        )
        .unwrap()
    }

    fn envelope() -> Envelope {
        Envelope {
            generated_at: "2026-08-04T09:00:00Z".into(),
            tool_version: "0.1.0".into(),
            host: None,
        }
    }

    fn policy(hits: Vec<RuleHit>) -> PolicyRef {
        PolicyRef {
            policy_id: "default".into(),
            policy_version: "1.0.0".into(),
            policy_hash: "a".repeat(64),
            rule_hits: hits,
        }
    }

    #[test]
    fn suspected_findings_are_carried_separately() {
        let mut b = ReportBuilder::new();
        b.add_findings([
            finding(Confidence::Confirmed, "python.static.a"),
            finding(Confidence::Suspect, "python.static.b"),
        ]);
        let report = b.build(
            envelope(),
            policy(vec![]),
            CoverageStatement::static_only(RuleSetSource::Embedded),
        );

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.suspect_findings.len(), 1);
        assert!(report
            .findings
            .iter()
            .all(|f| f.confidence == Confidence::Confirmed));
        assert!(report
            .suspect_findings
            .iter()
            .all(|f| f.confidence == Confidence::Suspect));
    }

    #[test]
    fn a_coverage_gap_alone_does_not_warn() {
        let b = ReportBuilder::new();
        let mut coverage = CoverageStatement::static_only(RuleSetSource::Embedded);
        coverage.parsed_files = 1;
        coverage.unparsed_files = vec![crate::coverage::UnparsedFile {
            path: "x.py".into(),
            reason: periskop_core::coverage::UnparsedReason::ParseError,
        }];
        let report = b.build(envelope(), policy(vec![]), coverage);

        assert_eq!(report.verdict, Verdict::Pass);
        // The gap is not hidden by passing. It is still there to read.
        assert_eq!(report.coverage.unparsed_files.len(), 1);
    }

    #[test]
    fn the_report_verdict_and_a_rule_hit_speak_one_vocabulary() {
        // Two byte identical enums used to exist, one of them only so rule hits
        // could be sorted. The schema binds both fields to the same list, so a
        // value added to one and not the other would have split the vocabulary
        // in a way nothing in the build would have caught.
        let hit = RuleHit {
            rule_id: "policy.confirmed-egress".into(),
            verdict: Verdict::Fail,
            finding_ids: None,
            coverage_condition: None,
        };
        let report = ReportBuilder::new().build(
            envelope(),
            policy(vec![hit.clone()]),
            CoverageStatement::static_only(RuleSetSource::Embedded),
        );

        assert_eq!(report.verdict, hit.verdict);
        assert_eq!(
            serde_json::to_value(report.verdict).unwrap(),
            serde_json::to_value(hit.verdict).unwrap()
        );
        // Ordering runs from weakest to strongest, which is what lets the verdict
        // be read off the strongest hit.
        assert!(Verdict::Pass < Verdict::Warn && Verdict::Warn < Verdict::Fail);
    }

    #[test]
    fn a_declared_threshold_is_what_warns() {
        let report = ReportBuilder::new().build(
            envelope(),
            policy(vec![RuleHit {
                rule_id: "coverage.unparsed-ratio".into(),
                verdict: Verdict::Warn,
                finding_ids: None,
                coverage_condition: Some("coverage_unparsed_ratio > 500".into()),
            }]),
            CoverageStatement::static_only(RuleSetSource::Embedded),
        );
        assert_eq!(report.verdict, Verdict::Warn);
    }

    #[test]
    fn a_gap_over_the_declared_limit_warns_and_says_which_limit() {
        let mut b = ReportBuilder::new();
        b.policy(Policy {
            unparsed_ratio_warn: Some(500),
            ..Policy::default()
        });
        let mut coverage = CoverageStatement::static_only(RuleSetSource::Embedded);
        coverage.parsed_files = 1;
        coverage.unparsed_files = vec![crate::coverage::UnparsedFile {
            path: "x.py".into(),
            reason: periskop_core::coverage::UnparsedReason::ParseError,
        }];
        let report = b.build(envelope(), policy(vec![]), coverage);

        assert_eq!(report.verdict, Verdict::Warn);
        // K-20's other half: the threshold that produced the warning is written
        // into the report, so the warning can be argued with.
        let hit = report
            .policy_ref
            .rule_hits
            .iter()
            .find(|h| h.rule_id == "policy.coverage-unparsed-ratio")
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Warn);
        assert_eq!(
            hit.coverage_condition.as_deref(),
            Some("coverage_unparsed_ratio 5000 greater_than 500")
        );
    }

    #[test]
    fn the_policy_records_what_it_decided_even_when_it_passes() {
        // The bug this pins: F1 left rule_hits empty on every run, so a pass could
        // not be told apart from a policy that never ran, and the verdict was PASS
        // whatever the findings said.
        let mut b = ReportBuilder::new();
        b.add_findings([finding(Confidence::Confirmed, "python.static.a")]);
        let report = b.build(
            envelope(),
            policy(vec![]),
            CoverageStatement::static_only(RuleSetSource::Embedded),
        );

        assert_eq!(report.verdict, Verdict::Pass);
        let hit = report
            .policy_ref
            .rule_hits
            .iter()
            .find(|h| h.rule_id == "policy.confirmed-egress")
            .unwrap();
        assert_eq!(hit.verdict, Verdict::Pass);
        assert_eq!(
            hit.finding_ids.as_deref(),
            Some(&[report.findings[0].finding_id.clone()][..]),
            "the pass has to name the findings it passed on"
        );
    }

    #[test]
    fn a_confirmed_finding_fails_once_the_policy_declares_a_limit() {
        let mut b = ReportBuilder::new();
        b.policy(Policy {
            confirmed_findings_fail: Some(1),
            ..Policy::default()
        });
        b.add_findings([finding(Confidence::Confirmed, "python.static.a")]);
        let report = b.build(
            envelope(),
            policy(vec![]),
            CoverageStatement::static_only(RuleSetSource::Embedded),
        );

        assert_eq!(report.verdict, Verdict::Fail);
    }

    #[test]
    fn a_suspect_finding_warns_by_default() {
        // Not a coverage gap, so K-20 does not apply: the scanner saw something it
        // could not prove, which is the case a human is meant to look at.
        let mut b = ReportBuilder::new();
        b.add_findings([finding(Confidence::Suspect, "python.static.b")]);
        let report = b.build(
            envelope(),
            policy(vec![]),
            CoverageStatement::static_only(RuleSetSource::Embedded),
        );

        assert_eq!(report.verdict, Verdict::Warn);
    }

    #[test]
    fn the_same_input_produces_the_same_identifiers() {
        let build = || {
            let mut b = ReportBuilder::new();
            b.add_findings([finding(Confidence::Confirmed, "python.static.a")]);
            b.build(
                envelope(),
                policy(vec![]),
                CoverageStatement::static_only(RuleSetSource::Embedded),
            )
        };
        let a = build();
        let b = build();
        assert_eq!(a.report_id, b.report_id);
        assert_eq!(a.scan_run_id, b.scan_run_id);
    }

    #[test]
    fn two_unrelated_scans_of_the_same_size_get_different_identities() {
        // The bug this pins: identities were hashed from the *count* of findings,
        // so two repositories with nothing in common collided as long as they
        // produced the same number of findings, and a store keyed on report_id
        // overwrote one with the other.
        let build = |rule: &str| {
            let mut b = ReportBuilder::new();
            b.add_findings([finding(Confidence::Confirmed, rule)]);
            b.build(
                envelope(),
                policy(vec![]),
                CoverageStatement::static_only(RuleSetSource::Embedded),
            )
        };
        let a = build("python.static.openai");
        let b = build("typescript.static.anthropic");

        assert_eq!(a.findings.len(), b.findings.len());
        assert_ne!(a.scan_run_id, b.scan_run_id);
        assert_ne!(a.report_id, b.report_id);
    }

    #[test]
    fn the_same_findings_over_different_coverage_are_different_runs() {
        // A tree the scanner read in full and one it barely read are not the same
        // run even when they yield the same findings, and the identity has to say
        // so or a diff of two stored reports shows nothing.
        let build = |parsed_files: u64| {
            let mut b = ReportBuilder::new();
            b.add_findings([finding(Confidence::Confirmed, "python.static.a")]);
            let mut coverage = CoverageStatement::static_only(RuleSetSource::Embedded);
            coverage.parsed_files = parsed_files;
            b.build(envelope(), policy(vec![]), coverage)
        };
        assert_ne!(build(400).scan_run_id, build(4).scan_run_id);
    }

    #[test]
    fn declared_scan_inputs_reach_the_identity() {
        let build = |root: &str| {
            let mut b = ReportBuilder::new();
            b.scan_inputs(ScanInputs {
                scan_root_id: root.into(),
                rule_set_hash: "c".repeat(64),
            });
            b.build(
                envelope(),
                policy(vec![]),
                CoverageStatement::static_only(RuleSetSource::Embedded),
            )
        };
        assert_ne!(build("repo-a").scan_run_id, build("repo-b").scan_run_id);
    }

    #[test]
    fn findings_are_ordered_regardless_of_insertion_order() {
        let make = |order: [&str; 2]| {
            let mut b = ReportBuilder::new();
            b.add_findings(order.map(|r| finding(Confidence::Confirmed, r)));
            b.build(
                envelope(),
                policy(vec![]),
                CoverageStatement::static_only(RuleSetSource::Embedded),
            )
            .findings
        };
        let forward = make(["python.static.a", "python.static.b"]);
        let reverse = make(["python.static.b", "python.static.a"]);
        assert_eq!(forward, reverse);
    }

    #[test]
    fn a_repeated_finding_is_counted_once() {
        let mut b = ReportBuilder::new();
        b.add_findings([
            finding(Confidence::Confirmed, "python.static.a"),
            finding(Confidence::Confirmed, "python.static.a"),
        ]);
        assert_eq!(
            b.build(
                envelope(),
                policy(vec![]),
                CoverageStatement::static_only(RuleSetSource::Embedded)
            )
            .findings
            .len(),
            1
        );
    }
}
