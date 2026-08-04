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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    pub verdict: VerdictOrder,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_ids: Option<Vec<String>>,
    /// Present when the hit came from a coverage threshold rather than a finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage_condition: Option<String>,
}

/// Same values as [`Verdict`], with an ordering so rule hits can be sorted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VerdictOrder {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "WARN")]
    Warn,
    #[serde(rename = "FAIL")]
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRef {
    pub policy_id: String,
    pub policy_version: String,
    pub policy_hash: String,
    pub rule_hits: Vec<RuleHit>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticComponent {
    StaticScanner,
    RuntimeHooks,
    NetworkSensor,
    Reconciliation,
    Reporting,
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

pub const SCHEMA_VERSION: &str = "1.0";

/// Collects findings and produces a report.
#[derive(Debug, Default)]
pub struct ReportBuilder {
    findings: Vec<Finding>,
    coverage: Option<CoverageStatement>,
    diagnostics: Vec<Diagnostic>,
}

impl ReportBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_findings(&mut self, findings: impl IntoIterator<Item = Finding>) -> &mut Self {
        self.findings.extend(findings);
        self
    }

    pub fn coverage(&mut self, mut coverage: CoverageStatement) -> &mut Self {
        coverage.normalize();
        self.coverage = Some(coverage);
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
    pub fn build(mut self, envelope: Envelope, policy_ref: PolicyRef) -> ScanReport {
        self.findings
            .sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
        self.findings.dedup_by(|a, b| a.finding_id == b.finding_id);

        let (suspect, confirmed): (Vec<Finding>, Vec<Finding>) = self
            .findings
            .into_iter()
            .partition(|f| f.confidence == Confidence::Suspect);

        let mut coverage = self.coverage.unwrap_or_else(CoverageStatement::static_only);
        coverage.normalize();

        self.diagnostics.sort();
        self.diagnostics.dedup();

        let mut policy_ref = policy_ref;
        policy_ref.rule_hits.sort();

        let scan_run_id = format!(
            "scan_{}",
            periskop_core::ids::short_hash(
                "sr/v1",
                &[
                    &confirmed.len().to_string(),
                    &suspect.len().to_string(),
                    &policy_ref.policy_hash,
                ],
            )
        );
        let report_id = format!(
            "rpt_{}",
            periskop_core::ids::short_hash(
                "rp/v1",
                &[&scan_run_id, &policy_ref.policy_hash, SCHEMA_VERSION],
            )
        );

        let verdict = decide_verdict(&confirmed, &policy_ref);

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

/// Decides the verdict from findings and the rules that fired.
///
/// A coverage gap on its own never produces a warning. Warnings come from a
/// threshold the policy declared and a rule hit that records it. Wiring every gap
/// straight to a warning would leave the reader looking at a yellow screen on
/// every run, and a warning that is always on is a warning nobody reads.
fn decide_verdict(confirmed: &[Finding], policy: &PolicyRef) -> Verdict {
    if policy
        .rule_hits
        .iter()
        .any(|h| h.verdict == VerdictOrder::Fail)
    {
        return Verdict::Fail;
    }
    if policy
        .rule_hits
        .iter()
        .any(|h| h.verdict == VerdictOrder::Warn)
    {
        return Verdict::Warn;
    }
    let _ = confirmed;
    Verdict::Pass
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use periskop_core::finding::{
        Component, Detector, EntityRef, Evidence, EvidenceType, Kind, RefType,
    };

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
        let report = b.build(envelope(), policy(vec![]));

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
        let mut b = ReportBuilder::new();
        let mut coverage = CoverageStatement::static_only();
        coverage.parsed_files = 1;
        coverage.unparsed_files = vec![crate::coverage::UnparsedFile {
            path: "x.py".into(),
            reason: periskop_core::coverage::UnparsedReason::ParseError,
        }];
        b.coverage(coverage);
        let report = b.build(envelope(), policy(vec![]));

        assert_eq!(report.verdict, Verdict::Pass);
        // The gap is not hidden by passing. It is still there to read.
        assert_eq!(report.coverage.unparsed_files.len(), 1);
    }

    #[test]
    fn a_declared_threshold_is_what_warns() {
        let report = ReportBuilder::new().build(
            envelope(),
            policy(vec![RuleHit {
                rule_id: "coverage.unparsed-ratio".into(),
                verdict: VerdictOrder::Warn,
                finding_ids: None,
                coverage_condition: Some("coverage_unparsed_ratio > 500".into()),
            }]),
        );
        assert_eq!(report.verdict, Verdict::Warn);
    }

    #[test]
    fn the_same_input_produces_the_same_identifiers() {
        let build = || {
            let mut b = ReportBuilder::new();
            b.add_findings([finding(Confidence::Confirmed, "python.static.a")]);
            b.build(envelope(), policy(vec![]))
        };
        let a = build();
        let b = build();
        assert_eq!(a.report_id, b.report_id);
        assert_eq!(a.scan_run_id, b.scan_run_id);
    }

    #[test]
    fn findings_are_ordered_regardless_of_insertion_order() {
        let make = |order: [&str; 2]| {
            let mut b = ReportBuilder::new();
            b.add_findings(order.map(|r| finding(Confidence::Confirmed, r)));
            b.build(envelope(), policy(vec![])).findings
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
        assert_eq!(b.build(envelope(), policy(vec![])).findings.len(), 1);
    }
}
