//! Human readable summary of a report.
//!
//! The coverage section is not optional and cannot be filtered out. A summary
//! that lists findings without saying what was unreadable would let a reader
//! conclude "nothing found" from a scan that barely read anything, which is the
//! single failure this tool is built to prevent.

use periskop_report::coverage::{DnsObservation, RuntimeStatus, SensorPlatformClass};
use periskop_report::report::ScanReport;
use periskop_report::Verdict;

pub fn summary(report: &ScanReport) -> String {
    let mut out = String::new();

    let verdict = match report.verdict {
        Verdict::Pass => "PASS",
        Verdict::Warn => "WARN",
        Verdict::Fail => "FAIL",
    };
    out.push_str(&format!("periskop {verdict}\n\n"));

    if report.findings.is_empty() {
        out.push_str("No confirmed egress found.\n");
    } else {
        out.push_str(&format!("{} confirmed:\n", report.findings.len()));
        for finding in &report.findings {
            out.push_str(&format!("  {}\n", describe(finding)));
        }
    }

    if !report.suspect_findings.is_empty() {
        out.push_str(&format!(
            "\n{} suspected, listed separately because the evidence is weaker:\n",
            report.suspect_findings.len()
        ));
        for finding in &report.suspect_findings {
            out.push_str(&format!("  {}\n", describe(finding)));
        }
    }

    out.push_str("\nCoverage\n");
    out.push_str(&format!(
        "  read       {} files\n",
        report.coverage.parsed_files
    ));

    if report.coverage.unparsed_files.is_empty() {
        out.push_str("  unread     none\n");
    } else {
        out.push_str(&format!(
            "  unread     {} files ({} basis points of the code surface)\n",
            report.coverage.unparsed_files.len(),
            report.coverage.unparsed_ratio_basis_points()
        ));
        for entry in report.coverage.unparsed_files.iter().take(5) {
            out.push_str(&format!(
                "             {} ({:?})\n",
                entry.path, entry.reason
            ));
        }
        if report.coverage.unparsed_files.len() > 5 {
            out.push_str(&format!(
                "             and {} more\n",
                report.coverage.unparsed_files.len() - 5
            ));
        }
    }

    if !report.coverage.undetected_libraries.is_empty() {
        out.push_str(&format!(
            "  no rules   {}\n",
            report.coverage.undetected_libraries.join(", ")
        ));
    }

    out.push_str(&runtime_line(report));
    out.push_str(&network_line(report));

    if !report.diagnostics.is_empty() {
        out.push_str("\nDiagnostics\n");
        for diagnostic in &report.diagnostics {
            out.push_str(&format!(
                "  {:?} in {:?}\n",
                diagnostic.code, diagnostic.component
            ));
        }
    }

    out
}

/// The runtime line, read off the coverage block rather than asserted.
///
/// This used to be a fixed string saying the runtime layer was not instrumented.
/// It happened to be close to what the report said, which is worse than being
/// plainly wrong: the moment a hook lands and the report says `instrumented`,
/// the terminal would keep printing the opposite, and the reader believes the
/// screen.
fn runtime_line(report: &ScanReport) -> String {
    let coverage = &report.coverage;
    if coverage.runtime_coverage.is_empty() {
        return "  runtime    no status declared for any language\n".to_owned();
    }

    let mut instrumented = Vec::new();
    let mut not_instrumented = Vec::new();
    let mut degraded = Vec::new();
    let mut unsupported = Vec::new();
    for entry in &coverage.runtime_coverage {
        let name = entry.language.as_str();
        match entry.status {
            RuntimeStatus::Instrumented => instrumented.push(name),
            RuntimeStatus::NotInstrumented => not_instrumented.push(name),
            RuntimeStatus::Degraded => degraded.push(name),
            RuntimeStatus::Unsupported => unsupported.push(name),
        }
    }

    let mut parts = Vec::new();
    if !instrumented.is_empty() {
        parts.push(format!("hooked: {}", instrumented.join(", ")));
    }
    if !degraded.is_empty() {
        parts.push(format!("degraded: {}", degraded.join(", ")));
    }
    if !not_instrumented.is_empty() {
        parts.push(format!(
            "hook available but off: {}",
            not_instrumented.join(", ")
        ));
    }
    if !unsupported.is_empty() {
        parts.push(format!("no hook exists: {}", unsupported.join(", ")));
    }
    format!("  runtime    {}\n", parts.join("; "))
}

/// The network line, likewise read off the coverage block.
fn network_line(report: &ScanReport) -> String {
    let coverage = &report.coverage;
    let sensor = match coverage.sensor_platform_class {
        SensorPlatformClass::None => {
            return "  network    no sensor, so traffic with no matching call site was not seen\n"
                .to_owned()
        }
        SensorPlatformClass::LinuxEbpf => "linux ebpf",
        SensorPlatformClass::MacosPcap => "macos pcap",
        SensorPlatformClass::WindowsPcapEtw => "windows pcap and etw",
    };
    let dns = match coverage.dns_observation {
        DnsObservation::Available => "dns readable",
        DnsObservation::UnavailableEncryptedDns => "dns encrypted, names not readable",
    };
    format!(
        "  network    {sensor}, {dns}, {} ms observed\n",
        coverage.observation_window_ms
    )
}

fn describe(finding: &periskop_core::finding::Finding) -> String {
    let location = finding
        .location
        .as_ref()
        .and_then(|l| {
            l.path.as_ref().map(|p| match &l.span {
                Some(span) => format!("{p}:{}", span.start_line),
                None => p.clone(),
            })
        })
        .unwrap_or_else(|| "unknown location".to_owned());
    format!(
        "{location}  {} via {}",
        finding.provider_ref, finding.detector.rule_id
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use periskop_core::finding::{
        Component, Confidence, Detector, EntityRef, Evidence, EvidenceType, Finding, Kind,
        Location, RefType, Span,
    };
    use periskop_report::coverage::{CoverageLanguage, CoverageStatement, RuntimeCoverage};
    use periskop_report::report::{Envelope, PolicyRef, ReportBuilder, RuleHit};

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

    fn finding(confidence: Confidence, rule: &str, line: u32) -> Finding {
        Finding::new(
            Kind::DeclaredEgressPoint,
            confidence,
            "openai",
            EntityRef {
                ref_type: RefType::EgressPoint,
                ref_id: format!("ep_{:016x}", u64::from(line)),
            },
            Evidence {
                evidence_type: EvidenceType::AstNode,
                r#ref: "call@services/summary.py".into(),
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
        .with_location(Location {
            component: Component::StaticScanner,
            path: Some("services/summary.py".into()),
            span: Some(Span {
                start_line: line,
                start_col: 5,
                end_line: line + 3,
                end_col: 6,
            }),
            symbol: None,
        })
    }

    fn empty_report() -> ScanReport {
        ReportBuilder::new().build(
            envelope(),
            policy(Vec::new()),
            CoverageStatement::static_only(),
        )
    }

    #[test]
    fn coverage_appears_even_when_nothing_was_found() {
        // The property worth pinning: a clean result still has to say what it
        // could not see, or "nothing found" reads as a guarantee it is not.
        let text = summary(&empty_report());
        assert!(text.contains("No confirmed egress found."));
        assert!(text.contains("Coverage"));
        assert!(text.contains("runtime"));
        assert!(text.contains("network"));
    }

    #[test]
    fn the_verdict_is_the_first_thing_shown() {
        assert!(summary(&empty_report()).starts_with("periskop PASS"));
    }

    #[test]
    fn a_verdict_other_than_pass_is_shown_as_itself() {
        // The old version of this test could only ever see PASS, because the
        // verdict was fixed at PASS in every report the tool produced. It
        // therefore proved nothing about the rendering.
        let report = ReportBuilder::new().build(
            envelope(),
            policy(vec![RuleHit {
                rule_id: "policy.confirmed-egress".into(),
                verdict: Verdict::Fail,
                finding_ids: None,
                coverage_condition: None,
            }]),
            CoverageStatement::static_only(),
        );
        assert!(summary(&report).starts_with("periskop FAIL"), "{report:?}");
    }

    #[test]
    fn a_finding_is_printed_with_its_location_provider_and_rule() {
        // Nothing used to look at this path: the only fixture was an empty
        // report, so the location formatting could break without a red test.
        let mut builder = ReportBuilder::new();
        builder.add_findings([
            finding(
                Confidence::Confirmed,
                "python.static.openai-client-call",
                10,
            ),
            finding(
                Confidence::Suspect,
                "python.static.http-provider-endpoint",
                200,
            ),
        ]);
        let text = summary(&builder.build(
            envelope(),
            policy(Vec::new()),
            CoverageStatement::static_only(),
        ));

        assert!(text.contains("1 confirmed:"), "{text}");
        assert!(text.contains("services/summary.py:10"), "{text}");
        assert!(
            text.contains("openai via python.static.openai-client-call"),
            "{text}"
        );
        assert!(text.contains("1 suspected"), "{text}");
        assert!(text.contains("services/summary.py:200"), "{text}");
    }

    #[test]
    fn the_runtime_line_reports_what_the_coverage_block_says() {
        // The bug this pins: the line was a fixed string. It agreed with the
        // report by coincidence, and would have kept printing "not instrumented"
        // on the day a hook started reporting otherwise.
        let mut coverage = CoverageStatement::static_only();
        coverage.runtime_coverage = vec![
            RuntimeCoverage {
                language: CoverageLanguage::Python,
                status: RuntimeStatus::Instrumented,
                hook_mechanism: Some("sitecustomize".into()),
            },
            RuntimeCoverage {
                language: CoverageLanguage::Go,
                status: RuntimeStatus::Unsupported,
                hook_mechanism: None,
            },
        ];
        let text = summary(&ReportBuilder::new().build(envelope(), policy(Vec::new()), coverage));

        assert!(text.contains("hooked: python"), "{text}");
        assert!(text.contains("no hook exists: go"), "{text}");
        assert!(
            !text.contains("not instrumented, so calls"),
            "the fixed string is back: {text}"
        );
    }
}
