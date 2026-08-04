//! Human readable summary of a report.
//!
//! The coverage section is not optional and cannot be filtered out. A summary
//! that lists findings without saying what was unreadable would let a reader
//! conclude "nothing found" from a scan that barely read anything, which is the
//! single failure this tool is built to prevent.

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

    out.push_str(
        "  runtime    not instrumented, so calls that only happen at run time were not seen\n",
    );
    out.push_str("  network    no sensor, so traffic with no matching call site was not seen\n");

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
mod tests {
    use super::*;
    use periskop_report::report::{Envelope, PolicyRef, ReportBuilder};

    fn empty_report() -> ScanReport {
        ReportBuilder::new().build(
            Envelope {
                generated_at: "2026-08-04T09:00:00Z".into(),
                tool_version: "0.1.0".into(),
                host: None,
            },
            PolicyRef {
                policy_id: "default".into(),
                policy_version: "1.0.0".into(),
                policy_hash: "a".repeat(64),
                rule_hits: Vec::new(),
            },
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
}
