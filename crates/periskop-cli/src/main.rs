//! periskop command line interface.
//!
//! Exit codes are a contract, not a detail. Continuous integration reads them, so
//! they are mapped explicitly here rather than falling out of whatever the last
//! expression returned.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod render;
mod scan;

/// Exit codes, fixed by the command line contract.
mod exit {
    /// Scan completed and the policy passed.
    pub const PASS: u8 = 0;
    /// Scan completed and the policy failed.
    pub const FAIL: u8 = 1;
    /// The scan itself could not run.
    pub const ERROR: u8 = 2;
    /// The scan ran but saw too little to stand behind the result.
    pub const INSUFFICIENT_COVERAGE: u8 = 3;
}

#[derive(Parser)]
#[command(
    name = "periskop",
    version,
    about = "Find out where your code sends data to LLM providers, and prove the answer."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a project for calls that send data to a model provider.
    Scan {
        /// Project directory to scan.
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Emit the full report as JSON instead of a summary.
        #[arg(long)]
        json: bool,

        /// Directory holding detector rules.
        #[arg(long, value_name = "DIR")]
        rules: Option<PathBuf>,

        /// Fail when the share of unreadable files exceeds this many basis points.
        #[arg(long, value_name = "BASIS_POINTS")]
        max_unparsed_ratio: Option<u64>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan {
            path,
            json,
            rules,
            max_unparsed_ratio,
        } => run_scan(path, json, rules, max_unparsed_ratio),
    }
}

fn run_scan(
    path: PathBuf,
    json: bool,
    rules: Option<PathBuf>,
    max_unparsed_ratio: Option<u64>,
) -> ExitCode {
    if !path.is_dir() {
        eprintln!("periskop: {} is not a directory", path.display());
        return ExitCode::from(exit::ERROR);
    }

    let rules_root = rules.unwrap_or_else(default_rules_root);
    if !rules_root.is_dir() {
        eprintln!(
            "periskop: no rule directory at {}. Pass --rules to point at one.",
            rules_root.display()
        );
        return ExitCode::from(exit::ERROR);
    }

    let outcome = scan::run(scan::ScanRequest {
        project_root: &path,
        rules_root: &rules_root,
        tool_version: env!("CARGO_PKG_VERSION"),
        generated_at: now_rfc3339(),
    });

    for error in &outcome.rule_errors {
        eprintln!("periskop: rule problem: {error}");
    }

    let output = if json {
        match periskop_report::to_canonical_json(&outcome.report) {
            Ok(text) => text,
            Err(e) => {
                eprintln!("periskop: could not serialize the report: {e}");
                return ExitCode::from(exit::ERROR);
            }
        }
    } else {
        render::summary(&outcome.report)
    };
    print!("{output}");

    // Coverage is checked before the verdict. A scan that could not read enough
    // of the tree has not earned the right to report a pass, and giving that its
    // own exit code lets a pipeline tell "clean" apart from "did not look".
    if let Some(limit) = max_unparsed_ratio {
        let ratio = outcome.report.coverage.unparsed_ratio_basis_points();
        if ratio > limit {
            eprintln!(
                "periskop: unreadable share is {ratio} basis points, above the limit of {limit}"
            );
            return ExitCode::from(exit::INSUFFICIENT_COVERAGE);
        }
    }

    match outcome.report.verdict {
        periskop_report::Verdict::Fail => ExitCode::from(exit::FAIL),
        _ => ExitCode::from(exit::PASS),
    }
}

/// Where rules live when the caller does not say.
///
/// Looks next to the executable first, which is how an installed build finds the
/// rules shipped alongside it, then falls back to the repository layout so the
/// binary works from a development checkout without extra flags.
fn default_rules_root() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let beside = dir.join("rules");
            if beside.is_dir() {
                return beside;
            }
        }
    }
    PathBuf::from("rules")
}

/// Current time in the format the envelope declares.
///
/// The envelope is excluded from the body hash, so this value never affects
/// whether two reports of the same tree compare equal.
fn now_rfc3339() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_epoch_seconds(seconds)
}

/// Formats seconds since the epoch as RFC 3339 in UTC.
///
/// Written out rather than pulled in as a dependency: the report needs one
/// timestamp in one format, and a date library would be a new dependency
/// decision for that alone.
fn format_epoch_seconds(seconds: u64) -> String {
    let days = seconds / 86_400;
    let time_of_day = seconds % 86_400;
    let (hour, minute, second) = (
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60,
    );
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Days since the epoch to a calendar date.
///
/// Howard Hinnant's civil_from_days, the standard branch free form of this
/// conversion. It handles leap years without a lookup table.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_formats_as_the_start_of_1970() {
        assert_eq!(format_epoch_seconds(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn a_known_instant_round_trips() {
        assert_eq!(format_epoch_seconds(1_785_834_000), "2026-08-04T09:00:00Z");
    }

    #[test]
    fn leap_day_is_handled() {
        assert_eq!(format_epoch_seconds(1_709_164_800), "2024-02-29T00:00:00Z");
    }
}
