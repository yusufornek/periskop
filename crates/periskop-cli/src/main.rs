//! periskop command line interface.
//!
//! Exit codes are a contract, not a detail. Continuous integration reads them, so
//! they are mapped explicitly here rather than falling out of whatever the last
//! expression returned.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use periskop_cli::clock::now_rfc3339;
use periskop_cli::{render, rpc, scan};

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

    /// Serve the engine over JSON-RPC on stdin and stdout.
    ///
    /// Used by the MCP server, which stays a thin client so that detection lives
    /// in one place rather than being reimplemented in a second language.
    ServeRpc {
        /// Directory holding detector rules.
        #[arg(long, value_name = "DIR")]
        rules: Option<PathBuf>,
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
        Command::ServeRpc { rules } => run_serve_rpc(rules),
    }
}

fn run_serve_rpc(rules: Option<PathBuf>) -> ExitCode {
    let rules_root = rules.unwrap_or_else(default_rules_root);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();

    match rpc::serve(
        stdin.lock(),
        stdout.lock(),
        rules_root,
        env!("CARGO_PKG_VERSION"),
        now_rfc3339,
    ) {
        Ok(()) => ExitCode::from(exit::PASS),
        Err(e) => {
            eprintln!("periskop: rpc transport failed: {e}");
            ExitCode::from(exit::ERROR)
        }
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

    // The clock is read before anything else runs. A report whose envelope
    // carries an invented timestamp is not auditable, and the previous behaviour
    // was to fall back to the epoch, which prints as a real date and reads as
    // one. Refusing to produce the report at all is the honest answer.
    let generated_at = match now_rfc3339() {
        Ok(now) => now,
        Err(e) => {
            eprintln!("periskop: {e}");
            return ExitCode::from(exit::ERROR);
        }
    };

    let outcome = scan::run(scan::ScanRequest {
        project_root: &path,
        rules_root: &rules_root,
        tool_version: env!("CARGO_PKG_VERSION"),
        generated_at,
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
