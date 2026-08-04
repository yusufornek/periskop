//! `periskop verify`.
//!
//! The exit code is the whole point of this command, so it is decided in one
//! place and stated here rather than being read out of the code.
//!
//! `0` means one thing: a public key the caller named signed this exact document.
//! Every other outcome is non zero. No signature, a signature that does not
//! verify, a key nobody trusts, an envelope that fails its own schema, a document
//! whose bytes were changed after signing: all of them leave with `1`, because
//! `signature-envelope.md` says a report that fails verification is handled as an
//! unsigned report, never as a partly accepted one.
//!
//! `2` is reserved for the run that could not happen at all: an unreadable report
//! file, an unreadable or malformed public key, or a `--signature` path that is
//! not there. The last one is the distinction worth naming, because it is easy
//! to get backwards. A report with no envelope beside it is unsigned and that is
//! a verdict; an envelope the caller named and mistyped is a question that never
//! reached the signature. The pipeline has to tell "this report is not
//! trustworthy" apart from "the check never ran", which are different incidents
//! with different responses.
//!
//! What a `0` does not mean is worth as much as what it means. It says the bytes
//! came from the named key unaltered. It says nothing about whether the scan
//! behind them was complete or correct.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;

use periskop_report::signature::{self, KeyRing, VerifyingKey};

use crate::exit;
// One rule for where an envelope lives, owned by the side that writes it.
use crate::sign::envelope_path;

#[derive(Args)]
pub struct VerifyArgs {
    /// Report document to check.
    #[arg(long, value_name = "FILE")]
    pub report: PathBuf,

    /// Signature envelope. Defaults to the report path with `.sig.json`.
    #[arg(long, value_name = "FILE")]
    pub signature: Option<PathBuf>,

    /// A public key to trust. Repeat to build a key ring.
    ///
    /// Required, and deliberately so. There is no ambient key store and no
    /// implicit trust: a caller who has not said whose signature counts has not
    /// asked a question that can be answered.
    #[arg(long = "public-key", value_name = "FILE", required = true)]
    pub public_keys: Vec<PathBuf>,
}

pub fn run(args: &VerifyArgs) -> ExitCode {
    let document = match std::fs::read(&args.report) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("periskop: cannot read {}: {e}", args.report.display());
            return ExitCode::from(exit::ERROR);
        }
    };

    // Whether the caller named the envelope decides what its absence means, so
    // the two cases are kept apart here rather than collapsed into one path.
    let named = args.signature.is_some();
    let envelope_path = args
        .signature
        .clone()
        .unwrap_or_else(|| envelope_path(&args.report));
    let envelope = match std::fs::read(&envelope_path) {
        Ok(bytes) => bytes,
        // A path the caller typed and got wrong is a run that could not happen,
        // which is a `2`. Reporting it as a `1` tells a pipeline the report is
        // not trustworthy, and the report is not the thing that was wrong.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && named => {
            eprintln!(
                "periskop: no signature envelope at {}, which is where --signature points",
                envelope_path.display()
            );
            return ExitCode::from(exit::ERROR);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Not an error and not a pass. An unsigned report is a perfectly
            // valid report, but `verify` was asked whether this one is signed,
            // and the answer is no.
            eprintln!(
                "periskop: {} is unsigned: no signature envelope at {}",
                args.report.display(),
                envelope_path.display()
            );
            return ExitCode::from(exit::FAIL);
        }
        Err(e) => {
            eprintln!("periskop: cannot read {}: {e}", envelope_path.display());
            return ExitCode::from(exit::ERROR);
        }
    };

    let keys = match read_key_ring(&args.public_keys) {
        Ok(keys) => keys,
        Err(code) => return code,
    };

    match signature::verify(&document, &envelope, &keys) {
        Ok(verified) => {
            println!(
                "verified {} under key {}\n  body_hash {}",
                verified.report_id, verified.key_id, verified.body_hash
            );
            ExitCode::from(exit::PASS)
        }
        Err(e) => {
            eprintln!("periskop: {} is NOT verified: {e}", args.report.display());
            ExitCode::from(exit::FAIL)
        }
    }
}

fn read_key_ring(paths: &[PathBuf]) -> Result<KeyRing, ExitCode> {
    let mut keys = Vec::with_capacity(paths.len());
    for path in paths {
        keys.push(read_public_key(path)?);
    }
    Ok(KeyRing::new(keys))
}

/// A key file that cannot be read is an operator problem, not a verdict.
///
/// It exits with the error code rather than the failure code, so that a typo in
/// a path is never reported to a pipeline as "this report is not trustworthy".
fn read_public_key(path: &Path) -> Result<VerifyingKey, ExitCode> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        eprintln!(
            "periskop: cannot read the public key at {}: {e}",
            path.display()
        );
        ExitCode::from(exit::ERROR)
    })?;
    VerifyingKey::from_key_file(&text).map_err(|e| {
        eprintln!(
            "periskop: {} is not a periskop public key: {e}",
            path.display()
        );
        ExitCode::from(exit::ERROR)
    })
}
