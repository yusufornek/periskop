//! `periskop sign` and `periskop key generate`.
//!
//! Key generation lives beside signing rather than in a module of its own,
//! because the two share one rule that is easier to keep in one file: nothing is
//! written to a path the user did not name. There is no default location for a
//! private key, no fallback into a home directory and no "we put it in the usual
//! place". A tool that quietly leaves key material somewhere has decided, on its
//! owner's behalf, that the owner did not need to know where the key is.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use zeroize::Zeroizing;

use periskop_report::signature::{self, SigningKey};

use crate::exit;

#[derive(Args)]
pub struct SignArgs {
    /// Report document to sign, exactly as it was written.
    #[arg(long, value_name = "FILE")]
    pub report: PathBuf,

    /// File holding the private signing key.
    #[arg(long, value_name = "FILE")]
    pub key: PathBuf,

    /// Where the envelope goes. Defaults to the report path with `.sig.json`.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,

    /// Timestamp to record in the envelope.
    ///
    /// Absent by default, and the default is the useful one: the timestamp sits
    /// outside the signed bytes, so leaving it out makes the envelope a function
    /// of the report and the key alone, and two signings can be compared byte for
    /// byte the way two reports can.
    #[arg(long, value_name = "RFC3339")]
    pub signed_at: Option<String>,

    /// Replace an envelope that is already there.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct KeyGenerateArgs {
    /// Where the private key is written. No default, on purpose.
    #[arg(long, value_name = "FILE")]
    pub secret_key: PathBuf,

    /// Where the public key is written. No default, on purpose.
    #[arg(long, value_name = "FILE")]
    pub public_key: PathBuf,

    /// Replace key files that are already there.
    ///
    /// Off by default: overwriting a private key destroys the only copy of it,
    /// and every report signed under it becomes unverifiable.
    #[arg(long)]
    pub force: bool,
}

/// Signs a report and writes the detached envelope.
///
/// Every failure here exits with the error code rather than the policy failure
/// code. Signing is not a gate: "this report failed the policy" and "this report
/// could not be signed" are different sentences and a pipeline must be able to
/// tell them apart.
pub fn run(args: &SignArgs) -> ExitCode {
    let document = match std::fs::read(&args.report) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("periskop: cannot read {}: {e}", args.report.display());
            return ExitCode::from(exit::ERROR);
        }
    };

    let key = match read_signing_key(&args.key) {
        Ok(key) => key,
        Err(code) => return code,
    };

    let envelope = match signature::sign(&document, &key, args.signed_at.clone()) {
        Ok(envelope) => envelope,
        Err(e) => {
            eprintln!("periskop: cannot sign {}: {e}", args.report.display());
            return ExitCode::from(exit::ERROR);
        }
    };

    let text = match envelope.to_canonical_json() {
        Ok(text) => text,
        Err(e) => {
            eprintln!("periskop: cannot serialize the signature envelope: {e}");
            return ExitCode::from(exit::ERROR);
        }
    };

    let target = args
        .out
        .clone()
        .unwrap_or_else(|| envelope_path(&args.report));
    if let Err(e) = write_file(&target, text.as_bytes(), args.force, Visibility::Public) {
        eprintln!("periskop: cannot write {}: {e}", target.display());
        return ExitCode::from(exit::ERROR);
    }

    // On stderr, so a pipeline redirecting stdout gets the envelope path in its
    // log rather than in the middle of whatever it was collecting.
    eprintln!(
        "periskop: signed {} as {} under key {}",
        envelope.report_id,
        target.display(),
        envelope.key_id
    );
    ExitCode::from(exit::PASS)
}

/// Generates a key pair and writes it exactly where the two flags say.
///
/// Both paths are checked before either file is written, so a run that would
/// have collided does not leave half a key pair behind.
pub fn run_key_generate(args: &KeyGenerateArgs) -> ExitCode {
    if !args.force {
        for path in [&args.secret_key, &args.public_key] {
            if path.exists() {
                eprintln!(
                    "periskop: {} is already there. Pass --force to replace it, but read the warning first: replacing a private key makes every report signed under it unverifiable.",
                    path.display()
                );
                return ExitCode::from(exit::ERROR);
            }
        }
    }

    let key = match SigningKey::generate() {
        Ok(key) => key,
        Err(e) => {
            eprintln!("periskop: {e}");
            return ExitCode::from(exit::ERROR);
        }
    };

    if let Err(e) = write_file(
        &args.secret_key,
        key.to_key_file().as_bytes(),
        args.force,
        Visibility::Private,
    ) {
        eprintln!("periskop: cannot write {}: {e}", args.secret_key.display());
        return ExitCode::from(exit::ERROR);
    }

    if let Err(e) = write_file(
        &args.public_key,
        key.verifying_key().to_key_file().as_bytes(),
        args.force,
        Visibility::Public,
    ) {
        // Said out loud rather than cleaned up silently. Deleting the private key
        // that was just written would be the tidy answer and the wrong one: if
        // the delete also failed, the user would be told nothing about a key
        // sitting on their disk.
        eprintln!(
            "periskop: cannot write {}: {e}\n  → the private key was already written to {}. Delete it yourself if you are starting over.",
            args.public_key.display(),
            args.secret_key.display()
        );
        return ExitCode::from(exit::ERROR);
    }

    eprintln!(
        "periskop: generated key {}\n  private key: {}\n  public key:  {}",
        key.key_id(),
        args.secret_key.display(),
        args.public_key.display()
    );
    ExitCode::from(exit::PASS)
}

/// Where the envelope for a report goes when nobody says otherwise.
///
/// `signature-envelope.md`: `<name>.report.json` pairs with
/// `<name>.report.sig.json`. Shared with `verify`, which has to look in the same
/// place; two copies of this rule is how a signer and a verifier stop finding
/// each other's files.
pub fn envelope_path(report: &Path) -> PathBuf {
    match report.extension().and_then(|e| e.to_str()) {
        Some("json") => report.with_extension("sig.json"),
        // A report that is not named `.json` still gets a companion rather than
        // an error: the naming rule is a convention, not a precondition.
        _ => {
            let mut name = report.as_os_str().to_os_string();
            name.push(".sig.json");
            PathBuf::from(name)
        }
    }
}

/// Reads a private key file, keeping the text in a buffer that clears itself.
fn read_signing_key(path: &Path) -> Result<SigningKey, ExitCode> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => Zeroizing::new(text),
        Err(e) => {
            eprintln!(
                "periskop: cannot read the signing key at {}: {e}",
                path.display()
            );
            return Err(ExitCode::from(exit::ERROR));
        }
    };
    SigningKey::from_key_file(&text).map_err(|e| {
        // The error type carries no key material, so printing it is safe. That
        // is a property of the type rather than of this call site, and it is
        // tested in `periskop-report`.
        eprintln!(
            "periskop: {} is not a periskop signing key: {e}",
            path.display()
        );
        ExitCode::from(exit::ERROR)
    })
}

/// Whether a file may be read by anyone on the machine.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Visibility {
    Private,
    Public,
}

fn write_file(
    path: &Path,
    contents: &[u8],
    force: bool,
    visibility: Visibility,
) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        // `create_new` rather than a prior existence check: the check and the
        // write would be two steps, and a file created between them would be
        // overwritten by a command that promised not to.
        options.create_new(true);
    }

    #[cfg(unix)]
    if visibility == Visibility::Private {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Applied at creation rather than afterwards, so a newly created key is
        // never world readable, not even for the moment between two calls.
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = visibility;

    let mut file = options.open(path)?;

    // `mode` above only applies to a file this call created. Under `--force` the
    // file was already there and keeps whatever permissions it had, so a key
    // written over a world readable file would stay world readable. Narrowed
    // before the bytes go in, not after.
    #[cfg(unix)]
    if visibility == Visibility::Private {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }

    file.write_all(contents)?;
    file.sync_all()
}
