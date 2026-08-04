//! `periskop sign` and `periskop key generate`.
//!
//! Key generation lives beside signing rather than in a module of its own,
//! because the two share one rule that is easier to keep in one file: nothing is
//! written to a path the user did not name. There is no default location for a
//! private key, no fallback into a home directory and no "we put it in the usual
//! place". A tool that quietly leaves key material somewhere has decided, on its
//! owner's behalf, that the owner did not need to know where the key is.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use zeroize::Zeroizing;

use periskop_cli::write_target::{self, Existing, Restriction};
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
    // The envelope is a file beside the report, never one of the files the
    // signature was made from. `--out <the report> --force` used to write the
    // envelope over the document it attests to: the signed bytes were gone, the
    // envelope described a file that no longer existed, and the command exited
    // zero. The same flag aimed at the key destroys the key.
    for (path, name) in [(&args.report, "report"), (&args.key, "signing key")] {
        if names_one_file(&target, path) {
            eprintln!(
                "periskop: --out names the {name} at {}. The envelope is written beside a report, never over a file the signature is made from.",
                path.display()
            );
            return ExitCode::from(exit::ERROR);
        }
    }

    if let Err(e) = write_target::write_public(&target, text.as_bytes(), existing(args.force)) {
        eprintln!("periskop: {e}");
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
    // One file cannot hold both halves, and the failure is silent in the worst
    // way: the second write lands on the first, the file ends up holding the
    // public key alone, the private key is gone with no copy anywhere, and the
    // command prints both paths and exits zero. Refused before anything is
    // written rather than reported after.
    if names_one_file(&args.secret_key, &args.public_key) {
        eprintln!(
            "periskop: --secret-key and --public-key both name {}. One file cannot hold both halves, and writing them in turn would leave the public half and lose the private key.",
            args.secret_key.display()
        );
        return ExitCode::from(exit::ERROR);
    }

    if !args.force {
        for path in [&args.secret_key, &args.public_key] {
            // `symlink_metadata` rather than `exists`, which follows a link and
            // answers "no" for one that dangles. The path is occupied either
            // way, and a write there would have created the link's target
            // instead of the file the user named.
            if std::fs::symlink_metadata(path).is_ok() {
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

    match write_target::write_private(
        &args.secret_key,
        key.to_key_file().as_bytes(),
        existing(args.force),
    ) {
        Ok(restriction) => report_restriction(&args.secret_key, restriction),
        Err(e) => {
            eprintln!("periskop: {e}");
            return ExitCode::from(exit::ERROR);
        }
    }

    if let Err(e) = write_target::write_public(
        &args.public_key,
        key.verifying_key().to_key_file().as_bytes(),
        existing(args.force),
    ) {
        // Said out loud rather than cleaned up silently. Deleting the private key
        // that was just written would be the tidy answer and the wrong one: if
        // the delete also failed, the user would be told nothing about a key
        // sitting on their disk.
        eprintln!(
            "periskop: {e}\n  → the private key was already written to {}. Delete it yourself if you are starting over.",
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
    refuse_a_widely_readable_key(path)?;
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

/// Refuses a signing key the rest of the machine can read.
///
/// `key generate` writes a private key readable by its owner alone and narrows a
/// replaced one to the same, so a key file anybody else can read was either not
/// written by this command or was widened after it was. Signing with it would be
/// signing with a key whose copies are not accounted for, and the tool whose
/// README argues that an unprotected key is the problem cannot be the tool that
/// uses one without a word. The rule is ssh's, and so is the reason.
#[cfg(unix)]
fn refuse_a_widely_readable_key(path: &Path) -> Result<(), ExitCode> {
    use std::os::unix::fs::PermissionsExt as _;
    // `metadata` rather than `symlink_metadata`: what gets read is the file at
    // the end of the path, and a link's own mode bits decide nothing about who
    // can read the key. A path that cannot be inspected at all is left to the
    // read that follows, which has the better message for it.
    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(());
    };
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        eprintln!(
            "periskop: {} is readable by more than its owner (mode {mode:04o}), so it is not a key this command can treat as private. Run `chmod 600` on it, or generate a key that has never been exposed.",
            path.display()
        );
        return Err(ExitCode::from(exit::ERROR));
    }
    Ok(())
}

/// Says that the key's protection went unchecked, rather than passing quietly.
///
/// This build reads Unix mode bits and knows no other access control, so on any
/// other platform the question was not asked. A reader of the log is told that
/// instead of being left to assume an answer.
#[cfg(not(unix))]
fn refuse_a_widely_readable_key(path: &Path) -> Result<(), ExitCode> {
    eprintln!(
        "periskop: who may read {} was not checked: this build reads file permissions on Unix only.",
        path.display()
    );
    Ok(())
}

/// Says out loud when a private key landed somewhere its access could not be
/// narrowed.
///
/// What this replaced discarded the answer, so a key written on a platform this
/// build cannot restrict a file on looked exactly like one written where it can.
fn report_restriction(path: &Path, restriction: Restriction) {
    if restriction == Restriction::NotEnforceable {
        eprintln!(
            "periskop: {} was written without narrowing who may read it: this build sets file permissions on Unix only. Restrict it yourself before signing anything under it.",
            path.display()
        );
    }
}

/// What `--force` means to a write.
fn existing(force: bool) -> Existing {
    if force {
        Existing::Replace
    } else {
        Existing::Refuse
    }
}

/// Whether two paths lead to one file, decided before either has been written.
///
/// Two questions, because neither answers alone. The device and inode numbers
/// settle the aliases, a hard link or a second name for one file, but only for
/// paths that already exist. Making both absolute settles the spellings, `k` and
/// `./k`, which is the ordinary case for a key that is about to be generated.
///
/// A link and the file it points at are correctly two files here. A write
/// through the link is refused by `write_target`, which is the place that can
/// refuse it without also refusing the honest case.
fn names_one_file(one: &Path, other: &Path) -> bool {
    if same_existing_file(one, other) {
        return true;
    }
    match (std::path::absolute(one), std::path::absolute(other)) {
        (Ok(one), Ok(other)) => one == other,
        // A path that cannot be made absolute is compared as it was written.
        // Answering "different" on a comparison that failed would turn a lost
        // answer into permission to overwrite.
        _ => one == other,
    }
}

#[cfg(unix)]
fn same_existing_file(one: &Path, other: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    match (
        std::fs::symlink_metadata(one),
        std::fs::symlink_metadata(other),
    ) {
        (Ok(one), Ok(other)) => one.dev() == other.dev() && one.ino() == other.ino(),
        _ => false,
    }
}

/// Without inode numbers the aliases cannot be seen, so the spelling comparison
/// in the caller is the whole answer on this platform.
#[cfg(not(unix))]
fn same_existing_file(_one: &Path, _other: &Path) -> bool {
    false
}
