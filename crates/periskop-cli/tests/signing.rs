#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! Report signing, driven through the binary the way a pipeline drives it.
//!
//! These tests are about exit codes and bytes on disk, which is the surface a
//! continuous integration job actually sees. The cryptographic properties are
//! pinned inside `periskop-report`; what is pinned here is that the command line
//! never turns a refusal into a pass, and that the file it signs is the file the
//! reader has.
//!
//! The exit code contract under test:
//!
//! | outcome                                            | code |
//! |----------------------------------------------------|------|
//! | verified                                            | 0    |
//! | unsigned, altered, unknown key, malformed envelope  | 1    |
//! | the check could not run: missing file, bad key file | 2    |

use std::path::{Path, PathBuf};
use std::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_periskop");

/// Exit codes, repeated here on purpose.
///
/// The binary maps these in `main.rs`; a test that imported them would pass even
/// if both sides changed together, which is exactly the change that breaks every
/// pipeline in the world without breaking a test.
const PASS: i32 = 0;
const FAIL: i32 = 1;
const ERROR: i32 = 2;

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("periskop-signing-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    /// A canonical report document, the way the scan command writes one.
    fn report(&self, name: &str, verdict: &str) -> PathBuf {
        let document = periskop_report::to_canonical_json(&serde_json::json!({
            "schema_version": "1.0",
            "report_id": "rpt_0123456789abcdef",
            "scan_run_id": "scan_0123456789abcdef",
            "envelope": {
                "generated_at": "2026-08-04T09:00:00Z",
                "tool_version": "0.0.0-test"
            },
            "verdict": verdict,
            "findings": [],
            "suspect_findings": [],
            "diagnostics": []
        }))
        .unwrap();
        let path = self.path(name);
        std::fs::write(&path, document).unwrap();
        path
    }

    /// Generates a key pair and returns the two paths.
    fn key_pair(&self, name: &str) -> (PathBuf, PathBuf) {
        let secret = self.path(&format!("{name}.secret"));
        let public = self.path(&format!("{name}.public"));
        let outcome = run(&[
            "key",
            "generate",
            "--secret-key",
            secret.to_str().unwrap(),
            "--public-key",
            public.to_str().unwrap(),
        ]);
        assert_eq!(outcome.code, PASS, "{}", outcome.stderr);
        (secret, public)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct Outcome {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Outcome {
    let output = Command::new(BINARY).args(args).output().unwrap();
    Outcome {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn sign(report: &Path, key: &Path) -> Outcome {
    run(&[
        "sign",
        "--report",
        report.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
    ])
}

fn verify(report: &Path, public_key: &Path) -> Outcome {
    run(&[
        "verify",
        "--report",
        report.to_str().unwrap(),
        "--public-key",
        public_key.to_str().unwrap(),
    ])
}

fn envelope_of(report: &Path) -> PathBuf {
    report.with_extension("sig.json")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn the_written_envelope_matches_the_schema_file_field_for_field() {
    // Read out of `schemas/` rather than restated here. A second copy of the
    // field list in a test is a copy that drifts, and the day it drifts the
    // test still passes while the emitted envelope stops matching the contract.
    let scratch = Scratch::new("schema-shape");
    let (secret, _public) = scratch.key_pair("k");
    let report = scratch.report("scan.report.json", "PASS");
    assert_eq!(sign(&report, &secret).code, PASS);

    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("schemas/signature-envelope.schema.json"))
            .unwrap(),
    )
    .unwrap();
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(envelope_of(&report)).unwrap()).unwrap();

    let declared = schema["properties"].as_object().unwrap();
    let produced = written.as_object().unwrap();
    for field in schema["required"].as_array().unwrap() {
        let name = field.as_str().unwrap();
        assert!(
            produced.contains_key(name),
            "{name} is required and missing"
        );
    }
    for name in produced.keys() {
        assert!(
            declared.contains_key(name),
            "{name} is not declared by the schema, which closes the object"
        );
    }
    assert!(schema["properties"]["algorithm"]["enum"]
        .as_array()
        .unwrap()
        .contains(&written["algorithm"]));
}

#[test]
fn the_signature_value_is_an_unpadded_base64url_ed25519_signature() {
    let scratch = Scratch::new("value-shape");
    let (secret, _public) = scratch.key_pair("k");
    let report = scratch.report("scan.report.json", "PASS");
    assert_eq!(sign(&report, &secret).code, PASS);

    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(envelope_of(&report)).unwrap()).unwrap();
    let value = written["value"].as_str().unwrap();

    // 64 bytes encode to 86 unpadded characters, and none of them may be `=`,
    // `+` or `/`: the contract says base64url without padding.
    assert_eq!(value.len(), 86, "{value}");
    assert!(
        !value.contains('=') && !value.contains('+') && !value.contains('/'),
        "{value}"
    );
}

#[test]
fn a_signed_report_verifies() {
    let scratch = Scratch::new("round-trip");
    let (secret, public) = scratch.key_pair("k");
    let report = scratch.report("scan.report.json", "PASS");

    let signed = sign(&report, &secret);
    assert_eq!(signed.code, PASS, "{}", signed.stderr);
    assert!(envelope_of(&report).is_file());

    let verified = verify(&report, &public);
    assert_eq!(verified.code, PASS, "{}", verified.stderr);
    assert!(verified.stdout.contains("verified rpt_0123456789abcdef"));
}

#[test]
fn signing_leaves_the_report_bytes_untouched() {
    // The reason the envelope is detached at all: a signed report and an
    // unsigned one are the same document, so a diff between two runs shows a
    // change in the code rather than a change in the signature.
    let scratch = Scratch::new("untouched");
    let (secret, _public) = scratch.key_pair("k");
    let report = scratch.report("scan.report.json", "PASS");
    let before = std::fs::read(&report).unwrap();

    assert_eq!(sign(&report, &secret).code, PASS);
    assert_eq!(std::fs::read(&report).unwrap(), before);
}

#[test]
fn one_changed_byte_fails_verification() {
    // The claim the whole feature stands on, exercised on the file rather than
    // on a structure: one character in the document, same length, still valid
    // JSON, still canonical.
    let scratch = Scratch::new("one-byte");
    let (secret, public) = scratch.key_pair("k");
    let report = scratch.report("scan.report.json", "PASS");
    assert_eq!(sign(&report, &secret).code, PASS);

    let original = std::fs::read_to_string(&report).unwrap();
    let tampered = original.replace("\"PASS\"", "\"FAIL\"");
    assert_eq!(original.len(), tampered.len());
    assert_ne!(original, tampered);
    std::fs::write(&report, &tampered).unwrap();

    let verified = verify(&report, &public);
    assert_eq!(verified.code, FAIL, "{}", verified.stdout);
    assert!(
        verified.stderr.contains("NOT verified"),
        "{}",
        verified.stderr
    );
}

#[test]
fn a_whitespace_only_edit_fails_verification() {
    // Re-serializing the parsed report before hashing would have accepted this,
    // because nothing structural moved. The bytes the reader holds did.
    let scratch = Scratch::new("whitespace");
    let (secret, public) = scratch.key_pair("k");
    let report = scratch.report("scan.report.json", "PASS");
    assert_eq!(sign(&report, &secret).code, PASS);

    let original = std::fs::read_to_string(&report).unwrap();
    std::fs::write(&report, format!("{original}\n")).unwrap();

    assert_eq!(verify(&report, &public).code, FAIL);
}

#[test]
fn an_unsigned_report_is_not_verified() {
    // The failure mode this forbids: a `--verify` that finds no envelope,
    // decides there is nothing to complain about, and exits zero.
    let scratch = Scratch::new("unsigned");
    let (_secret, public) = scratch.key_pair("k");
    let report = scratch.report("scan.report.json", "PASS");

    let verified = verify(&report, &public);
    assert_eq!(verified.code, FAIL, "{}", verified.stdout);
    assert!(verified.stderr.contains("unsigned"), "{}", verified.stderr);
    assert!(verified.stdout.is_empty(), "{}", verified.stdout);
}

#[test]
fn a_signature_from_a_key_nobody_named_is_not_verified() {
    let scratch = Scratch::new("stranger");
    let (signer_secret, _signer_public) = scratch.key_pair("signer");
    let (_other_secret, other_public) = scratch.key_pair("other");
    let report = scratch.report("scan.report.json", "PASS");

    assert_eq!(sign(&report, &signer_secret).code, PASS);
    let verified = verify(&report, &other_public);
    assert_eq!(verified.code, FAIL, "{}", verified.stdout);
    assert!(
        verified.stderr.contains("no trusted public key"),
        "{}",
        verified.stderr
    );
}

#[test]
fn a_report_signed_under_a_rotated_key_still_verifies_when_both_keys_are_named() {
    let scratch = Scratch::new("rotation");
    let (old_secret, old_public) = scratch.key_pair("old");
    let (_new_secret, new_public) = scratch.key_pair("new");
    let report = scratch.report("scan.report.json", "PASS");
    assert_eq!(sign(&report, &old_secret).code, PASS);

    let verified = run(&[
        "verify",
        "--report",
        report.to_str().unwrap(),
        "--public-key",
        new_public.to_str().unwrap(),
        "--public-key",
        old_public.to_str().unwrap(),
    ]);
    assert_eq!(verified.code, PASS, "{}", verified.stderr);
}

#[test]
fn a_corrupt_envelope_is_not_verified() {
    let scratch = Scratch::new("corrupt");
    let (secret, public) = scratch.key_pair("k");
    let report = scratch.report("scan.report.json", "PASS");
    assert_eq!(sign(&report, &secret).code, PASS);

    std::fs::write(envelope_of(&report), "{ this is not json").unwrap();
    assert_eq!(verify(&report, &public).code, FAIL);
}

#[test]
fn an_envelope_carrying_an_unknown_field_is_not_verified() {
    // `additionalProperties: false`. A field this build does not understand may
    // be the field that narrows what the signature covers.
    let scratch = Scratch::new("extra-field");
    let (secret, public) = scratch.key_pair("k");
    let report = scratch.report("scan.report.json", "PASS");
    assert_eq!(sign(&report, &secret).code, PASS);

    let path = envelope_of(&report);
    let mut envelope: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    envelope
        .as_object_mut()
        .unwrap()
        .insert("scope".into(), serde_json::json!("partial"));
    std::fs::write(&path, serde_json::to_string_pretty(&envelope).unwrap()).unwrap();

    assert_eq!(verify(&report, &public).code, FAIL);
}

#[test]
fn an_envelope_missing_its_signature_value_is_not_verified() {
    let scratch = Scratch::new("missing-field");
    let (secret, public) = scratch.key_pair("k");
    let report = scratch.report("scan.report.json", "PASS");
    assert_eq!(sign(&report, &secret).code, PASS);

    let path = envelope_of(&report);
    let mut envelope: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    envelope.as_object_mut().unwrap().remove("value");
    std::fs::write(&path, serde_json::to_string_pretty(&envelope).unwrap()).unwrap();

    assert_eq!(verify(&report, &public).code, FAIL);
}

#[test]
fn an_envelope_that_names_a_different_report_is_not_verified() {
    let scratch = Scratch::new("wrong-report");
    let (secret, public) = scratch.key_pair("k");
    let report = scratch.report("scan.report.json", "PASS");
    assert_eq!(sign(&report, &secret).code, PASS);

    let path = envelope_of(&report);
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        text.replace("rpt_0123456789abcdef", "rpt_fedcba9876543210"),
    )
    .unwrap();

    assert_eq!(verify(&report, &public).code, FAIL);
}

#[test]
fn the_same_report_and_key_sign_to_the_same_bytes() {
    // Ed25519 is deterministic (RFC 8032) and no clock is read unless one is
    // asked for, so a signed report stays as diffable as an unsigned one.
    let scratch = Scratch::new("deterministic");
    let (secret, _public) = scratch.key_pair("k");
    let report = scratch.report("scan.report.json", "PASS");

    assert_eq!(sign(&report, &secret).code, PASS);
    let first = std::fs::read(envelope_of(&report)).unwrap();

    let again = run(&[
        "sign",
        "--report",
        report.to_str().unwrap(),
        "--key",
        secret.to_str().unwrap(),
        "--force",
    ]);
    assert_eq!(again.code, PASS, "{}", again.stderr);
    assert_eq!(std::fs::read(envelope_of(&report)).unwrap(), first);
}

#[test]
fn signing_refuses_to_replace_an_envelope_without_being_asked() {
    let scratch = Scratch::new("no-clobber");
    let (secret, _public) = scratch.key_pair("k");
    let report = scratch.report("scan.report.json", "PASS");
    assert_eq!(sign(&report, &secret).code, PASS);

    let outcome = sign(&report, &secret);
    assert_eq!(outcome.code, ERROR, "{}", outcome.stderr);
}

#[test]
fn signing_refuses_a_document_that_is_not_in_canonical_form() {
    // Signing it would produce an envelope for a byte string that exists in no
    // file, and the reader's copy would fail verification with no visible cause.
    let scratch = Scratch::new("not-canonical");
    let (secret, _public) = scratch.key_pair("k");
    let report = scratch.path("compact.report.json");
    std::fs::write(
        &report,
        r#"{"envelope":{},"report_id":"rpt_0123456789abcdef"}"#,
    )
    .unwrap();

    let outcome = sign(&report, &secret);
    assert_eq!(outcome.code, ERROR, "{}", outcome.stdout);
    assert!(outcome.stderr.contains("canonical"), "{}", outcome.stderr);
    assert!(!envelope_of(&report).exists());
}

#[test]
fn a_missing_report_is_an_error_rather_than_a_failed_verification() {
    // A typo in a path and an untrustworthy report are different incidents, and
    // a pipeline has to be able to respond to them differently.
    let scratch = Scratch::new("missing-report");
    let (_secret, public) = scratch.key_pair("k");
    let outcome = verify(&scratch.path("absent.report.json"), &public);
    assert_eq!(outcome.code, ERROR, "{}", outcome.stderr);
}

#[test]
fn a_public_key_file_that_is_not_one_is_an_error() {
    let scratch = Scratch::new("bad-public-key");
    let (secret, _public) = scratch.key_pair("k");
    let report = scratch.report("scan.report.json", "PASS");
    assert_eq!(sign(&report, &secret).code, PASS);

    let not_a_key = scratch.path("notes.txt");
    std::fs::write(&not_a_key, "this is not a key\n").unwrap();
    let outcome = verify(&report, &not_a_key);
    assert_eq!(outcome.code, ERROR, "{}", outcome.stderr);
}

#[test]
fn a_public_key_handed_in_as_a_signing_key_is_refused() {
    let scratch = Scratch::new("swapped-halves");
    let (_secret, public) = scratch.key_pair("k");
    let report = scratch.report("scan.report.json", "PASS");

    let outcome = sign(&report, &public);
    assert_eq!(outcome.code, ERROR, "{}", outcome.stderr);
    assert!(!envelope_of(&report).exists());
}

#[test]
fn verifying_without_naming_a_key_is_refused() {
    // There is no ambient trust. A caller who has not said whose signature
    // counts has not asked a question that can be answered with a zero.
    let scratch = Scratch::new("no-key-named");
    let report = scratch.report("scan.report.json", "PASS");
    let outcome = run(&["verify", "--report", report.to_str().unwrap()]);
    assert_ne!(outcome.code, PASS, "{}", outcome.stdout);
}

#[test]
fn key_generation_writes_the_two_files_it_was_given_and_nothing_else() {
    // No default location, no quiet copy anywhere. The directory holds exactly
    // what was asked for.
    let scratch = Scratch::new("keygen-scope");
    let (secret, public) = scratch.key_pair("k");

    let mut written: Vec<String> = std::fs::read_dir(&scratch.root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    written.sort();
    assert_eq!(written, vec!["k.public".to_owned(), "k.secret".to_owned()]);
    assert!(secret.is_file() && public.is_file());
}

#[test]
fn key_generation_refuses_to_overwrite_an_existing_key() {
    // Overwriting a private key destroys the only copy of it and makes every
    // report signed under it unverifiable, so it is never the default.
    let scratch = Scratch::new("keygen-clobber");
    let (secret, public) = scratch.key_pair("k");
    let before = std::fs::read(&secret).unwrap();

    let outcome = run(&[
        "key",
        "generate",
        "--secret-key",
        secret.to_str().unwrap(),
        "--public-key",
        public.to_str().unwrap(),
    ]);
    assert_eq!(outcome.code, ERROR, "{}", outcome.stderr);
    assert_eq!(std::fs::read(&secret).unwrap(), before);
}

#[cfg(unix)]
#[test]
fn a_replaced_private_key_is_narrowed_rather_than_inheriting_old_permissions() {
    // The gap this pins: creation time mode only applies to a file the call
    // created. Under `--force` the file is already there, and a key written over
    // a world readable file used to stay world readable.
    use std::os::unix::fs::PermissionsExt as _;
    let scratch = Scratch::new("keygen-force-mode");
    let secret = scratch.path("k.secret");
    let public = scratch.path("k.public");
    std::fs::write(&secret, "placeholder\n").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();

    let outcome = run(&[
        "key",
        "generate",
        "--secret-key",
        secret.to_str().unwrap(),
        "--public-key",
        public.to_str().unwrap(),
        "--force",
    ]);
    assert_eq!(outcome.code, PASS, "{}", outcome.stderr);
    let mode = std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "private key mode is {mode:o}");
}

#[cfg(unix)]
#[test]
fn a_generated_private_key_is_not_readable_by_anyone_else() {
    use std::os::unix::fs::PermissionsExt as _;
    let scratch = Scratch::new("keygen-mode");
    let (secret, _public) = scratch.key_pair("k");
    let mode = std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "private key mode is {mode:o}");
}

#[test]
fn the_private_key_never_appears_in_what_the_commands_print() {
    // Not a code review claim, an executed one. Every command that touches the
    // key is run and its whole output searched for the key's own text.
    let scratch = Scratch::new("no-leak");
    let (secret, public) = scratch.key_pair("k");
    let key_file = std::fs::read_to_string(&secret).unwrap();
    let material = key_file.split_whitespace().nth(1).unwrap().to_owned();
    assert!(
        material.len() > 40,
        "expected the encoded key, got {material:?}"
    );

    let report = scratch.report("scan.report.json", "PASS");
    let mut printed = String::new();
    for outcome in [
        sign(&report, &secret),
        sign(&report, &secret),
        verify(&report, &public),
        run(&[
            "key",
            "generate",
            "--secret-key",
            secret.to_str().unwrap(),
            "--public-key",
            public.to_str().unwrap(),
        ]),
        run(&[
            "sign",
            "--report",
            report.to_str().unwrap(),
            "--key",
            "/nonexistent",
        ]),
    ] {
        printed.push_str(&outcome.stdout);
        printed.push_str(&outcome.stderr);
    }

    assert!(!printed.contains(&material), "the key leaked into output");
    assert!(!printed.contains(periskop_report::signature::SECRET_KEY_TAG));
}

#[test]
fn a_report_the_scan_command_wrote_signs_and_verifies_as_written() {
    // The end to end claim: the bytes the scan writes are canonical, so the
    // document a reader receives is exactly the document the signature covers.
    // Nothing in between re-serializes anything.
    let scratch = Scratch::new("end-to-end");
    let (secret, public) = scratch.key_pair("k");

    let root = repo_root();
    let scan = run(&[
        "scan",
        root.join("crates/periskop-static-scanner/fixtures/python")
            .to_str()
            .unwrap(),
        "--json",
        "--rules",
        root.join("rules").to_str().unwrap(),
    ]);
    assert!(scan.code == PASS || scan.code == FAIL, "{}", scan.stderr);
    assert!(scan.stdout.contains("\"report_id\""), "{}", scan.stderr);

    let report = scratch.path("scan.report.json");
    std::fs::write(&report, scan.stdout.as_bytes()).unwrap();

    let signed = sign(&report, &secret);
    assert_eq!(signed.code, PASS, "{}", signed.stderr);
    let verified = verify(&report, &public);
    assert_eq!(verified.code, PASS, "{}", verified.stderr);
}
