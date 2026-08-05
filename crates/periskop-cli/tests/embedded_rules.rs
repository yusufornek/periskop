#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
//! The scenario a downloaded binary is actually run in.
//!
//! Copy one file somewhere, put some code next to it, run `periskop scan .`. That
//! is the command the README prints and it did not work: the binary looked for a
//! `rules` directory beside itself and then in the working directory, found
//! neither, and stopped with
//! `no rule directory at rules. Pass --rules to point at one.` and exit code 2.
//! Nothing in the test suite ran the binary from outside the checkout, so the
//! defect sat where no test could see it, and the packaging document had written
//! it down as a shipping requirement rather than as a bug.
//!
//! Everything here runs the real executable from a directory that has no rule
//! tree anywhere above it, because that is the only way to check the thing that
//! was broken. A test calling the scan library would pass with the rule set the
//! library was handed.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// A directory outside the repository, holding nothing but what the test puts in
/// it.
///
/// The system temporary directory rather than a path under `target/`: a rule
/// tree in an ancestor is exactly what these tests have to be free of.
struct Elsewhere {
    root: PathBuf,
}

impl Elsewhere {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("periskop-embedded-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a working directory");
        Self { root }
    }

    /// Copies the built executable in, the way a release archive is unpacked.
    ///
    /// The copy is flushed and closed before anybody tries to run it. Linux
    /// refuses to execute a file that any process still holds open for writing
    /// (`ETXTBSY`, "text file busy"), and these tests run in parallel with
    /// others that fork, so a descriptor still open here becomes a failure to
    /// exec over there. macOS does not enforce that rule, which is why the first
    /// version passed on the development machine and failed on both Linux jobs.
    fn install_binary(&self) -> PathBuf {
        let installed = self
            .root
            .join(format!("periskop{}", std::env::consts::EXE_SUFFIX));

        let mut source =
            std::fs::File::open(env!("CARGO_BIN_EXE_periskop")).expect("the built executable");
        let mut target = std::fs::File::create(&installed).expect("a place to put it");
        std::io::copy(&mut source, &mut target).expect("the copy");
        target.sync_all().expect("the copy on disk");
        drop(target);

        // `File::create` does not carry the source's mode, and an executable
        // that is not executable is a different test failure with a confusing
        // message.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&installed, std::fs::Permissions::from_mode(0o755))
                .expect("the executable bit");
        }

        installed
    }

    fn write(&self, name: &str, contents: &str) {
        std::fs::write(self.root.join(name), contents).expect("a source file");
    }
}

impl Drop for Elsewhere {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A call the shipped Python rules confirm.
const PYTHON_EGRESS: &str = "from openai import OpenAI\n\nclient = OpenAI()\n\n\ndef ask(record):\n    return client.chat.completions.create(model=\"gpt-4\", messages=[{\"content\": record}])\n";

/// Runs a prepared command, waiting out the one failure that is about the
/// machine rather than the program.
///
/// A copied executable can be refused with `ETXTBSY` while any process still
/// holds it open for writing, and the window that matters is not this test's
/// own: between a sibling test's `fork` and its `exec`, the child briefly holds
/// every descriptor this process had, and closing on exec does not help inside
/// that gap. Nothing about the product is being measured here, so the answer is
/// to try again rather than to fail. It is bounded, and running out of attempts
/// is still a failure.
fn run_once_it_is_runnable<T>(mut attempt: impl FnMut() -> std::io::Result<T>) -> T {
    for _ in 0..50 {
        match attempt() {
            Ok(value) => return value,
            Err(error) if error.raw_os_error() == Some(26) => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(error) => panic!("the command did not start: {error}"),
        }
    }
    panic!("the copied executable stayed busy for a second, which is not a timing problem");
}

fn scan_json(binary: &Path, working_directory: &Path, extra: &[&str]) -> (i32, String, String) {
    let output = run_once_it_is_runnable(|| {
        Command::new(binary)
            .arg("scan")
            .arg(".")
            .arg("--json")
            .args(extra)
            .current_dir(working_directory)
            .output()
    });
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn a_binary_on_its_own_in_an_empty_directory_finds_egress() {
    let elsewhere = Elsewhere::new("alone");
    let binary = elsewhere.install_binary();
    elsewhere.write("app.py", PYTHON_EGRESS);

    let (code, stdout, stderr) = scan_json(&binary, &elsewhere.root, &[]);

    assert_ne!(code, 2, "the scan refused to run: {stderr}");
    assert!(
        !stderr.contains("no rule directory"),
        "the binary still wants a rule directory beside it: {stderr}"
    );

    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("the report is not JSON ({e}): {stdout}"));
    let findings = report["findings"].as_array().expect("a findings array");
    assert_eq!(findings.len(), 1, "{stdout}");
    assert_eq!(
        findings[0]["detector"]["rule_id"], "python.static.openai-client-call",
        "{stdout}"
    );

    // No diagnostics about the rule set, which is the other half of the claim:
    // the rules did not merely exist, they loaded clean.
    let diagnostics = report["diagnostics"]
        .as_array()
        .expect("a diagnostics array");
    assert!(
        !diagnostics.iter().any(|d| d["code"] == "RULE_LOAD_ERROR"),
        "{stdout}"
    );
}

#[test]
fn the_run_says_which_rule_set_decided_it() {
    // A reader told a tree is clean has to be able to ask "according to what".
    // The embedded set and an operator's own directory produce different
    // answers, and a run that does not say which one it used leaves the reader
    // to guess from the working directory.
    let elsewhere = Elsewhere::new("announce");
    let binary = elsewhere.install_binary();
    elsewhere.write("app.py", PYTHON_EGRESS);

    let (_, _, stderr) = scan_json(&binary, &elsewhere.root, &[]);
    assert!(
        stderr.contains("periskop: rules built into this binary"),
        "{stderr}"
    );
}

/// Runs `serve-rpc`, feeds it the given lines and closes the input.
///
/// The real executable rather than the `rpc::serve` library entry point, because
/// what is under test here is the split between the two output streams and a
/// library call has only one caller supplied writer.
fn serve_rpc(
    binary: &Path,
    working_directory: &Path,
    extra: &[&str],
    requests: &str,
) -> (i32, String, String) {
    let mut child = run_once_it_is_runnable(|| {
        Command::new(binary)
            .arg("serve-rpc")
            .args(extra)
            .current_dir(working_directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    });
    child
        .stdin
        .take()
        .expect("a pipe to the bridge")
        .write_all(requests.as_bytes())
        .expect("the request was sent");
    let output = child.wait_with_output().expect("the bridge exited");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

const PING: &str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";

#[test]
fn the_rpc_bridge_says_which_rule_set_decided_it() {
    // The gap this closes: `scan` printed the declaration and `serve-rpc`, which
    // resolves its rules through the same function, printed nothing. An editor
    // driving the bridge could not tell the detectors shipped in the binary from
    // a directory somebody edited, and the two produce different verdicts on one
    // tree.
    let elsewhere = Elsewhere::new("rpc-announce");
    let binary = elsewhere.install_binary();

    let (code, _, stderr) = serve_rpc(&binary, &elsewhere.root, &[], PING);

    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains("periskop: rules built into this binary"),
        "the bridge did not say which rule set decided it: {stderr}"
    );
}

#[test]
fn the_rpc_bridge_names_the_directory_and_keeps_the_answer_byte_identical() {
    // Two claims in one run, because they constrain each other. The path has to
    // reach the reader, and it can only reach them on stderr: the report body
    // carries the source as a closed enum on purpose, and an absolute path in
    // the answer would make two machines produce different bytes for one tree.
    // So the second assertion is the price of the first, and it is checked
    // against the embedded run rather than against a literal, which is what
    // makes it fail if the declaration ever moves to stdout.
    let elsewhere = Elsewhere::new("rpc-directory");
    let binary = elsewhere.install_binary();
    let rules = elsewhere.root.join("own-rules");
    std::fs::create_dir_all(rules.join("python")).expect("a rule directory");

    let (embedded_code, embedded_stdout, _) = serve_rpc(&binary, &elsewhere.root, &[], PING);
    let (code, stdout, stderr) = serve_rpc(
        &binary,
        &elsewhere.root,
        &["--rules", &rules.to_string_lossy()],
        PING,
    );

    assert_eq!(embedded_code, 0);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains("periskop: rules read from") && stderr.contains(&*rules.to_string_lossy()),
        "the bridge did not name the directory it was given: {stderr}"
    );
    assert_eq!(
        stdout, embedded_stdout,
        "the declaration reached the JSON-RPC stream and changed the answer's bytes"
    );
}

#[test]
fn a_named_rule_directory_wins_over_the_embedded_set() {
    // The operator's guarantee. Their directory holds one rule, and it is a rule
    // the shipped set does not have, so the finding it produces could not have
    // come from the embedded copy. If the two sets were merged, the shipped
    // OpenAI rule would fire on the same file as well and there would be two
    // findings rather than one.
    let elsewhere = Elsewhere::new("override");
    let binary = elsewhere.install_binary();
    elsewhere.write("app.py", PYTHON_EGRESS);

    let rules = elsewhere.root.join("own-rules").join("python");
    std::fs::create_dir_all(&rules).expect("a rule directory");
    std::fs::write(
        rules.join("house-style.toml"),
        "schema_version = \"1.0\"\n\
         language = \"python\"\n\
         provider = \"in-house\"\n\
         rule_id = \"python.static.house-style\"\n\
         rule_version = \"1.0.0\"\n\n\
         [[match]]\n\
         kind = \"call\"\n\
         query = '''\n(call function: (attribute attribute: (identifier) @method)) @call\n'''\n\
         [match.method]\n\
         capture = \"method\"\n\
         one_of = [\"create\"]\n\n\
         [classify]\n\
         egress_kind = \"llm_chat\"\n\
         default_confidence = \"confirmed\"\n",
    )
    .expect("a rule file");

    let (code, stdout, stderr) = scan_json(
        &binary,
        &elsewhere.root,
        &[
            "--rules",
            &elsewhere.root.join("own-rules").to_string_lossy(),
        ],
    );

    assert_ne!(code, 2, "{stderr}");
    assert!(stderr.contains("periskop: rules read from"), "{stderr}");

    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("the report is not JSON ({e}): {stdout}"));
    let ids: Vec<&str> = report["findings"]
        .as_array()
        .expect("a findings array")
        .iter()
        .filter_map(|f| f["detector"]["rule_id"].as_str())
        .collect();
    assert_eq!(ids, vec!["python.static.house-style"], "{stdout}");
}

#[test]
fn a_rules_flag_pointing_nowhere_stops_the_run() {
    // Falling back to the embedded set here would be the worst answer available:
    // the operator asked for their detectors and would be handed somebody else's
    // with a zero exit code on top.
    let elsewhere = Elsewhere::new("missing");
    let binary = elsewhere.install_binary();
    elsewhere.write("app.py", PYTHON_EGRESS);

    let (code, _, stderr) = scan_json(&binary, &elsewhere.root, &["--rules", "no-such-directory"]);

    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("no rule directory at"), "{stderr}");
}

#[test]
fn a_stray_rules_directory_in_the_working_directory_is_not_picked_up() {
    // The other half of the defect, and the quieter half. The old resolution
    // read `rules` relative to the working directory, so any project that
    // happened to have a directory by that name replaced the shipped detectors
    // without saying so, and the same command produced different results from
    // two different directories.
    let elsewhere = Elsewhere::new("stray");
    let binary = elsewhere.install_binary();
    elsewhere.write("app.py", PYTHON_EGRESS);
    std::fs::create_dir_all(elsewhere.root.join("rules")).expect("a decoy directory");
    std::fs::write(
        elsewhere.root.join("rules/not-a-rule.toml"),
        "nonsense = [\n",
    )
    .expect("a decoy file");

    let (code, stdout, stderr) = scan_json(&binary, &elsewhere.root, &[]);

    assert_ne!(code, 2, "{stderr}");
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("the report is not JSON ({e}): {stdout}"));
    assert_eq!(
        report["findings"].as_array().map(Vec::len),
        Some(1),
        "the decoy directory decided the run: {stdout}"
    );
}
