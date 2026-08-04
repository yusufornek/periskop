#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! Where `periskop sensor` puts its records, driven through the binary.
//!
//! This surface is tested from outside for one reason: the command is documented
//! to run with `CAP_BPF` and `CAP_PERFMON`, so whatever it writes, it writes with
//! privileges the person who arranged the path may not hold. A unit test can show
//! that the writing function refuses a link; only the binary can show that the
//! refusal survives argument parsing and reaches an exit code, which is the whole
//! of what an operator and a pipeline see.

use std::path::PathBuf;
use std::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_periskop");

/// The record file one pass writes, named here rather than imported.
///
/// A test that read the constant out of the code would keep passing if the name
/// changed on both sides, and the name is half of the contract `scan --flows`
/// reads.
const RECORD_FILE_NAME: &str = "flows.jsonl";

/// Exit codes, repeated on purpose for the same reason.
const ERROR: i32 = 2;

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("periskop-sensor-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct Outcome {
    code: i32,
    stderr: String,
}

fn sensor(out_dir: &std::path::Path) -> Outcome {
    let output = Command::new(BINARY)
        .args(["sensor", "--out", out_dir.to_str().unwrap()])
        .output()
        .unwrap();
    Outcome {
        code: output.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[cfg(unix)]
#[test]
fn a_record_file_that_is_a_symbolic_link_stops_the_pass_and_spares_the_other_file() {
    // The live failure, reproduced at the surface it was found on. With
    // `flows.jsonl` linked at another file, the pass emptied that other file to
    // zero bytes, kept the link, and exited 3: a privileged command destroyed a
    // file it was never pointed at while announcing that it had not managed to
    // do anything at all.
    let scratch = Scratch::new("symlinked-records");
    let out = scratch.path("sout");
    let victim = scratch.path("sd-target.txt");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(&victim, "data somebody needs\n").unwrap();
    std::os::unix::fs::symlink(&victim, out.join(RECORD_FILE_NAME)).unwrap();

    let outcome = sensor(&out);

    assert_eq!(outcome.code, ERROR, "{}", outcome.stderr);
    assert_eq!(
        std::fs::read_to_string(&victim).unwrap(),
        "data somebody needs\n",
        "the linked file was written through"
    );
    assert!(std::fs::symlink_metadata(out.join(RECORD_FILE_NAME))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn a_pass_writes_its_record_file_and_says_where() {
    // The refusal above must not have cost the ordinary run. Whatever this
    // machine can observe, and on a developer's laptop that is nothing, the
    // record file is there afterwards: an absent file and an empty one say
    // different things to the scan that reads the directory next.
    let scratch = Scratch::new("ordinary-pass");
    let out = scratch.path("sout");

    let outcome = sensor(&out);

    assert_ne!(outcome.code, ERROR, "{}", outcome.stderr);
    assert!(out.join(RECORD_FILE_NAME).is_file(), "{}", outcome.stderr);
}
