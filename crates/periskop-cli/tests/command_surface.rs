#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
//! Two claims about the shape of this product's command line, both of which have
//! been made in prose for months and neither of which was checked.
//!
//! **One executable.** ADR-001 says every workspace member is a library and
//! exactly one crate produces a `[[bin]]`, so that a component becoming its own
//! crate does not quietly become its own program. A second executable changes
//! ADR-002's distribution decision, which is why the ADR requires a revision to
//! add one; this test is what makes that revision unavoidable. Auto discovery is
//! checked too, because `src/main.rs` and `src/bin/` produce a binary target with
//! nothing written in a manifest to notice.
//!
//! There is one directory under `crates/` that declares a binary and is not a
//! second executable: `periskop-ebpf-object`, whose target is a kernel and whose
//! output is an ELF object the loader hands to `bpf(2)` (ADR-014 §8). It is not
//! a workspace member, so `cargo build --workspace` never produces it and no
//! release ever ships it as a program. That exemption is not a hole in the check:
//! it is asserted, and the three things that make it true are asserted with it,
//! so a host binary cannot arrive by being placed outside the members list.
//!
//! **The documented command tree is the real one.** `cli/spec.md` section 2 opens
//! with "the surface the binary offers today (identical to `periskop --help`)".
//! That sentence was true when it was written and had no way of staying true. Now
//! the tree in the document is parsed and compared against what the binary
//! prints, in both directions: a command in the document that the binary does not
//! have fails, and so does a command the binary has that nobody wrote down.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn exactly_one_crate_in_the_workspace_produces_an_executable() {
    let crates = repo_root().join("crates");
    let mut declared: Vec<String> = Vec::new();
    let mut discovered: Vec<String> = Vec::new();

    let members: Vec<PathBuf> = std::fs::read_dir(&crates)
        .expect("the crates directory")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.join("Cargo.toml").is_file())
        .collect();

    // A scan that found no crates would pass silently, which is the failure shape
    // this repository keeps having to design against.
    assert!(members.len() >= 8, "only {} crates found", members.len());

    let in_workspace = workspace_members();
    // A members list that could not be read would turn the filter below into an
    // exemption for every crate, which is the opposite of what this test is for.
    assert!(
        in_workspace.len() >= 8,
        "the root manifest lists only {} members",
        in_workspace.len()
    );

    for member in &members {
        let name = member
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();

        let manifest: toml::Value = toml::from_str(
            &std::fs::read_to_string(member.join("Cargo.toml")).expect("a crate manifest"),
        )
        .expect("a parseable crate manifest");

        if !in_workspace.contains(&name) {
            // Everything outside the workspace has to justify itself here, and
            // there is exactly one thing that can.
            assert_kernel_object_rather_than_a_second_program(&name, member, &manifest);
            continue;
        }

        if let Some(bins) = manifest.get("bin").and_then(toml::Value::as_array) {
            for bin in bins {
                let target = bin
                    .get("name")
                    .and_then(toml::Value::as_str)
                    .unwrap_or("<unnamed>");
                declared.push(format!("{name} declares [[bin]] {target}"));
            }
        }

        // Cargo builds these without anyone writing a manifest section, which is
        // how a second executable would arrive unannounced.
        if member.join("src/main.rs").is_file() {
            discovered.push(format!("{name} has src/main.rs"));
        }
        if member.join("src/bin").is_dir() {
            discovered.push(format!("{name} has src/bin/"));
        }
    }

    assert_eq!(
        declared,
        vec!["periskop-cli declares [[bin]] periskop".to_owned()],
        "ADR-001 allows one binary target in this workspace"
    );
    assert_eq!(
        discovered,
        vec!["periskop-cli has src/main.rs".to_owned()],
        "a binary target arrived through cargo's auto discovery rather than a manifest"
    );
}

/// The crate directories the root manifest lists as members.
///
/// Read from the manifest rather than from the directory listing, because the
/// question this test asks is what `cargo build --workspace` produces, and that
/// is decided by the list and not by what is on disk.
fn workspace_members() -> BTreeSet<String> {
    let root: toml::Value =
        toml::from_str(&std::fs::read_to_string(repo_root().join("Cargo.toml")).expect("the root"))
            .expect("a parseable root manifest");
    root.get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .map(|members| {
            members
                .iter()
                .filter_map(toml::Value::as_str)
                .filter_map(|path| path.rsplit('/').next())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The one crate allowed to sit outside the workspace, and the three facts that
/// make it something other than a second program.
///
/// Checked rather than trusted, because "it is not a real binary" is a sentence
/// anybody could write in a comment above a real binary.
fn assert_kernel_object_rather_than_a_second_program(
    name: &str,
    directory: &Path,
    manifest: &toml::Value,
) {
    assert_eq!(
        name, "periskop-ebpf-object",
        "a crate outside the workspace members list appeared; ADR-001 and ADR-002 both have \
         something to say about that and neither has said it yet"
    );
    assert!(
        manifest.get("workspace").is_some(),
        "{name} is not in the root members list and does not declare its own workspace, so cargo \
         resolves it against the root and its toolchain constraints leak into every other crate"
    );
    let cargo_config = std::fs::read_to_string(directory.join(".cargo/config.toml"))
        .expect("the kernel object pins its own build target");
    assert!(
        cargo_config.contains("bpfel-unknown-none"),
        "{name} declares a binary and does not build for a kernel target, which makes it a second \
         executable whatever its documentation says"
    );
}

/// The command tree as this repository ships it.
///
/// A committed copy exists because the specification does not travel. `docs/`
/// is deliberately absent from the published tree, so a test that reads it
/// passes on a developer machine and fails on every clone, which is what
/// happened: this file was green locally and red on the first CI run that
/// reached it.
///
/// So the shipped assertion runs against this constant, and the agreement with
/// `cli/spec.md` is checked separately and only where that file exists.
const COMMITTED_TREE: &[&str] = &[
    "hook",
    "hook install",
    "key",
    "key generate",
    "proxy",
    "scan",
    "sensor",
    "serve-rpc",
    "sign",
    "verify",
];

fn committed_tree() -> BTreeSet<String> {
    COMMITTED_TREE.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn the_help_output_matches_the_committed_command_tree() {
    let committed = committed_tree();
    let implemented = implemented_tree();

    let missing: Vec<_> = committed.difference(&implemented).collect();
    let undocumented: Vec<_> = implemented.difference(&committed).collect();

    assert!(
        missing.is_empty(),
        "listed but not implemented: {missing:?}"
    );
    assert!(
        undocumented.is_empty(),
        "implemented but not listed: {undocumented:?}"
    );
}

#[test]
fn the_specification_matches_the_command_tree_in_this_file() {
    let spec = repo_root().join("docs/02-components/cli/spec.md");
    if !spec.exists() {
        // Not a silent skip. `docs/` is never published, so its absence is the
        // normal state of a clone and the expected state in CI. What would be a
        // defect is the directory being there with the file missing from it,
        // and that is the case this asserts rather than passes over.
        assert!(
            !repo_root().join("docs").exists(),
            "docs/ is present but cli/spec.md is not, which means the \
             specification moved rather than that this is a published tree"
        );
        return;
    }

    let documented = documented_tree();
    let implemented = implemented_tree();

    // Both directions. The first catches a document that promises a command
    // nobody wrote, which is what `report`, `reconcile` and `vault` were before
    // the specification was corrected. The second catches a command that shipped
    // without anybody writing it down.
    let missing: Vec<_> = documented.difference(&implemented).collect();
    let undocumented: Vec<_> = implemented.difference(&documented).collect();

    assert!(
        missing.is_empty(),
        "documented but not implemented: {missing:?}"
    );
    assert!(
        undocumented.is_empty(),
        "implemented but not documented: {undocumented:?}"
    );
    // The tree is not empty, so an unparseable document cannot pass as agreement.
    assert!(documented.contains("scan"), "{documented:?}");
    assert!(documented.contains("proxy"), "{documented:?}");
    assert!(documented.contains("hook install"), "{documented:?}");
}

/// The command tree drawn in `cli/spec.md` section 2.
fn documented_tree() -> BTreeSet<String> {
    let spec = std::fs::read_to_string(repo_root().join("docs/02-components/cli/spec.md"))
        .expect("the cli specification");
    let block = fenced_block_after(&spec, "## 2. Komut ağacı").expect("the command tree block");

    let mut tree = BTreeSet::new();
    let mut parent = String::new();
    for line in block.lines() {
        let Some(marker) = line.find("── ") else {
            // The root of the drawing, `periskop` itself.
            continue;
        };

        // The drawing indents one level per four columns: "├── scan" at the top,
        // "│   └── install" or "    └── generate" underneath.
        let depth = line[..marker].chars().count() / 4;
        let name = line[marker + "── ".len()..]
            .split_whitespace()
            .next()
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }

        match depth {
            0 => {
                parent = name.to_owned();
                tree.insert(name.to_owned());
            }
            _ => {
                tree.insert(format!("{parent} {name}"));
            }
        }
    }
    tree
}

/// The command tree the built binary prints.
fn implemented_tree() -> BTreeSet<String> {
    let mut tree = BTreeSet::new();
    for name in subcommands_of(&[]) {
        for nested in subcommands_of(&[name.as_str()]) {
            tree.insert(format!("{name} {nested}"));
        }
        tree.insert(name);
    }
    tree
}

/// The `Commands:` section of one help page.
///
/// `help` is dropped: clap adds it to every command with subcommands, and it is
/// not part of this product's surface.
fn subcommands_of(path: &[&str]) -> Vec<String> {
    let output = Command::new(env!("CARGO_BIN_EXE_periskop"))
        .args(path)
        .arg("--help")
        .output()
        .expect("the binary runs");
    assert!(output.status.success(), "periskop {path:?} --help failed");
    let help = String::from_utf8(output.stdout).expect("help output is text");

    let mut names = Vec::new();
    let mut inside = false;
    for line in help.lines() {
        if line.starts_with("Commands:") {
            inside = true;
            continue;
        }
        if inside {
            if line.trim().is_empty() {
                break;
            }
            // Continuation lines of a long description are indented further than
            // the two columns clap uses for a command name.
            if !line.starts_with("  ") || line.starts_with("      ") {
                continue;
            }
            if let Some(name) = line.split_whitespace().next() {
                if name != "help" {
                    names.push(name.to_owned());
                }
            }
        }
    }
    names
}

/// The first fenced code block after a heading.
fn fenced_block_after<'a>(document: &'a str, heading: &str) -> Option<&'a str> {
    let after_heading = document.split_once(heading)?.1;
    let (_, rest) = after_heading.split_once("```")?;
    let body = rest.split_once("```")?.0;
    // The opening fence may carry a language tag on the same line.
    Some(body.split_once('\n').map_or(body, |(_, body)| body))
}
