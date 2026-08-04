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

#[test]
fn the_help_output_matches_the_command_tree_in_the_specification() {
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
