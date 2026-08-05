//! The boundary ADR-014 §5 draws, enforced rather than described.
//!
//! This crate holds the workspace's only exception to `unsafe_code = "forbid"`.
//! ADR-014 §5 makes the grant narrower than the crate: every operation that uses
//! it belongs in one module named `syscall`, and nothing outside that module may
//! open it. A rule of that shape is exactly the kind that survives as prose for
//! a while and then quietly stops being true, because breaking it is a one line
//! change in a file nobody was reviewing for that.
//!
//! So it is a test. It reads this crate's own sources and fails the build if any
//! file other than the designated module opens the exception.
//!
//! # What changed when the loader landed
//!
//! Until milestone F4-97 the correct answer was zero occurrences everywhere, and
//! a test asserted exactly that. `syscall.rs` now exists and uses the exception,
//! so that assertion was rewritten rather than deleted, and it was rewritten in
//! the direction that keeps it load bearing:
//!
//! - the module named by the ADR **must** open the exception, because a boundary
//!   check that passes by finding nothing to check is not a boundary check, and
//!   deleting or emptying `syscall.rs` would otherwise turn this file green;
//! - the number of openings is **capped**, so the exception's surface cannot
//!   grow one line at a time without somebody raising the cap on purpose.
//!
//! The check is textual, and that is a real limit: it looks for the keyword in
//! the positions the compiler accepts it in, so a comment quoting one of those
//! forms would be a false positive. That is the right direction to be wrong in,
//! since the alternative is a check that misses what it exists to catch.
//!
//! # What the scan covers, and why it is not `src/` alone
//!
//! It used to read `src/` and nothing else, which left two files inside the
//! crate boundary that the grant applies to and the check could not see:
//! `build.rs`, which runs on the machine doing the building, and everything
//! under `tests/`. Neither is `src/syscall.rs`, so neither is allowed the
//! exception, and neither was being checked for it. The scan now walks the whole
//! package.
//!
//! That widening is the reason the patterns below are assembled at run time
//! instead of being written out as literals. A scanner that contains the exact
//! text it searches for reports itself the moment it starts reading its own
//! directory, and the usual answer to that is to exempt the scanner, which puts
//! a hole in the middle of the boundary. Building the forms from a keyword and a
//! list of tails leaves no literal in this file, so it is scanned like every
//! other file in the package and gets no exemption at all.

use std::fs;
use std::path::{Path, PathBuf};

/// The module ADR-014 §5 names as the only place the exception may be used,
/// relative to the package root.
///
/// A path rather than a file name: a bare `syscall.rs` matched anywhere in the
/// package, so a `tests/syscall.rs` would have inherited the whole grant by
/// being named after it.
const DESIGNATED_MODULE: &str = "src/syscall.rs";

/// How many times the exception may be opened in this crate's shipped code.
///
/// Three: `capget`, `capset` and `clock_gettime`, which is one call per thing
/// the loader needs and `std` does not provide. Raising this is a decision about
/// the size of the workspace's only `unsafe` surface, so it is a line somebody
/// has to change on purpose and explain in a commit message. A budget rather
/// than an exact match on the current count, because the point is to stop the
/// surface growing, not to make refactoring inside it a test failure.
///
/// The count is over shipped code alone. The module's own test code opens the
/// exception as well, to stand in for the kernel writing into the capability
/// buffer, and that is the only shape of those two calls miri can interpret at
/// all; counting it here would put the miri coverage and the size of the shipped
/// surface into one number where neither could move without the other.
const OPENING_BUDGET: usize = 3;

/// The attribute that starts a file's test code.
///
/// Everything after it in a source file is compiled only under `cfg(test)` and
/// ships in nothing. Assembled from parts for the reason the patterns below are:
/// this file is inside its own scan.
const TEST_ATTRIBUTE: &str = "#[cfg(test)]";

/// The keyword, and the five things that may follow it when it is doing
/// something rather than being talked about.
///
/// Assembled rather than written out; see the module documentation. Without
/// that, this file would be the loudest offender in its own scan.
const KEYWORD: &str = "unsafe";
const TAILS: [&str; 5] = [" {", " fn", " impl", " trait", " extern"];

/// The forms in which the keyword actually opens the exception. A file that
/// contains none of these cannot be using it, whatever its prose says.
fn opening_forms() -> Vec<String> {
    TAILS
        .iter()
        .map(|tail| format!("{KEYWORD}{tail}"))
        .collect()
}

/// One source file and where the exception is opened in it.
struct Opening {
    file: String,
    line: usize,
    /// Whether the opening sits after the file's `#[cfg(test)]` attribute, and
    /// therefore ships in nothing.
    in_test_code: bool,
}

fn source_files(directory: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            source_files(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

fn package_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every Rust file inside the package the grant was given to.
///
/// `src/` and `tests/` are walked and `build.rs` is named, which is the whole of
/// the package: the grant in `Cargo.toml` covers the package, so the check has
/// to cover it too. `target/` is not walked, because nothing there was written
/// by anybody and a generated file is not a place the boundary can be crossed.
fn crate_sources() -> Vec<PathBuf> {
    let root = package_root();
    let mut found = Vec::new();
    source_files(&root.join("src"), &mut found);
    source_files(&root.join("tests"), &mut found);
    let build_script = root.join("build.rs");
    if build_script.is_file() {
        found.push(build_script);
    }
    found.sort();
    found
}

/// A path as this crate's own manifest would name it, so that a failure points
/// at a file rather than at a machine's directory layout.
fn relative(path: &Path) -> String {
    path.strip_prefix(package_root())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Every place the exception is opened, in the files the filter admits.
///
/// A file that cannot be read is reported as an opening rather than skipped. A
/// boundary check that treats an unreadable file as clean is a boundary check
/// that can be switched off by making a file unreadable.
fn openings(include: impl Fn(&Path) -> bool) -> Vec<Opening> {
    let forms = opening_forms();
    let mut found = Vec::new();
    for path in crate_sources() {
        if !include(&path) {
            continue;
        }
        let file = relative(&path);
        let Ok(source) = fs::read_to_string(&path) else {
            found.push(Opening {
                file,
                line: 0,
                in_test_code: false,
            });
            continue;
        };
        let mut in_test_code = false;
        for (index, line) in source.lines().enumerate() {
            if line.trim_start().starts_with(TEST_ATTRIBUTE) {
                in_test_code = true;
            }
            if forms.iter().any(|form| line.contains(form.as_str())) {
                found.push(Opening {
                    file: file.clone(),
                    line: index + 1,
                    in_test_code,
                });
            }
        }
    }
    found
}

/// The openings that end up in a shipped binary.
fn shipped(openings: Vec<Opening>) -> Vec<Opening> {
    openings
        .into_iter()
        .filter(|opening| !opening.in_test_code)
        .collect()
}

fn is_designated(path: &Path) -> bool {
    relative(path) == DESIGNATED_MODULE
}

fn describe(openings: &[Opening]) -> Vec<String> {
    openings
        .iter()
        .map(|opening| format!("{}:{}", opening.file, opening.line))
        .collect()
}

#[test]
fn the_exception_is_opened_nowhere_outside_the_module_adr_014_names() {
    let outside = openings(|path| !is_designated(path));
    assert!(
        outside.is_empty(),
        "ADR-014 confines the unsafe exception to {DESIGNATED_MODULE}; these are outside it: {:?}",
        describe(&outside)
    );
}

#[test]
fn the_designated_module_exists_and_actually_opens_the_exception() {
    // The assertion that stops this file from passing for the wrong reason.
    // Before the loader landed, the whole crate opened the exception nowhere and
    // the test above was true of an empty crate; it would be true again if
    // somebody deleted `syscall.rs`, moved the calls into a dependency, or
    // emptied the module. None of those is the boundary holding.
    let inside = openings(is_designated);
    assert!(
        !inside.is_empty(),
        "{DESIGNATED_MODULE} opens the exception nowhere, so the check above is checking nothing. \
         Either the module was emptied or the syscalls moved somewhere this test cannot see them."
    );
}

#[test]
fn the_exception_surface_stays_within_its_budget() {
    // A boundary that only says "in one file" lets the file grow. This is the
    // other half: the count of places the workspace steps outside its own
    // guarantee is fixed at a number somebody decided, and adding a fourth is a
    // failing test rather than a diff nobody read closely.
    let inside = shipped(openings(is_designated));
    assert!(
        inside.len() <= OPENING_BUDGET,
        "the unsafe surface grew past its budget of {OPENING_BUDGET}: {:?}",
        describe(&inside)
    );
}

#[test]
fn the_designated_module_opens_the_exception_in_its_test_code_too() {
    // ADR-014 §5 asks for a miri target for this crate, and miri does not
    // execute foreign functions: `libc::syscall` stops the interpreter rather
    // than being checked by it. So the interpretable part of `capget` and
    // `capset` is what surrounds the call, and reaching it needs a stand-in that
    // writes into the capability buffer the way the kernel does, through the
    // same raw pointer. That stand-in is the exception opened in test code, and
    // deleting it would leave `cargo miri test --lib` green over an exception it
    // never interpreted, which is exactly the state this crate was in.
    //
    // Checked here rather than in the module because this file runs on every
    // platform, and `src/syscall.rs` is compiled on Linux with a program object
    // and nowhere else.
    let in_tests: Vec<Opening> = openings(is_designated)
        .into_iter()
        .filter(|opening| opening.in_test_code)
        .collect();
    assert!(
        !in_tests.is_empty(),
        "{DESIGNATED_MODULE} has no stand-in for the kernel in its test code, so the miri job \
         compiles the exception and interprets none of it"
    );

    // And that the stand-in is pointed at the shipped seams rather than at a
    // buffer of its own. A test that allocated its own array and wrote into it
    // would open the exception, satisfy the assertion above, and interpret code
    // no binary contains.
    //
    // A file this cannot read becomes an empty source, which fails every
    // assertion below rather than passing one. That is the same direction
    // `openings` above is wrong in, and for the same reason: a check that reads
    // an unreadable file as clean can be switched off by making a file
    // unreadable.
    let source = fs::read_to_string(package_root().join(DESIGNATED_MODULE)).unwrap_or_default();
    let test_code = source
        .split_once(TEST_ATTRIBUTE)
        .map(|(_, tests)| tests)
        .unwrap_or_default();
    for seam in ["read_capabilities_with", "write_capabilities_with"] {
        assert!(
            test_code.contains(seam),
            "{DESIGNATED_MODULE}'s test code does not drive `{seam}`, so the buffer the kernel \
             fills is interpreted by nothing"
        );
    }
}

#[test]
fn the_boundary_check_is_looking_at_the_whole_package() {
    // Without this, moving the source directory would turn the check into a test
    // that passes by finding nothing to look at. A guarantee that holds because
    // nobody looked is the silent pass this repository treats as worse than a
    // failure.
    let sources = crate_sources();
    assert!(
        sources.len() >= 5,
        "expected to scan this crate's modules and found {} file(s)",
        sources.len()
    );
    assert!(
        sources.iter().any(|path| is_designated(path)),
        "{DESIGNATED_MODULE} is not among this crate's sources"
    );

    // The three parts of the package, each named, because the scan was `src/`
    // alone for two milestones and nobody could tell from a green run.
    for part in ["src/", "tests/", "build.rs"] {
        assert!(
            sources.iter().any(|path| relative(path).starts_with(part)),
            "nothing under {part} reached the scan, so the grant covers ground the check does not"
        );
    }
    // This file is in its own scan. It has to be: it is inside the package the
    // grant was given to, and a scanner that skipped itself would be the one
    // place in the package where the exception could be opened unseen.
    assert!(
        sources
            .iter()
            .any(|path| relative(path) == "tests/unsafe_boundary.rs"),
        "the scanner exempted itself"
    );
}

#[test]
fn the_check_recognises_every_form_the_compiler_accepts_and_leaves_prose_alone() {
    // The check is only worth what its pattern list is worth. This holds the
    // list against the forms that actually open the exception, so a list that
    // silently lost one is a failing test rather than a boundary with a hole.
    let forms = opening_forms();
    assert_eq!(
        forms.len(),
        TAILS.len(),
        "a form was lost between the tail list and the patterns"
    );

    let catches = |line: &str| forms.iter().any(|form| line.contains(form.as_str()));
    for form in &forms {
        // Assembled from the form rather than quoted, so that this file stays
        // clean under its own scan; see the module documentation.
        let code = format!("    {form} the_rest_of_the_line");
        assert!(
            catches(&code),
            "the boundary check would not notice: {code}"
        );
    }

    // The two shapes the keyword takes when it is not opening anything. Both
    // appear in this package's own prose and manifest, so a check that fired on
    // them would be a check nobody could keep green honestly.
    for harmless in [
        format!("// the {KEYWORD} exception is documented here"),
        format!("{KEYWORD}_code = \"allow\""),
    ] {
        assert!(
            !catches(&harmless),
            "the boundary check fires on something that opens nothing: {harmless}"
        );
    }
}
