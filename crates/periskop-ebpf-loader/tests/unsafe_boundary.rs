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

use std::fs;
use std::path::{Path, PathBuf};

/// The module ADR-014 §5 names as the only place the exception may be used.
const DESIGNATED_MODULE: &str = "syscall.rs";

/// How many times the exception may be opened in this crate.
///
/// Three: `capget`, `capset` and `clock_gettime`, which is one call per thing
/// the loader needs and `std` does not provide. Raising this is a decision about
/// the size of the workspace's only `unsafe` surface, so it is a line somebody
/// has to change on purpose and explain in a commit message. A budget rather
/// than an exact match on the current count, because the point is to stop the
/// surface growing, not to make refactoring inside it a test failure.
const OPENING_BUDGET: usize = 3;

/// The forms in which the keyword actually opens the exception. A file that
/// contains none of these cannot be using it, whatever its prose says.
const OPENING_FORMS: [&str; 5] = [
    "unsafe {",
    "unsafe fn",
    "unsafe impl",
    "unsafe trait",
    "unsafe extern",
];

/// One source file and where the exception is opened in it.
struct Opening {
    file: String,
    line: usize,
}

fn source_files(directory: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir(directory) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(source_files(&path));
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
    found.sort();
    found
}

fn crate_sources() -> Vec<PathBuf> {
    source_files(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))
}

/// Every place the exception is opened, in the files the filter admits.
///
/// A file that cannot be read is reported as an opening rather than skipped. A
/// boundary check that treats an unreadable file as clean is a boundary check
/// that can be switched off by making a file unreadable.
fn openings(include: impl Fn(&Path) -> bool) -> Vec<Opening> {
    let mut found = Vec::new();
    for path in crate_sources() {
        if !include(&path) {
            continue;
        }
        let file = path.display().to_string();
        let Ok(source) = fs::read_to_string(&path) else {
            found.push(Opening { file, line: 0 });
            continue;
        };
        for (index, line) in source.lines().enumerate() {
            if OPENING_FORMS.iter().any(|form| line.contains(form)) {
                found.push(Opening {
                    file: file.clone(),
                    line: index + 1,
                });
            }
        }
    }
    found
}

fn is_designated(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name == DESIGNATED_MODULE)
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
    let inside = openings(is_designated);
    assert!(
        inside.len() <= OPENING_BUDGET,
        "the unsafe surface grew past its budget of {OPENING_BUDGET}: {:?}",
        describe(&inside)
    );
}

#[test]
fn the_boundary_check_is_looking_at_a_crate_that_has_sources() {
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
}

#[test]
fn the_check_recognises_every_form_the_compiler_accepts() {
    // The check is only worth what its pattern list is worth. This holds the
    // list against the forms that actually open the exception, so a list that
    // silently lost one is a failing test rather than a boundary with a hole.
    let samples = [
        "    let value = unsafe { *pointer };",
        "unsafe fn call_the_kernel() {}",
        "unsafe impl Send for Ring {}",
        "unsafe trait Mapped {}",
        "unsafe extern \"C\" fn handler() {}",
    ];
    for sample in samples {
        assert!(
            OPENING_FORMS.iter().any(|form| sample.contains(form)),
            "the boundary check would not notice: {sample}"
        );
    }
    assert!(
        !OPENING_FORMS
            .iter()
            .any(|form| "// the exception is documented here".contains(form)),
        "the boundary check fires on ordinary prose"
    );
}
