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
//! file other than the designated module opens the exception. Today that module
//! does not exist yet and the correct answer is zero occurrences everywhere,
//! which means the boundary is in force before there is anything inside it, and
//! the first line that crosses it lands red.
//!
//! The check is textual, and that is a real limit: it looks for the keyword in
//! the positions the compiler accepts it in, so a comment quoting one of those
//! forms would be a false positive. That is the right direction to be wrong in,
//! since the alternative is a check that misses what it exists to catch.

use std::fs;
use std::path::{Path, PathBuf};

/// The module ADR-014 §5 names as the only place the exception may be used.
const DESIGNATED_MODULE: &str = "syscall.rs";

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

fn describe(openings: &[Opening]) -> Vec<String> {
    openings
        .iter()
        .map(|opening| format!("{}:{}", opening.file, opening.line))
        .collect()
}

#[test]
fn the_exception_is_opened_nowhere_outside_the_module_adr_014_names() {
    let outside = openings(|path| {
        path.file_name()
            .is_none_or(|name| name != DESIGNATED_MODULE)
    });
    assert!(
        outside.is_empty(),
        "ADR-014 confines the unsafe exception to {DESIGNATED_MODULE}; these are outside it: {:?}",
        describe(&outside)
    );
}

#[test]
fn this_build_opens_the_exception_nowhere_at_all() {
    // The claim the crate documentation makes, held as an assertion rather than
    // left as prose: the grant exists at the crate boundary and nothing has used
    // it, because every operation that would need it is still deferred
    // (ADR-014 §4). When the syscall module lands, this is the test that has to
    // be rewritten, and having to rewrite it deliberately is the point.
    let anywhere = openings(|_| true);
    assert!(
        anywhere.is_empty(),
        "the crate documentation says this build opens the exception nowhere: {:?}",
        describe(&anywhere)
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
