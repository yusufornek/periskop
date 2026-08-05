// No source file may contain a string a secret scanner will call a credential.
//
// This is the source side of the invariant `p0_invariants.rs` enforces on
// generated aliases, and it exists because the same mistake was made twice in
// one day, in two different directions.
//
// The generator produced aliases shaped like live Stripe keys, which would have
// made every masked prompt trip a scanner downstream. That was fixed by
// changing what the generator emits. Then the detector tests were written with
// real looking keys as input, which is unavoidable in spirit, because a
// detector for provider keys has to be tested against text that looks like a
// provider key.
//
// Both times GitHub push protection caught it, and both times it was right on
// the evidence it had. The published documentation examples from Stripe and
// GitHub open nothing, but nothing in the string says so, and a scanner that
// tried to tell them apart would be a scanner that can be fooled.
//
// So the rule is not "do not test against credential shapes". It is "do not
// leave a continuous match in a source file". Test fixtures are assembled at
// run time from parts, in `detect::sample`, and this test keeps them that way.

use std::fs;
use std::path::Path;

/// What the common scanners look for, by prefix and body length.
///
/// The list is short on purpose: it covers the families this repository has
/// actually been blocked on plus the ones most likely to appear in a masking
/// fixture. It is not a general credential detector and does not need to be,
/// because it guards a source tree rather than user text.
const FAMILIES: &[(&str, usize)] = &[
    ("sk_live_", 16),
    ("sk_test_", 16),
    ("ghp_", 30),
    ("gho_", 30),
    ("github_pat_", 20),
    ("xoxb-", 20),
    ("AIza", 30),
];

fn body_run(rest: &str) -> usize {
    rest.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .count()
}

/// A hit is a prefix followed by an unbroken run of at least `minimum` body
/// characters. The run has to be unbroken: `sk_live_` followed by a quote, a
/// brace or a format placeholder is what an assembled fixture looks like, and
/// that is the shape this test is written to permit.
fn credential_shaped(line: &str) -> Option<String> {
    for (prefix, minimum) in FAMILIES {
        let mut from = 0;
        while let Some(at) = line[from..].find(prefix) {
            let start = from + at;
            let rest = &line[start + prefix.len()..];
            if body_run(rest) >= *minimum {
                return Some((*prefix).to_string());
            }
            from = start + prefix.len();
        }
    }
    None
}

fn walk(dir: &Path, hits: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, hits);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            for (number, line) in text.lines().enumerate() {
                if let Some(family) = credential_shaped(line) {
                    hits.push(format!("{}:{} ({family})", path.display(), number + 1));
                }
            }
        }
    }
}

#[test]
fn no_credential_shaped_literal() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut hits = Vec::new();
    walk(&root.join("src"), &mut hits);
    walk(&root.join("tests"), &mut hits);

    assert!(
        hits.is_empty(),
        "these lines carry a string a secret scanner will read as a live \
         credential, which blocks a push and, worse, teaches every scanner \
         downstream to cry wolf. Assemble the value at run time instead, the \
         way detect::sample does:\n  {}",
        hits.join("\n  ")
    );
}

#[test]
fn the_check_can_tell_an_assembled_fixture_from_a_written_one() {
    // Without this, a bug that made credential_shaped always return None would
    // leave the test above passing over any source tree at all.
    //
    // The positive case is itself assembled, because the first version of this
    // file wrote it out and the test above caught this file. That is the check
    // working, and it is the reason the rule has to apply to itself.
    let written_out = format!(r#"let k = "sk_{}_{}";"#, "live", "4eC39HqLyjWDarjtT1zdp7dc");
    assert!(credential_shaped(&written_out).is_some());
    assert!(credential_shaped(r#"format!("sk_{}_{}", "live", "4eC39Hq")"#).is_none());
    assert!(credential_shaped(&format!(r#"let p = "sk_{}_";"#, "live")).is_none());
}
