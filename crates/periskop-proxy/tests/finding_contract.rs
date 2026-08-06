#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! The proxy's finding, held to the example that documents it.
//!
//! This crate writes a finding as a `serde_json::Value` rather than through
//! `periskop_core::finding::Finding`, so the schema version it stamps is a
//! second copy of a constant that lives in another crate. Nothing compared the
//! two and they drifted: this crate said `1.2`, the core type said `1.1`, and
//! `finding.schema.json` was at `1.3`. A reader of a report could not tell which
//! of the three it had been written against, and every gate was green.
//!
//! It lives here rather than beside the code it checks because
//! `vault_touches_no_files.rs` scans every module of `src/` for a filesystem
//! call and refuses one. That guard is about the alias to person map, which is
//! at its widest outside the vault, and reading a schema example is not a reason
//! to widen it. An integration test is outside the scanned tree and is the right
//! place for a check that has to open a file.

use periskop_proxy::http::declare::{Declared, Gap, Subject};

/// The example this crate's output is documented by.
fn shipped_example() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/examples/finding.proxy.valid.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("the shipped example is not valid JSON")
}

/// A declaration built the only way there is to build one.
fn declared() -> Declared {
    Declared::make(
        Gap::ToolArguments,
        true,
        true,
        Subject {
            scope: "9f2c4a10bb730e5188a4d7c6e0f21a34",
            provider: "anthropic",
        },
    )
    .expect("a nameable subject was refused")
}

#[test]
fn the_version_this_crate_stamps_is_the_one_the_shipped_example_carries() {
    let emitted = declared().finding().to_value();
    assert_eq!(
        emitted["schema_version"],
        shipped_example()["schema_version"],
        "the proxy stamps a schema version the example beside it does not carry"
    );
}

#[test]
fn the_closed_vocabularies_this_crate_writes_are_the_ones_the_example_uses() {
    // Read out of the example rather than restated, for the same reason the
    // version is: a restated list agrees on the day both change together, which
    // is the one change that cannot go wrong.
    let emitted = declared().finding().to_value();
    let example = shipped_example();

    for field in ["kind", "source", "confidence", "coverage_impact"] {
        assert_eq!(emitted[field], example[field], "{field} disagrees");
    }
    assert_eq!(
        emitted["detector"]["component"],
        example["detector"]["component"]
    );
    assert_eq!(
        emitted["refs"][0]["ref_type"],
        example["refs"][0]["ref_type"]
    );
    assert_eq!(
        emitted["evidence"][0]["evidence_type"],
        example["evidence"][0]["evidence_type"]
    );
}

#[test]
fn the_exchange_reference_is_shaped_the_way_the_example_says() {
    // `px_` and sixteen hex characters. The identity type that parses it lives
    // in `periskop-core`, which this crate deliberately does not depend on, so
    // the shape is asserted here against the same pattern the schema pins.
    let emitted = declared().finding().to_value();
    let reference = emitted["refs"][0]["ref_id"]
        .as_str()
        .expect("refs[0].ref_id is not a string");
    let rest = reference
        .strip_prefix("px_")
        .unwrap_or_else(|| panic!("{reference} does not start with px_"));
    assert_eq!(rest.len(), 16, "{reference}");
    assert!(
        rest.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "{reference}"
    );
}
