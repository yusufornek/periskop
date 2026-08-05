//! Finds the kernel side object, or records that there is not one.
//!
//! `crates/periskop-ebpf-object/` compiles for `bpfel-unknown-none` on a nightly
//! toolchain with `bpf-linker`, none of which the workspace's own toolchain pin
//! provides (ADR-002 D-19). So the two builds are separate, and this script is
//! the join: whoever built the object points `PERISKOP_EBPF_OBJECT` at it, and
//! this crate embeds it.
//!
//! With the variable unset, which is every ordinary `cargo build` on every
//! platform, nothing changes: the `periskop_kernel_object` cfg stays off, `aya`
//! is never called, and `EbpfLoader::load` reports `loader_not_built` exactly as
//! it did before. That is the honest answer for a binary that carries no
//! program, and it is the same answer whether the object was never built or the
//! build of it failed.
//!
//! # Why an environment variable rather than a build of the object from here
//!
//! A build script that shelled out to a second `cargo` on a second toolchain
//! would make an ordinary `cargo build` depend on a nightly compiler, a linker
//! plugin and a network fetch, and would fail in a way that looks like this
//! crate failing. Keeping the object's build a separate, visible step means a
//! run that could not build it says so in the step that could not, and the
//! resulting binary still works, still scans, and still declares what it cannot
//! do.

use std::path::Path;

/// Where a caller says the compiled object is.
const OBJECT_PATH: &str = "PERISKOP_EBPF_OBJECT";

fn main() {
    // Declared so that `unexpected_cfgs` stays quiet under `-D warnings`. A
    // custom cfg nobody declared is a warning, and a warning is a failed build
    // in continuous integration.
    println!("cargo::rustc-check-cfg=cfg(periskop_kernel_object)");
    println!("cargo::rerun-if-env-changed={OBJECT_PATH}");

    let Some(raw) = std::env::var_os(OBJECT_PATH) else {
        return;
    };
    // Empty means unset. Continuous integration clears an inherited variable by
    // setting it to nothing, and a build that treated that as "a path I cannot
    // read" would fail where the caller was asking for the ordinary build.
    if raw.is_empty() {
        return;
    }
    let path = Path::new(&raw);

    // A path that was given and does not resolve is an error rather than a
    // silent fallback to the object-less build. Somebody who set the variable
    // meant to ship a loader, and a build that quietly produced one without a
    // program would be the exact failure mode this crate exists to avoid.
    let object = match path.canonicalize() {
        Ok(object) => object,
        Err(error) => {
            println!("cargo::error={OBJECT_PATH} is set to {raw:?}, which cannot be read: {error}");
            return;
        }
    };
    match object.metadata().map(|meta| meta.len()) {
        Ok(0) | Err(_) => {
            println!(
                "cargo::error={OBJECT_PATH} points at an empty file: {}",
                object.display()
            );
            return;
        }
        Ok(_) => {}
    }

    let Some(text) = object.to_str() else {
        println!("cargo::error={OBJECT_PATH} is not valid UTF-8, and `include_bytes!` needs a path it can be handed as a literal");
        return;
    };
    println!("cargo::rerun-if-changed={text}");
    println!("cargo::rustc-env=PERISKOP_EBPF_OBJECT_PATH={text}");
    println!("cargo::rustc-cfg=periskop_kernel_object");
}
