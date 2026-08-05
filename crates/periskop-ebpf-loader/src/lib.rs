//! The crate that is allowed to touch a kernel, and the statement of what it
//! still cannot do.
//!
//! # Why this is a separate crate
//!
//! Loading an eBPF program is a `bpf(2)` call, a set of file descriptors and a
//! memory mapped ring buffer. Every one of those is a foreign function
//! boundary, and the workspace sets `unsafe_code = "forbid"` (ADR-002). ADR-002
//! named the eBPF loader as one of three places allowed the exception but did
//! not say through which mechanism, and `forbid` is not a level a crate can
//! lift from the inside. ADR-014 closed that gap: the exception is a **crate
//! boundary**, declared in this package's own manifest, so the other seven
//! crates keep the guarantee at full strength and the exception is a directory
//! a reviewer can point at rather than a line in a shared file.
//!
//! # What this crate is not allowed to contain
//!
//! No `Flow`, no `Observation`, no classification, no naming, no bucketing. The
//! reason is testability rather than taste: the programs cannot run in
//! continuous integration, so anything decided in here ships untested. Whatever
//! a report ends up saying about a destination is decided in
//! `periskop-network-sensor`, which builds and runs on every platform in the
//! workspace. This crate carries the transport and the gate, and nothing that
//! interprets.
//!
//! The dependency arrow points one way for the same reason it points one way
//! everywhere else in this workspace: `periskop-network-sensor` depends on this
//! crate behind an off by default feature, and this crate depends on nothing of
//! the sensor's. That is also what keeps the two out of a cycle, and it is why
//! the `KernelEvents` implementation itself lives on the sensor's side of the
//! seam rather than here (ADR-014 revision note, 2026-08-04).
//!
//! # Two builds of this crate, and how to tell which one you have
//!
//! The difference is decided at compile time by `build.rs` and never at run
//! time. It is not a runtime switch because a binary that could be talked into
//! loading kernel programs by its environment would be a worse thing to ship
//! than either of the two.
//!
//! **Without a program object**, which is every build on the macOS machine this
//! repository is developed on and every build where `PERISKOP_EBPF_OBJECT` was
//! not set: nothing is ever loaded, [`EbpfLoader::poll`] never returns an event,
//! and [`EbpfLoader::load`] runs every check it can and then reports
//! [`LoaderUnavailable::LoaderNotBuilt`]. That is a stated cause in the same
//! fixed vocabulary a permission failure uses. The sensor puts it in the
//! coverage statement and the scan carries on: such a report says "the sensor
//! did not run, and here is why", never "the network was clean".
//!
//! **With one** (Linux only): [`EbpfLoader::load`] hands the object to the
//! kernel through `aya`, attaches the hooks the caller asked for, gives up the
//! capabilities that allowed it (`network-sensor/spec.md` §9), and
//! [`EbpfLoader::poll`] starts returning frames decoded by [`record`].
//!
//! The object itself is built separately, from `crates/periskop-ebpf-object/`,
//! because `bpfel-unknown-none` has no precompiled `core` and needs a nightly
//! toolchain and `bpf-linker` that the workspace's own pin does not provide
//! (ADR-002 D-19). Keeping that build a separate, visible step is what lets a
//! run that could not perform it produce a working binary that says so.
//!
//! # What no build of this crate does
//!
//! It carries no `clsact` classifier, so no build of it observes DNS answers or
//! TLS server names, and a plan naming either traffic control hook is refused
//! whole rather than trimmed. ADR-008 still fixes `tc` as the mechanism for
//! them; what is absent is the program, and the gate artefact lists name
//! resolution among the things it does not prove.
//!
//! # Where the exception is used
//!
//! In [`syscall`], and nowhere else. `tests/unsafe_boundary.rs` reads this
//! crate's own sources and fails the build if any other file opens it, and also
//! fails if that module stops opening it at all, because a boundary check that
//! passes by there being nothing to check is not a boundary check.
//!
//! The exception turned out to be narrower than ADR-014 expected. `aya` exposes
//! loading, attaching and the ring buffer through a safe API, so what is left is
//! three calls with no equivalent in `std`: reading capabilities, dropping them,
//! and the monotonic clock the kernel program's own clock has to be aligned
//! against.

#[cfg(all(target_os = "linux", periskop_kernel_object))]
mod attached;
pub mod capability;
pub mod hook;
pub mod loader;
mod object;
pub mod platform;
pub mod record;
#[cfg(all(target_os = "linux", periskop_kernel_object))]
mod syscall;
mod unavailable;

pub use capability::Capabilities;
pub use hook::Hook;
pub use loader::{EbpfLoader, RawBatch};
pub use platform::HostPlatform;
pub use record::{PayloadKind, Protocol, RawEvent, RawKey, RawProcess, RecordError};
pub use unavailable::LoaderUnavailable;

/// Whether the run that is interpreting this crate can see the exception at all.
///
/// ADR-014 §5 requires a separate miri or sanitiser target for this crate, and
/// the reason it requires one is [`syscall`]: it is the only file in the
/// workspace that steps outside `unsafe_code = "forbid"`, and it is compiled
/// only when a kernel side object is present. A miri job configured without one
/// therefore interprets a crate in which that module does not exist, passes, and
/// establishes nothing about the thing it was created to check. That is what the
/// job in `.github/workflows/ci.yml` did while it set `PERISKOP_EBPF_OBJECT` to
/// the empty string.
///
/// A comment would not have caught it, because the job was green either way. So
/// it is a test, and it is red on exactly the configuration that used to be
/// silently green.
#[cfg(all(test, miri))]
mod under_miri {
    #[test]
    fn miri_is_looking_at_the_build_that_carries_the_unsafe_module() {
        assert!(
            cfg!(all(target_os = "linux", periskop_kernel_object)),
            "miri is interpreting a build of this crate with no `syscall` module in it, so it is \
             checking the one thing this crate has no exception for. Run it on Linux with \
             PERISKOP_EBPF_OBJECT pointing at a built kernel side object."
        );
    }
}
