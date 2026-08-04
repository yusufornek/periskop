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
//! # What this build cannot do, stated plainly
//!
//! **There is no kernel side program object in this build, so nothing is ever
//! loaded and [`EbpfLoader::poll`] never returns an event.** [`EbpfLoader::load`]
//! runs every check it can and then reports
//! [`LoaderUnavailable::LoaderNotBuilt`], which is a stated cause in the same
//! fixed vocabulary a permission failure uses. The sensor puts that cause in the
//! coverage statement, and the scan carries on: a report from this build says
//! "the sensor did not run, and here is why", never "the network was clean".
//!
//! Three things are missing, and each is a decision rather than a gap somebody
//! forgot to fill:
//!
//! 1. **A user space eBPF runtime.** `aya` is the accepted candidate in
//!    principle (ADR-014 §4) and is still not added. It compiles on Linux only,
//!    this workspace is developed on macOS, and code that no gate on the
//!    development machine can compile cannot be claimed to have passed a gate.
//! 2. **The kernel side object.** It needs the `bpfel-unknown-none` target and
//!    `bpf-linker`, which is a build and toolchain decision of its own against a
//!    toolchain this repository pins (ADR-002 D-19).
//! 3. **The privilege drop.** `network-sensor/spec.md` §9 requires the sensor to
//!    give up its capabilities the moment the descriptors are open. That is a
//!    syscall, so it belongs in this crate, next to the descriptors it is
//!    dropping around, and it arrives with them.
//!
//! What is here instead is everything the seam needs that does **not** need a
//! kernel, written and tested now so that what remains is a hookup rather than a
//! design: the record layout the kernel program will have to write
//! ([`record`]), the capability gate that decides whether a load may be
//! attempted at all ([`capability`], [`loader`]), the closed hook list a caller
//! may ask for ([`hook`]), and the platform decision ([`platform`]).
//!
//! # Where the exception will be used
//!
//! When the syscalls arrive they go in a single module named `syscall`, and
//! nowhere else. That module does not exist yet because an empty one would be
//! the "we will need it later" code this repository does not commit; the rule it
//! will live under is enforced today by `tests/unsafe_boundary.rs`, which reads
//! this crate's own sources and fails if any file outside that one module opens
//! the exception. The boundary is therefore in force before there is anything
//! inside it.

pub mod capability;
pub mod hook;
pub mod loader;
pub mod platform;
pub mod record;
mod unavailable;

pub use capability::Capabilities;
pub use hook::Hook;
pub use loader::{EbpfLoader, RawBatch};
pub use platform::HostPlatform;
pub use record::{PayloadKind, Protocol, RawEvent, RawKey, RawProcess, RecordError};
pub use unavailable::LoaderUnavailable;
