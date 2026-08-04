//! The pieces the `periskop` binary is assembled from.
//!
//! A library beside the binary rather than a binary alone. The integration tests
//! used to reach into `src/scan.rs` through a `#[path]` attribute, which compiles
//! the module a second time inside the test binary and exercises a copy rather
//! than the surface anything else uses. The moment that module touched something
//! only `main.rs` provides, the tests would have stopped compiling for a reason
//! that reads as unrelated.
//!
//! The public surface is deliberately small: the scan, the two front ends that
//! call it, and the clock the envelope needs.

pub mod clock;
pub mod hook;
pub mod render;
pub mod rpc;
pub mod scan;
