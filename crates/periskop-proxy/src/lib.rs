//! The masking forward proxy (ADR-004), and today the vault underneath it
//! (ADR-007).
//!
//! # What is here and what is not
//!
//! This crate is being built in the order the risk demands rather than the order
//! a request travels. The vault sits first: restoring an alias is a vault lookup,
//! so a vault that hands back the wrong record makes every layer above it deliver
//! somebody else's personal data while every test above it stays green. The alias
//! generators, the detection layers and the request path follow in later waves.
//!
//! There is deliberately **no masking code here yet**, and none of the vault's
//! types decide what an alias looks like. The vault stores an alias string it was
//! handed beside the value it stands for, and refuses to hand the value back
//! under any identity but the one it was sealed under.
//!
//! # Binary targets
//!
//! None. ADR-001 fixes one `[[bin]]` for the whole workspace, in `periskop-cli`,
//! and `periskop proxy` is a subcommand of it. `crates/periskop-cli/tests/
//! command_surface.rs` fails if a second one appears.

pub mod vault;
