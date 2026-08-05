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
//! The vault's own types still decide nothing about what an alias looks like.
//! The vault stores an alias string it was handed beside the value it stands
//! for, and refuses to hand the value back under any identity but the one it was
//! sealed under. What an alias *is* belongs to [`alias`], which was added in the
//! wave after the vault and answers a different question: how to name a value
//! without naming somebody else in the process (ADR-010's P-0).
//!
//! [`detect`] is the wave after that: which bytes of a prompt stand for
//! somebody, decided by two deterministic layers and by nothing statistical.
//! [`policy`] is what an operator writes down, loaded fail closed, because a
//! rule that is silently dropped is a value the operator believes is masked.
//!
//! The request path follows. Nothing here reads an HTTP request yet.
//!
//! # Binary targets
//!
//! None. ADR-001 fixes one `[[bin]]` for the whole workspace, in `periskop-cli`,
//! and `periskop proxy` is a subcommand of it. `crates/periskop-cli/tests/
//! command_surface.rs` fails if a second one appears.

// The vault may not write to a process stream, and neither may anything else in
// this crate. `tests/vault_no_plaintext.rs` searches five surfaces for a planted
// value and `stdout` is the sixth; a single `dbg!(plaintext)` in the sealing path
// puts every masked value on `stderr`, where no artefact and no reviewer would
// look. Denied here rather than left to review, and `no_vault_source_writes_to_a_
// process_stream` is what catches an `#[allow]` put back on top of it.
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

pub mod alias;
pub mod detect;
pub mod policy;
pub mod vault;
