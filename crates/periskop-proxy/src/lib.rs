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
//! [`http`] is where all of it becomes a running component, and it is the first
//! module in this crate that opens a socket. Everything below it was reachable
//! only from this process; from there a port is listening, and the vault keys, the
//! session to alias map and the unmasked request bodies are behind it. That is why
//! the default bind address is loopback, why header redaction is enforced by a
//! function rather than by review, and why every refusal in it is fail closed.
//!
//! `http::stream` is the answer coming back, and it is the hardest thing in this
//! crate. Everything above it decides once, over a whole document; a stream
//! arrives in pieces the network chose, and `PSK_PERSON_1` can be `PSK_PER` in one
//! of them and `SON_1` in the next. Three claims have to hold at the same time
//! there: no alias reaches the client cut in half, no un-masked value is released
//! early, and the latency budget is not spent holding everything back. They pull
//! against each other, so the resolution is one function that decides every
//! release and returns what proves it safe, rather than a rule spread over the
//! code and remembered.
//!
//! # Binary targets
//!
//! None. ADR-001 fixes one `[[bin]]` for the whole workspace, in `periskop-cli`,
//! and `periskop proxy` is a subcommand of it. `crates/periskop-cli/tests/
//! command_surface.rs` fails if a second one appears.

// The vault may not write to a process stream, and neither may anything else in
// this crate. `tests/vault_no_plaintext.rs` searches a named list of surfaces for
// a planted value and two of them are the `stdout` and `stderr` of real child
// processes: one that runs a vault's lifecycle, one that masks a prompt and
// restores an answer. A single `dbg!(plaintext)` on either path puts every value
// a user typed on `stderr`, where no artefact and no reviewer would look.
//
// This denial is crate wide, and that is exactly why a scan that read one subtree
// was not enough to hold it: an `#[allow(clippy::dbg_macro)]` written on **any**
// module turns it off for that module, and the request path is where the
// plaintext is at its widest. `no_source_writes_to_a_process_stream` reads what
// this line covers and fails on the `#[allow]` that would put the denial back to
// sleep.
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

pub mod alias;
pub mod detect;
pub mod http;
pub mod policy;
pub mod vault;
