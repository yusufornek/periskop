//! The `periskop proxy` command surface.
//!
//! # What this command does today, and what it does not
//!
//! It opens the masking vault and stops. There is no listening socket yet: the
//! request path, the detection layers and the alias generators are later waves,
//! and the order is deliberate rather than accidental. A streaming rewriter built
//! on the wrong alias set works perfectly and delivers the wrong data, and its
//! tests pass while it does it, so the vault and the alias generators are built
//! first.
//!
//! What that means for this command is that it cannot succeed. It derives the
//! key, reports what the vault would be, and exits non zero saying nothing is
//! listening. The alternative would be a command that starts, accepts a
//! connection and passes it through unmasked, which is the one behaviour
//! `proxy/spec.md` section 10 rules out entirely.
//!
//! # The passphrase comes from standard input
//!
//! ADR-016 section 4 struck the operating system keyring from this phase, so the
//! passphrase is the only way in. It is read from standard input rather than from
//! a flag or an environment variable: a flag puts the passphrase in the process
//! table for every other user on the machine to read, and an environment variable
//! puts it in `/proc` and in every child process. Standard input is also what
//! makes the command usable without a terminal, which `cli/spec.md` requires of
//! everything here.

use std::io::Read;

use periskop_proxy::vault::{OpenRequest, Passphrase, ProfileName, Vault};
use zeroize::Zeroizing;

/// What one `periskop proxy` invocation was asked for.
pub struct ProxyRequest<'a> {
    /// The `--vault-profile` value, if the caller named one.
    pub vault_profile: Option<&'a str>,
}

/// How far the command got.
///
/// A type rather than an exit code so that the wiring in `main.rs` decides the
/// code in one place, and so that this can be tested without a process.
#[derive(Debug, PartialEq, Eq)]
pub enum ProxyOutcome {
    /// The vault opened. Whatever else it says, this run still ends non zero:
    /// nothing is listening.
    VaultOpened { notes: Vec<String> },
    /// The vault did not open, and no request would have been served.
    Refused { reason: String },
}

/// Reads the passphrase, opens the vault, and reports what happened.
///
/// Takes its input as a reader so that the passphrase path is exercised by a test
/// rather than only by a person at a terminal.
pub fn run(request: &ProxyRequest<'_>, passphrase_source: &mut impl Read) -> ProxyOutcome {
    let profile = match request.vault_profile {
        None => ProfileName::default(),
        Some(name) => match ProfileName::parse(name) {
            Some(profile) => profile,
            // Refused rather than defaulted. A typo that quietly ran under some
            // other key derivation strength is the surprise this command exists
            // to avoid.
            None => {
                return ProxyOutcome::Refused {
                    reason: format!(
                        "unknown vault profile `{name}`; expected `{}` or `{}`",
                        ProfileName::Standard.as_str(),
                        ProfileName::Ci.as_str()
                    ),
                }
            }
        },
    };

    let passphrase = match read_passphrase(passphrase_source) {
        Ok(passphrase) => passphrase,
        Err(reason) => return ProxyOutcome::Refused { reason },
    };

    match Vault::open(&OpenRequest {
        passphrase: &passphrase,
        profile,
    }) {
        Ok(vault) => ProxyOutcome::VaultOpened {
            notes: vault.notes().iter().map(ToString::to_string).collect(),
        },
        Err(refusal) => ProxyOutcome::Refused {
            reason: format!("{refusal} (HTTP {})", refusal.http_status()),
        },
    }
}

/// Reads a passphrase from a stream, into a buffer that clears itself.
///
/// One trailing newline is dropped, because a shell adds one and an operator did
/// not type it. Nothing else is trimmed: leading and inner whitespace are part of
/// a passphrase somebody chose.
fn read_passphrase(source: &mut impl Read) -> Result<Passphrase, String> {
    let mut raw = Zeroizing::new(Vec::new());
    source
        .read_to_end(&mut raw)
        .map_err(|e| format!("the passphrase could not be read from standard input: {e}"))?;

    let passphrase = Passphrase::new(without_trailing_newline(&raw).to_vec());
    if passphrase.is_empty() {
        return Err(
            "no vault passphrase on standard input; the vault stays sealed and no request \
             would be served (HTTP 503)"
                .to_owned(),
        );
    }
    Ok(passphrase)
}

/// Drops the line ending a shell adds, and nothing else.
///
/// One newline, optionally preceded by a carriage return. Leading and inner
/// whitespace stay: they are part of a passphrase somebody chose, and trimming
/// them would make the vault refuse the same passphrase typed anywhere else.
fn without_trailing_newline(typed: &[u8]) -> &[u8] {
    let stripped = typed.strip_suffix(b"\n").unwrap_or(typed);
    stripped.strip_suffix(b"\r").unwrap_or(stripped)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn request(profile: Option<&str>) -> ProxyRequest<'_> {
        ProxyRequest {
            vault_profile: profile,
        }
    }

    #[test]
    fn an_empty_standard_input_refuses_rather_than_opening_an_empty_vault() {
        let outcome = run(&request(Some("ci")), &mut std::io::empty());
        match outcome {
            ProxyOutcome::Refused { reason } => {
                assert!(reason.contains("passphrase"), "{reason}");
                assert!(reason.contains("503"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_unknown_profile_is_refused_even_with_a_good_passphrase() {
        let outcome = run(&request(Some("fast")), &mut "hunter2\n".as_bytes());
        match outcome {
            ProxyOutcome::Refused { reason } => {
                assert!(reason.contains("fast"), "{reason}");
                assert!(reason.contains("default"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_reduced_profile_opens_the_vault_and_says_what_it_cost() {
        let outcome = run(&request(Some("ci")), &mut "hunter2\n".as_bytes());
        match outcome {
            ProxyOutcome::VaultOpened { notes } => {
                assert_eq!(notes.len(), 1);
                assert!(notes[0].contains("ci"), "{notes:?}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_trailing_newline_is_not_part_of_the_passphrase() {
        // A shell adds it, an operator did not type it, and a vault that treated
        // it as key material would refuse the same passphrase typed anywhere else.
        assert_eq!(without_trailing_newline(b"hunter2\n"), b"hunter2");
        assert_eq!(without_trailing_newline(b"hunter2\r\n"), b"hunter2");
        assert_eq!(without_trailing_newline(b"hunter2"), b"hunter2");
        // And nothing more than that one line ending.
        assert_eq!(without_trailing_newline(b" hunter 2 \n"), b" hunter 2 ");
        assert_eq!(without_trailing_newline(b"hunter2\n\n"), b"hunter2\n");
    }

    #[test]
    fn a_newline_alone_is_not_a_passphrase() {
        assert!(read_passphrase(&mut "\n".as_bytes()).is_err());
    }
}
