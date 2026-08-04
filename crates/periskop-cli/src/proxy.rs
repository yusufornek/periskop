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

use periskop_proxy::vault::{Backing, OpenRequest, Passphrase, ProfileName, Vault};
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
        // The default, and the only backing this command offers. The `file`
        // backend exists (`vault.psk`, ADR-007) but reaching it needs a flag, a
        // path and a way to carry the record counter across restarts, and all
        // three belong to the command surface `cli/spec.md` defines rather than to
        // this wave. Until they are decided, a run of `periskop proxy` writes
        // nothing to a disk, which is what CLAUDE.md's first prohibition asks for.
        backing: Backing::Memory,
    }) {
        Ok(vault) => ProxyOutcome::VaultOpened {
            notes: vault.notes().iter().map(ToString::to_string).collect(),
        },
        Err(refusal) => ProxyOutcome::Refused {
            reason: format!("{refusal} (HTTP {})", refusal.http_status()),
        },
    }
}

/// The most passphrase this command will take from standard input.
///
/// A passphrase somebody typed is tens of bytes and the longest anybody generates
/// is hundreds. The ceiling is here because standard input is whatever the caller
/// attached to it, and `read_to_end` on `/dev/zero` is a command that never
/// returns rather than one that says no.
const PASSPHRASE_CEILING: usize = 4096;

/// The buffer the read starts with, sized so an ordinary passphrase never grows it.
const PASSPHRASE_ROOM: usize = 256;

/// Reads a passphrase from a stream, into a buffer that clears itself.
///
/// One trailing newline is dropped, because a shell adds one and an operator did
/// not type it. Nothing else is trimmed: leading and inner whitespace are part of
/// a passphrase somebody chose.
///
/// Read in chunks rather than with `read_to_end`, and grown by hand. `Zeroizing`
/// clears the buffer it is holding when it drops, which is the **last** allocation
/// and not the ones before it: a `Vec` that grows copies its contents into a new
/// allocation and frees the old one with the bytes still in it. A passphrase long
/// enough to make the buffer grow twice therefore left two readable copies of its
/// own prefix on the heap, which is the thing `Zeroizing` was reached for to
/// prevent.
fn read_passphrase(source: &mut impl Read) -> Result<Passphrase, String> {
    let raw = read_bounded(source)?;
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

/// The bytes on the stream, in a buffer that never leaves a copy of itself behind.
///
/// Separate from [`read_passphrase`] so that the assembly can be tested on its own
/// bytes: [`Passphrase`] deliberately has no accessor a test could read, which is a
/// property worth keeping rather than one to work around.
fn read_bounded(source: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut raw = Zeroizing::new(Vec::with_capacity(PASSPHRASE_ROOM));
    let mut chunk = Zeroizing::new([0u8; PASSPHRASE_ROOM]);

    loop {
        let read = source
            .read(chunk.as_mut_slice())
            .map_err(|e| format!("the passphrase could not be read from standard input: {e}"))?;
        if read == 0 {
            return Ok(raw);
        }
        if raw.len() + read > PASSPHRASE_CEILING {
            return Err(format!(
                "the passphrase on standard input is longer than {PASSPHRASE_CEILING} bytes; \
                 the vault stays sealed"
            ));
        }
        grow_without_leaving_a_copy(&mut raw, read);
        raw.extend_from_slice(&chunk[..read]);
    }
}

/// Makes room for `more` bytes, clearing the buffer it grew out of.
///
/// The replacement is assigned over the old one, so the old `Zeroizing` is dropped
/// here and zeroizes the allocation it holds **before** it is freed. That is the
/// step `Vec`'s own reallocation skips, and it is the whole reason this function
/// exists rather than a call to `reserve`.
fn grow_without_leaving_a_copy(raw: &mut Zeroizing<Vec<u8>>, more: usize) {
    let needed = raw.len() + more;
    if needed <= raw.capacity() {
        return;
    }
    let mut grown = Zeroizing::new(Vec::with_capacity(needed.max(raw.capacity() * 2)));
    grown.extend_from_slice(raw);
    *raw = grown;
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
                // The note names the two memory parameters rather than the profile
                // it was asked for. That changed when the `file` backend arrived:
                // a vault file carries its own Argon2id parameters, so the note has
                // to describe the strength the vault is *actually* protected at,
                // and a note that named `ci` would be false for a file whose header
                // says something the shipped profiles never say.
                assert!(notes[0].contains("64 MiB"), "{notes:?}");
                assert!(notes[0].contains("256 MiB"), "{notes:?}");
                assert!(notes[0].contains("cheaper"), "{notes:?}");
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

    /// A passphrase longer than the buffer starts out with still arrives whole.
    ///
    /// The read is chunked and the buffer is grown by hand, so the join between
    /// two chunks is a place a byte could be dropped or repeated. Sized past two
    /// growths on purpose: one would exercise the fast path only.
    #[test]
    fn a_passphrase_longer_than_the_first_buffer_arrives_byte_for_byte() {
        for length in [
            PASSPHRASE_ROOM - 1,
            PASSPHRASE_ROOM,
            PASSPHRASE_ROOM * 3 + 7,
        ] {
            let typed: Vec<u8> = (0..length).map(|at| b'a' + (at % 23) as u8).collect();
            let mut source = typed.clone();
            source.push(b'\n');

            let read = read_bounded(&mut source.as_slice()).unwrap();
            assert_eq!(
                without_trailing_newline(&read),
                typed.as_slice(),
                "a {length} byte passphrase did not survive the read"
            );
        }
    }

    /// Standard input is whatever the caller attached to it, and this command does
    /// not read all of it.
    #[test]
    fn a_passphrase_past_the_ceiling_is_refused_rather_than_read() {
        let enormous = vec![b'x'; PASSPHRASE_CEILING + 1];
        let error = read_bounded(&mut enormous.as_slice()).unwrap_err();
        assert!(error.contains(&PASSPHRASE_CEILING.to_string()), "{error}");

        // And one exactly at the ceiling is still a passphrase, so what was refused
        // was the size and not the input.
        let at_the_ceiling = vec![b'x'; PASSPHRASE_CEILING];
        assert_eq!(
            read_bounded(&mut at_the_ceiling.as_slice()).unwrap().len(),
            PASSPHRASE_CEILING
        );
    }

    #[test]
    fn a_newline_alone_is_not_a_passphrase() {
        assert!(read_passphrase(&mut "\n".as_bytes()).is_err());
    }
}
