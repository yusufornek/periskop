//! The `periskop proxy` command surface.
//!
//! # What this command does
//!
//! It reads the vault passphrase, opens the vault, loads the policy, and serves
//! the masking proxy on a socket until the process ends.
//!
//! It did not always. For several waves it opened the vault, printed that
//! nothing was listening, and exited non zero, while `periskop-proxy`'s whole
//! HTTP surface sat finished behind a library boundary that only the phase gate's
//! own harness ever crossed. Every masking claim in this repository was therefore
//! true of a test harness and not of the program anybody would install. That is
//! the failure this module now exists to prevent: the shipped binary is the thing
//! under test, and `tests/proxy_command.rs` drives this one.
//!
//! # Assembling and serving are two functions
//!
//! [`prepare`] does everything that can refuse and touches no socket; [`serve`]
//! binds and runs forever. Split because everything worth checking is in the
//! first half, and a function that ends in an accept loop cannot be called by a
//! test that intends to return.
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
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use periskop_proxy::http::gateway::{Clock, Gateway};
use periskop_proxy::http::listen::{Exposure, ListenAddress};
use periskop_proxy::http::route::Provider;
use periskop_proxy::http::serve::Listener;
use periskop_proxy::http::upstream::{RustlsUpstream, Upstream};
use periskop_proxy::http::AllowList;
use periskop_proxy::policy::Policy;
use periskop_proxy::vault::{Backing, OpenRequest, Passphrase, ProfileName, Vault};
use zeroize::Zeroizing;

/// What one `periskop proxy` invocation was asked for.
pub struct ProxyRequest<'a> {
    /// The `--vault-profile` value, if the caller named one.
    pub vault_profile: Option<&'a str>,
    /// The `--policy` path. `None` means `./policy.toml`.
    pub policy: Option<&'a Path>,
    /// The `--listen` value. `None` means `127.0.0.1:8787`.
    pub listen: Option<&'a str>,
    /// Whether `--allow-external-interface` was given.
    pub allow_external_interface: bool,
    /// `--upstream <provider>=<url>`, in the order they were written.
    pub upstreams: &'a [String],
}

/// Everything a run needs, assembled without binding anything.
pub struct Prepared {
    pub gateway: Gateway,
    pub address: ListenAddress,
    /// What the vault wants the operator to know, plus every upstream override.
    pub notes: Vec<String>,
}

/// How far the command got.
///
/// A type rather than an exit code so that the wiring in `main.rs` decides the
/// code in one place, and so that this can be tested without a process.
pub enum ProxyOutcome {
    /// Everything opened and loaded. Nothing is listening yet: [`serve`] does
    /// that, and it is a separate call so that a test can stop here.
    Ready(Box<Prepared>),
    /// Something refused, and no request would have been served.
    Refused { reason: String },
}

/// Assembles the proxy: passphrase, vault, policy, allow list, bind address.
///
/// Takes its input as a reader so that the passphrase path is exercised by a test
/// rather than only by a person at a terminal. Every branch that cannot be
/// satisfied answers [`ProxyOutcome::Refused`], because the alternative to a
/// proxy that will not start is a proxy that starts and forwards, and
/// `proxy/spec.md` section 10 rules that out entirely.
pub fn prepare(request: &ProxyRequest<'_>, passphrase_source: &mut impl Read) -> ProxyOutcome {
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

    let address = match bind_address(request.listen, request.allow_external_interface) {
        Ok(address) => address,
        Err(reason) => return ProxyOutcome::Refused { reason },
    };

    let overrides = match upstream_overrides(request.upstreams) {
        Ok(overrides) => overrides,
        Err(reason) => return ProxyOutcome::Refused { reason },
    };

    // The policy before the passphrase, so an operator with an unloadable policy
    // is told about it without having typed a secret first.
    let policy_path = request
        .policy
        .map_or_else(|| PathBuf::from(DEFAULT_POLICY), Path::to_owned);
    let root = policy_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_owned);
    let policy = match Policy::load_from_path(&policy_path, &root, None) {
        Ok(policy) => policy,
        Err(refusal) => {
            return ProxyOutcome::Refused {
                reason: format!(
                    "the policy at {} did not load, so no request is served: {refusal}",
                    policy_path.display()
                ),
            }
        }
    };

    let passphrase = match read_passphrase(passphrase_source) {
        Ok(passphrase) => passphrase,
        Err(reason) => return ProxyOutcome::Refused { reason },
    };

    let vault = match Vault::open(&OpenRequest {
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
        Ok(vault) => vault,
        Err(refusal) => {
            return ProxyOutcome::Refused {
                reason: format!("{refusal} (HTTP {})", refusal.http_status()),
            }
        }
    };

    let mut notes: Vec<String> = vault.notes().iter().map(ToString::to_string).collect();

    // An operator who wrote a base URL on the command line has named that host as
    // explicitly as an allow list entry could, so the host joins the list. Said
    // out loud rather than done quietly: a widened allow list nobody can see in
    // the output is the shape of an accident.
    let allow = AllowList::of(
        AllowList::shipped()
            .hosts()
            .map(ToOwned::to_owned)
            .chain(overrides.iter().map(|(_, host, _)| host.clone())),
    );

    let upstream: Arc<dyn Upstream> = match RustlsUpstream::new() {
        Ok(client) => Arc::new(client),
        Err(unreachable) => {
            return ProxyOutcome::Refused {
                reason: format!("no outbound client could be built: {}", unreachable.why),
            }
        }
    };

    let mut gateway = match Gateway::new(policy, vault, upstream, allow, Clock::System) {
        Ok(gateway) => gateway,
        Err(refusal) => {
            return ProxyOutcome::Refused {
                reason: refusal.detail().to_owned(),
            }
        }
    };
    for (provider, host, url) in &overrides {
        gateway = match gateway.with_base(*provider, url) {
            Ok(gateway) => gateway,
            Err(refusal) => {
                return ProxyOutcome::Refused {
                    reason: refusal.detail().to_owned(),
                }
            }
        };
        notes.push(format!(
            "{} requests go to {url}, and `{host}` was added to the connect allow list because \
             you named it",
            provider.as_str()
        ));
    }

    ProxyOutcome::Ready(Box::new(Prepared {
        gateway,
        address,
        notes,
    }))
}

/// Binds the socket and answers requests until the process ends.
///
/// `announce` is handed the address that was actually bound, which is not always
/// the one that was asked for: port `0` is resolved by the kernel, and a caller
/// that used it has no other way to learn where to send anything.
pub fn serve(prepared: Prepared, announce: impl FnOnce(SocketAddr)) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("no runtime could be started: {error}"))?;

    runtime.block_on(async move {
        let listener = Listener::bind(prepared.address)
            .await
            .map_err(|error| format!("{} could not be bound: {error}", prepared.address))?;
        announce(listener.address());
        listener
            .serve(Arc::new(prepared.gateway))
            .await
            .map_err(|error| format!("the listener stopped: {error}"))
    })
}

/// Where the policy is read from when the caller names no path.
///
/// A relative path rather than a system directory: this build is a single tenant,
/// local deployment (roadmap F4 phase boundary item 3), so the policy belongs
/// beside the project it governs. There is no built-in fallback policy, and there
/// may not be: a masking proxy running under rules nobody wrote is the failure
/// this whole component is an argument against.
const DEFAULT_POLICY: &str = "policy.toml";

fn bind_address(listen: Option<&str>, allow_external: bool) -> Result<ListenAddress, String> {
    let exposure = if allow_external {
        Exposure::ExternalInterfaceAllowed
    } else {
        Exposure::LoopbackOnly
    };
    match listen {
        None => Ok(ListenAddress::loopback()),
        Some(text) => ListenAddress::parse(text, exposure).map_err(|refusal| refusal.to_string()),
    }
}

/// Reads `--upstream <provider>=<url>` into the triples the gateway needs.
///
/// The host is returned beside the URL because the allow list is keyed on hosts
/// and re-parsing the URL in two places is how the two would come to disagree.
fn upstream_overrides(written: &[String]) -> Result<Vec<(Provider, String, String)>, String> {
    let mut out = Vec::with_capacity(written.len());
    for entry in written {
        let Some((name, url)) = entry.split_once('=') else {
            return Err(format!(
                "`{entry}` is not of the form <provider>=<url>, for example \
                 openai=https://gateway.internal.example/v1"
            ));
        };
        let provider = match name {
            "openai" => Provider::OpenAi,
            "anthropic" => Provider::Anthropic,
            other => {
                return Err(format!(
                    "`{other}` is not a provider this build proxies; expected `openai` or \
                     `anthropic`"
                ))
            }
        };
        let host = host_of(url).ok_or_else(|| format!("`{url}` has no host to connect to"))?;
        out.push((provider, host, url.to_owned()));
    }
    Ok(out)
}

/// The host in a base URL, without a scheme, userinfo, port or path.
///
/// Written here rather than taken from a URL parser because the workspace has
/// none and adding one for four lines would need an ADR (CLAUDE.md, K-25). What
/// this produces is only ever compared against the allow list, and
/// `passthrough::resolve_base_url` parses the URL again for real, so a host this
/// gets wrong ends in a refusal rather than in a connection.
fn host_of(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .filter(|text| !text.is_empty())?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, at)| at);
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split_once(']').map(|(address, _)| address.to_owned());
    }
    let host = authority
        .split_once(':')
        .map_or(authority, |(host, _)| host);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
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

    /// A policy on disk, because the command loads one before it opens anything.
    fn policy_file() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "periskop-proxy-cli-{}-{:?}.toml",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(
            &path,
            "policy_id = \"cli-test\"\npolicy_version = \"1\"\n[default]\nmode = \"mask\"\n",
        )
        .unwrap();
        path
    }

    fn request<'a>(profile: Option<&'a str>, policy: &'a Path) -> ProxyRequest<'a> {
        ProxyRequest {
            vault_profile: profile,
            policy: Some(policy),
            listen: None,
            allow_external_interface: false,
            upstreams: &[],
        }
    }

    fn refusal(outcome: ProxyOutcome) -> String {
        match outcome {
            ProxyOutcome::Refused { reason } => reason,
            ProxyOutcome::Ready(_) => panic!("this was expected to refuse and did not"),
        }
    }

    #[test]
    fn an_empty_standard_input_refuses_rather_than_opening_an_empty_vault() {
        let policy = policy_file();
        let reason = refusal(prepare(
            &request(Some("ci"), &policy),
            &mut std::io::empty(),
        ));
        assert!(reason.contains("passphrase"), "{reason}");
        assert!(reason.contains("503"), "{reason}");
    }

    #[test]
    fn an_unknown_profile_is_refused_even_with_a_good_passphrase() {
        let policy = policy_file();
        let reason = refusal(prepare(
            &request(Some("fast"), &policy),
            &mut "hunter2\n".as_bytes(),
        ));
        assert!(reason.contains("fast"), "{reason}");
        assert!(reason.contains("default"), "{reason}");
    }

    #[test]
    fn the_reduced_profile_opens_the_vault_and_says_what_it_cost() {
        let policy = policy_file();
        let outcome = prepare(&request(Some("ci"), &policy), &mut "hunter2\n".as_bytes());
        let ProxyOutcome::Ready(prepared) = outcome else {
            panic!("the proxy did not assemble");
        };
        assert_eq!(prepared.notes.len(), 1);
        // The note names the two memory parameters rather than the profile it was
        // asked for. That changed when the `file` backend arrived: a vault file
        // carries its own Argon2id parameters, so the note has to describe the
        // strength the vault is *actually* protected at, and a note that named
        // `ci` would be false for a file whose header says something the shipped
        // profiles never say.
        assert!(prepared.notes[0].contains("64 MiB"), "{:?}", prepared.notes);
        assert!(
            prepared.notes[0].contains("256 MiB"),
            "{:?}",
            prepared.notes
        );
        assert!(
            prepared.notes[0].contains("cheaper"),
            "{:?}",
            prepared.notes
        );
        // And the documented default bind address, which is the one thing about
        // this command an operator copies out of the README.
        assert_eq!(prepared.address.socket_addr().to_string(), "127.0.0.1:8787");
    }

    /// A policy that is not there is a refusal, not a default.
    ///
    /// The alternative is a proxy that starts under rules nobody wrote, which is
    /// the failure this whole component argues against.
    #[test]
    fn a_missing_policy_refuses_before_the_passphrase_is_even_read() {
        let outcome = prepare(
            &ProxyRequest {
                vault_profile: Some("ci"),
                policy: Some(Path::new("/nonexistent/periskop/policy.toml")),
                listen: None,
                allow_external_interface: false,
                upstreams: &[],
            },
            &mut "hunter2\n".as_bytes(),
        );
        let reason = refusal(outcome);
        assert!(reason.contains("policy"), "{reason}");
        assert!(reason.contains("no request is served"), "{reason}");
    }

    /// `listen.rs`'s rule, reached through the command that an operator types.
    #[test]
    fn a_reachable_interface_is_refused_unless_the_operator_said_they_meant_it() {
        let policy = policy_file();
        let mut asked = request(Some("ci"), &policy);
        asked.listen = Some("0.0.0.0:8787");
        let reason = refusal(prepare(&asked, &mut "hunter2\n".as_bytes()));
        assert!(reason.contains("reachable from outside"), "{reason}");

        // And with the consent, the same address is accepted, so what was refused
        // was the silence and not the address.
        let mut consented = request(Some("ci"), &policy);
        consented.listen = Some("0.0.0.0:8787");
        consented.allow_external_interface = true;
        let outcome = prepare(&consented, &mut "hunter2\n".as_bytes());
        assert!(matches!(outcome, ProxyOutcome::Ready(_)));
    }

    #[test]
    fn an_upstream_override_names_its_host_and_a_malformed_one_stops_the_command() {
        assert_eq!(
            host_of("http://127.0.0.1:9931/v1"),
            Some("127.0.0.1".to_owned())
        );
        assert_eq!(
            host_of("https://Gateway.Internal.Example"),
            Some("gateway.internal.example".to_owned())
        );
        assert_eq!(host_of("http://[::1]:80/v1"), Some("::1".to_owned()));
        assert_eq!(host_of("http://"), None);

        assert!(upstream_overrides(&["openai=http://127.0.0.1:1/v1".to_owned()]).is_ok());
        let no_equals = upstream_overrides(&["openai".to_owned()]).unwrap_err();
        assert!(no_equals.contains("<provider>=<url>"), "{no_equals}");
        let unknown = upstream_overrides(&["gemini=http://127.0.0.1:1".to_owned()]).unwrap_err();
        assert!(unknown.contains("gemini"), "{unknown}");
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
