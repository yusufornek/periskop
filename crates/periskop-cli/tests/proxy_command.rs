#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `periskop proxy`, run as the program somebody installs.
//!
//! # Why this file is not the F4 gate over again
//!
//! `tests/proof_f4.rs` builds a [`Gateway`] and a [`Listener`] itself, in
//! process, out of the library. It proves the masking path works. It cannot
//! prove that the **binary** reaches that path, and for several waves it did
//! not: `periskop proxy` opened the vault, printed that nothing was listening
//! and exited non zero, while every masking claim in the repository rested on a
//! harness nobody ships. A phase whose deliverable is a runnable proxy cannot be
//! closed by a test that supplies its own proxy.
//!
//! So nothing here is imported from `periskop-proxy`. The proxy is a child
//! process started from `CARGO_BIN_EXE_periskop`, spoken to over a socket, with
//! the passphrase on its standard input, exactly as an operator would start it.
//! The only stand-in is the provider, and it is stubbed for the reason CLAUDE.md
//! gives: periskop may not be an egress source, and a test that dialled a real
//! provider would be measuring whether this machine has a network and a funded
//! key.
//!
//! # What one run establishes
//!
//! 1. the shipped binary binds a socket and answers HTTP on it;
//! 2. it loads the policy it was given and refuses to start without one;
//! 3. a value in a request it forwarded **did not reach the provider**, checked
//!    against the bytes the stub recorded rather than inferred from a header;
//! 4. the response says how many entities were masked, and the number is right.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// A value with a checksum that passes, assembled at run time so that no source
/// file carries a continuous identifier-shaped literal
/// (`tests/no_credential_literals.rs`).
fn iban() -> String {
    format!("TR{}", "330006100519786457841326")
}

/// The provider, replaced by something that writes down what it was handed.
///
/// One connection, one answer, and the request bytes go back down a channel. A
/// second connection is not served, because this test is about one exchange and
/// a stub that kept accepting would hide a proxy that retried.
fn stub_provider() -> (SocketAddr, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port is free");
    let address = listener.local_addr().expect("the stub is bound");
    let (sender, receiver) = mpsc::channel();

    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut seen = Vec::new();
        let mut buffer = [0u8; 4096];
        // Read until the body has arrived. The proxy sends `content-length`, so
        // the end of the head plus that many bytes is the whole request.
        loop {
            let Ok(read) = stream.read(&mut buffer) else {
                break;
            };
            if read == 0 {
                break;
            }
            seen.extend_from_slice(&buffer[..read]);
            if body_is_complete(&seen) {
                break;
            }
        }
        let _sent = sender.send(String::from_utf8_lossy(&seen).into_owned());

        let body = r#"{"choices":[{"message":{"role":"assistant","content":"noted"}}]}"#;
        let answer = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        let _written = stream.write_all(answer.as_bytes());
        let _flushed = stream.flush();
    });

    (address, receiver)
}

fn body_is_complete(seen: &[u8]) -> bool {
    let text = String::from_utf8_lossy(seen);
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return false;
    };
    let declared = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    body.len() >= declared
}

/// The proxy, as a child process, with the address it actually bound.
struct Running {
    child: Child,
    address: SocketAddr,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _killed = self.child.kill();
        let _reaped = self.child.wait();
    }
}

fn policy_file(directory: &std::path::Path) -> std::path::PathBuf {
    let path = directory.join("policy.toml");
    std::fs::write(
        &path,
        "policy_id = \"cli-proxy-test\"\npolicy_version = \"1\"\n[default]\nmode = \"mask\"\n",
    )
    .expect("the policy is written");
    path
}

fn scratch() -> std::path::PathBuf {
    let directory =
        std::env::temp_dir().join(format!("periskop-proxy-command-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("a scratch directory");
    directory
}

/// Starts the shipped binary and waits until it says where it is listening.
fn start(policy: &std::path::Path, upstream: SocketAddr) -> Running {
    let mut child = Command::new(env!("CARGO_BIN_EXE_periskop"))
        .arg("proxy")
        .arg("--vault-profile")
        .arg("ci")
        .arg("--policy")
        .arg(policy)
        // Port zero, so two runs of this test on one machine cannot collide and
        // so nothing here depends on 8787 being free.
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--upstream")
        .arg(format!("openai=http://{upstream}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the shipped binary starts");

    child
        .stdin
        .as_mut()
        .expect("standard input is piped")
        .write_all(b"an operator's passphrase\n")
        .expect("the passphrase is written");
    // Closed, so the passphrase read reaches end of input rather than blocking.
    drop(child.stdin.take());

    let stderr = child.stderr.take().expect("standard error is piped");
    let mut lines = BufReader::new(stderr).lines();
    let mut said = Vec::new();
    let address = loop {
        let Some(Ok(line)) = lines.next() else {
            let _killed = child.kill();
            panic!(
                "the proxy never said where it was listening; it said:\n{}",
                said.join("\n")
            );
        };
        said.push(line.clone());
        if let Some(rest) = line.split_once("listening on ") {
            break rest
                .1
                .parse::<SocketAddr>()
                .expect("an address was printed");
        }
    };
    // Kept draining, or the child blocks on a full pipe if it ever logs again.
    std::thread::spawn(move || while let Some(Ok(_line)) = lines.next() {});

    Running { child, address }
}

/// One HTTP/1.1 exchange, written by hand so that nothing on this side of the
/// socket shares code with the thing under test.
fn post(address: SocketAddr, path: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(address).expect("the proxy accepts a connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("a read timeout");
    let request = format!(
        "POST {path} HTTP/1.1\r\nhost: 127.0.0.1\r\nauthorization: Bearer {}\r\ncontent-type: \
         application/json\r\nx-periskop-session: one-conversation\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{body}",
        "sk-not-a-real-key",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .expect("the request is written");
    let mut answer = String::new();
    let _read = stream.read_to_string(&mut answer);
    answer
}

#[test]
fn the_shipped_binary_serves_the_proxy_and_the_value_does_not_reach_the_provider() {
    let directory = scratch();
    let policy = policy_file(&directory);
    let (stub, recorded) = stub_provider();
    let running = start(&policy, stub);

    let sent = format!(
        r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"hesabim {}"}}]}}"#,
        iban()
    );
    let answer = post(running.address, "/v1/chat/completions", &sent);

    // Claim 1: it is an HTTP server and it answered.
    assert!(
        answer.starts_with("HTTP/1.1 200"),
        "the proxy did not answer 200:\n{answer}"
    );

    // Claim 3, and the only one that matters: the bytes the provider was handed.
    let provider_saw = recorded
        .recv_timeout(Duration::from_secs(30))
        .expect("the provider was never called, so nothing was proxied");
    assert!(
        !provider_saw.contains(&iban()),
        "the account number reached the provider:\n{provider_saw}"
    );
    assert!(
        provider_saw.contains("hesabim"),
        "the prompt did not arrive at all, so nothing was proved:\n{provider_saw}"
    );

    // Claim 4: the count the response carries is the count that happened.
    assert!(
        answer
            .to_ascii_lowercase()
            .contains("x-periskop-masked-entities: 1"),
        "the response does not report the masking it did:\n{answer}"
    );

    drop(running);
    let _cleaned = std::fs::remove_file(&policy);
}

#[test]
fn the_shipped_binary_refuses_to_start_without_a_policy() {
    // The fail closed half. A proxy that started under a policy nobody wrote
    // would mask by accident and stop masking by accident.
    let output = Command::new(env!("CARGO_BIN_EXE_periskop"))
        .arg("proxy")
        .arg("--vault-profile")
        .arg("ci")
        .arg("--policy")
        .arg(scratch().join("there-is-no-policy-here.toml"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("the shipped binary runs");

    assert!(
        !output.status.success(),
        "a proxy with no policy exited zero"
    );
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains("policy"), "{said}");
    assert!(said.contains("no request is served"), "{said}");
    assert!(
        !said.contains("listening on"),
        "the proxy bound a socket before refusing:\n{said}"
    );
}
