//! The connection to the provider.
//!
//! Behind a trait, and the trait is not ceremony. Everything this wave has to
//! prove about the upstream side is a property of **what was sent**: that the
//! caller's credential crossed unchanged, that the alias scope did not, that a
//! host off the allow list is never dialled. A test that has to reach
//! `api.openai.com` to check any of those proves nothing about the code and stops
//! working on an aeroplane, so the recorder below is what the assertions run
//! against and [`RustlsUpstream`] is what a running proxy uses.
//!
//! The real client is `hyper-util`'s pooling client over `hyper-rustls`, which is
//! ADR-016 section 3's decision: the server half of this crate is already `hyper`,
//! so the client half is the same stack's other half rather than a second HTTP
//! implementation with its own parser and its own disagreements.

use std::future::Future;
use std::pin::Pin;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use super::headers::HeaderList;

/// One request, already masked and already redacted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub method: String,
    pub url: String,
    pub headers: HeaderList,
    pub body: Vec<u8>,
}

/// What came back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub headers: HeaderList,
    pub body: Vec<u8>,
}

/// Why a call did not complete.
///
/// One variant, because from this side every failure is the same fact: the
/// provider was not reached. `proxy-api.md` is explicit that an upstream that
/// answers with a 4xx or a 5xx is **not** an error here; that answer is forwarded
/// transparently and arrives as an [`Answer`] with that status on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unreachable {
    pub why: String,
}

type Pending<'a> = Pin<Box<dyn Future<Output = Result<Answer, Unreachable>> + Send + 'a>>;

/// Somewhere to send a masked request.
pub trait Upstream: Send + Sync {
    fn send<'a>(&'a self, call: Call) -> Pending<'a>;
}

/// The real client.
pub struct RustlsUpstream {
    client: Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
}

impl RustlsUpstream {
    /// Builds the client over the operating system's trust store.
    ///
    /// `rustls-native-certs` rather than an embedded root list, which ADR-016
    /// section 3 settled: an embedded list ties the trust decision to periskop's
    /// release calendar, so a root the organisation revoked stays trusted here
    /// until periskop ships again.
    ///
    /// Redirects are not followed, and the client does not have the option:
    /// `hyper-util`'s client returns the 3xx to the caller. That is the SSRF
    /// property the allow list would otherwise lose, because a permitted host is
    /// free to answer with a `Location` pointing anywhere.
    pub fn new() -> Result<Self, Unreachable> {
        let tls = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|why| Unreachable {
                why: format!("the operating system trust store could not be read: {why}"),
            })?
            .https_or_http()
            .enable_http1()
            .build();

        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build(tls),
        })
    }
}

impl Upstream for RustlsUpstream {
    fn send<'a>(&'a self, call: Call) -> Pending<'a> {
        Box::pin(async move {
            let mut builder = hyper::Request::builder()
                .method(call.method.as_str())
                .uri(call.url.as_str());

            for (name, value) in call.headers.iter() {
                builder = builder.header(name, value);
            }

            let request = builder
                .body(Full::new(Bytes::from(call.body)))
                .map_err(|why| Unreachable {
                    why: format!("the upstream request could not be built: {why}"),
                })?;

            let response = self
                .client
                .request(request)
                .await
                .map_err(|why| Unreachable {
                    why: format!("the provider was not reached: {why}"),
                })?;

            let status = response.status().as_u16();
            let mut headers = HeaderList::new();
            for (name, value) in response.headers() {
                headers.push(
                    name.as_str(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                );
            }

            let body = response
                .into_body()
                .collect()
                .await
                .map_err(|why| Unreachable {
                    why: format!("the provider's answer could not be read: {why}"),
                })?
                .to_bytes()
                .to_vec();

            Ok(Answer {
                status,
                headers,
                body,
            })
        })
    }
}

/// An upstream that records what it was asked to send and answers from a script.
///
/// The seam every assertion about the upstream side runs through. Not
/// `#[cfg(test)]`: the integration tests in `tests/` are separate crates and
/// cannot see a test-only item, and the whole point of this type is that the
/// gate which proves no credential leaks can drive a real request path.
pub struct Recorder {
    sent: std::sync::Mutex<Vec<Call>>,
    answer: Answer,
}

impl Recorder {
    pub fn answering(answer: Answer) -> Self {
        Self {
            sent: std::sync::Mutex::new(Vec::new()),
            answer,
        }
    }

    /// An upstream that answers `200` with an empty JSON object.
    pub fn ok() -> Self {
        Self::answering(Answer {
            status: 200,
            headers: HeaderList::new().with("content-type", "application/json"),
            body: b"{}".to_vec(),
        })
    }

    /// Everything that was sent, in order.
    ///
    /// A poisoned lock is recovered from rather than propagated: this is a test
    /// double, and a panic in one case must not turn every later assertion into a
    /// lock error that hides which case actually failed.
    pub fn calls(&self) -> Vec<Call> {
        match self.sent.lock() {
            Ok(calls) => calls.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl Upstream for Recorder {
    fn send<'a>(&'a self, call: Call) -> Pending<'a> {
        match self.sent.lock() {
            Ok(mut sent) => sent.push(call),
            Err(poisoned) => poisoned.into_inner().push(call),
        }
        let answer = self.answer.clone();
        Box::pin(async move { Ok(answer) })
    }
}

/// An upstream that is not there.
pub struct Absent;

impl Upstream for Absent {
    fn send<'a>(&'a self, _call: Call) -> Pending<'a> {
        Box::pin(async move {
            Err(Unreachable {
                why: "no upstream is configured".to_owned(),
            })
        })
    }
}
