//! The socket, and nothing else.
//!
//! Deliberately thin. Every decision this component makes lives in a module that
//! needs no runtime to test: routing, redaction, session identity, masking and the
//! error matrix are all reachable from a synchronous test, and what is left here is
//! the translation between `hyper`'s types and [`Incoming`] / [`Outgoing`]. A
//! server that mixed the two would make "does a credential leak downstream" a
//! question you can only answer by opening a port.

use std::convert::Infallible;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use super::gateway::{Gateway, Incoming, Outgoing};
use super::listen::ListenAddress;

/// The largest request body this proxy will read.
///
/// The request side does not stream by contract (`proxy-api.md`, "Streaming SSE"
/// point 1: the body is taken in full, masked, and only then sent), which means an
/// unbounded body is an unbounded allocation in a process holding vault keys. Eight
/// megabytes is far above any chat completion and far below anything that
/// threatens the host.
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// A bound listener, so that a caller can learn the port before serving.
pub struct Listener {
    listener: TcpListener,
    address: std::net::SocketAddr,
}

impl Listener {
    /// Binds, and refuses to bind anywhere [`ListenAddress`] did not permit.
    pub async fn bind(address: ListenAddress) -> std::io::Result<Self> {
        let listener = TcpListener::bind(address.socket_addr()).await?;
        let address = listener.local_addr()?;
        Ok(Self { listener, address })
    }

    /// The address actually bound, which is the requested one with port 0
    /// resolved.
    pub fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    /// Accepts connections until the process ends.
    pub async fn serve(self, gateway: Arc<Gateway>) -> std::io::Result<()> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            let gateway = Arc::clone(&gateway);
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let gateway = Arc::clone(&gateway);
                    async move { answer(&gateway, request).await }
                });
                // A connection that fails is that connection's problem. There is
                // no logger in this crate, and the crate level `deny` on
                // `print_stderr` is why this is dropped rather than printed: the
                // one process stream a leak would reach is the one nothing writes
                // to. The request record carries what happened.
                let _served = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    }
}

async fn answer(
    gateway: &Gateway,
    request: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().map(str::to_owned);

    let mut headers = super::headers::HeaderList::new();
    for (name, value) in request.headers() {
        headers.push(
            name.as_str(),
            String::from_utf8_lossy(value.as_bytes()).into_owned(),
        );
    }

    let body = match read_body(request.into_body()).await {
        Ok(body) => body,
        Err(status) => return Ok(refuse(status)),
    };

    let outgoing = gateway
        .handle(Incoming {
            method,
            path,
            query,
            headers,
            body,
        })
        .await;

    Ok(render(outgoing))
}

/// Reads the body, bounded.
async fn read_body(body: hyper::body::Incoming) -> Result<Vec<u8>, u16> {
    let collected = body.collect().await.map_err(|_| 400u16)?.to_bytes();
    if collected.len() > MAX_BODY_BYTES {
        return Err(413);
    }
    Ok(collected.to_vec())
}

fn render(outgoing: Outgoing) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(outgoing.status);
    for (name, value) in outgoing.headers.iter() {
        builder = builder.header(name, value);
    }
    builder
        .body(Full::new(Bytes::from(outgoing.body)))
        // A header the gateway produced that `hyper` will not accept is a bug in
        // this crate, not in the request. Answering 500 with an empty body is the
        // one response that cannot itself leak: it carries nothing.
        .unwrap_or_else(|_| {
            let mut fallback = Response::new(Full::new(Bytes::new()));
            *fallback.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
            fallback
        })
}

fn refuse(status: u16) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() =
        hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::BAD_REQUEST);
    response
}
