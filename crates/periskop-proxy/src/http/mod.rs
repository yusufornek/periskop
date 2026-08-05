//! The proxy's HTTP surface: the port it listens on and the connection it opens.
//!
//! Everything before this module was a library. Nothing it did could be reached
//! from another machine, and nothing it held could leave the process. From here
//! there is a listening socket, and behind that socket sit the three things
//! `threat-model.md` calls the highest value target in the system: the vault keys,
//! the session to alias map, and the request bodies before they are masked.
//!
//! The modules are split along the lines the risk falls on rather than along the
//! order a request travels, so that each answer lives in one file:
//!
//! | module | the question it answers |
//! |---|---|
//! | [`listen`] | where the socket is, and why that is loopback by default |
//! | [`route`] | which endpoint this is, from the path alone |
//! | [`headers`] | what crosses each way, and what does not |
//! | [`session`] | which conversation this request belongs to |
//! | [`request_path`] | what happens to the body before it is sent |
//! | [`passthrough`] | where a forwarded request is allowed to go |
//! | [`admin`] | what the read only endpoints may say |
//! | [`errors`] | the closed error vocabulary and the fail closed matrix |
//! | [`declare`] | the three legged declaration for what is not masked |
//! | [`observe`] | what one request may leave behind |
//! | [`event`] | the measurement record, and what it may never carry |
//! | [`stream`] | the response side: frames, the hold buffer and alias restoration |
//! | [`gateway`] | the order all of the above run in |
//! | [`serve`] | the translation between `hyper` and the types above |
//! | [`upstream`] | the connection to the provider, behind a seam |
//!
//! # Which direction streams
//!
//! The **request** side never does, and that is a contract rather than an
//! omission (`proxy-api.md`, "Streaming SSE" point 1): the body is taken in full,
//! masked, and only then sent, because a masking decision cannot be taken on half
//! a document. The **response** side does, and [`stream`] is where it happens.

pub mod admin;
pub mod declare;
pub mod errors;
pub mod event;
pub mod gateway;
pub mod headers;
pub mod json;
pub mod listen;
pub mod observe;
pub mod passthrough;
pub mod request_path;
pub mod route;
pub mod serve;
pub mod session;
pub mod stream;
pub mod upstream;

pub use errors::{ProxyError, Refusal};
pub use event::ProxyEvent;
pub use gateway::{Clock, Gateway, Incoming, Outgoing, VaultAccess};
pub use headers::{HeaderList, Marks};
pub use listen::{Exposure, ListenAddress};
pub use passthrough::AllowList;
pub use route::{Provider, Resolved, Route};
