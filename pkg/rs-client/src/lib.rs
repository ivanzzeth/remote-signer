//! Rust SDK for the `remote-signer` service.
//!
//! Two client flavours share one set of types, one request-signing path and one
//! set of endpoint definitions:
//!
//! - [`Client`] — blocking, always available.
//! - [`AsyncClient`] — non-blocking, behind the `async` feature.
//!
//! ```toml
//! remote-signer-client = { path = "...", features = ["async"] }
//! ```
//!
//! The blocking client uses `reqwest::blocking` and therefore **cannot be
//! called from inside a Tokio runtime** — doing so panics. Async callers should
//! enable the `async` feature rather than wrapping the blocking client.

// `transport::transport`, `audit::audit` and friends predate this crate's
// public API; renaming them would be a breaking change for no functional gain.
#![allow(clippy::module_inception)]

mod client;
mod error;
pub mod transport;

pub mod acls;
pub mod apikeys;
pub mod audit;
pub mod evm;
pub mod presets;
pub mod templates;

pub use client::{Client, Config, HealthResponse, SecurityConfigInfo};

#[cfg(feature = "async")]
pub use client::AsyncClient;
#[cfg(feature = "async")]
pub use transport::async_transport::AsyncTransport;
pub use error::{ApiError, Error, ErrorResponse, SignError};
pub use transport::tls::TlsConfig;
