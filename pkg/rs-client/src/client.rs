use std::time::Duration;

use ed25519_dalek::SigningKey;
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::acls;
use crate::apikeys;
use crate::audit;
use crate::error::Error;
use crate::evm;
use crate::presets;
use crate::templates;
use crate::transport::auth::{Auth, self};
use crate::transport::tls::TlsConfig;
use crate::transport::transport::{Transport, TransportConfig};

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub base_url: String,
    pub api_key_id: String,

    /// Ed25519 private key (hex, 32-byte seed or 64-byte private key).
    pub private_key_hex: Option<String>,

    /// Path to PEM file (PKCS#8) containing Ed25519 private key. Used when private_key_hex/base64 are unset.
    pub private_key_file: Option<String>,

    /// Ed25519 private key in base64 DER (seed extracted from tail 32 bytes, matching Go SDK behaviour).
    pub private_key_base64: Option<String>,

    pub timeout: Option<Duration>,

    pub poll_interval: Option<Duration>,
    pub poll_timeout: Option<Duration>,

    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfigInfo {
    pub auto_lock_timeout: String,
    pub sign_timeout: String,
    pub audit_retention_days: i32,
    pub content_type_validation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    #[serde(default)]
    pub security: Option<SecurityConfigInfo>,
}

#[derive(Clone)]
pub struct Client {
    pub evm: evm::Service,
    pub audit: audit::Service,
    pub templates: templates::Service,
    pub apikeys: apikeys::Service,
    pub presets: presets::Service,
    pub acls: acls::Service,

    transport: Transport,
}

/// Resolve the Ed25519 signing key from whichever config field is set.
///
/// Shared by [`Client`] and the async client so both accept exactly the same
/// key sources in the same precedence order.
pub(crate) fn signing_key_from(cfg: &Config) -> Result<SigningKey, Error> {
    if let Some(hex) = cfg.private_key_hex.as_deref() {
        auth::Auth::parse_private_key_hex(hex)
    } else if let Some(b64) = cfg.private_key_base64.as_deref() {
        auth::Auth::parse_private_key_base64_der(b64)
    } else if let Some(path) = cfg.private_key_file.as_deref() {
        auth::Auth::load_private_key_from_pem_file(path)
    } else {
        Err(Error::InvalidConfig(
            "either private_key_hex, private_key_base64, or private_key_file is required"
                .to_string(),
        ))
    }
}

pub(crate) const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);
pub(crate) const DEFAULT_POLL_TIMEOUT: Duration = Duration::from_secs(300);

pub(crate) fn transport_config(cfg: Config) -> TransportConfig {
    TransportConfig {
        base_url: cfg.base_url,
        api_key_id: cfg.api_key_id,
        timeout: cfg.timeout,
        tls: cfg.tls,
    }
}

impl Client {
    pub fn new(cfg: Config) -> Result<Self, Error> {
        let auth = Auth::new(signing_key_from(&cfg)?);

        let poll_interval = cfg.poll_interval.unwrap_or(DEFAULT_POLL_INTERVAL);
        let poll_timeout = cfg.poll_timeout.unwrap_or(DEFAULT_POLL_TIMEOUT);

        let transport = Transport::new(transport_config(cfg), auth)?;

        let evm = evm::Service::new(transport.clone(), poll_interval, poll_timeout);

        Ok(Self {
            audit: audit::Service::new(transport.clone()),
            templates: templates::Service::new(transport.clone()),
            apikeys: apikeys::Service::new(transport.clone()),
            presets: presets::Service::new(transport.clone()),
            acls: acls::Service::new(transport.clone()),
            evm,
            transport,
        })
    }

    pub fn health(&self) -> Result<HealthResponse, Error> {
        let bytes = self
            .transport
            .request_no_auth_raw(Method::GET, "/health")?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn metrics(&self) -> Result<String, Error> {
        let bytes = self
            .transport
            .request_no_auth_raw(Method::GET, "/metrics")?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}

#[cfg(feature = "async")]
mod asynchronous {
    use super::*;
    use crate::transport::async_transport::AsyncTransport;

    /// Non-blocking counterpart of [`Client`].
    ///
    /// Accepts the same [`Config`] and exposes the same EVM surface, so moving
    /// from the blocking client is a matter of adding `.await`.
    #[derive(Clone)]
    pub struct AsyncClient {
        pub evm: evm::AsyncService,

        transport: AsyncTransport,
    }

    impl AsyncClient {
        pub fn new(cfg: Config) -> Result<Self, Error> {
            let auth = Auth::new(signing_key_from(&cfg)?);

            let poll_interval = cfg.poll_interval.unwrap_or(DEFAULT_POLL_INTERVAL);
            let poll_timeout = cfg.poll_timeout.unwrap_or(DEFAULT_POLL_TIMEOUT);

            let transport = AsyncTransport::new(transport_config(cfg), auth)?;

            Ok(Self {
                evm: evm::AsyncService::new(transport.clone(), poll_interval, poll_timeout),
                transport,
            })
        }

        pub fn base_url(&self) -> &str {
            self.transport.base_url()
        }

        pub async fn health(&self) -> Result<HealthResponse, Error> {
            let bytes = self
                .transport
                .request_no_auth_raw(Method::GET, "/health")
                .await?;
            Ok(serde_json::from_slice(&bytes)?)
        }

        pub async fn metrics(&self) -> Result<String, Error> {
            let bytes = self
                .transport
                .request_no_auth_raw(Method::GET, "/metrics")
                .await?;
            Ok(String::from_utf8_lossy(&bytes).to_string())
        }
    }
}

#[cfg(feature = "async")]
pub use asynchronous::AsyncClient;

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn config_without_any_key_source_is_rejected() {
        let err = signing_key_from(&Config {
            base_url: "http://localhost:8548".to_string(),
            api_key_id: "key-1".to_string(),
            ..Default::default()
        })
        .expect_err("should reject");
        assert_matches!(err, Error::InvalidConfig(_));
    }

    #[test]
    fn hex_key_source_is_accepted() {
        let (key, _) = auth::Auth::generate_keypair();
        let hex_key = hex::encode(key.to_bytes());

        let parsed = signing_key_from(&Config {
            private_key_hex: Some(hex_key),
            ..Default::default()
        })
        .expect("should parse");

        assert_eq!(parsed.to_bytes(), key.to_bytes());
    }

    #[test]
    fn hex_key_takes_precedence_over_other_sources() {
        let (key, _) = auth::Auth::generate_keypair();

        let parsed = signing_key_from(&Config {
            private_key_hex: Some(hex::encode(key.to_bytes())),
            // Deliberately unusable — must not be reached.
            private_key_file: Some("/nonexistent/key.pem".to_string()),
            ..Default::default()
        })
        .expect("hex wins");

        assert_eq!(parsed.to_bytes(), key.to_bytes());
    }

    #[test]
    fn empty_base_url_is_rejected_by_transport() {
        let res = Client::new(Config {
            base_url: String::new(),
            api_key_id: "key-1".to_string(),
            private_key_hex: Some(hex::encode([7u8; 32])),
            ..Default::default()
        });
        assert_matches!(res.err(), Some(Error::InvalidConfig(_)));
    }

    #[test]
    fn empty_api_key_id_is_rejected_by_transport() {
        let res = Client::new(Config {
            base_url: "http://localhost:8548".to_string(),
            api_key_id: String::new(),
            private_key_hex: Some(hex::encode([7u8; 32])),
            ..Default::default()
        });
        assert_matches!(res.err(), Some(Error::InvalidConfig(_)));
    }
}
