use std::time::Duration;

use ed25519_dalek::SigningKey;
use reqwest::Method;
use serde::{Deserialize, Serialize};

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

    transport: Transport,
}

impl Client {
    pub fn new(cfg: Config) -> Result<Self, Error> {
        let signing_key: SigningKey = if let Some(hex) = cfg.private_key_hex.as_deref() {
            auth::Auth::parse_private_key_hex(hex)?
        } else if let Some(b64) = cfg.private_key_base64.as_deref() {
            auth::Auth::parse_private_key_base64_der(b64)?
        } else if let Some(path) = cfg.private_key_file.as_deref() {
            auth::Auth::load_private_key_from_pem_file(path)?
        } else {
            return Err(Error::InvalidConfig(
                "either private_key_hex, private_key_base64, or private_key_file is required"
                    .to_string(),
            ));
        };

        let auth = Auth::new(signing_key);

        let transport = Transport::new(
            TransportConfig {
                base_url: cfg.base_url,
                api_key_id: cfg.api_key_id,
                timeout: cfg.timeout,
                tls: cfg.tls,
            },
            auth,
        )?;

        let poll_interval = cfg.poll_interval.unwrap_or(Duration::from_secs(2));
        let poll_timeout = cfg.poll_timeout.unwrap_or(Duration::from_secs(300));

        let evm = evm::Service::new(transport.clone(), poll_interval, poll_timeout);

        Ok(Self {
            audit: audit::Service::new(transport.clone()),
            templates: templates::Service::new(transport.clone()),
            apikeys: apikeys::Service::new(transport.clone()),
            presets: presets::Service::new(transport.clone()),
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
