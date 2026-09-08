//! Non-blocking HTTP transport.
//!
//! Mirrors [`crate::transport::transport::Transport`] method for method. Both
//! share request signing, status handling and TLS setup via
//! [`crate::transport::common`], so behaviour cannot diverge between them.

use std::time::Duration;

use reqwest::{Client as HttpClient, ClientBuilder, Method};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::Error;
use crate::transport::auth::Auth;
use crate::transport::common::{
    configure_builder, is_accepted, parse_api_error, prepare_request,
};
use crate::transport::transport::TransportConfig;

#[derive(Clone)]
pub struct AsyncTransport {
    base_url: String,
    api_key_id: String,
    auth: Auth,
    http: HttpClient,
}

impl AsyncTransport {
    pub fn new(cfg: TransportConfig, auth: Auth) -> Result<Self, Error> {
        if cfg.base_url.trim().is_empty() {
            return Err(Error::InvalidConfig("BaseURL is required".to_string()));
        }
        if cfg.api_key_id.trim().is_empty() {
            return Err(Error::InvalidConfig("APIKeyID is required".to_string()));
        }

        let builder = configure_builder!(ClientBuilder::new(), cfg.timeout, cfg.tls);

        let http = builder
            .build()
            .map_err(|e| Error::InvalidConfig(format!("failed to build http client: {e}")))?;

        Ok(Self {
            base_url: cfg.base_url.trim_end_matches('/').to_string(),
            api_key_id: cfg.api_key_id,
            auth,
            http,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Default request timeout used when [`TransportConfig::timeout`] is unset.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    pub async fn request_no_auth_raw(&self, method: Method, path: &str) -> Result<Vec<u8>, Error> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .request(method, url)
            .send()
            .await
            .map_err(|e| Error::RequestFailed(e.to_string()))?;

        let status = resp.status().as_u16();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Error::RequestFailed(e.to_string()))?
            .to_vec();

        if !is_accepted(status, None) {
            return Err(Error::from_api_error(parse_api_error(status, &bytes)));
        }

        Ok(bytes)
    }

    pub async fn request_json<TReq: Serialize, TResp: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&TReq>,
        accepted: Option<&[u16]>,
    ) -> Result<TResp, Error> {
        let bytes = self.request_raw(method, path, body, accepted).await?;
        let out = serde_json::from_slice::<TResp>(&bytes)?;
        Ok(out)
    }

    pub async fn request_raw<TReq: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&TReq>,
        accepted: Option<&[u16]>,
    ) -> Result<Vec<u8>, Error> {
        let prepared = prepare_request(&self.base_url, &self.auth, &method, path, body)?;

        let mut req = self.http.request(method, prepared.url);
        if !prepared.body.is_empty() {
            req = req
                .header("Content-Type", "application/json")
                .body(prepared.body);
        }

        req = req
            .header("X-API-Key-ID", &self.api_key_id)
            .header("X-Timestamp", prepared.timestamp_ms.to_string())
            .header("X-Nonce", prepared.nonce)
            .header("X-Signature", prepared.signature);

        let resp = req
            .send()
            .await
            .map_err(|e| Error::RequestFailed(e.to_string()))?;
        let status = resp.status().as_u16();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Error::RequestFailed(e.to_string()))?
            .to_vec();

        if !is_accepted(status, accepted) {
            return Err(Error::from_api_error(parse_api_error(status, &bytes)));
        }

        Ok(bytes)
    }
}
