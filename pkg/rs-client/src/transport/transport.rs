use std::time::Duration;

use reqwest::blocking::{Client as HttpClient, ClientBuilder};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{ApiError, Error};
use crate::transport::auth::Auth;
use crate::transport::tls::TlsConfig;

#[derive(Clone)]
pub struct Transport {
    base_url: String,
    api_key_id: String,
    auth: Auth,
    http: HttpClient,
}

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub base_url: String,
    pub api_key_id: String,
    pub timeout: Option<Duration>,
    pub tls: Option<TlsConfig>,
}

impl Transport {
    pub fn new(cfg: TransportConfig, auth: Auth) -> Result<Self, Error> {
        if cfg.base_url.trim().is_empty() {
            return Err(Error::InvalidConfig("BaseURL is required".to_string()));
        }
        if cfg.api_key_id.trim().is_empty() {
            return Err(Error::InvalidConfig("APIKeyID is required".to_string()));
        }

        let mut builder = ClientBuilder::new();
        builder = builder.timeout(cfg.timeout.unwrap_or(Duration::from_secs(30)));

        if let Some(tls) = &cfg.tls {
            tls.validate_paths()?;
            if tls.skip_verify {
                builder = builder.danger_accept_invalid_certs(true);
            }
            if let Some(ca_file) = &tls.ca_file {
                let ca_pem = std::fs::read(ca_file)
                    .map_err(|e| Error::InvalidConfig(format!("failed to read TLS CA file: {e}")))?;
                let cert = reqwest::Certificate::from_pem(&ca_pem)
                    .map_err(|e| Error::InvalidConfig(format!("failed to parse TLS CA PEM: {e}")))?;
                builder = builder.add_root_certificate(cert);
            }

            if let (Some(cert_file), Some(key_file)) = (&tls.cert_file, &tls.key_file) {
                let cert_pem = std::fs::read(cert_file).map_err(|e| {
                    Error::InvalidConfig(format!("failed to read TLS client cert file: {e}"))
                })?;
                let key_pem = std::fs::read(key_file).map_err(|e| {
                    Error::InvalidConfig(format!("failed to read TLS client key file: {e}"))
                })?;
                let mut combined = Vec::with_capacity(cert_pem.len() + key_pem.len() + 1);
                combined.extend_from_slice(&cert_pem);
                combined.push(b'\n');
                combined.extend_from_slice(&key_pem);

                let id = reqwest::Identity::from_pem(&combined).map_err(|e| {
                    Error::InvalidConfig(format!("failed to parse TLS identity PEM (cert+key): {e}"))
                })?;
                builder = builder.identity(id);
            }
        }

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

    pub fn request_no_auth_raw(&self, method: Method, path: &str) -> Result<Vec<u8>, Error> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .request(method, url)
            .send()
            .map_err(|e| Error::RequestFailed(e.to_string()))?;

        let status = resp.status();
        let bytes = resp
            .bytes()
            .map_err(|e| Error::RequestFailed(e.to_string()))?
            .to_vec();

        if !status.is_success() {
            return Err(Error::from_api_error(parse_api_error(status.as_u16(), &bytes)));
        }

        Ok(bytes)
    }

    pub fn request_json<TReq: Serialize, TResp: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&TReq>,
        accepted: Option<&[u16]>,
    ) -> Result<TResp, Error> {
        let bytes = self.request_raw(method, path, body, accepted)?;
        let out = serde_json::from_slice::<TResp>(&bytes)?;
        Ok(out)
    }

    pub fn request_raw<TReq: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&TReq>,
        accepted: Option<&[u16]>,
    ) -> Result<Vec<u8>, Error> {
        let url = format!("{}{}", self.base_url, path);

        let body_bytes = if let Some(b) = body {
            serde_json::to_vec(b)?
        } else {
            Vec::new()
        };

        let timestamp_ms: i64 = (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
            .try_into()
            .unwrap_or_else(|_| time::OffsetDateTime::now_utc().unix_timestamp() * 1000);
        let nonce = Auth::generate_nonce_hex();
        let signature = self
            .auth
            .sign_request(timestamp_ms, &nonce, method.as_str(), path, &body_bytes);

        let mut req = self.http.request(method, url);
        if !body_bytes.is_empty() {
            req = req.header("Content-Type", "application/json").body(body_bytes.clone());
        }

        req = req
            .header("X-API-Key-ID", &self.api_key_id)
            .header("X-Timestamp", timestamp_ms.to_string())
            .header("X-Nonce", nonce)
            .header("X-Signature", signature);

        let resp = req.send().map_err(|e| Error::RequestFailed(e.to_string()))?;
        let status = resp.status();
        let bytes = resp
            .bytes()
            .map_err(|e| Error::RequestFailed(e.to_string()))?
            .to_vec();

        let accepted_ok = if let Some(accepted) = accepted {
            accepted.iter().any(|s| *s == status.as_u16())
        } else {
            status.is_success()
        };

        if !accepted_ok {
            return Err(Error::from_api_error(parse_api_error(status.as_u16(), &bytes)));
        }

        Ok(bytes)
    }
}

fn parse_api_error(status_code: u16, body: &[u8]) -> ApiError {
    let parsed = serde_json::from_slice::<serde_json::Value>(body).ok();
    let (code, message) = if let Some(v) = parsed {
        let code = v
            .get("error")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string();
        let message = v
            .get("message")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| String::from_utf8_lossy(body).to_string());
        (code, message)
    } else {
        ("unknown".to_string(), String::from_utf8_lossy(body).to_string())
    };

    ApiError {
        status_code,
        code,
        message,
    }
}
