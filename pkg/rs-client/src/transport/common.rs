//! Logic shared by the blocking and async transports.
//!
//! Anything that both transports must agree on lives here: request signing,
//! status-code acceptance and API error parsing. Keeping it in one place is
//! what prevents the two transports from drifting apart.

use reqwest::Method;
use serde::Serialize;

use crate::error::{ApiError, Error};
use crate::transport::auth::Auth;

/// Everything needed to issue a signed request, computed independently of the
/// HTTP client flavour.
pub(crate) struct PreparedRequest {
    pub url: String,
    pub body: Vec<u8>,
    pub timestamp_ms: i64,
    pub nonce: String,
    pub signature: String,
}

/// Serialize the body and compute the Ed25519 request signature.
///
/// The signed message is `{timestamp_ms}|{nonce}|{method}|{path}|{sha256(body)}`
/// and must match the server middleware exactly.
pub(crate) fn prepare_request<TReq: Serialize>(
    base_url: &str,
    auth: &Auth,
    method: &Method,
    path: &str,
    body: Option<&TReq>,
) -> Result<PreparedRequest, Error> {
    let body_bytes = match body {
        Some(b) => serde_json::to_vec(b)?,
        None => Vec::new(),
    };

    let timestamp_ms = now_millis();
    let nonce = Auth::generate_nonce_hex();
    let signature = auth.sign_request(timestamp_ms, &nonce, method.as_str(), path, &body_bytes);

    Ok(PreparedRequest {
        url: format!("{base_url}{path}"),
        body: body_bytes,
        timestamp_ms,
        nonce,
        signature,
    })
}

fn now_millis() -> i64 {
    let now = time::OffsetDateTime::now_utc();
    (now.unix_timestamp_nanos() / 1_000_000)
        .try_into()
        .unwrap_or_else(|_| now.unix_timestamp() * 1000)
}

/// Whether a response status counts as success.
///
/// When `accepted` is supplied the status must be listed explicitly; otherwise
/// any 2xx is accepted.
pub(crate) fn is_accepted(status: u16, accepted: Option<&[u16]>) -> bool {
    match accepted {
        Some(accepted) => accepted.contains(&status),
        None => (200..300).contains(&status),
    }
}

/// Best-effort extraction of the server's structured error body.
pub(crate) fn parse_api_error(status_code: u16, body: &[u8]) -> ApiError {
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
        (
            "unknown".to_string(),
            String::from_utf8_lossy(body).to_string(),
        )
    };

    ApiError {
        status_code,
        code,
        message,
    }
}

/// Apply timeout and TLS settings to a `reqwest` client builder.
///
/// `reqwest::blocking::ClientBuilder` and `reqwest::ClientBuilder` share method
/// names but no trait, so this is a macro rather than a function. Both
/// transports must configure TLS identically — that is the point of sharing it.
macro_rules! configure_builder {
    ($builder:expr, $timeout:expr, $tls:expr) => {{
        let mut builder = $builder.timeout(
            $timeout.unwrap_or_else(|| std::time::Duration::from_secs(30)),
        );

        if let Some(tls) = &$tls {
            tls.validate_paths()?;

            if tls.skip_verify {
                builder = builder.danger_accept_invalid_certs(true);
            }

            if let Some(ca_file) = &tls.ca_file {
                let ca_pem = std::fs::read(ca_file).map_err(|e| {
                    $crate::error::Error::InvalidConfig(format!("failed to read TLS CA file: {e}"))
                })?;
                let cert = reqwest::Certificate::from_pem(&ca_pem).map_err(|e| {
                    $crate::error::Error::InvalidConfig(format!("failed to parse TLS CA PEM: {e}"))
                })?;
                builder = builder.add_root_certificate(cert);
            }

            if let (Some(cert_file), Some(key_file)) = (&tls.cert_file, &tls.key_file) {
                let cert_pem = std::fs::read(cert_file).map_err(|e| {
                    $crate::error::Error::InvalidConfig(format!(
                        "failed to read TLS client cert file: {e}"
                    ))
                })?;
                let key_pem = std::fs::read(key_file).map_err(|e| {
                    $crate::error::Error::InvalidConfig(format!(
                        "failed to read TLS client key file: {e}"
                    ))
                })?;

                let mut combined = Vec::with_capacity(cert_pem.len() + key_pem.len() + 1);
                combined.extend_from_slice(&cert_pem);
                combined.push(b'\n');
                combined.extend_from_slice(&key_pem);

                let id = reqwest::Identity::from_pem(&combined).map_err(|e| {
                    $crate::error::Error::InvalidConfig(format!(
                        "failed to parse TLS identity PEM (cert+key): {e}"
                    ))
                })?;
                builder = builder.identity(id);
            }
        }

        builder
    }};
}

pub(crate) use configure_builder;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_accepted_defaults_to_2xx() {
        assert!(is_accepted(200, None));
        assert!(is_accepted(204, None));
        assert!(!is_accepted(300, None));
        assert!(!is_accepted(404, None));
    }

    #[test]
    fn is_accepted_honours_explicit_list() {
        assert!(is_accepted(202, Some(&[200, 201, 202])));
        assert!(!is_accepted(204, Some(&[200, 201, 202])));
        // An explicit list overrides the 2xx default in both directions.
        assert!(is_accepted(404, Some(&[404])));
        assert!(!is_accepted(200, Some(&[201])));
    }

    #[test]
    fn parse_api_error_reads_structured_body() {
        let err = parse_api_error(400, br#"{"error":"invalid_payload","message":"bad chain id"}"#);
        assert_eq!(err.status_code, 400);
        assert_eq!(err.code, "invalid_payload");
        assert_eq!(err.message, "bad chain id");
    }

    #[test]
    fn parse_api_error_falls_back_to_raw_body() {
        let err = parse_api_error(502, b"upstream exploded");
        assert_eq!(err.code, "unknown");
        assert_eq!(err.message, "upstream exploded");
    }

    #[test]
    fn parse_api_error_uses_raw_body_when_message_missing() {
        let err = parse_api_error(400, br#"{"error":"blocked"}"#);
        assert_eq!(err.code, "blocked");
        assert_eq!(err.message, r#"{"error":"blocked"}"#);
    }

    #[test]
    fn prepare_request_signs_body_and_sets_url() {
        let (key, _) = Auth::generate_keypair();
        let auth = Auth::new(key);

        let prepared = prepare_request(
            "http://localhost:8548",
            &auth,
            &Method::POST,
            "/api/v1/evm/sign",
            Some(&serde_json::json!({"a": 1})),
        )
        .expect("prepare");

        assert_eq!(prepared.url, "http://localhost:8548/api/v1/evm/sign");
        assert_eq!(prepared.body, br#"{"a":1}"#);
        assert!(!prepared.signature.is_empty());
        assert_eq!(prepared.nonce.len(), 32);
        assert!(prepared.timestamp_ms > 0);
    }

    #[test]
    fn prepare_request_without_body_signs_empty_payload() {
        let (key, _) = Auth::generate_keypair();
        let auth = Auth::new(key);

        let prepared = prepare_request(
            "http://localhost:8548",
            &auth,
            &Method::GET,
            "/api/v1/evm/requests",
            Option::<&()>::None,
        )
        .expect("prepare");

        assert!(prepared.body.is_empty());
        // Signature over an empty body must still be produced.
        assert!(!prepared.signature.is_empty());
    }
}
