//! HTTP-level tests for the blocking client.
//!
//! The blocking client cannot run inside a Tokio worker, so every call is
//! moved onto `spawn_blocking` while the mock server runs on the runtime.

mod common;

use remote_signer_client::evm::{ListRequestsFilter, STATUS_COMPLETED, STATUS_PENDING};
use remote_signer_client::{Client, Error};
use wiremock::matchers::{header_exists, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn sign_returns_signature_when_rule_auto_approves() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/evm/sign"))
        .and(header_exists("X-API-Key-ID"))
        .and(header_exists("X-Timestamp"))
        .and(header_exists("X-Nonce"))
        .and(header_exists("X-Signature"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(common::sign_response(STATUS_COMPLETED)),
        )
        .mount(&server)
        .await;

    let cfg = common::config(&server.uri());
    let resp = tokio::task::spawn_blocking(move || {
        let client = Client::new(cfg)?;
        client.evm.sign.execute(&common::sign_request())
    })
    .await
    .expect("join")
    .expect("sign");

    assert_eq!(resp.status, STATUS_COMPLETED);
    assert_eq!(resp.signature.as_deref(), Some("0xdeadbeef"));
}

#[tokio::test]
async fn execute_async_surfaces_pending_instead_of_blocking() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/evm/sign"))
        .respond_with(
            ResponseTemplate::new(202).set_body_json(common::sign_response(STATUS_PENDING)),
        )
        .mount(&server)
        .await;

    let cfg = common::config(&server.uri());
    let err = tokio::task::spawn_blocking(move || {
        let client = Client::new(cfg)?;
        client.evm.sign.execute_async(&common::sign_request())
    })
    .await
    .expect("join")
    .expect_err("pending must not be treated as success");

    assert!(matches!(err, Error::Sign(e) if e.status == STATUS_PENDING));
}

#[tokio::test]
async fn list_requests_sends_filter_as_query_params() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/evm/requests"))
        .and(query_param("status", "pending"))
        .and(query_param("limit", "5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "requests": [],
            "total": 0,
            "has_more": false,
        })))
        .mount(&server)
        .await;

    let cfg = common::config(&server.uri());
    let resp = tokio::task::spawn_blocking(move || {
        let client = Client::new(cfg)?;
        client.evm.requests.list(Some(&ListRequestsFilter {
            status: Some("pending".to_string()),
            limit: Some(5),
            ..Default::default()
        }))
    })
    .await
    .expect("join")
    .expect("list");

    assert_eq!(resp.total, 0);
}

#[tokio::test]
async fn http_error_codes_map_to_typed_errors() {
    for code in [401u16, 404u16, 429u16] {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/v1/evm/sign"))
            .respond_with(ResponseTemplate::new(code).set_body_json(serde_json::json!({
                "error": "boom",
                "message": "nope",
            })))
            .mount(&server)
            .await;

        let cfg = common::config(&server.uri());
        let err = tokio::task::spawn_blocking(move || {
            let client = Client::new(cfg)?;
            client.evm.sign.execute(&common::sign_request())
        })
        .await
        .expect("join")
        .expect_err("should fail");

        let matched = matches!(
            (code, &err),
            (401, Error::Unauthorized) | (404, Error::NotFound) | (429, Error::RateLimited)
        );
        assert!(matched, "status {code} produced unexpected error: {err:?}");
    }
}
