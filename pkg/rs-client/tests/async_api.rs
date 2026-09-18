//! HTTP-level tests for the async client.
//!
//! These run the client directly on the Tokio runtime — no `spawn_blocking`,
//! which is the whole point of the `async` feature.

#![cfg(feature = "async")]

mod common;

use std::time::Duration;

use remote_signer_client::evm::{
    ListRequestsFilter, ListSignersFilter, STATUS_AUTHORIZING, STATUS_COMPLETED, STATUS_FAILED,
    STATUS_PENDING,
};
use remote_signer_client::{AsyncClient, Error};
use wiremock::matchers::{header_exists, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn sign_runs_on_the_runtime_without_blocking_it() {
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

    let client = AsyncClient::new(common::config(&server.uri())).expect("client");
    let resp = client
        .evm
        .sign
        .execute(&common::sign_request())
        .await
        .expect("sign");

    assert_eq!(resp.status, STATUS_COMPLETED);
    assert_eq!(resp.signature.as_deref(), Some("0xdeadbeef"));
}

#[tokio::test]
async fn concurrent_signs_do_not_serialize() {
    let server = MockServer::start().await;

    // Each response is delayed; if the client blocked a worker per call the
    // whole set would take 4x as long as one.
    Mock::given(method("POST"))
        .and(path("/api/v1/evm/sign"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(150))
                .set_body_json(common::sign_response(STATUS_COMPLETED)),
        )
        .mount(&server)
        .await;

    let client = AsyncClient::new(common::config(&server.uri())).expect("client");

    let req = common::sign_request();

    let started = std::time::Instant::now();
    let (a, b, c, d) = tokio::join!(
        client.evm.sign.execute(&req),
        client.evm.sign.execute(&req),
        client.evm.sign.execute(&req),
        client.evm.sign.execute(&req),
    );
    let elapsed = started.elapsed();

    for r in [a, b, c, d] {
        assert_eq!(r.expect("sign").status, STATUS_COMPLETED);
    }
    assert!(
        elapsed < Duration::from_millis(450),
        "four 150ms calls took {elapsed:?}; they appear to have serialized"
    );
}

#[tokio::test]
async fn pending_request_is_polled_until_it_completes() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/evm/sign"))
        .respond_with(
            ResponseTemplate::new(202).set_body_json(common::sign_response(STATUS_AUTHORIZING)),
        )
        .mount(&server)
        .await;

    // First poll still authorizing, second one completes.
    Mock::given(method("GET"))
        .and(path("/api/v1/evm/requests/req-1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(common::request_status(STATUS_AUTHORIZING)),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/evm/requests/req-1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(common::request_status(STATUS_COMPLETED)),
        )
        .mount(&server)
        .await;

    let client = AsyncClient::new(common::config(&server.uri())).expect("client");
    let resp = client
        .evm
        .sign
        .execute(&common::sign_request())
        .await
        .expect("sign");

    assert_eq!(resp.status, STATUS_COMPLETED);
    assert_eq!(resp.signature.as_deref(), Some("0xdeadbeef"));
}

#[tokio::test]
async fn polling_stops_on_terminal_failure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/evm/sign"))
        .respond_with(
            ResponseTemplate::new(202).set_body_json(common::sign_response(STATUS_PENDING)),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/evm/requests/req-1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(common::request_status(STATUS_FAILED)),
        )
        .mount(&server)
        .await;

    let client = AsyncClient::new(common::config(&server.uri())).expect("client");
    let err = client
        .evm
        .sign
        .execute(&common::sign_request())
        .await
        .expect_err("should fail");

    assert!(matches!(err, Error::Sign(e) if e.message == "denied by rule"));
}

#[tokio::test]
async fn execute_no_wait_fails_fast_on_pending() {
    // The path automated callers take: a request that needs human approval is
    // reported immediately rather than waited out.
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/evm/sign"))
        .respond_with(
            ResponseTemplate::new(202).set_body_json(common::sign_response(STATUS_PENDING)),
        )
        .mount(&server)
        .await;

    // No poll endpoint is mounted: reaching it would 404 and fail the test.
    let client = AsyncClient::new(common::config(&server.uri())).expect("client");
    let err = client
        .evm
        .sign
        .execute_no_wait(&common::sign_request())
        .await
        .expect_err("pending must not be treated as success");

    assert!(matches!(err, Error::Sign(e) if e.status == STATUS_PENDING));
}

#[tokio::test]
async fn poll_timeout_is_enforced() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/evm/sign"))
        .respond_with(
            ResponseTemplate::new(202).set_body_json(common::sign_response(STATUS_PENDING)),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/evm/requests/req-1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(common::request_status(STATUS_PENDING)),
        )
        .mount(&server)
        .await;

    let mut cfg = common::config(&server.uri());
    cfg.poll_interval = Some(Duration::from_millis(5));
    cfg.poll_timeout = Some(Duration::from_millis(40));

    let client = AsyncClient::new(cfg).expect("client");
    let err = client
        .evm
        .sign
        .execute(&common::sign_request())
        .await
        .expect_err("should time out");

    assert!(matches!(err, Error::Timeout));
}

#[tokio::test]
async fn list_requests_sends_filter_as_query_params() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/evm/requests"))
        .and(query_param("status", "pending"))
        .and(query_param("signer_address", "0xabc"))
        .and(query_param("limit", "5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "requests": [],
            "total": 0,
            "has_more": false,
        })))
        .mount(&server)
        .await;

    let client = AsyncClient::new(common::config(&server.uri())).expect("client");
    let resp = client
        .evm
        .requests
        .list(Some(&ListRequestsFilter {
            status: Some("pending".to_string()),
            signer_address: Some("0xabc".to_string()),
            limit: Some(5),
            ..Default::default()
        }))
        .await
        .expect("list");

    assert_eq!(resp.total, 0);
}

#[tokio::test]
async fn list_signers_maps_type_filter_and_parses_rows() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/evm/signers"))
        .and(query_param("type", "keystore"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signers": [{
                "address": "0x1111111111111111111111111111111111111111",
                "type": "keystore",
                "enabled": true,
                "locked": false,
            }],
            "total": 1,
            "has_more": false,
        })))
        .mount(&server)
        .await;

    let client = AsyncClient::new(common::config(&server.uri())).expect("client");
    let resp = client
        .evm
        .signers
        .list(Some(&ListSignersFilter {
            signer_type: Some("keystore".to_string()),
            ..Default::default()
        }))
        .await
        .expect("list");

    assert_eq!(resp.total, 1);
    assert_eq!(resp.signers[0].signer_type, "keystore");
    assert!(!resp.signers[0].locked);
}

#[tokio::test]
async fn health_is_unauthenticated() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "ok",
            "version": "1.2.3",
        })))
        .mount(&server)
        .await;

    let client = AsyncClient::new(common::config(&server.uri())).expect("client");
    let health = client.health().await.expect("health");

    assert_eq!(health.status, "ok");
    assert_eq!(health.version, "1.2.3");
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

        let client = AsyncClient::new(common::config(&server.uri())).expect("client");
        let err = client
            .evm
            .sign
            .execute(&common::sign_request())
            .await
            .expect_err("should fail");

        let matched = matches!(
            (code, &err),
            (401, Error::Unauthorized) | (404, Error::NotFound) | (429, Error::RateLimited)
        );
        assert!(matched, "status {code} produced unexpected error: {err:?}");
    }
}

#[tokio::test]
async fn async_remote_signer_signs_a_transaction() {
    use remote_signer_client::evm::Transaction;
    use remote_signer_client::signer::{AddressGetter, AsyncRemoteSigner, AsyncTransactionSigner};

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/evm/sign"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "request_id": "req-1",
            "status": STATUS_COMPLETED,
            "signed_data": "0x0a0b0c",
        })))
        .mount(&server)
        .await;

    let client = AsyncClient::new(common::config(&server.uri())).expect("client");
    let signer = AsyncRemoteSigner::new(
        client.evm.sign.clone(),
        "0x1111111111111111111111111111111111111111",
        "56",
    );

    assert_eq!(signer.address(), "0x1111111111111111111111111111111111111111");

    let tx = Transaction::eip1559("0", 21000, "1", "2")
        .to("0x2222222222222222222222222222222222222222")
        .nonce(41);

    let raw = signer.sign_transaction(&tx).await.expect("sign");
    assert_eq!(raw, vec![0x0a, 0x0b, 0x0c]);
}

#[tokio::test]
async fn async_remote_signer_does_not_wait_for_approval() {
    use remote_signer_client::evm::Transaction;
    use remote_signer_client::signer::{AsyncRemoteSigner, AsyncTransactionSigner};

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/evm/sign"))
        .respond_with(
            ResponseTemplate::new(202).set_body_json(common::sign_response(STATUS_PENDING)),
        )
        .mount(&server)
        .await;

    // No poll endpoint mounted — reaching it would 404 and fail the test.
    let client = AsyncClient::new(common::config(&server.uri())).expect("client");
    let signer = AsyncRemoteSigner::new(client.evm.sign.clone(), "0xabc", "56");

    let err = signer
        .sign_transaction(&Transaction::legacy("0", 21000, "1").nonce(1))
        .await
        .expect_err("must not wait for a human");

    assert!(matches!(err, Error::Sign(e) if e.status == STATUS_PENDING));
}

#[tokio::test]
async fn async_signer_is_usable_behind_a_trait_object() {
    use remote_signer_client::evm::Transaction;
    use remote_signer_client::signer::{AsyncRemoteSigner, AsyncTransactionSigner};

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/evm/sign"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "request_id": "req-1",
            "status": STATUS_COMPLETED,
            "signed_data": "AQID",
        })))
        .mount(&server)
        .await;

    let client = AsyncClient::new(common::config(&server.uri())).expect("client");
    let signer: Box<dyn AsyncTransactionSigner> =
        Box::new(AsyncRemoteSigner::new(client.evm.sign.clone(), "0xabc", "56"));

    // base64 signed_data decodes the same as hex would.
    let raw = signer
        .sign_transaction(&Transaction::legacy("0", 21000, "1").nonce(1))
        .await
        .expect("sign");
    assert_eq!(raw, vec![1, 2, 3]);
}
