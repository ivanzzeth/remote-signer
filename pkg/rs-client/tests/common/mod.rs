//! Shared helpers for the HTTP-level SDK tests.
//!
//! Included by several test binaries; not every helper is used by each of them.
#![allow(dead_code)]

use remote_signer_client::Config;

/// A deterministic Ed25519 key. Test-only, never a real credential.
pub const TEST_KEY_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

pub fn config(base_url: &str) -> Config {
    Config {
        base_url: base_url.to_string(),
        api_key_id: "test-key".to_string(),
        private_key_hex: Some(TEST_KEY_HEX.to_string()),
        // Keep polling fast so approval tests do not idle.
        poll_interval: Some(std::time::Duration::from_millis(10)),
        poll_timeout: Some(std::time::Duration::from_secs(5)),
        ..Default::default()
    }
}

pub fn sign_response(status: &str) -> serde_json::Value {
    serde_json::json!({
        "request_id": "req-1",
        "status": status,
        "signature": "0xdeadbeef",
        "message": "why",
    })
}

pub fn request_status(status: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "req-1",
        "api_key_id": "test-key",
        "chain_type": "evm",
        "chain_id": "56",
        "signer_address": "0x1111111111111111111111111111111111111111",
        "sign_type": "tx",
        "status": status,
        "signature": "0xdeadbeef",
        "error_message": "denied by rule",
        "created_at": "1970-01-01T00:00:00Z",
        "updated_at": "1970-01-01T00:00:00Z",
    })
}

pub fn sign_request() -> remote_signer_client::evm::SignRequest {
    remote_signer_client::evm::SignRequest {
        chain_id: "56".to_string(),
        signer_address: "0x1111111111111111111111111111111111111111".to_string(),
        sign_type: "personal".to_string(),
        payload: serde_json::json!({ "message": "hello" }),
    }
}
