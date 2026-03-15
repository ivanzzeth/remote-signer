# remote-signer-client (Rust)

Rust SDK for the `remote-signer` service.

## Install

From this mono-repo (path dependency):

```toml
[dependencies]
remote-signer-client = { path = "../remote-signer/pkg/rs-client" }
```

## Authentication

Requests are signed with Ed25519.
Message format (matches server middleware):

```
{timestamp_ms}|{nonce}|{method}|{path_with_query}|{sha256(body)}
```

Headers:
- `X-API-Key-ID`
- `X-Timestamp`
- `X-Nonce`
- `X-Signature` (base64)

## Minimal example

```rust
use remote_signer_client::{Client, Config};
use remote_signer_client::evm::{SignRequest, SIGN_TYPE_PERSONAL};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(Config {
        base_url: "http://127.0.0.1:8548".to_string(),
        api_key_id: "my-key".to_string(),
        private_key_hex: Some("0x...".to_string()),
        ..Default::default()
    })?;

    let req = SignRequest {
        chain_id: "1".to_string(),
        signer_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
        sign_type: SIGN_TYPE_PERSONAL.to_string(),
        payload: serde_json::json!({"message": "hello"}),
    };

    let resp = client.evm.sign.execute(&req)?;
    println!("status={} sig={:?}", resp.status, resp.signature);

    Ok(())
}
```
