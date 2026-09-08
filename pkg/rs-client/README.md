# remote-signer-client (Rust)

Rust SDK for the `remote-signer` service.

## Install

From this mono-repo (path dependency):

```toml
[dependencies]
remote-signer-client = { path = "../remote-signer/pkg/rs-client" }
```

With the non-blocking client:

```toml
[dependencies]
remote-signer-client = { path = "../remote-signer/pkg/rs-client", features = ["async"] }
```

## Which client?

| | `Client` | `AsyncClient` |
|---|---|---|
| Feature | always available | `async` |
| Transport | `reqwest::blocking` | `reqwest` |
| Usable inside a Tokio runtime | **no — panics** | yes |

Both accept the same `Config` and expose the same EVM surface, so moving between
them is a matter of adding `.await`. They also share request signing, endpoint
paths and the approval state machine, so their behaviour cannot drift.

> The blocking client builds its own runtime internally. Calling it from an
> async context panics with *"Cannot start a runtime from within a runtime"*.
> Enable the `async` feature instead of wrapping `Client` in `spawn_blocking`.

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

## Minimal example (blocking)

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

## Minimal example (async)

```rust
use remote_signer_client::{AsyncClient, Config};
use remote_signer_client::evm::{SignRequest, SIGN_TYPE_PERSONAL};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AsyncClient::new(Config {
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

    let resp = client.evm.sign.execute(&req).await?;
    println!("status={} sig={:?}", resp.status, resp.signature);

    Ok(())
}
```

## Pending approvals

`execute()` waits for a request that lands in `pending`/`authorizing` to be
approved, polling `poll_interval` until `poll_timeout`.

Automated callers on a latency budget should use `execute_no_wait()`
(`execute_async()` on the blocking client), which returns `Error::Sign`
immediately with the request id. In an automated flow a request reaching
`pending` usually means a rule is missing, not that approval is imminent.

## Layout

```
src/
  client.rs              Client / AsyncClient
  transport/
    common.rs            request signing, status handling, TLS setup (shared)
    transport.rs         blocking transport
    async_transport.rs   non-blocking transport (feature = "async")
  evm/
    paths.rs             endpoint paths and query strings (shared)
    sign.rs              SignService / AsyncSignService + approval state machine
    ...                  one file per service, blocking and async side by side
```

Blocking and async live in the same file so a change to one is visible next to
the other. Anything they must agree on — endpoint paths, request signing, status
classification — lives in `transport/common.rs`, `evm/paths.rs` or a shared
function, never duplicated.

## Development

```bash
cargo test                                    # blocking only
cargo test --features async                   # both clients
cargo clippy --all-targets --features async   # must be warning-free
```

`tests/` runs both clients against a `wiremock` server: auth headers, query
strings, approval polling, timeout and error mapping.

## Adding an endpoint

1. Add the path (and query builder, if any) to `src/evm/paths.rs`.
2. Add the method to the blocking service.
3. Add the same method to the `asynchronous` module in the same file.
4. Add a `wiremock` test in `tests/`.
