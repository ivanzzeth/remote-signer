# TLS, Security & Deployment

## TLS / mTLS

### Configuration

```yaml
server:
  port: 8548
  tls:
    enabled: true
    cert_file: "./certs/server.crt"
    key_file: "./certs/server.key"
    ca_file: "./certs/ca.crt"          # CA for verifying client certs
    client_auth: false                 # true = require client certs (mTLS)
```

### Generate Certificates

```bash
./scripts/gen-certs.sh
# Creates certs/ca.crt, certs/server.crt, certs/server.key,
#          certs/client.crt, certs/client.key
```

Force overwrite: `CERTS_FORCE=1 ./scripts/gen-certs.sh`

### Health Check by TLS Mode

**Plain HTTP:**
```bash
curl -fsS "http://127.0.0.1:8548/health"
```

**HTTPS (private CA, no mTLS):**
```bash
curl --cacert certs/ca.crt -fsS "https://127.0.0.1:8548/health"
```

**HTTPS + mTLS:**
```bash
curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key \
  -fsS "https://127.0.0.1:8548/health"
```

### MCP/TLS

```json
{
  "env": {
    "REMOTE_SIGNER_URL": "https://127.0.0.1:8548",
    "REMOTE_SIGNER_CA_FILE": "./certs/ca.crt",
    "REMOTE_SIGNER_CLIENT_CERT_FILE": "./certs/client.crt",
    "REMOTE_SIGNER_CLIENT_KEY_FILE": "./certs/client.key"
  }
}
```

## IP Whitelist

```yaml
security:
  ip_whitelist:
    enabled: true
    allowed_ips:
      - "127.0.0.1"
      - "::1"
      - "10.0.0.0/8"
    trust_proxy: true                     # Trust X-Forwarded-For
    trusted_proxies: ["10.0.0.1"]         # Required when trust_proxy=true
```

- Without `trusted_proxies`, proxy headers are **ignored** (fail-closed)
- Only requests from `allowed_ips` (or trusted proxy with valid forwarded IP) are accepted

## Security Configuration

### Recommended Production Baseline

```yaml
security:
  max_request_age: "30s"              # Replay window
  rate_limit_default: 100             # Per-key req/min
  ip_rate_limit: 200                  # Pre-auth req/min
  nonce_required: true                # Replay protection
  manual_approval_enabled: false      # true = unmatched → pending approval
  rules_api_readonly: true            # Block API rule mutations
  api_keys_api_readonly: true         # Block API key CRUD
  signers_api_readonly: false         # Allow runtime signer creation

  approval_guard:
    enabled: true
    window: "1h"
    rejection_threshold_pct: 50
    min_samples: 10
    resume_after: "2h"
```

### Key Management

| Method | Production Ready |
|--------|:---:|
| Encrypted keystore (JSON) | Yes |
| HD Wallet (BIP-39, encrypted) | Yes |
| Plaintext key (env var) | No (test only) |
| HSM | Planned |

**Memory hardening:** `mlockall`, `PR_SET_DUMPABLE=0`, password zeroization, container `mem_swappiness: 0`

### Sandboxing

- **JS rules**: 20ms timeout, 32MB memory, 13+ blocked globals (eval, Function, fetch, Reflect, Proxy)
- **Solidity rules**: 24 blocked patterns (vm.ffi, vm.readFile, etc.), 30s timeout
