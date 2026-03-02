# TLS / mTLS Certificate Guide

Remote-signer supports TLS (HTTPS) and mutual TLS (mTLS). This document explains the certificate trust model, generation, configuration, and production security best practices.

## Certificate Trust Model

Remote-signer uses a **three-key-pair** architecture. Each participant holds its own private key and never shares it.

```
                    ┌──────────────┐
                    │      CA      │
                    │  (ca.key)    │  ← Signs server & client certs
                    │  (ca.crt)    │  ← Distributed to all parties for verification
                    └──────┬───────┘
                           │ signs
               ┌───────────┴───────────┐
               ▼                       ▼
        ┌──────────────┐        ┌──────────────┐
        │    Server     │        │    Client     │
        │ (server.key)  │        │ (client.key)  │
        │ (server.crt)  │        │ (client.crt)  │
        └──────────────┘        └──────────────┘
```

### What each party holds

| Role | Private key | Certificates | Purpose |
|------|-------------|-------------|---------|
| **CA** | `ca.key` | `ca.crt` | Signs and issues server/client certs |
| **Server** | `server.key` | `server.crt`, `ca.crt` | Proves server identity; verifies client certs |
| **Client** | `client.key` | `client.crt`, `ca.crt` | Proves client identity; verifies server cert |

### Key principle

- **Private keys never leave their owner.** The CA never sees `server.key` or `client.key`. The server never sees `client.key`. The client never sees `server.key`.
- **`ca.crt` (public)** is the only file shared across all parties. It is used to verify that a certificate was issued by the trusted CA.
- **`ca.key` is the most sensitive secret.** Anyone with `ca.key` can issue arbitrary certificates that all parties will trust.

### mTLS handshake flow

```
Client                                    Server
  │                                         │
  │ ──── ClientHello ────────────────────►  │
  │                                         │
  │ ◄─── ServerHello + server.crt ───────  │
  │                                         │
  │  (Client verifies server.crt            │
  │   against ca.crt)                       │
  │                                         │
  │ ──── client.crt + proof ─────────────►  │
  │                                         │
  │       (Server verifies client.crt       │
  │        against ca.crt)                  │
  │                                         │
  │ ◄───── TLS 1.3 Established ──────────  │
```

## Quick Start (Development)

Generate all three key pairs with one command:

```bash
./scripts/gen-certs.sh

# Or with extra SAN IPs for LAN/remote access
./scripts/gen-certs.sh 10.0.0.5 192.168.1.100
```

Output in `./certs/`:

| File | Permission | Description |
|------|-----------|-------------|
| `ca.crt` | 644 | CA public certificate |
| `ca.key` | 600 | CA private key |
| `server.crt` | 644 | Server certificate (SAN: localhost, 127.0.0.1, ::1, LAN IP) |
| `server.key` | 600 | Server private key |
| `client.crt` | 644 | Client certificate |
| `client.key` | 600 | Client private key |

### Server configuration

```yaml
server:
  tls:
    enabled: true
    cert_file: "./certs/server.crt"
    key_file: "./certs/server.key"
    ca_file: "./certs/ca.crt"       # For verifying client certs
    client_auth: true               # Require client certificate (mTLS)
```

Set `client_auth: false` for TLS-only mode (server authentication only, no client certificate required).

### Client usage

```bash
# curl
curl --cacert certs/ca.crt \
     --cert certs/client.crt \
     --key certs/client.key \
     https://localhost:8548/health

# TUI
./remote-signer-tui \
  -tls-ca ./certs/ca.crt \
  -tls-cert ./certs/client.crt \
  -tls-key ./certs/client.key \
  -url https://localhost:8548 \
  -api-key-id your-key-id \
  -private-key your-ed25519-key
```

```go
// Go SDK
c, err := client.NewClient(client.Config{
    BaseURL:     "https://localhost:8548",
    TLSCAFile:   "certs/ca.crt",
    TLSCertFile: "certs/client.crt",
    TLSKeyFile:  "certs/client.key",
    // ...
})
```

```typescript
// Node.js SDK
const client = new RemoteSignerClient({
  baseURL: 'https://localhost:8548',
  httpClient: {
    tls: {
      ca: fs.readFileSync('certs/ca.crt'),
      cert: fs.readFileSync('certs/client.crt'),
      key: fs.readFileSync('certs/client.key'),
    },
  },
  // ...
});
```

## Production Security Best Practices

### 1. Separate CA from server and client machines

In development, `gen-certs.sh` generates all three key pairs on one machine. **In production, the CA should be isolated:**

```
┌─────────────────────────┐
│   CA Machine (offline)  │    Generate ca.key + ca.crt here.
│                         │    Sign CSRs from server/client.
│   Holds: ca.key, ca.crt │    Then take ca.key OFFLINE.
└─────────┬───────────────┘
          │  (issue certs via CSR)
    ┌─────┴──────┐
    ▼            ▼
┌──────────┐  ┌──────────┐
│  Server  │  │  Client  │
│          │  │          │
│ Has:     │  │ Has:     │
│ server.key│  │ client.key│   ← Generated locally, never leaves
│ server.crt│  │ client.crt│   ← Signed by CA via CSR
│ ca.crt   │  │ ca.crt   │   ← Public, for verification only
└──────────┘  └──────────┘
```

**Steps:**

```bash
# === On the server machine ===
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr \
  -subj "/CN=remote-signer-server"

# === Transfer server.csr to CA machine (NOT server.key) ===

# === On the CA machine ===
openssl x509 -req -in server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 \
  -extfile server_ext.cnf

# === Transfer server.crt back to server machine ===
# === Delete server.csr from CA machine ===
```

Repeat the same process for client certificates.

### 2. Protect `ca.key`

| Environment | Recommendation |
|-------------|---------------|
| Small team | Store `ca.key` on an encrypted USB drive, offline |
| Enterprise | Use a Hardware Security Module (HSM) or managed PKI (HashiCorp Vault, AWS Private CA, CFSSL) |
| After signing | Remove `ca.key` from any network-connected machine |

If `ca.key` is compromised, an attacker can issue trusted client certificates and bypass mTLS. Rotate the entire chain if this happens.

### 3. Use short-lived certificates

The default validity is 365 days. For higher security:

```bash
# 90-day certificates
DAYS=90 ./scripts/gen-certs.sh
```

Automate renewal before expiry. Monitor certificate expiration dates:

```bash
openssl x509 -in certs/server.crt -noout -enddate
```

### 4. Issue separate client certificates per service

Do not share one `client.crt`/`client.key` across multiple services. Issue a separate certificate per client so you can revoke individually:

```
CA signs → client-app-a.crt   (for Service A)
CA signs → client-app-b.crt   (for Service B)
CA signs → client-admin.crt   (for admin TUI)
```

### 5. File permissions

```bash
# Private keys: owner-only read
chmod 600 ca.key server.key client.key

# Certificates: world-readable is fine (public data)
chmod 644 ca.crt server.crt client.crt
```

Never commit private keys (`.key` files) to version control.

### 6. TLS version

Remote-signer enforces **TLS 1.3 minimum** (configured in Go code). TLS 1.2 and below are rejected.

## Certificate Verification Commands

```bash
# View certificate details
openssl x509 -in certs/server.crt -text -noout

# Verify server cert was signed by CA
openssl verify -CAfile certs/ca.crt certs/server.crt

# Verify client cert was signed by CA
openssl verify -CAfile certs/ca.crt certs/client.crt

# Check certificate expiration
openssl x509 -in certs/server.crt -noout -enddate

# Test TLS connection
openssl s_client -connect localhost:8548 -CAfile certs/ca.crt

# Test mTLS connection
openssl s_client -connect localhost:8548 \
  -CAfile certs/ca.crt \
  -cert certs/client.crt \
  -key certs/client.key
```

## Configuration Modes

| Mode | `tls.enabled` | `tls.client_auth` | Use case |
|------|--------------|-------------------|----------|
| HTTP (no TLS) | `false` | — | Development only, behind trusted network |
| TLS only | `true` | `false` | Server authentication only, clients don't need certs |
| mTLS | `true` | `true` | Both sides authenticate. Recommended for production |

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `tls: certificate required` | Server requires client cert but client didn't provide one | Add `--cert` and `--key` to client |
| `x509: certificate signed by unknown authority` | Client doesn't trust server's CA | Add `--cacert ca.crt` or set `TLSCAFile` |
| `x509: certificate has expired` | Certificate past validity date | Re-generate certificates |
| `tls: bad certificate` | Client cert not signed by the CA the server trusts | Ensure client cert was signed by the same CA configured in `ca_file` |
| `remote error: tls: unrecognized name` | Server cert SAN doesn't include the hostname/IP used | Re-generate with correct SAN: `./scripts/gen-certs.sh <ip>` |
