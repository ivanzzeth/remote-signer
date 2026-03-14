# remote-signer-mcp

MCP (Model Context Protocol) server for the [remote-signer](https://github.com/ivanzzeth/remote-signer) service. Uses [remote-signer-client](https://www.npmjs.com/package/remote-signer-client) from npm.

## Run with npx (no install)

```bash
npx -y remote-signer-mcp
```

## Environment variables

Sensitive values can be set **by path** (recommended) or by raw value.

| Variable | Required | Description |
|----------|----------|-------------|
| `REMOTE_SIGNER_URL` | No | Base URL (default: http://localhost:8548) |
| `REMOTE_SIGNER_API_KEY_ID` | Yes | API key ID (e.g. `admin`) |
| `REMOTE_SIGNER_PRIVATE_KEY` | One of | Ed25519 private key in **hex** |
| `REMOTE_SIGNER_PRIVATE_KEY_FILE` | One of | **Path** to PEM file (e.g. `data/admin_private.pem`) |

**TLS / mTLS** (optional, for HTTPS backends):

| Variable | Description |
|----------|-------------|
| `REMOTE_SIGNER_CA_FILE` | Path to CA certificate (PEM) for server verification |
| `REMOTE_SIGNER_CLIENT_CERT_FILE` | Path to client certificate (PEM) for mTLS |
| `REMOTE_SIGNER_CLIENT_KEY_FILE` | Path to client private key (PEM) for mTLS |
| `REMOTE_SIGNER_TLS_INSECURE_SKIP_VERIFY` | Set to `1` or `true` to skip server cert verification (insecure, testing only) |

## Cursor / MCP config

**Path-based (recommended):** no secrets in config, only paths.

```json
{
  "mcpServers": {
    "remote-signer": {
      "command": "npx",
      "args": ["-y", "remote-signer-mcp"],
      "env": {
        "REMOTE_SIGNER_URL": "https://your-server.example.com",
        "REMOTE_SIGNER_API_KEY_ID": "admin",
        "REMOTE_SIGNER_PRIVATE_KEY_FILE": "/abs/path/to/data/admin_private.pem",
        "REMOTE_SIGNER_CA_FILE": "/path/to/ca.pem",
        "REMOTE_SIGNER_CLIENT_CERT_FILE": "/path/to/client.pem",
        "REMOTE_SIGNER_CLIENT_KEY_FILE": "/path/to/client-key.pem"
      }
    }
  }
}
```

**Local HTTP (no TLS):**

```json
{
  "mcpServers": {
    "remote-signer": {
      "command": "npx",
      "args": ["-y", "remote-signer-mcp"],
      "env": {
        "REMOTE_SIGNER_URL": "http://localhost:8548",
        "REMOTE_SIGNER_API_KEY_ID": "admin",
        "REMOTE_SIGNER_PRIVATE_KEY_FILE": "projects/personal/ivanzzeth/remote-signer/data/admin_private.pem"
      }
    }
  }
}
```

Paths in `env` are resolved from the process working directory (often the workspace root when Cursor starts the MCP server).

## Install and run locally

```bash
npm install
npm run build
REMOTE_SIGNER_API_KEY_ID=admin REMOTE_SIGNER_PRIVATE_KEY_FILE=./data/admin_private.pem node build/index.js
```

## Local development / test without publishing

When testing HTTPS or TLS fixes before publishing:

1. **Use the local client in the MCP:** from `pkg/mcp-server` run `npm install file:../js-client`, then `npm run build`.
2. **Verify HTTPS client:** from the agents repo root, with the same `env` as in `.cursor/mcp.json` (including `REMOTE_SIGNER_URL=https://...` and cert paths), run:
   ```bash
   node projects/personal/ivanzzeth/remote-signer/pkg/mcp-server/scripts/test-https.mjs
   ```
   You should see `OK: { "rules": [...] }` or a connection error if the backend is down — not "Client sent an HTTP request to an HTTPS server".
3. **Cover all MCP tools:** run the full self-test (all 16 tools over HTTPS):
   ```bash
   node projects/personal/ivanzzeth/remote-signer/pkg/mcp-server/scripts/test-all-tools.mjs
   ```
   You should see `passed: 16, failed: 0`.
4. **Run the MCP from the repo:** in `.cursor/mcp.json` point `remote-signer` at the local build instead of npx, e.g. `"command": "node"`, `"args": ["projects/personal/ivanzzeth/remote-signer/pkg/mcp-server/build/index.js"]`, and keep the same `env`. Restart Cursor MCP and trigger a tool (e.g. list rules) to confirm.

Publish a new version only after local tests are stable.

## License

MIT
