# remote-signer-mcp

MCP (Model Context Protocol) server for the [remote-signer](https://github.com/ivanzzeth/remote-signer) service. Uses [remote-signer-client](https://www.npmjs.com/package/remote-signer-client) from npm.

## Run with npx (no install)

```bash
npx -y remote-signer-mcp
```

Requires env vars:

- `REMOTE_SIGNER_URL` – base URL (default: http://localhost:8548)
- `REMOTE_SIGNER_API_KEY_ID` – API key ID
- `REMOTE_SIGNER_PRIVATE_KEY` – Ed25519 private key (hex)

## Cursor / MCP config

In `.cursor/mcp.json` or your MCP config:

```json
{
  "mcpServers": {
    "remote-signer": {
      "command": "npx",
      "args": ["-y", "remote-signer-mcp"],
      "env": {
        "REMOTE_SIGNER_URL": "http://localhost:8548",
        "REMOTE_SIGNER_API_KEY_ID": "your-api-key-id",
        "REMOTE_SIGNER_PRIVATE_KEY": "your-ed25519-private-key-hex"
      }
    }
  }
}
```

## Install and run locally

```bash
npm install
npm run build
REMOTE_SIGNER_API_KEY_ID=... REMOTE_SIGNER_PRIVATE_KEY=... node build/index.js
```

## License

MIT
