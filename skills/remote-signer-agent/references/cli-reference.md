# CLI Reference

## First Launch

```bash
./remote-signer
# → Creates ~/.remote-signer/ with SQLite config
# → Generates Ed25519 admin keypair
# → Prints private key path ONCE to stderr
```

## Remote CLI Auth Flags

Every remote API command shares these persistent flags (also configurable via env vars):

| Flag | Env Var | Description |
|------|---------|-------------|
| `--url` | `REMOTE_SIGNER_URL` | Server URL (default: `https://localhost:8548`) |
| `--api-key-id` | `REMOTE_SIGNER_API_KEY_ID` | API key ID (required) |
| `--api-key-file` | `REMOTE_SIGNER_API_KEY_FILE` | Path to Ed25519 private key PEM |
| `--api-key-keystore` | `REMOTE_SIGNER_API_KEY_KEYSTORE` | Path to encrypted keystore (mutually exclusive with `--api-key-file`) |
| `--output` / `-o` | — | Output format: `table` (default), `json`, `yaml` |
| `--json` | — | Shorthand for `-o json` |

Auth auto-discovery: when neither `--api-key-file` nor `--api-key-keystore` is set, the CLI auto-discovers:
- For `--api-key-id admin`: looks for `admin.keystore.json` in `~/.remote-signer/apikeys/`
- For other IDs: looks for `<id>.key.priv` PEM in `~/.remote-signer/apikeys/`

## Key Commands

```bash
# Server
./remote-signer                          # Start daemon
./remote-signer tui                      # Terminal UI
./remote-signer validate rules/          # Offline rule validation (needs forge)

# API Key management (requires admin auth)
./remote-signer api-key keygen --out ./my-key
./remote-signer api-key create --id my-key --name "My Key" --role dev \
  --public-key <hex> --url http://localhost:8548 \
  --api-key-id admin --api-key-file ~/.remote-signer/apikeys/admin.key.priv
./remote-signer api-key list
./remote-signer api-key delete my-key

# EVM operations
./remote-signer evm request list [--status authorizing]
./remote-signer evm request approve <request-id>
./remote-signer evm request reject <request-id>
./remote-signer evm simulate tx --chain-id 1 --from 0x... --to 0x...
./remote-signer evm broadcast <signed-tx-hex> --chain-id 1

# Template management (remote CRUD via daemon API)
./remote-signer template list [--type evm_js] [--source uploaded] [--limit 50]
./remote-signer template get <template-id>
./remote-signer template validate <template-id>
./remote-signer template create -f template.yaml
./remote-signer template update <template-id> -f update.yaml
./remote-signer template delete <template-id>
./remote-signer template instantiate <template-id> -f req.yaml
./remote-signer template revoke-instance <rule-id>

# Local preset management (file-based, in rules/presets/)
./remote-signer preset list [--presets-dir rules/presets]
./remote-signer preset vars <preset-name>
./remote-signer preset create-from <preset-name>
./remote-signer preset create-from <preset-name> --config config.yaml --write \
  --set chain_id=56 --set token_address=0x...

# Remote preset management (via daemon API)
./remote-signer preset remote-list
./remote-signer preset remote-get <preset-id>
./remote-signer preset apply <preset-id> \
  --set chain_id=56 --set token_address=0x... \
  --set max_approve_amount=0 --set allowed_spenders=0x... \
  --api-key-id admin
./remote-signer preset validate <preset-id> \
  --set chain_id=56 --set token_address=0x... \
  --api-key-id admin
```

## Remote Preset Apply Protocol (Least-Privilege)

Before applying a preset to create rules:

1. **Query variables**: `preset remote-get <id>` to see all variables with descriptions, types, and defaults
2. **Query template**: `template get <template-id>` to see the full template with variable constraints
3. **Assess each variable's default danger** — the universal rule:
   - `""` (empty) with `requireInListIfNonEmpty()` = **any value allowed** (no restriction)
   - `"-1"` with `requireLte()` = **no cap** (unlimited)
4. **Fill EVERY variable** that controls scope — never leave optional variables at permissive defaults
5. **Ask the user** before deciding final values. Do not pick values yourself.
6. For the detailed protocol, see the `remote-signer-rule-development` skill.
