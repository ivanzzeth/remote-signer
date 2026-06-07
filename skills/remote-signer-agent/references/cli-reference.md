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

**Local HTTP daemon (TLS off):** add `--url http://127.0.0.1:8548 --tls-skip-verify`. Do **not** pass `--config` on API commands — `--config` is only for `server start` and offline `config`/`preset` subcommands.

Run `./remote-signer doctor --url http://127.0.0.1:8548 --tls-skip-verify` to sanity-check reachability and key paths.

## Key Commands

```bash
# Server
./remote-signer                          # Start daemon
./remote-signer tui                      # Terminal UI
./remote-signer validate rules/          # Offline rule validation (needs forge)

# API Key management (requires admin auth)
./remote-signer api-key keygen --out ./my-key
./remote-signer api-key create --id my-key --name "My Key" --role dev \
  --public-key <hex> --url http://127.0.0.1:8548 --tls-skip-verify \
  --api-key-id admin --api-key-keystore ~/.remote-signer/apikeys/admin.keystore.json
./remote-signer api-key list
./remote-signer api-key delete my-key

# Sign (subcommands — there is no --sign-type / --payload on the parent command)
./remote-signer evm sign tx --signer 0xYourAddr --chain-id 1 \
  --to 0xRecipient --value 0 --data 0x --gas 21000 --tx-type legacy \
  --url http://127.0.0.1:8548 --api-key-id agent \
  --api-key-file ~/.remote-signer/apikeys/agent.key.priv --tls-skip-verify
./remote-signer evm sign personal --signer 0xYourAddr --message "hello"
./remote-signer evm sign hash --signer 0xYourAddr --hash 0x<64-hex-bytes>

# EVM operations
./remote-signer evm request list [--status authorizing] \
  --url http://127.0.0.1:8548 --api-key-id admin \
  --api-key-keystore ~/.remote-signer/apikeys/admin.keystore.json --tls-skip-verify
./remote-signer evm request approve <request-id>
./remote-signer evm request reject <request-id>
./remote-signer evm signer approve <signer-address>   # approve pending signer (admin)
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
./remote-signer preset remote-list --q stargate   # fuzzy search (API: GET /api/v1/presets?q=)
./remote-signer preset remote-get <preset-id>
# Agent can apply presets (creates rules owner=agent, applied_to=self):
./remote-signer preset apply <preset-id> \
  --set max_input_amount=1000000000000000000 \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv

# Admin may also apply (broader applied_to scope):
./remote-signer preset apply <preset-id> \
  --set chain_id=56 --set token_address=0x... \
  --url http://127.0.0.1:8548 --api-key-id admin

./remote-signer preset validate <preset-id> \
  --set chain_id=56 --set token_address=0x... \
  --url http://127.0.0.1:8548 --api-key-id agent
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
