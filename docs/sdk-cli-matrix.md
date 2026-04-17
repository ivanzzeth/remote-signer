# Go SDK (`pkg/client`) ⇄ `remote-signer-cli` matrix

This document is the **auditable** mapping between the Go SDK surface (`github.com/ivanzzeth/remote-signer/pkg/client`) and what `remote-signer-cli` exposes today.

It exists to prevent accidental “full parity” claims: **the SDK is a superset of what we want to expose via a terminal UX**, and some workflows are intentionally **TUI-first** or **HTTP-only**.

## Legend

- **CLI covered**: there is a `remote-signer-cli` subcommand that calls the SDK method(s) directly.
- **CLI partial**: CLI exists but does not expose every filter/field the SDK supports (gap is noted).
- **Intentionally not CLI (defer)**: deliberate product choice; use TUI/HTTP/SDK for now.
- **Needs board scope**: would materially expand operator-facing surface area or security posture; should be a separate decision.

## Top-level client (`pkg/client.Client`)

| SDK API | CLI | Decision | Notes |
|---|---|---|---|
| `Client.Health` | `health` | CLI covered | Uses `GET /health` without auth (same as SDK). |
| `Client.Metrics` | `metrics` | CLI partial | CLI uses raw `GET /metrics` (no auth). SDK uses authenticated transport; endpoint is still typically unauth. |

## `client.Audit` (`pkg/client/audit`)

| SDK method | CLI | Decision | Notes |
|---|---|---|---|
| `Audit.List` | `audit list` | CLI partial (fixed in this change) | SDK supports `cursor` **and** `cursor_id`; CLI previously exposed only `cursor`. |

## `client.APIKeys` (`pkg/client/apikeys`)

| SDK method | CLI | Decision | Notes |
|---|---|---|---|
| `APIKeys.List/Get/Create/Update/Delete` | `api-key …` | CLI covered | Admin-only operations; CLI prints JSON/table. |

## `client.Templates` (`pkg/client/templates`)

| SDK method | CLI | Decision | Notes |
|---|---|---|---|
| `Templates.*` | `template …` | CLI covered | CRUD + instantiate + revoke-instance. |

## `client.ACLs` (`pkg/client/acls`)

| SDK method | CLI | Decision | Notes |
|---|---|---|---|
| `ACLs.GetIPWhitelist` | `acl ip-whitelist` | CLI covered | Read-only admin view. |

## `client.Presets` (`pkg/client/presets`)

| SDK method | CLI | Decision | Notes |
|---|---|---|---|
| `Presets.List/Vars/Apply*` | `preset …` | CLI covered | |

## `client.EVM` (`pkg/client/evm`)

The EVM SDK is large (signing, rules, wallets, requests, simulation, broadcast, guard, HD wallets, …). The CLI exposes the **operator-focused** subset under `evm …` plus a few legacy top-level aliases (`rule`, `sign`).

| Area | SDK entrypoints (examples) | CLI | Decision | Notes |
|---|---|---|---|---|
| Signing | `EVM.Sign.Execute*`, `EVM.Sign.ExecuteBatch`, `RemoteSigner.*` helpers | `evm sign …` | CLI covered | High-risk paths belong in explicit commands, not “raw calldata” blobs. |
| Rules | `EVM.Rules.*` | `evm rule …` | CLI covered | |
| Signers / access | `EVM.Signers.*` | `evm signer …` | CLI covered | |
| Wallets / members | `EVM.Wallets.*` | `evm wallet …` | CLI covered | |
| Requests / approvals | `EVM.Requests.*` | `evm request …` | CLI covered | |
| Simulation | `EVM.Simulate.*` | `evm simulate …` | CLI covered | |
| Broadcast | `EVM.Broadcast.*` | `evm broadcast …` | CLI covered | Money-moving; CLI remains the “typed intent” layer. |
| Guard | `EVM.Guard.Resume` | `evm guard …` | CLI covered | |
| HD wallets | `EVM.HDWallet.*` | `evm hdwallet …` | CLI covered | |

### Known intentional gaps (defer)

These are **SDK-present** capabilities that are still intentionally **not** mirrored as CLI commands because they are primarily interactive or are not “safe” as scriptable operators:

- **Anything better served by the TUI** (interactive workflows): use `remote-signer-cli tui` (pass-through) or the web/TUI surfaces.
- **Low-level “compose arbitrary calldata” helpers** (if added in the future): must remain behind explicit, validated intent types (per product governance), not free-form blobs.

## Change policy (how to edit this file)

1. If you add a new SDK service method, update this matrix **in the same PR**.
2. If CLI is intentionally not added, mark **Intentionally not CLI (defer)** and link to the TUI/HTTP route.
3. If you need a new CLI command family, confirm **no divergence** with the Founding Engineer’s stack boundaries first.
