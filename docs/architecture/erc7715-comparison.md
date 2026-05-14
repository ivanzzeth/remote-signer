# ERC-7715 (Grant Permissions from Wallets) Comparison

Comparison of [ERC-7715](https://eips.ethereum.org/EIPS/eip-7715) wallet permission model with Remote Signer's rule-based authorization system.

> Last updated: 2026-03-19

---

## Background

ERC-7715 defines `wallet_requestExecutionPermissions` — a JSON-RPC method for dApps to request structured permissions from wallets. Users approve a permission scope (token type, allowance, expiry), and the dApp can then execute transactions within that scope without per-tx approval.

This is conceptually identical to what Remote Signer achieves with its rule engine + manual approval flow, but through different mechanisms.

---

## Core Concept Mapping

| ERC-7715 Concept | Remote Signer Equivalent | Notes |
|------------------|--------------------------|-------|
| `wallet_requestExecutionPermissions` | Agent creates rule → admin approves | Same flow: request permission → human review → grant |
| `wallet_revokeExecutionPermission` | Delete rule / disable rule / lock signer | Multiple revocation granularities |
| Permission `type` (e.g. `erc20-token-transfer`) | Rule `type` (e.g. `evm_address_list`, `evm_contract_method`, `evm_js`) | RS has more types and composability |
| Permission `allowance` | Budget `max_total` / `max_per_tx` | RS adds per-tx limit + dynamic unit tracking |
| `ExpiryRule { timestamp }` | Budget `period` (e.g. 24h auto-reset) | RS resets periodically; ERC-7715 is one-shot expiry |
| `permissionsContext` (opaque token) | Rule ID + API key scope | RS uses RBAC, not bearer tokens |
| DelegationManager (on-chain) | Sign service (off-chain) | RS signs off-chain; no on-chain delegation contract |
| Session key (`to` address) | Agent API key | RS uses Ed25519 API keys, not on-chain session keys |

---

## Where Remote Signer Goes Beyond ERC-7715

### 1. Richer Permission Types

ERC-7715 defines a small set of permission types (`native-token-transfer`, `erc20-token-transfer`, etc.). Remote Signer supports:

| Rule Type | Description |
|-----------|-------------|
| `evm_address_list` | Whitelist/blocklist by recipient address |
| `evm_contract_method` | Allow/block by contract + method selector |
| `evm_value_limit` | Cap value per tx / aggregate |
| `evm_js` | Arbitrary JavaScript logic (Sobek sandbox) |
| `evm_solidity_expression` | Custom Solidity conditions (Foundry sandbox) |
| `evm_dynamic_blocklist` | Real-time OFAC/sanctions blocklist |
| Composable rules | Multiple rules evaluated in order (blocklist → whitelist) |

ERC-7715 permission types are static and predefined. RS rules are programmable — any condition expressible in JS or Solidity can be a rule.

### 2. Simulation-Based Budget (Not Just Allowance)

ERC-7715 relies on the dApp to self-report spending within the granted allowance. Remote Signer **independently verifies** via transaction simulation:

- Simulates every transaction via `eth_simulateV1`
- Extracts actual balance changes from simulation events
- Deducts from budget based on real outflows, not declared intent
- Detects dangerous state changes (OwnershipTransferred, Upgraded, etc.)
- Gas cost included in native budget

This means a malicious or buggy agent cannot under-report spending.

### 3. Two-Tier Rule Evaluation (Blocklist + Whitelist)

ERC-7715 has a single permission grant model. Remote Signer evaluates in two phases:

1. **Blocklist (mandatory, fail-closed)**: Known dangerous operations rejected immediately, no appeal
2. **Whitelist**: Matching rule → auto-approve within budget; no match → manual approval or reject

This separation means blocklist rules cannot be bypassed by permissive whitelist rules.

### 4. Periodic Budget Reset

ERC-7715 permissions expire at a fixed timestamp. Remote Signer budgets **reset periodically** (e.g. every 24h), which is more practical for ongoing agent operations:

```
Day 1: spend 80 USDC (budget: 100) → 20 remaining
Day 2: budget resets → 100 available again
```

ERC-7715 would require re-granting permission after expiry.

### 5. Managed Signer Security Layer

Beyond permission rules, Remote Signer adds signer-level security:

- **Signer ownership**: Only the owner API key can approve manual-approval requests
- **Auto-lock timeout**: Signers lock after inactivity
- **Approval guard**: Detects burst patterns of rejected/manual-approval outcomes
- **Dangerous event detection**: Simulation catches OwnershipTransferred, ApprovalForAll, Upgraded regardless of call wrapping (multicall, etc.)

### 6. Off-Chain = No Gas Overhead

ERC-7715 requires on-chain delegation contracts (DelegationManager, caveats enforced on-chain). Remote Signer enforces everything off-chain — zero gas overhead for permission checks.

---

## Where ERC-7715 Has Advantages

| Advantage | Description | RS Mitigation |
|-----------|-------------|---------------|
| **Standardized** | Any wallet supporting ERC-7715 can grant permissions to any dApp | RS is a custom system; agents must integrate with RS client SDK |
| **On-chain enforcement** | Permissions enforced by smart contracts, trustless | RS requires trusting the server; mitigated by audit logging + container hardening |
| **Composable with account abstraction** | Works with ERC-4337, ERC-7702, session keys | RS is independent of account abstraction |
| **UI standardization** | Wallets display permissions in a standard format | RS relies on CLI/TUI/MCP for admin review |

---

## Conclusion

Remote Signer's rule engine is a **superset** of ERC-7715's permission model:

- ERC-7715's `permission + allowance + expiry` maps to RS's `whitelist rule + budget + period`
- RS adds programmable rules (JS/Solidity), simulation-based verification, two-tier evaluation, and signer-level security
- RS operates off-chain (no gas cost, no on-chain contracts), trading trustlessness for flexibility and performance

For AI agent use cases, RS's approach is more practical: agents need complex, evolving permissions (not just "spend X tokens") and independent verification of actual behavior (not self-reported).

If future interoperability with ERC-7715 wallets is needed, RS rules can be mapped to ERC-7715 permission types as a compatibility layer — the underlying capabilities already exceed what ERC-7715 specifies.
