# Transaction Simulation Engine

## Status: Implemented

## Problem

The current budget engine tracks token spending by parsing known calldata patterns (ERC20 transfer, approve, etc.). For complex DeFi interactions — DEX swaps, aggregator routes, batch operations — the budget engine cannot decode arbitrary router calldata and falls back to `tx_count`, leaving actual token spending untracked.

Example: An agent swaps 2300 USDC → ETH via OKX DEX router. The budget engine sees an unknown selector (`0xf2c42696`) on an unknown contract, counts it as 1 `tx_count`, and the 2300 USDC expenditure is invisible.

## Solution

Add a transaction simulation layer to remote-signer. Simulation uses **`eth_simulateV1`** on the configured `rpc_gateway` (no local fork process).

### Simulation engine

| Mechanism | Description | Latency |
|-----------|-------------|---------|
| **RPC** (`eth_simulateV1`) | Calls `eth_simulateV1` via RPC gateway | Typically &lt;1s |

The gateway must expose `eth_simulateV1` for chains you simulate.

The simulation engine is a **general-purpose infrastructure** that:

1. Provides public API endpoints for single and batch simulation
2. Parses standard token events (ERC20/ERC721/ERC1155/WETH/native) and computes balance changes
3. Supports batch sign requests for atomic multi-tx workflows (approve + swap)
4. Is consumed internally by the budget engine as a fallback rule

The simulation engine is independent of budget logic — it returns structured results that any consumer (budget, UI, monitoring) can use.

```
                    ┌────────────────────────────────────┐
                    │   TransactionSimulator              │
                    │   (RPCSimulator + EventParser)      │
                    └───┬──────────────┬─────────────┬───┘
                        │              │             │
           ┌────────────▼──┐  ┌────────▼────────┐  ┌▼──────────────────┐
           │ Public API     │  │ Batch Sign API  │  │ Budget Rule       │
           │ /evm/simulate  │  │ /evm/sign/batch │  │ (internal         │
           │ /evm/simulate/ │  │ (sign N txs     │  │  fallback)        │
           │   batch        │  │  atomically)    │  │                   │
           └────────────────┘  └─────────────────┘  └───────────────────┘
```

---

## Public API

### `POST /api/v1/evm/simulate`

Simulate a single transaction. Any authenticated API key can call this.

#### Request

```json
{
  "chain_id": "1",
  "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  "to": "0x5E1f62Dac767b0491e3CE72469C217365D5B48cC",
  "value": "0x0",
  "data": "0xf2c42696...",
  "gas": "0x598731"
}
```

#### Response (200 OK)

```json
{
  "success": true,
  "gas_used": 285000,
  "balance_changes": [
    {
      "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
      "standard": "erc20",
      "amount": "-2300000000",
      "direction": "outflow"
    },
    {
      "token": "native",
      "standard": "native",
      "amount": "980000000000000000",
      "direction": "inflow"
    }
  ],
  "events": [
    {
      "address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
      "event": "Transfer",
      "standard": "erc20",
      "args": {"from": "0xf39F...", "to": "0x5E1f...", "value": "2300000000"}
    }
  ],
  "has_approval": false,
  "revert_reason": ""
}
```

### `POST /api/v1/evm/simulate/batch`

Simulate multiple transactions in sequence on the same base state. Each tx sees the state changes from previous txs (via `eth_simulateV1` batch semantics on the gateway).

#### Request

```json
{
  "chain_id": "1",
  "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  "transactions": [
    {
      "to": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
      "value": "0x0",
      "data": "0x095ea7b3...",
      "gas": "0x11170"
    },
    {
      "to": "0x5E1f62Dac767b0491e3CE72469C217365D5B48cC",
      "value": "0x0",
      "data": "0xf2c42696...",
      "gas": "0x598731"
    }
  ]
}
```

#### Response (200 OK)

```json
{
  "results": [
    {
      "index": 0,
      "success": true,
      "gas_used": 46000,
      "balance_changes": [],
      "events": [...],
      "has_approval": true,
      "revert_reason": ""
    },
    {
      "index": 1,
      "success": true,
      "gas_used": 285000,
      "balance_changes": [
        {"token": "0xa0b8...", "standard": "erc20", "amount": "-2300000000", "direction": "outflow"},
        {"token": "native", "standard": "native", "amount": "980000000000000000", "direction": "inflow"}
      ],
      "events": [...],
      "has_approval": false,
      "revert_reason": ""
    }
  ],
  "net_balance_changes": [
    {"token": "0xa0b8...", "standard": "erc20", "amount": "-2300000000", "direction": "outflow"},
    {"token": "native", "standard": "native", "amount": "980000000000000000", "direction": "inflow"}
  ]
}
```

`net_balance_changes` is the aggregate across all txs in the batch — used by budget engine.

### `POST /api/v1/evm/sign/batch`

Sign multiple transactions atomically. Simulates the batch first, checks budget against net balance changes, then signs all if approved.

#### Request

```json
{
  "requests": [
    {
      "chain_id": "1",
      "signer_address": "0xf39F...",
      "sign_type": "transaction",
      "transaction": {"to": "0xa0b8...", "value": "0x0", "data": "0x095ea7b3..."}
    },
    {
      "chain_id": "1",
      "signer_address": "0xf39F...",
      "sign_type": "transaction",
      "transaction": {"to": "0x5E1f...", "value": "0x0", "data": "0xf2c42696..."}
    }
  ]
}
```

#### Response (200 OK)

```json
{
  "results": [
    {
      "index": 0,
      "signature": "0x...",
      "simulation": {"success": true, "gas_used": 46000, "balance_changes": [], "has_approval": true}
    },
    {
      "index": 1,
      "signature": "0x...",
      "simulation": {"success": true, "gas_used": 285000, "balance_changes": [...]}
    }
  ],
  "net_balance_changes": [
    {"token": "0xa0b8...", "standard": "erc20", "amount": "-2300000000", "direction": "outflow"},
    {"token": "native", "standard": "native", "amount": "980000000000000000", "direction": "inflow"}
  ]
}
```

If any tx in the batch fails simulation or budget check, the entire batch is rejected (atomic).

### Client SDK

#### Go (`pkg/client/evm`)

```go
// Single simulation
result, err := client.EVM.Simulate(ctx, &SimulateRequest{...})

// Batch simulation
batchResult, err := client.EVM.SimulateBatch(ctx, &SimulateBatchRequest{...})

// Batch sign (simulate + sign atomically)
signResult, err := client.EVM.Sign.ExecuteBatch(ctx, &BatchSignRequest{...})
```

#### JavaScript (`remote-signer-client` npm)

```javascript
// Single simulation
const result = await client.evm.simulate({chainId: "1", from: "0x...", to: "0x...", data: "0x..."});

// Batch simulation
const batch = await client.evm.simulateBatch({chainId: "1", from: "0x...", transactions: [...]});

// Batch sign
const signed = await client.evm.sign.executeBatch({requests: [...]});
```

---

## Architecture

### Components

```
┌──────────────────────────────────────────────────────────────────────┐
│                  TransactionSimulator (infrastructure)                │
│                                                                      │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────┐ │
│  │ Backend        │  │ EventLogParser │  │ BalanceChangeCalc      │ │
│  │ (eth_          │  │ (ERC20/721/    │  │ (net per token         │ │
│  │  simulateV1    │  │  1155/WETH/    │  │  per signer, supports  │ │
│  │  via gateway)  │  │  native/       │  │  single + batch)       │ │
│  │                │  │  approval)     │  │                        │ │
│  └────────────────┘  └────────────────┘  └────────────────────────┘ │
└──────┬──────────────────────────────────────────┬───────────────────┘
       │                                          │
┌──────▼────────────────────┐        ┌────────────▼──────────────────┐
│  Public API                │        │  Rule Engine                   │
│                            │        │                                │
│  POST /evm/simulate        │        │  1. User rules (fast path)     │
│  POST /evm/simulate/batch  │        │  2. SimulationBudgetRule       │
│  POST /evm/sign/batch      │        │     (built-in fallback)        │
│                            │        │  3. Budget engine               │
│  Consumers:                │        │                                │
│  - Agent preview           │        │  Single sign: batch window     │
│  - UI display              │        │  accumulates requests (1s),    │
│  - Monitoring              │        │  simulates together             │
└────────────────────────────┘        └─────────────────────────────────┘
```

### Data Flow: Single Sign Request (with batch accumulation)

```
Sign request arrives (sign_type: transaction)
  │
  ├── User rules evaluate (fast path)
  │   ├── Matched whitelist → validateBudget → allow/deny (existing flow, no simulation)
  │   ├── Matched blocklist → deny
  │   └── No match → enqueue for simulation
  │
  ├── Batch accumulation window (configurable, default 1s)
  │   └── Collect all unmatched tx requests for same chain_id
  │
  ├── Batch simulation via eth_simulateV1 (sequential txs on same base state):
  │   └── Parse results → balance changes per tx + net totals
  │
  ├── Per-request evaluation:
  │   ├── Budget check against net balance changes (ALWAYS runs first)
  │   │   └── Approve txs have no outflow → budget passes
  │   │   └── Swap txs → budget deducted for outflows
  │   ├── Has approval event (HasApproval)? → require manual approval
  │   └── No approval event + budget passed → auto-allow
  │
  └── Return result to each waiting request
```

### Data Flow: Batch Sign Request (explicit)

```
POST /api/v1/evm/sign/batch
  │
  ├── User rules evaluate each tx (fast path)
  │   └── All must pass (any blocklist hit → reject entire batch)
  │
  ├── Simulate entire batch via eth_simulateV1 (sequential execution)
  │   └── Compute per-tx + net balance changes
  │
  ├── Budget check against NET balance changes (not per-tx, ALWAYS runs first)
  │   └── Batch is atomic: all pass or all fail
  │
  ├── Has any approval event? → require manual approval for batch
  │   └── Budget already passed; approval is an additional gate
  │
  └── Sign all txs → return batch result
```

---

## Component Design

### 1. RPCSimulator (`Simulator`)

Implements `internal/simulation.Simulator`. For each request it calls **`eth_simulateV1`** on the RPC gateway URL for the target `chain_id`, then parses receipts/logs via `EventParser`. No local node is started.

#### Config (relevant fields)

```yaml
chains:
  evm:
    rpc_gateway:
      base_url: "https://your-gateway.example.com/chain/evm"
      api_key: "${EVM_RPC_GATEWAY_API_KEY:-}"
    simulation:
      enabled: true
      timeout: "60s"
      batch_window: "1s"
      batch_max_size: 20
```

#### Files

| File | Description |
|------|-------------|
| `internal/simulation/rpc_simulator.go` | `eth_simulateV1` client + `Simulator` implementation |
| `internal/simulation/simulator.go` | `Simulator` interface |
| `internal/simulation/event_parser.go` | Log → balance change / approval detection |

---

### 2. TransactionSimulator

Simulates single or batch transactions via the gateway and returns parsed results.

#### Simulation Method

Uses **`eth_simulateV1`** (stateless on the signer): the gateway returns execution results and logs; the signer does not run a local EVM.

```go
type SimulationRequest struct {
    ChainID      string
    From         string
    To           string
    Value        string // hex
    Data         string // hex calldata
    Gas          string // hex, optional
}

type BatchSimulationRequest struct {
    ChainID      string
    From         string
    Transactions []TxParams  // ordered
}

type SimulationResult struct {
    Success        bool
    GasUsed        uint64
    BalanceChanges []BalanceChange
    Events         []SimEvent
    HasApproval    bool
    RevertReason   string
}

type BatchSimulationResult struct {
    Results           []SimulationResult  // per-tx results (ordered)
    NetBalanceChanges []BalanceChange     // aggregate across all txs
}

type BalanceChange struct {
    Token     string   // token contract address, or "native" for ETH
    Standard  string   // "erc20", "erc721", "erc1155", "native", "weth"
    Amount    *big.Int // positive = inflow, negative = outflow
    Direction string   // "inflow" or "outflow"
    TokenID   *big.Int // non-nil for ERC721/ERC1155
}

type SimEvent struct {
    Address  string
    Event    string            // "Transfer", "Approval", "Deposit", etc.
    Standard string            // "erc20", "erc721", "erc1155", "weth"
    Args     map[string]string
}
```

#### Event Log Parsing

The simulator parses ALL standard token events from transaction receipts:

##### ERC20: Transfer

```
Topic0: 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
Topics: [topic0, from (indexed), to (indexed)]
Data:   [value (uint256)]

Balance change:
  from → -value (outflow)
  to   → +value (inflow)
```

##### ERC721: Transfer

```
Topic0: 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef  (SAME as ERC20!)
Topics: [topic0, from (indexed), to (indexed), tokenId (indexed)]
Data:   [] (empty — tokenId is in topic3, not data)

Distinction: 4 topics = ERC721, 3 topics + 32-byte data = ERC20.

Balance change:
  from → -1 NFT (tokenId)
  to   → +1 NFT (tokenId)
```

##### ERC1155: TransferSingle

```
Topic0: 0xc3d58168c5ae7397731d063d5bbf3d657706970af1fbf4d87d8d6f7c7cc0a0fa
Topics: [topic0, operator (indexed), from (indexed), to (indexed)]
Data:   [id (uint256), value (uint256)]

Balance change:
  from → -value of token id
  to   → +value of token id
```

##### ERC1155: TransferBatch

```
Topic0: 0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d9738d51b3ff80634
Topics: [topic0, operator (indexed), from (indexed), to (indexed)]
Data:   [ids (uint256[]), values (uint256[])]

Balance change: for each (id, value) pair:
  from → -value
  to   → +value
```

##### WETH: Deposit (ETH → WETH)

```
Topic0: 0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c
Topics: [topic0, dst (indexed)]
Data:   [wad (uint256)]

Budget: neutral (ETH → WETH, same value)
```

##### WETH: Withdrawal (WETH → ETH)

```
Topic0: 0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65
Topics: [topic0, src (indexed)]
Data:   [wad (uint256)]

Budget: neutral (WETH → ETH, same value)
```

##### Approval Events (detection only, not balance changes)

```
ERC20/ERC721 Approval:
  Topic0: 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925

ERC721 ApprovalForAll:
  Topic0: 0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31

NOT balance changes. Set HasApproval = true → require manual approval.
```

##### Native ETH transfer

```
Captured from tx.value (not an event):
  from → -tx.value (outflow)
  to   → +tx.value (inflow)
```

#### Net Balance Calculation

```
Per token, per signer:
  netChange = sum(inflows) - sum(outflows)

  netChange < 0 → outflow (budget deduction)
  netChange > 0 → inflow (no budget impact)
  netChange = 0 → neutral (e.g., WETH wrap/unwrap)

For batch: net across ALL txs in the batch.
Example (approve + swap):
  tx1 (approve):  no Transfer events → no balance change
  tx2 (swap):     USDC Transfer out, ETH received
  Net: USDC = -2300 (outflow), ETH = +0.98 (inflow)
  Budget: deduct 2300 USDC only
```

#### Approval Detection

Detection is based on **simulation events + on-chain allowance comparison** (not calldata parsing):

##### ERC20 Approval: Allowance Increase Detection

ERC20 `transferFrom()` emits an `Approval` event with the REMAINING allowance (not zero). When a signer has a large allowance (e.g. max uint256 for Permit2), every `transferFrom` emits `Approval(owner, spender, remainingAllowance)` where remaining ≈ max — this is NOT a new approval grant but a side effect.

**Solution**: Compare event value with current on-chain allowance:

```
For each ERC20 Approval event where owner = managed signer:
  1. Query on-chain: currentAllowance = allowance(owner, spender)
  2. If event.value > currentAllowance → allowance INCREASED → real approval → manual approval
  3. If event.value ≤ currentAllowance → transferFrom consumed some → side effect → safe, skip
```

This works because:
- `approve(spender, amount)` sets new allowance → if amount > current, it increased
- `transferFrom` decreases allowance → event.value < current → skipped
- Requires 1 RPC call (`eth_call` for `allowance()`) per Approval event (rare in normal swaps)

##### ApprovalForAll (ERC721/ERC1155)

No side-effect issue — `transferFrom` does not emit `ApprovalForAll`. Detected directly.

##### Filtering rules

- **Managed signer filter**: only approvals where the `owner` (topic[1]) is one of our managed signer addresses trigger manual approval. Internal contract-to-contract approvals (e.g. DEX router internals) are ignored.
- **Allowance increase filter** (ERC20 only): queries on-chain allowance to distinguish real approvals from `transferFrom` side effects.
- **Fallback**: if allowance query fails, non-zero Approval events are treated as suspicious (fail-closed).

If detected → route to manual approval (signer owner must approve).

> **Note**: Top-level calldata selector checking was considered but is **redundant** — simulation catches the effects regardless of how they're triggered. On-chain allowance comparison is the authoritative method for ERC20.

#### Files

| File | Description |
|------|-------------|
| `internal/simulation/simulator.go` | TransactionSimulator (single + batch) |
| `internal/simulation/event_parser.go` | Event log parsing for all token standards |
| `internal/simulation/balance_calc.go` | Net balance change calculation |
| `internal/simulation/simulator_test.go` | Unit tests |
| `internal/simulation/event_parser_test.go` | Event parsing tests |
| `internal/api/handler/evm/simulate.go` | POST /evm/simulate + /evm/simulate/batch |
| `internal/api/handler/evm/sign_batch.go` | POST /evm/sign/batch |
| `pkg/client/evm/simulate.go` | Go client SDK |
| `pkg/client/evm/simulate_types.go` | Request/response types |
| `pkg/client/evm/sign_batch.go` | Go client SDK batch sign |

---

### 3. SimulationBudgetRule

Built-in fallback rule that runs AFTER all user-defined rules. For single sign requests, accumulates a batch window before simulating.

#### Evaluation Order

```
Rule engine evaluation:
  1. Blocklist rules (all) → if any blocks, deny
  2. Whitelist rules (user-defined) → if any allows, use its validateBudget
  3. SimulationBudgetRule (built-in, lowest priority)
     → Only if no whitelist rule matched
     → Only for sign_type: transaction
     → Enqueue into batch window (1s / max 20 txs)
     → On batch trigger:
       → Simulate batch via eth_simulateV1
       → Per-tx: approval? → manual approval
       → Per-tx: budget check against net balance changes
       → Return allow/deny to each waiting request
```

#### Batch Window

> **TODO**: Batch window accumulator is NOT YET IMPLEMENTED. Currently each single sign request is simulated independently. The design below is the target state for a future iteration.

Single sign requests that fall through to simulation are accumulated:

```
Request arrives → enqueue with response channel
  → Timer starts (1s) or batch full (20 txs)
  → Batch fires:
    → Group by chain_id
    → Per chain: eth_simulateV1 batch → parse
    → Distribute results to waiting response channels
```

This handles both:
- **Single request**: waits at most 1s, then simulated alone (batch of 1)
- **Burst of requests**: naturally batched, state dependencies resolved

#### Budget Integration

For single sign: budget deducted per-tx from simulation balance changes.

For batch sign (`/evm/sign/batch`): budget deducted from **net** balance changes across the entire batch. This prevents double-counting (e.g., approve amount not counted separately from swap amount).

#### Manual Approval for Approvals

When `HasApproval = true` (from calldata OR simulation events), the rule returns `pending_approval`. Operator must manually approve via existing approval guard.

For batch sign: if ANY tx in the batch has approval, the entire batch requires manual approval.

#### Files

| File | Description |
|------|-------------|
| `internal/chain/evm/simulation_rule.go` | SimulationBudgetRule + batch window |
| `internal/chain/evm/simulation_rule_test.go` | Tests |

---

## Config

```yaml
simulation:
  enabled: true                          # enable/disable simulation engine
  batch_window: "1s"                     # accumulation window for single sign fallback
  batch_max_size: 20                     # max txs per batch
  timeout: "60s"                         # per-simulation timeout (includes remote RPC state fetch)
  require_approval_for_approvals: true   # force manual approval for approve txs
```

Simulation always uses **`eth_simulateV1`** through `chains.evm.rpc_gateway`. Ensure the gateway supports it for your chains.

---

## Security Considerations

### Threat: Simulation divergence from mainnet

**Risk**: Gateway `eth_simulateV1` may use a block head slightly behind the tip.

**Mitigation**: Budget is a spending limit, not exact on-chain accounting. Treat simulation as best-effort preview.

### Threat: Compromised RPC / gateway

**Risk**: Fake simulation results from a malicious or buggy gateway.

**Mitigation**: Run a trusted RPC gateway; monitor for anomalies; manual approval remains the backstop for high-risk patterns (e.g. approvals).

### Threat: Approve bypass via nested calls

**Risk**: Contract calls `approve` internally, bypassing top-level calldata detection.

**Mitigation**: Event parser scans ALL logs from simulation receipt, not just top-level. Any `Approval`/`ApprovalForAll` event → manual approval.

### Threat: Gas griefing via simulation

**Risk**: Tx takes long to simulate, DoS-ing signing service.

**Mitigation**: 10s timeout per simulation. Batch window limits max txs. If timeout, deny with "simulation timeout".

### Threat: Batch ordering manipulation

**Risk**: Attacker reorders txs in batch to bypass budget.

**Mitigation**: Batch sign preserves request order. Budget computed on net across entire batch. Reordering doesn't change net balance.

---

## Implementation Phases

### Phase 1: RPCSimulator + TransactionSimulator + Public API
- `eth_simulateV1` integration via RPC gateway
- Single + batch simulation
- Event log parsing for ERC20/ERC721/ERC1155/WETH/native/approval
- Net balance change calculation (single + batch)
- `POST /api/v1/evm/simulate` endpoint
- `POST /api/v1/evm/simulate/batch` endpoint
- Go client SDK
- JS client SDK (`remote-signer-client`)
- Unit tests

### Phase 2: Batch Sign + SimulationBudgetRule
- `POST /api/v1/evm/sign/batch` endpoint
- Batch window accumulator for single sign fallback
- Built-in fallback rule in rule engine
- Approval detection → manual approval
- Budget entry generation from simulation results
- Integration with existing budget engine
- E2E tests

### Phase 3: Operational
- Config schema + config.example.yaml
- Health endpoint: `GET /api/v1/evm/simulate/status`
- Metrics: simulation latency, batch size
- CLI: `remote-signer-cli evm simulate <tx-params>`
- Documentation

---

## Agent Preset Changes (TODO)

### Remove agent-tx whitelist rule
The `agent-tx` rule ("allow any transaction") bypasses simulation entirely — all
transactions are matched by the whitelist and budget is tracked via calldata parsing
only. For unknown calldata (DEX swaps, aggregator routes), budget falls back to
`tx_count` which does not track actual token spending.

**Fix**: Remove `agent-tx` from the agent template. All transaction signing will
fall through to SimulationBudgetRule, which simulates via eth_simulateV1 and tracks
real token outflows via Transfer events.

After removal, agent preset keeps:
- `agent-sign` (whitelist): personal_sign + typed_data
- `agent-safety` (blocklist): dangerous selectors

### Typed data: restrict verifyingContract
The `agent-sign` rule currently allows signing any typed data. This is dangerous —
an agent could sign a Permit for an arbitrary contract/spender, equivalent to an
unlimited approve.

**Fix**: Add a `allowed_verifying_contracts` template variable to `agent-sign`.
Only typed data with `domain.verifyingContract` in the whitelist is allowed.
Unknown contracts fall through to manual approval.

---

## Dependencies

- **`rpc_gateway`**: configured with RPC URLs for target chains (must support `eth_simulateV1` for simulation)
- Manual approval guard enabled (for approve tx handling)
