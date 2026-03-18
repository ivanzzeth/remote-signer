# Transaction Simulation Engine

## Status: Design

## Problem

The current budget engine tracks token spending by parsing known calldata patterns (ERC20 transfer, approve, etc.). For complex DeFi interactions — DEX swaps, aggregator routes, batch operations — the budget engine cannot decode arbitrary router calldata and falls back to `tx_count`, leaving actual token spending untracked.

Example: An agent swaps 2300 USDC → ETH via OKX DEX router. The budget engine sees an unknown selector (`0xf2c42696`) on an unknown contract, counts it as 1 `tx_count`, and the 2300 USDC expenditure is invisible.

## Solution

Add a transaction simulation layer to remote-signer using Foundry's `anvil` as a persistent per-chain fork. The simulation engine is a **general-purpose infrastructure** that:

1. Provides public API endpoints for single and batch simulation
2. Parses standard token events (ERC20/ERC721/ERC1155/WETH/native) and computes balance changes
3. Supports batch sign requests for atomic multi-tx workflows (approve + swap)
4. Is consumed internally by the budget engine as a fallback rule

The simulation engine is independent of budget logic — it returns structured results that any consumer (budget, UI, monitoring) can use.

```
                    ┌────────────────────────────────────┐
                    │   TransactionSimulator              │
                    │   (AnvilForkManager + EventParser)  │
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

Simulate multiple transactions in sequence on the same fork state. Each tx sees the state changes from previous txs.

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
│  │ AnvilForkMgr   │  │ EventLogParser │  │ BalanceChangeCalc      │ │
│  │ (per-chain     │  │ (ERC20/721/    │  │ (net per token         │ │
│  │  anvil fork,   │  │  1155/WETH/    │  │  per signer, supports  │ │
│  │  snapshot/     │  │  native/       │  │  single + batch)       │ │
│  │  revert)       │  │  approval)     │  │                        │ │
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
  ├── Batch simulation on anvil fork:
  │   ├── evm_snapshot → save fork state
  │   ├── For each tx in batch (arrival order):
  │   │   ├── eth_sendTransaction (local execution on fork)
  │   │   └── eth_getTransactionReceipt → logs + gas
  │   ├── evm_revert → restore fork state (no permanent change)
  │   └── Parse all receipts → balance changes per tx + net totals
  │
  ├── Per-request evaluation:
  │   ├── Has approval event? → require manual approval
  │   └── Budget check against net balance changes → allow/deny
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
  ├── Simulate entire batch on anvil fork:
  │   ├── evm_snapshot
  │   ├── Execute all txs in sequence
  │   ├── evm_revert
  │   └── Compute per-tx + net balance changes
  │
  ├── Budget check against NET balance changes (not per-tx)
  │   └── Batch is atomic: all pass or all fail
  │
  ├── Has any approval event? → require manual approval for batch
  │
  └── Sign all txs → return batch result
```

---

## Component Design

### 1. AnvilForkManager

Manages one persistent `anvil` process per chain. Uses `evm_snapshot` / `evm_revert` for atomic simulations (no cache invalidation).

#### Lifecycle

```
Server startup
  → For each chain_id in startup_chains (or lazy on first request):
    → Start: anvil --fork-url <rpc_gateway>/<chain_id> --port <auto> --no-mining
    → Health check: eth_blockNumber
    → Ready

Periodic sync (every sync_interval):
    → anvil_reset (re-fork from latest block)
    → Only happens when no simulation is in progress (mutex)

Post-broadcast sync:
    → Mark chain as "dirty"
    → Next simulation request triggers anvil_reset before snapshot (lazy)
    → Consecutive broadcasts only trigger one reset (natural debounce)

Per-simulation (atomic, no state leak):
    → evm_snapshot → ID
    → Execute tx(s) via eth_sendTransaction
    → Collect receipts
    → evm_revert(ID) → state restored
    → Simulation never pollutes the fork state

Server shutdown:
    → SIGTERM all anvil processes → graceful exit

Crash recovery:
    → Health check fails → restart anvil
    → Max 3 retries → mark chain simulation-unavailable
```

#### Why snapshot/revert instead of reset

| Approach | Cache behavior | Latency |
|----------|---------------|---------|
| `anvil_reset` per simulation | Clears all cached state, next sim is cold | 2-5s (cold cache) |
| `evm_snapshot` + `evm_revert` | Cache preserved, only simulation changes rolled back | < 500ms (warm cache) |

`anvil_reset` is reserved for periodic sync (every 60s) or dirty-flag sync — infrequent enough that cold cache is acceptable.

#### Config

```yaml
simulation:
  enabled: true
  sync_interval: "60s"          # periodic fork reset interval
  batch_window: "1s"            # accumulation window for single sign requests
  batch_max_size: 20            # max txs per batch
  startup_chains: []            # pre-warm chain IDs (empty = lazy start)
  anvil_path: "anvil"           # path to anvil binary
  timeout: "10s"                # per-simulation timeout
  max_chains: 10                # max concurrent anvil forks
  require_approval_for_approvals: true  # force manual approval for approve txs
```

#### Interface

```go
type AnvilForkManager interface {
    // GetForkURL returns the local anvil RPC URL for a chain.
    // Starts anvil lazily if not running.
    GetForkURL(ctx context.Context, chainID string) (string, error)

    // Snapshot creates a state snapshot, returns snapshot ID.
    Snapshot(ctx context.Context, chainID string) (string, error)

    // Revert rolls back to a snapshot. Cache is preserved.
    Revert(ctx context.Context, chainID string, snapshotID string) error

    // SyncIfDirty resets the fork if the chain was marked dirty.
    SyncIfDirty(ctx context.Context, chainID string) error

    // MarkDirty marks a chain for lazy sync (call after tx broadcast).
    MarkDirty(chainID string)

    // Close shuts down all anvil processes.
    Close() error
}
```

#### Files

| File | Description |
|------|-------------|
| `internal/simulation/anvil_manager.go` | AnvilForkManager implementation |
| `internal/simulation/anvil_manager_test.go` | Unit tests |

---

### 2. TransactionSimulator

Simulates single or batch transactions on the fork and returns parsed results.

#### Simulation Method

Uses `evm_snapshot` → `eth_sendTransaction` (local) → `eth_getTransactionReceipt` → `evm_revert`. No `debug_traceCall` needed — anvil executes the tx locally and returns a full receipt with logs.

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

Top-level calldata selectors:
- `approve(address,uint256)` — `0x095ea7b3`
- `setApprovalForAll(address,bool)` — `0xa22cb465`
- `increaseAllowance(address,uint256)` — `0x39509351`

PLUS: any `Approval` / `ApprovalForAll` event in simulation logs (catches nested approvals).

If detected → `HasApproval = true` → route to manual approval.

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
       → Simulate batch on anvil fork
       → Per-tx: approval? → manual approval
       → Per-tx: budget check against net balance changes
       → Return allow/deny to each waiting request
```

#### Batch Window

Single sign requests that fall through to simulation are accumulated:

```
Request arrives → enqueue with response channel
  → Timer starts (1s) or batch full (20 txs)
  → Batch fires:
    → Group by chain_id
    → Per chain: snapshot → execute all → revert → parse
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
  sync_interval: "60s"                   # periodic anvil_reset interval
  batch_window: "1s"                     # accumulation window for single sign fallback
  batch_max_size: 20                     # max txs per batch
  timeout: "10s"                         # per-simulation timeout
  anvil_path: "anvil"                    # path to anvil binary
  max_chains: 10                         # max concurrent anvil forks
  startup_chains: []                     # pre-warm chains (e.g., ["1", "137"])
  require_approval_for_approvals: true   # force manual approval for approve txs
```

---

## Security Considerations

### Threat: Simulation divergence from mainnet

**Risk**: Anvil fork state may be stale (up to 60s behind).

**Mitigation**: 60s sync interval + dirty-flag lazy sync after broadcast. Budget is a spending limit, not exact accounting. snapshot/revert ensures simulations don't pollute each other.

### Threat: Anvil process compromise

**Risk**: Fake simulation results from compromised anvil.

**Mitigation**: Anvil runs on localhost only. Managed by remote-signer with health checks. No external exposure.

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

### Phase 1: AnvilForkManager + TransactionSimulator + Public API
- Anvil process lifecycle (start/stop/sync/health/snapshot/revert)
- Single + batch simulation via anvil RPC
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
- Metrics: simulation latency, batch size, fork sync count
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
fall through to SimulationBudgetRule, which simulates on anvil fork and tracks
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

- Foundry (`anvil`) installed on the server
- `rpc_gateway` configured with RPC URLs for target chains
- Manual approval guard enabled (for approve tx handling)
