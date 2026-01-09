# Remote Signer API Documentation

## Base URL

```
http://localhost:8080/api/v1
```

## Authentication

All endpoints (except `/health`) require Ed25519 signature authentication.

### Required Headers

| Header | Description |
|--------|-------------|
| `X-API-Key-ID` | Your API key identifier |
| `X-Timestamp` | Unix timestamp in milliseconds |
| `X-Signature` | Base64-encoded Ed25519 signature |

### Signature Format

The signature is computed over the following message:

```
{timestamp}|{method}|{path}|{sha256(body)}
```

Example in Go:

```go
import (
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "time"
)

func signRequest(privateKey ed25519.PrivateKey, method, path string, body []byte) (int64, string) {
    timestamp := time.Now().UnixMilli()
    bodyHash := sha256.Sum256(body)
    message := fmt.Sprintf("%d|%s|%s|%x", timestamp, method, path, bodyHash)
    signature := ed25519.Sign(privateKey, []byte(message))
    return timestamp, base64.StdEncoding.EncodeToString(signature)
}
```

### Generating Ed25519 Key Pair

Use OpenSSL to generate an Ed25519 key pair:

```bash
# Generate private key
openssl genpkey -algorithm ed25519 -out private_key.pem

# Extract public key
openssl pkey -in private_key.pem -pubout -out public_key.pem

# Get private key in hex format (for configuration)
echo "Private Key (Hex):"
openssl pkey -in private_key.pem -text | grep 'priv:' -A 3 | tail -n +2 | tr -d ':\n ' && echo

# Get public key in hex format (for API key registration)
echo "Public Key (Hex):"
openssl pkey -pubin -in public_key.pem -text | grep 'pub:' -A 3 | tail -n +2 | tr -d ':\n ' && echo
```

**Example Output:**

```
Private Key (Hex):
a1b2c3d4e5f6...  (32 bytes)

Public Key (Hex):
1234567890ab...  (32 bytes)
```

The hex-encoded public key is used when creating an API key in the system.

---

## Workflows

### Workflow 1: Auto-Approved Sign Request

When a sign request matches an existing whitelist rule, it's automatically approved and signed.

```
┌──────────┐     ┌──────────────┐     ┌─────────────┐     ┌───────────┐
│  Client  │────▶│ POST /sign   │────▶│ Rule Match  │────▶│ Sign Data │
└──────────┘     └──────────────┘     └─────────────┘     └───────────┘
                                            │                    │
                                            │                    ▼
                                            │              ┌───────────┐
                                            └─────────────▶│ Completed │
                                                           └───────────┘
```

**Steps:**
1. Client submits sign request via `POST /api/v1/evm/sign`
2. Server validates payload and checks signer availability
3. Request status: `pending` → `authorizing`
4. Rule engine evaluates request against whitelist rules
5. **Rule matches**: Request status: `authorizing` → `signing` → `completed`
6. Client receives signature immediately

**Example:**

```bash
# Request
curl -X POST http://localhost:8080/api/v1/evm/sign \
  -H "X-API-Key-ID: key_123" \
  -H "X-Timestamp: 1705312200000" \
  -H "X-Signature: base64_sig" \
  -H "Content-Type: application/json" \
  -d '{
    "chain_id": "1",
    "signer_address": "0x1234...",
    "sign_type": "transaction",
    "payload": {
      "transaction": {
        "to": "0xwhitelisted_address",
        "value": "1000000000000000000",
        "gas": 21000,
        "gasPrice": "20000000000",
        "txType": "legacy"
      }
    }
  }'

# Response (immediate, rule matched)
{
  "request_id": "req_abc123",
  "status": "completed",
  "signature": "0x...",
  "signed_data": "0xf86c..."
}
```

---

### Workflow 2: Manual Approval Required

When no rule matches, the request requires manual approval via notification.

```
┌──────────┐     ┌──────────────┐     ┌─────────────┐     ┌────────────┐
│  Client  │────▶│ POST /sign   │────▶│ No Rule     │────▶│ Notify     │
└──────────┘     └──────────────┘     │ Match       │     │ Admin      │
                                      └─────────────┘     └────────────┘
                                                                │
     ┌──────────────────────────────────────────────────────────┘
     │
     ▼
┌──────────┐     ┌──────────────┐     ┌─────────────┐     ┌───────────┐
│  Admin   │────▶│POST /approve │────▶│ Sign Data   │────▶│ Completed │
└──────────┘     └──────────────┘     └─────────────┘     └───────────┘
```

**Steps:**
1. Client submits sign request via `POST /api/v1/evm/sign`
2. Server validates payload and checks signer availability
3. Request status: `pending` → `authorizing`
4. Rule engine evaluates request - **no rule matches**
5. Notification sent to admin (Slack/Pushover)
6. Client receives response with `status: "authorizing"`
7. Admin previews rule via `POST /api/v1/evm/requests/{id}/preview-rule` (optional)
8. Admin approves via `POST /api/v1/evm/requests/{id}/approve`
9. Request status: `authorizing` → `signing` → `completed`
10. Client polls `GET /api/v1/evm/requests/{id}` to get result

**Example:**

```bash
# Step 1: Submit request
curl -X POST http://localhost:8080/api/v1/evm/sign \
  -H "X-API-Key-ID: key_123" \
  -H "X-Timestamp: 1705312200000" \
  -H "X-Signature: base64_sig" \
  -H "Content-Type: application/json" \
  -d '{
    "chain_id": "1",
    "signer_address": "0x1234...",
    "sign_type": "transaction",
    "payload": {
      "transaction": {
        "to": "0xnew_unknown_address",
        "value": "5000000000000000000",
        "gas": 21000,
        "gasPrice": "20000000000",
        "txType": "legacy"
      }
    }
  }'

# Response (pending approval)
{
  "request_id": "req_xyz789",
  "status": "authorizing",
  "message": "pending manual approval"
}

# Step 2: Admin previews what rule would be generated
curl -X POST http://localhost:8080/api/v1/evm/requests/req_xyz789/preview-rule \
  -H "X-API-Key-ID: admin_key" \
  -H "X-Timestamp: 1705312300000" \
  -H "X-Signature: base64_sig" \
  -H "Content-Type: application/json" \
  -d '{
    "rule_type": "evm_address_list",
    "rule_mode": "whitelist",
    "rule_name": "Allow transfers to 0xnew_unknown_address"
  }'

# Response (preview)
{
  "id": "preview_abc123",
  "name": "Allow transfers to 0xnew_unknown_address",
  "type": "evm_address_list",
  "mode": "whitelist",
  "config": {
    "addresses": ["0xnew_unknown_address"]
  }
}

# Step 3: Admin approves with rule generation (after reviewing preview)
curl -X POST http://localhost:8080/api/v1/evm/requests/req_xyz789/approve \
  -H "X-API-Key-ID: admin_key" \
  -H "X-Timestamp: 1705312350000" \
  -H "X-Signature: base64_sig" \
  -H "Content-Type: application/json" \
  -d '{
    "approved": true,
    "rule_type": "evm_address_list",
    "rule_mode": "whitelist",
    "rule_name": "Allow transfers to 0xnew_unknown_address"
  }'

# Response
{
  "request_id": "req_xyz789",
  "status": "completed",
  "signature": "0x...",
  "signed_data": "0xf86c...",
  "generated_rule": {
    "id": "rule_xyz789",
    "name": "Allow transfers to 0xnew_unknown_address",
    "type": "evm_address_list",
    "mode": "whitelist"
  }
}

# Step 4: Client polls for result
curl http://localhost:8080/api/v1/evm/requests/req_xyz789 \
  -H "X-API-Key-ID: key_123" \
  -H "X-Timestamp: 1705312400000" \
  -H "X-Signature: base64_sig"
```

---

### Workflow 3: Request Rejection

Admin can reject a pending request.

```
┌──────────┐     ┌──────────────┐     ┌─────────────┐
│  Admin   │────▶│POST /approve │────▶│  Rejected   │
│          │     │approved:false│     │             │
└──────────┘     └──────────────┘     └─────────────┘
```

**Example:**

```bash
curl -X POST http://localhost:8080/api/v1/evm/requests/req_xyz789/approve \
  -H "X-API-Key-ID: admin_key" \
  -H "X-Timestamp: 1705312300000" \
  -H "X-Signature: base64_sig" \
  -H "Content-Type: application/json" \
  -d '{
    "approved": false
  }'

# Response
{
  "request_id": "req_xyz789",
  "status": "rejected",
  "message": "request rejected"
}
```

---

### Workflow 4: Validation Failure

Request fails validation (invalid payload, signer not found, etc.)

```
┌──────────┐     ┌──────────────┐     ┌─────────────┐
│  Client  │────▶│ POST /sign   │────▶│  Error 400  │
└──────────┘     └──────────────┘     └─────────────┘
```

**Example:**

```bash
# Invalid signer address
curl -X POST http://localhost:8080/api/v1/evm/sign \
  -H "X-API-Key-ID: key_123" \
  -H "X-Timestamp: 1705312200000" \
  -H "X-Signature: base64_sig" \
  -H "Content-Type: application/json" \
  -d '{
    "chain_id": "1",
    "signer_address": "0xunknown_signer",
    "sign_type": "personal",
    "payload": {"message": "test"}
  }'

# Response
{
  "error": "signer_not_found",
  "message": "signer not found: 0xunknown_signer"
}
```

---

### Workflow 5: Request Blocked by Blocklist Rule

When a request violates a blocklist rule, it's immediately rejected without possibility of manual approval.

```
┌──────────┐     ┌──────────────┐     ┌─────────────┐     ┌───────────┐
│  Client  │────▶│ POST /sign   │────▶│ Blocklist   │────▶│ Rejected  │
└──────────┘     └──────────────┘     │ Violation   │     │ (blocked) │
                                      └─────────────┘     └───────────┘
```

**Steps:**
1. Client submits sign request via `POST /api/v1/evm/sign`
2. Server validates payload and checks signer availability
3. Request status: `pending` → `authorizing`
4. Rule engine evaluates request against **blocklist rules FIRST**
5. **Blocklist rule violated**: Request immediately rejected
6. Client receives response with `status: "rejected"` and block reason

**Example:**

```bash
# Request with value exceeding blocklist limit
curl -X POST http://localhost:8080/api/v1/evm/sign \
  -H "X-API-Key-ID: key_123" \
  -H "X-Timestamp: 1705312200000" \
  -H "X-Signature: base64_sig" \
  -H "Content-Type: application/json" \
  -d '{
    "chain_id": "1",
    "signer_address": "0x1234...",
    "sign_type": "transaction",
    "payload": {
      "transaction": {
        "to": "0xsome_address",
        "value": "100000000000000000000",
        "gas": 21000,
        "gasPrice": "20000000000",
        "txType": "legacy"
      }
    }
  }'

# Response (blocked by rule)
{
  "request_id": "req_blocked123",
  "status": "rejected",
  "message": "blocked by rule Max 10 ETH: value 100000000000000000000 exceeds limit 10000000000000000000"
}
```

**Key Difference from Manual Rejection:**
- Blocklist rejection happens automatically and **cannot be manually overridden**
- Manual rejection (Workflow 3) is a deliberate admin decision on pending requests
- Blocklist rules are for enforcing hard security limits

---

## Rules Configuration

Rules use a **two-tier evaluation system**:

1. **Blocklist Rules** (Mandatory): Evaluated FIRST. ANY violation = immediate rejection, no manual approval possible.
2. **Whitelist Rules** (Permissive): Evaluated SECOND. ANY match = auto-approve.
3. **No Match**: If no blocklist violation and no whitelist match → manual approval required.

```
┌─────────────────────────────────────────────────────────────────┐
│                     Sign Request Received                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              Phase 1: Evaluate Blocklist Rules                   │
│              (mode: "blocklist")                                 │
│              ANY violation = BLOCKED immediately                 │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              │ Violated?                     │
              ▼                               ▼
┌─────────────────────┐           ┌─────────────────────┐
│   YES: REJECTED     │           │   NO: Continue      │
│   (no override)     │           │                     │
└─────────────────────┘           └─────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              Phase 2: Evaluate Whitelist Rules                   │
│              (mode: "whitelist")                                 │
│              ANY match = AUTO-APPROVED                           │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              │ Matched?                      │
              ▼                               ▼
┌─────────────────────┐           ┌─────────────────────┐
│   YES: APPROVED     │           │   NO: Manual        │
│   (auto-sign)       │           │   Approval Required │
└─────────────────────┘           └─────────────────────┘
```

### Rule Structure

```json
{
  "id": "rule_abc123",
  "name": "Allow DEX swaps",
  "description": "Auto-approve swaps on Uniswap",
  "type": "evm_contract_method",
  "mode": "whitelist",
  "source": "api",
  "chain_type": "evm",
  "chain_id": "1",
  "api_key_id": "key_123",
  "signer_address": "0x1234...",
  "config": { ... },
  "enabled": true,
  "expires_at": null
}
```

### Rule Mode

| Mode | Behavior | Use Case |
|------|----------|----------|
| `whitelist` | ANY match = auto-approve | Allow specific addresses, methods, small values |
| `blocklist` | ANY violation = immediate block | Enforce hard limits, block suspicious patterns |

### Rule Scoping

Rules can be scoped to specific:
- **Chain Type**: `"chain_type": "evm"` - only applies to EVM chains
- **Chain ID**: `"chain_id": "1"` - only applies to Ethereum mainnet
- **API Key**: `"api_key_id": "key_123"` - only applies to this API key
- **Signer**: `"signer_address": "0x..."` - only applies to this signer

Set to `null` to apply to all.

---

### Rule Type: `evm_address_list`

Control transactions based on recipient address. **Behavior depends on rule mode.**

**Use Cases:**
- **Whitelist mode**: Allow transfers to known hot wallets, verified contracts
- **Blocklist mode**: Block transfers to suspicious/blacklisted addresses

**Config:**

```json
{
  "type": "evm_address_list",
  "mode": "whitelist",
  "config": {
    "addresses": [
      "0x1234567890abcdef1234567890abcdef12345678",
      "0xabcdef1234567890abcdef1234567890abcdef12"
    ]
  }
}
```

**Matching Logic (depends on mode):**

| Mode | Fires When | Result |
|------|------------|--------|
| `whitelist` | `tx.to` IS in list | Auto-approve |
| `blocklist` | `tx.to` IS in list | Immediate block |

- For `transaction` sign type: matches if `tx.to` is in the address list
- Case-insensitive comparison

**Example Scenarios:**

```json
// Scenario 1: WHITELIST - Allow transfers to treasury
{
  "name": "Treasury transfers",
  "type": "evm_address_list",
  "mode": "whitelist",
  "chain_id": "1",
  "config": {
    "addresses": ["0xTreasuryAddress"]
  }
}

// Scenario 2: WHITELIST - Allow interaction with specific DeFi protocols
{
  "name": "Aave interactions",
  "type": "evm_address_list",
  "mode": "whitelist",
  "chain_id": "1",
  "config": {
    "addresses": [
      "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9",  // Aave LendingPool
      "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"   // Aave V3 Pool
    ]
  }
}

// Scenario 3: BLOCKLIST - Block known malicious addresses
{
  "name": "Block suspicious addresses",
  "type": "evm_address_list",
  "mode": "blocklist",
  "chain_id": "1",
  "config": {
    "addresses": [
      "0xMaliciousAddress1",
      "0xMaliciousAddress2"
    ]
  }
}
```

---

### Rule Type: `evm_contract_method`

Allow specific smart contract method calls.

**Use Cases:**
- Allow only ERC20 `transfer()` and `approve()` methods
- Allow specific DEX swap functions
- Restrict to read-only methods

**Config:**

```json
{
  "type": "evm_contract_method",
  "config": {
    "contract": "0xContractAddress",
    "method_sigs": [
      "0xa9059cbb",
      "0x095ea7b3"
    ]
  }
}
```

**Method Signatures (4-byte selectors):**

| Method | Selector | Description |
|--------|----------|-------------|
| `transfer(address,uint256)` | `0xa9059cbb` | ERC20 transfer |
| `approve(address,uint256)` | `0x095ea7b3` | ERC20 approve |
| `transferFrom(address,address,uint256)` | `0x23b872dd` | ERC20 transferFrom |
| `swap(...)` | varies | DEX swap |

**How to get method selector:**

```go
// keccak256("transfer(address,uint256)")[:4]
selector := crypto.Keccak256([]byte("transfer(address,uint256)"))[:4]
// Result: 0xa9059cbb
```

**Matching Logic:**
- Matches if `tx.to` equals `contract` AND first 4 bytes of `tx.data` is in `method_sigs`

**Example Scenarios:**

```json
// Scenario 1: Allow only ERC20 transfers on USDC
{
  "name": "USDC transfers only",
  "type": "evm_contract_method",
  "chain_id": "1",
  "config": {
    "contract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "method_sigs": ["0xa9059cbb"]
  }
}

// Scenario 2: Allow Uniswap V2 swaps
{
  "name": "Uniswap V2 swaps",
  "type": "evm_contract_method",
  "chain_id": "1",
  "config": {
    "contract": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    "method_sigs": [
      "0x38ed1739",  // swapExactTokensForTokens
      "0x8803dbee",  // swapTokensForExactTokens
      "0x7ff36ab5",  // swapExactETHForTokens
      "0x4a25d94a"   // swapTokensForExactETH
    ]
  }
}

// Scenario 3: Allow ERC721 transfers
{
  "name": "NFT transfers",
  "type": "evm_contract_method",
  "chain_id": "1",
  "config": {
    "contract": "0xNFTContractAddress",
    "method_sigs": [
      "0x23b872dd",  // transferFrom
      "0x42842e0e",  // safeTransferFrom(address,address,uint256)
      "0xb88d4fde"   // safeTransferFrom(address,address,uint256,bytes)
    ]
  }
}
```

---

### Rule Type: `evm_value_limit`

Control transactions based on ETH value. **Behavior depends on rule mode.**

**Use Cases:**
- **Whitelist mode**: Allow small transactions without approval
- **Blocklist mode**: Block large transactions (hard limit, no manual override)

**Config:**

```json
{
  "type": "evm_value_limit",
  "mode": "whitelist",
  "config": {
    "max_value": "1000000000000000000"
  }
}
```

**Value Format:**
- Value is in **wei** (smallest ETH unit)
- Use string to avoid precision issues
- `1 ETH = 1000000000000000000 wei (10^18)`

**Common Values:**

| Amount | Wei Value |
|--------|-----------|
| 0.01 ETH | `"10000000000000000"` |
| 0.1 ETH | `"100000000000000000"` |
| 1 ETH | `"1000000000000000000"` |
| 10 ETH | `"10000000000000000000"` |
| 100 ETH | `"100000000000000000000"` |

**Matching Logic (depends on mode):**

| Mode | Fires When | Result |
|------|------------|--------|
| `whitelist` | `tx.value <= max_value` | Auto-approve |
| `blocklist` | `tx.value > max_value` | Immediate block |

**Example Scenarios:**

```json
// Scenario 1: WHITELIST - Allow small transfers (< 0.1 ETH) auto-approve
// Transactions <= 0.1 ETH are auto-approved
// Transactions > 0.1 ETH require manual approval (not blocked!)
{
  "name": "Small transfers auto-approve",
  "type": "evm_value_limit",
  "mode": "whitelist",
  "chain_id": "1",
  "config": {
    "max_value": "100000000000000000"
  }
}

// Scenario 2: BLOCKLIST - Block large transfers (> 10 ETH)
// Transactions > 10 ETH are IMMEDIATELY BLOCKED (no manual override)
// Transactions <= 10 ETH continue to whitelist evaluation
{
  "name": "Max 10 ETH hard limit",
  "type": "evm_value_limit",
  "mode": "blocklist",
  "chain_id": "1",
  "config": {
    "max_value": "10000000000000000000"
  }
}

// Scenario 3: Allow gas-only transactions (value = 0)
{
  "name": "Zero-value transactions",
  "type": "evm_value_limit",
  "mode": "whitelist",
  "chain_id": "1",
  "config": {
    "max_value": "0"
  }
}
```

**Whitelist vs Blocklist Comparison:**

```
                    Whitelist Mode              Blocklist Mode
                    (mode: "whitelist")         (mode: "blocklist")
                    max_value: 0.1 ETH          max_value: 10 ETH

tx.value = 0.05 ETH   ✅ Auto-approve            ✅ Continue (no violation)
tx.value = 0.5 ETH    ❓ Manual approval          ✅ Continue (no violation)
tx.value = 5 ETH      ❓ Manual approval          ✅ Continue (no violation)
tx.value = 50 ETH     ❓ Manual approval          ❌ BLOCKED (no override)
```

---

### Rule Type: `evm_solidity_expression`

Write complex validation logic using Solidity syntax with `require()` statements. This rule type uses Foundry's `forge` tool to execute Solidity code for parameter-level risk control.

**Use Cases:**
- Complex value limits with multiple conditions
- Parameter-level validation (decode and check calldata fields)
- Custom logic combining multiple checks
- Address blocklists with dynamic rules

**Requirements:**
- Foundry must be installed on the server (`forge` in PATH)
- Rules must include at least one test case to verify correctness
- All test cases must pass during rule creation

**Config:**

```json
{
  "type": "evm_solidity_expression",
  "mode": "whitelist",
  "config": {
    "expression": "require(value <= 1 ether, \"exceeds 1 ETH limit\");",
    "description": "Limits transfers to maximum 1 ETH",
    "test_cases": [
      {
        "name": "should pass for 0.5 ETH",
        "input": {
          "value": "500000000000000000",
          "to": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
        },
        "expect_pass": true
      },
      {
        "name": "should reject for 2 ETH",
        "input": {
          "value": "2000000000000000000",
          "to": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
        },
        "expect_pass": false,
        "expect_reason": "exceeds 1 ETH limit"
      }
    ]
  }
}
```

**Available Variables in Expression:**

| Variable | Type | Description |
|----------|------|-------------|
| `to` | `address` | Transaction recipient address |
| `value` | `uint256` | Transaction value in wei |
| `selector` | `bytes4` | Method selector (first 4 bytes of calldata) |
| `data` | `bytes` | Full transaction calldata |
| `chainId` | `uint256` | Chain ID |
| `signer` | `address` | Signing address |

**Test Case Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Descriptive name for the test case |
| `input.to` | string | No | Recipient address (0x-prefixed, checksummed) |
| `input.value` | string | No | Value in wei (decimal string) |
| `input.selector` | string | No | Method selector (0x-prefixed, 4 bytes) |
| `input.data` | string | No | Full calldata (0x-prefixed hex) |
| `input.chain_id` | string | No | Chain ID (decimal string, default: "1") |
| `input.signer` | string | No | Signer address (0x-prefixed, checksummed) |
| `expect_pass` | bool | Yes | Whether the rule should pass (true) or revert (false) |
| `expect_reason` | string | No | Expected revert reason (only when `expect_pass: false`) |

**Important Notes:**
- Addresses must be checksummed (e.g., `0x5B38Da6a701c568545dCfcB03FcB875f56beddC4`)
- Use Solidity units like `1 ether`, `1 gwei` in expressions
- Test cases are executed during rule creation - all must pass

**Example Scenarios:**

```json
// Scenario 1: Simple value limit
{
  "name": "Max 1 ETH transfer",
  "type": "evm_solidity_expression",
  "mode": "whitelist",
  "config": {
    "expression": "require(value <= 1 ether, \"exceeds limit\");",
    "description": "Auto-approve transfers up to 1 ETH",
    "test_cases": [
      {"name": "pass 0.5 ETH", "input": {"value": "500000000000000000"}, "expect_pass": true},
      {"name": "reject 2 ETH", "input": {"value": "2000000000000000000"}, "expect_pass": false, "expect_reason": "exceeds limit"}
    ]
  }
}

// Scenario 2: Address blocklist
{
  "name": "Block suspicious addresses",
  "type": "evm_solidity_expression",
  "mode": "blocklist",
  "config": {
    "expression": "require(to != address(0), \"cannot send to zero address\"); require(to != 0x000000000000000000000000000000000000dEaD, \"blocked: dead address\");",
    "description": "Block transfers to known bad addresses",
    "test_cases": [
      {"name": "pass normal address", "input": {"to": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"}, "expect_pass": true},
      {"name": "block zero address", "input": {"to": "0x0000000000000000000000000000000000000000"}, "expect_pass": false, "expect_reason": "cannot send to zero address"}
    ]
  }
}

// Scenario 3: Method selector restriction
{
  "name": "Only ERC20 transfer",
  "type": "evm_solidity_expression",
  "mode": "whitelist",
  "config": {
    "expression": "require(selector == bytes4(0xa9059cbb), \"only transfer allowed\");",
    "description": "Only allow ERC20 transfer method",
    "test_cases": [
      {"name": "pass transfer", "input": {"selector": "0xa9059cbb"}, "expect_pass": true},
      {"name": "reject approve", "input": {"selector": "0x095ea7b3"}, "expect_pass": false, "expect_reason": "only transfer allowed"}
    ]
  }
}

// Scenario 4: Complex - decode and validate parameters
{
  "name": "USDC transfer limit",
  "type": "evm_solidity_expression",
  "mode": "whitelist",
  "config": {
    "expression": "require(selector == bytes4(0xa9059cbb), \"must be transfer\"); (address recipient, uint256 amount) = abi.decode(data[4:], (address, uint256)); require(amount <= 10000 * 1e6, \"exceeds 10k USDC limit\");",
    "description": "Limit USDC transfers to 10,000 USDC",
    "abi_signature": "transfer(address,uint256)",
    "test_cases": [
      {
        "name": "pass 1000 USDC",
        "input": {
          "selector": "0xa9059cbb",
          "data": "0xa9059cbb0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc4000000000000000000000000000000000000000000000000000000003b9aca00"
        },
        "expect_pass": true
      },
      {
        "name": "reject non-transfer",
        "input": {"selector": "0x095ea7b3"},
        "expect_pass": false,
        "expect_reason": "must be transfer"
      }
    ]
  }
}
```

**API Response for Validation Errors:**

When creating a rule with invalid Solidity syntax:

```json
{
  "error": "rule validation failed",
  "validation": {
    "valid": false,
    "syntax_error": {
      "message": "Error: Expected ';' but got '}'",
      "line": 15,
      "column": 10,
      "severity": "error"
    }
  }
}
```

When test cases fail:

```json
{
  "error": "rule validation failed",
  "validation": {
    "valid": false,
    "test_case_results": [
      {
        "name": "should pass for 0.5 ETH",
        "passed": true,
        "expected_pass": true,
        "actual_pass": true
      },
      {
        "name": "should reject for 2 ETH",
        "passed": false,
        "expected_pass": false,
        "actual_pass": true,
        "error": "expected revert but passed"
      }
    ],
    "failed_test_cases": 1
  }
}
```

---

### Combining Rules

Rules are evaluated in two phases:
1. **Phase 1 (Blocklist)**: ALL blocklist rules are checked first. ANY violation = immediate block.
2. **Phase 2 (Whitelist)**: If no blocklist violation, whitelist rules are checked. ANY match = auto-approve.

**Example: Production Setup with Two-Tier Rules**

```json
// BLOCKLIST RULES (checked FIRST - any violation = blocked)

// Rule 1: Hard limit - block any transaction > 100 ETH
{
  "name": "Max 100 ETH hard limit",
  "type": "evm_value_limit",
  "mode": "blocklist",
  "chain_id": "1",
  "config": {"max_value": "100000000000000000000"}
}

// WHITELIST RULES (checked SECOND - any match = auto-approve)

// Rule 2: Allow all transactions to treasury
{
  "name": "Treasury",
  "type": "evm_address_list",
  "mode": "whitelist",
  "config": {"addresses": ["0xTreasury"]}
}

// Rule 3: Allow USDC transfers to any address
{
  "name": "USDC transfers",
  "type": "evm_contract_method",
  "mode": "whitelist",
  "config": {
    "contract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "method_sigs": ["0xa9059cbb"]
  }
}

// Rule 4: Allow small ETH transfers (< 0.1 ETH)
{
  "name": "Small ETH",
  "type": "evm_value_limit",
  "mode": "whitelist",
  "config": {"max_value": "100000000000000000"}
}
```

**Evaluation Flow:**

```
Request: 0.05 ETH to unknown address
├─ Phase 1: Check blocklist rules
│  └─ Rule 1 (Max 100 ETH): 0.05 <= 100 → NO violation
├─ Phase 2: Check whitelist rules
│  ├─ Rule 2 (Treasury): unknown ≠ treasury → no match
│  ├─ Rule 3 (USDC): not USDC contract → no match
│  └─ Rule 4 (Small ETH): 0.05 <= 0.1 → ✅ MATCH
└─ Result: AUTO-APPROVED by Rule 4

Request: 50 ETH to treasury
├─ Phase 1: Check blocklist rules
│  └─ Rule 1 (Max 100 ETH): 50 <= 100 → NO violation
├─ Phase 2: Check whitelist rules
│  └─ Rule 2 (Treasury): treasury = treasury → ✅ MATCH
└─ Result: AUTO-APPROVED by Rule 2

Request: 150 ETH to treasury
├─ Phase 1: Check blocklist rules
│  └─ Rule 1 (Max 100 ETH): 150 > 100 → ❌ VIOLATION
└─ Result: BLOCKED (even though treasury is whitelisted!)

Request: 5 ETH to unknown address
├─ Phase 1: Check blocklist rules
│  └─ Rule 1 (Max 100 ETH): 5 <= 100 → NO violation
├─ Phase 2: Check whitelist rules
│  ├─ Rule 2 (Treasury): unknown ≠ treasury → no match
│  ├─ Rule 3 (USDC): not USDC contract → no match
│  └─ Rule 4 (Small ETH): 5 > 0.1 → no match
└─ Result: MANUAL APPROVAL REQUIRED
```

**Summary:**
- ❌ 150 ETH to treasury → **BLOCKED** (blocklist violation, no override)
- ✅ 50 ETH to treasury → approved by Rule 2
- ✅ USDC transfer to any address → approved by Rule 3
- ✅ 0.05 ETH transfer to unknown address → approved by Rule 4
- ❓ 5 ETH transfer to unknown address → requires manual approval

---

### Rule Generation on Approval

When approving a request, you can optionally generate a rule to auto-approve similar requests in the future. **You must explicitly specify `rule_type` and `rule_mode`** - the system does not auto-determine these.

**Supported Rule Types for Generation:**

| Rule Type | Description | Required Fields |
|-----------|-------------|-----------------|
| `evm_address_list` | Whitelist/blocklist recipient address | `rule_type`, `rule_mode` |
| `evm_contract_method` | Allow/block specific contract methods | `rule_type`, `rule_mode` |
| `evm_value_limit` | Value-based limit | `rule_type`, `rule_mode`, `max_value` |
| `evm_solidity_expression` | Custom Solidity logic with require() | `rule_type`, `rule_mode`, `expression`, `test_cases` |

**Workflow:**
1. Submit sign request → pending manual approval
2. **Preview rule** via `POST /api/v1/evm/requests/{id}/preview-rule`
3. Review the generated rule configuration
4. **Approve with rule generation** via `POST /api/v1/evm/requests/{id}/approve`

**Before Approval:**
- Request to `0xNewAddress` requires manual approval

**After Approval with rule generation:**
- New rule created based on specified `rule_type` and `rule_mode`
- Future matching requests auto-approved (whitelist) or blocked (blocklist)

---

## Endpoints

### Health Check

Check service health status.

```
GET /health
```

**Response:**

```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```

---

### Sign Request (EVM)

Submit a new signing request.

```
POST /api/v1/evm/sign
```

**Request Body:**

```json
{
  "chain_id": "1",
  "signer_address": "0x1234567890abcdef1234567890abcdef12345678",
  "sign_type": "personal",
  "payload": {
    "message": "Hello, World!"
  }
}
```

**Sign Types and Payloads:**

#### `hash`
Sign a pre-hashed 32-byte value.

```json
{
  "sign_type": "hash",
  "payload": {
    "hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
  }
}
```

#### `raw_message`
Sign raw bytes.

```json
{
  "sign_type": "raw_message",
  "payload": {
    "raw_message": "SGVsbG8gV29ybGQ="
  }
}
```

#### `personal`
Sign a personal message (adds Ethereum prefix).

```json
{
  "sign_type": "personal",
  "payload": {
    "message": "Hello, World!"
  }
}
```

#### `eip191`
Sign an EIP-191 formatted message.

```json
{
  "sign_type": "eip191",
  "payload": {
    "message": "Hello, World!"
  }
}
```

#### `typed_data`
Sign EIP-712 typed data.

```json
{
  "sign_type": "typed_data",
  "payload": {
    "typed_data": {
      "types": {
        "EIP712Domain": [
          {"name": "name", "type": "string"},
          {"name": "version", "type": "string"},
          {"name": "chainId", "type": "uint256"}
        ],
        "Message": [
          {"name": "content", "type": "string"}
        ]
      },
      "primaryType": "Message",
      "domain": {
        "name": "Example",
        "version": "1",
        "chainId": "1"
      },
      "message": {
        "content": "Hello"
      }
    }
  }
}
```

#### `transaction`
Sign an Ethereum transaction.

**Legacy Transaction:**
```json
{
  "sign_type": "transaction",
  "payload": {
    "transaction": {
      "to": "0xrecipient_address",
      "value": "1000000000000000000",
      "data": "0x",
      "nonce": 0,
      "gas": 21000,
      "gasPrice": "20000000000",
      "txType": "legacy"
    }
  }
}
```

**EIP-1559 Transaction:**
```json
{
  "sign_type": "transaction",
  "payload": {
    "transaction": {
      "to": "0xrecipient_address",
      "value": "0",
      "data": "0xa9059cbb000000000000000000000000...",
      "nonce": 5,
      "gas": 100000,
      "gasTipCap": "1000000000",
      "gasFeeCap": "30000000000",
      "txType": "eip1559"
    }
  }
}
```

**Response (Auto-Approved):**

```json
{
  "request_id": "req_abc123",
  "status": "completed",
  "signature": "base64_encoded_signature",
  "signed_data": "base64_encoded_signed_tx"
}
```

**Response (Pending Approval):**

```json
{
  "request_id": "req_abc123",
  "status": "authorizing",
  "message": "pending manual approval"
}
```

---

### List Requests

List signing requests with optional filters.

```
GET /api/v1/evm/requests
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status |
| `signer_address` | string | Filter by signer address |
| `chain_id` | string | Filter by chain ID |
| `limit` | int | Max results (default: 100) |
| `offset` | int | Pagination offset |

**Response:**

```json
{
  "requests": [
    {
      "id": "req_abc123",
      "api_key_id": "key_123",
      "chain_type": "evm",
      "chain_id": "1",
      "signer_address": "0x1234...",
      "sign_type": "personal",
      "status": "completed",
      "created_at": "2024-01-15T10:30:00Z",
      "completed_at": "2024-01-15T10:30:01Z"
    }
  ],
  "total": 1
}
```

---

### Get Request

Get details of a specific signing request.

```
GET /api/v1/evm/requests/{request_id}
```

**Response:**

```json
{
  "id": "req_abc123",
  "api_key_id": "key_123",
  "chain_type": "evm",
  "chain_id": "1",
  "signer_address": "0x1234567890abcdef1234567890abcdef12345678",
  "sign_type": "personal",
  "payload": {"message": "Hello"},
  "status": "completed",
  "rule_matched_id": "rule_xyz",
  "signature": "base64_signature",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:01Z",
  "completed_at": "2024-01-15T10:30:01Z"
}
```

---

### Preview Rule for Request

Preview what rule would be generated for a pending request. Use this to review the rule configuration before approving.

```
POST /api/v1/evm/requests/{request_id}/preview-rule
```

**Request Body:**

```json
{
  "rule_type": "evm_address_list",
  "rule_mode": "whitelist",
  "rule_name": "Allow transfers to 0xabc..."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `rule_type` | string | Yes | Type of rule to generate: `evm_address_list`, `evm_contract_method`, `evm_value_limit` |
| `rule_mode` | string | Yes | Rule mode: `whitelist` or `blocklist` |
| `rule_name` | string | No | Custom name for the rule |
| `max_value` | string | For `evm_value_limit` | Max value in wei (required for value limit rules) |

**Response:**

```json
{
  "id": "preview_abc123",
  "name": "Allow transfers to 0xabc...",
  "type": "evm_address_list",
  "mode": "whitelist",
  "source": "auto_generated",
  "chain_type": "evm",
  "chain_id": "1",
  "api_key_id": "key_123",
  "signer_address": "0x1234...",
  "config": {
    "addresses": ["0xabc..."]
  },
  "enabled": true
}
```

---

### Approve/Reject Request

Manually approve or reject a pending request. Optionally generate a rule on approval.

```
POST /api/v1/evm/requests/{request_id}/approve
```

**Request Body (Simple Approval):**

```json
{
  "approved": true
}
```

**Request Body (Approval with Rule Generation):**

```json
{
  "approved": true,
  "rule_type": "evm_address_list",
  "rule_mode": "whitelist",
  "rule_name": "Allow transfers to 0xabc..."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `approved` | bool | Yes | `true` to approve, `false` to reject |
| `rule_type` | string | No | Type of rule to generate (if generating a rule) |
| `rule_mode` | string | No | Rule mode: `whitelist` or `blocklist` (required if `rule_type` is set) |
| `rule_name` | string | No | Custom name for the generated rule |
| `max_value` | string | No | Max value in wei (required for `evm_value_limit` rule type) |

**Response (Approved without Rule):**

```json
{
  "request_id": "req_abc123",
  "status": "completed",
  "signature": "0x...",
  "signed_data": "0xf86c..."
}
```

**Response (Approved with Rule Generation):**

```json
{
  "request_id": "req_abc123",
  "status": "completed",
  "signature": "0x...",
  "signed_data": "0xf86c...",
  "generated_rule": {
    "id": "rule_xyz789",
    "name": "Allow transfers to 0xabc...",
    "type": "evm_address_list",
    "mode": "whitelist",
    "config": {
      "addresses": ["0xabc..."]
    }
  }
}
```

**Response (Rejected):**

```json
{
  "request_id": "req_abc123",
  "status": "rejected",
  "message": "request rejected"
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "error": "error_code",
  "message": "Human readable error message"
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `unauthorized` | 401 | Invalid or expired API key/signature |
| `not_found` | 404 | Resource not found |
| `invalid_request` | 400 | Malformed request body |
| `signer_not_found` | 400 | Requested signer not available |
| `invalid_payload` | 400 | Invalid signing payload |
| `rate_limited` | 429 | Too many requests |
| `internal_error` | 500 | Server error |

---

## Rate Limiting

Default rate limit: 100 requests per minute per API key.

When rate limited, you'll receive:

```
HTTP 429 Too Many Requests
```

```json
{
  "error": "rate_limited",
  "message": "Rate limit exceeded. Try again later."
}
```
