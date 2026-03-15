# Use Cases

Remote Signer is an open-source, self-hosted signing service focused on **parameter-level intent verification** and **budget control**. It is not a direct replacement for key-management giants like ConsenSys Web3Signer (which dominates staking and node tooling); it is **complementary** and excels in use cases where you need fine-grained policy (whom to pay, which methods, value caps, Solidity expressions) and optional manual approval before a key is used.

---

## Positioning in the ecosystem (Feb 2026)

> *Third-party assessment:* Remote Signer ranks **upper-middle to top tier** among open-source self-hosted signing services. In the niche of **parameter-level intent verification + budget control**, it is **almost in a league of its own**. The open-source self-hosted Web3 signing landscape is clear: ConsenSys Web3Signer largely owns the mainstream (Apache 2.0, staking-node standard); the rest are niche or hardware/TEE variants. This project is **complementary** to Web3Signer and **significantly ahead** on the dimensions that matter for policy-driven, treasury-style signing.

Use Remote Signer when you need:

- **Intent verification**: Allow/block by recipient, contract, method selector, value, or custom Solidity logic.
- **Budget control**: Per-rule value limits (`evm_value_limit`), optional template budgets and alerts.
- **Audit and approval**: Request lifecycle, manual approval workflow, Slack/Pushover notifications.
- **Self-hosted custody**: Your keys, your infra; no dependency on a third-party signer SaaS.

---

## 1. Treasury

**Scenario:** A shared treasury (DAO, company, or multi-sig) pays invoices, grants, and operational expenses. You want only certain recipients and amount caps; anything else should be blocked or go to manual approval.

**How Remote Signer helps:**

- **Recipient whitelist** (`evm_address_list`): Only listed addresses can receive funds; everything else is blocked or pending approval.
- **Value limits** (`evm_value_limit`): e.g. “max 10 ETH per tx” or “max 0.1 ETH for this rule”; larger amounts can use a separate rule or manual approval.
- **Contract/method rules** (`evm_contract_method`, `evm_solidity_expression`): Restrict which protocols or functions the treasury can call (e.g. only `transfer` on a specific token, or only a known payroll contract).
- **Manual approval**: Requests that don’t match any whitelist rule can be routed to human approval with notifications (Slack/Pushover), then approved or rejected via the API.

**Typical setup:** One or more API keys (e.g. per operator or system), rules per payment corridor (recipient + max value), and optional manual approval for one-off or high-value moves.

---

## 2. Bot / automated strategies

**Scenario:** A market maker, arbitrage bot, or DeFi strategy bot needs to sign transactions automatically. You want it to only sign within strict bounds (allowed pairs, max size, specific contract methods) so a bug or compromise doesn’t drain the wallet.

**How Remote Signer helps:**

- **Method and contract restrictions** (`evm_contract_method`, `evm_solidity_expression`): Only allow calls to known contracts and selectors (e.g. swap on specific DEX, no arbitrary `transferFrom`).
- **Value and size caps** (`evm_value_limit`): Cap native value per tx; combine with Solidity rules to cap token amounts or other parameters.
- **Recipient / address rules** (`evm_address_list`): Limit `to` to known routers, pools, or protocol addresses.
- **Per-key rate limits**: Each API key (e.g. one per bot instance) has its own rate limit to avoid runaway traffic.

The bot calls Remote Signer’s sign API; the server evaluates rules and either signs, blocks, or flags for manual approval. Keys stay on your server; the bot only holds API credentials.

---

## 3. DeFi operations

**Scenario:** Swaps, liquidity provision, staking, or other DeFi actions from a hot wallet or operator account. You want to allow only intended protocols and parameter ranges (e.g. max slippage, allowed tokens, max amount).

**How Remote Signer helps:**

- **Solidity expression rules** (`evm_solidity_expression`): Encode complex checks (e.g. “only Uniswap V3 router”, “max slippage”, “only these tokens”). Rules are compiled and run in a sandbox; any failure blocks the sign.
- **Contract/method whitelist** (`evm_contract_method`): Restrict to specific contracts and method selectors so only intended DeFi actions are allowed.
- **Value limits** (`evm_value_limit`): Cap ETH (or native token) per transaction.
- **EIP-712 / typed data**: Support for signing structured data (e.g. permit, orders) with the same rule engine so only allowed domains and parameters are signed.

You get **parameter-level intent verification** (not just “this key can sign”) and optional **budget control** (per-rule or template-based limits and alerts), which is where Remote Signer stands out compared to generic signer services.

---

## 4. Account Abstraction (EIP-4337)

**Scenario:** An EIP-4337 smart account (or bundler service) needs to sign UserOperations before submitting them to the EntryPoint. You want policy control over which UserOps are signed: only certain smart account senders, approved paymasters, gas caps, and -- critically -- validation of the *inner calls* encoded in `callData` (e.g. only allow `USDC.transfer` to whitelisted recipients, not arbitrary calls).

**Problem:** A UserOperation is signed as EIP-712 typed data, but the actual intent (e.g. "transfer 100 USDC to Alice") is buried inside the `callData` field as an ABI-encoded `execute(address,uint256,bytes)` or `executeBatch(...)` call. Generic typed-data signing has no visibility into these inner operations, so without deep inspection any callData would be signed.

**How Remote Signer helps:**

- **UserOp template** (`eip4337_userop`): A built-in JS rule template that validates the EIP-712 UserOperation structure -- EntryPoint address, sender allowlist, paymaster allowlist, initCode policy, gas limits -- then **parses `callData`** to extract inner `execute` / `executeBatch` calls.
- **Delegation to inner call rules**: The template uses delegation (`delegate_to` / `delegate_to_by_target`) to forward each inner call to an appropriate rule. For example, a `USDC.transfer(...)` call inside `execute(USDC_address, 0, transferCalldata)` is delegated to an ERC20 rule that validates the recipient and amount cap. This is the same composition model used by the Safe template.
- **Batch support**: `executeBatch` UserOps (multiple inner calls in one UserOp) are decomposed into per-item delegation (`delegate_mode: per_item`), so each inner call is validated independently.
- **EntryPoint verification**: The template enforces that `verifyingContract` in the EIP-712 domain matches the configured EntryPoint address (v0.6 or v0.7).

**Example flow:**

```
UserOp (EIP-712 typed data)
  -> eip4337_userop template validates:
       - sender in allowed_senders
       - paymaster in allowed_paymasters
       - initCode blocked (or allowed)
       - callGasLimit <= max_call_gas_limit
  -> parse callData: execute(USDC_addr, 0, transfer(Alice, 100e6))
  -> delegate to "erc20" rule:
       - validates USDC contract address
       - validates Alice in allowed_recipients
       - validates 100e6 <= max_amount
  -> all pass -> sign the UserOp
```

**Typical setup:**

```yaml
rules:
  - template: eip4337_userop
    id: "userop"
    variables:
      chain_id: "1"
      entrypoint_address: "0x5FF137D4b0FDCD49DcA30c7CF57E578a026338cc"
      allowed_senders: "0xYourSmartAccount"
      allowed_paymasters: "0xYourPaymaster"
      allow_initcode: "false"
      max_call_gas_limit: "1000000"
      allowed_targets: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"  # USDC
      delegate_to: "erc20"
  - template: erc20_transfer
    id: "erc20"
    variables:
      chain_id: "1"
      token_address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
      allowed_recipients: "0xAlice,0xBob"
      max_amount: "1000000000"  # 1000 USDC
```

This also applies to EIP-6900 modular accounts, which use the same UserOp signing flow.

---

## Summary

| Use case   | Main rule types / features |
|-----------|----------------------------|
| **Treasury** | `evm_address_list`, `evm_value_limit`, manual approval, notifications |
| **Bot**      | `evm_contract_method`, `evm_solidity_expression`, `evm_value_limit`, per-key rate limit |
| **DeFi**     | `evm_solidity_expression`, `evm_contract_method`, `evm_value_limit`, EIP-712 |
| **EIP-4337** | `eip4337_userop` template, delegation to inner call rules (ERC20, native, DEX), EntryPoint verification |

For API details, rule syntax, and configuration, see [api.md](api.md), [rule-syntax.md](rule-syntax.md), and [config.example.yaml](../config.example.yaml).
