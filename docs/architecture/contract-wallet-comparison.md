# Contract Wallet Solutions Comparison

Comparison of mature, open-source on-chain access-control / smart-contract wallet frameworks for protecting large fund positions. All solutions build on top of Safe (Gnosis Safe) multisig.

> Last updated: 2026-03-11

---

## Overview

| Solution | Developer | License | Base Layer |
|----------|-----------|---------|------------|
| [CoboSafe v2](https://github.com/CoboGlobal/cobosafe) | Cobo | LGPL-3.0 | Safe Module + Guard |
| [Zodiac Roles Modifier v2](https://github.com/gnosisguild/zodiac-modifier-roles) | Gnosis Guild | LGPL-3.0 | Safe Module (Zodiac) |
| [Brahma Console v2](https://github.com/Brahma-fi/console-kit) | Brahma Finance | MIT | Safe Module + Guard |

---

## Architecture

### CoboSafe v2

- **Model**: Delegate → Authorizer chain
- A Safe owner grants Delegate rights to an address (e.g. remote-signer)
- Each Delegate is bound to an Authorizer (or chain of Authorizers)
- Authorizer implements `preExecCheck` / `postExecCheck` / `preExecProcess` / `postExecProcess`
- Custom ACL contracts (one per target protocol) implement fine-grained parameter checks
- **TransactionData** struct: `from, delegate, flag (call/delegatecall), to, value, data, hint, extra`
- **Hint mechanism**: Off-chain pre-computation passed on-chain for verification, saving gas on complex checks

### Zodiac Roles Modifier v2

- **Model**: Role → Target → Function → Parameter conditions tree
- Roles are assigned to member addresses
- Each Role defines a set of allowed targets, optionally scoped to specific functions
- Functions can have declarative conditions on each parameter (comparison operators, AND/OR/NOT trees)
- Built-in Allowance system for rate/amount limiting
- **Transaction unwrapping**: Native support for multi-send batches — each inner call checked individually

### Brahma Console v2

- **Model**: Main Account → Sub-Account + Transaction Policy
- Main Safe creates Sub-Account Safes with isolated funds
- Operators are authorized to execute within Sub-Account policy boundaries
- Policies configured at protocol / asset / timeframe level
- Custom Transaction Guard enforces policies on every Sub-Account transaction

---

## Permission Granularity

| Capability | CoboSafe v2 | Zodiac Roles v2 | Brahma Console v2 |
|------------|------------|-----------------|-------------------|
| Target address control | ✅ | ✅ | ✅ |
| Function selector control | ✅ FuncAuthorizer | ✅ Function scoping | ✅ Protocol-level |
| Parameter-level checks | ✅ Custom ACL (Solidity) | ✅ Declarative conditions | ⚠️ Coarse (policy-level) |
| Condition combinators (AND/OR/NOT) | ✅ Code-level, arbitrary | ✅ Built-in condition tree | ⚠️ Limited |
| Pre-execution check | ✅ preExecCheck | ✅ | ✅ Guard |
| **Post-execution check** | ✅ **postExecCheck** | ❌ | ❌ |
| Amount/rate allowances | ❌ Manual ACL implementation | ✅ **Built-in Allowance** | ⚠️ Timeframe-level |
| Delegate call control | ✅ flag field | ✅ Per-target config | ✅ |
| ETH value transfer limit | ✅ In ACL | ✅ Built-in ETH allowance | ✅ |
| Multi-send unwrapping | ✅ In ACL | ✅ **Native** | ⚠️ |

---

## Development Experience

| Dimension | CoboSafe v2 | Zodiac Roles v2 | Brahma Console v2 |
|-----------|------------|-----------------|-------------------|
| New protocol onboarding | Write + deploy Solidity ACL contract | Declarative JSON config via SDK | UI configuration / ConsoleKit |
| Learning curve | High (Solidity + ACL patterns) | Medium (TypeScript SDK + conditions DSL) | Low (UI-driven) |
| Flexibility | ⭐⭐⭐⭐⭐ Unlimited (raw Solidity) | ⭐⭐⭐⭐ Powerful but bounded by conditions DSL | ⭐⭐⭐ Preset policy templates |
| Development speed | Slow (contract per protocol + audit) | Fast (declarative, no new contracts) | Fastest (UI clicks) |
| SDK / Tooling | pycobosafe (Python) | TypeScript SDK (well-documented) | ConsoleKit (TypeScript) |

---

## Security

| Dimension | CoboSafe v2 | Zodiac Roles v2 | Brahma Console v2 |
|-----------|------------|-----------------|-------------------|
| Audits | Slowmist, etc. | G0 Group, Omniscia | Ackee Blockchain, Code4rena |
| Production usage | Cobo Argus institutional clients | ENS DAO, GnosisDAO, Balancer, **Gnosis Pay** (every Visa card tx) | Blast L2, various DAOs |
| Attack surface | Each ACL contract = new attack surface | Centralized conditions engine (audited once) | Medium |
| Post-exec state verification | ✅ Can verify state changes after execution | ❌ | ❌ |
| Hint (off-chain proof) | ✅ Off-chain compute → on-chain verify | ❌ | ❌ |

---

## Strengths & Weaknesses

### CoboSafe v2

**Strengths**:
1. **Post-execution checks** — Only solution supporting state verification after tx execution. Can catch flash-loan-style attacks, slippage violations, unexpected balance changes
2. **Hint mechanism** — Off-chain pre-computation passed to on-chain verification, saving significant gas for complex checks
3. **Unlimited flexibility** — ACL is raw Solidity; any check expressible in code can be implemented
4. **Authorizer chaining** — Multiple Authorizers in series for layered permission strategies

**Weaknesses**:
1. Each protocol requires a new ACL contract → higher development + audit cost
2. More attack surface (more deployed contracts)
3. No built-in rate/amount limiting primitives

### Zodiac Roles Modifier v2

**Strengths**:
1. **Built-in Allowance system** — Native rate/amount limits with refill periods, no custom contracts needed
2. **Declarative conditions** — Parameter-level permissions without deploying new contracts; drastically lowers onboarding cost and audit burden
3. **Largest production scale** — Gnosis Pay processes every Visa card transaction through Roles
4. **Smaller attack surface** — One audited conditions engine vs per-protocol ACL contracts
5. **Native multi-send unwrapping** — Automatically validates each call in a batch

**Weaknesses**:
1. No post-execution checks (cannot verify state changes)
2. Conditions DSL has boundaries — some exotic checks may not be expressible
3. No hint/off-chain-proof mechanism

### Brahma Console v2

**Strengths**:
1. **Sub-Account isolation** — Natural fund segregation via separate Safe per sub-account
2. **Best UX** — UI-driven configuration, accessible to non-technical users
3. **Agent automation** — ConsoleKit provides built-in framework for automated on-chain workflows

**Weaknesses**:
1. Coarser permission granularity (protocol/asset/timeframe, not parameter-level)
2. No post-execution checks
3. Less suitable for complex DeFi permission requirements

---

## Rating Summary

| | Permission Granularity | Security Depth | Dev Efficiency | Ecosystem Maturity | Overall |
|---|---|---|---|---|---|
| **CoboSafe v2** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | **Strongest security ceiling** |
| **Zodiac Roles v2** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | **Best overall balance** |
| **Brahma Console v2** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | **Best user experience** |

---

## Recommendation for Remote-Signer

Remote-signer should position itself as an **automated delegate/member** within any of these frameworks:

1. **Large fund protection**: Store funds in a Safe multisig + on-chain ACL (CoboSafe or Zodiac Roles)
2. **Remote-signer role**: Acts as one signer/delegate with on-chain permission constraints
3. **Defense in depth**: Even if remote-signer is fully compromised, on-chain ACL limits the blast radius
4. **Dual protection**: Remote-signer's off-chain rule engine (JS/Solidity) provides fast filtering; on-chain ACL provides trustless enforcement

The choice between CoboSafe and Zodiac Roles depends on use case:
- **CoboSafe** when post-execution state verification is critical (e.g. DEX slippage protection, flash-loan defense)
- **Zodiac Roles** when rapid protocol onboarding and built-in rate limiting are priorities
- Both can be used simultaneously on the same Safe for different delegates/roles

---

## References

- [CoboSafe GitHub](https://github.com/CoboGlobal/cobosafe)
- [CoboSafe Technical Documentation](https://docs.cobo.com/cobo-argus/cobo-safe-technical-documentation)
- [Zodiac Roles Modifier GitHub](https://github.com/gnosisguild/zodiac-modifier-roles)
- [Zodiac Roles Documentation](https://docs.roles.gnosisguild.org/)
- [Zodiac Roles - Conditions](https://docs.roles.gnosisguild.org/general/conditions)
- [Zodiac Roles - Allowances](https://docs.roles.gnosisguild.org/general/allowances)
- [Gnosis Guild - Evolving Smart Accounts with Onchain Permissions](https://gnosisguild.mirror.xyz/oQcy_c62huwNkFS0cMIxXwQzrfG0ESQax8EBc_tWwwk)
- [Brahma Console Documentation](https://docs.brahma.fi/)
- [Brahma ConsoleKit GitHub](https://github.com/Brahma-fi/console-kit)
- [Brahma Security Design](https://brahma.fi/blog/security-first-design-of-brahma)
- [ENS Roles Policy Audit](https://github.com/ThirdGuard/roles-policy-audits)
- [Safe Global](https://safe.global/)
