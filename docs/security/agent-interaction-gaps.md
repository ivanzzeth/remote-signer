# Agent Interaction Security Gaps

Tracks known security gaps in agent free-interaction scenarios. Each gap has a priority, attack path, and proposed fix.

## HIGH Priority

### GAP-1: Multicall wrapping bypasses blocklist
- **Attack**: Agent sends multicall/batch, internally calls transferOwnership. Top-level selector is multicall, not in blocklist.
- **Status**: FIXED
- **Fix**: Simulation-level dangerous event detection (OwnershipTransferred, ApprovalForAll, Upgraded, AdminChanged). Catches dangerous operations regardless of how triggered (direct call, multicall, etc.). Blocklist is fast-fail only; simulation is the real security boundary.

### GAP-2: Gas fees not counted in simulation budget
- **Attack**: Agent sets gasPrice=1000 Gwei, each tx burns large MATIC. Budget only tracks token outflow, not gas.
- **Status**: FIXED
- **Fix**: Gas cost (gasUsed × gasFeeCap/gasPrice) added as native outflow in simulation budget rule.

## MEDIUM Priority

### GAP-3: Typed data Order signatures have no price protection
- **Attack**: Agent signs a DEX limit order at extremely bad price.
- **Status**: TODO
- **Fix**: For known DEX order primaryTypes, add price sanity checks or require verifyingContract whitelist.

### GAP-4: Typed data domain.verifyingContract not validated
- **Attack**: Forge verifyingContract pointing to malicious contract.
- **Status**: TODO
- **Fix**: Add verifyingContract whitelist for sensitive primaryTypes (Permit already covered, extend to others).

### GAP-5: NFT-related typed_data not covered by approval check
- **Attack**: SetApprovalForAll via typed_data bypasses on-chain approval detection.
- **Status**: TODO
- **Fix**: Extend Permit-type check to cover NFT marketplace typed_data signatures.

## LOW Priority

### GAP-6: Agent-safety blocklist incomplete
- **Attack**: Dangerous selectors beyond the current 5 (e.g., delegatecall wrappers, selfdestruct wrappers).
- **Status**: TODO
- **Fix**: Expand blocklist with more known dangerous selectors.

### GAP-7: Flash loan net balance = 0 bypasses budget
- **Attack**: Borrow -> manipulate -> repay. Net balance change is 0, budget doesn't deduct.
- **Status**: ACCEPTED (no good generic defense; rely on contract-specific blocklist rules).
