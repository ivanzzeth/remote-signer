# Security Review & Action Plan

## Review Date: 2026-02-04

---

## Implementation Status (Updated 2026-02-04)

| Issue | Priority | Status | Details |
|-------|----------|--------|---------|
| Fail-Open → Fail-Closed | P0 | **IMPLEMENTED** | Mandatory for blocklist rules |
| Ed25519 nonce for replay protection | P1 | **ENHANCED** | 60s window, nonce required, sequence support |
| Foundry sandbox isolation | P1 | Pending | - |
| Multi-party approval | P1 | Pending | - |

### Changes Made

**1. Fail-Closed Mechanism (P0)**
- Blocklist rules use **mandatory** Fail-Closed behavior (not configurable)
- Any blocklist rule evaluation error immediately rejects the request
- This prevents attackers from bypassing security checks by causing evaluation failures
- **Behavior by rule type**:
  - Blocklist errors → reject immediately with `RuleEvaluationError` (mandatory)
  - Whitelist errors → skip and continue to next rule (preserves "any match = allow" semantic)
- Files: `internal/core/rule/engine.go`, `internal/core/rule/whitelist.go`

**2. Ed25519 Nonce & Replay Protection (P1) - Enhanced**
- New signature format: `{timestamp}|{nonce}|{method}|{path}|{sha256(body)}`
- Client generates random 16-byte nonce per request
- Server validates nonce uniqueness via `NonceStore` interface
- **Security Improvements (2026-02-04)**:
  - **Reduced time window**: Default `max_request_age` reduced from 5min to **60 seconds**
    - Minimizes replay attack window while tolerating network latency
  - **Nonce enforcement**: `nonce_required: true` (default) rejects requests without X-Nonce header
    - Legacy format (without nonce) can be allowed by setting `nonce_required: false`
- In-memory nonce store included; **production recommendation**: Use Redis for distributed deployments
- Files: `internal/core/auth/verifier.go`, `internal/storage/nonce_store.go`, `internal/api/middleware/auth.go`, `pkg/client/client.go`

**Configuration (config.yaml)**:
```yaml
security:
  max_request_age: "60s"    # Reduced from 5min (recommended: 30-60s)
  nonce_required: true      # Reject requests without X-Nonce header
```

**Client defaults**:
- `UseNonce` is enabled by default in client SDKs
- Signature format: `{timestamp}|{nonce}|{method}|{path}|{sha256(body)}`

---

## Overall Assessment

**Rating**: Medium-High (suitable for low-medium value assets)

**Reviewer**: External Security Expert (Blockchain & API Security)

**Verdict**: Architecture has good modularity and basic protections, but requires hardening for production use with high-value assets (>$10K).

---

## Issue Summary

| Severity | Issue | Current State | Priority |
|----------|-------|---------------|----------|
| **CRITICAL** | Fail-Open Design | ~~Rules error → continue signing~~ **FIXED** | P0 |
| **HIGH** | Ed25519 Replay Risk | ~~No nonce/challenge-response~~ **FIXED** | P1 |
| **HIGH** | Foundry in Production | Test framework used at runtime | P1 |
| **HIGH** | Single-Person Approval | No multi-sig/MFA | P1 |
| **MEDIUM** | Weak IP Whitelist | Spoofable | P2 |
| **MEDIUM** | Insecure Notification Channel | Slack/Pushover phishing risk | P2 |
| **MEDIUM** | No Approval Timeout | Service can hang | P2 |
| **MEDIUM** | No Key Rotation | Long-term exposure risk | P2 |
| **LOW** | DB Encryption Not Enforced | Depends on deployment | P3 |
| **LOW** | No Anomaly Detection | Vulnerable to batch attacks | P3 |

---

## Detailed Findings

### 1. Authentication & Access Control

#### Finding: Ed25519 Replay Risk
**Severity**: HIGH

**Current**: Signature format `{timestamp}|{method}|{path}|{sha256(body)}` with 5-minute window.

**Problem**: Deterministic signature without nonce. Attacker intercepting valid signature (via MITM or log leak) can replay within 5 minutes. Clock drift or NTP attacks widen the window.

**Recommendation**:
- Add random nonce to signature string (client generates, server validates uniqueness)
- Use challenge-response mode (server issues nonce, client signs)
- Maintain nonce deduplication table (Redis, 5-min TTL)

```
Before: {timestamp}|{method}|{path}|{sha256(body)}
After:  {timestamp}|{nonce}|{method}|{path}|{sha256(body)}
```

#### Finding: Weak IP Whitelist
**Severity**: MEDIUM

**Problem**: IP whitelist easily spoofed via proxy or cloud IPs. Not suitable as primary control for public/VPN scenarios.

**Recommendation**:
- Replace with zero-trust model (mTLS or JWT + device fingerprint)
- Use IP whitelist only as defense-in-depth layer

### 2. Rule Engine

#### Finding: Fail-Open Design (CRITICAL)
**Severity**: CRITICAL

**Current**: Rule evaluation errors don't block requests, only log.

**Problem**: If rule engine crashes (Foundry vulnerability, DB failure), attackers bypass all checks and sign high-value transactions. Violates "Fail-Closed" principle.

**Recommendation**:
```
Rule evaluation error → Default REJECT + Alert

Configurable degradation strategy:
  - strict: error = reject (default, REQUIRED for production)
  - degraded: error = manual approval (optional)
```

**Implementation Priority**: IMMEDIATE

#### Finding: Foundry in Production
**Severity**: HIGH

**Problem**: Foundry is a testing framework, not a runtime tool. Even with dangerous cheatcodes disabled (vm.ffi, vm.readFile), zero-day vulnerabilities in expression parsing could allow code execution or side-channel leaks. No input sanitization against Solidity injection.

**Recommendation**:
- Option A: Docker + seccomp isolation for Foundry execution
- Option B: Replace with safer validator (Z3 solver for static analysis)
- Option C: Restrict to predefined rule templates, disable custom expressions

#### Finding: Insufficient Rule Coverage
**Severity**: MEDIUM

**Problem**: Missing rate limits (daily signing quota) and anomaly detection (unusual patterns). `typed_data` signing vulnerable to drainer scams.

**Recommendation**:
- Add global rate limiting rules (per signer, per day)
- Implement ML-based anomaly detection
- Add typed_data domain validation

### 3. Manual Approval

#### Finding: Single-Person Approval
**Severity**: HIGH

**Problem**: Single approver vulnerable to error and insider threat. Blockchain best practice requires multi-sig (2-of-3) for high-value operations.

**Recommendation**:
```
Multi-sig configuration by value:
  - Low value (<$1K): 1-of-1
  - Medium value ($1K-$10K): 2-of-3
  - High value (>$10K): 3-of-5 + time lock
```

#### Finding: Insecure Notification Channel
**Severity**: MEDIUM

**Problem**: Slack/Pushover vulnerable to phishing and account hijacking. Fake notifications can trick approvers. No MFA or context verification.

**Recommendation**:
- Slack approval requires secondary MFA confirmation
- Or dedicated approval app (TOTP/WebAuthn)
- Independent audit logging for approvals

#### Finding: No Approval Timeout
**Severity**: MEDIUM

**Problem**: If approver offline, service hangs indefinitely.

**Recommendation**:
- 30-minute timeout → auto-reject
- Escalation to backup approvers

#### Finding: TUI Security
**Severity**: LOW

**Problem**: Terminal UI approval without encryption/authentication vulnerable to local malware input capture.

**Recommendation**:
- Add TUI session authentication
- Consider web-based approval interface with proper auth

### 4. Key Storage

#### Finding: Software Key Storage Risk
**Severity**: HIGH

**Problem**: Keystore + Secret Manager (AWS SSM) encrypted but vulnerable to memory dump if server compromised (supply chain attack). No HSM enforcement. Private key theft accounts for 44% of blockchain breaches.

**Recommendation**:
- Enforce HSM/MPC (YubiHSM, AWS KMS) for production
- Add key usage monitoring
- Multi-sig architecture to distribute risk

#### Finding: No Key Rotation
**Severity**: MEDIUM

**Problem**: Keys not periodically rotated, increasing long-term exposure risk.

**Recommendation**:
- Annual key rotation policy
- Automated rotation tooling
- Encrypted offline backup

### 5. Infrastructure

#### Finding: PostgreSQL Security
**Severity**: MEDIUM

**Problem**: State/logs in DB without enforced encryption (at-rest/in-transit), RBAC, or backup protection. GORM misconfiguration can introduce vulnerabilities.

**Recommendation**:
- Use pgcrypto for at-rest encryption
- Enforce TLS for DB connections
- Implement least-privilege access

#### Finding: TLS Termination at Proxy
**Severity**: MEDIUM

**Problem**: If proxy (Nginx) has weak configuration (weak ciphers), vulnerable to MITM. No end-to-end encryption for internal traffic.

**Recommendation**:
- E2EE for internal service traffic
- Strong TLS configuration (TLS 1.3, strong ciphers only)

#### Finding: No Monitoring/Updates
**Severity**: LOW

**Problem**: No real-time alerting, penetration testing, or dependency scanning mentioned. ethsig/Foundry vulnerabilities could be exploited.

**Recommendation**:
- Integrate Prometheus monitoring + alerting
- Automated dependency updates (Dependabot)
- Regular security audits (CertiK, etc.)

---

## Action Plan

### P0 - Immediate (Fail-Closed)

**Issue**: Fail-Open design allows rule bypass on errors.

**Action**:
1. Change `RuleEngine.Evaluate()` to return error on evaluation failure
2. Default behavior: reject on any error
3. Add configuration option for degradation strategy
4. Add alerting on rule evaluation failures

**Files to modify**:
- `internal/core/rule/engine.go`
- `internal/core/rule/whitelist.go`
- `internal/core/service/sign.go`

### P1 - High Priority

#### 1. Ed25519 Nonce Enhancement

**Action**:
1. Add `nonce` field to request signature format
2. Implement nonce deduplication (Redis or in-memory with TTL)
3. Reject duplicate nonces

**Files to modify**:
- `internal/core/auth/verifier.go`
- `internal/api/middleware/auth.go`
- `pkg/client/client.go`

#### 2. Foundry Sandbox Isolation

**Action**:
1. Run Foundry in Docker container with seccomp profile
2. Add input sanitization for Solidity expressions
3. Consider replacing with static analysis (Z3) for critical deployments

**Files to modify**:
- `internal/chain/evm/solidity_evaluator.go`

#### 3. Multi-Party Approval

**Action**:
1. Add approval threshold configuration (M-of-N)
2. Track partial approvals
3. Implement timeout with auto-reject

**Files to modify**:
- `internal/core/service/approval.go`
- `internal/core/types/request.go`
- `internal/storage/request_repo.go`

### P2 - Medium Priority

#### 4. Authentication Upgrade

**Phases**:
1. Add nonce (covered in P1)
2. Implement mTLS option to replace IP whitelist
3. Add device binding + MFA

#### 5. Secure Approval Channel

**Action**:
1. Add MFA confirmation requirement for Slack approvals
2. Or implement dedicated approval API with WebAuthn
3. Independent approval audit log

#### 6. Key Management Enhancement

**Action**:
1. Enforce HSM for high-value deployments (>$10K)
2. Implement key rotation policy (annual)
3. Add key usage monitoring and alerting

### P3 - Low Priority

#### 7. Database Security

**Action**:
1. Document required encryption settings
2. Add GORM security configuration validation
3. Implement audit log integrity checks

#### 8. Anomaly Detection

**Action**:
1. Add global rate limiting rules
2. Implement pattern-based anomaly detection
3. Alert on unusual signing patterns

---

## Recommended Architecture Improvements

```
                    ┌─────────────────────────────────────────┐
                    │           Load Balancer (mTLS)          │
                    └──────────────────┬──────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                          Remote Signer Service                               │
│  ┌────────────────┐  ┌─────────────────┐  ┌──────────────────────────────┐  │
│  │ Auth Layer     │  │ Rule Engine     │  │ Signing Layer                │  │
│  │ + Nonce check  │  │ + Fail-Closed   │  │ + HSM/MPC integration        │  │
│  │ + mTLS         │  │ + Sandboxed eval│  │ + Multi-sig for high value   │  │
│  └────────────────┘  └─────────────────┘  └──────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │ Approval Layer                                                         │ │
│  │ + Multi-party (2-of-3)  + MFA confirmation  + 30min timeout           │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Deployment Recommendations by Asset Value

| Asset Value | Auth | Rules | Approval | Key Storage |
|-------------|------|-------|----------|-------------|
| <$1K (Dev) | Ed25519 | Fail-Open OK | 1-of-1 | Keystore |
| $1K-$10K | Ed25519 + nonce | Fail-Closed | 2-of-3 | Secret Manager |
| >$10K | mTLS + MFA | Fail-Closed + Sandbox | 3-of-5 + timelock | HSM/MPC |

---

## References

- OWASP API Security Top 10
- NIST SP 800-57 (Key Management)
- Blockchain Security Best Practices (CertiK, Hacken reports)
- Ed25519 Authentication Best Practices

---

## Review History

| Date | Reviewer | Changes |
|------|----------|---------|
| 2026-02-04 | External Security Expert | Initial review |
