# Remote-Signer Security Audit Report

**Audit Date**: 2026-01-15
**Auditor**: Security Review
**Status**: In Progress

---

## Summary

| Severity | Count | Fixed |
|----------|-------|-------|
| CRITICAL | 1 | 1 |
| HIGH | 0 | 0 |
| MEDIUM | 0 | 0 |
| LOW | 8 | 3 |

---

## Issues

### 1. [CRITICAL] Solidity Code Execution Risk

**Status**: FIXED
**Location**: `internal/chain/evm/solidity_evaluator.go:438-493`

**Description**:
User-provided Solidity expressions are executed via `forge script`. Foundry cheatcodes like `vm.ffi`, `vm.readFile`, `vm.writeFile` can be exploited for:
- Arbitrary command execution
- File system access
- Information exfiltration

**Current Mitigation**: Only timeout protection (30s default)

**Required Fix**:

1. Disable dangerous Foundry cheatcodes:
```go
cmd.Env = append(os.Environ(),
    "FOUNDRY_FFI=false",
    "FOUNDRY_FS_PERMISSIONS=[]",
)
```

2. Add static code validation before saving rules:
```go
var dangerousPatterns = []string{
    `vm\.ffi`,
    `vm\.readFile`,
    `vm\.writeFile`,
    `vm\.envOr`,
    `vm\.setEnv`,
    `vm\.projectRoot`,
    `vm\.readDir`,
    `vm\.fsMetadata`,
    `vm\.rpc`,
}
```

3. Docker resource limits in `docker-compose.yml`:
```yaml
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 2G
security_opt:
  - no-new-privileges:true
```

**Priority**: P0

---

### 2. [LOW] Private Key String Not Zeroized

**Status**: TODO
**Location**: `internal/chain/evm/signer.go:83`

**Description**:
The `keyHex` variable (private key hex string) is not zeroized after use. However, after review of the ethsig library:

- `crypto.HexToECDSA` errors do NOT contain the private key
- ethsig has `SecureBytes` and `Zeroize()` for passwords
- Keystore passwords are properly zeroized via `keystore.SecureZeroize(password)`

**Risk**: Very low - Go GC will eventually clean up the string, and the actual private key is stored as `*ecdsa.PrivateKey` struct, not the raw string.

**Optional Fix** (if desired):
```go
keyHex := resolvePrivateKey(pk.KeyEnvVar)
defer func() {
    // Note: Go strings are immutable, would need []byte for true zeroization
}()
```

**Priority**: P3

---

### 3. [LOW] Rate Limiter Cleanup Interval Bug

**Status**: FIXED
**Location**: `internal/api/router.go:173`

**Description**:
The cleanup interval is incorrectly specified:

```go
r.rateLimiter.StartCleanupRoutine(5*60*1000, stop) // every 5 minutes
```

`time.Duration` base unit is **nanoseconds**, not milliseconds!
- Current: `5*60*1000` = 300,000 nanoseconds = **0.3 milliseconds**
- Expected: 5 minutes

**Impact**:
- NOT a memory leak (cleanup runs too frequently, not too infrequently)
- CPU waste due to cleanup running ~3,333 times per second
- Minor performance impact

**Fix**:
```go
r.rateLimiter.StartCleanupRoutine(5*time.Minute, stop)
```

**Priority**: P2 (bug fix, not security)

---

### 4. [LOW] Async Rule Match Count May Be Lost

**Status**: ACCEPTED
**Location**: `internal/core/rule/whitelist.go:134-138, 174-179`

**Description**:
Rule match counts are updated asynchronously via `go func()`:
```go
go func(ruleID types.RuleID) {
    if err := e.repo.IncrementMatchCount(context.Background(), ruleID); err != nil {
        e.logger.Error("failed to increment match count", ...)
    }
}(rule.ID)
```

**Potential Issues**:
- Counts may be lost if service shuts down before goroutine completes
- Uses `context.Background()` - not controlled by graceful shutdown

**Impact**: Very low
- Match count is statistical data only
- Does not affect security or core signing functionality
- Losing a few counts is acceptable

**Decision**: Accept as-is. Not worth adding complexity for non-critical stats.

**Priority**: P3

---

### 5. [LOW] Application Does Not Support Built-in TLS

**Status**: ACCEPTED
**Location**: `internal/api/server.go:72`

**Description**:
The application only supports HTTP via `ListenAndServe()`. No built-in TLS support.

```go
// server.go:72
return s.httpServer.ListenAndServe()  // No ListenAndServeTLS option
```

**Impact**: Low
- Production deployments typically use reverse proxy (nginx/traefik) for TLS termination
- This is a common and acceptable architecture pattern
- User confirmed TLS is enforced via external proxy in production

**Decision**: Accept as-is. TLS handled by reverse proxy in Docker deployment.

**Optional Enhancement** (if desired):
Add TLS configuration to `ServerConfig` and support `ListenAndServeTLS()`.

**Priority**: P3

---

### 6. [LOW] Database DSN Contains Password

**Status**: ACCEPTED
**Location**: `config.example.yaml:12`

**Description**:
Database DSN may contain password in connection string.

```yaml
dsn: "${DATABASE_DSN:-postgres://signer:signer_password@localhost:5432/...}"
```

**Mitigations Already in Place**:
- DSN is NOT logged anywhere ✅
- Config supports environment variable `${DATABASE_DSN}` ✅
- Example password is only for local development

**Impact**: Very low
- Production should use `DATABASE_DSN` env var with proper secrets management
- No actual exposure in logs or errors

**Decision**: Accept as-is. Follow standard practice of using env vars in production.

**Priority**: P3

---

### 7. [LOW] Empty AllowedSigners Means Allow All

**Status**: ACCEPTED
**Location**: `internal/core/types/auth.go:48-51`

**Description**:
Empty `AllowedSigners` or `AllowedChainTypes` arrays mean "allow all":

```go
func (k *APIKey) IsAllowedSigner(address string) bool {
    if len(k.AllowedSigners) == 0 {
        return true // empty = all allowed
    }
    // ...
}
```

**Impact**: Low
- This is intentional design (documented in config.example.yaml)
- Configuration errors are the operator's responsibility
- Explicit `allow_all: true` flag would be marginally safer

**Decision**: Accept as-is. Behavior is documented and intentional.

**Priority**: P3

---

### 8. [LOW] Rule Evaluation Errors Silently Continue

**Status**: ACCEPTED
**Location**: `internal/core/rule/whitelist.go:158-165`

**Description**:
When a rule evaluation fails, the error is logged but the rule is skipped:

```go
if err != nil {
    e.logger.Error("whitelist rule evaluation error", ...)
    continue  // Skip rule, don't fail request
}
```

**Impact**: Low
- Fail-open design (rule error = skip rule, not block request)
- May allow requests that should be blocked if rule is misconfigured
- But: rule validation happens at creation time (test cases required for Solidity rules)

**Trade-off**: Fail-open vs fail-closed
- Fail-closed: More secure but may cause service disruption
- Fail-open: Less secure but more available

**Decision**: Accept current fail-open design. Production rules should have test cases.

**Priority**: P3

---

### 9. [LOW] Temp File Permissions Too Open

**Status**: FIXED
**Location**: `internal/chain/evm/solidity_evaluator.go:216, 445`

**Description**:
Temporary directories and files use standard permissions:

```go
os.MkdirAll(tempDir, 0755)        // World-readable directory
os.WriteFile(scriptPath, ..., 0644)  // World-readable file
```

**Impact**: Very low
- Docker container runs isolated
- Temp files contain Solidity scripts (not secrets)
- Other users on same system could read scripts

**Fix** (optional):
```go
os.MkdirAll(tempDir, 0700)        // Owner-only directory
os.WriteFile(scriptPath, ..., 0600)  // Owner-only file
```

**Priority**: P3

---

## Accepted Risks

### Nonce Replay Protection

**Decision**: Not implementing
**Reason**:
- TLS enforced in production
- Internal use only (not public API)
- Primarily used for transaction signing (EVM nonce provides protection)
- Trusted client environment

---

## Automated Security Tooling

To prevent regressions and discover new vulnerabilities continuously, the following automated checks are in place. All run locally (no external CI/CD required).

### Pre-Commit Checks (Git Hooks)

```bash
# Install: ./scripts/install-hooks.sh
gosec ./...          # Go static security analysis
govulncheck ./...    # Dependency CVE scanning
go vet ./...         # Code correctness
```

### Periodic Scanning (Cron)

```bash
# Run: ./scripts/security-audit.sh
# Schedule: daily or weekly via cron
govulncheck ./...                      # Go dependency CVEs
gosec ./...                            # Static analysis
trivy fs .                             # Filesystem vulnerability scan
trivy image remote-signer:latest       # Docker image CVEs
```

### Configuration Validation

```bash
# Run: ./scripts/config-check.sh
# Validates: no plaintext secrets, TLS enabled, nonce_required=true, sane rate limits
```

### Fuzz Testing

```bash
# Auth middleware: go test -fuzz=FuzzAuthMiddleware -fuzztime=5m ./internal/api/middleware/
# Sign requests: go test -fuzz=FuzzSignRequestParsing -fuzztime=5m ./internal/api/handler/
# Rule engine:   go test -fuzz=FuzzRuleEvaluation -fuzztime=5m ./internal/chain/evm/
```

### Adversarial E2E Tests

```bash
# Run: go test -tags=e2e -run TestSecurity ./e2e/...
# Covers: replay attacks, auth bypass, rule engine bypass, privilege escalation, race conditions
```

### Runtime Monitoring

```bash
# Run: ./scripts/audit-monitor.sh (via cron, hourly)
# Detects: brute-force auth, rule probing, off-hours activity, DoS patterns
# Alerts via: Slack/Pushover (existing notification channels)
```

See `docs/security-review.md` § "Security Automation Plan" for full details.

---

## Changelog

| Date | Issue | Action |
|------|-------|--------|
| 2026-01-15 | All issues | Completed initial audit and documentation |
| 2026-01-15 | Nonce replay | Accepted (TLS + internal use) |
| 2026-01-15 | Private key logs | Downgraded HIGH→LOW (ethsig safe) |
| 2026-01-15 | Rate limiter | Downgraded MEDIUM→LOW (bug, not leak) |
| 2026-01-15 | Async match count | Downgraded MEDIUM→LOW (stats only) |
| 2026-01-15 | TLS | Downgraded MEDIUM→LOW (reverse proxy) |
| 2026-01-15 | DSN | Downgraded MEDIUM→LOW (env vars) |
| 2026-01-15 | Solidity execution | **FIXED**: Disabled dangerous cheatcodes + static validation |
| 2026-01-15 | Rate limiter bug | **FIXED**: Changed to 5*time.Minute |
| 2026-01-15 | Temp permissions | **FIXED**: Changed to 0700/0600 |
| 2026-01-15 | Docker security | **ADDED**: Resource limits + security options |
| 2026-02-14 | Security automation | **ADDED**: Git hooks, fuzz tests, adversarial E2E, scanning scripts, runtime monitoring |

