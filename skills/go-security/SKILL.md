---
name: go-security
description: Go security review checklist adapted for remote-signer. Covers keystore management, Ed25519 auth, input validation, and signing service specific threats.
---

# Go Security Review (remote-signer)

Security review checklist for the remote-signer Go codebase.

## When to Activate

- Implementing authentication or authorization
- Handling signing requests or key material
- Working with keystore files or HD wallets
- Creating new API endpoints
- Modifying rule engine evaluation
- Working with secrets or credentials

## remote-signer Specific Threats

### 1. Keystore & Key Management

```go
// FAIL: Hardcoded keystore password
password := "my-secret-password"

// PASS: Password from env or secure config
password := os.Getenv("KEYSTORE_PASSWORD")
if password == "" {
    return fmt.Errorf("KEYSTORE_PASSWORD not set")
}
```

**Checklist:**
- [ ] No hardcoded keystore passwords
- [ ] No hardcoded Ed25519 private keys
- [ ] No hardcoded secp256k1 private keys
- [ ] Keystore files stored with restricted permissions (0600)
- [ ] HD wallet mnemonics never logged or stored in plaintext
- [ ] `KeystoreProvider` / `PasswordProvider` implementations are audited

### 2. API Key Authentication

```go
// Ed25519 public key in config — ok (public)
// Ed25519 private key — NEVER in source code

// FAIL: Private key in source
const adminPrivateKey = "ed25519:abc123..."

// PASS: Private key loaded from secure storage
privKey, err := loadPrivateKey(config.PrivateKeyPath)
```

### 3. Rule Engine Security

- [ ] Blocklist rules always evaluated before whitelist rules
- [ ] Delegation depth limit enforced (`DelegationMaxDepth = 6`)
- [ ] Cycle detection active on delegation paths
- [ ] Blocklist re-evaluation happens on delegated inner payloads
- [ ] JS sandbox: 20ms timeout, 32MB memory, blocked globals enforced
- [ ] Solidity sandbox: disabled cheatcodes enforced
- [ ] Budget enforcement happens after whitelist match, before approval

### 4. Input Validation

```go
// FAIL: Unvalidated address
func SignTx(signer string, tx Transaction) (*Signature, error) {
    return sign(signer, tx)
}

// PASS: Validate addresses
func SignTx(signer string, tx Transaction) (*Signature, error) {
    if !isValidAddress(signer) {
        return nil, fmt.Errorf("invalid signer address: %s", signer)
    }
    if !isValidAddress(tx.To) {
        return nil, fmt.Errorf("invalid recipient: %s", tx.To)
    }
    return sign(signer, tx)
}
```

- [ ] All Ethereum addresses validated (0x prefix, 42 chars hex)
- [ ] Transaction values validated (non-negative, within bounds)
- [ ] Chain IDs validated
- [ ] Sign type values validated against allowlist

### 5. SQL Injection Prevention

```go
// FAIL: String concatenation
db.Raw("SELECT * FROM rules WHERE id = '" + ruleID + "'")

// PASS: Parameterized query (GORM)
db.Where("id = ?", ruleID).First(&rule)
```

- [ ] All GORM queries use parameterized forms
- [ ] No raw SQL string concatenation
- [ ] `json_extract` used safely in debug queries only

### 6. Error Handling

```go
// FAIL: Leaking internal state
return fmt.Errorf("keystore file at %s not readable: %v", path, err)

// PASS: Generic error, log detail server-side
log.Error("keystore access failed", "path", path, "error", err)
return fmt.Errorf("signer unavailable")
```

- [ ] Error messages don't leak file paths, key material, or internal state
- [ ] Detailed errors logged server-side only
- [ ] No stack traces exposed to API clients

### 7. Audit Logging

- [ ] All sign operations logged (sign_request, sign_complete, sign_failed, sign_rejected)
- [ ] All auth events logged (auth_success, auth_failure)
- [ ] All rule changes logged (rule_created, rule_updated, rule_deleted)
- [ ] Rate limit hits logged
- [ ] Audit logs never contain private keys or mnemonics

## Pre-Commit Security Scan

The pre-commit hook automatically scans for:
- Ed25519 private keys (64+ hex chars after `ed25519:`)
- secp256k1/Ethereum private keys (0x-prefixed 64 hex chars)
- Keystore passwords in config
- API key assignments
- SSH/PGP private key blocks
- GitHub tokens

Run manually:
```bash
git diff --cached | grep -E 'ed25519:|private_key:|keystore_password:'
```
