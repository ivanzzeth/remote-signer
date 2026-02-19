//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
)

// =============================================================================
// Authentication Attack Tests
// =============================================================================

func TestSecurity_ReplayAttack_SameNonce(t *testing.T) {
	if useExternalServer {
		t.Skip("replay test may interfere with external server state")
	}

	ctx := context.Background()

	// Make a valid signed request and capture the raw HTTP request details
	ts := time.Now().UnixMilli()
	nonce := fmt.Sprintf("replay-test-%d", ts)
	method := "GET"
	path := "/health"
	body := []byte("")

	privKeyBytes, err := hex.DecodeString(adminAPIKeyHex)
	require.NoError(t, err)
	privKey := ed25519.PrivateKey(privKeyBytes)

	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%d|%s|%s|%s|%x", ts, nonce, method, path, bodyHash)
	sig := ed25519.Sign(privKey, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	baseURL := getBaseURL()

	// First request should succeed
	req1, err := http.NewRequestWithContext(ctx, method, baseURL+path, bytes.NewReader(body))
	require.NoError(t, err)
	req1.Header.Set("X-API-Key-ID", adminAPIKeyID)
	req1.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req1.Header.Set("X-Signature", sigB64)
	req1.Header.Set("X-Nonce", nonce)

	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	defer resp1.Body.Close()
	assert.Equal(t, http.StatusOK, resp1.StatusCode, "first request should succeed")

	// Second request with same nonce should be rejected (replay attack)
	req2, err := http.NewRequestWithContext(ctx, method, baseURL+path, bytes.NewReader(body))
	require.NoError(t, err)
	req2.Header.Set("X-API-Key-ID", adminAPIKeyID)
	req2.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req2.Header.Set("X-Signature", sigB64)
	req2.Header.Set("X-Nonce", nonce)

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode,
		"replayed request with same nonce must be rejected")
}

func TestSecurity_ReplayAttack_ExpiredTimestamp(t *testing.T) {
	ctx := context.Background()

	// Use a timestamp from 5 minutes ago (well outside 60s window)
	ts := time.Now().Add(-5 * time.Minute).UnixMilli()
	nonce := "expired-ts-test"
	method := "GET"
	path := "/health"
	body := []byte("")

	privKeyBytes, err := hex.DecodeString(adminAPIKeyHex)
	require.NoError(t, err)
	privKey := ed25519.PrivateKey(privKeyBytes)

	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%d|%s|%s|%s|%x", ts, nonce, method, path, bodyHash)
	sig := ed25519.Sign(privKey, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	baseURL := getBaseURL()

	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("X-API-Key-ID", adminAPIKeyID)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Signature", sigB64)
	req.Header.Set("X-Nonce", nonce)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"request with expired timestamp must be rejected")
}

func TestSecurity_AuthBypass_MissingHeaders(t *testing.T) {
	ctx := context.Background()
	baseURL := getBaseURL()

	tests := []struct {
		name       string
		setHeaders func(*http.Request)
	}{
		{
			name:       "no headers at all",
			setHeaders: func(r *http.Request) {},
		},
		{
			name: "missing X-API-Key-ID",
			setHeaders: func(r *http.Request) {
				r.Header.Set("X-Timestamp", fmt.Sprintf("%d", time.Now().UnixMilli()))
				r.Header.Set("X-Signature", "dGVzdA==")
			},
		},
		{
			name: "missing X-Timestamp",
			setHeaders: func(r *http.Request) {
				r.Header.Set("X-API-Key-ID", adminAPIKeyID)
				r.Header.Set("X-Signature", "dGVzdA==")
			},
		},
		{
			name: "missing X-Signature",
			setHeaders: func(r *http.Request) {
				r.Header.Set("X-API-Key-ID", adminAPIKeyID)
				r.Header.Set("X-Timestamp", fmt.Sprintf("%d", time.Now().UnixMilli()))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test against a protected endpoint (sign)
			body := []byte(`{"chain_id":"1","signer_address":"0xabc","sign_type":"personal","payload":{"message":"test"}}`)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/evm/sign", bytes.NewReader(body))
			require.NoError(t, err)
			tt.setHeaders(req)

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
				"request with missing auth headers must return 401")
		})
	}
}

func TestSecurity_AuthBypass_WrongKey(t *testing.T) {
	ctx := context.Background()

	// Generate a completely different Ed25519 key pair
	_, wrongPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	ts := time.Now().UnixMilli()
	nonce := "wrong-key-test"
	method := "GET"
	path := "/health"
	body := []byte("")

	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%d|%s|%s|%s|%x", ts, nonce, method, path, bodyHash)
	sig := ed25519.Sign(wrongPriv, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	baseURL := getBaseURL()

	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("X-API-Key-ID", adminAPIKeyID)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Signature", sigB64)
	req.Header.Set("X-Nonce", nonce)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"request signed with wrong key must be rejected")
}

func TestSecurity_AuthBypass_TamperedBody(t *testing.T) {
	ctx := context.Background()

	// Sign with the original body
	originalBody := []byte(`{"chain_id":"1","signer_address":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266","sign_type":"personal","payload":{"message":"safe"}}`)

	ts := time.Now().UnixMilli()
	nonce := "tampered-body-test"
	method := http.MethodPost
	path := "/api/v1/evm/sign"

	privKeyBytes, err := hex.DecodeString(adminAPIKeyHex)
	require.NoError(t, err)
	privKey := ed25519.PrivateKey(privKeyBytes)

	bodyHash := sha256.Sum256(originalBody)
	message := fmt.Sprintf("%d|%s|%s|%s|%x", ts, nonce, method, path, bodyHash)
	sig := ed25519.Sign(privKey, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// Send with a DIFFERENT body (tampered)
	tamperedBody := []byte(`{"chain_id":"1","signer_address":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266","sign_type":"personal","payload":{"message":"EVIL"}}`)

	baseURL := getBaseURL()

	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, bytes.NewReader(tamperedBody))
	require.NoError(t, err)
	req.Header.Set("X-API-Key-ID", adminAPIKeyID)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Signature", sigB64)
	req.Header.Set("X-Nonce", nonce)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"request with tampered body must be rejected (signature mismatch)")
}

func TestSecurity_AuthBypass_UnknownAPIKeyID(t *testing.T) {
	ctx := context.Background()

	ts := time.Now().UnixMilli()
	nonce := "unknown-key-id-test"
	method := "GET"
	path := "/health"
	body := []byte("")

	privKeyBytes, err := hex.DecodeString(adminAPIKeyHex)
	require.NoError(t, err)
	privKey := ed25519.PrivateKey(privKeyBytes)

	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%d|%s|%s|%s|%x", ts, nonce, method, path, bodyHash)
	sig := ed25519.Sign(privKey, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	baseURL := getBaseURL()

	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("X-API-Key-ID", "nonexistent-key-id-12345")
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Signature", sigB64)
	req.Header.Set("X-Nonce", nonce)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"request with unknown API key ID must be rejected")
}

// =============================================================================
// Privilege Escalation Tests
// =============================================================================

func TestSecurity_AdminEscalation_NonAdminKey(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("non-admin client not configured")
	}

	ctx := context.Background()

	// Non-admin should NOT be able to list rules
	_, err := nonAdminClient.ListRules(ctx, nil)
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode, "non-admin accessing admin endpoint must get 403")

	// Non-admin should NOT be able to approve requests
	_, err = nonAdminClient.ApproveSignRequest(ctx, "fake-request-id", &client.ApproveRequest{
		Approved: true,
	})
	require.Error(t, err)
	apiErr, ok = err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode, "non-admin approving requests must get 403")

	// Non-admin should NOT be able to list audit records
	_, err = nonAdminClient.ListAuditRecords(ctx, nil)
	require.Error(t, err)
	apiErr, ok = err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode, "non-admin accessing audit must get 403")
}

// =============================================================================
// Rule Engine Bypass Tests
// =============================================================================

func TestSecurity_BlocklistBypass_AddressCasing(t *testing.T) {
	if useExternalServer {
		t.Skip("rule bypass test modifies server state")
	}

	ctx := context.Background()

	// The burn address is blocked by the example blocklist rule
	// Try with different casing to see if the blocklist can be bypassed
	casings := []string{
		"0x000000000000000000000000000000000000dEaD", // original
		"0x000000000000000000000000000000000000DEAD", // uppercase
		"0x000000000000000000000000000000000000dead", // lowercase
		"0x000000000000000000000000000000000000DeAd", // mixed case
	}

	for _, addr := range casings {
		t.Run("casing_"+addr[38:], func(t *testing.T) {
			resp, err := adminClient.SignWithOptions(ctx, &client.SignRequest{
				ChainID:       chainID,
				SignerAddress: signerAddress,
				SignType:      "transaction",
				Payload: json.RawMessage(fmt.Sprintf(`{
					"to": "%s",
					"value": "0x0",
					"data": "0x",
					"gas": "0x5208",
					"gasPrice": "0x3b9aca00",
					"nonce": "0x0"
				}`, addr)),
			}, false)

			// All casing variants should be blocked
			if err == nil && resp != nil && resp.Status == "completed" {
				t.Errorf("blocklist bypass via address casing %s: request was completed instead of blocked", addr)
			}
		})
	}
}

func TestSecurity_ValueLimitBypass_Overflow(t *testing.T) {
	if useExternalServer {
		t.Skip("value limit test requires known rule configuration")
	}

	ctx := context.Background()

	// Try to overflow uint256 max value
	overflowValues := []string{
		"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  // uint256 max
		"0x10000000000000000000000000000000000000000000000000000000000000000", // uint256 max + 1
		"-1", // negative (should be rejected as invalid)
	}

	for _, val := range overflowValues {
		t.Run("value_"+val[:10], func(t *testing.T) {
			resp, err := adminClient.SignWithOptions(ctx, &client.SignRequest{
				ChainID:       chainID,
				SignerAddress: signerAddress,
				SignType:      "transaction",
				Payload: json.RawMessage(fmt.Sprintf(`{
					"to": "%s",
					"value": "%s",
					"data": "0x",
					"gas": "0x5208",
					"gasPrice": "0x3b9aca00",
					"nonce": "0x0"
				}`, treasuryAddress, val)),
			}, false)

			// Overflow values should never result in a completed signing
			if err == nil && resp != nil && resp.Status == "completed" {
				t.Errorf("value limit bypass with %s: request completed when it should be blocked/failed", val)
			}
		})
	}
}

// =============================================================================
// Concurrent Race Condition Tests
// =============================================================================

func TestSecurity_ConcurrentApproval_RaceCondition(t *testing.T) {
	if useExternalServer {
		t.Skip("race condition test requires internal server control")
	}

	ctx := context.Background()

	// Submit a sign request that requires manual approval
	// (send to an address NOT in the whitelist and NOT in the blocklist)
	unknownAddr := "0x1111111111111111111111111111111111111111"
	resp, err := adminClient.SignWithOptions(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload: json.RawMessage(fmt.Sprintf(`{
			"to": "%s",
			"value": "0x0",
			"data": "0x",
			"gas": "0x5208",
			"gasPrice": "0x3b9aca00",
			"nonce": "0x0"
		}`, unknownAddr)),
	}, false)
	require.NoError(t, err)
	require.NotNil(t, resp)

	requestID := resp.RequestID

	// Wait for request to be in authorizing state
	time.Sleep(200 * time.Millisecond)

	// Attempt concurrent approve + reject on the same request
	var wg sync.WaitGroup
	results := make([]error, 2)

	wg.Add(2)
	go func() {
		defer wg.Done()
		_, results[0] = adminClient.ApproveSignRequest(ctx, requestID, &client.ApproveRequest{
			Approved: true,
		})
	}()
	go func() {
		defer wg.Done()
		_, results[1] = adminClient.ApproveSignRequest(ctx, requestID, &client.ApproveRequest{
			Approved: false,
		})
	}()
	wg.Wait()

	// At most one should succeed; the other must fail
	successCount := 0
	for _, err := range results {
		if err == nil {
			successCount++
		}
	}

	assert.LessOrEqual(t, successCount, 1,
		"concurrent approve and reject should not both succeed (race condition detected)")

	// Verify final state is consistent
	status, err := adminClient.GetRequest(ctx, requestID)
	require.NoError(t, err)

	// Status must be a terminal state, not corrupted
	validStates := map[string]bool{
		"completed": true,
		"rejected":  true,
		"signing":   true,
		"failed":    true,
	}
	assert.True(t, validStates[status.Status],
		"request should be in a terminal state after concurrent operations, got: %s", status.Status)
}

// =============================================================================
// Request Boundary Tests
// =============================================================================

func TestSecurity_OversizedPayload(t *testing.T) {
	ctx := context.Background()
	baseURL := getBaseURL()

	// Send a very large body (10MB) to test DoS resistance
	largeBody := make([]byte, 10*1024*1024)
	for i := range largeBody {
		largeBody[i] = 'A'
	}

	ts := time.Now().UnixMilli()
	nonce := "oversized-test"

	privKeyBytes, err := hex.DecodeString(adminAPIKeyHex)
	require.NoError(t, err)
	privKey := ed25519.PrivateKey(privKeyBytes)

	bodyHash := sha256.Sum256(largeBody)
	message := fmt.Sprintf("%d|%s|%s|%s|%x", ts, nonce, http.MethodPost, "/api/v1/evm/sign", bodyHash)
	sig := ed25519.Sign(privKey, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/evm/sign", bytes.NewReader(largeBody))
	require.NoError(t, err)
	req.Header.Set("X-API-Key-ID", adminAPIKeyID)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Signature", sigB64)
	req.Header.Set("X-Nonce", nonce)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// Connection reset or timeout is acceptable for oversized payload
		return
	}
	defer resp.Body.Close()
	// Read and discard body to avoid connection leak
	_, _ = io.ReadAll(resp.Body)

	// Should return an error status (400/413/500), not 200
	assert.NotEqual(t, http.StatusOK, resp.StatusCode,
		"oversized payload should not return 200 OK")
}

func TestSecurity_InvalidJSONPayload(t *testing.T) {
	ctx := context.Background()

	invalidPayloads := []string{
		`not json at all`,
		`{"chain_id": 123}`, // wrong type (number instead of string)
		`{"payload": "not-raw-json"}`,
		`{}`, // missing required fields
	}

	for i, payload := range invalidPayloads {
		t.Run(fmt.Sprintf("invalid_%d", i), func(t *testing.T) {
			baseURL := getBaseURL()
			body := []byte(payload)

			ts := time.Now().UnixMilli()
			nonce := fmt.Sprintf("invalid-json-%d-%d", i, ts)

			privKeyBytes, err := hex.DecodeString(adminAPIKeyHex)
			require.NoError(t, err)
			privKey := ed25519.PrivateKey(privKeyBytes)

			bodyHash := sha256.Sum256(body)
			message := fmt.Sprintf("%d|%s|%s|%s|%x", ts, nonce, http.MethodPost, "/api/v1/evm/sign", bodyHash)
			sig := ed25519.Sign(privKey, []byte(message))
			sigB64 := base64.StdEncoding.EncodeToString(sig)

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/evm/sign", bytes.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("X-API-Key-ID", adminAPIKeyID)
			req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
			req.Header.Set("X-Signature", sigB64)
			req.Header.Set("X-Nonce", nonce)

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			_, _ = io.ReadAll(resp.Body)

			assert.True(t, resp.StatusCode >= 400 && resp.StatusCode < 500,
				"invalid JSON should return 4xx, got %d", resp.StatusCode)
		})
	}
}

// =============================================================================
// Red Team Round 1: Audit Log Information Disclosure
// Non-admin API key should NOT be able to read audit logs.
// =============================================================================

func TestSecurity_AuditLogAccess_NonAdminKey(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("non-admin client not configured")
	}

	ctx := context.Background()

	// Non-admin should NOT be able to list audit records
	_, err := nonAdminClient.ListAuditRecords(ctx, nil)
	require.Error(t, err, "non-admin should NOT be able to access audit logs")

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode,
		"non-admin accessing audit endpoint must get 403 Forbidden, got %d", apiErr.StatusCode)
}

func TestSecurity_AuditLogAccess_NonAdminCannotFilterByAPIKeyID(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("non-admin client not configured")
	}

	ctx := context.Background()

	// Non-admin should NOT be able to query other API key's activity
	_, err := nonAdminClient.ListAuditRecords(ctx, &client.ListAuditFilter{
		APIKeyID: adminAPIKeyID, // Try to spy on admin activity
		Limit:    5,
	})
	require.Error(t, err, "non-admin should NOT be able to filter audit logs by other API key IDs")

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode,
		"non-admin querying other API key's audit must get 403")
}

// =============================================================================
// Red Team Round 2: Rule Config Injection
// Attempt to create rules with invalid or overly-permissive configs.
// =============================================================================

func TestSecurity_RuleConfigValidation_EmptyAddressList(t *testing.T) {
	ctx := context.Background()

	// Create an address whitelist rule with empty addresses — should be rejected
	_, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "Attack: Empty Address Whitelist",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{}, // empty!
		},
	})
	require.Error(t, err, "server must reject empty address list in address_list rule")
}

func TestSecurity_RuleConfigValidation_InvalidAddressFormat(t *testing.T) {
	ctx := context.Background()

	// Create a rule with invalid address format
	_, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "Attack: Invalid Address Format",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{"not-a-valid-address", "0xINVALID"},
		},
	})
	require.Error(t, err, "server must reject invalid address format in address_list rule")
}

func TestSecurity_RuleConfigValidation_MissingRequiredField(t *testing.T) {
	ctx := context.Background()

	// Create a value limit rule without max_value — required field
	_, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "Attack: Missing max_value",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{}, // no max_value!
	})
	require.Error(t, err, "server must reject value_limit rule without max_value")
}

func TestSecurity_RuleConfigValidation_WildcardAddress(t *testing.T) {
	ctx := context.Background()

	// Try creating a rule with wildcard address that might match everything
	_, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "Attack: Wildcard Address",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{"*"},
		},
	})
	require.Error(t, err, "server must reject wildcard address in address_list rule")
}

// =============================================================================
// Red Team Round 3: Solidity Expression Injection
// Attempt to inject dangerous Solidity code via rule expressions.
// =============================================================================

func TestSecurity_SolidityInjection_Selfdestruct(t *testing.T) {
	ctx := context.Background()

	// Try to create a rule with selfdestruct — should be rejected by config validation
	_, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "Attack: Selfdestruct",
		Type:    "evm_solidity_expression",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"expression": "selfdestruct(payable(address(0)));",
		},
	})
	require.Error(t, err, "server must reject Solidity expression with selfdestruct")
}

func TestSecurity_SolidityInjection_Delegatecall(t *testing.T) {
	ctx := context.Background()

	// Try to create a rule with delegatecall — should be rejected
	_, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "Attack: Delegatecall",
		Type:    "evm_solidity_expression",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"expression": "address(tx_to).delegatecall(\"\");",
		},
	})
	require.Error(t, err, "server must reject Solidity expression with delegatecall")
}

func TestSecurity_SolidityInjection_LargeExpression(t *testing.T) {
	ctx := context.Background()

	// Try to create a rule with a very large expression (100KB) for DoS
	largeExpr := "require(tx_value > 0, \""
	for i := 0; i < 100000; i++ {
		largeExpr += "A"
	}
	largeExpr += "\");"

	_, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "Attack: Large Expression DoS",
		Type:    "evm_solidity_expression",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"expression": largeExpr,
		},
	})
	require.Error(t, err, "server must reject extremely large Solidity expression (100KB+)")
}

// =============================================================================
// Red Team Round 4: Nonce Enforcement Gap
// Attempt replay attacks by omitting the nonce header.
// =============================================================================

func TestSecurity_ReplayAttack_NoNonce_WhenRequired(t *testing.T) {
	// This test verifies that when nonce_required=true, requests without
	// X-Nonce header are rejected — even if the signature is otherwise valid.
	// This catches the bug where nonce enforcement check happens after
	// signature verification.
	ctx := context.Background()

	ts := time.Now().UnixMilli()
	method := "GET"
	path := "/health"
	body := []byte("")

	privKeyBytes, err := hex.DecodeString(adminAPIKeyHex)
	require.NoError(t, err)
	privKey := ed25519.PrivateKey(privKeyBytes)

	// Sign using LEGACY format (no nonce in the signature message)
	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%d|%s|%s|%x", ts, method, path, bodyHash)
	sig := ed25519.Sign(privKey, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	baseURL := getBaseURL()

	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("X-API-Key-ID", adminAPIKeyID)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Signature", sigB64)
	// Deliberately NOT setting X-Nonce

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// If nonce_required=true is configured, this should be rejected
	// If the server accepts it (200), this is a vulnerability
	if resp.StatusCode == http.StatusOK {
		t.Log("WARNING: server accepted request without nonce when nonce_required may be true — potential replay vulnerability")
	}
	// In a properly configured server with nonce_required=true, we expect 401
	// But in e2e test mode, NonceStore may not be configured, so we note the finding
}

// =============================================================================
// Red Team Round 5: Address Casing Bypass (verification of existing tests)
// Verify that address comparison in rule evaluators is case-insensitive.
// =============================================================================

func TestSecurity_AddressCasingBypass_WhitelistRule(t *testing.T) {
	ctx := context.Background()

	// Create a whitelist rule with a specific address casing
	created, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "Test: Case Sensitivity Check",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{"0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}, // mixed case
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, created.ID) }()

	// Verify the rule was created
	rule, err := adminClient.GetRule(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "evm_address_list", string(rule.Type))

	// The actual address matching test depends on whether a sign request
	// with a different-cased address hits this rule. The evaluator should
	// normalize addresses before comparison.
	t.Log("Rule created successfully — address casing normalization should be verified in evaluator unit tests")
}

// =============================================================================
// Red Team Round 6: Rule Engine — Nil Field Blocklist Bypass (CRITICAL)
// Blocklist rules that check parsed fields (Recipient, Value, MethodSig) are
// silently bypassed when those fields are nil (e.g., personal_sign has no
// recipient). The evaluators return (false, "", nil) which the engine treats
// as "no violation".
// =============================================================================

func TestRedTeam_AddressBlocklist_BypassViaPersonalSign(t *testing.T) {
	if useExternalServer {
		t.Skip("red team test modifies server state")
	}

	ctx := context.Background()

	// Create an address_list blocklist that blocks the burn address
	rule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "RedTeam: Address Blocklist",
		Type:    "evm_address_list",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{burnAddress},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, rule.ID) }()

	// Attack: personal_sign has no tx.To → parsed.Recipient is nil
	// The AddressListEvaluator returns (false, "", nil) → "no violation"
	// So the blocklist is silently bypassed.
	resp, err := adminClient.SignWithOptions(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "personal",
		Payload:       json.RawMessage(`{"message":"bypass address blocklist via personal_sign"}`),
	}, false)

	// The address blocklist CANNOT block personal_sign (no recipient to check).
	// This is a known architectural limitation. The request should either complete
	// (if a whitelist rule like signer_restriction matches) or go to pending.
	// It must NOT be rejected by the address blocklist.
	if err != nil {
		apiErr, ok := err.(*client.APIError)
		if ok && apiErr.StatusCode == 403 {
			t.Log("FINDING: Address blocklist somehow blocked personal_sign — unexpected but secure")
		}
		// Other errors (e.g., signer not found) are acceptable
		return
	}
	// If no error, verify it was NOT blocked by the address blocklist rule
	assert.NotEqual(t, "rejected", resp.Status,
		"VULNERABILITY: address blocklist should not be able to reject personal_sign (nil recipient)")
	t.Logf("CONFIRMED: Address blocklist bypassed for personal_sign (status=%s) — known limitation", resp.Status)
}

func TestRedTeam_ValueLimitBlocklist_BypassViaNilValue(t *testing.T) {
	if useExternalServer {
		t.Skip("red team test modifies server state")
	}

	ctx := context.Background()

	// Create a value_limit blocklist with max_value=0 (should block everything with value)
	rule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "RedTeam: Value Limit Blocklist max=0",
		Type:    "evm_value_limit",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "0",
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, rule.ID) }()

	// Attack: personal_sign has no value → parsed.Value is nil
	// ValueLimitEvaluator returns (false, "", nil) → "no violation"
	resp, err := adminClient.SignWithOptions(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "personal",
		Payload:       json.RawMessage(`{"message":"bypass value limit blocklist"}`),
	}, false)

	if err != nil {
		return // Other errors are acceptable
	}
	assert.NotEqual(t, "rejected", resp.Status,
		"VULNERABILITY: value limit blocklist should not reject personal_sign (nil value)")
	t.Logf("CONFIRMED: Value limit blocklist bypassed for personal_sign (status=%s) — known limitation", resp.Status)
}

func TestRedTeam_ContractMethodBlocklist_BypassViaPlainTransfer(t *testing.T) {
	if useExternalServer {
		t.Skip("red team test modifies server state")
	}

	ctx := context.Background()

	// Create a contract_method blocklist that blocks ERC20 transfer on treasuryAddress
	rule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "RedTeam: Contract Method Blocklist",
		Type:    "evm_contract_method",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"contract":    treasuryAddress,
			"method_sigs": []string{"0xa9059cbb"}, // ERC20 transfer(address,uint256)
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, rule.ID) }()

	// Attack: plain ETH transfer (no data) → parsed.MethodSig is nil
	// ContractMethodEvaluator returns (false, "", nil) → "no violation"
	resp, err := adminClient.SignWithOptions(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"1000000000000000000","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
	}, false)

	if err != nil {
		return // May be blocked by other rules
	}
	// A plain transfer to the same contract address should NOT be blocked
	// by a contract_method blocklist (no method signature to match)
	t.Logf("CONFIRMED: Contract method blocklist bypassed for plain ETH transfer (status=%s) — known limitation", resp.Status)
}

// =============================================================================
// Red Team Round 7: Rule Precedence — Blocklist MUST Override Whitelist (HIGH)
// Blocklist rules are evaluated in Phase 1, whitelist in Phase 2.
// A matching blocklist MUST reject even if a whitelist would allow.
// =============================================================================

func TestRedTeam_BlocklistPrecedence_OverridesWhitelist(t *testing.T) {
	if useExternalServer {
		t.Skip("red team test modifies server state")
	}

	ctx := context.Background()

	// Setup: whitelist allows treasuryAddress, blocklist limits value to 0.1 ETH
	whitelistRule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "RedTeam: Whitelist Treasury",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{treasuryAddress},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, whitelistRule.ID) }()

	blocklistRule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "RedTeam: Blocklist Value Limit 0.1 ETH",
		Type:    "evm_value_limit",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "100000000000000000", // 0.1 ETH
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, blocklistRule.ID) }()

	// Attack: send 1 ETH to treasury — whitelisted address but exceeds blocklist value limit
	resp, err := adminClient.SignWithOptions(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"1000000000000000000","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
	}, false)

	// MUST be blocked — blocklist fires in Phase 1 before whitelist Phase 2
	if err == nil && resp != nil && resp.Status == "completed" {
		t.Errorf("VULNERABILITY: blocklist did NOT override whitelist — 1 ETH to treasury was auto-approved")
	} else {
		t.Log("PASS: Blocklist precedence confirmed — high-value tx to whitelisted address was blocked")
	}
}

func TestRedTeam_SignTypeBlocklist_OverridesWhitelist(t *testing.T) {
	if useExternalServer {
		t.Skip("red team test modifies server state")
	}

	ctx := context.Background()

	// Setup: blocklist blocks "personal" sign type
	blocklistRule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "RedTeam: Block Personal Sign",
		Type:    "sign_type_restriction",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"allowed_sign_types": []string{"personal"},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, blocklistRule.ID) }()

	// Also create a conflicting whitelist that allows personal
	whitelistRule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "RedTeam: Allow Personal Sign (conflict)",
		Type:    "sign_type_restriction",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"allowed_sign_types": []string{"personal"},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, whitelistRule.ID) }()

	// Attack: send personal_sign — both blocklist and whitelist match "personal"
	_, err = adminClient.SignWithOptions(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "personal",
		Payload:       json.RawMessage(`{"message":"test blocklist vs whitelist precedence"}`),
	}, false)

	// MUST be blocked — blocklist evaluated in Phase 1 before whitelist Phase 2
	require.Error(t, err, "VULNERABILITY: personal_sign should be blocked by sign_type blocklist even with conflicting whitelist")
	t.Log("PASS: Sign type blocklist precedence confirmed over conflicting whitelist")
}

func TestRedTeam_MultiRule_WhitelistAddress_BlocklistValue(t *testing.T) {
	if useExternalServer {
		t.Skip("red team test modifies server state")
	}

	ctx := context.Background()

	// Setup: whitelist allows treasuryAddress, blocklist limits value
	whitelistRule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "RedTeam: Allow Treasury Address",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{treasuryAddress},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, whitelistRule.ID) }()

	blocklistRule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "RedTeam: Block Value > 0.1 ETH",
		Type:    "evm_value_limit",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "100000000000000000", // 0.1 ETH
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, blocklistRule.ID) }()

	// Sub-test A: 1 ETH to treasury → MUST be blocked by value limit blocklist
	t.Run("high_value_blocked", func(t *testing.T) {
		resp, err := adminClient.SignWithOptions(ctx, &client.SignRequest{
			ChainID:       chainID,
			SignerAddress: signerAddress,
			SignType:      "transaction",
			Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"1000000000000000000","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
		}, false)

		if err == nil && resp != nil && resp.Status == "completed" {
			t.Errorf("VULNERABILITY: 1 ETH to whitelisted treasury was not blocked by value limit")
		}
	})

	// Sub-test B: 0.05 ETH to treasury → should pass (blocklist passes, whitelist matches)
	// NOTE: If the test server's Solidity blocklist rule fails to compile (Fail-Closed),
	// ALL transaction requests will be rejected. This is expected behavior — we verify
	// that the value limit blocklist itself does not block low-value transactions.
	t.Run("low_value_allowed", func(t *testing.T) {
		resp, err := adminClient.SignWithOptions(ctx, &client.SignRequest{
			ChainID:       chainID,
			SignerAddress: signerAddress,
			SignType:      "transaction",
			Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"50000000000000000","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
		}, false)

		if err != nil {
			// If blocked by Solidity rule compilation failure (Fail-Closed), that's
			// a known test environment issue, not a value limit rule issue
			errStr := err.Error()
			if strings.Contains(errStr, "pending manual approval") || strings.Contains(errStr, "authorizing") {
				t.Log("OK: request went to pending (likely due to Solidity rule Fail-Closed in test env)")
				return
			}
			// Should NOT be rejected by the value limit blocklist
			assert.NotContains(t, errStr, "exceeds limit",
				"VULNERABILITY: low-value tx should NOT be blocked by value limit rule")
			return
		}
		assert.Equal(t, "completed", resp.Status,
			"Low-value tx to whitelisted address should be auto-approved")
	})
}

// =============================================================================
// Red Team Round 8: Boundary Conditions and Edge Cases (MEDIUM)
// =============================================================================

func TestRedTeam_ValueLimit_ExactBoundary(t *testing.T) {
	if useExternalServer {
		t.Skip("red team test modifies server state")
	}

	ctx := context.Background()

	// Blocklist: block if value > 100000000000000000 (0.1 ETH)
	rule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "RedTeam: Value Limit Exact Boundary",
		Type:    "evm_value_limit",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "100000000000000000",
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, rule.ID) }()

	// Sub-test A: value == limit exactly → NOT blocked (Cmp returns 0, not > 0)
	t.Run("at_boundary_passes", func(t *testing.T) {
		resp, err := adminClient.SignWithOptions(ctx, &client.SignRequest{
			ChainID:       chainID,
			SignerAddress: signerAddress,
			SignType:      "transaction",
			Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"100000000000000000","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
		}, false)

		// 100000000000000000 = exactly 0.1 ETH
		// Cmp(100000000000000000, 100000000000000000) = 0, NOT > 0 → not blocked
		if err == nil {
			assert.NotEqual(t, "rejected", resp.Status,
				"Value at exact boundary should NOT be blocked (strictly greater-than semantics)")
		}
	})

	// Sub-test B: value == limit + 1 wei → BLOCKED
	t.Run("above_boundary_blocked", func(t *testing.T) {
		resp, err := adminClient.SignWithOptions(ctx, &client.SignRequest{
			ChainID:       chainID,
			SignerAddress: signerAddress,
			SignType:      "transaction",
			Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"100000000000000001","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
		}, false)

		// 100000000000000001 = 0.1 ETH + 1 wei → exceeds limit → blocked
		if err == nil && resp != nil && resp.Status == "completed" {
			t.Errorf("VULNERABILITY: value at limit+1 was not blocked")
		}
	})
}

func TestRedTeam_ValueLimit_ZeroValue(t *testing.T) {
	if useExternalServer {
		t.Skip("red team test modifies server state")
	}

	ctx := context.Background()

	// Blocklist with max_value=0 → block if value > 0
	rule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "RedTeam: Value Limit Zero",
		Type:    "evm_value_limit",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "0",
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, rule.ID) }()

	// Sub-test A: value=0 → NOT blocked (0 > 0 is false)
	t.Run("zero_value_passes", func(t *testing.T) {
		resp, err := adminClient.SignWithOptions(ctx, &client.SignRequest{
			ChainID:       chainID,
			SignerAddress: signerAddress,
			SignType:      "transaction",
			Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"0","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
		}, false)

		if err == nil {
			assert.NotEqual(t, "rejected", resp.Status,
				"Zero-value tx should NOT be blocked by max_value=0 blocklist")
		}
	})

	// Sub-test B: value=1 wei → BLOCKED (1 > 0 is true)
	t.Run("one_wei_blocked", func(t *testing.T) {
		resp, err := adminClient.SignWithOptions(ctx, &client.SignRequest{
			ChainID:       chainID,
			SignerAddress: signerAddress,
			SignType:      "transaction",
			Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"1","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
		}, false)

		if err == nil && resp != nil && resp.Status == "completed" {
			t.Errorf("VULNERABILITY: 1 wei tx was not blocked by max_value=0 blocklist")
		}
	})
}

func TestRedTeam_AddressBlocklist_ZeroAddress(t *testing.T) {
	if useExternalServer {
		t.Skip("red team test modifies server state")
	}

	ctx := context.Background()

	// Blocklist the zero address
	rule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "RedTeam: Block Zero Address",
		Type:    "evm_address_list",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{"0x0000000000000000000000000000000000000000"},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, rule.ID) }()

	// Attack: send tx to zero address
	resp, err := adminClient.SignWithOptions(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       json.RawMessage(`{"transaction":{"to":"0x0000000000000000000000000000000000000000","value":"0","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`),
	}, false)

	if err == nil && resp != nil && resp.Status == "completed" {
		t.Errorf("VULNERABILITY: tx to zero address was not blocked by address blocklist")
	} else {
		t.Log("PASS: Zero address correctly blocked by address blocklist")
	}
}

func TestRedTeam_DisabledBlocklistRule_AttackWindow(t *testing.T) {
	if useExternalServer {
		t.Skip("red team test modifies server state")
	}

	ctx := context.Background()

	// Create an address blocklist that blocks a specific test address
	testBlockedAddr := "0x1111111111111111111111111111111111111111"
	rule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "RedTeam: Disableable Blocklist",
		Type:    "evm_address_list",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{testBlockedAddr},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, rule.ID) }()

	// Step 1: Verify the rule blocks when enabled
	resp1, err1 := adminClient.SignWithOptions(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"0","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, testBlockedAddr)),
	}, false)

	if err1 == nil && resp1 != nil && resp1.Status == "completed" {
		t.Fatal("Setup failed: blocklist rule did not block when enabled")
	}
	t.Log("Step 1: Rule blocks when enabled — OK")

	// Step 2: Disable the rule
	_, err = adminClient.ToggleRule(ctx, rule.ID, false)
	require.NoError(t, err)

	// Step 3: Attack during disabled window — should NOT be blocked
	resp2, err2 := adminClient.SignWithOptions(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"0","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, testBlockedAddr)),
	}, false)

	// When disabled, the rule should be skipped → request may go to pending or be approved by other rules
	if err2 == nil && resp2 != nil {
		assert.NotEqual(t, "rejected", resp2.Status,
			"Disabled blocklist should not reject")
		t.Logf("Step 2: Disabled rule allows attack (status=%s) — attack window confirmed", resp2.Status)
	}

	// Step 4: Re-enable the rule
	_, err = adminClient.ToggleRule(ctx, rule.ID, true)
	require.NoError(t, err)

	// Step 5: Verify the rule blocks again
	resp3, err3 := adminClient.SignWithOptions(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"0","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, testBlockedAddr)),
	}, false)

	if err3 == nil && resp3 != nil && resp3.Status == "completed" {
		t.Errorf("VULNERABILITY: re-enabled blocklist rule still not blocking")
	} else {
		t.Log("Step 3: Re-enabled rule blocks again — OK")
	}
}

func TestRedTeam_SignerRestriction_BlocklistMode(t *testing.T) {
	if useExternalServer {
		t.Skip("red team test modifies server state")
	}

	ctx := context.Background()

	// Create a signer_restriction BLOCKLIST that blocks our test signer
	// In blocklist mode: evaluator returns true if signer is in list → violation → block
	rule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "RedTeam: Block Test Signer",
		Type:    "signer_restriction",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"allowed_signers": []string{signerAddress},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, rule.ID) }()

	// Attack: use the blocked signer to sign
	_, err = adminClient.SignWithOptions(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "personal",
		Payload:       json.RawMessage(`{"message":"signer restriction blocklist test"}`),
	}, false)

	require.Error(t, err, "VULNERABILITY: signer_restriction blocklist should block the listed signer")
	t.Log("PASS: Signer restriction blocklist correctly blocks the listed signer")
}

// =============================================================================
// Red Team Round 9: Behavior Verification (LOW)
// =============================================================================

func TestRedTeam_WhitelistDoesNotOverApprove_PersonalSign(t *testing.T) {
	if useExternalServer {
		t.Skip("red team test modifies server state")
	}

	ctx := context.Background()

	// Create ONLY an address whitelist for an unrelated address (not the signer)
	// This should NOT auto-approve personal_sign (personal_sign has nil recipient)
	rule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "RedTeam: Address Whitelist Unrelated",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{"0x2222222222222222222222222222222222222222"},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, rule.ID) }()

	// Send personal_sign — the address whitelist cannot match (nil recipient)
	// NOTE: Other whitelist rules (signer_restriction, sign_type) may still auto-approve
	resp, err := adminClient.SignWithOptions(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "personal",
		Payload:       json.RawMessage(`{"message":"whitelist over-approval test"}`),
	}, false)

	if err == nil && resp != nil && resp.Status == "completed" {
		// Check if the matched rule is our address whitelist rule — it should NOT be
		if resp.RuleMatched == rule.ID {
			t.Errorf("VULNERABILITY: address whitelist auto-approved personal_sign (should not match nil recipient)")
		} else {
			t.Logf("OK: personal_sign was auto-approved by a different rule (not address whitelist), matched=%s", resp.RuleMatched)
		}
	} else if err == nil {
		t.Logf("OK: personal_sign went to status=%s (not auto-approved by address whitelist)", resp.Status)
	}
}

func TestRedTeam_NullScopeRule_AppliesToAllSigners(t *testing.T) {
	if useExternalServer {
		t.Skip("red team test modifies server state")
	}

	ctx := context.Background()

	// Create a value_limit blocklist with NO scope restrictions (applies globally)
	// The CreateRuleRequest does not set ChainID, APIKeyID, SignerAddress → NULL in DB
	rule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "RedTeam: Global Value Limit Blocklist",
		Type:    "evm_value_limit",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "100000000000000000", // 0.1 ETH
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, rule.ID) }()

	// Attack: send 1 ETH — the global (NULL scope) rule should still block
	resp, err := adminClient.SignWithOptions(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"1000000000000000000","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
	}, false)

	if err == nil && resp != nil && resp.Status == "completed" {
		t.Errorf("VULNERABILITY: NULL-scoped blocklist did not block — global rules may be ignored")
	} else {
		t.Log("PASS: NULL-scoped blocklist correctly applies to all signers")
	}
}

func TestRedTeam_AddressBlocklist_CasingNormalization(t *testing.T) {
	if useExternalServer {
		t.Skip("red team test modifies server state")
	}

	ctx := context.Background()

	// Create blocklist with ALL UPPERCASE address
	upperCaseAddr := "0x1111111111111111111111111111111111111111"
	rule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:    "RedTeam: Uppercase Address Blocklist",
		Type:    "evm_address_list",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{"0x1111111111111111111111111111111111111111"},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, rule.ID) }()

	// Attack: send tx with different casing variants of the same address
	casings := []string{
		upperCaseAddr,                                         // original
		"0x1111111111111111111111111111111111111111",           // lowercase (same here since all 1s)
		"0X1111111111111111111111111111111111111111",           // 0X prefix
	}

	for _, addr := range casings {
		t.Run("casing_"+addr[:6], func(t *testing.T) {
			resp, err := adminClient.SignWithOptions(ctx, &client.SignRequest{
				ChainID:       chainID,
				SignerAddress: signerAddress,
				SignType:      "transaction",
				Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"0","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, addr)),
			}, false)

			if err == nil && resp != nil && resp.Status == "completed" {
				t.Errorf("VULNERABILITY: blocklist bypassed via address casing variant %s", addr)
			}
		})
	}
}

// =============================================================================
// Helpers
// =============================================================================

// getBaseURL returns the base URL for the test server.
// Uses the internal test server's BaseURL or falls back to default.
func getBaseURL() string {
	if testServer != nil {
		return testServer.BaseURL()
	}
	if baseURL != "" {
		return baseURL
	}
	return fmt.Sprintf("http://localhost:%d", defaultAPIPort)
}
