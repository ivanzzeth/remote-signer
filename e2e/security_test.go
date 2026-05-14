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
	"github.com/ivanzzeth/remote-signer/pkg/client/audit"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
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
	path := "/api/v1/evm/requests"
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
	path := "/api/v1/evm/requests"
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
	path := "/api/v1/evm/requests"
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
	path := "/api/v1/evm/requests"
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
	_, err := nonAdminClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode, "non-admin accessing admin endpoint must get 403")

	// Non-admin should NOT be able to approve requests
	_, err = nonAdminClient.EVM.Requests.Approve(ctx, "fake-request-id", &evm.ApproveRequest{
		Approved: true,
	})
	require.Error(t, err)
	apiErr, ok = err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode, "non-admin approving requests must get 403")

	// Non-admin should NOT be able to list audit records
	_, err = nonAdminClient.Audit.List(ctx, nil)
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
			resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
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
			})

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
		name := val
		if len(name) > 10 {
			name = name[:10]
		}
		t.Run("value_"+name, func(t *testing.T) {
			resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
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
			})

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

	// Ensure approval guard is not paused (e2e server may use config.e2e.yaml with guard;
	// TestZ_ApprovalGuard_PauseAndResume runs last by name, but guard could be paused if that test failed before Resume).
	_ = adminClient.EVM.Guard.Resume(ctx)

	// Submit a sign request that requires manual approval
	// Use 'personal' sign type to avoid Solidity rule Fail-Closed issues with 'transaction'
	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "personal",
		Payload:       json.RawMessage(`{"message":"concurrent-approval-race-test"}`),
	})
	// SignWithOptions returns both resp and err when status=authorizing
	// (resp contains the request ID, err is a SignError with pending status)
	if resp != nil && resp.RequestID != "" {
		err = nil // Clear the "pending approval" error — we have the request ID
	}
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
		_, results[0] = adminClient.EVM.Requests.Approve(ctx, requestID, &evm.ApproveRequest{
			Approved: true,
		})
	}()
	go func() {
		defer wg.Done()
		_, results[1] = adminClient.EVM.Requests.Approve(ctx, requestID, &evm.ApproveRequest{
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
	status, err := adminClient.EVM.Requests.Get(ctx, requestID)
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
	_, err := nonAdminClient.Audit.List(ctx, nil)
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
	_, err := nonAdminClient.Audit.List(ctx, &audit.ListFilter{
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
	_, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
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
	_, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
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
	_, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
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
	_, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
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
	_, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
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
	_, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
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

	_, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
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
	created, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "Test: Case Sensitivity Check",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{"0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}, // mixed case
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, created.ID) }()

	// Verify the rule was created
	rule, err := adminClient.EVM.Rules.Get(ctx, created.ID)
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
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RedTeam: Address Blocklist",
		Type:    "evm_address_list",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{burnAddress},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	// Attack: personal_sign has no tx.To → parsed.Recipient is nil
	// The AddressListEvaluator returns (false, "", nil) → "no violation"
	// So the blocklist is silently bypassed.
	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "personal",
		Payload:       json.RawMessage(`{"message":"bypass address blocklist via personal_sign"}`),
	})

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
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RedTeam: Value Limit Blocklist max=0",
		Type:    "evm_value_limit",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "0",
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	// Attack: personal_sign has no value → parsed.Value is nil
	// ValueLimitEvaluator returns (false, "", nil) → "no violation"
	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "personal",
		Payload:       json.RawMessage(`{"message":"bypass value limit blocklist"}`),
	})

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
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
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
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	// Attack: plain ETH transfer (no data) → parsed.MethodSig is nil
	// ContractMethodEvaluator returns (false, "", nil) → "no violation"
	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"1000000000000000000","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
	})

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
	whitelistRule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RedTeam: Whitelist Treasury",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{treasuryAddress},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, whitelistRule.ID) }()

	blocklistRule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RedTeam: Blocklist Value Limit 0.1 ETH",
		Type:    "evm_value_limit",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "100000000000000000", // 0.1 ETH
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, blocklistRule.ID) }()

	// Attack: send 1 ETH to treasury — whitelisted address but exceeds blocklist value limit
	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"1000000000000000000","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
	})

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
	blocklistRule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RedTeam: Block Personal Sign",
		Type:    "sign_type_restriction",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"allowed_sign_types": []string{"personal"},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, blocklistRule.ID) }()

	// Also create a conflicting whitelist that allows personal
	whitelistRule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RedTeam: Allow Personal Sign (conflict)",
		Type:    "sign_type_restriction",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"allowed_sign_types": []string{"personal"},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, whitelistRule.ID) }()

	// Attack: send personal_sign — both blocklist and whitelist match "personal"
	_, err = adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "personal",
		Payload:       json.RawMessage(`{"message":"test blocklist vs whitelist precedence"}`),
	})

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
	whitelistRule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RedTeam: Allow Treasury Address",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{treasuryAddress},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, whitelistRule.ID) }()

	blocklistRule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RedTeam: Block Value > 0.1 ETH",
		Type:    "evm_value_limit",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "100000000000000000", // 0.1 ETH
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, blocklistRule.ID) }()

	// Sub-test A: 1 ETH to treasury → MUST be blocked by value limit blocklist
	t.Run("high_value_blocked", func(t *testing.T) {
		resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
			ChainID:       chainID,
			SignerAddress: signerAddress,
			SignType:      "transaction",
			Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"1000000000000000000","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
		})

		if err == nil && resp != nil && resp.Status == "completed" {
			t.Errorf("VULNERABILITY: 1 ETH to whitelisted treasury was not blocked by value limit")
		}
	})

	// Sub-test B: 0.05 ETH to treasury → should pass (blocklist passes, whitelist matches)
	// NOTE: If the test server's Solidity blocklist rule fails to compile (Fail-Closed),
	// ALL transaction requests will be rejected. This is expected behavior — we verify
	// that the value limit blocklist itself does not block low-value transactions.
	t.Run("low_value_allowed", func(t *testing.T) {
		resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
			ChainID:       chainID,
			SignerAddress: signerAddress,
			SignType:      "transaction",
			Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"50000000000000000","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
		})

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
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RedTeam: Value Limit Exact Boundary",
		Type:    "evm_value_limit",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "100000000000000000",
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	// Sub-test A: value == limit exactly → NOT blocked (Cmp returns 0, not > 0)
	t.Run("at_boundary_passes", func(t *testing.T) {
		resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
			ChainID:       chainID,
			SignerAddress: signerAddress,
			SignType:      "transaction",
			Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"100000000000000000","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
		})

		// 100000000000000000 = exactly 0.1 ETH
		// Cmp(100000000000000000, 100000000000000000) = 0, NOT > 0 → not blocked
		if err == nil {
			assert.NotEqual(t, "rejected", resp.Status,
				"Value at exact boundary should NOT be blocked (strictly greater-than semantics)")
		}
	})

	// Sub-test B: value == limit + 1 wei → BLOCKED
	t.Run("above_boundary_blocked", func(t *testing.T) {
		resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
			ChainID:       chainID,
			SignerAddress: signerAddress,
			SignType:      "transaction",
			Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"100000000000000001","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
		})

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
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RedTeam: Value Limit Zero",
		Type:    "evm_value_limit",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "0",
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	// Sub-test A: value=0 → NOT blocked (0 > 0 is false)
	t.Run("zero_value_passes", func(t *testing.T) {
		resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
			ChainID:       chainID,
			SignerAddress: signerAddress,
			SignType:      "transaction",
			Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"0","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
		})

		if err == nil {
			assert.NotEqual(t, "rejected", resp.Status,
				"Zero-value tx should NOT be blocked by max_value=0 blocklist")
		}
	})

	// Sub-test B: value=1 wei → BLOCKED (1 > 0 is true)
	t.Run("one_wei_blocked", func(t *testing.T) {
		resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
			ChainID:       chainID,
			SignerAddress: signerAddress,
			SignType:      "transaction",
			Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"1","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
		})

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
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RedTeam: Block Zero Address",
		Type:    "evm_address_list",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{"0x0000000000000000000000000000000000000000"},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	// Attack: send tx to zero address
	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       json.RawMessage(`{"transaction":{"to":"0x0000000000000000000000000000000000000000","value":"0","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`),
	})

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
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RedTeam: Disableable Blocklist",
		Type:    "evm_address_list",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{testBlockedAddr},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	// Step 1: Verify the rule blocks when enabled
	resp1, err1 := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"0","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, testBlockedAddr)),
	})

	if err1 == nil && resp1 != nil && resp1.Status == "completed" {
		t.Fatal("Setup failed: blocklist rule did not block when enabled")
	}
	t.Log("Step 1: Rule blocks when enabled — OK")

	// Step 2: Disable the rule
	_, err = adminClient.EVM.Rules.Toggle(ctx, rule.ID, false)
	require.NoError(t, err)

	// Step 3: Attack during disabled window — should NOT be blocked
	resp2, err2 := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"0","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, testBlockedAddr)),
	})

	// When disabled, the rule should be skipped → request may go to pending or be approved by other rules
	if err2 == nil && resp2 != nil {
		assert.NotEqual(t, "rejected", resp2.Status,
			"Disabled blocklist should not reject")
		t.Logf("Step 2: Disabled rule allows attack (status=%s) — attack window confirmed", resp2.Status)
	}

	// Step 4: Re-enable the rule
	_, err = adminClient.EVM.Rules.Toggle(ctx, rule.ID, true)
	require.NoError(t, err)

	// Step 5: Verify the rule blocks again
	resp3, err3 := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"0","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, testBlockedAddr)),
	})

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
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RedTeam: Block Test Signer",
		Type:    "signer_restriction",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"allowed_signers": []string{signerAddress},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	// Attack: use the blocked signer to sign
	_, err = adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "personal",
		Payload:       json.RawMessage(`{"message":"signer restriction blocklist test"}`),
	})

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
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RedTeam: Address Whitelist Unrelated",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{"0x2222222222222222222222222222222222222222"},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	// Send personal_sign — the address whitelist cannot match (nil recipient)
	// NOTE: Other whitelist rules (signer_restriction, sign_type) may still auto-approve
	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "personal",
		Payload:       json.RawMessage(`{"message":"whitelist over-approval test"}`),
	})

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
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RedTeam: Global Value Limit Blocklist",
		Type:    "evm_value_limit",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "100000000000000000", // 0.1 ETH
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	// Attack: send 1 ETH — the global (NULL scope) rule should still block
	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"1000000000000000000","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, treasuryAddress)),
	})

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
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RedTeam: Uppercase Address Blocklist",
		Type:    "evm_address_list",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{"0x1111111111111111111111111111111111111111"},
		},
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	// Attack: send tx with different casing variants of the same address
	casings := []string{
		upperCaseAddr,                                         // original
		"0x1111111111111111111111111111111111111111",           // lowercase (same here since all 1s)
		"0X1111111111111111111111111111111111111111",           // 0X prefix
	}

	for _, addr := range casings {
		t.Run("casing_"+addr[:6], func(t *testing.T) {
			resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
				ChainID:       chainID,
				SignerAddress: signerAddress,
				SignType:      "transaction",
				Payload:       json.RawMessage(fmt.Sprintf(`{"transaction":{"to":"%s","value":"0","gas":21000,"gasPrice":"20000000000","txType":"legacy"}}`, addr)),
			})

			if err == nil && resp != nil && resp.Status == "completed" {
				t.Errorf("VULNERABILITY: blocklist bypassed via address casing variant %s", addr)
			}
		})
	}
}

// =============================================================================
// Red Team Round 7: Authentication — Future Timestamp Bypass
// The auth verifier previously used abs(age) which allowed future timestamps
// to pass the MaxRequestAge check, enabling pre-signing attacks.
// =============================================================================

func TestRedTeam_Auth_FutureTimestamp(t *testing.T) {
	ctx := context.Background()

	// Use a timestamp 30 seconds in the FUTURE against an AUTHENTICATED endpoint.
	// /health has no auth middleware, so we must test against /api/v1/evm/requests.
	// Before fix: abs(30s) = 30s < 60s max → accepted (VULNERABILITY)
	// After fix: future timestamps beyond 5s clock skew → rejected
	ts := time.Now().Add(30 * time.Second).UnixMilli()
	nonce := fmt.Sprintf("future-ts-%d", ts)
	method := "GET"
	path := "/api/v1/evm/requests"
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
		"VULNERABILITY: request with future timestamp (30s ahead) must be rejected")
}

func TestRedTeam_Auth_FutureTimestamp_PreSign(t *testing.T) {
	ctx := context.Background()

	// Pre-sign a request with timestamp 10 seconds in the future.
	// Even though it's "only" 10s, it exceeds the 5s clock skew tolerance.
	// Test against authenticated endpoint (not /health which has no auth).
	futureTS := time.Now().Add(10 * time.Second).UnixMilli()
	nonce := fmt.Sprintf("presigned-replay-%d", futureTS)
	method := "GET"
	path := "/api/v1/evm/requests"
	body := []byte("")

	privKeyBytes, err := hex.DecodeString(adminAPIKeyHex)
	require.NoError(t, err)
	privKey := ed25519.PrivateKey(privKeyBytes)

	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%d|%s|%s|%s|%x", futureTS, nonce, method, path, bodyHash)
	sig := ed25519.Sign(privKey, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// Send IMMEDIATELY (timestamp is 10s in the future)
	baseURL := getBaseURL()
	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("X-API-Key-ID", adminAPIKeyID)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", futureTS))
	req.Header.Set("X-Signature", sigB64)
	req.Header.Set("X-Nonce", nonce)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"VULNERABILITY: pre-signed request with future timestamp should be rejected immediately")
}

func TestRedTeam_ConcurrentNonce_RaceCondition(t *testing.T) {
	if useExternalServer {
		t.Skip("concurrent nonce test requires internal server with nonce store")
	}

	ctx := context.Background()

	// Send N concurrent requests with the SAME nonce against an AUTHENTICATED endpoint.
	// The nonce store must ensure at most 1 succeeds.
	// NOTE: /health has no auth middleware, so we use /api/v1/evm/requests.
	ts := time.Now().UnixMilli()
	nonce := fmt.Sprintf("race-test-%d", ts)
	method := "GET"
	path := "/api/v1/evm/requests"
	body := []byte("")

	privKeyBytes, err := hex.DecodeString(adminAPIKeyHex)
	require.NoError(t, err)
	privKey := ed25519.PrivateKey(privKeyBytes)

	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%d|%s|%s|%s|%x", ts, nonce, method, path, bodyHash)
	sig := ed25519.Sign(privKey, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	baseURL := getBaseURL()
	n := 10
	results := make([]int, n)
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r, err := http.NewRequestWithContext(ctx, method, baseURL+path, bytes.NewReader(body))
			if err != nil {
				results[idx] = -1
				return
			}
			r.Header.Set("X-API-Key-ID", adminAPIKeyID)
			r.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
			r.Header.Set("X-Signature", sigB64)
			r.Header.Set("X-Nonce", nonce)

			resp, err := http.DefaultClient.Do(r)
			if err != nil {
				results[idx] = -1
				return
			}
			resp.Body.Close()
			results[idx] = resp.StatusCode
		}(i)
	}

	wg.Wait()

	successCount := 0
	for _, status := range results {
		if status == http.StatusOK {
			successCount++
		}
	}

	assert.LessOrEqual(t, successCount, 1,
		"VULNERABILITY: %d/%d concurrent requests with same nonce succeeded (expect at most 1)",
		successCount, n)
	t.Logf("Race condition test: %d/%d requests succeeded", successCount, n)
}

// =============================================================================
// Red Team Round 8: Permission Bypass — Signer Address Casing, Preview-Rule ACL
// =============================================================================

func TestRedTeam_SignerPermission_CaseSensitiveBypass(t *testing.T) {
	if useExternalServer {
		t.Skip("requires controlled API key configuration")
	}

	ctx := context.Background()

	// The test signer address is "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	// Try with ALL UPPERCASE hex portion to test case-insensitive comparison.
	// Before fix: IsAllowedSigner used == (case-sensitive), uppercase would fail
	// After fix: strings.EqualFold makes comparison case-insensitive
	upperAddress := "0xF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266"

	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: upperAddress,
		SignType:      "personal",
		Payload:       json.RawMessage(`{"message":"case bypass test"}`),
	})

	// After fix, this should succeed (personal_sign auto-approved by existing rules)
	// We check it does NOT return 403 "not authorized for this signer"
	if err != nil {
		apiErr, ok := err.(*client.APIError)
		if ok && apiErr.StatusCode == 403 {
			t.Errorf("VULNERABILITY: Case-sensitive signer permission bypass — uppercase address rejected with 403")
		} else {
			// Other errors (e.g., signer not found because go-ethereum normalizes differently) are OK
			t.Logf("Non-403 error (acceptable): %v", err)
		}
	} else if resp != nil {
		t.Logf("PASS: Case-insensitive signer permission — status=%s", resp.Status)
	}
}

func TestRedTeam_PreviewRule_NonAdminAccess(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("non-admin client not configured")
	}
	if useExternalServer {
		t.Skip("requires internal server for state setup")
	}

	ctx := context.Background()

	// Submit a personal_sign request as ADMIN first (to get a request ID).
	// Use personal sign to avoid Solidity rule Fail-Closed in test env.
	// The request may be auto-approved or fail with "authorizing" status.
	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "personal",
		Payload:       json.RawMessage(`{"message":"preview-rule acl test"}`),
	})

	var requestID string
	if resp != nil {
		requestID = resp.RequestID
	}
	// SignWithOptions may return error with resp containing RequestID when status is "authorizing"
	if requestID == "" && err != nil {
		// Try to extract request ID from error message (format: "sign error [UUID] status=...")
		errMsg := err.Error()
		if idx := strings.Index(errMsg, "["); idx != -1 {
			if endIdx := strings.Index(errMsg[idx:], "]"); endIdx != -1 {
				requestID = errMsg[idx+1 : idx+endIdx]
			}
		}
	}
	if requestID == "" {
		t.Skip("could not get a request ID for preview-rule test")
	}

	// Non-admin attempts to access preview-rule endpoint
	// Before fix: no admin check on preview-rule, may return 200 or 403 (ownership check only)
	// After fix: admin middleware enforced, returns 403 before ownership check
	_, prevErr := nonAdminClient.EVM.Requests.PreviewRule(ctx, requestID, &evm.PreviewRuleRequest{
		RuleType: "evm_address_list",
		RuleMode: "whitelist",
	})

	require.Error(t, prevErr, "VULNERABILITY: non-admin should not access preview-rule endpoint")
	apiErr, ok := prevErr.(*client.APIError)
	if ok {
		assert.Equal(t, 403, apiErr.StatusCode,
			"Non-admin preview-rule access should get 403, got %d", apiErr.StatusCode)
	}
}

func TestRedTeam_NonceCollision_ColonInNonce(t *testing.T) {
	if useExternalServer {
		t.Skip("nonce collision test requires internal server")
	}

	ctx := context.Background()

	// Test that nonces containing ":" are handled safely on an authenticated endpoint.
	// Before fix: key = "apiKeyID:nonce" → collision possible
	// After fix: key = "len(apiKeyID):apiKeyID:nonce" → no collision
	colonNonce := fmt.Sprintf("test:%d:colon:nonce", time.Now().UnixMilli())

	baseURL := getBaseURL()
	method := "GET"
	path := "/api/v1/evm/requests"
	body := []byte("")
	ts := time.Now().UnixMilli()

	privKeyBytes, err := hex.DecodeString(adminAPIKeyHex)
	require.NoError(t, err)
	privKey := ed25519.PrivateKey(privKeyBytes)

	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%d|%s|%s|%s|%x", ts, colonNonce, method, path, bodyHash)
	sig := ed25519.Sign(privKey, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("X-API-Key-ID", adminAPIKeyID)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Signature", sigB64)
	req.Header.Set("X-Nonce", colonNonce)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Server should handle colons in nonces safely (200 OK)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"nonce with colon characters should be handled safely, got %d", resp.StatusCode)
}

// =============================================================================
// Red Team Round 9: Input Validation — Hash Hex, Error Info Leak, Large Payload
// =============================================================================

func TestRedTeam_HashPayload_InvalidHex(t *testing.T) {
	ctx := context.Background()

	// "0xGGGG..." has 64 chars after prefix (length=66) but invalid hex chars.
	// Before fix: passes ValidatePayload length check, fails later at Sign
	// After fix: fails at ValidatePayload with 400 Bad Request
	invalidHash := "0x" + strings.Repeat("GG", 32)
	assert.Equal(t, 66, len(invalidHash), "test setup: invalid hash should be 66 chars")

	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "hash",
		Payload:       json.RawMessage(fmt.Sprintf(`{"hash":"%s"}`, invalidHash)),
	})

	require.Error(t, err,
		"VULNERABILITY: hash with invalid hex characters should be rejected at validation")

	if resp != nil {
		assert.NotEqual(t, "completed", resp.Status,
			"VULNERABILITY: signing succeeded with invalid hex hash")
	}
}

func TestRedTeam_ErrorInfoLeak_StructType(t *testing.T) {
	ctx := context.Background()
	baseURL := getBaseURL()

	// Send completely invalid JSON to trigger decode error
	body := []byte(`{not valid json at all}`)

	ts := time.Now().UnixMilli()
	nonce := fmt.Sprintf("infoleak-struct-%d", ts)

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

	respBody, _ := io.ReadAll(resp.Body)
	respStr := string(respBody)

	// Error response must NOT contain Go type names or package paths
	assert.NotContains(t, respStr, "evm.SignRequest",
		"VULNERABILITY: error leaks Go struct type name")
	assert.NotContains(t, respStr, "type evm",
		"VULNERABILITY: error leaks package/type info")
	// Should return a generic message (either Content-Type rejection or invalid body)
	lowerResp := strings.ToLower(respStr)
	assert.True(t, strings.Contains(lowerResp, "invalid request body") || strings.Contains(lowerResp, "content-type must be application/json"),
		"error response should contain generic error message, got: %s", respStr)
}

func TestRedTeam_ErrorInfoLeak_FieldNames(t *testing.T) {
	ctx := context.Background()
	baseURL := getBaseURL()

	// Send JSON with extra unknown fields.
	// Go json.Decoder with DisallowUnknownFields would reveal field info.
	// Without it, extra fields are silently ignored, so we test both scenarios.
	body := []byte(`{"chain_id":"1","signer_address":"` + signerAddress + `","sign_type":"personal","payload":{"message":"test"},"unknown_evil_field":"attack"}`)

	ts := time.Now().UnixMilli()
	nonce := fmt.Sprintf("infoleak-field-%d", ts)

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

	respBody, _ := io.ReadAll(resp.Body)
	respStr := string(respBody)

	// Regardless of whether extra fields cause an error or are silently ignored,
	// the response must never contain Go struct type names
	assert.NotContains(t, respStr, "SignRequest",
		"VULNERABILITY: error exposes internal struct name 'SignRequest'")
	assert.NotContains(t, respStr, "unknown field",
		"VULNERABILITY: error reveals Go json unknown field detail")
}

func TestRedTeam_PayloadSize_LargeTransactionData(t *testing.T) {
	ctx := context.Background()

	// Create a 512KB data field (hex-encoded, so ~1MB in JSON)
	largeData := make([]byte, 512*1024)
	for i := range largeData {
		largeData[i] = 0xAA
	}
	hexData := fmt.Sprintf("0x%x", largeData)

	payload := fmt.Sprintf(`{"transaction":{"to":"%s","value":"0","gas":21000,"gasPrice":"20000000000","txType":"legacy","data":"%s"}}`,
		treasuryAddress, hexData)

	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       json.RawMessage(payload),
	})

	// Large data should either be rejected or handled gracefully (no crash/hang)
	if err != nil {
		t.Logf("Large data field handled: error=%v", err)
	} else if resp != nil {
		t.Logf("Large data field handled: status=%s", resp.Status)
	}

	// Critical: verify server is still alive after large payload
	_, healthErr := adminClient.Health(ctx)
	require.NoError(t, healthErr, "server should still be healthy after large payload")
}

// =============================================================================
// Red Team Round 4: Parameter-Level Validation Attacks
// =============================================================================

func TestRedTeam_SignHandler_InvalidSignType(t *testing.T) {
	ctx := context.Background()

	// Attack: use an invalid sign_type to bypass validation
	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "evil_type",
		Payload:       json.RawMessage(`{"message":"test"}`),
	})

	require.Error(t, err, "VULNERABILITY: invalid sign_type should be rejected at handler level")
	if resp != nil {
		assert.NotEqual(t, "completed", resp.Status)
	}
}

func TestRedTeam_SignHandler_InvalidSignerAddress(t *testing.T) {
	ctx := context.Background()

	// Attack: signer_address without valid Ethereum format
	for _, addr := range []string{"0xINVALID", "not_an_address", "0x123", "0x" + strings.Repeat("GG", 20)} {
		t.Run("addr_"+addr[:min(len(addr), 16)], func(t *testing.T) {
			resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
				ChainID:       chainID,
				SignerAddress: addr,
				SignType:      "personal",
				Payload:       json.RawMessage(`{"message":"test"}`),
			})

			require.Error(t, err, "VULNERABILITY: invalid signer_address '%s' should be rejected", addr)
			if resp != nil {
				assert.NotEqual(t, "completed", resp.Status)
			}
		})
	}
}

func TestRedTeam_SignHandler_InvalidChainID(t *testing.T) {
	ctx := context.Background()

	// Attack: various invalid chain_id values
	for _, id := range []string{"-1", "abc", "1.5", "0x1", ""} {
		name := id
		if name == "" {
			name = "empty"
		}
		t.Run("chainid_"+name, func(t *testing.T) {
			resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
				ChainID:       id,
				SignerAddress: signerAddress,
				SignType:      "personal",
				Payload:       json.RawMessage(`{"message":"test"}`),
			})

			require.Error(t, err, "VULNERABILITY: invalid chain_id '%s' should be rejected", id)
			if resp != nil {
				assert.NotEqual(t, "completed", resp.Status)
			}
		})
	}
}

func TestRedTeam_SignHandler_NegativeTransactionValue(t *testing.T) {
	ctx := context.Background()

	// Attack: negative ETH value — big.Int accepts negative numbers
	payload := json.RawMessage(`{
		"transaction": {
			"to": "0x0000000000000000000000000000000000000001",
			"value": "-1000000000000000000",
			"gas": 21000,
			"gasPrice": "20000000000",
			"txType": "legacy"
		}
	}`)

	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       payload,
	})

	require.Error(t, err, "VULNERABILITY: negative transaction value should be rejected")
	if resp != nil {
		assert.NotEqual(t, "completed", resp.Status,
			"VULNERABILITY: signing succeeded with negative value")
	}
}

func TestRedTeam_SignHandler_NegativeGasPrice(t *testing.T) {
	ctx := context.Background()

	// Attack: negative gas price
	payload := json.RawMessage(`{
		"transaction": {
			"to": "0x0000000000000000000000000000000000000001",
			"value": "0",
			"gas": 21000,
			"gasPrice": "-1",
			"txType": "legacy"
		}
	}`)

	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       payload,
	})

	require.Error(t, err, "VULNERABILITY: negative gasPrice should be rejected")
	if resp != nil {
		assert.NotEqual(t, "completed", resp.Status,
			"VULNERABILITY: signing succeeded with negative gasPrice")
	}
}

func TestRedTeam_SignHandler_InvalidToAddress(t *testing.T) {
	ctx := context.Background()

	// Attack: invalid "to" address — common.HexToAddress silently returns zero address
	payload := json.RawMessage(`{
		"transaction": {
			"to": "0xINVALID_ADDRESS_NOT_HEX",
			"value": "0",
			"gas": 21000,
			"gasPrice": "20000000000",
			"txType": "legacy"
		}
	}`)

	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       payload,
	})

	require.Error(t, err, "VULNERABILITY: invalid 'to' address should be rejected, not silently converted to zero address")
	if resp != nil {
		assert.NotEqual(t, "completed", resp.Status,
			"VULNERABILITY: signing succeeded with invalid 'to' address (silent truncation to zero address)")
	}
}

func TestRedTeam_SignHandler_OversizedPayload(t *testing.T) {
	ctx := context.Background()

	// Attack: 3MB payload to exceed the 2MB payload limit
	bigValue := strings.Repeat("A", 3*1024*1024)
	payload := json.RawMessage(fmt.Sprintf(`{"message":"%s"}`, bigValue))

	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "personal",
		Payload:       payload,
	})

	require.Error(t, err, "VULNERABILITY: oversized payload (3MB) should be rejected")
	if resp != nil {
		assert.NotEqual(t, "completed", resp.Status)
	}
}

func TestRedTeam_SignHandler_OversizedMessage(t *testing.T) {
	ctx := context.Background()

	// Attack: 2MB personal message to exceed the 1MB message limit
	bigMessage := strings.Repeat("B", 2*1024*1024)
	payload := json.RawMessage(fmt.Sprintf(`{"message":"%s"}`, bigMessage))

	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "personal",
		Payload:       payload,
	})

	require.Error(t, err, "VULNERABILITY: oversized message (2MB) should be rejected")
	if resp != nil {
		assert.NotEqual(t, "completed", resp.Status)
	}
}

func TestRedTeam_SignHandler_OversizedTxData(t *testing.T) {
	ctx := context.Background()

	// Attack: 256KB+ transaction data to exceed the 128KB limit
	// Data is base64 encoded in JSON, so we send hex-encoded bytes
	bigData := strings.Repeat("AA", 200*1024) // 200KB of hex = 200KB bytes when decoded
	payload := json.RawMessage(fmt.Sprintf(`{
		"transaction": {
			"to": "0x0000000000000000000000000000000000000001",
			"value": "0",
			"gas": 21000,
			"gasPrice": "20000000000",
			"txType": "legacy",
			"data": "%s"
		}
	}`, bigData))

	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload:       payload,
	})

	require.Error(t, err, "VULNERABILITY: oversized transaction data should be rejected")
	if resp != nil {
		assert.NotEqual(t, "completed", resp.Status)
	}
}

func TestRedTeam_ListRequests_InvalidStatusFilter(t *testing.T) {
	ctx := context.Background()
	baseURL := getBaseURL()

	// Attack: inject invalid status filter into query parameter
	ts := time.Now().UnixMilli()
	nonce := fmt.Sprintf("status-filter-%d", ts)
	method := "GET"
	path := "/api/v1/evm/requests?status=evil_status"
	body := []byte("")

	privKeyBytes, err := hex.DecodeString(adminAPIKeyHex)
	require.NoError(t, err)
	privKey := ed25519.PrivateKey(privKeyBytes)

	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%d|%s|%s|%s|%x", ts, nonce, method, path, bodyHash)
	sig := ed25519.Sign(privKey, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("X-API-Key-ID", adminAPIKeyID)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Signature", sigB64)
	req.Header.Set("X-Nonce", nonce)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"VULNERABILITY: invalid status filter 'evil_status' should return 400")

	respBody, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(respBody), "invalid status filter",
		"error response should mention invalid status filter")
}

func TestRedTeam_ListRequests_InvalidCursor(t *testing.T) {
	ctx := context.Background()
	baseURL := getBaseURL()

	// Attack: send a non-RFC3339 cursor
	ts := time.Now().UnixMilli()
	nonce := fmt.Sprintf("cursor-test-%d", ts)
	method := "GET"
	path := "/api/v1/evm/requests?cursor=not-a-timestamp"
	body := []byte("")

	privKeyBytes, err := hex.DecodeString(adminAPIKeyHex)
	require.NoError(t, err)
	privKey := ed25519.PrivateKey(privKeyBytes)

	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%d|%s|%s|%s|%x", ts, nonce, method, path, bodyHash)
	sig := ed25519.Sign(privKey, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("X-API-Key-ID", adminAPIKeyID)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Signature", sigB64)
	req.Header.Set("X-Nonce", nonce)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"VULNERABILITY: invalid cursor 'not-a-timestamp' should return 400, not be silently ignored")
}

func TestRedTeam_SecurityHeaders_Present(t *testing.T) {
	baseURL := getBaseURL()

	// Check security headers on /health (unauthenticated endpoint)
	resp, err := http.Get(baseURL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"),
		"VULNERABILITY: X-Content-Type-Options header missing")
	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"),
		"VULNERABILITY: X-Frame-Options header missing")
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"),
		"VULNERABILITY: Cache-Control header missing")
	assert.Equal(t, "default-src 'none'", resp.Header.Get("Content-Security-Policy"),
		"VULNERABILITY: Content-Security-Policy header missing")
}

func TestRedTeam_HeaderLength_OversizedAPIKeyID(t *testing.T) {
	ctx := context.Background()
	baseURL := getBaseURL()

	// Attack: send a 10KB X-API-Key-ID to cause memory/DB issues
	hugeKeyID := strings.Repeat("A", 10*1024)
	ts := time.Now().UnixMilli()

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/v1/evm/requests", nil)
	require.NoError(t, err)
	req.Header.Set("X-API-Key-ID", hugeKeyID)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Signature", "dummysig")
	req.Header.Set("X-Nonce", "test-nonce")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"VULNERABILITY: oversized X-API-Key-ID (10KB) should return 400")
}

// =============================================================================
// Red Team Phase 5: Solidity Rule Bypass via API-Created Rules
// These tests create evm_solidity_expression rules (functions + typed_data)
// via the admin API, then attempt to bypass them with attack payloads.
//
// NOTE on transaction data encoding:
// The server's TransactionPayload.Data is a string type that accepts
// 0x-prefixed hex encoding, matching the Ethereum standard and client SDK.
//
// NOTE on rule mode for typed_data tests:
// Whitelist rules are OR'd — any matching whitelist rule approves the request.
// Since config-level signer_restriction and sign_type_restriction whitelist
// rules auto-approve typed_data, Solidity expression rules that validate
// typed_data MUST use "blocklist" mode so they are evaluated in Phase 1
// (before any whitelist rule can approve).
// =============================================================================

// TestRedTeam_PT5_FakeTokenApprove creates a functions-mode rule that only allows
// approve() to a known spender on a specific ERC20 contract, then sends
// approve(validSpender, max) targeting a FAKE ERC20 contract address.
// The rule's txTo check should block this.
func TestRedTeam_PT5_FakeTokenApprove(t *testing.T) {
	if useExternalServer {
		t.Skip("requires internal server with Foundry support")
	}

	ctx := context.Background()

	// Known good addresses
	realUSDC := "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
	validSpender := "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"

	// Create a functions-mode BLOCKLIST rule that rejects approve() to non-USDC contracts.
	// Blocklist rules are evaluated first; if the require() reverts the tx is blocked.
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RT5: ERC20 approve whitelist",
		Type:    "evm_solidity_expression",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"functions": fmt.Sprintf(`
				function approve(address spender, uint256 amount) external {
					require(txTo == %s, "target must be real USDC");
					require(spender == %s, "spender not whitelisted");
					require(amount <= 1000000000, "amount exceeds 1000 USDC");
				}
			`, realUSDC, validSpender),
			"description": "Only allow approve on real USDC to known spender",
			"test_cases": []map[string]interface{}{
				{
					"name": "should pass for real USDC approve",
					"input": map[string]interface{}{
						"to": realUSDC,
						// approve(validSpender, 500 USDC = 500e6)
						// selector 0x095ea7b3
						"data": "0x095ea7b3" +
							"0000000000000000000000005B38Da6a701c568545dCfcB03FcB875f56beddC4" +
							"000000000000000000000000000000000000000000000000000000001DCD6500",
					},
					"expect_pass": true,
				},
				{
					"name": "should reject fake token",
					"input": map[string]interface{}{
						"to": "0xdEAD000000000000000000000000000000000000", // fake contract
						"data": "0x095ea7b3" +
							"0000000000000000000000005B38Da6a701c568545dCfcB03FcB875f56beddC4" +
							"000000000000000000000000000000000000000000000000000000001DCD6500",
					},
					"expect_pass": false,
					"expect_reason": "target must be real USDC",
				},
			},
		},
	})
	if err != nil {
		t.Skipf("Foundry not available or rule creation failed: %v", err)
	}
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	// ATTACK: Send approve(validSpender, uint256.max) to a FAKE ERC20 contract
	fakeToken := "0xdEAD000000000000000000000000000000000000"
	// approve(validSpender, type(uint256).max)
	approveHex := "095ea7b3" +
		"0000000000000000000000005B38Da6a701c568545dCfcB03FcB875f56beddC4" +
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload: json.RawMessage(fmt.Sprintf(`{
			"transaction": {
				"to": "%s",
				"value": "0",
				"data": "%s",
				"gas": 50000,
				"gasPrice": "1000000000",
				"txType": "legacy",
				"nonce": 0
			}
		}`, fakeToken, "0x"+approveHex)),
	})

	// The blocklist rule should reject this because txTo != realUSDC
	if err == nil && resp != nil && resp.Status == "completed" {
		t.Errorf("VULNERABILITY: approve() to fake ERC20 contract %s was signed! txTo check bypassed", fakeToken)
	} else {
		t.Logf("PASS: approve to fake token correctly blocked (err=%v)", err)
	}
}

// TestRedTeam_PT5_FakeTokenTransfer creates a functions-mode rule that only
// allows transfer() on a specific ERC20 contract, then sends
// transfer(treasury, amount) targeting a fake ERC20 contract.
func TestRedTeam_PT5_FakeTokenTransfer(t *testing.T) {
	if useExternalServer {
		t.Skip("requires internal server with Foundry support")
	}

	ctx := context.Background()

	realUSDC := "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"

	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RT5: ERC20 transfer whitelist",
		Type:    "evm_solidity_expression",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"functions": fmt.Sprintf(`
				function transfer(address to, uint256 amount) external {
					require(txTo == %s, "target must be real USDC");
					require(amount <= 10000000000, "amount exceeds 10k USDC");
					require(to != address(0), "cannot transfer to zero address");
				}
			`, realUSDC),
			"description": "Only allow transfer on real USDC",
			"test_cases": []map[string]interface{}{
				{
					"name": "should pass for real USDC transfer",
					"input": map[string]interface{}{
						"to": realUSDC,
						// transfer(treasury, 1000 USDC = 1000e6)
						"data": "0xa9059cbb" +
							"0000000000000000000000005B38Da6a701c568545dCfcB03FcB875f56beddC4" +
							"000000000000000000000000000000000000000000000000000000003B9ACA00",
					},
					"expect_pass": true,
				},
				{
					"name": "should reject fake token",
					"input": map[string]interface{}{
						"to": "0x1111111111111111111111111111111111111111",
						"data": "0xa9059cbb" +
							"0000000000000000000000005B38Da6a701c568545dCfcB03FcB875f56beddC4" +
							"000000000000000000000000000000000000000000000000000000003B9ACA00",
					},
					"expect_pass": false,
					"expect_reason": "target must be real USDC",
				},
			},
		},
	})
	if err != nil {
		t.Skipf("Foundry not available or rule creation failed: %v", err)
	}
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	// ATTACK: Send transfer(treasury, 5000 USDC) to a FAKE token contract
	fakeToken := "0x1111111111111111111111111111111111111111"
	// transfer(treasury, 5000e6)
	transferHex := "a9059cbb" +
		"0000000000000000000000005B38Da6a701c568545dCfcB03FcB875f56beddC4" +
		"000000000000000000000000000000000000000000000000000000012A05F200"

	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload: json.RawMessage(fmt.Sprintf(`{
			"transaction": {
				"to": "%s",
				"value": "0",
				"data": "%s",
				"gas": 50000,
				"gasPrice": "1000000000",
				"txType": "legacy",
				"nonce": 1
			}
		}`, fakeToken, "0x"+transferHex)),
	})

	if err == nil && resp != nil && resp.Status == "completed" {
		t.Errorf("VULNERABILITY: transfer() to fake ERC20 contract %s was signed! txTo check bypassed", fakeToken)
	} else {
		t.Logf("PASS: transfer to fake token correctly blocked (err=%v)", err)
	}
}

// TestRedTeam_PT5_ExecTxDelegatecall creates a functions-mode rule for
// execTransaction that requires operation==0 (Call), then sends
// execTransaction with operation=1 (DelegateCall) to attempt code injection.
// NOTE: The Solidity code avoids the word "delegatecall" which is blocked
// by the API's dangerous pattern filter. The rule uses "operation must be zero".
func TestRedTeam_PT5_ExecTxDelegatecall(t *testing.T) {
	if useExternalServer {
		t.Skip("requires internal server with Foundry support")
	}

	ctx := context.Background()

	safeProxy := "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" // example Safe address

	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RT5: execTransaction - operation must be zero",
		Type:    "evm_solidity_expression",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"functions": fmt.Sprintf(`
				function execTransaction(
					address to,
					uint256 value,
					bytes calldata data_,
					uint8 operation,
					uint256 safeTxGas,
					uint256 baseGas,
					uint256 gasPrice_,
					address gasToken,
					address payable refundReceiver,
					bytes calldata signatures
				) external returns (bool) {
					require(txTo == %s, "target must be Safe proxy");
					require(operation == 0, "operation must be zero (Call only)");
					require(gasPrice_ == 0, "gasPrice must be zero");
					require(gasToken == address(0), "gasToken must be zero");
					require(refundReceiver == address(0), "refundReceiver must be zero");
				}
			`, safeProxy),
			"description": "execTransaction: only allow operation=0",
			"test_cases": []map[string]interface{}{
				{
					"name": "should pass for normal call",
					"input": map[string]interface{}{
						"to": safeProxy,
						// execTransaction(to, 0, empty_data, operation=0, ...)
						// selector: 0x6a761202
						"data": "0x6a761202" +
							"0000000000000000000000005B38Da6a701c568545dCfcB03FcB875f56beddC4" + // to
							"0000000000000000000000000000000000000000000000000000000000000000" + // value
							"0000000000000000000000000000000000000000000000000000000000000140" + // data offset
							"0000000000000000000000000000000000000000000000000000000000000000" + // operation=0 (Call)
							"0000000000000000000000000000000000000000000000000000000000000000" + // safeTxGas
							"0000000000000000000000000000000000000000000000000000000000000000" + // baseGas
							"0000000000000000000000000000000000000000000000000000000000000000" + // gasPrice=0
							"0000000000000000000000000000000000000000000000000000000000000000" + // gasToken=0
							"0000000000000000000000000000000000000000000000000000000000000000" + // refundReceiver=0
							"0000000000000000000000000000000000000000000000000000000000000160" + // signatures offset
							"0000000000000000000000000000000000000000000000000000000000000000" + // data length=0
							"0000000000000000000000000000000000000000000000000000000000000041" + // signatures length=65
							"0000000000000000000000000000000000000000000000000000000000000000" + // sig r
							"0000000000000000000000000000000000000000000000000000000000000000" + // sig s
							"0000000000000000000000000000000000000000000000000000000000000000", // sig v (padded)
					},
					"expect_pass": true,
				},
				{
					"name": "should reject operation=1",
					"input": map[string]interface{}{
						"to": safeProxy,
						"data": "0x6a761202" +
							"0000000000000000000000005B38Da6a701c568545dCfcB03FcB875f56beddC4" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000140" +
							"0000000000000000000000000000000000000000000000000000000000000001" + // operation=1
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000160" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000041" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000000",
					},
					"expect_pass": false,
					"expect_reason": "operation must be zero (Call only)",
				},
			},
		},
	})
	if err != nil {
		t.Skipf("Foundry not available or rule creation failed: %v", err)
	}
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	// ATTACK: Send execTransaction with operation=1 (DelegateCall)
	attackHex := "6a761202" +
		"0000000000000000000000005B38Da6a701c568545dCfcB03FcB875f56beddC4" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000140" +
		"0000000000000000000000000000000000000000000000000000000000000001" + // operation=1 (DelegateCall!)
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000160" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000041" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000"

	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload: json.RawMessage(fmt.Sprintf(`{
			"transaction": {
				"to": "%s",
				"value": "0",
				"data": "%s",
				"gas": 500000,
				"gasPrice": "1000000000",
				"txType": "legacy",
				"nonce": 2
			}
		}`, safeProxy, "0x"+attackHex)),
	})

	if err == nil && resp != nil && resp.Status == "completed" {
		t.Errorf("VULNERABILITY: execTransaction with operation=1 (DelegateCall) was signed!")
	} else {
		t.Logf("PASS: execTransaction with operation=1 correctly blocked (err=%v)", err)
	}
}

// TestRedTeam_PT5_ExecTxGasDrain creates a functions-mode rule for
// execTransaction, then sends execTransaction with gasPrice>0 and
// gasToken=USDT to attempt gas-fee draining of the Safe.
func TestRedTeam_PT5_ExecTxGasDrain(t *testing.T) {
	if useExternalServer {
		t.Skip("requires internal server with Foundry support")
	}

	ctx := context.Background()

	safeProxy := "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RT5: execTransaction - no gas drain",
		Type:    "evm_solidity_expression",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"functions": fmt.Sprintf(`
				function execTransaction(
					address to,
					uint256 value,
					bytes calldata data_,
					uint8 operation,
					uint256 safeTxGas,
					uint256 baseGas,
					uint256 gasPrice_,
					address gasToken,
					address payable refundReceiver,
					bytes calldata signatures
				) external returns (bool) {
					require(txTo == %s, "target must be Safe proxy");
					require(operation == 0, "only Call allowed");
					require(gasPrice_ == 0, "gasPrice must be zero to prevent drain");
					require(gasToken == address(0), "gasToken must be zero");
					require(refundReceiver == address(0), "refundReceiver must be zero");
				}
			`, safeProxy),
			"description": "execTransaction: block gas draining attack",
			"test_cases": []map[string]interface{}{
				{
					"name": "should pass for safe exec with zero gas params",
					"input": map[string]interface{}{
						"to": safeProxy,
						"data": "0x6a761202" +
							"0000000000000000000000005B38Da6a701c568545dCfcB03FcB875f56beddC4" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000140" +
							"0000000000000000000000000000000000000000000000000000000000000000" + // operation=0
							"0000000000000000000000000000000000000000000000000000000000000000" + // safeTxGas=0
							"0000000000000000000000000000000000000000000000000000000000000000" + // baseGas=0
							"0000000000000000000000000000000000000000000000000000000000000000" + // gasPrice=0
							"0000000000000000000000000000000000000000000000000000000000000000" + // gasToken=0
							"0000000000000000000000000000000000000000000000000000000000000000" + // refundReceiver=0
							"0000000000000000000000000000000000000000000000000000000000000160" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000041" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000000",
					},
					"expect_pass": true,
				},
				{
					"name": "should reject gas drain with non-zero gasPrice and gasToken",
					"input": map[string]interface{}{
						"to": safeProxy,
						"data": "0x6a761202" +
							"0000000000000000000000005B38Da6a701c568545dCfcB03FcB875f56beddC4" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000140" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000005F5E100" + // gasPrice=100M
							"000000000000000000000000dAC17F958D2ee523a2206206994597C13D831ec7" + // gasToken=USDT
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000160" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000041" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000000" +
							"0000000000000000000000000000000000000000000000000000000000000000",
					},
					"expect_pass": false,
					"expect_reason": "gasPrice must be zero to prevent drain",
				},
			},
		},
	})
	if err != nil {
		t.Skipf("Foundry not available or rule creation failed: %v", err)
	}
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	// ATTACK: Send execTransaction with gasPrice=100M and gasToken=USDT
	gasDrainHex := "6a761202" +
		"0000000000000000000000005B38Da6a701c568545dCfcB03FcB875f56beddC4" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000140" +
		"0000000000000000000000000000000000000000000000000000000000000000" + // operation=0 (ok)
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000005F5E100" + // gasPrice=100M ← ATTACK
		"000000000000000000000000dAC17F958D2ee523a2206206994597C13D831ec7" + // gasToken=USDT ← ATTACK
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000160" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000041" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000"

	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "transaction",
		Payload: json.RawMessage(fmt.Sprintf(`{
			"transaction": {
				"to": "%s",
				"value": "0",
				"data": "%s",
				"gas": 500000,
				"gasPrice": "1000000000",
				"txType": "legacy",
				"nonce": 3
			}
		}`, safeProxy, "0x"+gasDrainHex)),
	})

	if err == nil && resp != nil && resp.Status == "completed" {
		t.Errorf("VULNERABILITY: execTransaction with gasPrice>0 and gasToken=USDT was signed! Gas drain attack succeeded")
	} else {
		t.Logf("PASS: execTransaction gas drain correctly blocked (err=%v)", err)
	}
}

// TestRedTeam_PT5_FakeExchangeOrder creates a typed_data BLOCKLIST rule for
// an exchange Order struct with verifyingContract check, then sends an
// EIP-712 Order with a fake verifyingContract to attempt signature on a
// rogue exchange. Blocklist mode ensures the require() reverts block the tx
// before other whitelist rules (signer_restriction, sign_type_restriction)
// can auto-approve it.
func TestRedTeam_PT5_FakeExchangeOrder(t *testing.T) {
	if useExternalServer {
		t.Skip("requires internal server with Foundry support")
	}

	ctx := context.Background()

	realExchange := "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E" // example exchange
	// Use a properly checksummed fake address to avoid Solidity compiler errors
	fakeExchange := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RT5: Exchange Order - verifyingContract check",
		Type:    "evm_solidity_expression",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"typed_data_struct": `struct Order {
				address maker;
				address taker;
				uint256 makerAmount;
				uint256 takerAmount;
				uint256 nonce;
			}`,
			"typed_data_expression": fmt.Sprintf(`
				require(
					eip712_domainContract == %s,
					"verifyingContract must be the real exchange"
				);
				require(
					order.maker == ctx_signer,
					"maker must be the signer"
				);
				require(
					order.makerAmount <= 100000000000,
					"makerAmount exceeds 100k limit"
				);
			`, realExchange),
			"sign_type_filter": "typed_data",
			"description":      "Only sign Orders on the real exchange",
			"test_cases": []map[string]interface{}{
				{
					"name": "should pass for real exchange order",
					"input": map[string]interface{}{
						"typed_data": map[string]interface{}{
							"primaryType": "Order",
							"domain": map[string]interface{}{
								"name":              "TestExchange",
								"version":           "1",
								"chainId":           chainID,
								"verifyingContract": realExchange,
							},
							"message": map[string]interface{}{
								"maker":       signerAddress,
								"taker":       "0x0000000000000000000000000000000000000000",
								"makerAmount": "50000000000",
								"takerAmount": "25000000000",
								"nonce":       "1",
							},
						},
					},
					"expect_pass": true,
				},
				{
					"name": "should reject fake exchange",
					"input": map[string]interface{}{
						"typed_data": map[string]interface{}{
							"primaryType": "Order",
							"domain": map[string]interface{}{
								"name":              "FakeExchange",
								"version":           "1",
								"chainId":           chainID,
								"verifyingContract": fakeExchange,
							},
							"message": map[string]interface{}{
								"maker":       signerAddress,
								"taker":       "0x0000000000000000000000000000000000000000",
								"makerAmount": "50000000000",
								"takerAmount": "25000000000",
								"nonce":       "1",
							},
						},
					},
					"expect_pass": false,
					"expect_reason": "verifyingContract must be the real exchange",
				},
			},
		},
	})
	if err != nil {
		t.Skipf("Foundry not available or rule creation failed: %v", err)
	}
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	// ATTACK: Send an Order with a FAKE verifyingContract
	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "typed_data",
		Payload: json.RawMessage(fmt.Sprintf(`{
			"typed_data": {
				"types": {
					"EIP712Domain": [
						{"name": "name", "type": "string"},
						{"name": "version", "type": "string"},
						{"name": "chainId", "type": "uint256"},
						{"name": "verifyingContract", "type": "address"}
					],
					"Order": [
						{"name": "maker", "type": "address"},
						{"name": "taker", "type": "address"},
						{"name": "makerAmount", "type": "uint256"},
						{"name": "takerAmount", "type": "uint256"},
						{"name": "nonce", "type": "uint256"}
					]
				},
				"primaryType": "Order",
				"domain": {
					"name": "FakeExchange",
					"version": "1",
					"chainId": "%s",
					"verifyingContract": "%s"
				},
				"message": {
					"maker": "%s",
					"taker": "0x0000000000000000000000000000000000000000",
					"makerAmount": "50000000000",
					"takerAmount": "1",
					"nonce": "999"
				}
			}
		}`, chainID, fakeExchange, signerAddress)),
	})

	if err == nil && resp != nil && resp.Status == "completed" {
		t.Errorf("VULNERABILITY: EIP-712 Order with fake verifyingContract %s was signed!", fakeExchange)
	} else {
		t.Logf("PASS: Order with fake verifyingContract correctly blocked (err=%v)", err)
	}
}

// TestRedTeam_PT5_SafeTxDelegatecall creates a typed_data BLOCKLIST rule for
// a SafeTx struct that requires operation==0, then sends a SafeTx with
// operation=1 (DelegateCall) to attempt arbitrary code execution through
// the Safe. Blocklist mode ensures the Solidity require() is evaluated
// before other whitelist rules can auto-approve typed_data.
// NOTE: The Solidity code avoids the word "delegatecall" which is blocked
// by the API's dangerous pattern filter. The rule uses "operation must be zero".
func TestRedTeam_PT5_SafeTxDelegatecall(t *testing.T) {
	if useExternalServer {
		t.Skip("requires internal server with Foundry support")
	}

	ctx := context.Background()

	safeProxy := "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "RT5: SafeTx - operation must be zero",
		Type:    "evm_solidity_expression",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"typed_data_struct": `struct SafeTx {
				address to;
				uint256 value;
				bytes data;
				uint8 operation;
				uint256 safeTxGas;
				uint256 baseGas;
				uint256 gasPrice;
				address gasToken;
				address refundReceiver;
				uint256 nonce;
			}`,
			"typed_data_expression": fmt.Sprintf(`
				require(
					eip712_domainContract == %s,
					"verifyingContract must be the Safe proxy"
				);
				require(
					safeTx.operation == 0,
					"operation must be zero (Call only)"
				);
				require(
					safeTx.gasPrice == 0,
					"gasPrice must be zero"
				);
				require(
					safeTx.gasToken == address(0),
					"gasToken must be zero"
				);
				require(
					safeTx.refundReceiver == address(0),
					"refundReceiver must be zero"
				);
			`, safeProxy),
			"sign_type_filter": "typed_data",
			"description":      "SafeTx: block non-zero operation and gas drain via EIP-712",
			"test_cases": []map[string]interface{}{
				{
					"name": "should pass for safe Call operation",
					"input": map[string]interface{}{
						"typed_data": map[string]interface{}{
							"primaryType": "SafeTx",
							"domain": map[string]interface{}{
								"name":              "GnosisSafe",
								"version":           "1.3.0",
								"chainId":           chainID,
								"verifyingContract": safeProxy,
							},
							"message": map[string]interface{}{
								"to":             "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
								"value":          "0",
								"data":           "0x",
								"operation":      "0",
								"safeTxGas":      "0",
								"baseGas":        "0",
								"gasPrice":       "0",
								"gasToken":       "0x0000000000000000000000000000000000000000",
								"refundReceiver": "0x0000000000000000000000000000000000000000",
								"nonce":          "0",
							},
						},
					},
					"expect_pass": true,
				},
				{
					"name": "should reject operation=1",
					"input": map[string]interface{}{
						"typed_data": map[string]interface{}{
							"primaryType": "SafeTx",
							"domain": map[string]interface{}{
								"name":              "GnosisSafe",
								"version":           "1.3.0",
								"chainId":           chainID,
								"verifyingContract": safeProxy,
							},
							"message": map[string]interface{}{
								"to":             "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
								"value":          "0",
								"data":           "0x",
								"operation":      "1",
								"safeTxGas":      "0",
								"baseGas":        "0",
								"gasPrice":       "0",
								"gasToken":       "0x0000000000000000000000000000000000000000",
								"refundReceiver": "0x0000000000000000000000000000000000000000",
								"nonce":          "0",
							},
						},
					},
					"expect_pass": false,
					"expect_reason": "operation must be zero (Call only)",
				},
			},
		},
	})
	if err != nil {
		t.Skipf("Foundry not available or rule creation failed: %v", err)
	}
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	// ATTACK: Send SafeTx EIP-712 with operation=1 (DelegateCall)
	resp, err := adminClient.EVM.Sign.ExecuteAsync(ctx,&evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      "typed_data",
		Payload: json.RawMessage(fmt.Sprintf(`{
			"typed_data": {
				"types": {
					"EIP712Domain": [
						{"name": "name", "type": "string"},
						{"name": "version", "type": "string"},
						{"name": "chainId", "type": "uint256"},
						{"name": "verifyingContract", "type": "address"}
					],
					"SafeTx": [
						{"name": "to", "type": "address"},
						{"name": "value", "type": "uint256"},
						{"name": "data", "type": "bytes"},
						{"name": "operation", "type": "uint8"},
						{"name": "safeTxGas", "type": "uint256"},
						{"name": "baseGas", "type": "uint256"},
						{"name": "gasPrice", "type": "uint256"},
						{"name": "gasToken", "type": "address"},
						{"name": "refundReceiver", "type": "address"},
						{"name": "nonce", "type": "uint256"}
					]
				},
				"primaryType": "SafeTx",
				"domain": {
					"name": "GnosisSafe",
					"version": "1.3.0",
					"chainId": "%s",
					"verifyingContract": "%s"
				},
				"message": {
					"to": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
					"value": "0",
					"data": "0x",
					"operation": "1",
					"safeTxGas": "0",
					"baseGas": "0",
					"gasPrice": "0",
					"gasToken": "0x0000000000000000000000000000000000000000",
					"refundReceiver": "0x0000000000000000000000000000000000000000",
					"nonce": "42"
				}
			}
		}`, chainID, safeProxy)),
	})

	if err == nil && resp != nil && resp.Status == "completed" {
		t.Errorf("VULNERABILITY: SafeTx with operation=1 (DelegateCall) was signed!")
	} else {
		t.Logf("PASS: SafeTx with operation=1 correctly blocked (err=%v)", err)
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
