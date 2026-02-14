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
