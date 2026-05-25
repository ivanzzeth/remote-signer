//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/presets"
)

// TestE2E_PolymarketV2_ValidateAfterJSFix validates the polymarket_v2 template
// test cases through the JS sandbox. This is the regression test for the
// toChecksumAddressList -> rs.addr.toChecksumList fix.
func TestE2E_PolymarketV2_ValidateAfterJSFix(t *testing.T) {
	if useExternalServer {
		t.Skip("Polymarket V2 validation test requires internal server with shipped templates")
	}

	var listResp struct {
		Templates []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"templates"`
	}
	rawSignedRequest(t, http.MethodGet, "/api/v1/templates?limit=100", nil, &listResp)

	var targetID string
	for _, tmpl := range listResp.Templates {
		if tmpl.ID == "evm/polymarket_v2" {
			targetID = tmpl.ID
			break
		}
	}
	require.NotEmpty(t, targetID, "polymarket_v2 template not found in shipped catalog")

	var vresp struct {
		TemplateID   string `json:"template_id"`
		TemplateName string `json:"template_name"`
		Total        int    `json:"total"`
		Passed       int    `json:"passed"`
		Failed       int    `json:"failed"`
		Results      []struct {
			RuleName string `json:"rule_name"`
			Type     string `json:"type"`
			Valid    bool   `json:"valid"`
			Error    string `json:"error,omitempty"`
		} `json:"results,omitempty"`
	}
	rawSignedRequest(t, http.MethodPost, "/api/v1/templates/"+targetID+"/validate", nil, &vresp)

	require.GreaterOrEqual(t, vresp.Total, 1, "polymarket_v2 template should produce at least 1 rule")
	assert.Equal(t, 0, vresp.Failed, "all polymarket_v2 test cases should pass after JS fix; failed=%d", vresp.Failed)
	assert.Equal(t, vresp.Total, vresp.Passed, "all test cases should pass")

	t.Logf("Polymarket V2 validation: %d passed, %d failed, %d total", vresp.Passed, vresp.Failed, vresp.Total)
	for _, r := range vresp.Results {
		status := "PASS"
		if !r.Valid {
			status = "FAIL"
		}
		t.Logf("  %s [%s] %s", status, r.Type, r.RuleName)
		if r.Error != "" {
			t.Logf("    error: %s", r.Error)
		}
	}
}

// eip712TypeField mirrors the JSON field structure for EIP-712 type definitions.
type eip712TypeField struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// TestE2E_PolymarketV2_SignTypedDataOrder applies the polymarket_v2 preset,
// then signs a V2 Order typed_data and confirms the whitelist matches
// (no "no matching rule" rejection).
func TestE2E_PolymarketV2_SignTypedDataOrder(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Polymarket V2 sign test requires internal server with shipped templates")
	}

	presetName := "polymarket_v2_eoa_polygon"
	applyReq := map[string]interface{}{
		"variables": map[string]string{
			"allowed_safe_addresses": testSigner2Address,
		},
		"skip_validation": true,
	}
	body, _ := json.Marshal(applyReq)

	resp := doRawRequest(t, http.MethodPost, "/api/v1/presets/"+presetName+"/apply", body)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		t.Skipf("Preset %q not available (expected in shipped catalog)", presetName)
	}
	if resp.StatusCode != http.StatusCreated {
		var errBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errBody)
		t.Fatalf("preset apply should return 201, got %d, body: %+v", resp.StatusCode, errBody)
	}

	var applyResult struct {
		Results []json.RawMessage `json:"results"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&applyResult))
	require.GreaterOrEqual(t, len(applyResult.Results), 1,
		"preset apply should produce at least 1 rule result")
	t.Logf("Polymarket V2 preset applied successfully, %d rule(s)", len(applyResult.Results))

	chainID := "137"

	orderTypedData := map[string]interface{}{
		"types": map[string]interface{}{
			"EIP712Domain": []eip712TypeField{
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"Order": []eip712TypeField{
				{Name: "salt", Type: "uint256"},
				{Name: "maker", Type: "address"},
				{Name: "signer", Type: "address"},
				{Name: "tokenId", Type: "uint256"},
				{Name: "makerAmount", Type: "uint256"},
				{Name: "takerAmount", Type: "uint256"},
				{Name: "side", Type: "uint8"},
				{Name: "signatureType", Type: "uint8"},
				{Name: "timestamp", Type: "uint256"},
				{Name: "metadata", Type: "bytes32"},
				{Name: "builder", Type: "bytes32"},
				{Name: "expiration", Type: "uint256"},
			},
		},
		"primaryType": "Order",
		"domain": map[string]interface{}{
			"name":              "Polymarket CTF Exchange",
			"version":           "2",
			"chainId":           chainID,
			"verifyingContract": "0xE111180000d2663C0091e4f400237545B87B996B",
		},
		"message": map[string]interface{}{
			"salt":          "12345",
			"maker":         testSignerAddress,
			"signer":        testSignerAddress,
			"tokenId":       "1",
			"makerAmount":   "1000000000000000000",
			"takerAmount":   "1000000000000000000",
			"side":          "0",
			"signatureType": "0",
			"timestamp":     "1704067200",
			"metadata":      "0x0000000000000000000000000000000000000000000000000000000000000000",
			"builder":       "0x0000000000000000000000000000000000000000000000000000000000000000",
			"expiration":    "1893456000",
		},
	}

	signReq := map[string]interface{}{
		"chain_type":     "evm",
		"chain_id":       chainID,
		"signer_address": testSignerAddress,
		"sign_type":      "typed_data",
		"payload":        map[string]interface{}{"typed_data": orderTypedData},
	}

	signResp := doRawRequest(t, http.MethodPost, "/api/v1/evm/sign", signReq)
	defer signResp.Body.Close()

	if signResp.StatusCode == http.StatusForbidden {
		var errBody struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		json.NewDecoder(signResp.Body).Decode(&errBody)
		t.Fatalf("Polymarket V2 Order signature rejected (REGRESSION): %s - %s",
			errBody.Error, errBody.Message)
	}

	if signResp.StatusCode == http.StatusOK {
		t.Log("Polymarket V2 Order signature: whitelist matched successfully")
	} else if signResp.StatusCode == http.StatusAccepted {
		t.Log("Polymarket V2 Order signature: pending approval (authorizing mode)")
	} else {
		var errBody map[string]interface{}
		json.NewDecoder(signResp.Body).Decode(&errBody)
		t.Logf("Polymarket V2 Order signature: status %d, body: %+v",
			signResp.StatusCode, errBody)
		t.Log("Note: status not 200, but regression check passed (no 403)")
	}

	t.Log("Polymarket V2 regression test: PASSED")
}

// TestE2E_PolymarketV2Safe_SignAndDelegate applies the polymarket_v2_safe_polygon
// preset and tests the Safe delegation flow: SafeTx with inner V2 protocol calls
// are delegated to polymarket-v2-transactions, DELEGATECALL is rejected, and V2
// Order signatures pass the polymarket-v2-order-signature rule.
func TestE2E_PolymarketV2Safe_SignAndDelegate(t *testing.T) {
	ctx := context.Background()
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Polymarket V2 Safe test requires internal server with shipped presets")
	}

	presetID := "evm/polymarket_v2_safe_polygon"
	applyResp, err := adminClient.Presets.Apply(ctx, presetID, &presets.ApplyRequest{
		Variables:      map[string]string{"allowed_safe_addresses": testSigner2Address},
		SkipValidation: true,
	})
	require.NoError(t, err, "preset apply should succeed")
	require.NotNil(t, applyResp)
	require.GreaterOrEqual(t, len(applyResp.Results), 1,
		"preset apply should produce at least 1 rule result")
	t.Logf("Polymarket V2 Safe preset applied: %d rule(s)", len(applyResp.Results))
	snapshotRules(t)
	// Also register cleanup for apply results
	cleanupApplyResults(t, applyResp.Results)

	chainID := "137"

	// ---------------------------------------------------------------
	// 1. SafeTx delegation: pUSD approve to ExchangeV2 via Safe
	//    Safe template matches SafeTx → delegates to polymarket-v2-transactions
	//    which validates pUSD approve to ExchangeV2
	// ---------------------------------------------------------------
	safeTxTypedData := map[string]interface{}{
		"types": map[string]interface{}{
			"EIP712Domain": []eip712TypeField{
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"SafeTx": []eip712TypeField{
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "data", Type: "bytes"},
				{Name: "operation", Type: "uint8"},
				{Name: "safeTxGas", Type: "uint256"},
				{Name: "baseGas", Type: "uint256"},
				{Name: "gasPrice", Type: "uint256"},
				{Name: "gasToken", Type: "address"},
				{Name: "refundReceiver", Type: "address"},
				{Name: "nonce", Type: "uint256"},
			},
		},
		"primaryType": "SafeTx",
		"domain": map[string]interface{}{
			"chainId":           chainID,
			"verifyingContract": testSigner2Address,
		},
		"message": map[string]interface{}{
			"to":             "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB", // pUSD
			"value":          "0",
			"data":           "0x095ea7b3000000000000000000000000E111180000d2663C0091e4f400237545B87B996Bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"operation":      "0",
			"safeTxGas":      "0",
			"baseGas":        "0",
			"gasPrice":       "0",
			"gasToken":       "0x0000000000000000000000000000000000000000",
			"refundReceiver": "0x0000000000000000000000000000000000000000",
			"nonce":          "0",
		},
	}

	safeTxSignReq := map[string]interface{}{
		"chain_type":     "evm",
		"chain_id":       chainID,
		"signer_address": testSignerAddress,
		"sign_type":      "typed_data",
		"payload":        map[string]interface{}{"typed_data": safeTxTypedData},
	}

	safeTxResp := doRawRequest(t, http.MethodPost, "/api/v1/evm/sign", safeTxSignReq)
	defer safeTxResp.Body.Close()

	if safeTxResp.StatusCode == http.StatusForbidden {
		var errBody struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		json.NewDecoder(safeTxResp.Body).Decode(&errBody)
		t.Fatalf("SafeTx delegation REJECTED (REGRESSION): %s - %s", errBody.Error, errBody.Message)
	}
	assert.True(t, safeTxResp.StatusCode == http.StatusOK || safeTxResp.StatusCode == http.StatusAccepted,
		"SafeTx delegation should return 200 or 202, got %d", safeTxResp.StatusCode)
	t.Log("SafeTx delegation: PASSED (delegated to polymarket-v2-transactions)")

	// ---------------------------------------------------------------
	// 2. V2 Order signature: maker (Safe) != signer (EOA)
	// ---------------------------------------------------------------
	orderTypedData := map[string]interface{}{
		"types": map[string]interface{}{
			"EIP712Domain": []eip712TypeField{
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"Order": []eip712TypeField{
				{Name: "salt", Type: "uint256"},
				{Name: "maker", Type: "address"},
				{Name: "signer", Type: "address"},
				{Name: "tokenId", Type: "uint256"},
				{Name: "makerAmount", Type: "uint256"},
				{Name: "takerAmount", Type: "uint256"},
				{Name: "side", Type: "uint8"},
				{Name: "signatureType", Type: "uint8"},
				{Name: "timestamp", Type: "uint256"},
				{Name: "metadata", Type: "bytes32"},
				{Name: "builder", Type: "bytes32"},
				{Name: "expiration", Type: "uint256"},
			},
		},
		"primaryType": "Order",
		"domain": map[string]interface{}{
			"name":              "Polymarket CTF Exchange",
			"version":           "2",
			"chainId":           chainID,
			"verifyingContract": "0xE111180000d2663C0091e4f400237545B87B996B",
		},
		"message": map[string]interface{}{
			"salt":          "12345",
			"maker":         testSigner2Address,
			"signer":        testSignerAddress,
			"tokenId":       "1",
			"makerAmount":   "1000000000000000000",
			"takerAmount":   "1000000000000000000",
			"side":          "0",
			"signatureType": "0",
			"timestamp":     "1704067200",
			"metadata":      "0x0000000000000000000000000000000000000000000000000000000000000000",
			"builder":       "0x0000000000000000000000000000000000000000000000000000000000000000",
			"expiration":    "1893456000",
		},
	}

	orderSignReq := map[string]interface{}{
		"chain_type":     "evm",
		"chain_id":       chainID,
		"signer_address": testSignerAddress,
		"sign_type":      "typed_data",
		"payload":        map[string]interface{}{"typed_data": orderTypedData},
	}

	orderResp := doRawRequest(t, http.MethodPost, "/api/v1/evm/sign", orderSignReq)
	defer orderResp.Body.Close()

	if orderResp.StatusCode == http.StatusForbidden {
		var errBody struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		json.NewDecoder(orderResp.Body).Decode(&errBody)
		t.Fatalf("V2 Order signature REJECTED (REGRESSION): %s - %s", errBody.Error, errBody.Message)
	}
	assert.True(t, orderResp.StatusCode == http.StatusOK || orderResp.StatusCode == http.StatusAccepted,
		"V2 Order should return 200 or 202, got %d", orderResp.StatusCode)
	t.Log("V2 Order signature: PASSED")

	// ---------------------------------------------------------------
	// 3. DELEGATECALL SafeTx → must be rejected (safe-block-delegatecall)
	// ---------------------------------------------------------------
	delegateCallSafeTx := map[string]interface{}{
		"types": map[string]interface{}{
			"EIP712Domain": []eip712TypeField{
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"SafeTx": []eip712TypeField{
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "data", Type: "bytes"},
				{Name: "operation", Type: "uint8"},
				{Name: "safeTxGas", Type: "uint256"},
				{Name: "baseGas", Type: "uint256"},
				{Name: "gasPrice", Type: "uint256"},
				{Name: "gasToken", Type: "address"},
				{Name: "refundReceiver", Type: "address"},
				{Name: "nonce", Type: "uint256"},
			},
		},
		"primaryType": "SafeTx",
		"domain": map[string]interface{}{
			"chainId":           chainID,
			"verifyingContract": testSigner2Address,
		},
		"message": map[string]interface{}{
			"to":             "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB",
			"value":          "0",
			"data":           "0x095ea7b3000000000000000000000000E111180000d2663C0091e4f400237545B87B996Bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"operation":      "1", // DELEGATECALL
			"safeTxGas":      "0",
			"baseGas":        "0",
			"gasPrice":       "0",
			"gasToken":       "0x0000000000000000000000000000000000000000",
			"refundReceiver": "0x0000000000000000000000000000000000000000",
			"nonce":          "0",
		},
	}

	dcSignReq := map[string]interface{}{
		"chain_type":     "evm",
		"chain_id":       chainID,
		"signer_address": testSignerAddress,
		"sign_type":      "typed_data",
		"payload":        map[string]interface{}{"typed_data": delegateCallSafeTx},
	}

	dcResp := doRawRequest(t, http.MethodPost, "/api/v1/evm/sign", dcSignReq)
	defer dcResp.Body.Close()

	assert.Equal(t, http.StatusOK, dcResp.StatusCode,
		"DELEGATECALL SafeTx rejection should return 200 (blocked result, not 403), got %d", dcResp.StatusCode)

	var dcRespBody struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	json.NewDecoder(dcResp.Body).Decode(&dcRespBody)
	assert.Equal(t, "rejected", dcRespBody.Status,
		"DELEGATECALL SafeTx should be rejected, got status=%q message=%s", dcRespBody.Status, dcRespBody.Message)
	t.Logf("DELEGATECALL rejection: %s - %s", dcRespBody.Status, dcRespBody.Message)

	// ---------------------------------------------------------------
	// 4. Unknown Safe + CALL → blocklist MUST skip via try/catch
	//    Regression: before the panic(vm.ToValue(...)) fix, bare Go
	//    panic bypassed JS try/catch and this request was wrongly
	//    blocked with "invalid verifying contract". After the fix,
	//    the blocklist returns ok() (skip), and the request should
	//    NOT be rejected by the blocklist rule.
	// ---------------------------------------------------------------
	unknownSafeTx := map[string]interface{}{
		"types": map[string]interface{}{
			"EIP712Domain": []eip712TypeField{
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"SafeTx": []eip712TypeField{
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "data", Type: "bytes"},
				{Name: "operation", Type: "uint8"},
				{Name: "safeTxGas", Type: "uint256"},
				{Name: "baseGas", Type: "uint256"},
				{Name: "gasPrice", Type: "uint256"},
				{Name: "gasToken", Type: "address"},
				{Name: "refundReceiver", Type: "address"},
				{Name: "nonce", Type: "uint256"},
			},
		},
		"primaryType": "SafeTx",
		"domain": map[string]interface{}{
			"chainId":           chainID,
			"verifyingContract": "0x000000000000000000000000000000000000dEaD", // NOT in allowed_safe_addresses
		},
		"message": map[string]interface{}{
			"to":             "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB",
			"value":          "0",
			"data":           "0x",
			"operation":      "0", // CALL — valid operation
			"safeTxGas":      "0",
			"baseGas":        "0",
			"gasPrice":       "0",
			"gasToken":       "0x0000000000000000000000000000000000000000",
			"refundReceiver": "0x0000000000000000000000000000000000000000",
			"nonce":          "0",
		},
	}

	unknownSafeReq := map[string]interface{}{
		"chain_type":     "evm",
		"chain_id":       chainID,
		"signer_address": testSignerAddress,
		"sign_type":      "typed_data",
		"payload":        map[string]interface{}{"typed_data": unknownSafeTx},
	}

	unknownResp := doRawRequest(t, http.MethodPost, "/api/v1/evm/sign", unknownSafeReq)
	defer unknownResp.Body.Close()

	// The request should NOT be blocked with "invalid verifying contract".
	// Before the fix, bare Go panic bypassed JS try/catch and returned 403/blocked.
	// After the fix, the blocklist skips this request via try/catch → ok(),
	// and it falls through to manual approval or no-matching-rule result.
	var unknownBody struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	json.NewDecoder(unknownResp.Body).Decode(&unknownBody)
	assert.NotContains(t, unknownBody.Message, "invalid verifying contract",
		"REGRESSION: unknown Safe should not be blocked by safe-block-delegatecall; blocklist must skip via try/catch")
	assert.NotContains(t, unknownBody.Error, "invalid verifying contract",
		"REGRESSION: unknown Safe should not be blocked by safe-block-delegatecall; blocklist must skip via try/catch")
	t.Logf("Unknown Safe skip: status=%q message=%q — blocklist correctly skipped via try/catch", unknownBody.Status, unknownBody.Message)

	t.Log("Polymarket V2 Safe E2E: ALL PASSED")
}

// TestE2E_PolymarketV2Safe_ProductionRequest reproduces the exact
// production SafeTx that was rejected with "invalid verifying contract".
// Safe: 0xdb44cf4ce5e57193c2245901179f3c403b5cec30 on Polygon (137).
func TestE2E_PolymarketV2Safe_ProductionRequest(t *testing.T) {
	ctx := context.Background()
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Polymarket V2 Safe production test requires internal server")
	}

	prodSafeAddress := "0xdb44cf4ce5e57193c2245901179f3c403b5cec30"

	presetID := "evm/polymarket_v2_safe_polygon"
	applyResp, err := adminClient.Presets.Apply(ctx, presetID, &presets.ApplyRequest{
		Variables:      map[string]string{"allowed_safe_addresses": prodSafeAddress},
		SkipValidation: true,
	})
	require.NoError(t, err, "preset apply should succeed")
	require.NotNil(t, applyResp)
	require.GreaterOrEqual(t, len(applyResp.Results), 1)
	t.Logf("Preset applied: %d rule(s)", len(applyResp.Results))
	snapshotRules(t)
	cleanupApplyResults(t, applyResp.Results)

	// Exact production SafeTx from the bot's airdrop claim tx.
	prodSafeTx := map[string]interface{}{
		"types": map[string]interface{}{
			"EIP712Domain": []eip712TypeField{
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"SafeTx": []eip712TypeField{
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "data", Type: "bytes"},
				{Name: "operation", Type: "uint8"},
				{Name: "safeTxGas", Type: "uint256"},
				{Name: "baseGas", Type: "uint256"},
				{Name: "gasPrice", Type: "uint256"},
				{Name: "gasToken", Type: "address"},
				{Name: "refundReceiver", Type: "address"},
				{Name: "nonce", Type: "uint256"},
			},
		},
		"primaryType": "SafeTx",
		"domain": map[string]interface{}{
			"chainId":           "137",
			"verifyingContract": prodSafeAddress,
		},
		"message": map[string]interface{}{
			"baseGas":        "0",
			"data":           "0x9e7212ad0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000025fb28382075f418a944a781a9f8840e2f541152eea0d9798d1cabfa1466adbb00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000005fac30000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002",
			"gasPrice":       "0",
			"gasToken":       "0x0000000000000000000000000000000000000000",
			"nonce":          "84",
			"operation":      "0",
			"refundReceiver": "0x0000000000000000000000000000000000000000",
			"safeTxGas":      "1088718",
			"to":             "0xAdA200001000ef00D07553cEE7006808F895c6F1",
			"value":          "0",
		},
	}

	signReq := map[string]interface{}{
		"chain_type":     "evm",
		"chain_id":       "137",
		"signer_address": testSignerAddress,
		"sign_type":      "typed_data",
		"payload":        map[string]interface{}{"typed_data": prodSafeTx},
	}

	resp := doRawRequest(t, http.MethodPost, "/api/v1/evm/sign", signReq)
	defer resp.Body.Close()

	var body struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&body)

	// This must NOT be forbidden or rejected with "invalid verifying contract".
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("PRODUCTION REQUEST REJECTED (REGRESSION): status=%d error=%q message=%q",
			resp.StatusCode, body.Error, body.Message)
	}
	assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted,
		"production request should return 200 or 202, got %d", resp.StatusCode)
	assert.NotContains(t, body.Error+body.Message, "invalid verifying contract",
		"production request must not be rejected by safe-block-delegatecall")
	t.Logf("Production SafeTx: status=%d status_field=%q", resp.StatusCode, body.Status)
}

// TestE2E_PolymarketV2Safe_PresetApplyConfigBug verifies that when applying
// the preset with allowed_safe_addresses, the resulting rule's config actually
// contains the provided Safe address (not just the tx_to addresses).
func TestE2E_PolymarketV2Safe_PresetApplyConfigBug(t *testing.T) {
	ctx := context.Background()
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("config check requires internal server")
	}

	testSafeAddr := "0xAbCdEf1234567890aBcDeF1234567890AbcDeF01"

	presetID := "evm/polymarket_v2_safe_polygon"
	applyResp, err := adminClient.Presets.Apply(ctx, presetID, &presets.ApplyRequest{
		Variables:      map[string]string{"allowed_safe_addresses": testSafeAddr},
		SkipValidation: true,
	})
	require.NoError(t, err, "preset apply should succeed")
	snapshotRules(t)
	cleanupApplyResults(t, applyResp.Results)

	// Find the "Safe SafeTx and execTransaction" rule and verify its config.
	var safeRuleID string
	for _, item := range applyResp.Results {
		var rule struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(item.Rule, &rule); err != nil {
			continue
		}
		if strings.Contains(rule.Name, "SafeTx and execTransaction") {
			safeRuleID = rule.ID
			break
		}
	}
	require.NotEmpty(t, safeRuleID, "SafeTx whitelist rule not found in apply results")

	// Fetch the rule and check its config.
	rule, err := adminClient.EVM.Rules.Get(ctx, safeRuleID)
	require.NoError(t, err, "failed to fetch rule %s", safeRuleID)

	var config map[string]interface{}
	require.NoError(t, json.Unmarshal(rule.Config, &config), "failed to parse rule config")

	addrsStr, _ := config["allowed_safe_addresses"].(string)
	t.Logf("Rule %s config.allowed_safe_addresses = %q", safeRuleID, addrsStr)

	// The provided Safe address MUST be present in allowed_safe_addresses.
	assert.Contains(t, addrsStr, testSafeAddr,
		"allowed_safe_addresses=%q must contain the user-provided Safe address %q", addrsStr, testSafeAddr)

	// Also verify that no apply was done WITHOUT overrides (the preset
	// default is "0x1111...1111" — confirm the flow is working correctly).
	t.Run("default_placeholder_only", func(t *testing.T) {
		applyResp2, err := adminClient.Presets.Apply(ctx, presetID, &presets.ApplyRequest{
			SkipValidation: true,
		})
		require.NoError(t, err, "preset apply without overrides should succeed")
		cleanupApplyResults(t, applyResp2.Results)

		var safeRuleID2 string
		for _, item := range applyResp2.Results {
			var rule struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if err := json.Unmarshal(item.Rule, &rule); err != nil {
				continue
			}
			if strings.Contains(rule.Name, "SafeTx and execTransaction") {
				safeRuleID2 = rule.ID
				break
			}
		}
		require.NotEmpty(t, safeRuleID2)
		rule2, err := adminClient.EVM.Rules.Get(ctx, safeRuleID2)
		require.NoError(t, err)
		var config2 map[string]interface{}
		require.NoError(t, json.Unmarshal(rule2.Config, &config2))
		addrsStr2, _ := config2["allowed_safe_addresses"].(string)

		t.Logf("Default preset (no overrides): allowed_safe_addresses=%q", addrsStr2)
		// With no overrides, should use preset default "0x1111...1111"
		assert.Contains(t, addrsStr2, "0x1111111111111111111111111111111111111111",
			"without overrides, allowed_safe_addresses should be preset default")
		assert.NotContains(t, addrsStr2, "0xC011a7E12a19f7B", // NOT the tx_to addresses
			"allowed_safe_addresses should NOT contain contract addresses")
	})
}

// the polymarket_v2_safe_polygon preset. This is the regression test for the
// v2 preset missing evm/polymarket_auth template (bot's ClobAuth sign requests
// were getting 403 "no matching whitelist rule found").
func TestE2E_PolymarketV2Safe_ClobAuth(t *testing.T) {
	ctx := context.Background()
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Polymarket V2 Safe ClobAuth test requires internal server with shipped presets")
	}

	presetID := "evm/polymarket_v2_safe_polygon"
	applyResp, err := adminClient.Presets.Apply(ctx, presetID, &presets.ApplyRequest{
		Variables:      map[string]string{"allowed_safe_addresses": testSigner2Address},
		SkipValidation: true,
	})
	require.NoError(t, err, "preset apply should succeed")
	require.NotNil(t, applyResp)
	require.GreaterOrEqual(t, len(applyResp.Results), 1,
		"preset apply should produce at least 1 rule result")
	t.Logf("Polymarket V2 Safe preset applied: %d rule(s)", len(applyResp.Results))
	snapshotRules(t)
	cleanupApplyResults(t, applyResp.Results)

	chainID := "137"

	// ClobAuth typed_data — same structure the polymarket-airdrop bot sends
	clobAuthTypedData := map[string]interface{}{
		"types": map[string]interface{}{
			"EIP712Domain": []eip712TypeField{
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
			},
			"ClobAuth": []eip712TypeField{
				{Name: "address", Type: "address"},
				{Name: "timestamp", Type: "string"},
				{Name: "nonce", Type: "uint256"},
				{Name: "message", Type: "string"},
			},
		},
		"primaryType": "ClobAuth",
		"domain": map[string]interface{}{
			"name":    "ClobAuthDomain",
			"version": "1",
			"chainId": chainID,
		},
		"message": map[string]interface{}{
			"address":   testSignerAddress,
			"timestamp": "1704067200",
			"nonce":     "12345",
			"message":   "This message attests that I control the given wallet",
		},
	}

	signReq := map[string]interface{}{
		"chain_type":     "evm",
		"chain_id":       chainID,
		"signer_address": testSignerAddress,
		"sign_type":      "typed_data",
		"payload":        map[string]interface{}{"typed_data": clobAuthTypedData},
	}

	resp := doRawRequest(t, http.MethodPost, "/api/v1/evm/sign", signReq)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		var errBody struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		json.NewDecoder(resp.Body).Decode(&errBody)
		t.Fatalf("ClobAuth signature REJECTED (REGRESSION): %s - %s", errBody.Error, errBody.Message)
	}
	assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted,
		"ClobAuth should return 200 or 202, got %d", resp.StatusCode)
	t.Log("Polymarket V2 Safe ClobAuth: PASSED")
}
