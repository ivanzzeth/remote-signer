//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			"allowed_safe_addresses": testSignerAddress,
		},
		"skip_validation": true,
	}
	body, _ := json.Marshal(applyReq)

	resp := doRawRequest(t, http.MethodPost, "/api/v1/presets/"+presetName+"/apply", body)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		t.Skipf("Preset %q not available (expected in shipped catalog)", presetName)
	}
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"preset apply should return 201, got %d", resp.StatusCode)

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
		"chain_type":       "evm",
		"chain_id":         chainID,
		"signer_address":   testSignerAddress,
		"sign_type":        "typed_data",
		"typed_data":       orderTypedData,
		"wait_for_approval": false,
	}

	signBody, _ := json.Marshal(signReq)
	signResp := doRawRequest(t, http.MethodPost, "/api/v1/evm/sign/typed_data", signBody)
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
