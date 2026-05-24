//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// =============================================================================
// Helpers for the validate endpoints (no SDK wrapper exists yet)
// =============================================================================

// response helpers mirroring internal/api/handler/evm/rule_response.go

// validateTestResult is the per-test-case result in a validate response.
type validateTestResult struct {
	Name       string `json:"name"`
	Passed     bool   `json:"passed"`
	ActualPass bool   `json:"actual_pass"`
	Reason     string `json:"reason,omitempty"`
}

// validateRuleResponse is the response for POST /api/v1/evm/rules/{id}/validate.
type validateRuleResponse struct {
	RuleID   string               `json:"rule_id"`
	RuleName string               `json:"rule_name"`
	Type     string               `json:"type"`
	Valid    bool                 `json:"valid"`
	Results  []validateTestResult `json:"results,omitempty"`
	Error    string               `json:"error,omitempty"`
}

// batchValidateResponse is the response for POST /api/v1/evm/rules/validate.
type batchValidateResponse struct {
	Results []validateRuleResponse `json:"results"`
	Total   int                    `json:"total"`
	Passed  int                    `json:"passed"`
	Failed  int                    `json:"failed"`
}

// validateRuleResultItem is a single rule result in template/preset validation responses.
type validateRuleResultItem struct {
	RuleID   string `json:"rule_id,omitempty"`
	RuleName string `json:"rule_name"`
	Type     string `json:"type"`
	Mode     string `json:"mode"`
	Valid    bool   `json:"valid"`
	Error    string `json:"error,omitempty"`
}

// validateTemplateResponse mirrors handler.validateTemplateResponse.
type validateTemplateResponse struct {
	TemplateID   string                  `json:"template_id"`
	TemplateName string                  `json:"template_name"`
	Results      []*validateRuleResultItem `json:"results,omitempty"`
	Total        int                     `json:"total"`
	Passed       int                     `json:"passed"`
	Failed       int                     `json:"failed"`
}

// validatePresetResponse mirrors handler.validatePresetResponse.
type validatePresetResponse struct {
	PresetID   string                  `json:"preset_id"`
	PresetName string                  `json:"preset_name"`
	Results    []*validateRuleResultItem `json:"results,omitempty"`
	Total      int                     `json:"total"`
	Passed     int                     `json:"passed"`
	Failed     int                     `json:"failed"`
}

// rawSignedRequest sends an authenticated JSON request using Ed25519 signing and
// decodes the JSON response into result.
func rawSignedRequest(t *testing.T, method, path string, body, result interface{}) {
	t.Helper()

	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		require.NoError(t, err, "marshal request body")
	}

	reqURL := baseURL + path

	var bodyReader io.Reader
	if bodyBytes != nil {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, reqURL, bodyReader)
	require.NoError(t, err, "create request")

	if bodyBytes != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Ed25519 signing (matches internal/api/middleware/auth.go and pkg/client/internal/transport/auth.go)
	timestamp := time.Now().UnixMilli()
	nonceBytes := make([]byte, 16)
	_, err = rand.Read(nonceBytes)
	require.NoError(t, err, "generate nonce")
	nonce := hex.EncodeToString(nonceBytes)

	bodyHash := sha256.Sum256(bodyBytes)
	message := fmt.Sprintf("%d|%s|%s|%s|%x", timestamp, nonce, method, path, bodyHash)

	keyBytes, err := hex.DecodeString(adminAPIKeyHex)
	require.NoError(t, err, "decode admin private key")

	var privKey ed25519.PrivateKey
	switch len(keyBytes) {
	case ed25519.SeedSize:
		privKey = ed25519.NewKeyFromSeed(keyBytes)
	case ed25519.PrivateKeySize:
		privKey = ed25519.PrivateKey(keyBytes)
	default:
		t.Fatalf("unexpected private key length: %d", len(keyBytes))
	}
	signature := ed25519.Sign(privKey, []byte(message))

	req.Header.Set("X-API-Key-ID", adminAPIKeyID)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(signature))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "execute request")
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read response body")

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"expected 200 OK, got %d: %s", resp.StatusCode, string(respBytes))

	if result != nil {
		err = json.Unmarshal(respBytes, result)
		require.NoError(t, err, "unmarshal response: %s", string(respBytes))
	}
}

// =============================================================================
// Test: Single rule validate endpoint
// =============================================================================

func TestE2E_ValidateRuleEndpoint(t *testing.T) {
	ensureGuardResumed(t)
	snapshotRules(t)
	ctx := context.Background()

	// A script that passes for chain 1 and fails for chain 999.
	script := `function validate(input) {
		if (input.chain_id === 999) return fail("chain 999 blocked");
		return ok();
	}`

	chainType := "evm"

	// ── 1. Create an evm_js rule with test_cases (passing + failing) ──
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:      "E2E Validate Single - evm_js",
		Type:      "evm_js",
		Mode:      "whitelist",
		ChainType: &chainType,
		Config: map[string]interface{}{
			"script": script,
			"test_cases": []map[string]interface{}{
				{
					"name":       "pass: chain 1",
					"input":      map[string]interface{}{"sign_type": "personal", "chain_id": 1, "signer": signerAddress, "personal_sign": map[string]interface{}{"message": "hi"}},
					"expect_pass": true,
				},
				{
					"name":         "fail: chain 999",
					"input":        map[string]interface{}{"sign_type": "personal", "chain_id": 999, "signer": signerAddress, "personal_sign": map[string]interface{}{"message": "hi"}},
					"expect_pass":   false,
					"expect_reason": "chain 999 blocked",
				},
			},
		},
		Enabled: true,
	})
	require.NoError(t, err, "create evm_js rule")
	t.Cleanup(func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) })

	// ── 2. Validate the rule ──
	var vresp validateRuleResponse
	rawSignedRequest(t, http.MethodPost, "/api/v1/evm/rules/"+rule.ID+"/validate", nil, &vresp)

	// Verify overall structure
	assert.Equal(t, rule.ID, vresp.RuleID)
	assert.Equal(t, "E2E Validate Single - evm_js", vresp.RuleName)
	assert.Equal(t, "evm_js", vresp.Type)
	assert.True(t, vresp.Valid, "all test cases should pass -> valid=true")
	assert.Empty(t, vresp.Error, "no error expected for passing test cases")

	// Verify per-test-case results
	require.Len(t, vresp.Results, 2, "should have 2 test case results")

	// First test case: passing
	assert.Equal(t, "pass: chain 1", vresp.Results[0].Name)
	assert.True(t, vresp.Results[0].Passed)
	assert.True(t, vresp.Results[0].ActualPass)

	// Second test case: failing (but expect_pass=false so it passes)
	assert.Equal(t, "fail: chain 999", vresp.Results[1].Name)
	assert.True(t, vresp.Results[1].Passed, "expected fail and got fail -> passed=true")
	assert.False(t, vresp.Results[1].ActualPass, "validate should return fail (actual_pass=false)")
	assert.Contains(t, vresp.Results[1].Reason, "chain 999 blocked")

	// ── 3. Create a rule whose test case actually fails ──
	badScript := `function validate(input) { return ok(); }`
	badRule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:      "E2E Validate Single - bad evm_js",
		Type:      "evm_js",
		Mode:      "whitelist",
		ChainType: &chainType,
		Config: map[string]interface{}{
			"script": badScript,
			"test_cases": []map[string]interface{}{
				{
					"name":        "should never pass",
					"input":       map[string]interface{}{"sign_type": "personal", "chain_id": 1, "signer": signerAddress, "personal_sign": map[string]interface{}{"message": "hi"}},
					"expect_pass": false,
				},
			},
		},
		Enabled: true,
	})
	require.NoError(t, err, "create evm_js rule that will fail validation")
	t.Cleanup(func() { _ = adminClient.EVM.Rules.Delete(ctx, badRule.ID) })

	var bvresp validateRuleResponse
	rawSignedRequest(t, http.MethodPost, "/api/v1/evm/rules/"+badRule.ID+"/validate", nil, &bvresp)

	assert.False(t, bvresp.Valid, "test case expects fail but script returns ok -> valid=false")
	assert.Contains(t, bvresp.Error, "one or more test cases failed")
	require.Len(t, bvresp.Results, 1)
	assert.False(t, bvresp.Results[0].Passed)

	// ── 4. Non-evm_js rule returns bad request ──
	nonJSRule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:      "E2E Validate Non-JS",
		Type:      "evm_address_list",
		Mode:      "whitelist",
		ChainType: &chainType,
		Config:    map[string]interface{}{"addresses": []string{"0x0000000000000000000000000000000000000001"}},
		Enabled:   true,
	})
	require.NoError(t, err, "create address_list rule")
	t.Cleanup(func() { _ = adminClient.EVM.Rules.Delete(ctx, nonJSRule.ID) })

	resp := doRawRequest(t, http.MethodPost, "/api/v1/evm/rules/"+nonJSRule.ID+"/validate", nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "non-evm_js rules should return 400")
}

// =============================================================================
// Test: Batch validate
// =============================================================================

func TestE2E_BatchValidateRules(t *testing.T) {
	ensureGuardResumed(t)
	snapshotRules(t)
	ctx := context.Background()

	chainType := "evm"
	script := `function validate(input) { return ok(); }`

	// Create two evm_js rules with passing test cases
	rule1, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:      "E2E Batch Validate - rule 1",
		Type:      "evm_js",
		Mode:      "whitelist",
		ChainType: &chainType,
		Config: map[string]interface{}{
			"script": script,
			"test_cases": []map[string]interface{}{
				{
					"name":        "always pass 1",
					"input":       map[string]interface{}{"sign_type": "personal", "chain_id": 1, "signer": signerAddress, "personal_sign": map[string]interface{}{"message": "hello"}},
					"expect_pass": true,
				},
			},
		},
		Enabled: true,
	})
	require.NoError(t, err, "create rule 1")
	t.Cleanup(func() { _ = adminClient.EVM.Rules.Delete(ctx, rule1.ID) })

	rule2, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:      "E2E Batch Validate - rule 2",
		Type:      "evm_js",
		Mode:      "blocklist",
		ChainType: &chainType,
		Config: map[string]interface{}{
			"script": `function validate(input) { return fail("always blocked"); }`,
			"test_cases": []map[string]interface{}{
				{
					"name":        "expect block",
					"input":       map[string]interface{}{"sign_type": "personal", "chain_id": 1, "signer": signerAddress, "personal_sign": map[string]interface{}{"message": "hi"}},
					"expect_pass": false,
				},
			},
		},
		Enabled: true,
	})
	require.NoError(t, err, "create rule 2")
	t.Cleanup(func() { _ = adminClient.EVM.Rules.Delete(ctx, rule2.ID) })

	// Batch validate
	var bresp batchValidateResponse
	rawSignedRequest(t, http.MethodPost, "/api/v1/evm/rules/validate", nil, &bresp)

	require.GreaterOrEqual(t, bresp.Total, 2, "batch validate should include at least 2 evm_js rules")
	assert.GreaterOrEqual(t, bresp.Passed, 2, "both created rules should pass validation")
	assert.Equal(t, 0, bresp.Failed, "no rules should fail batch validation")

	// Find our rules in the results
	var found1, found2 bool
	for _, r := range bresp.Results {
		switch r.RuleID {
		case rule1.ID:
			found1 = true
			assert.True(t, r.Valid)
		case rule2.ID:
			found2 = true
			assert.True(t, r.Valid, "blocklist with expect_pass=false should be valid")
		}
	}
	assert.True(t, found1, "rule 1 should appear in batch results")
	assert.True(t, found2, "rule 2 should appear in batch results")
}

// =============================================================================
// Test: Template validate
// =============================================================================

func TestE2E_ValidateTemplate(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()

	// Find a known template from the registry. Prefer evm/agent (has evm_js test_cases).
	// Skip e2e-only helper templates (source=file) that may lack test_variables
	// needed for validation, e.g. e2e_delegator with delegate_to but no test_variables.
	templatesResp, err := adminClient.Templates.List(ctx, nil)
	require.NoError(t, err)
	require.NotEmpty(t, templatesResp.Templates, "at least one template must be synced")

	var targetID string
	for _, tmpl := range templatesResp.Templates {
		if tmpl.ID == "evm/agent" {
			targetID = tmpl.ID
			break
		}
	}
	if targetID == "" {
		// Fallback: pick any config-source evm_js template.
		// Skip file-source e2e helpers (e.g. e2e_delegator with delegate_to but no test_variables).
		for _, tmpl := range templatesResp.Templates {
			if tmpl.Type == "evm_js" && tmpl.Source == "config" {
				targetID = tmpl.ID
				break
			}
		}
	}
	if targetID == "" {
		// Last fallback: first config-source template
		for _, tmpl := range templatesResp.Templates {
			if tmpl.Source == "config" {
				targetID = tmpl.ID
				break
			}
		}
	}
	require.NotEmpty(t, targetID, "no suitable template found for validate test")

	var vresp validateTemplateResponse
	rawSignedRequest(t, http.MethodPost, "/api/v1/templates/"+targetID+"/validate", nil, &vresp)

	// Verify response structure
	assert.Equal(t, targetID, vresp.TemplateID)
	assert.NotEmpty(t, vresp.TemplateName)
	assert.GreaterOrEqual(t, vresp.Total, 1, "at least one rule result")

	// All results should either be valid=true, or valid=false with an error.
	for _, result := range vresp.Results {
		if !result.Valid {
			assert.NotEmpty(t, result.Error, "invalid result should have an error message")
		}
	}
}

// =============================================================================
// Test: Preset validate
// =============================================================================

func TestE2E_ValidatePreset(t *testing.T) {
	ensureGuardResumed(t)
	skipIfPresetAPIDisabled(t)

	// Use e2e_minimal.preset (always available in internal mode).
	var vresp validatePresetResponse
	rawSignedRequest(t, http.MethodPost, "/api/v1/presets/e2e_minimal.preset/validate", nil, &vresp)

	// Verify response structure
	assert.Equal(t, "e2e_minimal.preset", vresp.PresetID)
	assert.NotEmpty(t, vresp.PresetName)
	assert.GreaterOrEqual(t, vresp.Total, 1, "at least one rule result from the preset's templates")
	assert.GreaterOrEqual(t, vresp.Passed, vresp.Total, "all results should pass or be counted as passed")
}

// doRawRequest sends an authenticated GET/POST request and returns the raw *http.Response.
// The caller must close resp.Body.
func doRawRequest(t *testing.T, method, path string, body interface{}) *http.Response {
	t.Helper()

	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		require.NoError(t, err, "marshal request body")
	}

	reqURL := baseURL + path

	var bodyReader io.Reader
	if bodyBytes != nil {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, reqURL, bodyReader)
	require.NoError(t, err, "create request")

	if bodyBytes != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	timestamp := time.Now().UnixMilli()
	nonceBytes := make([]byte, 16)
	_, err = rand.Read(nonceBytes)
	require.NoError(t, err, "generate nonce")
	nonce := hex.EncodeToString(nonceBytes)

	bodyHash := sha256.Sum256(bodyBytes)
	message := fmt.Sprintf("%d|%s|%s|%s|%x", timestamp, nonce, method, path, bodyHash)

	keyBytes, err := hex.DecodeString(adminAPIKeyHex)
	require.NoError(t, err, "decode admin private key")

	var privKey ed25519.PrivateKey
	switch len(keyBytes) {
	case ed25519.SeedSize:
		privKey = ed25519.NewKeyFromSeed(keyBytes)
	case ed25519.PrivateKeySize:
		privKey = ed25519.PrivateKey(keyBytes)
	default:
		t.Fatalf("unexpected private key length: %d", len(keyBytes))
	}
	signature := ed25519.Sign(privKey, []byte(message))

	req.Header.Set("X-API-Key-ID", adminAPIKeyID)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(signature))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "execute request")
	return resp
}
