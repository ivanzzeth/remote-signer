package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ---------------------------------------------------------------------------
// validateTemplate — coverage gap tests (currently 38.3%)
// ---------------------------------------------------------------------------

// newHandlerNoJS creates a TemplateHandler without a JS evaluator.
func newHandlerNoJS(t *testing.T) *TemplateHandler {
	t.Helper()
	repo := newErrTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	svc, err := service.NewTemplateService(repo, ruleRepo, budgetRepo, newTestLogger())
	require.NoError(t, err)
	h, err := NewTemplateHandler(repo, svc, newTestLogger(), false)
	require.NoError(t, err)
	return h
}

// doValidateRequest sends a POST to /api/v1/templates/{id}/validate.
func doValidateRequest(t *testing.T, h *TemplateHandler, tmplID string, body any, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewBuffer(b)
	} else {
		bodyReader = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/"+tmplID+"/validate", bodyReader)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestValidateTemplate_InternalRepoError(t *testing.T) {
	repo := newErrTemplateRepo()
	repo.getErr = fmt.Errorf("connection lost")
	h := newErrHandler(t, repo)

	rr := doValidateRequest(t, h, "some-id", nil, testAPIKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "failed to get template")
}

func TestValidateTemplate_NilJSEvaluator(t *testing.T) {
	repo := newErrTemplateRepo()
	repo.seed(makeAPITemplate("tmpl-no-js", "No JS Template"))

	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	svc, err := service.NewTemplateService(repo, ruleRepo, budgetRepo, newTestLogger())
	require.NoError(t, err)
	hNilJS, err := NewTemplateHandler(repo, svc, newTestLogger(), false)
	require.NoError(t, err)

	rr := doValidateRequest(t, hNilJS, "tmpl-no-js", nil, testAPIKey())
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "JS evaluator not available")
}

func TestValidateTemplate_InvalidTestVariables(t *testing.T) {
	repo := newErrTemplateRepo()
	tmpl := makeAPITemplate("tmpl-bad-tv", "Bad Test Vars")
	tmpl.TestVariables = []byte(`{invalid`)
	repo.seed(tmpl)
	h := newErrHandler(t, repo)
	// Give handler a JS evaluator
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	h.jsEvaluator = eval

	rr := doValidateRequest(t, h, "tmpl-bad-tv", nil, testAPIKey())
	// Invalid test_variables is logged but not an error — the code sets testVars = make(map[string]string) and continues
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestValidateTemplate_InvalidVariablesJSON(t *testing.T) {
	repo := newErrTemplateRepo()
	tmpl := makeAPITemplate("tmpl-bad-vars-json", "Bad Vars JSON")
	tmpl.Variables = []byte(`{broken`)
	repo.seed(tmpl)
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	h := newErrHandler(t, repo)
	h.jsEvaluator = eval

	rr := doValidateRequest(t, h, "tmpl-bad-vars-json", nil, testAPIKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "failed to parse template variables")
}

func TestValidateTemplate_SubstitutionFailure(t *testing.T) {
	repo := newErrTemplateRepo()
	// Template config references a variable that doesn't exist and has no default
	tmpl := &types.RuleTemplate{
		ID:        "tmpl-sub-fail",
		Name:      "Sub Fail Template",
		Type:      types.RuleTypeEVMAddressList,
		Mode:      types.RuleModeWhitelist,
		Config:    []byte(`{"rules":[{"name":"r1","type":"evm_address_list","mode":"whitelist","config":{"addresses":["${missing_var}"]}}]}`),
		Source:    types.RuleSourceAPI,
		Enabled:   true,
		Variables: []byte(`[{"name":"missing_var","type":"string","required":true}]`),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	repo.seed(tmpl)
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	h := newErrHandler(t, repo)
	h.jsEvaluator = eval

	rr := doValidateRequest(t, h, "tmpl-sub-fail", nil, testAPIKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "variable substitution failed")
}

func TestValidateTemplate_FlatConfigPath(t *testing.T) {
	repo := newErrTemplateRepo()
	// "rules" as non-array makes the bundle unmarshal fail, flat config unmarshal succeeds
	tmpl := &types.RuleTemplate{
		ID:      "tmpl-flat",
		Name:    "Flat Config Template",
		Type:    types.RuleTypeEVMJS,
		Mode:    types.RuleModeWhitelist,
		Config:  []byte(`{"rules":"not-an-array","script":"function validate(input) { return {valid: true}; }","test_cases":[{"name":"tc1","input":{"sign_type":"transaction","chain_id":"1","signer":"0x742d35Cc6634C0532925a3b844Bc454e4438f44e","transaction":{"to":"0xRecipientAddress0000000000000000000000000000","value":"0","data":"0x"}},"expect_pass":true}]}`),
		Source:  types.RuleSourceAPI,
		Enabled: true,
	}
	repo.seed(tmpl)
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	h := newErrHandler(t, repo)
	h.jsEvaluator = eval

	rr := doValidateRequest(t, h, "tmpl-flat", nil, testAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp validateTemplateResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "tmpl-flat", resp.TemplateID)
	assert.Equal(t, 1, resp.Total)
	assert.Equal(t, 1, resp.Passed)
}

func TestValidateTemplate_NonEVMJSFallback(t *testing.T) {
	repo := newErrTemplateRepo()
	// Config is a JSON array — fails both bundle and flat config unmarshal
	tmpl := &types.RuleTemplate{
		ID:      "tmpl-nonjs",
		Name:    "Non-JS Template",
		Type:    types.RuleTypeSignTypeRestriction,
		Mode:    types.RuleModeWhitelist,
		Config:  []byte(`["not-a-valid-config-object"]`),
		Source:  types.RuleSourceAPI,
		Enabled: true,
	}
	repo.seed(tmpl)
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	h := newErrHandler(t, repo)
	h.jsEvaluator = eval

	rr := doValidateRequest(t, h, "tmpl-nonjs", nil, testAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp validateTemplateResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 1, resp.Total)
	assert.Equal(t, 1, resp.Passed)
	assert.Equal(t, 0, resp.Failed)
	require.Len(t, resp.Results, 1)
	assert.Contains(t, resp.Results[0].Error, "non-evm_js template")
}

func TestValidateTemplate_NilTestCasesInConfig(t *testing.T) {
	repo := newErrTemplateRepo()
	tmpl := &types.RuleTemplate{
		ID:      "tmpl-nil-tc",
		Name:    "Nil Test Cases",
		Type:    types.RuleTypeEVMJS,
		Mode:    types.RuleModeWhitelist,
		Config:  []byte(`{"rules":[{"name":"js-rule","type":"evm_js","mode":"whitelist","config":{"script":"function validate(input){return {valid:true}}","test_cases":null}}]}`),
		Source:  types.RuleSourceAPI,
		Enabled: true,
	}
	repo.seed(tmpl)
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	h := newErrHandler(t, repo)
	h.jsEvaluator = eval

	rr := doValidateRequest(t, h, "tmpl-nil-tc", nil, testAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp validateTemplateResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 1, resp.Total)
}

func TestValidateTemplate_InvalidTestCasesJSON(t *testing.T) {
	repo := newErrTemplateRepo()
	tmpl := &types.RuleTemplate{
		ID:      "tmpl-bad-tc",
		Name:    "Bad Test Cases JSON",
		Type:    types.RuleTypeEVMJS,
		Mode:    types.RuleModeWhitelist,
		Config:  []byte(`{"rules":[{"name":"js-rule","type":"evm_js","mode":"whitelist","config":{"script":"function validate(input){return {valid:true}}","test_cases":"not-an-array"}}]}`),
		Source:  types.RuleSourceAPI,
		Enabled: true,
	}
	repo.seed(tmpl)
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	h := newErrHandler(t, repo)
	h.jsEvaluator = eval

	rr := doValidateRequest(t, h, "tmpl-bad-tc", nil, testAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp validateTemplateResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 1, resp.Total)
}

func TestValidateTemplate_ChainIDInjection(t *testing.T) {
	repo := newErrTemplateRepo()
	tmpl := &types.RuleTemplate{
		ID:            "tmpl-chain",
		Name:          "Chain ID Template",
		Type:          types.RuleTypeEVMJS,
		Mode:          types.RuleModeWhitelist,
		ChainType:     types.ChainTypeEVM,
		Config:        []byte(`{"rules":[{"name":"js-rule","type":"evm_js","mode":"whitelist","config":{"script":"function validate(input) { return {valid: true}; }","test_cases":[{"name":"tc1","input":{"sign_type":"transaction","chain_id":"${chain_id}","signer":"0x742d35Cc6634C0532925a3b844Bc454e4438f44e","transaction":{"to":"0xRecipientAddress0000000000000000000000000000","value":"0","data":"0x"}},"expect_pass":true}]}}]}`),
		TestVariables: []byte(`{"chain_id":"137"}`),
		Source:        types.RuleSourceAPI,
		Enabled:       true,
	}
	tmpl.CreatedAt = time.Now()
	tmpl.UpdatedAt = time.Now()
	repo.seed(tmpl)
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	h := newErrHandler(t, repo)
	h.jsEvaluator = eval

	rr := doValidateRequest(t, h, "tmpl-chain", nil, testAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp validateTemplateResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 1, resp.Passed)
}

func TestValidateTemplate_ForbiddenForNonAdmin(t *testing.T) {
	h := newHandlerNoJS(t)
	nonAdmin := &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}
	rr := doValidateRequest(t, h, "some-id", nil, nonAdmin)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "admin role required")
}

// ---------------------------------------------------------------------------
// instantiateTemplate — coverage gap tests (currently 59.5%)
// ---------------------------------------------------------------------------

func TestInstantiateTemplate_RBACOwnershipError(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()

	// Create a template without variables (so ResolveTemplate succeeds)
	seedTemplate(t, tmplRepo, makeAPITemplate("tmpl-err-rbac", "RBAC Error"))

	h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)
	// Enable requireApproval so agent + whitelist triggers pending
	h.requireApproval = true

	// Use an agent key
	agentKey := &types.APIKey{ID: "agent-1", Role: types.RoleAgent, Enabled: true}

	reqBody := map[string]interface{}{"variables": map[string]string{}}
	rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/tmpl-err-rbac/instantiate", reqBody, agentKey)
	// Agent self-scoping should succeed (no error from RBAC)
	assert.Equal(t, http.StatusCreated, rr.Code)
}

func TestInstantiateTemplate_SubstitutionErrorInValidation(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()

	// Template with a required variable that's not provided → substitution fails
	tmpl := makeTemplateWithVars("tmpl-sub-err", "Sub Error")
	seedTemplate(t, tmplRepo, tmpl)

	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	svc := newTemplateService(t, tmplRepo, ruleRepo, budgetRepo)
	h, err := NewTemplateHandler(tmplRepo, svc, newTestLogger(), false, WithTemplateJSEvaluator(eval))
	require.NoError(t, err)

	// Don't provide the required variable
	reqBody := map[string]interface{}{"variables": map[string]string{}}
	rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/tmpl-sub-err/instantiate", reqBody, testAPIKey())
	// Should fail due to substitution error OR missing required variable
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestInstantiateTemplate_TestCaseValidationFailure(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()

	// evm_js template with bundle-style config: script returns false but test_case expects pass
	tmpl := &types.RuleTemplate{
		ID:      "tmpl-val-fail",
		Name:    "Validation Fail",
		Type:    types.RuleTypeEVMJS,
		Mode:    types.RuleModeWhitelist,
		Config:  []byte(`{"rules":[{"name":"js-rule","type":"evm_js","mode":"whitelist","config":{"script":"function validate(input) { return {valid: false, reason: 'blocked'}; }","test_cases":[{"name":"tc1","input":{"sign_type":"transaction","chain_id":"1","signer":"0x742d35Cc6634C0532925a3b844Bc454e4438f44e","transaction":{"to":"0xRecipientAddress0000000000000000000000000000","value":"0","data":"0x"}},"expect_pass":true}]}}]}`),
		Source:  types.RuleSourceConfig,
		Enabled: true,
	}
	tmpl.CreatedAt = time.Now()
	tmpl.UpdatedAt = time.Now()
	seedTemplate(t, tmplRepo, tmpl)

	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	svc := newTemplateService(t, tmplRepo, ruleRepo, budgetRepo)
	h, err := NewTemplateHandler(tmplRepo, svc, newTestLogger(), false, WithTemplateJSEvaluator(eval))
	require.NoError(t, err)

	reqBody := map[string]interface{}{"variables": map[string]string{}}
	rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/tmpl-val-fail/instantiate", reqBody, testAPIKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "test case validation failed")
}

func TestInstantiateTemplate_TestCaseValidationSkipped(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()

	// Same failing template but skip_validation=true
	tmpl := &types.RuleTemplate{
		ID:      "tmpl-skip-val",
		Name:    "Skip Validation",
		Type:    types.RuleTypeEVMJS,
		Mode:    types.RuleModeWhitelist,
		Config:  []byte(`{"script":"function validate(input) { return {valid: false}; }","test_cases":[{"name":"tc1","input":{"sign_type":"transaction","chain_id":"1","signer":"0x742d35Cc6634C0532925a3b844Bc454e4438f44e","transaction":{"to":"0xRecipientAddress0000000000000000000000000000","value":"0","data":"0x"}},"expect_pass":true}]}`),
		Source:  types.RuleSourceConfig,
		Enabled: true,
	}
	seedTemplate(t, tmplRepo, tmpl)

	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	svc := newTemplateService(t, tmplRepo, ruleRepo, budgetRepo)
	h, err := NewTemplateHandler(tmplRepo, svc, newTestLogger(), false, WithTemplateJSEvaluator(eval))
	require.NoError(t, err)

	reqBody := map[string]interface{}{
		"variables":       map[string]string{},
		"skip_validation": true,
	}
	rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/tmpl-skip-val/instantiate", reqBody, testAPIKey())
	// Should succeed because validation is skipped
	assert.Equal(t, http.StatusCreated, rr.Code)
}

func TestInstantiateTemplate_ReadOnlyBlocks(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()

	svc := newTemplateService(t, tmplRepo, ruleRepo, budgetRepo)
	h, err := NewTemplateHandler(tmplRepo, svc, newTestLogger(), true)
	require.NoError(t, err)

	rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/tmpl-1/instantiate", map[string]interface{}{}, testAPIKey())
	assert.Equal(t, http.StatusForbidden, rr.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "rules_api_readonly")
}

func TestInstantiateTemplate_InvalidJSONBody(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	seedTemplate(t, tmplRepo, makeAPITemplate("tmpl-bad-body", "Bad Body"))
	h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/tmpl-bad-body/instantiate",
		bytes.NewBufferString("{not json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(contextWithAPIKey(req.Context(), testAPIKey()))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "invalid request body")
}

func TestInstantiateTemplate_SolidityForgeUnavailable(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()

	// Single solidity template — templateContainsSolidity returns true
	tmpl := &types.RuleTemplate{
		ID:      "tmpl-sol",
		Name:    "Solidity Template",
		Type:    types.RuleTypeEVMSolidityExpression,
		Mode:    types.RuleModeWhitelist,
		Config:  []byte(`{"expression":"true"}`),
		Source:  types.RuleSourceAPI,
		Enabled: true,
	}
	tmpl.CreatedAt = time.Now()
	tmpl.UpdatedAt = time.Now()
	seedTemplate(t, tmplRepo, tmpl)

	svc := newTemplateService(t, tmplRepo, ruleRepo, budgetRepo)
	h, err := NewTemplateHandler(tmplRepo, svc, newTestLogger(), false) // no WithTemplateSolidityValidator
	require.NoError(t, err)

	reqBody := map[string]interface{}{"variables": map[string]string{}}
	rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/tmpl-sol/instantiate", reqBody, testAPIKey())
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Contains(t, rr.Body.String(), "forge not available")
}

func TestInstantiateTemplate_SolidityForgeUnavailable_Bundle(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()

	// template_bundle with a solidity sub-rule
	tmpl := &types.RuleTemplate{
		ID:   "tmpl-bundle-sol",
		Name: "Bundle With Solidity",
		Type: "template_bundle",
		Mode: types.RuleModeWhitelist,
		Config: mustJSONP(t, map[string]interface{}{
			"rules": []map[string]interface{}{
				{
					"name": "sub-sol",
					"type": "evm_solidity_expression",
					"mode": "whitelist",
					"config": map[string]interface{}{
						"expression": "true",
					},
				},
			},
		}),
		Source:  types.RuleSourceAPI,
		Enabled: true,
	}
	tmpl.CreatedAt = time.Now()
	tmpl.UpdatedAt = time.Now()
	seedTemplate(t, tmplRepo, tmpl)

	svc := newTemplateService(t, tmplRepo, ruleRepo, budgetRepo)
	h, err := NewTemplateHandler(tmplRepo, svc, newTestLogger(), false) // no WithTemplateSolidityValidator
	require.NoError(t, err)

	reqBody := map[string]interface{}{"variables": map[string]string{}}
	rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/tmpl-bundle-sol/instantiate", reqBody, testAPIKey())
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Contains(t, rr.Body.String(), "forge not available")
}

func TestInstantiateTemplate_ResolveTemplateError(t *testing.T) {
	// Use the errTemplateRepo to inject a get error — ResolveTemplate calls repo.Get internally
	repo := newErrTemplateRepo()
	repo.getErr = fmt.Errorf("repository unavailable")

	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	svc, err := service.NewTemplateService(repo, ruleRepo, budgetRepo, newTestLogger())
	require.NoError(t, err)
	h, err := NewTemplateHandler(repo, svc, newTestLogger(), false)
	require.NoError(t, err)

	reqBody := map[string]interface{}{"variables": map[string]string{}}
	rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/nonexistent/instantiate", reqBody, testAPIKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "failed to resolve template")
}
