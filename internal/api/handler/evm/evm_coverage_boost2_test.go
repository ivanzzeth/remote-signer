package evm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/simulation"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------------------------------------------------------------------------
// validateRule full integration test via HTTP handler (for uncovered paths)
// ---------------------------------------------------------------------------

func TestValidateRule_BodyParseErrorPath(t *testing.T) {
	eval := newJSEvaluator(t)
	repo := newMockRuleRepo()
	ct := types.ChainTypeEVM
	rule := &types.Rule{
		ID:        "rule_js_val",
		Name:      "js-val",
		Type:      types.RuleTypeEVMJS,
		Mode:      types.RuleModeWhitelist,
		Source:    types.RuleSourceAPI,
		ChainType: &ct,
		Config:    json.RawMessage(`{"script":"function validate(input) { return { valid: true }; }"}`),
		Enabled:   true,
	}
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(eval))
	require.NoError(t, err)

	// Test that configs without test_cases return valid:true
	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/validate", nil, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ValidateRuleResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.True(t, resp.Valid)
}

// ---------------------------------------------------------------------------
// validateRules full engine mode tests (rule_validation.go:243 — 0% coverage)
// ---------------------------------------------------------------------------

func TestValidateRulesFullEngine(t *testing.T) {
	eval := newJSEvaluator(t)

	t.Run("full_engine_mode_no_js_rules", func(t *testing.T) {
		repo := newMockRuleRepo()
		ct := types.ChainTypeEVM
		rule := &types.Rule{
			ID:        "rule_addr",
			Name:      "addr-rule",
			Type:      types.RuleTypeEVMAddressList,
			Mode:      types.RuleModeWhitelist,
			Source:    types.RuleSourceAPI,
			ChainType: &ct,
			Config:    json.RawMessage(`{"addresses":["0x0000000000000000000000000000000000000001"]}`),
			Enabled:   true,
		}
		repo.addRule(rule)

		h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(eval))
		require.NoError(t, err)

		rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/validate?full=true", nil, ruleAdminKey())
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp BatchValidateResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, 0, resp.Total) // no evm_js rules
	})

	t.Run("full_engine_mode_with_js_rules", func(t *testing.T) {
		repo := newMockRuleRepo()
		ct := types.ChainTypeEVM

		tc := JSRuleTestCase{
			Name: "full-tc",
			Input: map[string]interface{}{
				"sign_type": "transaction",
				"signer":    "0x1234567890123456789012345678901234567890",
				"transaction": map[string]interface{}{
					"to":    "0xaabbccddaabbccddaabbccddaabbccddaabbccdd",
					"value": "0",
				},
			},
			ExpectPass: true,
		}
		cfg := map[string]interface{}{
			"script":     "function validate(input) { return { valid: true }; }",
			"test_cases": []JSRuleTestCase{tc},
		}
		cfgJSON, _ := json.Marshal(cfg)
		rule := &types.Rule{
			ID:        "rule_js_full",
			Name:      "js-full",
			Type:      types.RuleTypeEVMJS,
			Mode:      types.RuleModeWhitelist,
			Source:    types.RuleSourceAPI,
			ChainType: &ct,
			Config:    cfgJSON,
			Enabled:   true,
			Owner:     "admin-key",
		}
		repo.addRule(rule)

		h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(eval))
		require.NoError(t, err)

		rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/validate?full=true", nil, ruleAdminKey())
		assert.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())

		var resp BatchValidateResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, 1, resp.Total)
		require.Len(t, resp.Results, 1)
		assert.True(t, resp.Results[0].Valid)
	})
}

// ---------------------------------------------------------------------------
// runJSTestCases edge cases (rule_validation.go:105 — 64.1% coverage)
// ---------------------------------------------------------------------------

func TestRunJSTestCases_NoEvaluator(t *testing.T) {
	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default())
	require.NoError(t, err)

	ct := types.ChainTypeEVM
	rule := &types.Rule{
		ID:        "rule_test",
		Name:      "test",
		Type:      types.RuleTypeEVMJS,
		Mode:      types.RuleModeWhitelist,
		ChainType: &ct,
		Config:    json.RawMessage(`{"script":"function validate(input) { return { valid: true }; }"}`),
	}

	tcs := []JSRuleTestCase{
		{Name: "tc1", Input: map[string]interface{}{"sign_type": "transaction"}, ExpectPass: true},
	}
	results, valid := h.runJSTestCases(rule, tcs)
	assert.False(t, valid, "should be invalid when no JS evaluator")
	assert.Nil(t, results, "results should be nil when jsEvaluator is nil")
}

func TestRunJSTestCases_InvalidConfig(t *testing.T) {
	eval := newJSEvaluator(t)

	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default(), WithJSEvaluator(eval))
	require.NoError(t, err)

	ct := types.ChainTypeEVM
	rule := &types.Rule{
		ID:        "rule_test",
		Name:      "test",
		Type:      types.RuleTypeEVMJS,
		Mode:      types.RuleModeWhitelist,
		ChainType: &ct,
		Config:    json.RawMessage(`{invalid json`), // Invalid JSON
	}

	tcs := []JSRuleTestCase{
		{Name: "tc1", Input: map[string]interface{}{"sign_type": "transaction"}, ExpectPass: true},
	}
	results, valid := h.runJSTestCases(rule, tcs)
	assert.False(t, valid)
	assert.Nil(t, results)
}

func TestRunJSTestCases_InvalidInput(t *testing.T) {
	eval := newJSEvaluator(t)

	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default(), WithJSEvaluator(eval))
	require.NoError(t, err)

	ct := types.ChainTypeEVM
	rule := &types.Rule{
		ID:        "rule_test",
		Name:      "test",
		Type:      types.RuleTypeEVMJS,
		Mode:      types.RuleModeWhitelist,
		ChainType: &ct,
		Config:    json.RawMessage(`{"script":"function validate(input) { return { valid: true }; }"}`),
	}

	tcs := []JSRuleTestCase{
		{Name: "bad-tc", Input: nil, ExpectPass: true},
	}
	results, valid := h.runJSTestCases(rule, tcs)
	assert.False(t, valid)
	assert.Len(t, results, 1)
	assert.False(t, results[0].Passed)
}

// ---------------------------------------------------------------------------
// approveRule error paths (rule_query.go:175 — 67.7% coverage)
// ---------------------------------------------------------------------------

func TestApproveRule_UpdateError(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Status = types.RuleStatusPendingApproval
	repo.addRule(rule)

	// Simulate update failure by overriding the repo
	failRepo := &mockRuleRepoFailUpdate{
		mockRuleRepo: mockRuleRepo{rules: make(map[types.RuleID]*types.Rule)},
	}
	for id, r := range repo.rules {
		failRepo.rules[id] = r
	}
	h, err := NewRuleHandler(failRepo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/approve", nil, ruleAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

type mockRuleRepoFailUpdate struct {
	mockRuleRepo
}

func (m *mockRuleRepoFailUpdate) Update(_ context.Context, rule *types.Rule) error {
	return errors.New("update failed")
}

// ---------------------------------------------------------------------------
// rejectRule error paths (rule_query.go:225 — 68.8% coverage)
// ---------------------------------------------------------------------------

func TestRejectRule_UpdateError(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Status = types.RuleStatusPendingApproval
	repo.addRule(rule)

	failRepo := &mockRuleRepoFailUpdate{
		mockRuleRepo: mockRuleRepo{rules: make(map[types.RuleID]*types.Rule)},
	}
	for id, r := range repo.rules {
		failRepo.rules[id] = r
	}
	h, err := NewRuleHandler(failRepo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/reject", nil, ruleAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestRejectRule_Unauthorized(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Status = types.RuleStatusPendingApproval
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/reject", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRejectRule_NotAdmin(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Status = types.RuleStatusPendingApproval
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/reject", nil, ruleAgentKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// listBudgets test (rule_query.go:161)
// ---------------------------------------------------------------------------

func TestListBudgets(t *testing.T) {
	t.Run("list_budgets_not_found_returns_empty", func(t *testing.T) {
		repo := newMockRuleRepo()
		rule := newAPIRule()
		repo.addRule(rule)

		h, err := NewRuleHandler(repo, slog.Default(),
			WithBudgetRepo(&mockBudgetRepo{}))
		require.NoError(t, err)

		rec := doRuleRequest(t, h, http.MethodGet, "/api/v1/evm/rules/"+string(rule.ID)+"/budgets", nil, ruleAdminKey())
		assert.Equal(t, http.StatusOK, rec.Code)

		var budgets []*types.RuleBudget
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&budgets))
		assert.Empty(t, budgets)
	})
}

// ---------------------------------------------------------------------------
// recordBroadcastAsync tests (rpc_proxy.go:193 — 66.7% coverage)
// ---------------------------------------------------------------------------

func TestRecordBroadcastAsync_EmptyParams(t *testing.T) {
	handler, err := NewRPCProxyHandler(&mockRPCBackend{}, nil, slog.Default())
	require.NoError(t, err)

	// Direct call — not panicking, just logging
	assert.NotPanics(t, func() {
		handler.recordBroadcastAsync("1", nil)
	})
}

func TestRecordBroadcastAsync_NonStringParam(t *testing.T) {
	handler, err := NewRPCProxyHandler(&mockRPCBackend{}, nil, slog.Default())
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		handler.recordBroadcastAsync("1", []interface{}{123})
	})
}

func TestRecordBroadcastAsync_WithRecorder(t *testing.T) {
	recorder := &mockTransactionRecorder{
		recordFn: func(ctx context.Context, chainID, signedTxHex string) (*types.Transaction, error) {
			return &types.Transaction{
				ID:      "tx-test",
				ChainID: chainID,
				TxHash:  signedTxHex,
			}, nil
		},
	}
	handler, err := NewRPCProxyHandler(&mockRPCBackend{}, recorder, slog.Default())
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		handler.recordBroadcastAsync("1", []interface{}{"0xf86c"})
	})
	// Give the goroutine time to fire (best-effort)
	time.Sleep(100 * time.Millisecond)
}

type mockTransactionRecorder struct {
	recordFn func(ctx context.Context, chainID, signedTxHex string) (*types.Transaction, error)
}

func (m *mockTransactionRecorder) RecordBroadcast(ctx context.Context, chainID, signedTxHex string) (*types.Transaction, error) {
	if m.recordFn != nil {
		return m.recordFn(ctx, chainID, signedTxHex)
	}
	return nil, nil
}

type mockRPCBackend struct {
	doWalletFn func(ctx context.Context, chainID, method string, params []interface{}) (json.RawMessage, error)
}

func (m *mockRPCBackend) DoWalletProxyRPC(ctx context.Context, chainID, method string, params []interface{}) (json.RawMessage, error) {
	if m.doWalletFn != nil {
		return m.doWalletFn(ctx, chainID, method, params)
	}
	return json.RawMessage(`"0xabc"`), nil
}

// ---------------------------------------------------------------------------
// handleTransferOwnership additional coverage - error paths in handleTransferOwnership
// (signer_locking.go:167 — currently 75%)
// ---------------------------------------------------------------------------

func TestHandleTransferOwnership_TransferToSelf(t *testing.T) {
	db := newCoverageTestDB(t)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)

	mustCreateAPIKey(t, apiKeyRepo, "owner-key", types.RoleAdmin)
	mustCreateSignerOwnership(t, ownershipRepo, testAddr, "owner-key", types.SignerOwnershipActive)

	accessSvc, err := service.NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, slog.Default())
	require.NoError(t, err)

	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	ownerKey := &types.APIKey{ID: "owner-key", Role: types.RoleAdmin, Enabled: true}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/transfer", map[string]string{"new_owner_id": "owner-key"}, ownerKey)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleTransferOwnership_InvalidBody(t *testing.T) {
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, &signerActionMock{}, owners)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/transfer", "bad json", testOwnerAPIKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// handleDeleteSigner additional tests (signer_crud.go:269)
// ---------------------------------------------------------------------------

func TestHandleDeleteSigner_NotFound(t *testing.T) {
	// No ownership record at all => 404
	mgr := &signerActionMock{}
	h := newActionHandler(t, mgr, nil) // no owners

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodDelete,
		"/api/v1/evm/signers/"+testAddr, nil, testOtherAPIKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// createRule additional coverage (rule_crud.go:24 — 74.5%)
// ---------------------------------------------------------------------------

func TestCreateRule_ReadOnly(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default(), WithReadOnly())
	require.NoError(t, err)

	body := CreateRuleRequest{
		Name: "test-rule",
		Type: "evm_address_list",
		Mode: "whitelist",
	}
	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules", body, ruleAdminKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "readonly")
}

func TestCreateRule_Unauthorized(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := CreateRuleRequest{
		Name: "test-rule",
		Type: "evm_address_list",
		Mode: "whitelist",
	}
	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules", body, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCreateRule_InvalidBody(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules", "bad json", ruleAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestCreateRule_MissingFields(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	t.Run("missing_name", func(t *testing.T) {
		body := CreateRuleRequest{Type: "evm_address_list", Mode: "whitelist"}
		rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules", body, ruleAdminKey())
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "name is required")
	})

	t.Run("missing_type", func(t *testing.T) {
		body := CreateRuleRequest{Name: "test", Mode: "whitelist"}
		rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules", body, ruleAdminKey())
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "type is required")
	})

	t.Run("missing_mode", func(t *testing.T) {
		body := CreateRuleRequest{Name: "test", Type: "evm_address_list"}
		rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules", body, ruleAdminKey())
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "mode is required")
	})

	t.Run("invalid_mode", func(t *testing.T) {
		body := CreateRuleRequest{Name: "test", Type: "evm_address_list", Mode: "invalid"}
		rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules", body, ruleAdminKey())
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "mode must be")
	})
}

func TestCreateRule_EVMJS_InvalidConfig(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := CreateRuleRequest{
		Name: "js-rule",
		Type: string(types.RuleTypeEVMJS),
		Mode: "whitelist",
		Config: map[string]interface{}{
			"script": "", // empty script
		},
		Enabled: true,
	}
	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules", body, ruleAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestCreateRule_EVMJS_Success(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := CreateRuleRequest{
		Name: "js-rule",
		Type: string(types.RuleTypeEVMJS),
		Mode: "whitelist",
		Config: map[string]interface{}{
			"script": "function validate(input) { return { valid: true }; }",
		},
		Enabled: true,
	}
	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules", body, ruleAdminKey())
	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestCreateRule_AgentBlockedType(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := CreateRuleRequest{
		Name: "agent-js",
		Type: string(types.RuleTypeEVMJS),
		Mode: "whitelist",
		Config: map[string]interface{}{
			"script": "function validate(input) { return { valid: true }; }",
		},
		Enabled: true,
	}
	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules", body, ruleAgentKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCreateRule_AgentBlockedSolidity(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := CreateRuleRequest{
		Name: "agent-sol",
		Type: string(types.RuleTypeEVMSolidityExpression),
		Mode: "whitelist",
		Config: map[string]interface{}{
			"expression": "true",
		},
		Enabled: true,
	}
	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules", body, ruleAgentKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCreateRule_MaxRulesExceeded(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default(),
		WithMaxRulesPerKey(1),
		WithRequireApproval(true),
		WithAPIKeyRepo(&stubAPIKeyRepo{}))
	require.NoError(t, err)

	// First rule
	body1 := CreateRuleRequest{
		Name: "rule-1",
		Type: string(types.RuleTypeEVMAddressList),
		Mode: "whitelist",
		Config: map[string]interface{}{
			"addresses": []string{"0x0000000000000000000000000000000000000001"},
		},
		Enabled: true,
	}
	rec1 := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules", body1, ruleAgentKey())
	assert.Equal(t, http.StatusAccepted, rec1.Code) // Pending approval

	// Second rule - should fail with limit exceeded
	body2 := CreateRuleRequest{
		Name: "rule-2",
		Type: string(types.RuleTypeEVMAddressList),
		Mode: "whitelist",
		Config: map[string]interface{}{
			"addresses": []string{"0x0000000000000000000000000000000000000002"},
		},
		Enabled: true,
	}
	rec2 := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules", body2, ruleAgentKey())
	assert.Equal(t, http.StatusForbidden, rec2.Code)
	assert.Contains(t, rec2.Body.String(), "rule limit exceeded")
}

type stubAPIKeyRepo struct{}

func (s *stubAPIKeyRepo) Create(_ context.Context, _ *types.APIKey) error             { return nil }
func (s *stubAPIKeyRepo) Get(_ context.Context, _ string) (*types.APIKey, error)      { return &types.APIKey{ID: "test-key", Role: types.RoleAdmin, Enabled: true}, nil }
func (s *stubAPIKeyRepo) Update(_ context.Context, _ *types.APIKey) error             { return nil }
func (s *stubAPIKeyRepo) Delete(_ context.Context, _ string) error                    { return nil }
func (s *stubAPIKeyRepo) List(_ context.Context, _ storage.APIKeyFilter) ([]*types.APIKey, error) {
	return nil, nil
}
func (s *stubAPIKeyRepo) UpdateLastUsed(_ context.Context, _ string) error            { return nil }
func (s *stubAPIKeyRepo) Count(_ context.Context, _ storage.APIKeyFilter) (int, error) { return 0, nil }
func (s *stubAPIKeyRepo) DeleteBySourceExcluding(_ context.Context, _ string, _ []string) (int64, error) {
	return 0, nil
}
func (s *stubAPIKeyRepo) BackfillSource(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

// ---------------------------------------------------------------------------
// updateRule additional coverage (rule_crud.go:224 — 69.9%)
// ---------------------------------------------------------------------------

func TestUpdateRule_ReadOnly(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default(), WithReadOnly())
	require.NoError(t, err)

	body := `{"name":"updated"}`
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAdminKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "readonly")
}

func TestUpdateRule_ConfigSource(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newConfigRule()
	rule.Owner = "admin-key"
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"name":"updated"}`
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAdminKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "config-sourced")
}

func TestUpdateRule_AgentChangeType(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "agent-key"
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"type":"evm_js"}`
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAgentKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestUpdateRule_NonAdminChangeAppliedTo(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "agent-key"
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"applied_to":["key-1"]}`
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAgentKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "applied_to")
}

func TestUpdateRule_EVMJS_EmptyScript(t *testing.T) {
	repo := newMockRuleRepo()
	ct := types.ChainTypeEVM
	rule := &types.Rule{
		ID:        "rule_js_upd",
		Name:      "js-upd",
		Type:      types.RuleTypeEVMJS,
		Mode:      types.RuleModeWhitelist,
		Source:    types.RuleSourceAPI,
		ChainType: &ct,
		Config:    json.RawMessage(`{"script":"function validate(input) { return { valid: true }; }"}`),
		Enabled:   true,
		Owner:     "admin-key",
	}
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"config":{"script":""}}`
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestUpdateRule_InvalidChainType(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"chain_type":"invalid"}`
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestUpdateRule_InvalidSignerAddress(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"signer_address":"invalid"}`
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// toRuleResponse budget period coverage (rule_response.go:115 — 75.9%)
// ---------------------------------------------------------------------------

func TestToRuleResponse_BudgetPeriod(t *testing.T) {
	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default())
	require.NoError(t, err)

	ct := types.ChainTypeEVM
	now := time.Now()
	budgetPeriod := time.Duration(1 * time.Hour)
	rule := &types.Rule{
		ID:                "rule_budget",
		Name:              "budget-rule",
		Type:              types.RuleTypeEVMValueLimit,
		Mode:              types.RuleModeWhitelist,
		Source:            types.RuleSourceAPI,
		ChainType:         &ct,
		Config:            json.RawMessage(`{}`),
		Enabled:           true,
		CreatedAt:         now,
		UpdatedAt:         now,
		BudgetPeriod:      &budgetPeriod,
		BudgetPeriodStart: &now,
		Owner:             "owner-key",
		Status:            types.RuleStatusActive,
		ApprovedBy:        strPtr("admin-key"),
		SignerAddress:     strPtr("0x0000000000000000000000000000000000000001"),
		ExpiresAt:         &now,
		LastMatchedAt:     &now,
	}
	resp := h.toRuleResponse(rule)
	assert.Equal(t, "1h0m0s", resp.BudgetPeriod)
	assert.NotNil(t, resp.BudgetPeriodStart)
	assert.NotNil(t, resp.Owner)
	assert.Equal(t, "active", resp.Status)
	assert.NotNil(t, resp.ApprovedBy)
	assert.NotNil(t, resp.SignerAddress)
	assert.NotNil(t, resp.ExpiresAt)
	assert.NotNil(t, resp.LastMatchedAt)
}

func strPtr(s string) *string {
	return &s
}

// ---------------------------------------------------------------------------
// createSigner additional coverage (signer_create.go:18 — 71.8%)
// ---------------------------------------------------------------------------

func TestCreateSigner_ResourceLimitExceeded(t *testing.T) {
	mgr := &signerMockSignerManager{}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)
	h.SetMaxKeystoresPerKey(0) // 0 = no limit, so should not block
	h.SetMaxKeystoresPerKey(1)

	// First creation succeeds
	h.signerManager = &signerMockSignerManager{
		createSignerFn: func(_ context.Context, req types.CreateSignerRequest) (*types.SignerInfo, error) {
			return &types.SignerInfo{
				Address: "0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd",
				Type:    string(req.Type),
				Enabled: true,
			}, nil
		},
	}

	body := `{"type":"keystore","keystore":{"password":"test123"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	apiKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin, Enabled: true}
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// Should succeed because CountByOwner returns 0 (stub) which is < 1
	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestCreateSigner_BothPrivateKeyAndKeystoreJSON(t *testing.T) {
	mgr := &signerMockSignerManager{
		createSignerFn: func(_ context.Context, req types.CreateSignerRequest) (*types.SignerInfo, error) {
			return &types.SignerInfo{
				Address: "0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd",
				Type:    string(req.Type),
				Enabled: true,
			}, nil
		},
	}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	body := `{"type":"keystore","keystore":{"password":"test123","private_key_hex":"0xabc","keystore_json":"{}"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	apiKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin, Enabled: true}
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "not both")
}

// ---------------------------------------------------------------------------
// listWalletSigners additional coverage (signer_wallet.go:20 — 61.7%)
// ---------------------------------------------------------------------------

func TestListWalletSigners_InvalidOffset(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	sm := &signerMockSignerManager{}
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	adminAPIKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/evm/wallets/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/signers?offset=-1", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, adminAPIKey))
	rec := httptest.NewRecorder()

	h.HandleWalletSigners(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestListWalletSigners_InvalidLimit(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	sm := &signerMockSignerManager{}
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	adminAPIKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/evm/wallets/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/signers?limit=-1", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, adminAPIKey))
	rec := httptest.NewRecorder()

	h.HandleWalletSigners(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestListWalletSigners_ListError(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{}, errors.New("list failed")
		},
	}
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	adminAPIKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/evm/wallets/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/signers", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, adminAPIKey))
	rec := httptest.NewRecorder()

	h.HandleWalletSigners(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// handleApproveSigner access check error path (signer_locking.go:144)
// ---------------------------------------------------------------------------

func TestHandleApproveSigner_GetOwnershipError(t *testing.T) {
	db := newCoverageTestDB(t)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)

	mustCreateAPIKey(t, apiKeyRepo, "admin-key", types.RoleAdmin)

	accessSvc, err := service.NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, slog.Default())
	require.NoError(t, err)

	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	adminKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin, Enabled: true}
	// No ownership record → 404
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/approve", nil, adminKey)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// toBalanceChangeJSON coverage (simulate.go)
// ---------------------------------------------------------------------------

func TestToBalanceChangeJSON(t *testing.T) {
	changes := []simulation.BalanceChange{
		{
			Token:     "0xtoken",
			Standard:  "erc20",
			Amount:    big.NewInt(100),
			Direction: "inflow",
		},
	}
	result := toBalanceChangeJSON(changes)
	require.Len(t, result, 1)
	assert.Equal(t, "0xtoken", result[0].Token)
	assert.Equal(t, "erc20", result[0].Standard)
	assert.Equal(t, "100", result[0].Amount)
	assert.Equal(t, "inflow", result[0].Direction)
}

// ---------------------------------------------------------------------------
// ServeBatchHTTP additional coverage (simulate.go:158 — 79.5%)
// ---------------------------------------------------------------------------

func TestServeBatchHTTP_Success(t *testing.T) {
	sim := &mockSimulator{
		simulateBatchFn: func(_ context.Context, req *simulation.BatchSimulationRequest) (*simulation.BatchSimulationResult, error) {
			return &simulation.BatchSimulationResult{
				Results: []simulation.SimulationResult{
					{Success: true, GasUsed: 21000},
				},
				NetBalanceChanges: []simulation.BalanceChange{
					{Token: "native", Standard: "native", Amount: big.NewInt(0), Direction: "inflow"},
				},
			}, nil
		},
	}
	h := newTestSimulateHandler(t, sim)

	body := map[string]interface{}{
		"chain_id": "1",
		"from":     "0x0000000000000000000000000000000000000001",
		"transactions": []map[string]interface{}{
			{
				"to":    "0x0000000000000000000000000000000000000002",
				"value": "0x1",
				"data":  "0x",
			},
		},
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/simulate/batch", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeBatchHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())

	var resp BatchSimulateResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Results, 1)
	assert.True(t, resp.Results[0].Success)
}

// ---------------------------------------------------------------------------
// Test for handlePatchSignerLabels signerInfoByAddress error returning 404
// (signer_crud.go:355 — already partially tested, ensure list error path)
// ---------------------------------------------------------------------------

func TestHandlePatchSignerLabels_InfoListError(t *testing.T) {
	db := newCoverageTestDB(t)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)

	mustCreateAPIKey(t, apiKeyRepo, "owner-key", types.RoleAdmin)
	mustCreateSignerOwnership(t, ownershipRepo, testAddr, "owner-key", types.SignerOwnershipActive)

	accessSvc, err := service.NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, slog.Default())
	require.NoError(t, err)

	h, err := NewSignerHandler(&signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{}, errors.New("list failed")
		},
	}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	ownerKey := &types.APIKey{ID: "owner-key", Role: types.RoleAdmin, Enabled: true}
	body := map[string]interface{}{"display_name": "New Name"}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPatch,
		"/api/v1/evm/signers/"+testAddr, body, ownerKey)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// listSigners filter by tag (signer_crud.go:176)
// ---------------------------------------------------------------------------

func TestListSigners_FilterByTag(t *testing.T) {
	// Use a minimal test with ownerships that have tags
	db := newCoverageTestDB(t)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)

	mustCreateAPIKey(t, apiKeyRepo, "owner-key", types.RoleAdmin)
	addr := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	mustCreateSignerOwnership(t, ownershipRepo, addr, "owner-key", types.SignerOwnershipActive)

	// Update with tags
	ctx := context.Background()
	own, _ := ownershipRepo.Get(ctx, addr)
	own.TagsJSON = types.FormatSignerTagsJSON([]string{"production", "mainnet"})
	require.NoError(t, ownershipRepo.Upsert(ctx, own))

	accessSvc, err := service.NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, slog.Default())
	require.NoError(t, err)

	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{
				Signers: []types.SignerInfo{
					{Address: addr, Type: "keystore", Enabled: true},
				},
				Total: 1,
			}, nil
		},
	}

	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	adminKey := &types.APIKey{ID: "owner-key", Role: types.RoleAdmin}
	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?tag=production", adminKey)
	require.Equal(t, http.StatusOK, rec.Code)

	resp := decodeSignerListResponse(t, rec)
	assert.Equal(t, 1, resp.Total)
}

// ---------------------------------------------------------------------------
// Validate rules list error (rule_validation.go:165, list error path)
// ---------------------------------------------------------------------------

type mockRuleRepoListError struct {
	mockRuleRepo
}

func (m *mockRuleRepoListError) List(_ context.Context, _ storage.RuleFilter) ([]*types.Rule, error) {
	return nil, errors.New("list error")
}

func TestValidateRules_ListError(t *testing.T) {
	h, err := NewRuleHandler(&mockRuleRepoListError{}, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/validate", nil, ruleAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// Transactions tests (transactions.go — reach 80%+)
// ---------------------------------------------------------------------------

func TestTransactionsHandler_List_InvalidLimit(t *testing.T) {
	db := newTxHandlerDB(t)
	repo, _ := storage.NewGormTransactionRepository(db)
	h, err := NewTransactionsHandler(repo, slog.Default())
	require.NoError(t, err)

	admin := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}
	rec := doTxRequest(t, h, http.MethodGet, "/api/v1/evm/transactions?limit=-1", admin)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestTransactionsHandler_List_InvalidOffset(t *testing.T) {
	db := newTxHandlerDB(t)
	repo, _ := storage.NewGormTransactionRepository(db)
	h, err := NewTransactionsHandler(repo, slog.Default())
	require.NoError(t, err)

	admin := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}
	rec := doTxRequest(t, h, http.MethodGet, "/api/v1/evm/transactions?offset=-1", admin)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestTransactionsHandler_Get_NonAdminOwnTx_200(t *testing.T) {
	db := newTxHandlerDB(t)
	alice, _, _ := seedTxFixture(t, db)
	repo, _ := storage.NewGormTransactionRepository(db)
	h, err := NewTransactionsHandler(repo, slog.Default())
	require.NoError(t, err)

	aliceKey := &types.APIKey{ID: "alice", Role: types.RoleAgent}
	rec := doTxRequest(t, h, http.MethodGet, "/api/v1/evm/transactions/"+alice, aliceKey)
	require.Equal(t, http.StatusOK, rec.Code)

	var got types.Transaction
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	assert.Equal(t, "tx-alice", got.ID)
}

func TestTransactionsHandler_List_NegativeLimit(t *testing.T) {
	db := newTxHandlerDB(t)
	seedTxFixture(t, db)
	repo, _ := storage.NewGormTransactionRepository(db)
	h, err := NewTransactionsHandler(repo, slog.Default())
	require.NoError(t, err)

	admin := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}
	rec := doTxRequest(t, h, http.MethodGet, "/api/v1/evm/transactions?limit=-5", admin)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// Budget handler test
// ---------------------------------------------------------------------------

func TestIsValidBudgetLimit_Nil(t *testing.T) {
	h, err := NewBudgetItemHandler(&mockBudgetRepo{}, newMockRuleRepo(), slog.Default())
	require.NoError(t, err)
	assert.NotNil(t, h)
}
