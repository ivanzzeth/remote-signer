package evm

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulepkg "github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// --- Dynamic budget limit sync tests ---

func TestResolveAndSyncBudgetLimits_DynamicTemplate(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	rule.TemplateID = strPtr("evm/agent")
	rule.Variables = json.RawMessage(`{
		"budget_period": "24h",
		"chain_id": "1",
		"max_sign_count": "250",
		"max_tx_count": "100",
		"max_native_total": "1"
	}`)
	repo.addRule(rule)

	budgetMetering := json.RawMessage(`{
		"dynamic": true,
		"known_units": {
			"sign_count": {"decimals": 0, "max_total": "${max_sign_count}", "max_per_tx": "1"},
			"native": {"decimals": 18, "max_total": "${max_native_total}", "max_per_tx": "${max_native_per_tx}"}
		}
	}`)

	tmplRepo := &mockTemplateRepo{
		getFn: func(ctx context.Context, id string) (*types.RuleTemplate, error) {
			return &types.RuleTemplate{
				ID:             id,
				Name:           "Agent Signature",
				BudgetMetering: budgetMetering,
			}, nil
		},
	}

	var upsertedRequests []storage.BudgetSyncRequest
	budgetRepo := &mockBudgetRepo{
		upsertLimitsFn: func(ctx context.Context, ruleID types.RuleID, requests []storage.BudgetSyncRequest) error {
			upsertedRequests = requests
			return nil
		},
	}

	h, err := NewRuleHandler(repo, slog.Default(),
		WithTemplateRepo(tmplRepo),
		WithBudgetRepo(budgetRepo),
	)
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID),
		map[string]interface{}{"enabled": true}, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	// No variables changed, so budget should NOT sync on non-variable updates
	require.Nil(t, upsertedRequests, "budget sync should not be triggered on non-variable update")
}

func TestResolveAndSyncBudgetLimits_VariableChangeSyncsLimits(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	rule.TemplateID = strPtr("evm/agent")
	rule.Variables = json.RawMessage(`{
		"max_sign_count": "500",
		"max_tx_count": "1000",
		"max_native_total": "10"
	}`)
	repo.addRule(rule)

	budgetMetering := json.RawMessage(`{
		"dynamic": true,
		"known_units": {
			"sign_count": {"decimals": 0, "max_total": "${max_sign_count}", "max_per_tx": "1"},
			"tx_count": {"decimals": 0, "max_total": "${max_tx_count}", "max_per_tx": "1", "max_tx_count": "${max_tx_count}"},
			"native": {"decimals": 18, "max_total": "${max_native_total}", "max_per_tx": "${max_native_per_tx}"}
		}
	}`)

	tmplRepo := &mockTemplateRepo{
		getFn: func(ctx context.Context, id string) (*types.RuleTemplate, error) {
			return &types.RuleTemplate{
				ID:             id,
				Name:           "Agent Signature",
				BudgetMetering: budgetMetering,
			}, nil
		},
	}

	var upsertedRequests []storage.BudgetSyncRequest
	budgetRepo := &mockBudgetRepo{
		upsertLimitsFn: func(ctx context.Context, ruleID types.RuleID, requests []storage.BudgetSyncRequest) error {
			upsertedRequests = requests
			return nil
		},
	}

	h, err := NewRuleHandler(repo, slog.Default(),
		WithTemplateRepo(tmplRepo),
		WithBudgetRepo(budgetRepo),
	)
	require.NoError(t, err)

	// PATCH variables: change max_sign_count from 500 to 250, max_tx_count from 1000 to 100
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID),
		map[string]interface{}{
			"variables": map[string]string{
				"max_sign_count":  "250",
				"max_tx_count":    "100",
				"max_native_total": "10",
			},
		}, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	require.NotNil(t, upsertedRequests, "variable change should trigger budget sync")
	require.Len(t, upsertedRequests, 3, "should sync all 3 known_units")

	// Build a map for easy lookup
	byUnit := make(map[string]storage.BudgetSyncRequest)
	for _, r := range upsertedRequests {
		byUnit[r.Unit] = r
	}

	// After SubstituteMeteringJSON: max_sign_count=250, max_tx_count=100, max_native_total=10
	sr, ok := byUnit[rulepkg.NormalizeBudgetUnit("sign_count")]
	require.True(t, ok, "should include sign_count")
	assert.Equal(t, "250", sr.MaxTotal, "max_sign_count=250 should resolve to max_total=250")
	assert.Equal(t, "1", sr.MaxPerTx)

	tr, ok := byUnit[rulepkg.NormalizeBudgetUnit("tx_count")]
	require.True(t, ok, "should include tx_count")
	assert.Equal(t, "100", tr.MaxTotal, "max_tx_count=100 should resolve to max_total=100")
	assert.Equal(t, 100, tr.MaxTxCount, "max_tx_count=100 should resolve to max_tx_count=100")

	nr, ok := byUnit[rulepkg.NormalizeBudgetUnit("native")]
	require.True(t, ok, "should include native")
	assert.Equal(t, "10", nr.MaxTotal, "max_native_total=10 should resolve to max_total=10")
	// max_native_per_tx is empty in variables → SubstituteMeteringJSON leaves it as "" → default to "-1"
	assert.Equal(t, "-1", nr.MaxPerTx)
}

func TestResolveAndSyncBudgetLimits_NoVariablesChangeNoSync(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	rule.TemplateID = strPtr("evm/agent")
	rule.Variables = json.RawMessage(`{"max_sign_count": "500"}`)
	repo.addRule(rule)

	budgetMetering := json.RawMessage(`{
		"dynamic": true,
		"known_units": {
			"sign_count": {"decimals": 0, "max_total": "${max_sign_count}", "max_per_tx": "1"}
		}
	}`)

	tmplRepo := &mockTemplateRepo{
		getFn: func(ctx context.Context, id string) (*types.RuleTemplate, error) {
			return &types.RuleTemplate{
				ID:             id,
				Name:           "Agent",
				BudgetMetering: budgetMetering,
			}, nil
		},
	}

	budgetSynced := false
	budgetRepo := &mockBudgetRepo{
		upsertLimitsFn: func(ctx context.Context, ruleID types.RuleID, requests []storage.BudgetSyncRequest) error {
			budgetSynced = true
			return nil
		},
	}

	h, err := NewRuleHandler(repo, slog.Default(),
		WithTemplateRepo(tmplRepo),
		WithBudgetRepo(budgetRepo),
	)
	require.NoError(t, err)

	// PATCH name only (no variables)
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID),
		map[string]interface{}{"name": "New Name"}, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.False(t, budgetSynced, "name-only update should NOT trigger budget sync")
}

func TestResolveAndSyncBudgetLimits_StaticTemplate(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	rule.TemplateID = strPtr("evm/erc20")
	rule.Variables = json.RawMessage(`{"chain_id": "1", "token_address": "0xUSDC"}`)
	repo.addRule(rule)

	budgetMetering := json.RawMessage(`{"method": "calldata_param", "unit": "${chain_id}:${token_address}", "param_index": 1}`)
	tmplRepo := &mockTemplateRepo{
		getFn: func(ctx context.Context, id string) (*types.RuleTemplate, error) {
			return &types.RuleTemplate{
				ID:             id,
				Name:           "ERC20",
				BudgetMetering: budgetMetering,
			}, nil
		},
	}

	var upsertedRequests []storage.BudgetSyncRequest
	budgetRepo := &mockBudgetRepo{
		upsertLimitsFn: func(ctx context.Context, ruleID types.RuleID, requests []storage.BudgetSyncRequest) error {
			upsertedRequests = requests
			return nil
		},
	}

	h, err := NewRuleHandler(repo, slog.Default(),
		WithTemplateRepo(tmplRepo),
		WithBudgetRepo(budgetRepo),
	)
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID),
		map[string]interface{}{
			"variables": map[string]string{
				"chain_id":      "137",
				"token_address": "0xUSDC",
			},
		}, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	require.Len(t, upsertedRequests, 1, "static budget should sync one unit")
	assert.Equal(t, "137:0xUSDC", upsertedRequests[0].Unit)
}

func TestResolveAndSyncBudgetLimits_NoTemplateRepoSkipsSync(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	rule.TemplateID = strPtr("evm/agent")
	rule.Variables = json.RawMessage(`{"max_sign_count": "500"}`)
	repo.addRule(rule)

	// No template repo or budget repo — sync should be skipped
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID),
		map[string]interface{}{
			"variables": map[string]string{"max_sign_count": "250"},
		}, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestResolveAndSyncBudgetLimits_TemplateGetError(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	rule.TemplateID = strPtr("evm/nonexistent")
	rule.Variables = json.RawMessage(`{"chain_id": "1"}`)
	repo.addRule(rule)

	tmplRepo := &mockTemplateRepo{
		getFn: func(ctx context.Context, id string) (*types.RuleTemplate, error) {
			return nil, types.ErrNotFound
		},
	}

	budgetSynced := false
	budgetRepo := &mockBudgetRepo{
		upsertLimitsFn: func(ctx context.Context, ruleID types.RuleID, requests []storage.BudgetSyncRequest) error {
			budgetSynced = true
			return nil
		},
	}

	h, err := NewRuleHandler(repo, slog.Default(),
		WithTemplateRepo(tmplRepo),
		WithBudgetRepo(budgetRepo),
	)
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID),
		map[string]interface{}{
			"variables": map[string]string{"chain_id": "137"},
		}, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.False(t, budgetSynced, "template get error should skip budget sync gracefully")
}

func TestResolveAndSyncBudgetLimits_EmptyBudgetMetering(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	rule.TemplateID = strPtr("evm/no_budget")
	rule.Variables = json.RawMessage(`{"chain_id": "1"}`)
	repo.addRule(rule)

	tmplRepo := &mockTemplateRepo{
		getFn: func(ctx context.Context, id string) (*types.RuleTemplate, error) {
			return &types.RuleTemplate{
				ID:   id,
				Name: "NoBudget",
			}, nil
		},
	}

	budgetSynced := false
	budgetRepo := &mockBudgetRepo{
		upsertLimitsFn: func(ctx context.Context, ruleID types.RuleID, requests []storage.BudgetSyncRequest) error {
			budgetSynced = true
			return nil
		},
	}

	h, err := NewRuleHandler(repo, slog.Default(),
		WithTemplateRepo(tmplRepo),
		WithBudgetRepo(budgetRepo),
	)
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID),
		map[string]interface{}{
			"variables": map[string]string{"chain_id": "137"},
		}, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.False(t, budgetSynced, "empty budget metering should skip budget sync")
}

func TestResolveAndSyncBudgetLimits_UnknownDefaultNotPresynced(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	rule.TemplateID = strPtr("evm/agent")
	rule.Variables = json.RawMessage(`{
		"max_sign_count": "500",
		"max_unknown_token_total": "1000",
		"max_unknown_token_tx_count": "50"
	}`)
	repo.addRule(rule)

	budgetMetering := json.RawMessage(`{
		"dynamic": true,
		"known_units": {
			"sign_count": {"decimals": 0, "max_total": "${max_sign_count}", "max_per_tx": "1"}
		},
		"unknown_default": {
			"max_total": "${max_unknown_token_total}",
			"max_tx_count": "${max_unknown_token_tx_count}"
		}
	}`)

	tmplRepo := &mockTemplateRepo{
		getFn: func(ctx context.Context, id string) (*types.RuleTemplate, error) {
			return &types.RuleTemplate{
				ID:             id,
				Name:           "Agent",
				BudgetMetering: budgetMetering,
			}, nil
		},
	}

	var upsertedRequests []storage.BudgetSyncRequest
	budgetRepo := &mockBudgetRepo{
		upsertLimitsFn: func(ctx context.Context, ruleID types.RuleID, requests []storage.BudgetSyncRequest) error {
			upsertedRequests = requests
			return nil
		},
	}

	h, err := NewRuleHandler(repo, slog.Default(),
		WithTemplateRepo(tmplRepo),
		WithBudgetRepo(budgetRepo),
	)
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID),
		map[string]interface{}{
			"variables": map[string]string{"max_sign_count": "250"},
		}, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	require.Len(t, upsertedRequests, 1, "only known_units should be pre-synced")
	assert.Equal(t, rulepkg.NormalizeBudgetUnit("sign_count"), upsertedRequests[0].Unit)
}
