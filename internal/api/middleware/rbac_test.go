package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/stretchr/testify/assert"
)

func TestHasPermission_AdminHasAll(t *testing.T) {
	allPerms := []Permission{
		PermSignRequest, PermListOwnRequests, PermListAllRequests, PermApproveRequest,
		PermListRules, PermCreateRuleSelf, PermCreateRuleAny, PermModifyOwnRule, PermModifyAnyRule,
		PermDeleteOwnRule, PermDeleteAnyRule, PermApproveRule,
		PermReadBudgets, PermReadTemplates, PermInstantiateTemplate, PermReadPresets, PermApplyPreset,
		PermReadSigners, PermCreateSigners, PermUnlockSigner,
		PermReadHDWallets, PermCreateHDWallet,
		PermManageAPIKeys, PermReadAudit, PermReadMetrics, PermReadACLs, PermResumeGuard,
	}
	for _, p := range allPerms {
		assert.True(t, HasPermission(types.RoleAdmin, p), "admin should have permission %s", p)
	}
}

func TestHasPermission_DevPermissions(t *testing.T) {
	allowed := []Permission{
		PermSignRequest, PermListOwnRequests, PermListAllRequests,
		PermListRules, PermCreateRuleSelf, PermModifyOwnRule, PermDeleteOwnRule,
		PermReadBudgets, PermReadTemplates, PermReadPresets,
		PermReadSigners, PermCreateSigners, PermReadHDWallets,
		PermReadAudit, PermReadMetrics,
	}
	denied := []Permission{
		PermApproveRequest, PermCreateRuleAny, PermModifyAnyRule, PermDeleteAnyRule, PermApproveRule,
		PermInstantiateTemplate, PermApplyPreset,
		PermUnlockSigner, PermCreateHDWallet,
		PermManageAPIKeys, PermReadACLs, PermResumeGuard,
	}

	for _, p := range allowed {
		assert.True(t, HasPermission(types.RoleDev, p), "dev should have permission %s", p)
	}
	for _, p := range denied {
		assert.False(t, HasPermission(types.RoleDev, p), "dev should NOT have permission %s", p)
	}
}

func TestHasPermission_AgentPermissions(t *testing.T) {
	allowed := []Permission{
		PermSignRequest, PermListOwnRequests,
		PermListRules, PermCreateRuleSelf, PermModifyOwnRule, PermDeleteOwnRule,
		PermReadBudgets, PermReadTemplates, PermReadPresets,
		PermReadSigners, PermCreateSigners, PermReadHDWallets,
	}
	denied := []Permission{
		PermListAllRequests, PermApproveRequest,
		PermCreateRuleAny, PermModifyAnyRule, PermDeleteAnyRule, PermApproveRule,
		PermInstantiateTemplate, PermApplyPreset,
		PermUnlockSigner, PermCreateHDWallet,
		PermManageAPIKeys, PermReadAudit, PermReadMetrics, PermReadACLs, PermResumeGuard,
	}

	for _, p := range allowed {
		assert.True(t, HasPermission(types.RoleAgent, p), "agent should have permission %s", p)
	}
	for _, p := range denied {
		assert.False(t, HasPermission(types.RoleAgent, p), "agent should NOT have permission %s", p)
	}
}

func TestHasPermission_StrategyPermissions(t *testing.T) {
	allowed := []Permission{
		PermSignRequest, PermListOwnRequests, PermReadSigners,
	}
	denied := []Permission{
		PermListAllRequests, PermApproveRequest,
		PermListRules, PermCreateRuleSelf, PermCreateRuleAny, PermModifyOwnRule, PermModifyAnyRule,
		PermDeleteOwnRule, PermDeleteAnyRule, PermApproveRule,
		PermReadBudgets, PermReadTemplates, PermInstantiateTemplate, PermReadPresets, PermApplyPreset,
		PermCreateSigners, PermUnlockSigner,
		PermReadHDWallets, PermCreateHDWallet,
		PermManageAPIKeys, PermReadAudit, PermReadMetrics, PermReadACLs, PermResumeGuard,
	}

	for _, p := range allowed {
		assert.True(t, HasPermission(types.RoleStrategy, p), "strategy should have permission %s", p)
	}
	for _, p := range denied {
		assert.False(t, HasPermission(types.RoleStrategy, p), "strategy should NOT have permission %s", p)
	}
}

func TestHasPermission_UnknownRole(t *testing.T) {
	assert.False(t, HasPermission(types.APIKeyRole("unknown"), PermSignRequest))
}

func TestRequirePermission_NoAPIKeyInContext_Returns401(t *testing.T) {
	logger := newTestLogger()
	mw := RequirePermission(PermSignRequest, logger)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/sign", nil)
	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestRequirePermission_PermissionGranted(t *testing.T) {
	logger := newTestLogger()
	mw := RequirePermission(PermSignRequest, logger)

	apiKey := &types.APIKey{ID: "key-1", Role: types.RoleStrategy}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/sign", nil)
	ctx := context.WithValue(req.Context(), APIKeyContextKey, apiKey)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRequirePermission_PermissionDenied(t *testing.T) {
	logger := newTestLogger()
	mw := RequirePermission(PermManageAPIKeys, logger)

	apiKey := &types.APIKey{ID: "key-agent", Role: types.RoleAgent}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	ctx := context.WithValue(req.Context(), APIKeyContextKey, apiKey)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// TestRBACAccessControlMatrix verifies the design doc permission table (Section 2.2).
func TestRBACAccessControlMatrix(t *testing.T) {
	logger := newTestLogger()

	adminKey := &types.APIKey{ID: "admin", Name: "admin-key", Role: types.RoleAdmin}
	devKey := &types.APIKey{ID: "dev", Name: "dev-key", Role: types.RoleDev}
	agentKey := &types.APIKey{ID: "agent", Name: "agent-key", Role: types.RoleAgent}
	strategyKey := &types.APIKey{ID: "strategy", Name: "strategy-key", Role: types.RoleStrategy}

	okHandler := func(called *bool) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*called = true
			w.WriteHeader(http.StatusOK)
		})
	}

	type testCase struct {
		name       string
		perm       Permission
		apiKey     *types.APIKey
		wantStatus int
		wantCalled bool
	}

	tests := []testCase{
		// Sign: all roles
		{"sign - admin", PermSignRequest, adminKey, http.StatusOK, true},
		{"sign - dev", PermSignRequest, devKey, http.StatusOK, true},
		{"sign - agent", PermSignRequest, agentKey, http.StatusOK, true},
		{"sign - strategy", PermSignRequest, strategyKey, http.StatusOK, true},

		// List rules: admin/dev/agent yes, strategy no
		{"list rules - admin", PermListRules, adminKey, http.StatusOK, true},
		{"list rules - dev", PermListRules, devKey, http.StatusOK, true},
		{"list rules - agent", PermListRules, agentKey, http.StatusOK, true},
		{"list rules - strategy denied", PermListRules, strategyKey, http.StatusForbidden, false},

		// Manage API keys: admin only
		{"manage keys - admin", PermManageAPIKeys, adminKey, http.StatusOK, true},
		{"manage keys - dev denied", PermManageAPIKeys, devKey, http.StatusForbidden, false},
		{"manage keys - agent denied", PermManageAPIKeys, agentKey, http.StatusForbidden, false},
		{"manage keys - strategy denied", PermManageAPIKeys, strategyKey, http.StatusForbidden, false},

		// Read audit: admin/dev yes, agent/strategy no
		{"audit - admin", PermReadAudit, adminKey, http.StatusOK, true},
		{"audit - dev", PermReadAudit, devKey, http.StatusOK, true},
		{"audit - agent denied", PermReadAudit, agentKey, http.StatusForbidden, false},
		{"audit - strategy denied", PermReadAudit, strategyKey, http.StatusForbidden, false},

		// Read templates: admin/dev/agent yes, strategy no
		{"templates - admin", PermReadTemplates, adminKey, http.StatusOK, true},
		{"templates - dev", PermReadTemplates, devKey, http.StatusOK, true},
		{"templates - agent", PermReadTemplates, agentKey, http.StatusOK, true},
		{"templates - strategy denied", PermReadTemplates, strategyKey, http.StatusForbidden, false},

		// Read presets: admin/dev/agent yes, strategy no
		{"presets - admin", PermReadPresets, adminKey, http.StatusOK, true},
		{"presets - dev", PermReadPresets, devKey, http.StatusOK, true},
		{"presets - agent", PermReadPresets, agentKey, http.StatusOK, true},
		{"presets - strategy denied", PermReadPresets, strategyKey, http.StatusForbidden, false},

		// Create signers: admin, dev, agent
		{"create signers - admin", PermCreateSigners, adminKey, http.StatusOK, true},
		{"create signers - dev", PermCreateSigners, devKey, http.StatusOK, true},
		{"create signers - agent", PermCreateSigners, agentKey, http.StatusOK, true},
		{"create signers - strategy denied", PermCreateSigners, strategyKey, http.StatusForbidden, false},

		// Read signers: all roles
		{"read signers - admin", PermReadSigners, adminKey, http.StatusOK, true},
		{"read signers - dev", PermReadSigners, devKey, http.StatusOK, true},
		{"read signers - agent", PermReadSigners, agentKey, http.StatusOK, true},
		{"read signers - strategy", PermReadSigners, strategyKey, http.StatusOK, true},

		// Read metrics: admin/dev only
		{"metrics - admin", PermReadMetrics, adminKey, http.StatusOK, true},
		{"metrics - dev", PermReadMetrics, devKey, http.StatusOK, true},
		{"metrics - agent denied", PermReadMetrics, agentKey, http.StatusForbidden, false},
		{"metrics - strategy denied", PermReadMetrics, strategyKey, http.StatusForbidden, false},

		// Approve request: admin only
		{"approve request - admin", PermApproveRequest, adminKey, http.StatusOK, true},
		{"approve request - dev denied", PermApproveRequest, devKey, http.StatusForbidden, false},
		{"approve request - agent denied", PermApproveRequest, agentKey, http.StatusForbidden, false},
		{"approve request - strategy denied", PermApproveRequest, strategyKey, http.StatusForbidden, false},

		// Create rule any: admin only
		{"create rule any - admin", PermCreateRuleAny, adminKey, http.StatusOK, true},
		{"create rule any - dev denied", PermCreateRuleAny, devKey, http.StatusForbidden, false},
		{"create rule any - agent denied", PermCreateRuleAny, agentKey, http.StatusForbidden, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			handler := RequirePermission(tc.perm, logger)(okHandler(&called))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			ctx := context.WithValue(req.Context(), APIKeyContextKey, tc.apiKey)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, tc.wantStatus, rr.Code, "unexpected status for %s", tc.name)
			assert.Equal(t, tc.wantCalled, called, "unexpected handler call for %s", tc.name)
		})
	}
}
