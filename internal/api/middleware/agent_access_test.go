package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/stretchr/testify/assert"
)

// TestAgentAccessControlMatrix verifies the design doc's permission table (section 7.2).
// Each test case represents an endpoint + role combination.
func TestAgentAccessControlMatrix(t *testing.T) {
	logger := newTestLogger()
	agentOrAdminMW := AgentOrAdminMiddleware(logger)
	adminMW := AdminMiddleware(logger)

	devKey := &types.APIKey{ID: "dev", Name: "dev-key", Admin: false, Agent: false}
	agentKey := &types.APIKey{ID: "agent", Name: "agent-key", Admin: false, Agent: true}
	adminKey := &types.APIKey{ID: "admin", Name: "admin-key", Admin: true, Agent: false}

	// dummy next handler that records it was called
	okHandler := func(called *bool) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*called = true
			w.WriteHeader(http.StatusOK)
		})
	}

	type testCase struct {
		name       string
		mw         func(http.Handler) http.Handler
		method     string
		path       string
		apiKey     *types.APIKey
		wantStatus int
		wantCalled bool
	}

	tests := []testCase{
		// --- Rules endpoints (AgentOrAdmin middleware) ---
		// GET /evm/rules: dev=denied, agent=allowed, admin=allowed
		{"GET rules - dev denied", agentOrAdminMW, "GET", "/api/v1/evm/rules", devKey, http.StatusForbidden, false},
		{"GET rules - agent allowed", agentOrAdminMW, "GET", "/api/v1/evm/rules", agentKey, http.StatusOK, true},
		{"GET rules - admin allowed", agentOrAdminMW, "GET", "/api/v1/evm/rules", adminKey, http.StatusOK, true},

		// POST /evm/rules: dev=denied, agent=denied, admin=allowed
		{"POST rules - dev denied", agentOrAdminMW, "POST", "/api/v1/evm/rules", devKey, http.StatusForbidden, false},
		{"POST rules - agent denied", agentOrAdminMW, "POST", "/api/v1/evm/rules", agentKey, http.StatusForbidden, false},
		{"POST rules - admin allowed", agentOrAdminMW, "POST", "/api/v1/evm/rules", adminKey, http.StatusOK, true},

		// DELETE /evm/rules/id: dev=denied, agent=denied, admin=allowed
		{"DELETE rules - dev denied", agentOrAdminMW, "DELETE", "/api/v1/evm/rules/some-id", devKey, http.StatusForbidden, false},
		{"DELETE rules - agent denied", agentOrAdminMW, "DELETE", "/api/v1/evm/rules/some-id", agentKey, http.StatusForbidden, false},
		{"DELETE rules - admin allowed", agentOrAdminMW, "DELETE", "/api/v1/evm/rules/some-id", adminKey, http.StatusOK, true},

		// PATCH /evm/rules/id: dev=denied, agent=denied, admin=allowed
		{"PATCH rules - dev denied", agentOrAdminMW, "PATCH", "/api/v1/evm/rules/some-id", devKey, http.StatusForbidden, false},
		{"PATCH rules - agent denied", agentOrAdminMW, "PATCH", "/api/v1/evm/rules/some-id", agentKey, http.StatusForbidden, false},
		{"PATCH rules - admin allowed", agentOrAdminMW, "PATCH", "/api/v1/evm/rules/some-id", adminKey, http.StatusOK, true},

		// GET /evm/rules/id/budgets: dev=denied, agent=allowed, admin=allowed
		{"GET budgets - dev denied", agentOrAdminMW, "GET", "/api/v1/evm/rules/some-id/budgets", devKey, http.StatusForbidden, false},
		{"GET budgets - agent allowed", agentOrAdminMW, "GET", "/api/v1/evm/rules/some-id/budgets", agentKey, http.StatusOK, true},
		{"GET budgets - admin allowed", agentOrAdminMW, "GET", "/api/v1/evm/rules/some-id/budgets", adminKey, http.StatusOK, true},

		// --- Presets endpoints (AgentOrAdmin middleware) ---
		// GET /presets: dev=denied, agent=allowed, admin=allowed
		{"GET presets - dev denied", agentOrAdminMW, "GET", "/api/v1/presets", devKey, http.StatusForbidden, false},
		{"GET presets - agent allowed", agentOrAdminMW, "GET", "/api/v1/presets", agentKey, http.StatusOK, true},
		{"GET presets - admin allowed", agentOrAdminMW, "GET", "/api/v1/presets", adminKey, http.StatusOK, true},

		// POST /presets (apply): dev=denied, agent=denied, admin=allowed
		{"POST presets - dev denied", agentOrAdminMW, "POST", "/api/v1/presets", devKey, http.StatusForbidden, false},
		{"POST presets - agent denied", agentOrAdminMW, "POST", "/api/v1/presets", agentKey, http.StatusForbidden, false},
		{"POST presets - admin allowed", agentOrAdminMW, "POST", "/api/v1/presets", adminKey, http.StatusOK, true},

		// --- Admin-only endpoints (Admin middleware) ---
		// Audit: admin-only
		{"GET audit - dev denied", adminMW, "GET", "/api/v1/audit", devKey, http.StatusForbidden, false},
		{"GET audit - agent denied", adminMW, "GET", "/api/v1/audit", agentKey, http.StatusForbidden, false},
		{"GET audit - admin allowed", adminMW, "GET", "/api/v1/audit", adminKey, http.StatusOK, true},

		// API keys: admin-only
		{"GET api-keys - dev denied", adminMW, "GET", "/api/v1/api-keys", devKey, http.StatusForbidden, false},
		{"GET api-keys - agent denied", adminMW, "GET", "/api/v1/api-keys", agentKey, http.StatusForbidden, false},
		{"GET api-keys - admin allowed", adminMW, "GET", "/api/v1/api-keys", adminKey, http.StatusOK, true},

		// Templates: admin-only
		{"POST templates - dev denied", adminMW, "POST", "/api/v1/templates", devKey, http.StatusForbidden, false},
		{"POST templates - agent denied", adminMW, "POST", "/api/v1/templates", agentKey, http.StatusForbidden, false},
		{"POST templates - admin allowed", adminMW, "POST", "/api/v1/templates", adminKey, http.StatusOK, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			handler := tc.mw(okHandler(&called))

			req := httptest.NewRequest(tc.method, tc.path, nil)
			ctx := context.WithValue(req.Context(), APIKeyContextKey, tc.apiKey)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, tc.wantStatus, rr.Code, "unexpected status for %s", tc.name)
			assert.Equal(t, tc.wantCalled, called, "unexpected handler call for %s", tc.name)
		})
	}
}

// TestAgentKeyExplicitSignerFiltering verifies that agent keys with allow_all_signers=true
// are still restricted to their explicit allowed_signers list.
func TestAgentKeyExplicitSignerFiltering(t *testing.T) {
	agentKey := &types.APIKey{
		ID:              "agent-bot",
		Agent:           true,
		AllowAllSigners: true, // should be ignored for agent keys
		AllowedSigners:  []string{"0x1111111111111111111111111111111111111111"},
	}

	// IsAllowedSigner (normal): returns true for any signer because AllowAllSigners=true
	assert.True(t, agentKey.IsAllowedSigner("0x9999999999999999999999999999999999999999"))

	// IsAllowedSignerExplicit: only checks explicit list
	assert.True(t, agentKey.IsAllowedSignerExplicit("0x1111111111111111111111111111111111111111"))
	assert.False(t, agentKey.IsAllowedSignerExplicit("0x9999999999999999999999999999999999999999"))

	// CheckSignerPermissionExplicit: uses explicit check
	assert.True(t, CheckSignerPermissionExplicit(agentKey, "0x1111111111111111111111111111111111111111", nil))
	assert.False(t, CheckSignerPermissionExplicit(agentKey, "0x9999999999999999999999999999999999999999", nil))

	// CheckSignerPermissionWithHDWallets: uses normal check (allow_all_signers applies)
	assert.True(t, CheckSignerPermissionWithHDWallets(agentKey, "0x9999999999999999999999999999999999999999", nil))
}

// TestAgentKeyExplicitHDWalletFiltering verifies agent HD wallet filtering.
func TestAgentKeyExplicitHDWalletFiltering(t *testing.T) {
	agentKey := &types.APIKey{
		ID:                "agent-bot",
		Agent:             true,
		AllowAllHDWallets: true, // should be ignored for agent keys in explicit check
		AllowedHDWallets:  []string{"0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	}

	assert.True(t, agentKey.IsAllowedHDWallet("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")) // AllowAll=true
	assert.True(t, agentKey.IsAllowedHDWalletExplicit("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	assert.False(t, agentKey.IsAllowedHDWalletExplicit("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"))
}
