package evm

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// --- Helpers ---

func doRuleRequest(t *testing.T, h *RuleHandler, method, path string, body interface{}, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	var buf *bytes.Buffer
	if body != nil {
		switch v := body.(type) {
		case string:
			buf = bytes.NewBufferString(v)
		default:
			data, err := json.Marshal(v)
			require.NoError(t, err)
			buf = bytes.NewBuffer(data)
		}
	} else {
		buf = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, buf)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func ruleAdminKey() *types.APIKey {
	return &types.APIKey{ID: "admin-key", Name: "Admin", Role: types.RoleAdmin, Enabled: true}
}

func ruleAgentKey() *types.APIKey {
	return &types.APIKey{ID: "agent-key", Name: "Agent", Role: types.RoleAgent, Enabled: true}
}

// --- Constructor tests ---

func TestNewRuleHandler(t *testing.T) {
	t.Run("nil_repo_returns_error", func(t *testing.T) {
		_, err := NewRuleHandler(nil, slog.Default())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rule repository is required")
	})

	t.Run("nil_logger_returns_error", func(t *testing.T) {
		_, err := NewRuleHandler(newMockRuleRepo(), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})

	t.Run("valid_args", func(t *testing.T) {
		h, err := NewRuleHandler(newMockRuleRepo(), slog.Default())
		require.NoError(t, err)
		assert.NotNil(t, h)
	})
}

// --- Unauthorized ---

func TestRuleHandler_Unauthorized(t *testing.T) {
	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodGet, "/api/v1/evm/rules", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// --- List rules ---

func TestRuleHandler_ListRules_Empty(t *testing.T) {
	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodGet, "/api/v1/evm/rules", nil, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ListRulesResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 0, resp.Total)
	assert.Empty(t, resp.Rules)
}

func TestRuleHandler_ListRules_WithData(t *testing.T) {
	repo := newMockRuleRepo()
	repo.addRule(newAPIRule())
	repo.addRule(newConfigRule())

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodGet, "/api/v1/evm/rules", nil, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ListRulesResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 2, resp.Total)
	assert.Len(t, resp.Rules, 2)
}

func TestRuleHandler_ListRules_InvalidType(t *testing.T) {
	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodGet, "/api/v1/evm/rules?type=invalid_type", nil, ruleAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// --- Get rule ---

func TestRuleHandler_GetRule_Success(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodGet, "/api/v1/evm/rules/"+string(rule.ID), nil, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp RuleResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, string(rule.ID), resp.ID)
	assert.Equal(t, rule.Name, resp.Name)
}

func TestRuleHandler_GetRule_NotFound(t *testing.T) {
	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodGet, "/api/v1/evm/rules/nonexistent", nil, ruleAdminKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestRuleHandler_GetRule_AgentRedacted(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "agent-key"
	rule.AppliedTo = []string{"self"}
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodGet, "/api/v1/evm/rules/"+string(rule.ID), nil, ruleAgentKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp RuleResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Nil(t, resp.Config) // Agent should not see config
}

// --- Delete rule ---

func TestRuleHandler_DeleteRule_Success(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodDelete, "/api/v1/evm/rules/"+string(rule.ID), nil, ruleAdminKey())
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// Verify deleted
	_, getErr := repo.Get(context.Background(), rule.ID)
	assert.ErrorIs(t, getErr, types.ErrNotFound)
}

func TestRuleHandler_DeleteRule_NotFound(t *testing.T) {
	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodDelete, "/api/v1/evm/rules/nonexistent", nil, ruleAdminKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestRuleHandler_DeleteRule_Immutable(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Immutable = true
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodDelete, "/api/v1/evm/rules/"+string(rule.ID), nil, ruleAdminKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "immutable")
}

func TestRuleHandler_DeleteRule_NotOwner(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "other-owner"
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	agentKey := &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}
	rec := doRuleRequest(t, h, http.MethodDelete, "/api/v1/evm/rules/"+string(rule.ID), nil, agentKey)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "permission denied")
}

// --- Approve rule ---

func TestRuleHandler_ApproveRule_Success(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Status = types.RuleStatusPendingApproval
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/approve", nil, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp RuleResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, string(types.RuleStatusActive), resp.Status)
}

func TestRuleHandler_ApproveRule_NotPending(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Status = types.RuleStatusActive
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/approve", nil, ruleAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "not pending approval")
}

func TestRuleHandler_ApproveRule_NotAdmin(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Status = types.RuleStatusPendingApproval
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/approve", nil, ruleAgentKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRuleHandler_ApproveRule_NotFound(t *testing.T) {
	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/nonexistent/approve", nil, ruleAdminKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// --- Reject rule ---

func TestRuleHandler_RejectRule_Success(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Status = types.RuleStatusPendingApproval
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]string{"reason": "not needed"}
	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/reject", body, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRuleHandler_RejectRule_NotAdmin(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Status = types.RuleStatusPendingApproval
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/reject", nil, ruleAgentKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// --- Reject rule (more) ---

func TestRuleHandler_RejectRule_NotPending(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Status = types.RuleStatusActive
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/reject", nil, ruleAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "not pending")
}

func TestRuleHandler_RejectRule_NotFound(t *testing.T) {
	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/nonexistent/reject", nil, ruleAdminKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// --- Update rule ---

func TestRuleHandler_UpdateRule_Success(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"name":"updated-name","description":"updated desc"}`
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp RuleResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "updated-name", resp.Name)
}

func TestRuleHandler_UpdateRule_NotFound(t *testing.T) {
	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default())
	require.NoError(t, err)

	body := `{"name":"updated"}`
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/nonexistent", body, ruleAdminKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestRuleHandler_UpdateRule_Immutable(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Immutable = true
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"name":"hacked"}`
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAdminKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "immutable")
}

func TestRuleHandler_UpdateRule_NotOwner(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "other-owner"
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"name":"hacked"}`
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAgentKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "permission denied")
}

func TestRuleHandler_UpdateRule_InvalidBody(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), "bad json", ruleAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRuleHandler_UpdateRule_EnableDisable(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	rule.Enabled = true
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"enabled":false}`
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp RuleResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.False(t, resp.Enabled)
}

// --- Method not allowed ---

func TestRuleHandler_MethodNotAllowed(t *testing.T) {
	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPut, "/api/v1/evm/rules", nil, ruleAdminKey())
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}
