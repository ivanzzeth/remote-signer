package evm

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
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

func TestRuleHandler_DeleteRule_SyntheticSimulationPlaceholder(t *testing.T) {
	repo := newMockRuleRepo()
	simID := types.RuleID("sim:0x0000000000000000000000000000000000000001")
	repo.addRule(&types.Rule{
		ID:     simID,
		Name:   "Simulation budget (auto)",
		Source: types.RuleSourceAutoGenerated,
		Owner:  "system",
		Type:   types.RuleTypeSignerRestriction,
		Mode:   types.RuleModeWhitelist,
		Status: types.RuleStatusActive,
	})

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodDelete, "/api/v1/evm/rules/"+string(simID), nil, ruleAdminKey())
	assert.Equal(t, http.StatusNoContent, rec.Code)

	_, getErr := repo.Get(context.Background(), simID)
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
	rule.Status = types.RuleStatusRejected
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
	rule.Status = types.RuleStatusRejected
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

// --- Proposal approve ---

func TestRuleHandler_ApproveProposal_Success(t *testing.T) {
	repo := newMockRuleRepo()
	target := newAPIRule()
	target.Status = types.RuleStatusActive
	target.Name = "original-name"
	target.Config = json.RawMessage(`{"addresses":["0x1111"]}`)
	repo.addRule(target)

	proposalID := types.RuleID("rule_proposal-00000000-0000-0000-0000-000000000099")
	pf := target.ID
	proposal := &types.Rule{
		ID:          proposalID,
		Name:        "proposed-name",
		Type:        types.RuleTypeEVMAddressList,
		Mode:        types.RuleModeWhitelist,
		Source:      types.RuleSourceAPI,
		Owner:       "agent-key",
		Config:      json.RawMessage(`{"addresses":["0x2222"]}`),
		Status:      types.RuleStatusPendingApproval,
		ProposalFor: &pf,
		Enabled:     false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	repo.addRule(proposal)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(proposalID)+"/approve", nil, ruleAdminKey())
	require.Equal(t, http.StatusOK, rec.Code)

	// Response returns the TARGET rule, not the proposal
	var resp RuleResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, string(target.ID), resp.ID)
	assert.Equal(t, "proposed-name", resp.Name)
	assert.Equal(t, string(types.RuleStatusActive), resp.Status)

	// Target rule updated in repo
	updatedTarget, err := repo.Get(t.Context(), target.ID)
	require.NoError(t, err)
	assert.Equal(t, "proposed-name", updatedTarget.Name)
	assert.Equal(t, string(types.RuleStatusActive), string(updatedTarget.Status))
	assert.Equal(t, `{"addresses":["0x2222"]}`, string(updatedTarget.Config))

	// Proposal deleted
	_, err = repo.Get(t.Context(), proposalID)
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestRuleHandler_ApproveProposal_TargetUpdated(t *testing.T) {
	repo := newMockRuleRepo()
	target := newAPIRule()
	target.Status = types.RuleStatusActive
	target.Owner = "admin-key"
	repo.addRule(target)

	pf := target.ID
	proposal := &types.Rule{
		ID:          "rule_proposal-00000000-0000-0000-0000-000000000098",
		Name:        target.Name,
		Type:        types.RuleTypeEVMAddressList,
		Mode:        types.RuleModeWhitelist,
		Source:      types.RuleSourceAPI,
		Owner:       "agent-key",
		Config:      json.RawMessage(`{"addresses":["0xdeadbeef"]}`),
		Status:      types.RuleStatusPendingApproval,
		ProposalFor: &pf,
		Enabled:     false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	repo.addRule(proposal)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/"+string(proposal.ID)+"/approve", nil, ruleAdminKey())
	require.Equal(t, http.StatusOK, rec.Code)

	// Target config updated
	updated, err := repo.Get(t.Context(), target.ID)
	require.NoError(t, err)
	assert.Equal(t, `{"addresses":["0xdeadbeef"]}`, string(updated.Config))

	// Only target remains in list (proposal deleted)
	rules, err := repo.List(t.Context(), storage.RuleFilter{Limit: 100})
	require.NoError(t, err)
	assert.Len(t, rules, 1, "proposal should be deleted, only target remains")
	assert.Equal(t, target.ID, rules[0].ID)
}

func TestRuleHandler_ApproveProposal_ProposalNotFound(t *testing.T) {
	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default())
	require.NoError(t, err)

	rec := doRuleRequest(t, h, http.MethodPost, "/api/v1/evm/rules/nonexistent-proposal/approve", nil, ruleAdminKey())
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

// TestRuleHandler_AgentUpdateActiveRule_TriggersRuleActivatedCallback verifies
// that agent self-service PATCH on an owned active rule (e.g. trusted_contracts)
// triggers onRuleActivated so ReevaluatePending can auto-approve authorizing requests.
func TestRuleHandler_AgentUpdateActiveRule_TriggersRuleActivatedCallback(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "agent-key"
	rule.Status = types.RuleStatusActive
	rule.Variables = json.RawMessage(`{"trusted_contracts":"0x1111"}`)
	repo.addRule(rule)

	calls := make(chan string, 1)
	h, err := NewRuleHandler(repo, slog.Default(),
		WithRuleActivatedCallback(func(caller string) { calls <- caller }),
	)
	require.NoError(t, err)

	body := `{"variables":{"trusted_contracts":"0x1111,0xStargate"}}`
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAgentKey())
	require.Equal(t, http.StatusOK, rec.Code)

	updated, err := repo.Get(t.Context(), rule.ID)
	require.NoError(t, err)
	assert.Contains(t, string(updated.Variables), "0xStargate")

	select {
	case caller := <-calls:
		assert.Contains(t, caller, "rule-updated:")
		assert.Contains(t, caller, string(rule.ID))
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected onRuleActivated after agent update of active rule")
	}
}

func TestRuleHandler_AgentUpdatePendingRule_DoesNotTriggerCallback(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "agent-key"
	rule.Status = types.RuleStatusPendingApproval
	rule.Variables = json.RawMessage(`{"trusted_contracts":"0x1111"}`)
	repo.addRule(rule)

	calls := make(chan string, 1)
	h, err := NewRuleHandler(repo, slog.Default(),
		WithRuleActivatedCallback(func(caller string) { calls <- caller }),
	)
	require.NoError(t, err)

	body := `{"variables":{"trusted_contracts":"0x1111,0x2222"}}`
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAgentKey())
	require.Equal(t, http.StatusOK, rec.Code)

	select {
	case caller := <-calls:
		t.Fatalf("unexpected onRuleActivated for pending_approval rule: %s", caller)
	case <-time.After(50 * time.Millisecond):
	}
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

// --- Update with Variables and Matrix ---

func TestRuleHandler_UpdateRule_Variables(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{
		"variables": map[string]string{
			"router_address": "0xABCD000000000000000000000000000000000000",
			"max_amount":     "1000000",
		},
	}
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp RuleResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	var vars map[string]string
	require.NoError(t, json.Unmarshal(resp.Variables, &vars))
	assert.Equal(t, "0xABCD000000000000000000000000000000000000", vars["router_address"])
	assert.Equal(t, "1000000", vars["max_amount"])
}

func TestRuleHandler_UpdateRule_Matrix(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{
		"matrix": []map[string]any{
			{
				"chain_id":       "1",
				"router_address": "0x1111111111111111111111111111111111111111",
			},
			{
				"chain_id":       "137",
				"router_address": "0x2222222222222222222222222222222222222222",
			},
		},
	}
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp RuleResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	var matrix []map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.Matrix, &matrix))
	assert.Len(t, matrix, 2)
	assert.Equal(t, "1", matrix[0]["chain_id"])
	assert.Equal(t, "137", matrix[1]["chain_id"])
}

func TestRuleHandler_UpdateRule_ClearMatrix(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	rule.Matrix = json.RawMessage(`[{"chain_id":"1","key":"val"}]`)
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{
		"matrix": []map[string]any{},
	}
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp RuleResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	var matrix []map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.Matrix, &matrix))
	assert.Len(t, matrix, 0)
}

// --- Budget migration tests ---

type mockTemplateRepo struct {
	getFn func(ctx context.Context, id string) (*types.RuleTemplate, error)
}

func (m *mockTemplateRepo) Create(ctx context.Context, tmpl *types.RuleTemplate) error { return nil }
func (m *mockTemplateRepo) Get(ctx context.Context, id string) (*types.RuleTemplate, error) {
	if m.getFn != nil {
		return m.getFn(ctx, id)
	}
	return nil, types.ErrNotFound
}
func (m *mockTemplateRepo) GetByName(ctx context.Context, name string) (*types.RuleTemplate, error) {
	return nil, types.ErrNotFound
}
func (m *mockTemplateRepo) Update(ctx context.Context, tmpl *types.RuleTemplate) error { return nil }
func (m *mockTemplateRepo) Delete(ctx context.Context, id string) error                { return nil }
func (m *mockTemplateRepo) List(ctx context.Context, filter storage.TemplateFilter) ([]*types.RuleTemplate, error) {
	return nil, nil
}
func (m *mockTemplateRepo) Count(ctx context.Context, filter storage.TemplateFilter) (int, error) { return 0, nil }
func (m *mockTemplateRepo) Upsert(ctx context.Context, tmpl *types.RuleTemplate) (bool, error) {
	return false, nil
}
func (m *mockTemplateRepo) ListIDsBySource(ctx context.Context, source types.RuleSource) ([]string, error) {
	return nil, nil
}
func (m *mockTemplateRepo) DeleteBySourceExcept(ctx context.Context, source types.RuleSource, keepIDs []string) (int64, error) {
	return 0, nil
}
func (m *mockTemplateRepo) DeleteMany(ctx context.Context, ids []string) error { return nil }

func newMockBudgetRepo() *mockBudgetRepo {
	return &mockBudgetRepo{}
}

func TestRuleHandler_UpdateRule_BudgetMigration(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	rule.TemplateID = strPtr("evm/erc20")
	rule.Variables = json.RawMessage(`{"chain_id":"1","token_address":"0xUSDC"}`)
	repo.addRule(rule)

	budgetMetering := json.RawMessage(`{"method":"calldata_param","unit":"${chain_id}:${token_address}","param_index":1,"param_type":"uint256"}`)
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

	// PATCH variables changing chain_id from 1 to 137
	body := map[string]interface{}{
		"variables": map[string]string{
			"chain_id":      "137",
			"token_address": "0xUSDC",
		},
	}
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify budget was synced: new unit = "137:0xUSDC" via UpsertLimits
	require.Len(t, upsertedRequests, 1, "budget sync should upsert one budget record")
	assert.Equal(t, "137:0xUSDC", upsertedRequests[0].Unit)
	assert.Equal(t, "-1", upsertedRequests[0].MaxTotal, "static budget uses default max_total")
	assert.Equal(t, "-1", upsertedRequests[0].MaxPerTx, "static budget uses default max_per_tx")
	assert.Equal(t, 80, upsertedRequests[0].AlertPct)
}

func TestRuleHandler_UpdateRule_BudgetMigrationNoTemplateRepo(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "admin-key"
	rule.TemplateID = strPtr("evm/erc20")
	rule.Variables = json.RawMessage(`{"chain_id":"1"}`)
	repo.addRule(rule)

	// No template repo or budget repo — migration should be skipped silently
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{
		"variables": map[string]string{"chain_id": "137"},
	}
	rec := doRuleRequest(t, h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

func strPtr(s string) *string { return &s }
