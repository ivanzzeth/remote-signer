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

// --- Mock RuleRepository for readonly tests ---

type mockRuleRepo struct {
	rules map[types.RuleID]*types.Rule
}

func newMockRuleRepo() *mockRuleRepo {
	return &mockRuleRepo{rules: make(map[types.RuleID]*types.Rule)}
}

func (m *mockRuleRepo) Create(_ context.Context, rule *types.Rule) error {
	m.rules[rule.ID] = rule
	return nil
}

func (m *mockRuleRepo) Get(_ context.Context, id types.RuleID) (*types.Rule, error) {
	r, ok := m.rules[id]
	if !ok {
		return nil, types.ErrNotFound
	}
	return r, nil
}

func (m *mockRuleRepo) Update(_ context.Context, rule *types.Rule) error {
	if _, ok := m.rules[rule.ID]; !ok {
		return types.ErrNotFound
	}
	m.rules[rule.ID] = rule
	return nil
}

func (m *mockRuleRepo) Delete(_ context.Context, id types.RuleID) error {
	if _, ok := m.rules[id]; !ok {
		return types.ErrNotFound
	}
	delete(m.rules, id)
	return nil
}

func (m *mockRuleRepo) List(_ context.Context, _ storage.RuleFilter) ([]*types.Rule, error) {
	var result []*types.Rule
	for _, r := range m.rules {
		result = append(result, r)
	}
	return result, nil
}

func (m *mockRuleRepo) Count(_ context.Context, _ storage.RuleFilter) (int, error) {
	return len(m.rules), nil
}

func (m *mockRuleRepo) ListByChainType(_ context.Context, _ types.ChainType) ([]*types.Rule, error) {
	return nil, nil
}

func (m *mockRuleRepo) IncrementMatchCount(_ context.Context, _ types.RuleID) error {
	return nil
}

// addRule adds a rule to the mock repo directly.
func (m *mockRuleRepo) addRule(rule *types.Rule) {
	m.rules[rule.ID] = rule
}

// --- Helper ---

func adminCtx() context.Context {
	return context.WithValue(context.Background(), middleware.APIKeyContextKey, &types.APIKey{
		ID:    "admin-key",
		Admin: true,
	})
}

func newAPIRule() *types.Rule {
	ct := types.ChainTypeEVM
	return &types.Rule{
		ID:        "rule_00000000-0000-0000-0000-000000000001",
		Name:      "test-api-rule",
		Type:      types.RuleTypeEVMAddressList,
		Mode:      types.RuleModeWhitelist,
		Source:    types.RuleSourceAPI,
		ChainType: &ct,
		Config:    json.RawMessage(`{"addresses":["0x0000000000000000000000000000000000000001"]}`),
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func newConfigRule() *types.Rule {
	ct := types.ChainTypeEVM
	return &types.Rule{
		ID:        "cfg_0",
		Name:      "test-config-rule",
		Type:      types.RuleTypeEVMAddressList,
		Mode:      types.RuleModeWhitelist,
		Source:    types.RuleSourceConfig,
		ChainType: &ct,
		Config:    json.RawMessage(`{"addresses":["0x0000000000000000000000000000000000000002"]}`),
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// --- Tests: readOnly blocks CRUD ---

func TestRuleHandler_ReadOnly_CreateBlocked(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default(), WithReadOnly())
	require.NoError(t, err)

	body := `{"name":"test","type":"evm_address_list","mode":"whitelist","config":{"addresses":["0x0000000000000000000000000000000000000001"]},"enabled":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules", bytes.NewBufferString(body))
	req = req.WithContext(adminCtx())
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "rules_api_readonly")
}

func TestRuleHandler_ReadOnly_UpdateBlocked(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default(), WithReadOnly())
	require.NoError(t, err)

	body := `{"name":"updated"}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), bytes.NewBufferString(body))
	req = req.WithContext(adminCtx())
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "rules_api_readonly")
}

func TestRuleHandler_ReadOnly_DeleteBlocked(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default(), WithReadOnly())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/rules/"+string(rule.ID), nil)
	req = req.WithContext(adminCtx())
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "rules_api_readonly")
}

func TestRuleHandler_ReadOnly_GetAllowed(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default(), WithReadOnly())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules/"+string(rule.ID), nil)
	req = req.WithContext(adminCtx())
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRuleHandler_ReadOnly_ListAllowed(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default(), WithReadOnly())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules", nil)
	req = req.WithContext(adminCtx())
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Tests: config-sourced rules always blocked ---

func TestRuleHandler_ConfigSourced_UpdateBlocked(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newConfigRule()
	repo.addRule(rule)

	// readOnly=false, but config-sourced should still be blocked
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"name":"hacked"}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), bytes.NewBufferString(body))
	req = req.WithContext(adminCtx())
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "config-sourced")
}

func TestRuleHandler_ConfigSourced_DeleteBlocked(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newConfigRule()
	repo.addRule(rule)

	// readOnly=false, but config-sourced should still be blocked
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/rules/"+string(rule.ID), nil)
	req = req.WithContext(adminCtx())
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "config-sourced")
}
