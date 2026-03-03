package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestTemplateHandler_ReadOnly_CreateBlocked(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	svc := newTemplateService(t, tmplRepo, ruleRepo, budgetRepo)

	h, err := NewTemplateHandler(tmplRepo, svc, newTestLogger(), true)
	require.NoError(t, err)

	body := `{"name":"test","type":"evm_address_list","mode":"whitelist","config":{"addresses":["0x01"]},"enabled":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates", bytes.NewBufferString(body))
	req = req.WithContext(contextWithAPIKey(req.Context(), adminAPIKey()))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "rules_api_readonly")
}

func TestTemplateHandler_ReadOnly_UpdateBlocked(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	svc := newTemplateService(t, tmplRepo, ruleRepo, budgetRepo)

	// Seed an API-sourced template
	tmpl := &types.RuleTemplate{
		ID:      "tmpl_api_1",
		Name:    "test-template",
		Type:    types.RuleTypeEVMAddressList,
		Mode:    types.RuleModeWhitelist,
		Source:  types.RuleSourceAPI,
		Enabled: true,
	}
	require.NoError(t, tmplRepo.Create(context.Background(), tmpl))

	h, err := NewTemplateHandler(tmplRepo, svc, newTestLogger(), true)
	require.NoError(t, err)

	body := `{"name":"updated"}`
	r := httptest.NewRequest(http.MethodPatch, "/api/v1/templates/tmpl_api_1", bytes.NewBufferString(body))
	r = r.WithContext(contextWithAPIKey(r.Context(), adminAPIKey()))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "rules_api_readonly")
}

func TestTemplateHandler_ReadOnly_DeleteBlocked(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	svc := newTemplateService(t, tmplRepo, ruleRepo, budgetRepo)

	// Seed an API-sourced template
	tmpl := &types.RuleTemplate{
		ID:      "tmpl_api_2",
		Name:    "test-template-del",
		Type:    types.RuleTypeEVMAddressList,
		Mode:    types.RuleModeWhitelist,
		Source:  types.RuleSourceAPI,
		Enabled: true,
	}
	require.NoError(t, tmplRepo.Create(context.Background(), tmpl))

	h, err := NewTemplateHandler(tmplRepo, svc, newTestLogger(), true)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodDelete, "/api/v1/templates/tmpl_api_2", nil)
	r = r.WithContext(contextWithAPIKey(r.Context(), adminAPIKey()))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "rules_api_readonly")
}

func TestTemplateHandler_ReadOnly_InstantiateBlocked(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	svc := newTemplateService(t, tmplRepo, ruleRepo, budgetRepo)

	h, err := NewTemplateHandler(tmplRepo, svc, newTestLogger(), true)
	require.NoError(t, err)

	body := `{"variables":{}}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/templates/tmpl_1/instantiate", bytes.NewBufferString(body))
	r = r.WithContext(contextWithAPIKey(r.Context(), adminAPIKey()))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "rules_api_readonly")
}

func TestTemplateHandler_ReadOnly_RevokeBlocked(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	svc := newTemplateService(t, tmplRepo, ruleRepo, budgetRepo)

	h, err := NewTemplateHandler(tmplRepo, svc, newTestLogger(), true)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/templates/instances/rule_1/revoke", nil)
	r = r.WithContext(contextWithAPIKey(r.Context(), adminAPIKey()))
	w := httptest.NewRecorder()

	h.ServeInstanceHTTP(w, r)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "rules_api_readonly")
}

func TestTemplateHandler_ReadOnly_GetAllowed(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	svc := newTemplateService(t, tmplRepo, ruleRepo, budgetRepo)

	h, err := NewTemplateHandler(tmplRepo, svc, newTestLogger(), true)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/templates", nil)
	r = r.WithContext(contextWithAPIKey(r.Context(), adminAPIKey()))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

// adminAPIKey returns a test admin API key.
func adminAPIKey() *types.APIKey {
	return &types.APIKey{
		ID:    "admin-key",
		Admin: true,
	}
}
