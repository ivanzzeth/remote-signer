package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

func setupValidateHandler(t *testing.T) (*TemplateHandler, *mockTemplateRepo) {
	t.Helper()
	repo := newMockTemplateRepo()
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	handler, err := NewTemplateHandler(
		repo,
		&service.TemplateService{},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		false,
		WithTemplateJSEvaluator(eval),
	)
	require.NoError(t, err)
	return handler, repo
}

func TestCoverage_ValidateTemplate_NonJS_BundleConfig(t *testing.T) {
	handler, repo := setupValidateHandler(t)
	require.NoError(t, repo.Create(context.TODO(), &types.RuleTemplate{
		ID: "evm/simple", Name: "Simple", Type: types.RuleTypeSignTypeRestriction,
		Mode: types.RuleModeWhitelist, ChainType: types.ChainType("evm"),
		Source: types.RuleSourceFile, ContentHash: "h1", Enabled: true,
		Config: mustJSONP(t, map[string]interface{}{
			"rules": []map[string]interface{}{{
				"name": "r1", "type": "sign_type_restriction", "mode": "whitelist",
				"config": map[string]interface{}{"allowed_sign_types": []string{"transaction"}},
			}},
		}),
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/evm%2Fsimple/validate",
		strings.NewReader(`{}`)).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	var resp validateTemplateResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "evm/simple", resp.TemplateID)
	assert.Equal(t, 1, resp.Total)
	assert.Equal(t, 1, resp.Passed)
}

func TestCoverage_ValidateTemplate_NotFound(t *testing.T) {
	handler, _ := setupValidateHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/nonexistent/validate",
		strings.NewReader(`{}`)).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCoverage_ValidateTemplate_NonAdminForbidden(t *testing.T) {
	handler, _ := setupValidateHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/some/validate",
		strings.NewReader(`{}`)).WithContext(contextWithKey(t, types.RoleDev, "dev"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCoverage_ValidateTemplate_MethodNotAllowed(t *testing.T) {
	handler, _ := setupValidateHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates/some/validate",
		nil).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestCoverage_ValidateTemplate_NoJSEvaluator(t *testing.T) {
	repo := newMockTemplateRepo()
	handler, err := NewTemplateHandler(repo, &service.TemplateService{},
		slog.New(slog.NewTextHandler(io.Discard, nil)), false)
	require.NoError(t, err)
	require.NoError(t, repo.Create(context.TODO(), &types.RuleTemplate{
		ID: "evm/js", Name: "JS Rule", Type: types.RuleTypeEVMJS,
		Mode: types.RuleModeWhitelist, ChainType: types.ChainType("evm"),
		Source: types.RuleSourceFile, ContentHash: "h1", Enabled: true,
		Config: []byte(`{"script":"function validate(i){return{valid:true}}"}`),
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/evm%2Fjs/validate",
		strings.NewReader(`{}`)).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "evaluator")
}

func TestCoverage_ValidateTemplate_VariableSubstitutionFailure(t *testing.T) {
	handler, repo := setupValidateHandler(t)
	require.NoError(t, repo.Create(context.TODO(), &types.RuleTemplate{
		ID: "evm/badvar", Name: "Bad Var", Type: types.RuleTypeSignTypeRestriction,
		Mode: types.RuleModeWhitelist, ChainType: types.ChainType("evm"),
		Source: types.RuleSourceFile, ContentHash: "h1", Enabled: true,
		Config: []byte(`{"rules":[{"name":"r1","type":"sign_type_restriction","mode":"whitelist","config":{"allowed_sign_types":["${missing_var}"]}}]}`),
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/evm%2Fbadvar/validate",
		strings.NewReader(`{}`)).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "variable substitution failed")
}

func TestCoverage_ValidateTemplate_InvalidTestVariables(t *testing.T) {
	handler, repo := setupValidateHandler(t)
	require.NoError(t, repo.Create(context.TODO(), &types.RuleTemplate{
		ID: "evm/badtest", Name: "Bad Test Vars", Type: types.RuleTypeSignTypeRestriction,
		Mode: types.RuleModeWhitelist, ChainType: types.ChainType("evm"),
		Source: types.RuleSourceFile, ContentHash: "h1", Enabled: true,
		TestVariables: []byte(`{invalid`),
		Config:        mustJSONP(t, map[string]interface{}{"rules": []map[string]interface{}{{"name": "r1", "type": "sign_type_restriction", "mode": "whitelist", "config": map[string]interface{}{"allowed_sign_types": []string{"transaction"}}}}}),
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/evm%2Fbadtest/validate",
		strings.NewReader(`{}`)).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	var resp validateTemplateResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "evm/badtest", resp.TemplateID)
}

func TestCoverage_ValidateTemplate_InvalidVariablesJSON(t *testing.T) {
	handler, repo := setupValidateHandler(t)
	require.NoError(t, repo.Create(context.TODO(), &types.RuleTemplate{
		ID: "evm/badvars", Name: "Bad Vars", Type: types.RuleTypeSignTypeRestriction,
		Mode: types.RuleModeWhitelist, ChainType: types.ChainType("evm"),
		Source: types.RuleSourceFile, ContentHash: "h1", Enabled: true,
		Variables: []byte(`{invalid`),
		Config:    mustJSONP(t, map[string]interface{}{"rules": []map[string]interface{}{{"name": "r1", "type": "sign_type_restriction", "mode": "whitelist", "config": map[string]interface{}{"allowed_sign_types": []string{"transaction"}}}}}),
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/evm%2Fbadvars/validate",
		strings.NewReader(`{}`)).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "failed to parse template variables")
}

func TestCoverage_Template_ServeHTTP_Unauthorized(t *testing.T) {
	handler, _ := setupValidateHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCoverage_Template_ServeHTTP_EscapedID(t *testing.T) {
	handler, repo := setupValidateHandler(t)
	require.NoError(t, repo.Create(context.TODO(), &types.RuleTemplate{
		ID: "evm/erc20", Name: "ERC20", Type: types.RuleTypeSignTypeRestriction,
		Mode: types.RuleModeWhitelist, ChainType: types.ChainType("evm"),
		Source: types.RuleSourceFile, ContentHash: "h1", Enabled: true,
		Config: mustJSONP(t, map[string]interface{}{
			"rules": []map[string]interface{}{{
				"name": "r1", "type": "sign_type_restriction", "mode": "whitelist",
				"config": map[string]interface{}{"allowed_sign_types": []string{"transaction"}},
			}},
		}),
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates/evm%2Ferc20", nil).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "evm/erc20")
}

func TestCoverage_Template_ServeInstanceHTTP_NoAPIKey(t *testing.T) {
	handler, _ := setupValidateHandler(t)
	w := httptest.NewRecorder()
	handler.ServeInstanceHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/templates/instances/rule-1/revoke", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCoverage_Template_ServeInstanceHTTP_NotFound(t *testing.T) {
	handler, _ := setupValidateHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates/instances/unknown", nil).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeInstanceHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCoverage_Template_ServeInstanceHTTP_MethodNotAllowed(t *testing.T) {
	handler, _ := setupValidateHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates/instances/rule-1/revoke", nil).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeInstanceHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestCoverage_WriteJSON_EncodeError_APIKeyHandler(t *testing.T) {
	h := &APIKeyHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w := httptest.NewRecorder()
	h.writeJSON(w, make(chan int), http.StatusOK)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCoverage_WriteJSON_EncodeError_PresetHandler(t *testing.T) {
	h := &PresetHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w := httptest.NewRecorder()
	h.writeJSON(w, make(chan int), http.StatusOK)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCoverage_WriteJSON_EncodeError_TemplateHandler(t *testing.T) {
	h := &TemplateHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w := httptest.NewRecorder()
	h.writeJSON(w, make(chan int), http.StatusOK)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCoverage_WriteJSON_EncodeError_AuditHandler(t *testing.T) {
	h := &AuditHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w := httptest.NewRecorder()
	h.writeJSON(w, make(chan int), http.StatusOK)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCoverage_WriteJSON_EncodeError_BootstrapHandler(t *testing.T) {
	h := &BootstrapHandler{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w := httptest.NewRecorder()
	h.writeJSON(w, http.StatusOK, make(chan int))
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCoverage_PresetHandler_WriteError(t *testing.T) {
	h := &PresetHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w := httptest.NewRecorder()
	h.writeError(w, "test error", http.StatusBadRequest)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "test error")
}

type brokenWriter struct{}

func (brokenWriter) Header() http.Header           { return http.Header{} }
func (brokenWriter) Write([]byte) (int, error)     { return 0, fmt.Errorf("write error") }
func (brokenWriter) WriteHeader(int)               {}

func TestCoverage_WriteSettingsJSON_WriteError(t *testing.T) {
	writeSettingsJSON(brokenWriter{}, http.StatusOK, map[string]interface{}{"foo": "bar"})
}

func TestCoverage_ListAPIKeyNames_Success(t *testing.T) {
	mock := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(mock, slog.New(slog.NewTextHandler(io.Discard, nil)), false)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys/names", nil).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ListAPIKeyNames(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCoverage_ListAPIKeyNames_RepoError(t *testing.T) {
	mock := newMockAPIKeyRepo()
	mock.listFn = func(_ context.Context, _ storage.APIKeyFilter) ([]*types.APIKey, error) {
		return nil, fmt.Errorf("list failed")
	}
	h, err := NewAPIKeyHandler(mock, slog.New(slog.NewTextHandler(io.Discard, nil)), false)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys/names", nil).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ListAPIKeyNames(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "failed to list api keys")
}
