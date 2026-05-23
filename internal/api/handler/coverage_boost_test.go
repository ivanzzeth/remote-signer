package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/settings"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ---------------------------------------------------------------------------
// Mock settings store that returns errors on Put
// ---------------------------------------------------------------------------

type errorSettingsStore struct {
	settings.Store
}

func (e *errorSettingsStore) Put(_ context.Context, _ settings.Group, _, _ string) error {
	return fmt.Errorf("store write error")
}

// ---------------------------------------------------------------------------
// APIKeyHandler: listAPIKeys — valid offset query (line 192)
// ---------------------------------------------------------------------------

func TestCoverage_ListAPIKeys_ValidOffset(t *testing.T) {
	mock := newMockAPIKeyRepo()
	mock.seed(makeTestAPIKey("k1", "Key 1", types.APIKeySourceAPI, true))
	mock.seed(makeTestAPIKey("k2", "Key 2", types.APIKeySourceAPI, true))
	h, err := NewAPIKeyHandler(mock, apikeyLogger(), false)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys?offset=5", nil).WithContext(
		context.WithValue(context.Background(), middleware.APIKeyContextKey, apikeyAdminKey()))
	w := httptest.NewRecorder()
	h.listAPIKeys(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// APIKeyHandler: createAPIKey — empty role and invalid role (lines 331-338)
// ---------------------------------------------------------------------------

func TestCoverage_CreateAPIKey_EmptyRole(t *testing.T) {
	mock := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(mock, apikeyLogger(), false)
	require.NoError(t, err)

	body := strings.NewReader(`{"id":"create-empty-role","name":"No Role","public_key":"0xabc","role":""}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(context.Background(), middleware.APIKeyContextKey, apikeyAdminKey()))
	w := httptest.NewRecorder()
	h.createAPIKey(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "role is required")
}

func TestCoverage_CreateAPIKey_InvalidRole(t *testing.T) {
	mock := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(mock, apikeyLogger(), false)
	require.NoError(t, err)

	body := strings.NewReader(`{"id":"create-bad-role","name":"Bad Role","public_key":"0xabc","role":"invalid_role"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(context.Background(), middleware.APIKeyContextKey, apikeyAdminKey()))
	w := httptest.NewRecorder()
	h.createAPIKey(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid role")
}

func TestCoverage_CreateAPIKey_WithAuditLogger(t *testing.T) {
	mock := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(mock, apikeyLogger(), false)
	require.NoError(t, err)
	auditLogger, aErr := audit.NewAuditLogger(newMockAuditRepo(), apikeyLogger())
	require.NoError(t, aErr)
	h.SetAuditLogger(auditLogger)

	body := strings.NewReader(`{"id":"create-audit","name":"Audit Create","public_key":"0xabc","role":"strategy"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(context.Background(), middleware.APIKeyContextKey, apikeyAdminKey()))
	w := httptest.NewRecorder()
	h.createAPIKey(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

// ---------------------------------------------------------------------------
// APIKeyHandler: updateAPIKey — invalid role and self-role-change (lines 415-418, 436-439)
// ---------------------------------------------------------------------------

func TestCoverage_UpdateAPIKey_InvalidRole(t *testing.T) {
	mock := newMockAPIKeyRepo()
	mock.seed(makeTestAPIKey("update-invalid-role", "Update Invalid Role", types.APIKeySourceAPI, true))
	h, err := NewAPIKeyHandler(mock, apikeyLogger(), false)
	require.NoError(t, err)

	body := strings.NewReader(`{"role":"bad_role"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/api-keys/update-invalid-role", body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(context.Background(), middleware.APIKeyContextKey, apikeyAdminKey()))
	w := httptest.NewRecorder()
	h.updateAPIKey(w, req, "update-invalid-role")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid role")
}

func TestCoverage_UpdateAPIKey_SelfRoleChange(t *testing.T) {
	mock := newMockAPIKeyRepo()
	adminKey := &types.APIKey{
		ID: "self-role-change", Name: "Self Role", Enabled: true, Role: types.RoleAdmin,
		PublicKeyHex: "0xabc", Source: types.APIKeySourceAPI,
		RateLimit: 100,
	}
	mock.seed(adminKey)
	h, err := NewAPIKeyHandler(mock, apikeyLogger(), false)
	require.NoError(t, err)

	body := strings.NewReader(`{"role":"dev"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/api-keys/self-role-change", body)
	req.Header.Set("Content-Type", "application/json")
	callerKey := &types.APIKey{ID: "self-role-change", Name: "Self Role", Enabled: true, Role: types.RoleAdmin}
	req = req.WithContext(context.WithValue(context.Background(), middleware.APIKeyContextKey, callerKey))
	w := httptest.NewRecorder()
	h.updateAPIKey(w, req, "self-role-change")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "cannot change your own role")
}

func TestCoverage_UpdateAPIKey_WithAuditLogger(t *testing.T) {
	mock := newMockAPIKeyRepo()
	mock.seed(makeTestAPIKey("update-audit", "Update Audit", types.APIKeySourceAPI, true))
	h, err := NewAPIKeyHandler(mock, apikeyLogger(), false)
	require.NoError(t, err)
	auditLogger, aErr := audit.NewAuditLogger(newMockAuditRepo(), apikeyLogger())
	require.NoError(t, aErr)
	h.SetAuditLogger(auditLogger)

	body := strings.NewReader(`{"name":"Updated Name"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/api-keys/update-audit", body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(context.Background(), middleware.APIKeyContextKey, apikeyAdminKey()))
	w := httptest.NewRecorder()
	h.updateAPIKey(w, req, "update-audit")
	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// APIKeyHandler: deleteAPIKey — self-delete (lines 485-488)
// ---------------------------------------------------------------------------

func TestCoverage_DeleteAPIKey_SelfDelete(t *testing.T) {
	mock := newMockAPIKeyRepo()
	selfKey := &types.APIKey{
		ID: "delete-self", Name: "Delete Self", Enabled: true, Role: types.RoleAdmin,
		PublicKeyHex: "0xabc", Source: types.APIKeySourceAPI, RateLimit: 100,
	}
	mock.seed(selfKey)
	h, err := NewAPIKeyHandler(mock, apikeyLogger(), false)
	require.NoError(t, err)

	callerKey := &types.APIKey{ID: "delete-self", Name: "Delete Self", Enabled: true, Role: types.RoleAdmin}
	rr := doAPIKeyItemRequest(t, h, http.MethodDelete, "/api/v1/api-keys/delete-self", nil, callerKey)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "cannot delete your own API key")
}

func TestCoverage_DeleteAPIKey_WithAuditLogger(t *testing.T) {
	mock := newMockAPIKeyRepo()
	delKey := &types.APIKey{
		ID: "delete-audit", Name: "Delete Audit", Enabled: true, Role: types.RoleStrategy,
		PublicKeyHex: "0xabc", Source: types.APIKeySourceAPI, RateLimit: 100,
	}
	mock.seed(delKey)
	adminKey := &types.APIKey{
		ID: "other-admin", Name: "Other Admin", Enabled: true, Role: types.RoleAdmin,
		PublicKeyHex: "0xabc", Source: types.APIKeySourceAPI, RateLimit: 100,
	}
	mock.seed(adminKey)

	h, err := NewAPIKeyHandler(mock, apikeyLogger(), false)
	require.NoError(t, err)
	auditLogger, aErr := audit.NewAuditLogger(newMockAuditRepo(), apikeyLogger())
	require.NoError(t, aErr)
	h.SetAuditLogger(auditLogger)

	rr := doAPIKeyItemRequest(t, h, http.MethodDelete, "/api/v1/api-keys/delete-audit", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusNoContent, rr.Code)
}

// ---------------------------------------------------------------------------
// AuditHandler: filter validation edge cases
// ---------------------------------------------------------------------------

func TestCoverage_Audit_FilterSeverity(t *testing.T) {
	repo := newMockAuditRepo()
	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?severity=invalid", auditAPIKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid severity")

	seedAuditRecord(repo, makeAuditRecord("sv1", types.AuditEventTypeAuthSuccess, time.Now()))
	rr = doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?severity=warning", auditAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestCoverage_Audit_FilterSignerAddress(t *testing.T) {
	repo := newMockAuditRepo()
	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?signer_address=not_a_valid_address", auditAPIKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid signer_address")

	seedAuditRecord(repo, makeAuditRecord("sa1", types.AuditEventTypeSignRequest, time.Now()))
	rr = doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?signer_address=0xabcdef1234567890abcdef1234567890abcdef12", auditAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestCoverage_Audit_FilterSignRequestID(t *testing.T) {
	repo := newMockAuditRepo()
	seedAuditRecord(repo, makeAuditRecord("srid1", types.AuditEventTypeSignRequest, time.Now()))
	h, err := NewAuditHandler(repo, auditLogger())
	require.NoError(t, err)

	rr := doAuditRequest(t, h, http.MethodGet, "/api/v1/audit?sign_request_id=req-999", auditAPIKey())
	assert.Equal(t, http.StatusOK, rr.Code)
}

// ---------------------------------------------------------------------------
// SettingsHandler: update error paths via errorSettingsStore
// ---------------------------------------------------------------------------

func TestCoverage_Settings_Put_Error(t *testing.T) {
	store := &errorSettingsStore{Store: newFakeSettingsStore()}
	mgr := settings.NewManager(store, silentSettingsLogger())
	h := NewSettingsHandler(mgr, silentSettingsLogger())

	tests := []struct {
		group string
		path  string
		body  string
	}{
		{"security", "security", `{"audit_retention_days":30}`},
		{"notify", "notify", `{"slack_webhook_url":"https://hooks.slack.com/test"}`},
		{"audit_monitor", "audit_monitor", `{"enabled":true}`},
		{"blocklist", "evm.dynamic_blocklist", `{"enabled":true}`},
		{"simulation", "evm.simulation", `{"enabled":true}`},
		{"foundry", "evm.foundry", `{"url":"http://localhost:8545"}`},
		{"rpc_gateway", "evm.rpc_gateway", `{"url":"http://localhost:8545"}`},
		{"material_check", "evm.material_check", `{"enabled":true}`},
		{"web", "web", `{"url":"http://localhost:8080"}`},
	}

	for _, tt := range tests {
		t.Run(tt.group, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/"+tt.path,
				strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			assert.Equal(t, http.StatusInternalServerError, w.Code, "group=%s body=%s", tt.group, w.Body.String())
			assert.Contains(t, w.Body.String(), "store write error")
		})
	}
}

// ---------------------------------------------------------------------------
// BootstrapHandler: nil logger path
// ---------------------------------------------------------------------------

func TestCoverage_Bootstrap_NilLogger(t *testing.T) {
	h := NewBootstrapHandler(newMockAPIKeyRepo(), nil, nil)
	assert.NotNil(t, h)
}

// ---------------------------------------------------------------------------
// SettingsHandler: recordAudit with provided audit logger
// ---------------------------------------------------------------------------

func TestCoverage_Settings_RecordAudit(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	mockAuditRepo := newMockAuditRepo()
	auditLogger, err := audit.NewAuditLogger(mockAuditRepo, silentSettingsLogger())
	require.NoError(t, err)
	h.SetAuditLogger(auditLogger)
	h.recordAudit(context.Background(), "test-actor", "security", map[string]interface{}{"key": "val"})
}
