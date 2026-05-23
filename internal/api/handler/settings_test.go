package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/settings"
)

// ---------------------------------------------------------------------------
// Fake in-memory settings store
// ---------------------------------------------------------------------------

type fakeSettingsStore struct {
	mu   sync.Mutex
	data map[settings.Group]string
}

func newFakeSettingsStore() *fakeSettingsStore {
	return &fakeSettingsStore{data: make(map[settings.Group]string)}
}

func (f *fakeSettingsStore) Get(_ context.Context, key settings.Group) (*settings.Setting, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[key]
	if !ok {
		return nil, settings.ErrNotFound
	}
	return &settings.Setting{Key: string(key), ValueJSON: v}, nil
}

func (f *fakeSettingsStore) Put(_ context.Context, key settings.Group, valueJSON string, updatedBy string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[key] = valueJSON
	return nil
}

func (f *fakeSettingsStore) List(_ context.Context) ([]*settings.Setting, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*settings.Setting
	for k, v := range f.data {
		out = append(out, &settings.Setting{Key: string(k), ValueJSON: v})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func silentSettingsLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newSettingsHandlerForTest(t *testing.T) (*SettingsHandler, *settings.Manager) {
	t.Helper()
	store := newFakeSettingsStore()
	mgr := settings.NewManager(store, silentSettingsLogger())
	h := NewSettingsHandler(mgr, silentSettingsLogger())
	return h, mgr
}

// ---------------------------------------------------------------------------
// NewSettingsHandler
// ---------------------------------------------------------------------------

func TestNewSettingsHandler(t *testing.T) {
	mgr := settings.NewManager(newFakeSettingsStore(), silentSettingsLogger())
	h := NewSettingsHandler(mgr, silentSettingsLogger())
	assert.NotNil(t, h)
}

func TestSettingsHandler_SetAuditLogger(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	h.SetAuditLogger(nil) // just ensure no panic
}

// ---------------------------------------------------------------------------
// ServeHTTP — routing
// ---------------------------------------------------------------------------

func TestSettingsHandler_ServeHTTP_NoPrefix(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/something-else", nil)
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSettingsHandler_ServeHTTP_NoGroup(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/", nil)
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSettingsHandler_ServeHTTP_GroupWithSlash(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/security/extra", nil)
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSettingsHandler_ServeHTTP_MethodNotAllowed(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/v1/admin/settings/security", nil)
			req = req.WithContext(adminCtx(t))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
		})
	}
}

// ---------------------------------------------------------------------------
// GET — all known groups
// ---------------------------------------------------------------------------

func TestSettingsHandler_GET_Security(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/security", nil)
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var s settings.SecuritySnapshot
	err := json.Unmarshal(w.Body.Bytes(), &s)
	require.NoError(t, err)
	assert.True(t, s.NonceRequired)
}

func TestSettingsHandler_GET_Notify(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/notify", nil)
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSettingsHandler_GET_AuditMonitor(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/audit_monitor", nil)
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSettingsHandler_GET_Blocklist(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/evm.dynamic_blocklist", nil)
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSettingsHandler_GET_Simulation(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/evm.simulation", nil)
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSettingsHandler_GET_Foundry(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/evm.foundry", nil)
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSettingsHandler_GET_RPCGateway(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/evm.rpc_gateway", nil)
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSettingsHandler_GET_MaterialCheck(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/evm.material_check", nil)
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSettingsHandler_GET_Web(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/web", nil)
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSettingsHandler_GET_UnknownGroup(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/unknown.group", nil)
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---------------------------------------------------------------------------
// PUT — security group
// ---------------------------------------------------------------------------

func TestSettingsHandler_PUT_Security(t *testing.T) {
	h, mgr := newSettingsHandlerForTest(t)
	body := `{"nonce_required": false, "rate_limit_default": 200}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/security", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	assert.False(t, mgr.Security().NonceRequired)
	assert.Equal(t, 200, mgr.Security().RateLimitDefault)
}

func TestSettingsHandler_PUT_Security_InvalidJSON(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{invalid json`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/security", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// PUT — all other groups
// ---------------------------------------------------------------------------

func TestSettingsHandler_PUT_Notify_InvalidJSON(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{invalid json`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/notify", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSettingsHandler_PUT_AuditMonitor_InvalidJSON(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{bad`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/audit_monitor", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSettingsHandler_PUT_Blocklist_InvalidJSON(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{{{`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/evm.dynamic_blocklist", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSettingsHandler_PUT_Simulation_InvalidJSON(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{bad`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/evm.simulation", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSettingsHandler_PUT_Foundry_InvalidJSON(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{{{`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/evm.foundry", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSettingsHandler_PUT_RPCGateway_InvalidJSON(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{bad`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/evm.rpc_gateway", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSettingsHandler_PUT_MaterialCheck_InvalidJSON(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{bad`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/evm.material_check", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSettingsHandler_PUT_Web_InvalidJSON(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{bad`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/web", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSettingsHandler_PUT_Notify(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{"providers": {}, "channels": {}}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/notify", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSettingsHandler_PUT_AuditMonitor(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{"enabled": true, "interval": 60000000000}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/audit_monitor", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSettingsHandler_PUT_Blocklist(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{"enabled": true, "sources": []}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/evm.dynamic_blocklist", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSettingsHandler_PUT_Simulation(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{"enabled": true, "timeout": 30000000000}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/evm.simulation", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSettingsHandler_PUT_Foundry(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{"enabled": true}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/evm.foundry", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSettingsHandler_PUT_RPCGateway(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{"base_url": "http://localhost:8545"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/evm.rpc_gateway", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSettingsHandler_PUT_MaterialCheck(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{"enabled": true}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/evm.material_check", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSettingsHandler_PUT_Web(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{"enabled": false}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/web", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSettingsHandler_PUT_UnknownGroup(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{"enabled": true}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/unknown.group", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// writeSettingsJSON
// ---------------------------------------------------------------------------

func TestWriteSettingsJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeSettingsJSON(w, http.StatusOK, map[string]string{"hello": "world"})
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var m map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &m)
	require.NoError(t, err)
	assert.Equal(t, "world", m["hello"])
}

// ---------------------------------------------------------------------------
// recordAudit
// ---------------------------------------------------------------------------

func TestSettingsHandler_RecordAudit_NilAuditLogger(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	// Should not panic
	h.recordAudit(context.Background(), "admin", settings.GroupSecurity, &settings.SecuritySnapshot{})
}

func TestSettingsHandler_RecordAudit_WithAuditLogger(t *testing.T) {
	store := newFakeSettingsStore()
	mgr := settings.NewManager(store, silentSettingsLogger())
	auditLogger, err := audit.NewAuditLogger(newMockAuditRepo(), silentSettingsLogger())
	require.NoError(t, err)

	h := NewSettingsHandler(mgr, silentSettingsLogger())
	h.SetAuditLogger(auditLogger)
	// Should not panic with a real audit logger; the mock repo records the event.
	h.recordAudit(context.Background(), "admin-key", settings.GroupSecurity, &settings.SecuritySnapshot{NonceRequired: true})
}

// ---------------------------------------------------------------------------
// PUT with API key in context (actor = key ID)
// ---------------------------------------------------------------------------

func TestSettingsHandler_PUT_WithAPIKeyActor(t *testing.T) {
	h, _ := newSettingsHandlerForTest(t)
	body := `{"max_request_age": 120000000000}` // 2 minutes
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/security", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(context.Background(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "my-key", Role: types.RoleAdmin})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
