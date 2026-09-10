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
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/settings"
)

// ---------------------------------------------------------------------------
// Fake in-memory settings store
// ---------------------------------------------------------------------------
//
// ⚠️ Exported from a _test.go file — the export_test.go idiom, the same one
// apikey_test.go and hdwallet_test.go use, and for the same reason. Proposal S5
// moved this handler's route-level tests to the external package handler_test
// (settings_routes_test.go), because driving the production route patterns means
// importing internal/api, which imports this package. The fake store is shared
// with in-package tests that stay here (TestCoverage_Settings_Put_Error wraps it
// in errorSettingsStore), so it cannot move — it is exported instead.
// ⛔ It is not part of the package's API: a _test.go file is compiled only into
// the test binary.

// FakeSettingsStore is an in-memory settings.Store for tests.
type FakeSettingsStore struct {
	mu   sync.Mutex
	data map[settings.Group]string
}

// NewFakeSettingsStore returns an empty in-memory store.
func NewFakeSettingsStore() *FakeSettingsStore {
	return &FakeSettingsStore{data: make(map[settings.Group]string)}
}

// Get implements settings.Store.
func (f *FakeSettingsStore) Get(_ context.Context, key settings.Group) (*settings.Setting, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[key]
	if !ok {
		return nil, settings.ErrNotFound
	}
	return &settings.Setting{Key: string(key), ValueJSON: v}, nil
}

// Put implements settings.Store.
func (f *FakeSettingsStore) Put(_ context.Context, key settings.Group, valueJSON string, updatedBy string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[key] = valueJSON
	return nil
}

// List implements settings.Store.
func (f *FakeSettingsStore) List(_ context.Context) ([]*settings.Setting, error) {
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

// SettingsTestLogger is a logger that discards everything. Exported for the
// external route-test package; see the note on FakeSettingsStore.
func SettingsTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// NewSettingsHandlerForTest builds a handler over a fresh in-memory store and
// returns the manager alongside it, so a test can read back what a PUT wrote.
func NewSettingsHandlerForTest(t *testing.T) (*SettingsHandler, *settings.Manager) {
	t.Helper()
	store := NewFakeSettingsStore()
	mgr := settings.NewManager(store, SettingsTestLogger())
	h := NewSettingsHandler(mgr, SettingsTestLogger())
	return h, mgr
}

// ---------------------------------------------------------------------------
// Store that fails every write
// ---------------------------------------------------------------------------

// errorSettingsStore turns every Put into a failure, which is how the 500 arm of
// each PUT endpoint is reached.
//
// ⚠️ It and TestCoverage_Settings_Put_Error moved here from
// coverage_boost_test.go in proposal S5 — same name, same assertions, different
// file. They belong next to the other in-package settings tests, and the
// coverage_boost ratchet (that file may only shrink) is the mechanism that says
// so.
type errorSettingsStore struct {
	settings.Store
}

func (e *errorSettingsStore) Put(_ context.Context, _ settings.Group, _, _ string) error {
	return fmt.Errorf("store write error")
}

// TestCoverage_Settings_Put_Error stays in package handler because
// errorSettingsStore is unexported (S5 moved the rest of the settings route
// tests to package handler_test).
//
// ⚠️ The rows used to be paths dispatched through ServeHTTP; they name their
// endpoint function directly now, one identifier per row, because ServeHTTP is
// gone and the route decides which function runs. The path is still passed so
// the request is well-formed, ⛔ but it no longer selects anything — that is the
// point of the change, and a row pointing at the wrong function would now fail
// on its own body rather than being silently re-routed by the path.
func TestCoverage_Settings_Put_Error(t *testing.T) {
	store := &errorSettingsStore{Store: NewFakeSettingsStore()}
	mgr := settings.NewManager(store, SettingsTestLogger())
	h := NewSettingsHandler(mgr, SettingsTestLogger())

	tests := []struct {
		group    string
		path     string
		body     string
		endpoint http.HandlerFunc
	}{
		{"security", "security", `{"audit_retention_days":30}`, h.PutSecurity},
		{"notify", "notify", `{"slack_webhook_url":"https://hooks.slack.com/test"}`, h.PutNotify},
		{"audit_monitor", "audit_monitor", `{"enabled":true}`, h.PutAuditMonitor},
		{"blocklist", "evm.dynamic_blocklist", `{"enabled":true}`, h.PutBlocklist},
		{"simulation", "evm.simulation", `{"enabled":true}`, h.PutSimulation},
		{"foundry", "evm.foundry", `{"url":"http://localhost:8545"}`, h.PutFoundry},
		{"rpc_gateway", "evm.rpc_gateway", `{"url":"http://localhost:8545"}`, h.PutRPCGateway},
		{"material_check", "evm.material_check", `{"enabled":true}`, h.PutMaterialCheck},
		{"web", "web", `{"url":"http://localhost:8080"}`, h.PutWeb},
	}

	for _, tt := range tests {
		t.Run(tt.group, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/"+tt.path,
				strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			tt.endpoint(w, req)
			assert.Equal(t, http.StatusInternalServerError, w.Code, "group=%s body=%s", tt.group, w.Body.String())
			assert.Contains(t, w.Body.String(), "store write error")
		})
	}
}

// ---------------------------------------------------------------------------
// writeSettingsJSON — unexported, so this test cannot leave the package
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
// recordAudit — unexported, so these tests cannot leave the package either
// ---------------------------------------------------------------------------

func TestSettingsHandler_RecordAudit_NilAuditLogger(t *testing.T) {
	h, _ := NewSettingsHandlerForTest(t)
	// Should not panic
	h.recordAudit(context.Background(), "admin", settings.GroupSecurity, &settings.SecuritySnapshot{})
}

func TestSettingsHandler_RecordAudit_WithAuditLogger(t *testing.T) {
	store := NewFakeSettingsStore()
	mgr := settings.NewManager(store, SettingsTestLogger())
	auditLogger, err := audit.NewAuditLogger(newMockAuditRepo(), SettingsTestLogger())
	require.NoError(t, err)

	h := NewSettingsHandler(mgr, SettingsTestLogger())
	h.SetAuditLogger(auditLogger)
	// Should not panic with a real audit logger; the mock repo records the event.
	h.recordAudit(context.Background(), "admin-key", settings.GroupSecurity, &settings.SecuritySnapshot{NonceRequired: true})
}
