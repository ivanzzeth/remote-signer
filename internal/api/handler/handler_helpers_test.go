package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/core/registry"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------------------------------------------------------------------------
// strFromMap
// ---------------------------------------------------------------------------

func TestStrFromMap(t *testing.T) {
	m := map[string]any{"a": "hello", "b": 42, "c": true}

	assert.Equal(t, "hello", strFromMap(m, "a"))
	assert.Equal(t, "42", strFromMap(m, "b"))
	assert.Equal(t, "true", strFromMap(m, "c"))
	assert.Equal(t, "", strFromMap(m, "nonexistent"))
	assert.Equal(t, "", strFromMap(nil, "x"))
}

func TestStrFromMap_NilMap(t *testing.T) {
	assert.Equal(t, "", strFromMap(nil, "key"))
}

// ---------------------------------------------------------------------------
// intFromMap
// ---------------------------------------------------------------------------

func TestIntFromMap(t *testing.T) {
	m := map[string]any{
		"a": int(42),
		"b": int64(100),
		"c": float64(3.14),
		"d": "not_a_number",
	}

	assert.Equal(t, 42, intFromMap(m, "a"))
	assert.Equal(t, 100, intFromMap(m, "b"))
	assert.Equal(t, 3, intFromMap(m, "c"))
	assert.Equal(t, 0, intFromMap(m, "d"), "non-numeric returns 0")
	assert.Equal(t, 0, intFromMap(m, "nonexistent"))
}

func TestIntFromMap_NilMap(t *testing.T) {
	assert.Equal(t, 0, intFromMap(nil, "key"))
}

// ---------------------------------------------------------------------------
// cloneStringMap
// ---------------------------------------------------------------------------

func TestCloneStringMap(t *testing.T) {
	orig := map[string]string{"a": "1", "b": "2"}
	cp := cloneStringMap(orig)
	assert.Equal(t, orig, cp)

	// Mutating copy must not affect original.
	cp["a"] = "changed"
	assert.Equal(t, "1", orig["a"])
}

func TestCloneStringMap_Nil(t *testing.T) {
	cp := cloneStringMap(nil)
	assert.Empty(t, cp)
	assert.NotNil(t, cp, "cloned nil map returns empty non-nil map")
}

func TestCloneStringMap_Empty(t *testing.T) {
	cp := cloneStringMap(map[string]string{})
	assert.Empty(t, cp)
}

// ---------------------------------------------------------------------------
// strPtrIfNotEmpty
// ---------------------------------------------------------------------------

func TestStrPtrIfNotEmpty(t *testing.T) {
	assert.NotNil(t, strPtrIfNotEmpty("hello"))
	assert.Equal(t, "hello", *strPtrIfNotEmpty("hello"))

	assert.Nil(t, strPtrIfNotEmpty(""))
}

// ---------------------------------------------------------------------------
// resolveTemplateDefaults
// ---------------------------------------------------------------------------

func TestResolveTemplateDefaults_UsesVarsFirst(t *testing.T) {
	defs := []types.TemplateVariable{
		{Name: "a", Default: "default_a"},
		{Name: "b", Default: "default_b"},
	}
	vars := map[string]string{"a": "override_a"}
	got := resolveTemplateDefaults(defs, vars)
	assert.Equal(t, "override_a", got["a"], "vars take precedence")
	assert.Equal(t, "default_b", got["b"], "default used when no var")
}

func TestResolveTemplateDefaults_NonStringDefault(t *testing.T) {
	defs := []types.TemplateVariable{
		{Name: "port", Default: 8080},
		{Name: "enabled", Default: true},
	}
	got := resolveTemplateDefaults(defs, nil)
	assert.Equal(t, "8080", got["port"])
	assert.Equal(t, "true", got["enabled"])
}

func TestResolveTemplateDefaults_NilDefaultSkipped(t *testing.T) {
	defs := []types.TemplateVariable{
		{Name: "a", Default: nil},
	}
	got := resolveTemplateDefaults(defs, nil)
	assert.Empty(t, got, "nil default produces no entry")
}

func TestResolveTemplateDefaults_EmptyStringDefaultSkipped(t *testing.T) {
	defs := []types.TemplateVariable{
		{Name: "a", Default: ""},
	}
	got := resolveTemplateDefaults(defs, nil)
	assert.Empty(t, got, "empty string default produces no entry")
}

func TestResolveTemplateDefaults_NilVars(t *testing.T) {
	got := resolveTemplateDefaults(nil, nil)
	assert.Empty(t, got)
}

// ---------------------------------------------------------------------------
// resolvedVarsToConfig
// ---------------------------------------------------------------------------

func TestResolvedVarsToConfig(t *testing.T) {
	cfg := resolvedVarsToConfig([]byte(`{"foo":"bar","num":42}`))
	assert.Equal(t, "bar", cfg["foo"])
	assert.Equal(t, float64(42), cfg["num"])
}

func TestResolvedVarsToConfig_Empty(t *testing.T) {
	cfg := resolvedVarsToConfig([]byte{})
	assert.Empty(t, cfg)
}

func TestResolvedVarsToConfig_InvalidJSON(t *testing.T) {
	cfg := resolvedVarsToConfig([]byte(`{invalid`))
	assert.Empty(t, cfg)
}

// ---------------------------------------------------------------------------
// aggregateRuleModes
// ---------------------------------------------------------------------------

func TestAggregateRuleModes_EmptyConfig(t *testing.T) {
	assert.Equal(t, "", aggregateRuleModes(nil))
	assert.Equal(t, "", aggregateRuleModes([]byte{}))
}

func TestAggregateRuleModes_InvalidJSON(t *testing.T) {
	assert.Equal(t, "", aggregateRuleModes([]byte(`{bad`)))
}

func TestAggregateRuleModes_NoRules(t *testing.T) {
	assert.Equal(t, "", aggregateRuleModes([]byte(`{}`)))
}

func TestAggregateRuleModes_SingleMode(t *testing.T) {
	cfg := []byte(`{"rules":[{"mode":"whitelist"}]}`)
	assert.Equal(t, "whitelist", aggregateRuleModes(cfg))
}

func TestAggregateRuleModes_MixedModes(t *testing.T) {
	cfg := []byte(`{"rules":[{"mode":"whitelist"},{"mode":"blocklist"}]}`)
	assert.Equal(t, "mixed", aggregateRuleModes(cfg))
}

func TestAggregateRuleModes_EmptyModeSkipped(t *testing.T) {
	cfg := []byte(`{"rules":[{"mode":"whitelist"},{"mode":""}]}`)
	assert.Equal(t, "whitelist", aggregateRuleModes(cfg))
}

func TestAggregateRuleModes_AllEmptyModes(t *testing.T) {
	cfg := []byte(`{"rules":[{"mode":""},{"mode":""}]}`)
	assert.Equal(t, "", aggregateRuleModes(cfg))
}

// ---------------------------------------------------------------------------
// Functional options — PresetHandler
// ---------------------------------------------------------------------------

func TestWithPresetRequireApproval(t *testing.T) {
	h := &PresetHandler{}
	WithPresetRequireApproval(true)(h)
	assert.True(t, h.requireApproval)

	WithPresetRequireApproval(false)(h)
	assert.False(t, h.requireApproval)
}

func TestWithPresetAPIKeyRepo(t *testing.T) {
	h := &PresetHandler{}
	mockRepo := newMockAPIKeyRepo()
	WithPresetAPIKeyRepo(mockRepo)(h)
	assert.Same(t, mockRepo, h.apiKeyRepo)
}

func TestWithPresetJSEvaluator(t *testing.T) {
	h := &PresetHandler{}
	WithPresetJSEvaluator(nil)(h)
	assert.Nil(t, h.jsEvaluator)
}

// ---------------------------------------------------------------------------
// SetAuditLogger — PresetHandler
// ---------------------------------------------------------------------------

func TestPresetHandler_SetAuditLogger(t *testing.T) {
	h := &PresetHandler{}
	h.SetAuditLogger(nil)
	assert.Nil(t, h.auditLogger)
}

// ---------------------------------------------------------------------------
// Functional options — TemplateHandler
// ---------------------------------------------------------------------------

func TestWithTemplateRequireApproval(t *testing.T) {
	h := &TemplateHandler{}
	WithTemplateRequireApproval(true)(h)
	assert.True(t, h.requireApproval)

	WithTemplateRequireApproval(false)(h)
	assert.False(t, h.requireApproval)
}

func TestWithTemplateAPIKeyRepo(t *testing.T) {
	h := &TemplateHandler{}
	mockRepo := newMockAPIKeyRepo()
	WithTemplateAPIKeyRepo(mockRepo)(h)
	assert.Same(t, mockRepo, h.apiKeyRepo)
}

func TestWithTemplateJSEvaluator(t *testing.T) {
	h := &TemplateHandler{}
	WithTemplateJSEvaluator(nil)(h)
	assert.Nil(t, h.jsEvaluator)
}

// ---------------------------------------------------------------------------
// NewPresetHandler — nil validation
// ---------------------------------------------------------------------------

func TestNewPresetHandler_NilPresetRepo(t *testing.T) {
	_, err := NewPresetHandler(nil, nil, nil, nil, false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "preset repository")
}

func TestNewPresetHandler_NilTemplateRepo(t *testing.T) {
	_, err := NewPresetHandler(newMockPresetRepo(), nil, nil, nil, false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "template repository")
}

func TestNewPresetHandler_NilLogger(t *testing.T) {
	_, err := NewPresetHandler(newMockPresetRepo(), &mockTemplateRepo{}, nil, nil, false, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "logger")
}

// ---------------------------------------------------------------------------
// toRefreshReport — with errors
// ---------------------------------------------------------------------------

func TestToRefreshReport_WithErrors(t *testing.T) {
	r := registry.SyncReport{
		Source:  "file",
		Changed: 1,
		Skipped: 2,
		Deleted: 0,
		Errors: []registry.SyncError{
			{ID: "evm/bad", Path: "/presets/evm/bad.yaml", Err: assert.AnError},
			{ID: "evm/missing", Path: "", Err: nil},
		},
	}
	report := toRefreshReport(r)
	assert.Equal(t, "file", report.Source)
	assert.Equal(t, 1, report.Changed)
	assert.Equal(t, 2, report.Skipped)
	require.Len(t, report.Errors, 2)
	assert.Equal(t, "evm/bad", report.Errors[0].ID)
	assert.Equal(t, "/presets/evm/bad.yaml", report.Errors[0].Path)
	assert.Contains(t, report.Errors[0].Error, assert.AnError.Error())
	assert.Equal(t, "evm/missing", report.Errors[1].ID)
	assert.Empty(t, report.Errors[1].Error, "nil Err yields empty string")
}

func TestToRefreshReport_NoErrors(t *testing.T) {
	r := registry.SyncReport{Source: "file", Changed: 1}
	report := toRefreshReport(r)
	assert.Empty(t, report.Errors)
}

// ---------------------------------------------------------------------------
// writeRegistryError
// ---------------------------------------------------------------------------

func TestWriteRegistryError(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := httptest.NewRecorder()
	writeRegistryError(w, log, "test error", http.StatusBadRequest)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "test error")
}

func TestWriteRegistryError_NilLoggerDoesNotPanic(t *testing.T) {
	w := httptest.NewRecorder()
	writeRegistryError(w, nil, "no logger", http.StatusInternalServerError)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// NewRegistryRefreshHandler — nil validation
// ---------------------------------------------------------------------------

func TestNewRegistryRefreshHandler_NilRegistries(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := NewRegistryRefreshHandler(nil, nil, log)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "registries are required")
}

func TestNewRegistryRefreshHandler_NilLogger(t *testing.T) {
	_, err := NewRegistryRefreshHandler(&registry.TemplateRegistry{}, &registry.PresetRegistry{}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "logger")
}

// ---------------------------------------------------------------------------
// APIKeyHandler setters
// ---------------------------------------------------------------------------

func TestAPIKeyHandler_SetAuditLogger(t *testing.T) {
	h := &APIKeyHandler{}
	h.SetAuditLogger(&audit.AuditLogger{})
	assert.NotNil(t, h.auditLogger)
}

func TestAPIKeyHandler_SetAccessService(t *testing.T) {
	h := &APIKeyHandler{}
	h.SetAccessService(nil)
	assert.Nil(t, h.accessService)
}

// ---------------------------------------------------------------------------
// AuditHandler.ServeRequestHTTP
// ---------------------------------------------------------------------------

func TestAuditHandler_ServeRequestHTTP_Unauthorized(t *testing.T) {
	h := &AuditHandler{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/audit/requests/some-req", nil)
	h.ServeRequestHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuditHandler_ServeRequestHTTP_MethodNotAllowed(t *testing.T) {
	h := &AuditHandler{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/audit/requests/some-req", nil)
	r = r.WithContext(context.WithValue(r.Context(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "admin", Role: types.RoleAdmin}))
	h.ServeRequestHTTP(w, r)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestAuditHandler_ServeRequestHTTP_EmptyPath(t *testing.T) {
	mockRepo := newMockAuditRepo()
	handler, err := NewAuditHandler(mockRepo, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/audit/requests/", nil)
	r = r.WithContext(context.WithValue(r.Context(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "admin", Role: types.RoleAdmin}))
	handler.ServeRequestHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuditHandler_ServeRequestHTTP_RepoError(t *testing.T) {
	mockRepo := newMockAuditRepo()
	mockRepo.getByRequestIDErr = fmt.Errorf("db error")
	handler, err := NewAuditHandler(mockRepo, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/audit/requests/some-req", nil)
	r = r.WithContext(context.WithValue(r.Context(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "admin", Role: types.RoleAdmin}))
	handler.ServeRequestHTTP(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAuditHandler_ServeRequestHTTP_Success(t *testing.T) {
	mockRepo := newMockAuditRepo()
	now := time.Now()
	reqID := types.SignRequestID("req-123")
	rec := &types.AuditRecord{
		ID:            types.AuditID("audit-1"),
		EventType:     types.AuditEventTypeSignRequest,
		Severity:      types.AuditSeverityInfo,
		Timestamp:     now,
		APIKeyID:      "key-1",
		ActorAddress:  "10.0.0.1",
		SignRequestID: &reqID,
		RequestMethod: "GET",
		RequestPath:   "/api/v1/audit/requests/req-123",
	}
	rec2 := &types.AuditRecord{
		ID:            types.AuditID("audit-2"),
		EventType:     types.AuditEventTypeAuthSuccess,
		Severity:      types.AuditSeverityInfo,
		Timestamp:     now.Add(time.Minute),
		APIKeyID:      "key-1",
		ActorAddress:  "10.0.0.1",
		SignRequestID: &reqID,
		RequestMethod: "POST",
		RequestPath:   "/api/v1/auth",
	}
	mockRepo.records = append(mockRepo.records, rec, rec2)

	handler, err := NewAuditHandler(mockRepo, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/audit/requests/req-123", nil)
	r = r.WithContext(context.WithValue(r.Context(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "admin", Role: types.RoleAdmin}))
	handler.ServeRequestHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp ListAuditResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, 2, len(resp.Records))
	assert.Equal(t, 2, resp.Total)
}

// ---------------------------------------------------------------------------
// Mini mock for preset repo (minimal — implements PresetRepository)
// ---------------------------------------------------------------------------

// mockPresetRepoStub implements storage.PresetRepository minimally. It's a
// lighter stand-in than a full GORM-backed repo for testing constructor
// validation and other call-site paths.
type mockPresetRepoStub struct{}

func newMockPresetRepo() *mockPresetRepoStub { return &mockPresetRepoStub{} }

func (m *mockPresetRepoStub) Create(_ context.Context, _ *types.RulePreset) error    { return nil }
func (m *mockPresetRepoStub) Get(_ context.Context, _ string) (*types.RulePreset, error) {
	return nil, types.ErrNotFound
}
func (m *mockPresetRepoStub) List(_ context.Context, _ storage.PresetFilter) ([]*types.RulePreset, error) {
	return nil, nil
}
func (m *mockPresetRepoStub) Update(_ context.Context, _ *types.RulePreset) error              { return nil }
func (m *mockPresetRepoStub) Delete(_ context.Context, _ string) error                         { return nil }
func (m *mockPresetRepoStub) Count(_ context.Context, _ storage.PresetFilter) (int, error)     { return 0, nil }
func (m *mockPresetRepoStub) Upsert(_ context.Context, _ *types.RulePreset) (bool, error)      { return false, nil }
func (m *mockPresetRepoStub) ListIDsBySource(_ context.Context, _ types.RuleSource) ([]string, error) {
	return nil, nil
}
func (m *mockPresetRepoStub) DeleteMany(_ context.Context, _ []string) error { return nil }
