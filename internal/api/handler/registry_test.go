package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/registry"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// refreshTestEnv assembles a fully-wired RegistryRefreshHandler over
// a tmpdir-backed FileSource + in-memory DB. Each test populates the
// tmpdir with whatever YAML it wants exposed; the handler then refreshes
// against it.
type refreshTestEnv struct {
	handler *RegistryRefreshHandler
	tmplDir string
	preDir  string
	tmpls   storage.TemplateRepository
	presets storage.PresetRepository
}

func newRefreshTestEnv(t *testing.T) *refreshTestEnv {
	t.Helper()
	dir := t.TempDir()
	tmplDir := filepath.Join(dir, "templates")
	preDir := filepath.Join(dir, "presets")
	require.NoError(t, os.MkdirAll(tmplDir, 0o755))
	require.NoError(t, os.MkdirAll(preDir, 0o755))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RuleTemplate{}, &types.RulePreset{}))

	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tmplReg := registry.NewTemplateRegistry(tmplRepo, registry.NewFileTemplateSource(tmplDir), log)
	presetReg := registry.NewPresetRegistry(presetRepo, registry.NewFilePresetSource(preDir), log)

	h, err := NewRegistryRefreshHandler(tmplReg, presetReg, log)
	require.NoError(t, err)
	return &refreshTestEnv{
		handler: h,
		tmplDir: tmplDir,
		preDir:  preDir,
		tmpls:   tmplRepo,
		presets: presetRepo,
	}
}

func writeYAML(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
}

func adminPostRefresh(t *testing.T) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/registry/refresh", nil)
	return r.WithContext(context.WithValue(r.Context(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "admin", Role: types.RoleAdmin}))
}

// ---------------------------------------------------------------------------
// First-pass refresh — empty DB picks up new files
// ---------------------------------------------------------------------------

func TestRegistryRefresh_FirstPassChangesEverything(t *testing.T) {
	env := newRefreshTestEnv(t)
	writeYAML(t, env.tmplDir, "evm/erc20.yaml", `
name: ERC20
variables:
  - name: token, type: address, required: true
rules:
  - id: erc20-transfer
    name: ERC20 transfer
    type: evm_address_list
    mode: whitelist
`)
	// Note: the body above has a YAML mapping issue (inline {} would be
	// cleaner) — rewrite as a structured doc the parser actually accepts.
	writeYAML(t, env.tmplDir, "evm/erc20.yaml", `
name: ERC20
variables:
  - {name: token, type: address, required: true}
rules:
  - id: erc20-transfer
    name: ERC20 transfer
    type: evm_address_list
    mode: whitelist
`)
	writeYAML(t, env.preDir, "evm/erc20.yaml", `
name: ERC20 preset
chain_type: evm
chain_id: "1"
template_ids: [evm/erc20]
`)

	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, adminPostRefresh(t))

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	var resp RefreshResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Templates.Changed, "fresh template upserted")
	assert.Equal(t, 0, resp.Templates.Skipped)
	assert.Equal(t, 1, resp.Presets.Changed, "fresh preset upserted")
	assert.Equal(t, 0, resp.Presets.Skipped)
	assert.Empty(t, resp.Templates.Errors)
	assert.Empty(t, resp.Presets.Errors)
}

// ---------------------------------------------------------------------------
// Second-pass refresh — content_hash short-circuits writes
// ---------------------------------------------------------------------------

func TestRegistryRefresh_SecondPassSkipsUnchanged(t *testing.T) {
	env := newRefreshTestEnv(t)
	writeYAML(t, env.tmplDir, "evm/x.yaml", `
name: X
variables: []
rules: [{id: r, name: r, type: evm_address_list, mode: whitelist}]
`)
	// First pass: write.
	env.handler.ServeHTTP(httptest.NewRecorder(), adminPostRefresh(t))

	// Second pass: nothing changed on disk → all skipped.
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, adminPostRefresh(t))

	require.Equal(t, http.StatusOK, w.Code)
	var resp RefreshResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 0, resp.Templates.Changed, "ContentHash matches → no write")
	assert.Equal(t, 1, resp.Templates.Skipped)
}

// ---------------------------------------------------------------------------
// Refresh prunes — file removed → row deleted
// ---------------------------------------------------------------------------

func TestRegistryRefresh_PrunesDeletedFiles(t *testing.T) {
	env := newRefreshTestEnv(t)
	writeYAML(t, env.tmplDir, "evm/a.yaml", `
name: A
variables: []
rules: [{id: r, name: r, type: evm_address_list, mode: whitelist}]
`)
	writeYAML(t, env.tmplDir, "evm/b.yaml", `
name: B
variables: []
rules: [{id: r, name: r, type: evm_address_list, mode: whitelist}]
`)
	env.handler.ServeHTTP(httptest.NewRecorder(), adminPostRefresh(t))

	// Drop b.yaml → next refresh prunes the DB row.
	require.NoError(t, os.Remove(filepath.Join(env.tmplDir, "evm/b.yaml")))
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, adminPostRefresh(t))

	require.Equal(t, http.StatusOK, w.Code)
	var resp RefreshResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Templates.Deleted)
	assert.Equal(t, 1, resp.Templates.Skipped, "a.yaml content unchanged")

	_, err := env.tmpls.Get(context.Background(), "evm/b")
	assert.Error(t, err, "pruned row no longer queryable")
}

// ---------------------------------------------------------------------------
// Permission gate
// ---------------------------------------------------------------------------

func TestRegistryRefresh_ForbiddenWithoutPermission(t *testing.T) {
	env := newRefreshTestEnv(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/registry/refresh", nil)
	r = r.WithContext(context.WithValue(r.Context(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "k", Role: types.RoleStrategy}))
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code,
		"strategy role lacks apply_preset → refresh denied")
}

func TestRegistryRefresh_RejectsNonPOST(t *testing.T) {
	env := newRefreshTestEnv(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/registry/refresh", nil)
	r = r.WithContext(context.WithValue(r.Context(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "admin", Role: types.RoleAdmin}))
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// ---------------------------------------------------------------------------
// Per-file errors surface as RefreshError entries
// ---------------------------------------------------------------------------

func TestRegistryRefresh_PerFileErrorsSurface(t *testing.T) {
	env := newRefreshTestEnv(t)
	// Two templates, one valid + one with a duplicate variable name —
	// the broken file fails sync-time validation. Registry returns no
	// top-level error; the broken file lands in report.Errors.
	writeYAML(t, env.tmplDir, "evm/good.yaml", `
name: Good
variables: []
rules: [{id: r, name: r, type: evm_address_list, mode: whitelist}]
`)
	writeYAML(t, env.tmplDir, "evm/bad.yaml", `
name: Bad
variables:
  - {name: x, type: address}
  - {name: x, type: bigint}
rules: []
`)

	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, adminPostRefresh(t))

	// FileTemplateSource.List currently aborts on first parse error
	// (returning a fatal err to the Registry), so the whole template
	// sync fails with 500 — that's the conservative path. If we
	// switch to "skip bad, surface in Errors" in the future this test
	// is the one to flip. Document current behaviour:
	if w.Code == http.StatusInternalServerError {
		assert.Contains(t, w.Body.String(), "bad.yaml")
		return
	}
	// Soft-error path (if/when implemented):
	var resp RefreshResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Templates.Errors, "bad.yaml should produce an error entry")
}
