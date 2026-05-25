//go:build integration

package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// presetTestEnv wires up the minimum the PresetHandler needs to
// answer requests: in-memory SQLite, real preset + template repos,
// a couple of seeded rows. The TemplateService is left nil — the
// list and detail paths don't touch it, and apply tests build their
// own env when they need it (apply requires a real signer + budget
// repo chain that's heavier than these tests want to set up).
type presetTestEnv struct {
	handler  *PresetHandler
	db       *gorm.DB
	template storage.TemplateRepository
	preset   storage.PresetRepository
}

func newPresetTestEnv(t *testing.T) *presetTestEnv {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}))

	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)

	h, err := NewPresetHandler(
		presetRepo,
		tmplRepo,
		db,
		nil, /* templateSvc — not exercised by these tests */
		false,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	require.NoError(t, err)
	return &presetTestEnv{handler: h, db: db, template: tmplRepo, preset: presetRepo}
}

// seedPresetTemplate puts a template directly into the preset test's
// repo. Named separately from template_test.go's seedTemplate so the
// two test files coexist in the same package.
func seedPresetTemplate(t *testing.T, env *presetTestEnv, tmpl *types.RuleTemplate) {
	t.Helper()
	require.NoError(t, env.template.Create(context.Background(), tmpl))
}

func seedPresetRow(t *testing.T, env *presetTestEnv, p *types.RulePreset) {
	t.Helper()
	require.NoError(t, env.preset.Create(context.Background(), p))
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

func TestPresetHandler_List_ReturnsTemplateIDs(t *testing.T) {
	env := newPresetTestEnv(t)
	seedPresetRow(t, env, &types.RulePreset{
		ID:          "evm/erc20",
		Name:        "ERC20",
		Description: "Token transfer limits",
		ChainType:   types.ChainType("evm"),
		ChainID:     "1",
		TemplateIDs: mustJSONP(t, []string{"evm/erc20"}),
		Source:      types.RuleSourceFile,
		ContentHash: "h",
		Enabled:     true,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/presets", nil).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Presets []PresetListItem `json:"presets"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Presets, 1)
	got := resp.Presets[0]
	assert.Equal(t, "evm/erc20", got.ID)
	assert.Equal(t, "ERC20", got.Name)
	assert.Equal(t, "Token transfer limits", got.Description)
	assert.Equal(t, "evm", got.ChainType)
	assert.Equal(t, []string{"evm/erc20"}, got.TemplateIDs,
		"template_ids must surface as a list; this is what the UI columns key off")
}

// ---------------------------------------------------------------------------
// Detail — slash IDs round-trip via EscapedPath
// ---------------------------------------------------------------------------

func TestPresetHandler_Detail_SlashIDRoundTrips(t *testing.T) {
	// Reproduces the URL-encoding fix: file-stem IDs containing '/' come
	// in as "evm%2Ferc20" and must resolve back to "evm/erc20" in the DB
	// lookup. Before the fix this returned 404 (handler split the path
	// on '/' inside the ID and dispatched on a phantom sub-action).
	env := newPresetTestEnv(t)
	seedPresetTemplate(t, env, &types.RuleTemplate{
		ID:          "evm/erc20",
		Name:        "ERC20",
		ChainType:   types.ChainType("evm"),
		Source:      types.RuleSourceFile,
		ContentHash: "h",
		Enabled:     true,
		Variables: mustJSONP(t, []types.TemplateVariable{{
			Name: "recipient", Type: types.VarTypeAddress, Required: true,
			Description: "Allowed recipient",
		}}),
	})
	seedPresetRow(t, env, &types.RulePreset{
		ID:          "evm/erc20",
		Name:        "ERC20 preset",
		ChainType:   types.ChainType("evm"),
		TemplateIDs: mustJSONP(t, []string{"evm/erc20"}),
		OperatorOverrides: mustJSONP(t, []types.OperatorOverride{
			{Name: "recipient", Required: true},
		}),
		Source:      types.RuleSourceFile,
		ContentHash: "h",
		Enabled:     true,
	})

	// Encoded URL — what the JS SDK actually sends.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/presets/evm%2Ferc20", nil).
		WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	var resp PresetDetailResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "evm/erc20", resp.ID)
	require.Len(t, resp.Variables, 1, "operator_overrides drives surfaced vars")
	v := resp.Variables[0]
	assert.Equal(t, "recipient", v.Name)
	assert.Equal(t, "address", v.Type, "type joined from template definition")
	assert.Equal(t, "Allowed recipient", v.Description)
	assert.True(t, v.Required, "operator_override.required=true forces this regardless of template")
}

func TestPresetHandler_Detail_RequiredFlagComesFromOverride(t *testing.T) {
	// Template variable is optional, preset override says required:true →
	// detail surfaces Required=true. The preset author's choice wins.
	env := newPresetTestEnv(t)
	seedPresetTemplate(t, env, &types.RuleTemplate{
		ID: "evm/x", Name: "X", ContentHash: "h", Source: types.RuleSourceFile,
		Variables: mustJSONP(t, []types.TemplateVariable{
			{Name: "a", Type: types.VarTypeString, Required: false},
		}),
	})
	seedPresetRow(t, env, &types.RulePreset{
		ID: "evm/x", Name: "X preset", ContentHash: "h", Source: types.RuleSourceFile,
		TemplateIDs: mustJSONP(t, []string{"evm/x"}),
		OperatorOverrides: mustJSONP(t, []types.OperatorOverride{
			{Name: "a", Required: true},
		}),
		Enabled: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/presets/evm%2Fx", nil).
		WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp PresetDetailResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Variables, 1)
	assert.True(t, resp.Variables[0].Required, "override.required=true beats template.required=false")
}

func TestPresetHandler_Detail_NotFound(t *testing.T) {
	env := newPresetTestEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/presets/nope", nil).
		WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---------------------------------------------------------------------------
// Routing — method dispatch
// ---------------------------------------------------------------------------

func TestPresetHandler_Routing_RejectsWrongMethod(t *testing.T) {
	env := newPresetTestEnv(t)
	// POST /api/v1/presets (the list endpoint accepts only GET)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets", nil).
		WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestPresetHandler_Apply_ForbiddenWithoutPermission(t *testing.T) {
	env := newPresetTestEnv(t)
	// Strategy keys don't have apply_preset.
	ctx := context.WithValue(context.Background(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "k", Role: types.RoleStrategy})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/foo/apply",
		strings.NewReader(`{}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestPresetHandler_Apply_RequiresAuth(t *testing.T) {
	env := newPresetTestEnv(t)
	// No API key in context — middleware would normally reject earlier,
	// but the handler must guard too in case the route is wired wrong.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/foo/apply",
		strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code,
		"missing api key falls through the permission check, which returns 403")
}

// ---------------------------------------------------------------------------
// Helpers — surface a few small ones via direct testing so a future
// refactor doesn't silently regress the JSON column decode rules.
// ---------------------------------------------------------------------------

func TestDecodeStringMap_CoercesNonStringValues(t *testing.T) {
	// Preset variables column stores map[string]any (numbers / bools /
	// arrays survive YAML→JSON). The API needs strings, so non-strings
	// get JSON-stringified to keep the natural shape readable.
	in := []byte(`{"a":"hi","b":42,"c":true,"d":["x","y"]}`)
	got, err := decodeStringMap(in)
	require.NoError(t, err)
	assert.Equal(t, "hi", got["a"])
	assert.Equal(t, "42", got["b"])
	assert.Equal(t, "true", got["c"])
	assert.Equal(t, `["x","y"]`, got["d"])
}

func TestDecodeStringMap_NilInput(t *testing.T) {
	got, err := decodeStringMap(nil)
	require.NoError(t, err)
	assert.Empty(t, got, "nil input yields empty (not nil) map")
}

func TestMergeForSubstitution_InjectsChainScope(t *testing.T) {
	preset := &types.RulePreset{
		ChainType: types.ChainType("evm"),
		ChainID:   "137",
	}
	got := mergeForSubstitution(map[string]string{"foo": "bar"}, preset)
	assert.Equal(t, "137", got["chain_id"], "preset.chain_id surfaces as substitution var")
	assert.Equal(t, "evm", got["chain_type"])
	assert.Equal(t, "bar", got["foo"], "operator-merged vars survive")
}

func TestMergeForSubstitution_OperatorOverridesChainScope(t *testing.T) {
	// If the operator passed chain_id=42 explicitly, that wins over the
	// preset's pinned chain_id. Matches legacy ParsePresetFile behaviour.
	preset := &types.RulePreset{ChainID: "1"}
	got := mergeForSubstitution(map[string]string{"chain_id": "42"}, preset)
	assert.Equal(t, "42", got["chain_id"])
}
