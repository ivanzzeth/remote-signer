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

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------------------------------------------------------------------------
// Preset handler validate [uses the real presetTestEnv + JS evaluator]
// ---------------------------------------------------------------------------

func newPresetEnvWithJSEval(t *testing.T) (*presetTestEnv, *evm.JSRuleEvaluator) {
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

	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	h, err := NewPresetHandler(
		presetRepo,
		tmplRepo,
		db,
		nil, /* templateSvc — not needed for validate */
		false,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithPresetJSEvaluator(eval),
	)
	require.NoError(t, err)
	return &presetTestEnv{handler: h, db: db, template: tmplRepo, preset: presetRepo}, eval
}

func TestPresetHandler_Validate_Success(t *testing.T) {
	env, _ := newPresetEnvWithJSEval(t)
	seedPresetTemplate(t, env, &types.RuleTemplate{
		ID:          "evm/test-tmpl",
		Name:        "Test Template",
		Type:        types.RuleTypeEVMJS,
		Mode:        types.RuleModeWhitelist,
		ChainType:   types.ChainType("evm"),
		Source:      types.RuleSourceFile,
		ContentHash: "h1",
		Enabled:     true,
		Config: mustJSONP(t, map[string]interface{}{
			"rules": []map[string]interface{}{
				{
					"name": "rule1",
					"type": "sign_type_restriction",
					"mode": "whitelist",
					"config": map[string]interface{}{
						"allowed_sign_types": []string{"transaction"},
					},
				},
			},
		}),
	})
	seedPresetRow(t, env, &types.RulePreset{
		ID:          "evm/test-preset",
		Name:        "Test Preset",
		ChainType:   types.ChainType("evm"),
		TemplateIDs: mustJSONP(t, []string{"evm/test-tmpl"}),
		Source:      types.RuleSourceFile,
		ContentHash: "h2",
		Enabled:     true,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/evm%2Ftest-preset/validate",
		strings.NewReader(`{}`)).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp validatePresetResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "evm/test-preset", resp.PresetID)
	assert.Equal(t, "Test Preset", resp.PresetName)
	assert.Equal(t, 1, resp.Total)
	assert.Equal(t, 1, resp.Passed)
}

func TestPresetHandler_Validate_NoTemplateIDs(t *testing.T) {
	env, _ := newPresetEnvWithJSEval(t)
	seedPresetRow(t, env, &types.RulePreset{
		ID:          "evm/no-tmpls",
		Name:        "No Templates",
		ContentHash: "h",
		Source:      types.RuleSourceFile,
		Enabled:     true,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/evm%2Fno-tmpls/validate",
		strings.NewReader(`{}`)).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "no template_ids")
}

func TestPresetHandler_Validate_PresetNotFound(t *testing.T) {
	env, _ := newPresetEnvWithJSEval(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/nonexistent/validate",
		strings.NewReader(`{}`)).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPresetHandler_Validate_NonAdminForbidden(t *testing.T) {
	env, _ := newPresetEnvWithJSEval(t)

	// Non-admin key
	ctx := contextWithKey(t, types.RoleStrategy, "dev-key")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/foo/validate",
		strings.NewReader(`{}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ---------------------------------------------------------------------------
// decodeAnyMap — coverage boost
// ---------------------------------------------------------------------------

func TestDecodeAnyMap_Nil(t *testing.T) {
	got, err := decodeAnyMap(nil)
	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestDecodeAnyMap_WithData(t *testing.T) {
	got, err := decodeAnyMap([]byte(`{"foo":"bar","num":42}`))
	assert.NoError(t, err)
	assert.Equal(t, "bar", got["foo"])
	assert.Equal(t, float64(42), got["num"])
}

func TestDecodeAnyMap_Invalid(t *testing.T) {
	got, err := decodeAnyMap([]byte(`{invalid`))
	assert.Error(t, err)
	assert.Nil(t, got)
}

// ---------------------------------------------------------------------------
// decodeStringSlice — coverage boost
// ---------------------------------------------------------------------------

func TestDecodeStringSlice_Nil(t *testing.T) {
	got, err := decodeStringSlice(nil)
	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestDecodeStringSlice_WithData(t *testing.T) {
	got, err := decodeStringSlice([]byte(`["a","b"]`))
	assert.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, got)
}

func TestDecodeStringSlice_Invalid(t *testing.T) {
	got, err := decodeStringSlice([]byte(`{bad`))
	assert.Error(t, err)
	assert.Nil(t, got)
}

// ---------------------------------------------------------------------------
// decodeOperatorOverrides — coverage boost
// ---------------------------------------------------------------------------

func TestDecodeOperatorOverrides_Nil(t *testing.T) {
	got, err := decodeOperatorOverrides(nil)
	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestDecodeOperatorOverrides_WithData(t *testing.T) {
	got, err := decodeOperatorOverrides([]byte(`[{"name":"foo","required":true}]`))
	assert.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "foo", got[0].Name)
	assert.True(t, got[0].Required)
}

func TestDecodeOperatorOverrides_Invalid(t *testing.T) {
	got, err := decodeOperatorOverrides([]byte(`{bad`))
	assert.Error(t, err)
	assert.Nil(t, got)
}

// ---------------------------------------------------------------------------
// decodeStringMap — invalid JSON branch
// ---------------------------------------------------------------------------

func TestDecodeStringMap_InvalidJSON(t *testing.T) {
	_, err := decodeStringMap([]byte(`{bad`))
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// runTemplateValidation — direct testing
// ---------------------------------------------------------------------------

func TestRunTemplateValidation_SkipsNonJSRules(t *testing.T) {
	env, _ := newPresetEnvWithJSEval(t)
	seedPresetTemplate(t, env, &types.RuleTemplate{
		ID:          "evm/tmpl",
		Name:        "Test",
		Type:        types.RuleTypeSignTypeRestriction,
		Mode:        types.RuleModeWhitelist,
		ChainType:   types.ChainType("evm"),
		Source:      types.RuleSourceFile,
		ContentHash: "h",
		Enabled:     true,
		Config: mustJSONP(t, map[string]interface{}{
			"rules": []map[string]interface{}{
				{
					"name": "r1",
					"type": "sign_type_restriction",
					"mode": "whitelist",
					"config": map[string]interface{}{
						"allowed_sign_types": []string{"transaction"},
					},
				},
			},
		}),
	})

	results := env.handler.runTemplateValidation(
		&types.RuleTemplate{Name: "Test", Type: types.RuleTypeSignTypeRestriction, Mode: types.RuleModeWhitelist},
		[]byte(`{"rules":[{"name":"r1","type":"sign_type_restriction","mode":"whitelist","config":{"allowed_sign_types":["transaction"]}}]}`),
		nil,
	)
	require.Len(t, results, 1)
	assert.True(t, results[0].Valid)
}

func TestRunTemplateValidation_NonBundleConfig(t *testing.T) {
	env, _ := newPresetEnvWithJSEval(t)
	resolvedConfig := []byte(`{"script":"function validate(input){return{valid:true}}","test_cases":[]}`)
	results := env.handler.runTemplateValidation(
		&types.RuleTemplate{Name: "Test", Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist},
		resolvedConfig,
		nil,
	)
	require.Len(t, results, 1)
	assert.True(t, results[0].Valid)
	assert.Contains(t, results[0].Error, "no rules array")
}

// ---------------------------------------------------------------------------
// Preset apply — early-exit branches (read-only, missing svc, disabled)
// ---------------------------------------------------------------------------

func TestPresetHandler_Apply_ReadOnly(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}))

	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)

	handler, err := NewPresetHandler(
		presetRepo,
		tmplRepo,
		db,
		nil, /* templateSvc */
		true,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	require.NoError(t, err)

	ctx := contextWithKey(t, types.RoleAdmin, "admin-key")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/foo/apply",
		strings.NewReader(`{}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "readonly")
}

func TestPresetHandler_Apply_NoTemplateSvc(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}))

	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)

	handler, err := NewPresetHandler(
		presetRepo,
		tmplRepo,
		db,
		nil, /* templateSvc */
		false,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	require.NoError(t, err)

	ctx := contextWithKey(t, types.RoleAdmin, "admin-key")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/foo/apply",
		strings.NewReader(`{}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "template service")
}

func TestPresetHandler_Apply_DisabledPreset(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}))

	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)

	err = presetRepo.Create(context.Background(), &types.RulePreset{
		ID:      "evm/disabled",
		Name:    "Disabled",
		Enabled: false,
		Source:  types.RuleSourceFile, ContentHash: "h",
	})
	require.NoError(t, err)

	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)

	handler, err := NewPresetHandler(
		presetRepo,
		tmplRepo,
		db,
		&service.TemplateService{},
		false,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	require.NoError(t, err)

	ctx := contextWithKey(t, types.RoleAdmin, "admin-key")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/evm%2Fdisabled/apply",
		strings.NewReader(`{}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "disabled")
}

func TestPresetHandler_Apply_NoTemplateIDs(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}))

	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)

	err = presetRepo.Create(context.Background(), &types.RulePreset{
		ID:      "evm/no-ids",
		Name:    "No IDs",
		Enabled: true,
		Source:  types.RuleSourceFile, ContentHash: "h",
	})
	require.NoError(t, err)

	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)

	handler, err := NewPresetHandler(
		presetRepo,
		tmplRepo,
		db,
		&service.TemplateService{},
		false,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	require.NoError(t, err)

	ctx := contextWithKey(t, types.RoleAdmin, "admin-key")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/evm%2Fno-ids/apply",
		strings.NewReader(`{}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "no template_ids")
}

func TestPresetHandler_Apply_BadRequestBody(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}))

	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)

	// Create the preset so the handler can fetch it
	err = presetRepo.Create(context.Background(), &types.RulePreset{
		ID:          "evm/apply-me",
		Name:        "Apply Me",
		Enabled:     true,
		TemplateIDs: mustJSONP(t, []string{"evm/tmpl"}),
		Source:      types.RuleSourceFile, ContentHash: "h",
	})
	require.NoError(t, err)

	handler, err := NewPresetHandler(
		presetRepo,
		tmplRepo,
		db,
		&service.TemplateService{}, // non-nil, so templateSvc check passes
		false,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	require.NoError(t, err)

	// Admin key with bad JSON body
	ctx := contextWithKey(t, types.RoleAdmin, "admin-key")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/evm%2Fapply-me/apply",
		strings.NewReader(`{bad json}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid request body")
}
