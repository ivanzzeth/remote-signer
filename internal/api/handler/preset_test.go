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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------------------------------------------------------------------------
// resolveInstances tests
// ---------------------------------------------------------------------------

func newResolveEnv(t *testing.T) (*presetApplyTestEnv, context.Context) {
	t.Helper()
	env := newPresetApplyTestEnv(t)
	ctx := context.WithValue(context.Background(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "admin-key", Role: types.RoleAdmin})
	return env, ctx
}

func seedResolveTemplate(t *testing.T, env *presetApplyTestEnv, id, name string) {
	t.Helper()
	tmpl := &types.RuleTemplate{
		ID:          id,
		Name:        name,
		Type:        types.RuleTypeEVMJS,
		Mode:        types.RuleModeWhitelist,
		ChainType:   types.ChainType("evm"),
		Source:      types.RuleSourceFile,
		ContentHash: "h",
		Enabled:     true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, env.tmplRepo.Create(context.Background(), tmpl))
}

func TestResolveInstances_SingleTemplate(t *testing.T) {
	env, ctx := newResolveEnv(t)
	seedResolveTemplate(t, env, "evm/t1", "Template 1")

	preset := &types.RulePreset{
		ID:        "evm/test-preset",
		Name:      "Test Preset",
		ChainType: types.ChainType("evm"),
		ChainID:   "137",
	}
	apiKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}

	resolved, err := env.handler.resolveInstances(ctx, apiKey, nil, preset,
		[]string{"evm/t1"}, map[string]string{"v1": "val1"}, nil, nil)
	require.NoError(t, err)
	require.Len(t, resolved, 1)
	assert.Equal(t, "evm/t1", resolved[0].req.TemplateID)
	assert.Equal(t, "val1", resolved[0].req.Variables["v1"])
	assert.Equal(t, "137", *resolved[0].req.ChainID)
	assert.Equal(t, "evm", *resolved[0].req.ChainType)
	assert.Equal(t, "admin-key", resolved[0].req.Owner)
	assert.Equal(t, types.RuleStatusActive, resolved[0].req.Status)
}

func TestResolveInstances_MultipleTemplates(t *testing.T) {
	env, ctx := newResolveEnv(t)
	seedResolveTemplate(t, env, "evm/t1", "T1")
	seedResolveTemplate(t, env, "evm/t2", "T2")

	preset := &types.RulePreset{ID: "evm/p", Name: "P"}
	apiKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}

	resolved, err := env.handler.resolveInstances(ctx, apiKey, nil, preset,
		[]string{"evm/t1", "evm/t2"}, map[string]string{}, nil, nil)
	require.NoError(t, err)
	require.Len(t, resolved, 2)
	assert.Equal(t, "evm/t1", resolved[0].req.TemplateID)
	assert.Equal(t, "evm/t2", resolved[1].req.TemplateID)
	// Variables should be independent clones
	resolved[0].req.Variables["extra"] = "only-t1"
	assert.NotContains(t, resolved[1].req.Variables, "extra")
}

func TestResolveInstances_TemplateNotFound(t *testing.T) {
	env, ctx := newResolveEnv(t)
	preset := &types.RulePreset{ID: "evm/p", Name: "P"}
	apiKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}

	_, err := env.handler.resolveInstances(ctx, apiKey, nil, preset,
		[]string{"evm/nonexistent"}, map[string]string{}, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "template")
	assert.Contains(t, err.Error(), "evm/nonexistent")
}

func TestResolveInstances_WithBudget(t *testing.T) {
	env, ctx := newResolveEnv(t)
	seedResolveTemplate(t, env, "evm/t1", "T1")

	preset := &types.RulePreset{ID: "evm/p", Name: "P"}
	apiKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}
	budget := map[string]any{
		"max_total":   "1000000",
		"max_per_tx":  "100000",
		"max_tx_count": 10.0,
		"alert_pct":   80.0,
	}

	resolved, err := env.handler.resolveInstances(ctx, apiKey, nil, preset,
		[]string{"evm/t1"}, map[string]string{}, budget, nil)
	require.NoError(t, err)
	require.Len(t, resolved, 1)
	require.NotNil(t, resolved[0].req.Budget)
	assert.Equal(t, "1000000", resolved[0].req.Budget.MaxTotal)
	assert.Equal(t, "100000", resolved[0].req.Budget.MaxPerTx)
	assert.Equal(t, 10, resolved[0].req.Budget.MaxTxCount)
	assert.Equal(t, 80, resolved[0].req.Budget.AlertPct)
}

func TestResolveInstances_WithSchedule(t *testing.T) {
	env, ctx := newResolveEnv(t)
	seedResolveTemplate(t, env, "evm/t1", "T1")

	preset := &types.RulePreset{ID: "evm/p", Name: "P"}
	apiKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}
	schedule := map[string]any{"period": "24h"}

	resolved, err := env.handler.resolveInstances(ctx, apiKey, nil, preset,
		[]string{"evm/t1"}, map[string]string{}, nil, schedule)
	require.NoError(t, err)
	require.Len(t, resolved, 1)
	require.NotNil(t, resolved[0].req.Schedule)
	assert.Equal(t, 24*time.Hour, resolved[0].req.Schedule.Period)
}

func TestResolveInstances_InvalidSchedulePeriod(t *testing.T) {
	env, ctx := newResolveEnv(t)
	seedResolveTemplate(t, env, "evm/t1", "T1")

	preset := &types.RulePreset{ID: "evm/p", Name: "P"}
	apiKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}
	schedule := map[string]any{"period": "not-a-duration"}

	_, err := env.handler.resolveInstances(ctx, apiKey, nil, preset,
		[]string{"evm/t1"}, map[string]string{}, nil, schedule)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid schedule period")
}

func TestResolveInstances_NonAdminSelfAppliedTo(t *testing.T) {
	env, ctx := newResolveEnv(t)
	seedResolveTemplate(t, env, "evm/t1", "T1")

	preset := &types.RulePreset{ID: "evm/p", Name: "P"}
	apiKey := &types.APIKey{ID: "agent-key", Role: types.RoleAgent}

	resolved, err := env.handler.resolveInstances(ctx, apiKey, nil, preset,
		[]string{"evm/t1"}, map[string]string{}, nil, nil)
	require.NoError(t, err)
	require.Len(t, resolved, 1)
	assert.Equal(t, "agent-key", resolved[0].req.Owner)
	assert.Equal(t, []string{"self"}, []string(resolved[0].req.AppliedTo))
}

func TestResolveInstances_AgentWhitelistRequiresApproval(t *testing.T) {
	env, ctx := newResolveEnv(t)
	seedResolveTemplate(t, env, "evm/t1", "T1")
	// Make the template whitelist mode
	tmpl, err := env.tmplRepo.Get(context.Background(), "evm/t1")
	require.NoError(t, err)
	tmpl.Mode = types.RuleModeWhitelist
	require.NoError(t, env.tmplRepo.Update(context.Background(), tmpl))

	env.handler.requireApproval = true
	preset := &types.RulePreset{ID: "evm/p", Name: "P"}
	apiKey := &types.APIKey{ID: "agent-key", Role: types.RoleAgent}

	resolved, err := env.handler.resolveInstances(ctx, apiKey, nil, preset,
		[]string{"evm/t1"}, map[string]string{}, nil, nil)
	require.NoError(t, err)
	require.Len(t, resolved, 1)
	assert.Equal(t, types.RuleStatusPendingApproval, resolved[0].req.Status)
}

func TestResolveInstances_EmptyBudgetSchedule(t *testing.T) {
	env, ctx := newResolveEnv(t)
	seedResolveTemplate(t, env, "evm/t1", "T1")

	preset := &types.RulePreset{ID: "evm/p", Name: "P"}
	apiKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}

	resolved, err := env.handler.resolveInstances(ctx, apiKey, nil, preset,
		[]string{"evm/t1"}, map[string]string{}, map[string]any{}, map[string]any{})
	require.NoError(t, err)
	require.Len(t, resolved, 1)
	assert.Nil(t, resolved[0].req.Budget)
	assert.Nil(t, resolved[0].req.Schedule)
}

func TestResolveInstances_AdminWithAppliedTo(t *testing.T) {
	env, ctx := newResolveEnv(t)
	seedResolveTemplate(t, env, "evm/t1", "T1")

	preset := &types.RulePreset{ID: "evm/p", Name: "P"}
	apiKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}

	resolved, err := env.handler.resolveInstances(ctx, apiKey, []string{"key-a", "key-b"}, preset,
		[]string{"evm/t1"}, map[string]string{}, nil, nil)
	require.NoError(t, err)
	require.Len(t, resolved, 1)
	assert.Equal(t, []string{"key-a", "key-b"}, []string(resolved[0].req.AppliedTo))
}

func TestResolveInstances_AdminAppliedToWildcard(t *testing.T) {
	env, ctx := newResolveEnv(t)
	seedResolveTemplate(t, env, "evm/t1", "T1")

	preset := &types.RulePreset{ID: "evm/p", Name: "P"}
	apiKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}

	resolved, err := env.handler.resolveInstances(ctx, apiKey, nil, preset,
		[]string{"evm/t1"}, map[string]string{}, nil, nil)
	require.NoError(t, err)
	require.Len(t, resolved, 1)
	assert.Equal(t, []string{"*"}, []string(resolved[0].req.AppliedTo))
}

func TestResolveInstances_NilPresetChainScope(t *testing.T) {
	env, ctx := newResolveEnv(t)
	seedResolveTemplate(t, env, "evm/t1", "T1")

	preset := &types.RulePreset{ID: "evm/p", Name: "P"} // no ChainType/ChainID
	apiKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}

	resolved, err := env.handler.resolveInstances(ctx, apiKey, nil, preset,
		[]string{"evm/t1"}, map[string]string{}, nil, nil)
	require.NoError(t, err)
	require.Len(t, resolved, 1)
	assert.Nil(t, resolved[0].req.ChainType)
	assert.Nil(t, resolved[0].req.ChainID)
}

func TestResolveInstances_RBACErrorOnInvalidAppliedTo(t *testing.T) {
	env, ctx := newResolveEnv(t)
	seedResolveTemplate(t, env, "evm/t1", "T1")

	// Wire apiKeyRepo so that applied_to validation runs
	mockKeyRepo := newMockAPIKeyRepo()
	env.handler.apiKeyRepo = mockKeyRepo

	preset := &types.RulePreset{ID: "evm/p", Name: "P"}
	apiKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}

	// "!!invalid!!" doesn't match the applied_to key ID pattern
	_, err := env.handler.resolveInstances(ctx, apiKey, []string{"!!invalid!!"}, preset,
		[]string{"evm/t1"}, map[string]string{}, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RBAC")
}

// ---------------------------------------------------------------------------
// apply — remaining branches
// ---------------------------------------------------------------------------

func newApplyEnvWithRepo(t *testing.T, preset *types.RulePreset, templateSvc *service.TemplateService) *PresetHandler {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}))
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)
	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	if preset != nil {
		require.NoError(t, presetRepo.Create(context.Background(), preset))
	}
	h, err := NewPresetHandler(presetRepo, tmplRepo, db, templateSvc, false,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	return h
}

func TestPresetHandler_Apply_PresetNotFound(t *testing.T) {
	h := newApplyEnvWithRepo(t, nil, &service.TemplateService{})
	ctx := context.WithValue(context.Background(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "admin", Role: types.RoleAdmin})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/evm%2Fnonexistent/apply",
		strings.NewReader(`{}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPresetHandler_Apply_NoDB(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}))
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)
	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	// Put a preset for the handler to find, but pass nil db to NewPresetHandler
	require.NoError(t, presetRepo.Create(context.Background(), &types.RulePreset{
		ID: "evm/test", Name: "Test", Enabled: true,
		TemplateIDs: mustJSONP(t, []string{"evm/tmpl"}),
		Source: types.RuleSourceFile, ContentHash: "h",
	}))
	h, err := NewPresetHandler(presetRepo, tmplRepo, nil, &service.TemplateService{},
		false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	ctx := context.WithValue(context.Background(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "admin", Role: types.RoleAdmin})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/evm%2Ftest/apply",
		strings.NewReader(`{}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "database")
}

func TestPresetHandler_Apply_MissingRequiredOverride(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}))
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)
	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	require.NoError(t, presetRepo.Create(context.Background(), &types.RulePreset{
		ID: "evm/test", Name: "Test", Enabled: true,
		TemplateIDs:      mustJSONP(t, []string{"evm/tmpl"}),
		OperatorOverrides: mustJSONP(t, []types.OperatorOverride{{Name: "my_override", Required: true}}),
		Source:           types.RuleSourceFile, ContentHash: "h",
	}))
	h, err := NewPresetHandler(presetRepo, tmplRepo, db, &service.TemplateService{},
		false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	ctx := context.WithValue(context.Background(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "admin", Role: types.RoleAdmin})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/evm%2Ftest/apply",
		strings.NewReader(`{"variables":{}}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	// The JSON encoding escapes the quotes: "required override \"my_override\" not supplied"
	assert.Contains(t, w.Body.String(), `required override`)
	assert.Contains(t, w.Body.String(), `my_override`)
}

func TestPresetHandler_Apply_RequiredOverrideSupplied(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}))
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)
	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	require.NoError(t, presetRepo.Create(context.Background(), &types.RulePreset{
		ID: "evm/test", Name: "Test", Enabled: true,
		TemplateIDs:      mustJSONP(t, []string{"evm/tmpl"}),
		OperatorOverrides: mustJSONP(t, []types.OperatorOverride{{Name: "my_override", Required: true}}),
		Source:           types.RuleSourceFile, ContentHash: "h",
	}))
	h, err := NewPresetHandler(presetRepo, tmplRepo, db, &service.TemplateService{},
		false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	ctx := context.WithValue(context.Background(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "admin", Role: types.RoleAdmin})
	// Required override supplied, but template doesn't exist so resolveInstances fails
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/evm%2Ftest/apply",
		strings.NewReader(`{"variables":{"my_override":"val"}}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	// Will fail at resolveInstances (template not found), not at required overrides
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPresetHandler_Apply_BudgetSubstitutionError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}))
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)
	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	// Budget has an unresolvable variable reference
	require.NoError(t, presetRepo.Create(context.Background(), &types.RulePreset{
		ID:          "evm/test",
		Name:        "Test",
		Enabled:     true,
		TemplateIDs: mustJSONP(t, []string{"evm/tmpl"}),
		Budget:      []byte(`{"max_total":"${missing_var}"}`),
		Source:      types.RuleSourceFile, ContentHash: "h",
	}))
	h, err := NewPresetHandler(presetRepo, tmplRepo, db, &service.TemplateService{},
		false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	ctx := context.WithValue(context.Background(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "admin", Role: types.RoleAdmin})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/evm%2Ftest/apply",
		strings.NewReader(`{}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "substitute preset budget")
}

func TestPresetHandler_Apply_ScheduleSubstitutionError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}))
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)
	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	require.NoError(t, presetRepo.Create(context.Background(), &types.RulePreset{
		ID:          "evm/test",
		Name:        "Test",
		Enabled:     true,
		TemplateIDs: mustJSONP(t, []string{"evm/tmpl"}),
		Schedule:    []byte(`{"period":"${missing_var}"}`),
		Source:      types.RuleSourceFile, ContentHash: "h",
	}))
	h, err := NewPresetHandler(presetRepo, tmplRepo, db, &service.TemplateService{},
		false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	ctx := context.WithValue(context.Background(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "admin", Role: types.RoleAdmin})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/evm%2Ftest/apply",
		strings.NewReader(`{}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "substitute preset schedule")
}

// ---------------------------------------------------------------------------
// runTemplateValidation — remaining branches
// ---------------------------------------------------------------------------

func newValidationEnv(t *testing.T) (*PresetHandler, *evm.JSRuleEvaluator) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}))
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)
	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	h, err := NewPresetHandler(presetRepo, tmplRepo, db, nil, false,
		slog.New(slog.NewTextHandler(io.Discard, nil)), WithPresetJSEvaluator(eval))
	require.NoError(t, err)
	return h, eval
}

func TestRunTemplateValidation_JSRuleWithTestCasesPass(t *testing.T) {
	h, _ := newValidationEnv(t)
	config := []byte(`{
		"rules": [{
			"name": "js-rule",
			"type": "evm_js",
			"mode": "whitelist",
			"config": {
				"script": "function validate(input){return{valid:true}}",
				"test_cases": [{"name":"tc1","input":{"sign_type":"transaction","signer":"0x1234567890123456789012345678901234567890","transaction":{"to":"0xaabbccddaabbccddaabbccddaabbccddaabbccdd","value":"0"}},"expect_pass":true}]
			}
		}]
	}`)
	results := h.runTemplateValidation(
		&types.RuleTemplate{Name: "Test", Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist},
		config, nil)
	require.Len(t, results, 1)
	assert.True(t, results[0].Valid)
	assert.Equal(t, "js-rule", results[0].RuleName)
}

func TestRunTemplateValidation_JSRuleWithTestCasesFail(t *testing.T) {
	h, _ := newValidationEnv(t)
	config := []byte(`{
		"rules": [{
			"name": "js-rule",
			"type": "evm_js",
			"mode": "whitelist",
			"config": {
				"script": "function validate(input){return{valid:false,message:'nope'}}",
				"test_cases": [{"name":"tc1","input":{"sign_type":"transaction","signer":"0x1234567890123456789012345678901234567890","transaction":{"to":"0xaabbccddaabbccddaabbccddaabbccddaabbccdd","value":"0"}},"expect_pass":true}]
			}
		}]
	}`)
	results := h.runTemplateValidation(
		&types.RuleTemplate{Name: "Test", Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist},
		config, nil)
	require.Len(t, results, 1)
	assert.False(t, results[0].Valid)
	assert.Contains(t, results[0].Error, "test case(s) failed")
}

func TestRunTemplateValidation_JSRuleNoTestCases(t *testing.T) {
	h, _ := newValidationEnv(t)
	config := []byte(`{
		"rules": [{
			"name": "js-rule",
			"type": "evm_js",
			"mode": "whitelist",
			"config": {"script": "function validate(input){return{valid:true}}"}
		}]
	}`)
	results := h.runTemplateValidation(
		&types.RuleTemplate{Name: "Test", Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist},
		config, nil)
	require.Len(t, results, 1)
	assert.True(t, results[0].Valid)
}

func TestRunTemplateValidation_JSRuleNoScript(t *testing.T) {
	h, _ := newValidationEnv(t)
	config := []byte(`{
		"rules": [{
			"name": "js-rule",
			"type": "evm_js",
			"mode": "whitelist",
			"config": {"test_cases": [{"name":"tc1","input":{},"expected":{"valid":true}}]}
		}]
	}`)
	results := h.runTemplateValidation(
		&types.RuleTemplate{Name: "Test", Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist},
		config, nil)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].Error, "no script")
}

func TestRunTemplateValidation_JSRuleScriptNotString(t *testing.T) {
	h, _ := newValidationEnv(t)
	config := []byte(`{
		"rules": [{
			"name": "js-rule",
			"type": "evm_js",
			"mode": "whitelist",
			"config": {"script": 42, "test_cases": [{"name":"tc1","input":{},"expected":{"valid":true}}]}
		}]
	}`)
	results := h.runTemplateValidation(
		&types.RuleTemplate{Name: "Test", Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist},
		config, nil)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].Error, "script is not a string")
}

func TestRunTemplateValidation_MultipleRules(t *testing.T) {
	h, _ := newValidationEnv(t)
	config := []byte(`{
		"rules": [
			{"name":"non-js","type":"sign_type_restriction","mode":"whitelist","config":{"allowed_sign_types":["transaction"]}},
			{"name":"js","type":"evm_js","mode":"whitelist","config":{"script":"function validate(input){return{valid:true}}","test_cases":[{"name":"t1","input":{"sign_type":"transaction","signer":"0x1234567890123456789012345678901234567890","transaction":{"to":"0xaabbccddaabbccddaabbccddaabbccddaabbccdd","value":"0"}},"expect_pass":true}]}}
		]
	}`)
	results := h.runTemplateValidation(
		&types.RuleTemplate{Name: "Test", Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist},
		config, nil)
	require.Len(t, results, 2)
	assert.True(t, results[0].Valid) // non-JS rule always valid
	assert.True(t, results[1].Valid) // JS rule with passing tests
}

func TestRunTemplateValidation_EmptyRulesArray(t *testing.T) {
	h, _ := newValidationEnv(t)
	config := []byte(`{"rules":[]}`)
	results := h.runTemplateValidation(
		&types.RuleTemplate{Name: "Test", Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist},
		config, nil)
	require.Len(t, results, 1)
	assert.True(t, results[0].Valid)
	assert.Contains(t, results[0].Error, "no rules array")
}

func TestRunTemplateValidation_NilTestCases(t *testing.T) {
	h, _ := newValidationEnv(t)
	config := []byte(`{
		"rules": [{
			"name": "js-rule",
			"type": "evm_js",
			"mode": "whitelist",
			"config": {"script": "function validate(input){return{valid:true}}","test_cases":null}
		}]
	}`)
	results := h.runTemplateValidation(
		&types.RuleTemplate{Name: "Test", Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist},
		config, nil)
	require.Len(t, results, 1)
	assert.True(t, results[0].Valid)
}

func TestRunTemplateValidation_EmptyTestCases(t *testing.T) {
	h, _ := newValidationEnv(t)
	config := []byte(`{
		"rules": [{
			"name": "js-rule",
			"type": "evm_js",
			"mode": "whitelist",
			"config": {"script": "function validate(input){return{valid:true}}","test_cases":[]}
		}]
	}`)
	results := h.runTemplateValidation(
		&types.RuleTemplate{Name: "Test", Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist},
		config, nil)
	require.Len(t, results, 1)
	assert.True(t, results[0].Valid)
}

func TestRunTemplateValidation_InvalidTestCasesJSON(t *testing.T) {
	h, _ := newValidationEnv(t)
	config := []byte(`{
		"rules": [{
			"name": "js-rule",
			"type": "evm_js",
			"mode": "whitelist",
			"config": {"script": "function validate(input){return{valid:true}}","test_cases":"not-an-array"}
		}]
	}`)
	results := h.runTemplateValidation(
		&types.RuleTemplate{Name: "Test", Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist},
		config, nil)
	require.Len(t, results, 1)
	assert.True(t, results[0].Valid)
}

// ---------------------------------------------------------------------------
// validatePreset — remaining branches
// ---------------------------------------------------------------------------

func TestPresetHandler_Validate_NoJSEvaluator(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}))
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)
	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	// No JS evaluator
	h, err := NewPresetHandler(presetRepo, tmplRepo, db, nil, false,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	ctx := contextWithKey(t, types.RoleAdmin, "admin")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/foo/validate",
		strings.NewReader(`{}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "JS evaluator not available")
}

func TestPresetHandler_Validate_WithBodyVariables(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}))
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)
	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	require.NoError(t, presetRepo.Create(context.Background(), &types.RulePreset{
		ID:      "evm/vp", Name: "VP", Enabled: true,
		TemplateIDs: mustJSONP(t, []string{"evm/vtmpl"}),
		Variables:   mustJSONP(t, map[string]string{"def_var": "default"}),
		Source:      types.RuleSourceFile, ContentHash: "h",
	}))
	require.NoError(t, tmplRepo.Create(context.Background(), &types.RuleTemplate{
		ID: "evm/vtmpl", Name: "V Template", Type: types.RuleTypeSignTypeRestriction,
		Mode: types.RuleModeWhitelist, Source: types.RuleSourceFile, ContentHash: "h", Enabled: true,
		Config: mustJSONP(t, map[string]interface{}{
			"rules": []map[string]interface{}{{"name": "r1", "type": "sign_type_restriction", "mode": "whitelist", "config": map[string]interface{}{"allowed_sign_types": []string{"transaction"}}}},
		}),
	}))
	h, err := NewPresetHandler(presetRepo, tmplRepo, db, nil, false,
		slog.New(slog.NewTextHandler(io.Discard, nil)), WithPresetJSEvaluator(eval))
	require.NoError(t, err)
	ctx := contextWithKey(t, types.RoleAdmin, "admin")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/evm%2Fvp/validate",
		strings.NewReader(`{"variables":{"extra":"value"}}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp validatePresetResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Equal(t, 1, resp.Passed)
}

func TestPresetHandler_Validate_SubstitutionFailure(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}))
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)
	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	require.NoError(t, presetRepo.Create(context.Background(), &types.RulePreset{
		ID: "evm/vp", Name: "VP", Enabled: true,
		TemplateIDs: mustJSONP(t, []string{"evm/vtmpl"}),
		Source:      types.RuleSourceFile, ContentHash: "h",
	}))
	// Config references a variable that doesn't exist and is required
	require.NoError(t, tmplRepo.Create(context.Background(), &types.RuleTemplate{
		ID: "evm/vtmpl", Name: "V Template", Type: types.RuleTypeEVMJS,
		Mode: types.RuleModeWhitelist, Source: types.RuleSourceFile, ContentHash: "h", Enabled: true,
		Config:    []byte(`{"rules":[{"name":"r1","type":"evm_js","mode":"whitelist","config":{"script":"function validate(input){return{valid:true}}","allowed_addresses":"${nonexistent_var}"}}]}`),
		Variables: mustJSONP(t, []types.TemplateVariable{{Name: "nonexistent_var", Type: types.VarTypeString, Required: true}}),
	}))
	h, err := NewPresetHandler(presetRepo, tmplRepo, db, nil, false,
		slog.New(slog.NewTextHandler(io.Discard, nil)), WithPresetJSEvaluator(eval))
	require.NoError(t, err)
	ctx := contextWithKey(t, types.RoleAdmin, "admin")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/evm%2Fvp/validate",
		strings.NewReader(`{}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp validatePresetResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Equal(t, 1, resp.Failed)
}

func TestPresetHandler_Validate_WithChainID(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}))
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)
	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	require.NoError(t, presetRepo.Create(context.Background(), &types.RulePreset{
		ID: "evm/vp", Name: "VP", Enabled: true, ChainID: "137",
		TemplateIDs: mustJSONP(t, []string{"evm/vtmpl"}),
		Source:      types.RuleSourceFile, ContentHash: "h",
	}))
	require.NoError(t, tmplRepo.Create(context.Background(), &types.RuleTemplate{
		ID: "evm/vtmpl", Name: "V Template", Type: types.RuleTypeSignTypeRestriction,
		Mode: types.RuleModeWhitelist, Source: types.RuleSourceFile, ContentHash: "h", Enabled: true,
		Config: mustJSONP(t, map[string]interface{}{
			"rules": []map[string]interface{}{{"name": "r1", "type": "sign_type_restriction", "mode": "whitelist", "config": map[string]interface{}{"allowed_sign_types": []string{"transaction"}}}},
		}),
	}))
	h, err := NewPresetHandler(presetRepo, tmplRepo, db, nil, false,
		slog.New(slog.NewTextHandler(io.Discard, nil)), WithPresetJSEvaluator(eval))
	require.NoError(t, err)
	ctx := contextWithKey(t, types.RoleAdmin, "admin")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/evm%2Fvp/validate",
		strings.NewReader(`{}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPresetHandler_Validate_TemplateNotFound_Continues(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}))
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)
	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	// Preset references 2 templates, only 1 exists
	require.NoError(t, presetRepo.Create(context.Background(), &types.RulePreset{
		ID: "evm/vp", Name: "VP", Enabled: true,
		TemplateIDs: mustJSONP(t, []string{"evm/missing", "evm/exists"}),
		Source:      types.RuleSourceFile, ContentHash: "h",
	}))
	require.NoError(t, tmplRepo.Create(context.Background(), &types.RuleTemplate{
		ID: "evm/exists", Name: "Exists", Type: types.RuleTypeSignTypeRestriction,
		Mode: types.RuleModeWhitelist, Source: types.RuleSourceFile, ContentHash: "h", Enabled: true,
		Config: mustJSONP(t, map[string]interface{}{
			"rules": []map[string]interface{}{{"name": "r1", "type": "sign_type_restriction", "mode": "whitelist", "config": map[string]interface{}{"allowed_sign_types": []string{"transaction"}}}},
		}),
	}))
	h, err := NewPresetHandler(presetRepo, tmplRepo, db, nil, false,
		slog.New(slog.NewTextHandler(io.Discard, nil)), WithPresetJSEvaluator(eval))
	require.NoError(t, err)
	ctx := contextWithKey(t, types.RoleAdmin, "admin")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/evm%2Fvp/validate",
		strings.NewReader(`{}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp validatePresetResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total) // Only the existing template produces results
}

func TestPresetHandler_Validate_NilBody(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}, &types.RuleTemplate{}))
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)
	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	require.NoError(t, presetRepo.Create(context.Background(), &types.RulePreset{
		ID: "evm/vp", Name: "VP", Enabled: true,
		TemplateIDs: mustJSONP(t, []string{"evm/vtmpl"}),
		Source:      types.RuleSourceFile, ContentHash: "h",
	}))
	require.NoError(t, tmplRepo.Create(context.Background(), &types.RuleTemplate{
		ID: "evm/vtmpl", Name: "V Template", Type: types.RuleTypeSignTypeRestriction,
		Mode: types.RuleModeWhitelist, Source: types.RuleSourceFile, ContentHash: "h", Enabled: true,
		Config: mustJSONP(t, map[string]interface{}{
			"rules": []map[string]interface{}{{"name": "r1", "type": "sign_type_restriction", "mode": "whitelist", "config": map[string]interface{}{"allowed_sign_types": []string{"transaction"}}}},
		}),
	}))
	h, err := NewPresetHandler(presetRepo, tmplRepo, db, nil, false,
		slog.New(slog.NewTextHandler(io.Discard, nil)), WithPresetJSEvaluator(eval))
	require.NoError(t, err)
	ctx := contextWithKey(t, types.RoleAdmin, "admin")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/evm%2Fvp/validate", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// collectTemplateVarDefs
// ---------------------------------------------------------------------------

func TestCollectTemplateVarDefs_DeduplicatesByName(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RuleTemplate{}))
	repo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	require.NoError(t, repo.Create(context.Background(), &types.RuleTemplate{
		ID: "a", Name: "A", Source: types.RuleSourceFile, ContentHash: "h",
		Variables: mustJSONP(t, []types.TemplateVariable{
			{Name: "shared", Type: types.VarTypeString, Required: true, Description: "from A"},
		}),
	}))
	require.NoError(t, repo.Create(context.Background(), &types.RuleTemplate{
		ID: "b", Name: "B", Source: types.RuleSourceFile, ContentHash: "h",
		Variables: mustJSONP(t, []types.TemplateVariable{
			{Name: "shared", Type: types.VarTypeAddress, Required: false, Description: "from B"},
			{Name: "only_b", Type: types.VarTypeString, Required: true},
		}),
	}))
	h := &PresetHandler{templateRepo: repo, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	defs := h.collectTemplateVarDefs(context.Background(), []string{"a", "b"})
	assert.Len(t, defs, 2)
	assert.Equal(t, "from A", defs["shared"].Description, "first occurrence wins")
	assert.Equal(t, types.VarTypeString, defs["shared"].Type)
	assert.True(t, defs["shared"].Required)
	assert.Equal(t, "only_b", defs["only_b"].Name)
}

func TestCollectTemplateVarDefs_EmptyVariables(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RuleTemplate{}))
	repo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	require.NoError(t, repo.Create(context.Background(), &types.RuleTemplate{
		ID: "a", Name: "A", Source: types.RuleSourceFile, ContentHash: "h",
	}))
	h := &PresetHandler{templateRepo: repo, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	defs := h.collectTemplateVarDefs(context.Background(), []string{"a"})
	assert.Empty(t, defs)
}

func TestCollectTemplateVarDefs_InvalidJSONVariables(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RuleTemplate{}))
	repo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	require.NoError(t, repo.Create(context.Background(), &types.RuleTemplate{
		ID: "a", Name: "A", Source: types.RuleSourceFile, ContentHash: "h",
		Variables: []byte(`{invalid`),
	}))
	h := &PresetHandler{templateRepo: repo, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	defs := h.collectTemplateVarDefs(context.Background(), []string{"a"})
	assert.Empty(t, defs)
}

func TestCollectTemplateVarDefs_TemplateNotFound(t *testing.T) {
	h := &PresetHandler{
		templateRepo: newMockTemplateRepo(),
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	defs := h.collectTemplateVarDefs(context.Background(), []string{"nonexistent"})
	assert.Empty(t, defs)
}

// ---------------------------------------------------------------------------
// writeError
// ---------------------------------------------------------------------------

func TestWriteError_EncodesJSON(t *testing.T) {
	h := &PresetHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w := httptest.NewRecorder()
	h.writeError(w, "test message", http.StatusTeapot)
	assert.Equal(t, http.StatusTeapot, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), `"test message"`)
}

// ---------------------------------------------------------------------------
// ServeHTTP — additional branches
// ---------------------------------------------------------------------------

func TestPresetHandler_ServeHTTP_UnknownSubAction(t *testing.T) {
	env := newPresetTestEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/presets/evm%2Fp/something", nil).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPresetHandler_ServeHTTP_GetSingleMethodNotAllowed(t *testing.T) {
	env := newPresetTestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/evm%2Fp", nil).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestPresetHandler_ServeHTTP_ApplyMethodNotAllowed(t *testing.T) {
	env := newPresetTestEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/presets/evm%2Fp/apply", nil).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestPresetHandler_ServeHTTP_ValidateMethodNotAllowed(t *testing.T) {
	env := newPresetTestEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/presets/evm%2Fp/validate", nil).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// ---------------------------------------------------------------------------
// List — error path
// ---------------------------------------------------------------------------

func TestPresetHandler_List_RepoError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	// Don't migrate — queries will fail
	presetRepo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)
	tmplRepo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	h, err := NewPresetHandler(presetRepo, tmplRepo, db, nil, false,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/presets", nil).WithContext(adminCtx(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
