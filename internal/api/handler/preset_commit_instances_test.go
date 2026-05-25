//go:build integration

package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// newPresetApplyTestEnv wires a PresetHandler with a real TemplateService
// backed by an in-memory SQLite database, suitable for testing commitInstances.
type presetApplyTestEnv struct {
	handler    *PresetHandler
	db         *gorm.DB
	tmplRepo   storage.TemplateRepository
	presetRepo storage.PresetRepository
	ruleRepo   storage.RuleRepository
	budgetRepo storage.BudgetRepository
	templateSvc *service.TemplateService
}

func newPresetApplyTestEnv(t *testing.T) *presetApplyTestEnv {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	requireNoErr(t, err)
	requireNoErr(t, db.AutoMigrate(
		&types.RulePreset{},
		&types.RuleTemplate{},
		&types.Rule{},
		&types.RuleBudget{},
	))

	tmplRepo, err := storage.NewGormTemplateRepository(db)
	requireNoErr(t, err)
	presetRepo, err := storage.NewGormPresetRepository(db)
	requireNoErr(t, err)
	ruleRepo, err := storage.NewGormRuleRepository(db)
	requireNoErr(t, err)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	requireNoErr(t, err)

	templateSvc, err := service.NewTemplateService(tmplRepo, ruleRepo, budgetRepo, slog.New(slog.NewTextHandler(io.Discard, nil)))
	requireNoErr(t, err)

	h, err := NewPresetHandler(
		presetRepo,
		tmplRepo,
		db,
		templateSvc,
		false,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	requireNoErr(t, err)

	return &presetApplyTestEnv{
		handler:     h,
		db:          db,
		tmplRepo:    tmplRepo,
		presetRepo:  presetRepo,
		ruleRepo:    ruleRepo,
		budgetRepo:  budgetRepo,
		templateSvc: templateSvc,
	}
}

func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// seedBundleTemplate creates and stores a template_bundle template.
func seedBundleTemplate(t *testing.T, env *presetApplyTestEnv, id, name string, subRules []map[string]interface{}) {
	t.Helper()
	subRulesJSON, err := json.Marshal(subRules)
	requireNoErr(t, err)
	config := map[string]interface{}{
		"rules_json": string(subRulesJSON),
	}
	configJSON, err := json.Marshal(config)
	requireNoErr(t, err)

	tmpl := &types.RuleTemplate{
		ID:        id,
		Name:      name,
		Type:      "template_bundle",
		Mode:      types.RuleModeWhitelist,
		Config:    configJSON,
		Source:    types.RuleSourceConfig,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	requireNoErr(t, env.tmplRepo.Create(context.Background(), tmpl))
}

// seedSimpleTemplate creates and stores a single-rule template.
func seedSimpleTemplate(t *testing.T, env *presetApplyTestEnv, id, name string, config map[string]interface{}) {
	t.Helper()
	configJSON, err := json.Marshal(config)
	requireNoErr(t, err)

	tmpl := &types.RuleTemplate{
		ID:        id,
		Name:      name,
		Type:      types.RuleTypeEVMJS,
		Mode:      types.RuleModeWhitelist,
		Config:    configJSON,
		Source:    types.RuleSourceConfig,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	requireNoErr(t, env.tmplRepo.Create(context.Background(), tmpl))
}

func TestCommitInstances_CrossTemplateDelegate(t *testing.T) {
	env := newPresetApplyTestEnv(t)
	ctx := context.Background()

	// Template A: bundle with a sub-rule ID "polymarket-transactions"
	subRules := []map[string]interface{}{
		{
			"id":   "polymarket-transactions",
			"name": "Polymarket Transactions",
			"type": string(types.RuleTypeEVMJS),
			"mode": string(types.RuleModeWhitelist),
			"config": map[string]interface{}{
				"expression": "true",
			},
			"enabled": true,
		},
	}
	seedBundleTemplate(t, env, "evm/polymarket", "Polymarket", subRules)

	// Template B: single-rule template with delegate_to referencing the bundle's sub-rule
	seedSimpleTemplate(t, env, "evm/safe", "Safe", map[string]interface{}{
		"delegate_to": "polymarket-transactions",
	})

	// Build resolved instances (simulating what resolveInstances does)
	pmTmpl, err := env.tmplRepo.Get(ctx, "evm/polymarket")
	requireNoErr(t, err)
	safeTmpl, err := env.tmplRepo.Get(ctx, "evm/safe")
	requireNoErr(t, err)

	resolved := []resolvedInstance{
		{
			tmpl: pmTmpl,
			req: &service.CreateInstanceRequest{
				TemplateID: "evm/polymarket",
				Variables:  map[string]string{},
			},
		},
		{
			tmpl: safeTmpl,
			req: &service.CreateInstanceRequest{
				TemplateID: "evm/safe",
				Variables:  map[string]string{},
			},
		},
	}

	results, err := env.handler.commitInstances(ctx, resolved)
	if err != nil {
		t.Fatalf("commitInstances failed: %v", err)
	}

	// Should have 2 results: one from polymarket bundle, one from safe
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Find the safe rule by checking which one has delegate_to in config
	var safeRule *types.Rule
	for _, entry := range results {
		r, ok := entry["rule"].(*types.Rule)
		if !ok {
			t.Fatal("expected entry['rule'] to be *types.Rule")
		}
		var cfg map[string]interface{}
		if err := json.Unmarshal(r.Config, &cfg); err == nil {
			if d, _ := cfg["delegate_to"].(string); d != "" {
				safeRule = r
			}
		}
	}
	if safeRule == nil {
		t.Fatal("expected to find a safe rule with delegate_to in config")
	}

	// Verify delegate_to is resolved to inst_<hash> format
	var safeCfg map[string]interface{}
	if err := json.Unmarshal(safeRule.Config, &safeCfg); err != nil {
		t.Fatalf("failed to parse safe rule config: %v", err)
	}
	gotDelegate, _ := safeCfg["delegate_to"].(string)
	if !strings.HasPrefix(gotDelegate, "inst_") {
		t.Errorf("expected delegate_to to start with 'inst_', got %q", gotDelegate)
	}

	// Verify the delegated ID actually exists in the DB as a polymarket sub-rule
	delegatedID := types.RuleID(gotDelegate)
	pmRule, err := env.ruleRepo.Get(ctx, delegatedID)
	if err != nil {
		t.Errorf("delegated rule %q not found in DB: %v", gotDelegate, err)
	} else if pmRule == nil {
		t.Errorf("delegated rule %q is nil", gotDelegate)
	}
}

func TestCommitInstances_CrossTemplateDelegate_NoChangeNeeded(t *testing.T) {
	env := newPresetApplyTestEnv(t)
	ctx := context.Background()

	// Template A: bundle with sub-rule "rule-alpha"
	subRules := []map[string]interface{}{
		{
			"id":   "rule-alpha",
			"name": "Alpha Rule",
			"type": string(types.RuleTypeEVMJS),
			"mode": string(types.RuleModeWhitelist),
			"config": map[string]interface{}{
				"expression": "true",
			},
			"enabled": true,
		},
	}
	seedBundleTemplate(t, env, "tmpl/alpha", "Alpha Bundle", subRules)

	// Template B: simple rule without any delegate_to
	seedSimpleTemplate(t, env, "tmpl/beta", "Beta", map[string]interface{}{
		"expression": "true",
	})

	alphaTmpl, _ := env.tmplRepo.Get(ctx, "tmpl/alpha")
	betaTmpl, _ := env.tmplRepo.Get(ctx, "tmpl/beta")

	resolved := []resolvedInstance{
		{tmpl: alphaTmpl, req: &service.CreateInstanceRequest{TemplateID: "tmpl/alpha", Variables: map[string]string{}}},
		{tmpl: betaTmpl, req: &service.CreateInstanceRequest{TemplateID: "tmpl/beta", Variables: map[string]string{}}},
	}

	results, err := env.handler.commitInstances(ctx, resolved)
	if err != nil {
		t.Fatalf("commitInstances failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

func TestCommitInstances_MultipleDelegateRules(t *testing.T) {
	env := newPresetApplyTestEnv(t)
	ctx := context.Background()

	// Bundle with two target sub-rules
	subRules := []map[string]interface{}{
		{
			"id":   "auth-rule",
			"name": "Auth Rule",
			"type": string(types.RuleTypeEVMJS),
			"mode": string(types.RuleModeWhitelist),
			"config": map[string]interface{}{
				"expression": "true",
			},
			"enabled": true,
		},
		{
			"id":   "tx-rule",
			"name": "Tx Rule",
			"type": string(types.RuleTypeEVMJS),
			"mode": string(types.RuleModeWhitelist),
			"config": map[string]interface{}{
				"expression": "true",
			},
			"enabled": true,
		},
	}
	seedBundleTemplate(t, env, "evm/polymarket_v2", "Polymarket V2", subRules)

	// Safe template with delegate_to referencing both
	seedSimpleTemplate(t, env, "evm/safe_v2", "Safe V2", map[string]interface{}{
		"delegate_to": "auth-rule, tx-rule",
	})

	pmTmpl, _ := env.tmplRepo.Get(ctx, "evm/polymarket_v2")
	safeTmpl, _ := env.tmplRepo.Get(ctx, "evm/safe_v2")

	resolved := []resolvedInstance{
		{tmpl: pmTmpl, req: &service.CreateInstanceRequest{TemplateID: "evm/polymarket_v2", Variables: map[string]string{}}},
		{tmpl: safeTmpl, req: &service.CreateInstanceRequest{TemplateID: "evm/safe_v2", Variables: map[string]string{}}},
	}

	results, err := env.handler.commitInstances(ctx, resolved)
	if err != nil {
		t.Fatalf("commitInstances failed: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results (2 bundle + 1 safe), got %d", len(results))
	}

	// Find safe rule
	var safeRule *types.Rule
	for _, entry := range results {
		r, _ := entry["rule"].(*types.Rule)
		if r == nil {
			continue
		}
		var cfg map[string]interface{}
		if err := json.Unmarshal(r.Config, &cfg); err == nil {
			if d, _ := cfg["delegate_to"].(string); strings.Contains(d, "inst_") {
				safeRule = r
				break
			}
		}
	}
	if safeRule == nil {
		t.Fatal("expected to find a safe rule with resolved delegate_to")
	}

	var safeCfg map[string]interface{}
	if err := json.Unmarshal(safeRule.Config, &safeCfg); err != nil {
		t.Fatalf("failed to parse safe rule config: %v", err)
	}
	gotDelegate, _ := safeCfg["delegate_to"].(string)
	parts := strings.Split(gotDelegate, ",")
	if len(parts) != 2 {
		t.Fatalf("expected 2 comma-separated delegate_to targets, got %d: %q", len(parts), gotDelegate)
	}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if !strings.HasPrefix(p, "inst_") {
			t.Errorf("expected all delegate_to targets to start with 'inst_', got %q", p)
		}
		// Verify each target exists in DB
		_, err := env.ruleRepo.Get(ctx, types.RuleID(p))
		if err != nil {
			t.Errorf("delegated rule %q not found in DB: %v", p, err)
		}
	}
}
