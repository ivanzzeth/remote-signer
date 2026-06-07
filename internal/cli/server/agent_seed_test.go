package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/lib/pq"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	_ "modernc.org/sqlite"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.New(sqlite.Config{DSN: ":memory:", DriverName: "sqlite"}), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(
		&types.Rule{},
		&types.RuleTemplate{},
		&types.RulePreset{},
		&types.RuleBudget{},
	); err != nil {
		t.Fatal(err)
	}
	return db
}

func newTestRuleRepo(t *testing.T, db *gorm.DB) storage.RuleRepository {
	t.Helper()
	repo, err := storage.NewGormRuleRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func newTestBudgetRepo(t *testing.T, db *gorm.DB) storage.BudgetRepository {
	t.Helper()
	repo, err := storage.NewGormBudgetRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func newTestPresetRepo(t *testing.T, db *gorm.DB) storage.PresetRepository {
	t.Helper()
	repo, err := storage.NewGormPresetRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func newTestTemplateRepo(t *testing.T, db *gorm.DB) storage.TemplateRepository {
	t.Helper()
	repo, err := storage.NewGormTemplateRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func TestBootstrapAgentPresetCreatesRules(t *testing.T) {
	db := newTestDB(t)
	presetRepo := newTestPresetRepo(t, db)
	templateRepo := newTestTemplateRepo(t, db)
	ruleRepo := newTestRuleRepo(t, db)
	budgetRepo := newTestBudgetRepo(t, db)

	// Seed the evm/agent preset into DB (simulates what registry sync does).
	presetVars := map[string]any{
		"max_message_length":          "1024",
		"budget_period":               "24h",
		"max_native_total":            "1",
		"max_native_per_tx":           "0.1",
		"max_tx_count":                "1000",
		"max_sign_count":              "500",
		"max_unknown_token_total":     "1000",
		"max_unknown_token_per_tx":    "100",
		"max_unknown_token_tx_count":  "50",
		"trusted_contracts":           "",
		"token_address":               "",
		"allowed_spenders":            "",
		"allowed_recipients":          "",
		"max_transfer_amount":         "0",
		"max_approve_amount":          "-1",
		"allowed_approve_to":          "",
		"allowed_operators":           "",
		"auth_only":                   "true",
	}
	presetVarsJSON, _ := json.Marshal(presetVars)
	presetTemplateIDsJSON, _ := json.Marshal([]string{"evm/agent", "evm/erc20", "evm/erc721", "evm/erc1155"})
	if err := presetRepo.Create(context.Background(), &types.RulePreset{
		ID:          "evm/agent",
		Name:        "Agent",
		ChainType:   "evm",
		TemplateIDs: presetTemplateIDsJSON,
		Variables:   presetVarsJSON,
		Enabled:     true,
		Source:      types.RuleSourceFile,
	}); err != nil {
		t.Fatal(err)
	}

	// Seed the evm/agent template into DB.
	tmplVars := []map[string]any{
		{"name": "max_message_length", "type": "string", "default": "1024"},
		{"name": "max_native_total", "type": "string", "default": "1"},
	}
	tmplVarsJSON, _ := json.Marshal(tmplVars)
	tmplConfig := map[string]any{
		"rules": []map[string]any{
			{
				"id":          "agent-sign",
				"priority":    10000,
				"name":        "Agent Signature",
				"type":        "evm_js",
				"mode":        "whitelist",
				"enabled":     true,
				"description": "Allow personal_sign and typed_data",
				"config": map[string]any{
					"sign_type_filter": "personal_sign,typed_data",
					"trusted_contracts": "",
					"script":            "function validate(input) { return ok(); }",
				},
			},
			{
				"id":          "agent-safety",
				"priority":    10000,
				"name":        "Agent Safety",
				"type":        "evm_js",
				"mode":        "blocklist",
				"enabled":     true,
				"description": "Block dangerous selectors",
				"config": map[string]any{
					"sign_type_filter": "transaction",
					"script":            "function validate(input) { return ok(); }",
				},
			},
		},
	}
	tmplConfigJSON, _ := json.Marshal(tmplConfig)
	if err := templateRepo.Create(context.Background(), &types.RuleTemplate{
		ID:        "evm/agent",
		Name:      "Agent Signature",
		Type:      "template_bundle",
		Variables: tmplVarsJSON,
		Config:    tmplConfigJSON,
		Source:    types.RuleSourceFile,
		Enabled:   true,
	}); err != nil {
		t.Fatal(err)
	}

	seedMinimalTokenTemplates(t, templateRepo)

	// Run bootstrap.
	if err := bootstrapAgentPresetIfNeeded(context.Background(), presetRepo, templateRepo, ruleRepo, budgetRepo, discardLogger()); err != nil {
		t.Fatal(err)
	}

	// Verify rules were created.
	source := types.RuleSourceInstance
	rules, err := ruleRepo.List(context.Background(), storage.RuleFilter{Source: &source})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 6 {
		t.Fatalf("expected 6 rules (agent×2 + erc20×2 + erc721×1 + erc1155×1), got %d", len(rules))
	}
	for _, r := range rules {
		if r.Priority != 10000 {
			t.Errorf("rule %q: priority = %d, want 10000", r.ID, r.Priority)
		}
		if r.Owner != "agent" {
			t.Errorf("rule %q: owner = %q, want agent", r.ID, r.Owner)
		}
		if r.Source != types.RuleSourceInstance {
			t.Errorf("rule %q: source = %q, want instance", r.ID, r.Source)
		}
		if r.Status != types.RuleStatusActive {
			t.Errorf("rule %q: status = %q, want active", r.ID, r.Status)
		}
	}

	// Verify budget was created for whitelist rule.
	var whitelistRuleID types.RuleID
	for _, r := range rules {
		if r.Mode == types.RuleModeWhitelist {
			whitelistRuleID = r.ID
			break
		}
	}
	if whitelistRuleID == "" {
		t.Fatal("no whitelist rule found")
	}
	budgets, err := budgetRepo.ListByRuleID(context.Background(), whitelistRuleID)
	if err != nil {
		t.Fatal(err)
	}
	if len(budgets) == 0 {
		t.Fatal("expected at least 1 budget for whitelist rule")
	}
}

func seedMinimalTokenTemplates(t *testing.T, templateRepo storage.TemplateRepository) {
	t.Helper()
	ctx := context.Background()

	erc20Config, _ := json.Marshal(map[string]any{
		"rules": []map[string]any{
			{"id": "erc20-transfer-limit", "priority": 10000, "name": "ERC20 transfer", "type": "evm_js", "mode": "whitelist", "enabled": true, "config": map[string]any{}},
			{"id": "erc20-approve-limit", "priority": 10000, "name": "ERC20 approve", "type": "evm_js", "mode": "whitelist", "enabled": true, "config": map[string]any{}},
		},
	})
	if err := templateRepo.Create(ctx, &types.RuleTemplate{
		ID: "evm/erc20", Name: "ERC20", Type: "template_bundle", Config: erc20Config, Source: types.RuleSourceFile, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	erc721Config, _ := json.Marshal(map[string]any{
		"rules": []map[string]any{
			{"id": "erc721-transfer-approve-allowlists", "priority": 10000, "name": "ERC721", "type": "evm_js", "mode": "whitelist", "enabled": true, "config": map[string]any{}},
		},
	})
	if err := templateRepo.Create(ctx, &types.RuleTemplate{
		ID: "evm/erc721", Name: "ERC721", Type: "template_bundle", Config: erc721Config, Source: types.RuleSourceFile, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	erc1155Config, _ := json.Marshal(map[string]any{
		"rules": []map[string]any{
			{"id": "erc1155-transfer-approve-allowlists", "priority": 10000, "name": "ERC1155", "type": "evm_js", "mode": "whitelist", "enabled": true, "config": map[string]any{}},
		},
	})
	if err := templateRepo.Create(ctx, &types.RuleTemplate{
		ID: "evm/erc1155", Name: "ERC1155", Type: "template_bundle", Config: erc1155Config, Source: types.RuleSourceFile, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapAgentPresetNoopWhenRulesExist(t *testing.T) {
	db := newTestDB(t)
	presetRepo := newTestPresetRepo(t, db)
	templateRepo := newTestTemplateRepo(t, db)
	ruleRepo := newTestRuleRepo(t, db)
	budgetRepo := newTestBudgetRepo(t, db)

	// Pre-create an instance rule.
	if err := ruleRepo.Create(context.Background(), &types.Rule{
		ID:        "inst_abc123",
		Name:      "existing instance",
		Type:      types.RuleTypeEVMJS,
		Mode:      types.RuleModeWhitelist,
		Source:    types.RuleSourceInstance,
		Enabled:   true,
		AppliedTo: pq.StringArray{"*"},
		Owner:     "agent",
		Status:    types.RuleStatusActive,
	}); err != nil {
		t.Fatal(err)
	}

	// Seed preset.
	presetVarsJSON, _ := json.Marshal(map[string]any{})
	presetTemplateIDsJSON, _ := json.Marshal([]string{"evm/agent"})
	if err := presetRepo.Create(context.Background(), &types.RulePreset{
		ID:          "evm/agent",
		Name:        "Agent",
		ChainType:   "evm",
		TemplateIDs: presetTemplateIDsJSON,
		Variables:   presetVarsJSON,
		Enabled:     true,
		Source:      types.RuleSourceFile,
	}); err != nil {
		t.Fatal(err)
	}

	// Seed template.
	tmplConfigJSON, _ := json.Marshal(map[string]any{
		"rules": []map[string]any{
			{
				"id":      "agent-sign",
				"name":    "Agent Signature",
				"type":    "evm_js",
				"mode":    "whitelist",
				"enabled": true,
				"config":  map[string]any{},
			},
		},
	})
	if err := templateRepo.Create(context.Background(), &types.RuleTemplate{
		ID:      "evm/agent",
		Name:    "Agent Signature",
		Type:    "template_bundle",
		Config:  tmplConfigJSON,
		Source:  types.RuleSourceFile,
		Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	if err := bootstrapAgentPresetIfNeeded(context.Background(), presetRepo, templateRepo, ruleRepo, budgetRepo, discardLogger()); err != nil {
		t.Fatal(err)
	}

	// Should still have only 1 rule (the pre-existing one).
	source := types.RuleSourceInstance
	rules, err := ruleRepo.List(context.Background(), storage.RuleFilter{Source: &source})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 pre-existing rule, got %d", len(rules))
	}
}

func TestBootstrapAgentPresetNoopWhenPresetNotFound(t *testing.T) {
	db := newTestDB(t)
	presetRepo := newTestPresetRepo(t, db)
	templateRepo := newTestTemplateRepo(t, db)
	ruleRepo := newTestRuleRepo(t, db)
	budgetRepo := newTestBudgetRepo(t, db)

	// No preset seeded — should gracefully skip.
	if err := bootstrapAgentPresetIfNeeded(context.Background(), presetRepo, templateRepo, ruleRepo, budgetRepo, discardLogger()); err != nil {
		t.Fatal(err)
	}

	source := types.RuleSourceInstance
	count, err := ruleRepo.Count(context.Background(), storage.RuleFilter{Source: &source})
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected 0 rules, got %d", count)
	}
}
