package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------------------------------------------------------------------------
// In-memory mock repositories
// ---------------------------------------------------------------------------

// mockTemplateRepo is an in-memory implementation of storage.TemplateRepository.
type mockTemplateRepo struct {
	mu        sync.RWMutex
	templates map[string]*types.RuleTemplate
}

func newMockTemplateRepo() *mockTemplateRepo {
	return &mockTemplateRepo{templates: make(map[string]*types.RuleTemplate)}
}

func (r *mockTemplateRepo) Create(_ context.Context, tmpl *types.RuleTemplate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.templates[tmpl.ID]; exists {
		return types.ErrAlreadyExists
	}
	cp := *tmpl
	r.templates[tmpl.ID] = &cp
	return nil
}

func (r *mockTemplateRepo) Get(_ context.Context, id string) (*types.RuleTemplate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tmpl, ok := r.templates[id]
	if !ok {
		return nil, types.ErrNotFound
	}
	cp := *tmpl
	return &cp, nil
}

func (r *mockTemplateRepo) GetByName(_ context.Context, name string) (*types.RuleTemplate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, tmpl := range r.templates {
		if tmpl.Name == name {
			cp := *tmpl
			return &cp, nil
		}
	}
	return nil, types.ErrNotFound
}

func (r *mockTemplateRepo) Update(_ context.Context, tmpl *types.RuleTemplate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.templates[tmpl.ID]; !exists {
		return types.ErrNotFound
	}
	cp := *tmpl
	r.templates[tmpl.ID] = &cp
	return nil
}

func (r *mockTemplateRepo) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.templates[id]; !exists {
		return types.ErrNotFound
	}
	delete(r.templates, id)
	return nil
}

func (r *mockTemplateRepo) List(_ context.Context, _ storage.TemplateFilter) ([]*types.RuleTemplate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*types.RuleTemplate
	for _, tmpl := range r.templates {
		cp := *tmpl
		out = append(out, &cp)
	}
	return out, nil
}

func (r *mockTemplateRepo) Count(_ context.Context, _ storage.TemplateFilter) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.templates), nil
}

// mockRuleRepo is an in-memory implementation of storage.RuleRepository.
type mockRuleRepo struct {
	mu    sync.RWMutex
	rules map[types.RuleID]*types.Rule
}

func newMockRuleRepo() *mockRuleRepo {
	return &mockRuleRepo{rules: make(map[types.RuleID]*types.Rule)}
}

func (r *mockRuleRepo) Create(_ context.Context, rule *types.Rule) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.rules[rule.ID]; exists {
		return types.ErrAlreadyExists
	}
	cp := *rule
	r.rules[rule.ID] = &cp
	return nil
}

func (r *mockRuleRepo) Get(_ context.Context, id types.RuleID) (*types.Rule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rule, ok := r.rules[id]
	if !ok {
		return nil, types.ErrNotFound
	}
	cp := *rule
	return &cp, nil
}

func (r *mockRuleRepo) Update(_ context.Context, rule *types.Rule) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.rules[rule.ID]; !exists {
		return types.ErrNotFound
	}
	cp := *rule
	r.rules[rule.ID] = &cp
	return nil
}

func (r *mockRuleRepo) Delete(_ context.Context, id types.RuleID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.rules[id]; !exists {
		return types.ErrNotFound
	}
	delete(r.rules, id)
	return nil
}

func (r *mockRuleRepo) List(_ context.Context, _ storage.RuleFilter) ([]*types.Rule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*types.Rule
	for _, rule := range r.rules {
		cp := *rule
		out = append(out, &cp)
	}
	return out, nil
}

func (r *mockRuleRepo) Count(_ context.Context, _ storage.RuleFilter) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.rules), nil
}

func (r *mockRuleRepo) ListByChainType(_ context.Context, _ types.ChainType) ([]*types.Rule, error) {
	return nil, nil
}

func (r *mockRuleRepo) IncrementMatchCount(_ context.Context, id types.RuleID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rule, ok := r.rules[id]
	if !ok {
		return types.ErrNotFound
	}
	rule.MatchCount++
	now := time.Now()
	rule.LastMatchedAt = &now
	return nil
}

// mockBudgetRepo is an in-memory implementation of storage.BudgetRepository.
type mockBudgetRepo struct {
	mu      sync.RWMutex
	budgets map[string]*types.RuleBudget // keyed by ID
}

func newMockBudgetRepo() *mockBudgetRepo {
	return &mockBudgetRepo{budgets: make(map[string]*types.RuleBudget)}
}

func (r *mockBudgetRepo) Create(_ context.Context, budget *types.RuleBudget) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.budgets[budget.ID]; exists {
		return types.ErrAlreadyExists
	}
	cp := *budget
	r.budgets[budget.ID] = &cp
	return nil
}

func (r *mockBudgetRepo) GetByRuleID(_ context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, b := range r.budgets {
		if b.RuleID == ruleID && b.Unit == unit {
			cp := *b
			return &cp, nil
		}
	}
	return nil, types.ErrNotFound
}

func (r *mockBudgetRepo) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.budgets[id]; !exists {
		return types.ErrNotFound
	}
	delete(r.budgets, id)
	return nil
}

func (r *mockBudgetRepo) DeleteByRuleID(_ context.Context, ruleID types.RuleID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, b := range r.budgets {
		if b.RuleID == ruleID {
			delete(r.budgets, id)
		}
	}
	return nil
}

func (r *mockBudgetRepo) AtomicSpend(_ context.Context, _ types.RuleID, _ string, _ string) error {
	return nil
}

func (r *mockBudgetRepo) ResetBudget(_ context.Context, _ types.RuleID, _ string, _ time.Time) error {
	return nil
}

func (r *mockBudgetRepo) ListByRuleID(_ context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*types.RuleBudget
	for _, b := range r.budgets {
		if b.RuleID == ruleID {
			cp := *b
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *mockBudgetRepo) ListByRuleIDs(_ context.Context, ruleIDs []types.RuleID) ([]*types.RuleBudget, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	idSet := make(map[types.RuleID]struct{}, len(ruleIDs))
	for _, id := range ruleIDs {
		idSet[id] = struct{}{}
	}
	var out []*types.RuleBudget
	for _, b := range r.budgets {
		if _, ok := idSet[b.RuleID]; ok {
			cp := *b
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *mockBudgetRepo) MarkAlertSent(_ context.Context, _ types.RuleID, _ string) error {
	return nil
}

// helper to count budgets in the mock repo
func (r *mockBudgetRepo) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.budgets)
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// mustJSON marshals v to JSON bytes; panics on failure.
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("mustJSON: %v", err))
	}
	return b
}

// seedTemplate inserts a template directly into the mock repo for test setup.
func seedTemplate(t *testing.T, repo *mockTemplateRepo, tmpl *types.RuleTemplate) {
	t.Helper()
	if err := repo.Create(context.Background(), tmpl); err != nil {
		t.Fatalf("seedTemplate: %v", err)
	}
}

// seedRule inserts a rule directly into the mock repo for test setup.
func seedRule(t *testing.T, repo *mockRuleRepo, rule *types.Rule) {
	t.Helper()
	if err := repo.Create(context.Background(), rule); err != nil {
		t.Fatalf("seedRule: %v", err)
	}
}

// makeTemplate builds a minimal RuleTemplate with sensible defaults.
func makeTemplate(id, name string, vars []types.TemplateVariable, config json.RawMessage) *types.RuleTemplate {
	return &types.RuleTemplate{
		ID:        id,
		Name:      name,
		Type:      types.RuleTypeEVMAddressList,
		Mode:      types.RuleModeWhitelist,
		Variables: mustJSON(vars),
		Config:    config,
		Source:    types.RuleSourceConfig,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNewTemplateService(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	logger := newTestLogger()

	t.Run("all_valid_args", func(t *testing.T) {
		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, logger)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
	})

	t.Run("nil_template_repo", func(t *testing.T) {
		_, err := NewTemplateService(nil, ruleRepo, budgetRepo, logger)
		if err == nil {
			t.Fatal("expected error for nil template repository")
		}
		if !strings.Contains(err.Error(), "template repository is required") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("nil_rule_repo", func(t *testing.T) {
		_, err := NewTemplateService(tmplRepo, nil, budgetRepo, logger)
		if err == nil {
			t.Fatal("expected error for nil rule repository")
		}
		if !strings.Contains(err.Error(), "rule repository is required") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("nil_budget_repo", func(t *testing.T) {
		_, err := NewTemplateService(tmplRepo, ruleRepo, nil, logger)
		if err == nil {
			t.Fatal("expected error for nil budget repository")
		}
		if !strings.Contains(err.Error(), "budget repository is required") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("nil_logger", func(t *testing.T) {
		_, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, nil)
		if err == nil {
			t.Fatal("expected error for nil logger")
		}
		if !strings.Contains(err.Error(), "logger is required") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}

func TestSubstituteVariables(t *testing.T) {
	t.Run("simple_substitution", func(t *testing.T) {
		config := []byte(`{"address":"${target}"}`)
		vars := map[string]string{"target": "0x1234567890abcdef1234567890abcdef12345678"}

		result, err := SubstituteVariables(config, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := `{"address":"0x1234567890abcdef1234567890abcdef12345678"}`
		if string(result) != expected {
			t.Errorf("expected %s, got %s", expected, string(result))
		}
	})

	t.Run("multiple_variables", func(t *testing.T) {
		config := []byte(`{"from":"${sender}","to":"${receiver}","amount":"${amount}"}`)
		vars := map[string]string{
			"sender":   "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"receiver": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"amount":   "1000000",
		}

		result, err := SubstituteVariables(config, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := `{"from":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","to":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","amount":"1000000"}`
		if string(result) != expected {
			t.Errorf("expected %s, got %s", expected, string(result))
		}
	})

	t.Run("same_variable_multiple_times", func(t *testing.T) {
		config := []byte(`{"a":"${x}","b":"${x}"}`)
		vars := map[string]string{"x": "hello"}

		result, err := SubstituteVariables(config, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := `{"a":"hello","b":"hello"}`
		if string(result) != expected {
			t.Errorf("expected %s, got %s", expected, string(result))
		}
	})

	t.Run("unresolved_variables_returns_error", func(t *testing.T) {
		config := []byte(`{"addr":"${target}","val":"${missing}"}`)
		vars := map[string]string{"target": "0x1234567890abcdef1234567890abcdef12345678"}

		_, err := SubstituteVariables(config, vars)
		if err == nil {
			t.Fatal("expected error for unresolved variable")
		}
		if !strings.Contains(err.Error(), "unresolved variables") {
			t.Errorf("error should mention unresolved variables, got: %v", err)
		}
		if !strings.Contains(err.Error(), "missing") {
			t.Errorf("error should name the unresolved variable 'missing', got: %v", err)
		}
	})

	t.Run("no_variables_to_substitute", func(t *testing.T) {
		config := []byte(`{"static":"value","count":42}`)
		vars := map[string]string{}

		result, err := SubstituteVariables(config, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(result) != string(config) {
			t.Errorf("expected config unchanged, got %s", string(result))
		}
	})

	t.Run("nil_vars_map", func(t *testing.T) {
		config := []byte(`{"static":"value"}`)

		result, err := SubstituteVariables(config, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(result) != `{"static":"value"}` {
			t.Errorf("expected unchanged config, got %s", string(result))
		}
	})

	t.Run("empty_config", func(t *testing.T) {
		result, err := SubstituteVariables([]byte(`{}`), map[string]string{"x": "y"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(result) != `{}` {
			t.Errorf("expected {}, got %s", string(result))
		}
	})

	t.Run("multiple_unresolved_variables", func(t *testing.T) {
		config := []byte(`{"a":"${x}","b":"${y}","c":"${z}"}`)

		_, err := SubstituteVariables(config, map[string]string{})
		if err == nil {
			t.Fatal("expected error for multiple unresolved variables")
		}
		// Should list all unresolved
		for _, name := range []string{"x", "y", "z"} {
			if !strings.Contains(err.Error(), name) {
				t.Errorf("error should mention unresolved variable '%s', got: %v", name, err)
			}
		}
	})
}

func TestCreateInstance(t *testing.T) {
	ctx := context.Background()

	// Shared template config with a single variable
	configWithVar := []byte(`{"addresses":["${target_address}"]}`)
	// Variables definition: one required address variable
	requiredAddrVar := []types.TemplateVariable{
		{Name: "target_address", Type: "address", Description: "Target address", Required: true},
	}

	t.Run("basic_creation_with_variables", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeTemplate("tmpl-1", "Address Whitelist", requiredAddrVar, configWithVar)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-1",
			Variables: map[string]string{
				"target_address": "0x1234567890abcdef1234567890abcdef12345678",
			},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Rule == nil {
			t.Fatal("expected non-nil rule in result")
		}

		// Rule should have source = instance
		if result.Rule.Source != types.RuleSourceInstance {
			t.Errorf("expected source %q, got %q", types.RuleSourceInstance, result.Rule.Source)
		}

		// Rule ID should start with "inst_"
		if !strings.HasPrefix(string(result.Rule.ID), "inst_") {
			t.Errorf("expected rule ID prefix 'inst_', got %q", result.Rule.ID)
		}

		// TemplateID should be set
		if result.Rule.TemplateID == nil || *result.Rule.TemplateID != "tmpl-1" {
			t.Errorf("expected template ID 'tmpl-1', got %v", result.Rule.TemplateID)
		}

		// Config should have the variable substituted
		expectedConfig := `{"addresses":["0x1234567890abcdef1234567890abcdef12345678"]}`
		if string(result.Rule.Config) != expectedConfig {
			t.Errorf("expected config %s, got %s", expectedConfig, string(result.Rule.Config))
		}

		// Rule should be enabled
		if !result.Rule.Enabled {
			t.Error("expected rule to be enabled")
		}

		// Variables should be stored as JSON
		var storedVars map[string]string
		if err := json.Unmarshal(result.Rule.Variables, &storedVars); err != nil {
			t.Fatalf("failed to unmarshal stored variables: %v", err)
		}
		if storedVars["target_address"] != "0x1234567890abcdef1234567890abcdef12345678" {
			t.Errorf("stored variable mismatch: %v", storedVars)
		}

		// Default name should include " (instance)"
		if result.Rule.Name != "Address Whitelist (instance)" {
			t.Errorf("expected default name 'Address Whitelist (instance)', got %q", result.Rule.Name)
		}

		// Rule should be persisted in the repo
		_, err = ruleRepo.Get(ctx, result.Rule.ID)
		if err != nil {
			t.Errorf("rule should be retrievable from repo: %v", err)
		}

		// No budget should be created
		if result.Budget != nil {
			t.Error("expected nil budget when none specified")
		}
	})

	t.Run("custom_name_override", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeTemplate("tmpl-name", "Base Template", requiredAddrVar, configWithVar)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-name",
			Name:       "My Custom Rule",
			Variables: map[string]string{
				"target_address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Rule.Name != "My Custom Rule" {
			t.Errorf("expected name 'My Custom Rule', got %q", result.Rule.Name)
		}
	})

	t.Run("lookup_by_name", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeTemplate("tmpl-by-name", "My EVM Template", requiredAddrVar, configWithVar)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateName: "My EVM Template",
			Variables: map[string]string{
				"target_address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Rule.TemplateID == nil || *result.Rule.TemplateID != "tmpl-by-name" {
			t.Errorf("expected template ID 'tmpl-by-name', got %v", result.Rule.TemplateID)
		}
	})

	t.Run("missing_required_variable_returns_error", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeTemplate("tmpl-req", "Required Var Template", requiredAddrVar, configWithVar)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		// Provide no variables
		_, err = svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-req",
			Variables:  map[string]string{},
		})
		if err == nil {
			t.Fatal("expected error for missing required variable")
		}
		if !strings.Contains(err.Error(), "target_address") {
			t.Errorf("error should mention missing variable 'target_address', got: %v", err)
		}
		if !strings.Contains(err.Error(), "variable validation failed") {
			t.Errorf("error should mention validation failure, got: %v", err)
		}
	})

	t.Run("optional_variable_uses_default", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "max_value", Type: "uint256", Description: "Max value", Required: false, Default: "1000000"},
		}
		config := []byte(`{"max_value":"${max_value}"}`)
		tmpl := makeTemplate("tmpl-opt", "Optional Var Template", vars, config)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		// Do not provide the optional variable
		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-opt",
			Variables:  map[string]string{},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}

		expectedConfig := `{"max_value":"1000000"}`
		if string(result.Rule.Config) != expectedConfig {
			t.Errorf("expected config %s, got %s", expectedConfig, string(result.Rule.Config))
		}
	})

	t.Run("optional_variable_overridden_by_user", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "max_value", Type: "uint256", Description: "Max value", Required: false, Default: "1000000"},
		}
		config := []byte(`{"max_value":"${max_value}"}`)
		tmpl := makeTemplate("tmpl-override", "Override Default", vars, config)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-override",
			Variables:  map[string]string{"max_value": "5000000"},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}

		expectedConfig := `{"max_value":"5000000"}`
		if string(result.Rule.Config) != expectedConfig {
			t.Errorf("expected config %s, got %s", expectedConfig, string(result.Rule.Config))
		}
	})

	t.Run("with_budget", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "target_address", Type: "address", Required: true},
		}
		metering := types.BudgetMetering{
			Method: "tx_value",
			Unit:   "eth",
		}
		tmpl := makeTemplate("tmpl-budget", "Budget Template", vars, configWithVar)
		tmpl.BudgetMetering = mustJSON(metering)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-budget",
			Variables: map[string]string{
				"target_address": "0xcccccccccccccccccccccccccccccccccccccccc",
			},
			Budget: &BudgetConfig{
				MaxTotal:   "10000000000000000000",
				MaxPerTx:   "1000000000000000000",
				MaxTxCount: 100,
				AlertPct:   90,
			},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Budget == nil {
			t.Fatal("expected non-nil budget")
		}
		if result.Budget.Unit != "eth" {
			t.Errorf("expected budget unit 'eth', got %q", result.Budget.Unit)
		}
		if result.Budget.MaxTotal != "10000000000000000000" {
			t.Errorf("expected max_total '10000000000000000000', got %q", result.Budget.MaxTotal)
		}
		if result.Budget.MaxPerTx != "1000000000000000000" {
			t.Errorf("expected max_per_tx '1000000000000000000', got %q", result.Budget.MaxPerTx)
		}
		if result.Budget.MaxTxCount != 100 {
			t.Errorf("expected max_tx_count 100, got %d", result.Budget.MaxTxCount)
		}
		if result.Budget.AlertPct != 90 {
			t.Errorf("expected alert_pct 90, got %d", result.Budget.AlertPct)
		}
		if result.Budget.Spent != "0" {
			t.Errorf("expected spent '0', got %q", result.Budget.Spent)
		}
		if result.Budget.TxCount != 0 {
			t.Errorf("expected tx_count 0, got %d", result.Budget.TxCount)
		}
		if result.Budget.RuleID != result.Rule.ID {
			t.Errorf("budget rule_id mismatch: expected %q, got %q", result.Rule.ID, result.Budget.RuleID)
		}

		// Budget should be in the repo
		if budgetRepo.count() != 1 {
			t.Errorf("expected 1 budget in repo, got %d", budgetRepo.count())
		}
	})

	t.Run("budget_default_alert_pct", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeTemplate("tmpl-alert", "Alert Default", requiredAddrVar, configWithVar)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-alert",
			Variables: map[string]string{
				"target_address": "0xdddddddddddddddddddddddddddddddddddddddd",
			},
			Budget: &BudgetConfig{
				MaxTotal: "100",
				MaxPerTx: "10",
				// AlertPct not set — should default to 80
			},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Budget.AlertPct != 80 {
			t.Errorf("expected default alert_pct 80, got %d", result.Budget.AlertPct)
		}
	})

	t.Run("budget_default_unit_count", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		// Template without BudgetMetering — unit should default to "count"
		tmpl := makeTemplate("tmpl-defunit", "Default Unit", requiredAddrVar, configWithVar)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-defunit",
			Variables: map[string]string{
				"target_address": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			},
			Budget: &BudgetConfig{
				MaxTotal: "50",
				MaxPerTx: "5",
			},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Budget.Unit != "count" {
			t.Errorf("expected default unit 'count', got %q", result.Budget.Unit)
		}
	})

	t.Run("budget_metering_empty_unit_defaults_to_count", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		metering := types.BudgetMetering{Method: "count_only", Unit: ""}
		tmpl := makeTemplate("tmpl-empty-unit", "Empty Unit", requiredAddrVar, configWithVar)
		tmpl.BudgetMetering = mustJSON(metering)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-empty-unit",
			Variables:  map[string]string{"target_address": "0xffffffffffffffffffffffffffffffffffffffff"},
			Budget:     &BudgetConfig{MaxTotal: "10", MaxPerTx: "1"},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Budget == nil {
			t.Fatal("expected non-nil budget")
		}
		if result.Budget.Unit != "count" {
			t.Errorf("expected unit 'count' when BudgetMetering.Unit is empty, got %q", result.Budget.Unit)
		}
	})

	t.Run("budget_unit_variable_substitution", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "chain_id", Type: "string", Required: true},
			{Name: "token_address", Type: "address", Required: true},
		}
		metering := types.BudgetMetering{
			Method: "js",
			Unit:   "${chain_id}:${token_address}",
		}
		configUnitSubst := []byte(`{"chain_id":"${chain_id}","token":"${token_address}"}`)
		tmpl := makeTemplate("tmpl-unit-subst", "Unit Substitution", vars, configUnitSubst)
		tmpl.BudgetMetering = mustJSON(metering)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-unit-subst",
			Variables: map[string]string{
				"chain_id":       "137",
				"token_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
			},
			Budget: &BudgetConfig{
				MaxTotal: "1000",
				MaxPerTx: "100",
			},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Budget == nil {
			t.Fatal("expected non-nil budget")
		}
		expectedUnit := "137:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
		if result.Budget.Unit != expectedUnit {
			t.Errorf("expected budget unit %q (substituted from ${chain_id}:${token_address}), got %q", expectedUnit, result.Budget.Unit)
		}
		if budgetRepo.count() != 1 {
			t.Errorf("expected 1 budget in repo, got %d", budgetRepo.count())
		}
	})

	t.Run("with_expires_at", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeTemplate("tmpl-expiry", "Expiry Template", requiredAddrVar, configWithVar)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		expiresAt := time.Now().Add(24 * time.Hour)
		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-expiry",
			Variables: map[string]string{
				"target_address": "0x1111111111111111111111111111111111111111",
			},
			ExpiresAt: &expiresAt,
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Rule.ExpiresAt == nil {
			t.Fatal("expected non-nil ExpiresAt")
		}
		if !result.Rule.ExpiresAt.Equal(expiresAt) {
			t.Errorf("expected ExpiresAt %v, got %v", expiresAt, *result.Rule.ExpiresAt)
		}
	})

	t.Run("with_expires_in_duration", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeTemplate("tmpl-dur", "Duration Template", requiredAddrVar, configWithVar)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		dur := 2 * time.Hour
		before := time.Now()
		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-dur",
			Variables: map[string]string{
				"target_address": "0x2222222222222222222222222222222222222222",
			},
			ExpiresIn: &dur,
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		after := time.Now()

		if result.Rule.ExpiresAt == nil {
			t.Fatal("expected non-nil ExpiresAt from ExpiresIn")
		}
		// The computed ExpiresAt should be roughly now + 2h
		expectedMin := before.Add(dur)
		expectedMax := after.Add(dur)
		if result.Rule.ExpiresAt.Before(expectedMin) || result.Rule.ExpiresAt.After(expectedMax) {
			t.Errorf("ExpiresAt %v not in expected range [%v, %v]", *result.Rule.ExpiresAt, expectedMin, expectedMax)
		}
	})

	t.Run("nil_request_returns_error", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstance(ctx, nil)
		if err == nil {
			t.Fatal("expected error for nil request")
		}
		if !strings.Contains(err.Error(), "request is required") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("template_not_found_by_id", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "nonexistent",
			Variables:  map[string]string{},
		})
		if err == nil {
			t.Fatal("expected error for nonexistent template")
		}
		if !strings.Contains(err.Error(), "failed to resolve template") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("template_not_found_by_name", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateName: "NonExistent Template",
			Variables:    map[string]string{},
		})
		if err == nil {
			t.Fatal("expected error for nonexistent template name")
		}
	})

	t.Run("neither_id_nor_name_returns_error", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstance(ctx, &CreateInstanceRequest{
			Variables: map[string]string{},
		})
		if err == nil {
			t.Fatal("expected error when neither template_id nor template_name is set")
		}
		if !strings.Contains(err.Error(), "template_id or template_name is required") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("invalid_address_variable_type", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeTemplate("tmpl-inv-addr", "Invalid Address", requiredAddrVar, configWithVar)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-inv-addr",
			Variables: map[string]string{
				"target_address": "not-an-address",
			},
		})
		if err == nil {
			t.Fatal("expected error for invalid address")
		}
		if !strings.Contains(err.Error(), "invalid address") {
			t.Errorf("error should mention invalid address, got: %v", err)
		}
	})

	t.Run("invalid_uint256_variable_type", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "amount", Type: "uint256", Required: true},
		}
		config := []byte(`{"amount":"${amount}"}`)
		tmpl := makeTemplate("tmpl-inv-uint", "Invalid Uint", vars, config)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-inv-uint",
			Variables:  map[string]string{"amount": "not-a-number"},
		})
		if err == nil {
			t.Fatal("expected error for invalid uint256")
		}
		if !strings.Contains(err.Error(), "invalid uint256") {
			t.Errorf("error should mention invalid uint256, got: %v", err)
		}
	})

	t.Run("scope_fields_are_set", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeTemplate("tmpl-scope", "Scope Test", requiredAddrVar, configWithVar)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		chainType := "evm"
		chainID := "1"
		apiKeyID := "key-123"
		signerAddr := "0x3333333333333333333333333333333333333333"

		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-scope",
			Variables: map[string]string{
				"target_address": "0x4444444444444444444444444444444444444444",
			},
			ChainType:     &chainType,
			ChainID:       &chainID,
			APIKeyID:      &apiKeyID,
			SignerAddress: &signerAddr,
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}

		if result.Rule.ChainType == nil || string(*result.Rule.ChainType) != "evm" {
			t.Errorf("expected ChainType 'evm', got %v", result.Rule.ChainType)
		}
		if result.Rule.ChainID == nil || *result.Rule.ChainID != "1" {
			t.Errorf("expected ChainID '1', got %v", result.Rule.ChainID)
		}
		if result.Rule.APIKeyID == nil || *result.Rule.APIKeyID != "key-123" {
			t.Errorf("expected APIKeyID 'key-123', got %v", result.Rule.APIKeyID)
		}
		if result.Rule.SignerAddress == nil || *result.Rule.SignerAddress != signerAddr {
			t.Errorf("expected SignerAddress %q, got %v", signerAddr, result.Rule.SignerAddress)
		}
	})

	t.Run("with_schedule", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeTemplate("tmpl-sched", "Schedule Template", requiredAddrVar, configWithVar)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		startAt := time.Now().Truncate(time.Second)
		period := 24 * time.Hour
		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-sched",
			Variables: map[string]string{
				"target_address": "0x5555555555555555555555555555555555555555",
			},
			Schedule: &ScheduleConfig{
				Period:  period,
				StartAt: &startAt,
			},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Rule.BudgetPeriod == nil || *result.Rule.BudgetPeriod != period {
			t.Errorf("expected BudgetPeriod %v, got %v", period, result.Rule.BudgetPeriod)
		}
		if result.Rule.BudgetPeriodStart == nil || !result.Rule.BudgetPeriodStart.Equal(startAt) {
			t.Errorf("expected BudgetPeriodStart %v, got %v", startAt, result.Rule.BudgetPeriodStart)
		}
	})

	t.Run("schedule_default_start_at", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeTemplate("tmpl-sched-def", "Schedule Default Start", requiredAddrVar, configWithVar)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		period := 7 * 24 * time.Hour
		before := time.Now()
		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-sched-def",
			Variables: map[string]string{
				"target_address": "0x6666666666666666666666666666666666666666",
			},
			Schedule: &ScheduleConfig{
				Period: period,
				// StartAt not set — should default to now
			},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		after := time.Now()

		if result.Rule.BudgetPeriodStart == nil {
			t.Fatal("expected non-nil BudgetPeriodStart")
		}
		if result.Rule.BudgetPeriodStart.Before(before) || result.Rule.BudgetPeriodStart.After(after) {
			t.Errorf("BudgetPeriodStart %v not in expected range [%v, %v]",
				*result.Rule.BudgetPeriodStart, before, after)
		}
	})

	t.Run("template_with_no_variables_definition", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		// Template with no variable definitions and a static config
		tmpl := &types.RuleTemplate{
			ID:        "tmpl-novar",
			Name:      "Static Template",
			Type:      types.RuleTypeEVMValueLimit,
			Mode:      types.RuleModeBlocklist,
			Variables: nil, // no variables
			Config:    []byte(`{"max_value":"1000000000000000000"}`),
			Source:    types.RuleSourceConfig,
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-novar",
			Variables:  map[string]string{},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}

		expectedConfig := `{"max_value":"1000000000000000000"}`
		if string(result.Rule.Config) != expectedConfig {
			t.Errorf("expected config %s, got %s", expectedConfig, string(result.Rule.Config))
		}
		if result.Rule.Type != types.RuleTypeEVMValueLimit {
			t.Errorf("expected type %s, got %s", types.RuleTypeEVMValueLimit, result.Rule.Type)
		}
		if result.Rule.Mode != types.RuleModeBlocklist {
			t.Errorf("expected mode %s, got %s", types.RuleModeBlocklist, result.Rule.Mode)
		}
	})
}

func TestRevokeInstance(t *testing.T) {
	ctx := context.Background()

	t.Run("successfully_revokes_instance", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		templateID := "tmpl-1"
		ruleID := types.RuleID("inst_abc123")
		rule := &types.Rule{
			ID:         ruleID,
			Name:       "Test Instance",
			Source:     types.RuleSourceInstance,
			TemplateID: &templateID,
			Enabled:    true,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		seedRule(t, ruleRepo, rule)

		// Seed associated budget
		budget := &types.RuleBudget{
			ID:       types.BudgetID(ruleID, "eth"),
			RuleID:   ruleID,
			Unit:     "eth",
			MaxTotal: "100",
			MaxPerTx: "10",
			Spent:    "25",
		}
		if err := budgetRepo.Create(ctx, budget); err != nil {
			t.Fatalf("failed to seed budget: %v", err)
		}

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		err = svc.RevokeInstance(ctx, ruleID)
		if err != nil {
			t.Fatalf("RevokeInstance failed: %v", err)
		}

		// Rule should be disabled
		updatedRule, err := ruleRepo.Get(ctx, ruleID)
		if err != nil {
			t.Fatalf("failed to get rule after revoke: %v", err)
		}
		if updatedRule.Enabled {
			t.Error("expected rule to be disabled after revoke")
		}

		// Budgets should be deleted
		budgets, err := budgetRepo.ListByRuleID(ctx, ruleID)
		if err != nil {
			t.Fatalf("failed to list budgets: %v", err)
		}
		if len(budgets) != 0 {
			t.Errorf("expected 0 budgets after revoke, got %d", len(budgets))
		}
	})

	t.Run("cannot_revoke_non_instance_rule", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		ruleID := types.RuleID("rule-api-1")
		rule := &types.Rule{
			ID:        ruleID,
			Name:      "API Rule",
			Source:    types.RuleSourceAPI,
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		seedRule(t, ruleRepo, rule)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		err = svc.RevokeInstance(ctx, ruleID)
		if err == nil {
			t.Fatal("expected error when revoking non-instance rule")
		}
		if !strings.Contains(err.Error(), "not an instance") {
			t.Errorf("error should mention 'not an instance', got: %v", err)
		}

		// Rule should remain enabled (no mutation)
		unchanged, _ := ruleRepo.Get(ctx, ruleID)
		if !unchanged.Enabled {
			t.Error("rule should remain enabled after failed revoke")
		}
	})

	t.Run("cannot_revoke_config_source_rule", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		ruleID := types.RuleID("rule-cfg-1")
		rule := &types.Rule{
			ID:        ruleID,
			Name:      "Config Rule",
			Source:    types.RuleSourceConfig,
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		seedRule(t, ruleRepo, rule)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		err = svc.RevokeInstance(ctx, ruleID)
		if err == nil {
			t.Fatal("expected error when revoking config-source rule")
		}
		if !strings.Contains(err.Error(), "not an instance") {
			t.Errorf("error should mention 'not an instance', got: %v", err)
		}
	})

	t.Run("rule_not_found_returns_error", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		err = svc.RevokeInstance(ctx, types.RuleID("nonexistent"))
		if err == nil {
			t.Fatal("expected error for nonexistent rule")
		}
		if !strings.Contains(err.Error(), "failed to get rule") {
			t.Errorf("error should mention failure to get rule, got: %v", err)
		}
	})

	t.Run("revoke_instance_with_multiple_budgets", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		templateID := "tmpl-multi"
		ruleID := types.RuleID("inst_multi123")
		rule := &types.Rule{
			ID:         ruleID,
			Name:       "Multi Budget Instance",
			Source:     types.RuleSourceInstance,
			TemplateID: &templateID,
			Enabled:    true,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		seedRule(t, ruleRepo, rule)

		// Seed two budgets for the same rule
		for _, unit := range []string{"eth", "usdt"} {
			b := &types.RuleBudget{
				ID:       types.BudgetID(ruleID, unit),
				RuleID:   ruleID,
				Unit:     unit,
				MaxTotal: "100",
				MaxPerTx: "10",
				Spent:    "0",
			}
			if err := budgetRepo.Create(ctx, b); err != nil {
				t.Fatalf("failed to seed budget: %v", err)
			}
		}

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		err = svc.RevokeInstance(ctx, ruleID)
		if err != nil {
			t.Fatalf("RevokeInstance failed: %v", err)
		}

		// All budgets should be deleted
		budgets, err := budgetRepo.ListByRuleID(ctx, ruleID)
		if err != nil {
			t.Fatalf("failed to list budgets: %v", err)
		}
		if len(budgets) != 0 {
			t.Errorf("expected 0 budgets after revoke, got %d", len(budgets))
		}
	})
}

// ---------------------------------------------------------------------------
// TestValidateVariableType_Extended
// ---------------------------------------------------------------------------

func TestValidateVariableType_Extended(t *testing.T) {
	ctx := context.Background()

	t.Run("address_list_valid", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "addrs", Type: "address_list", Required: true},
		}
		config := []byte(`{"addresses":"${addrs}"}`)
		tmpl := makeTemplate("tmpl-addrlist", "Address List", vars, config)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-addrlist",
			Variables: map[string]string{
				"addrs": "0x1111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222",
			},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Rule == nil {
			t.Fatal("expected non-nil rule")
		}
	})

	t.Run("address_list_invalid", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "addrs", Type: "address_list", Required: true},
		}
		config := []byte(`{"addresses":"${addrs}"}`)
		tmpl := makeTemplate("tmpl-addrlist-inv", "Invalid Address List", vars, config)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-addrlist-inv",
			Variables: map[string]string{
				"addrs": "0x1111111111111111111111111111111111111111,not-an-address",
			},
		})
		if err == nil {
			t.Fatal("expected error for invalid address in list")
		}
		if !strings.Contains(err.Error(), "invalid address in list") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("uint256_list_valid", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "amounts", Type: "uint256_list", Required: true},
		}
		config := []byte(`{"amounts":"${amounts}"}`)
		tmpl := makeTemplate("tmpl-uintlist", "Uint256 List", vars, config)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-uintlist",
			Variables: map[string]string{
				"amounts": "100,200,300",
			},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Rule == nil {
			t.Fatal("expected non-nil rule")
		}
	})

	t.Run("uint256_list_invalid", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "amounts", Type: "uint256_list", Required: true},
		}
		config := []byte(`{"amounts":"${amounts}"}`)
		tmpl := makeTemplate("tmpl-uintlist-inv", "Invalid Uint256 List", vars, config)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-uintlist-inv",
			Variables: map[string]string{
				"amounts": "100,not-a-number,300",
			},
		})
		if err == nil {
			t.Fatal("expected error for invalid uint256 in list")
		}
		if !strings.Contains(err.Error(), "invalid uint256 in list") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("string_type_accepts_anything", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "label", Type: "string", Required: true},
		}
		config := []byte(`{"label":"${label}"}`)
		tmpl := makeTemplate("tmpl-string", "String Var", vars, config)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-string",
			Variables: map[string]string{
				"label": "any arbitrary string !@#$%",
			},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Rule == nil {
			t.Fatal("expected non-nil rule")
		}
	})

	t.Run("unknown_type_skips_validation", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "custom", Type: "unknown_custom_type", Required: true},
		}
		config := []byte(`{"custom":"${custom}"}`)
		tmpl := makeTemplate("tmpl-unknown", "Unknown Type", vars, config)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-unknown",
			Variables: map[string]string{
				"custom": "whatever value",
			},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Rule == nil {
			t.Fatal("expected non-nil rule")
		}
	})

	t.Run("uppercase_0X_prefix_address", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "addr", Type: "address", Required: true},
		}
		config := []byte(`{"address":"${addr}"}`)
		tmpl := makeTemplate("tmpl-0X", "Uppercase 0X", vars, config)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-0X",
			Variables: map[string]string{
				"addr": "0XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Rule == nil {
			t.Fatal("expected non-nil rule")
		}
	})

	t.Run("address_wrong_length", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "addr", Type: "address", Required: true},
		}
		config := []byte(`{"address":"${addr}"}`)
		tmpl := makeTemplate("tmpl-short", "Short Address", vars, config)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-short",
			Variables: map[string]string{
				"addr": "0x1234", // too short
			},
		})
		if err == nil {
			t.Fatal("expected error for short address")
		}
	})

	t.Run("address_invalid_hex_chars", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "addr", Type: "address", Required: true},
		}
		config := []byte(`{"address":"${addr}"}`)
		tmpl := makeTemplate("tmpl-badhex", "Bad Hex", vars, config)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-badhex",
			Variables: map[string]string{
				"addr": "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG", // 40 chars but invalid hex
			},
		})
		if err == nil {
			t.Fatal("expected error for invalid hex characters")
		}
	})

	t.Run("uint256_negative_value", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "amount", Type: "uint256", Required: true},
		}
		config := []byte(`{"amount":"${amount}"}`)
		tmpl := makeTemplate("tmpl-neg", "Negative Uint", vars, config)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-neg",
			Variables: map[string]string{
				"amount": "-1",
			},
		})
		if err == nil {
			t.Fatal("expected error for negative uint256")
		}
	})

	t.Run("uint256_empty_string", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "amount", Type: "uint256", Required: true},
		}
		config := []byte(`{"amount":"${amount}"}`)
		tmpl := makeTemplate("tmpl-empty-uint", "Empty Uint", vars, config)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-empty-uint",
			Variables: map[string]string{
				"amount": "",
			},
		})
		if err == nil {
			t.Fatal("expected error for empty uint256")
		}
	})

	t.Run("address_no_0x_prefix", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "addr", Type: "address", Required: true},
		}
		config := []byte(`{"address":"${addr}"}`)
		tmpl := makeTemplate("tmpl-noprefix", "No Prefix", vars, config)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-noprefix",
			Variables: map[string]string{
				"addr": "1111111111111111111111111111111111111111", // missing 0x prefix
			},
		})
		if err == nil {
			t.Fatal("expected error for address without 0x prefix")
		}
	})
}
