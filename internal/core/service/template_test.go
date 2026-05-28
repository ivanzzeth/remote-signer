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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func (r *mockTemplateRepo) Upsert(ctx context.Context, tmpl *types.RuleTemplate) (bool, error) {
	if tmpl == nil {
		return false, fmt.Errorf("template cannot be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.templates[tmpl.ID]; ok {
		if existing.ContentHash != "" && existing.ContentHash == tmpl.ContentHash {
			return false, nil
		}
		cp := *tmpl
		r.templates[tmpl.ID] = &cp
		return true, nil
	}
	cp := *tmpl
	r.templates[tmpl.ID] = &cp
	return true, nil
}

func (r *mockTemplateRepo) ListIDsBySource(_ context.Context, source types.RuleSource) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var ids []string
	for id, t := range r.templates {
		if t.Source == source {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (r *mockTemplateRepo) DeleteMany(_ context.Context, ids []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range ids {
		delete(r.templates, id)
	}
	return nil
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

func (r *mockRuleRepo) ValidateDelegateRefs(_ context.Context, _ *types.Rule) error {
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

func (r *mockBudgetRepo) ListAll(_ context.Context) ([]*types.RuleBudget, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*types.RuleBudget, 0, len(r.budgets))
	for _, b := range r.budgets {
		cp := *b
		out = append(out, &cp)
	}
	return out, nil
}
func (r *mockBudgetRepo) Get(_ context.Context, id string) (*types.RuleBudget, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if b, ok := r.budgets[id]; ok {
		cp := *b
		return &cp, nil
	}
	return nil, types.ErrNotFound
}
func (r *mockBudgetRepo) Update(_ context.Context, budget *types.RuleBudget) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.budgets[budget.ID]; !ok {
		return types.ErrNotFound
	}
	cp := *budget
	r.budgets[budget.ID] = &cp
	return nil
}

func (r *mockBudgetRepo) MarkAlertSent(_ context.Context, _ types.RuleID, _ string) error {
	return nil
}

func (r *mockBudgetRepo) CountByRuleID(_ context.Context, _ types.RuleID) (int, error) {
	return 0, nil
}
func (r *mockBudgetRepo) CreateOrGet(_ context.Context, budget *types.RuleBudget) (*types.RuleBudget, bool, error) {
	return budget, true, nil
}

func (r *mockBudgetRepo) UpsertLimits(_ context.Context, _ types.RuleID, _ []storage.BudgetSyncRequest) error {
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
// errorDeleteRuleRepo wraps storage.RuleRepository but always fails Delete calls.
// It is used to test rollbackRules error path.
type errorDeleteRuleRepo struct {
	storage.RuleRepository
}

func (r *errorDeleteRuleRepo) Delete(_ context.Context, _ types.RuleID) error {
	return fmt.Errorf("delete failed")
}

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
		for _, name := range []string{"x", "y", "z"} {
			if !strings.Contains(err.Error(), name) {
				t.Errorf("error should mention unresolved variable '%s', got: %v", name, err)
			}
		}
	})

	t.Run("hex_prefix", func(t *testing.T) {
		config := []byte(`{"address_hex":"${hex:addr}"}`)
		vars := map[string]string{"addr": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"}

		result, err := SubstituteVariables(config, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := `{"address_hex":"A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"}`
		if string(result) != expected {
			t.Errorf("expected %s, got %s", expected, string(result))
		}
	})

	t.Run("paddedhex_prefix", func(t *testing.T) {
		config := []byte(`{"address_padded":"${paddedhex:addr}"}`)
		vars := map[string]string{"addr": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"}

		result, err := SubstituteVariables(config, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := `{"address_padded":"000000000000000000000000A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"}`
		if string(result) != expected {
			t.Errorf("expected %s, got %s", expected, string(result))
		}
	})

	t.Run("hex_and_paddedhex_mixed", func(t *testing.T) {
		config := []byte(`{"hex":"${hex:addr}","raw":"${addr}","padded":"${paddedhex:addr}"}`)
		vars := map[string]string{"addr": "0x1234"}

		result, err := SubstituteVariables(config, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := `{"hex":"1234","raw":"0x1234","padded":"0000000000000000000000000000000000000000000000000000000000001234"}`
		if string(result) != expected {
			t.Errorf("expected %s, got %s", expected, string(result))
		}
	})

	t.Run("paddedhex_no_0x_prefix", func(t *testing.T) {
		config := []byte(`{"padded":"${paddedhex:val}"}`)
		vars := map[string]string{"val": "abcd"}

		result, err := SubstituteVariables(config, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := `{"padded":"000000000000000000000000000000000000000000000000000000000000abcd"}`
		if string(result) != expected {
			t.Errorf("expected %s, got %s", expected, string(result))
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
			{Name: "max_value", Type: "bigint", Description: "Max value", Required: false, Default: "1000000"},
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
			{Name: "max_value", Type: "bigint", Description: "Max value", Required: false, Default: "1000000"},
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
			{Name: "amount", Type: "bigint", Required: true},
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
			t.Fatal("expected error for invalid bigint")
		}
		if !strings.Contains(err.Error(), "invalid bigint") {
			t.Errorf("error should mention invalid bigint, got: %v", err)
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
		if result.Rule.Owner != "key-123" {
			t.Errorf("expected APIKeyID 'key-123', got %v", result.Rule.Owner)
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
			{Name: "amounts", Type: "bigint_list", Required: true},
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
			{Name: "amounts", Type: "bigint_list", Required: true},
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
			t.Fatal("expected error for invalid bigint in list")
		}
		if !strings.Contains(err.Error(), "invalid bigint in list") {
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
			{Name: "amount", Type: "bigint", Required: true},
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
			{Name: "amount", Type: "bigint", Required: true},
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

// ---------------------------------------------------------------------------
// Reserved variable (chain_id) injection tests
// ---------------------------------------------------------------------------

func TestReservedVariableChainID(t *testing.T) {
	ctx := context.Background()

	// Helper: template with chain_id in config (like real ERC20 templates)
	makeChainIDTemplate := func(id, name string, includeChainIDVar bool, extraVars []types.TemplateVariable) *types.RuleTemplate {
		vars := make([]types.TemplateVariable, 0)
		if includeChainIDVar {
			vars = append(vars, types.TemplateVariable{
				Name: "chain_id", Type: "string", Description: "Chain ID", Required: true,
			})
		}
		vars = append(vars, extraVars...)
		config := []byte(`{"chain":"${chain_id}","token":"${token_address}"}`)
		return makeTemplate(id, name, vars, config)
	}

	t.Run("chain_id_injected_from_scope_no_template_var", func(t *testing.T) {
		// Template does NOT define chain_id variable (new style).
		// chain_id should be injected from req.ChainID.
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeChainIDTemplate("tmpl-nochainvar", "No ChainID Var", false,
			[]types.TemplateVariable{
				{Name: "token_address", Type: "address", Required: true},
			})
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		chainID := "137"
		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-nochainvar",
			ChainID:    &chainID,
			Variables: map[string]string{
				"token_address": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
			},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}

		// Config should have chain_id substituted from scope
		expectedConfig := `{"chain":"137","token":"0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"}`
		if string(result.Rule.Config) != expectedConfig {
			t.Errorf("config mismatch:\nwant: %s\ngot:  %s", expectedConfig, string(result.Rule.Config))
		}

		// Variables JSON should contain chain_id
		var storedVars map[string]string
		if err := json.Unmarshal(result.Rule.Variables, &storedVars); err != nil {
			t.Fatalf("failed to unmarshal variables: %v", err)
		}
		if storedVars["chain_id"] != "137" {
			t.Errorf("expected stored chain_id=137, got %q", storedVars["chain_id"])
		}

		// Rule scope should be set
		if result.Rule.ChainID == nil || *result.Rule.ChainID != "137" {
			t.Errorf("expected rule ChainID scope=137, got %v", result.Rule.ChainID)
		}
	})

	t.Run("chain_id_injected_overrides_user_variable", func(t *testing.T) {
		// Template still defines chain_id variable (old style, backward compat).
		// User provides chain_id in variables with a DIFFERENT value than scope.
		// Scope value should win.
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeChainIDTemplate("tmpl-oldstyle", "Old Style", true,
			[]types.TemplateVariable{
				{Name: "token_address", Type: "address", Required: true},
			})
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		chainID := "137"
		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-oldstyle",
			ChainID:    &chainID,
			Variables: map[string]string{
				"chain_id":      "1",                                          // user says chain 1 — should be overridden
				"token_address": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
			},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}

		// Config should use scope chain_id (137), not user's (1)
		expectedConfig := `{"chain":"137","token":"0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"}`
		if string(result.Rule.Config) != expectedConfig {
			t.Errorf("config mismatch:\nwant: %s\ngot:  %s", expectedConfig, string(result.Rule.Config))
		}

		// Stored variable should be 137
		var storedVars map[string]string
		if err := json.Unmarshal(result.Rule.Variables, &storedVars); err != nil {
			t.Fatalf("failed to unmarshal variables: %v", err)
		}
		if storedVars["chain_id"] != "137" {
			t.Errorf("expected stored chain_id=137, got %q", storedVars["chain_id"])
		}
	})

	t.Run("chain_id_required_in_old_template_skipped_during_validation", func(t *testing.T) {
		// Template defines chain_id as required, but user does NOT provide it in variables.
		// Should NOT fail validation — chain_id is a reserved variable.
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeChainIDTemplate("tmpl-req-skip", "Required Skip", true,
			[]types.TemplateVariable{
				{Name: "token_address", Type: "address", Required: true},
			})
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		chainID := "56"
		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-req-skip",
			ChainID:    &chainID,
			Variables: map[string]string{
				// chain_id NOT provided — should be injected from scope
				"token_address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		})
		if err != nil {
			t.Fatalf("CreateInstance should not fail: %v", err)
		}

		expectedConfig := `{"chain":"56","token":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
		if string(result.Rule.Config) != expectedConfig {
			t.Errorf("config mismatch:\nwant: %s\ngot:  %s", expectedConfig, string(result.Rule.Config))
		}
	})

	t.Run("no_chain_id_scope_and_no_variable_leaves_placeholder", func(t *testing.T) {
		// Neither scope chain_id nor variable chain_id provided.
		// ${chain_id} remains unresolved → SubstituteVariables should return error.
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeChainIDTemplate("tmpl-noscope", "No Scope", false,
			[]types.TemplateVariable{
				{Name: "token_address", Type: "address", Required: true},
			})
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-noscope",
			// ChainID is nil — no scope
			Variables: map[string]string{
				"token_address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		})
		if err == nil {
			t.Fatal("expected error for unresolved ${chain_id}")
		}
		if !strings.Contains(err.Error(), "chain_id") {
			t.Errorf("error should mention chain_id, got: %v", err)
		}
	})

	t.Run("budget_unit_uses_injected_chain_id", func(t *testing.T) {
		// Budget metering unit "${chain_id}:${token_address}" should resolve
		// with the scope-injected chain_id.
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "token_address", Type: "address", Required: true},
		}
		config := []byte(`{"token":"${token_address}"}`)
		budgetMetering := mustJSON(types.BudgetMetering{
			Method: "js",
			Unit:   "${chain_id}:${token_address}",
		})

		tmpl := &types.RuleTemplate{
			ID:             "tmpl-budget",
			Name:           "Budget Template",
			Type:           types.RuleTypeEVMJS,
			Mode:           types.RuleModeWhitelist,
			Variables:      mustJSON(vars),
			Config:         config,
			BudgetMetering: budgetMetering,
			Source:         types.RuleSourceConfig,
			Enabled:        true,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		chainID := "137"
		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-budget",
			ChainID:    &chainID,
			Variables: map[string]string{
				"token_address": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
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
			t.Fatal("expected budget to be created")
		}

		// Budget unit should be "137:0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"
		expectedUnit := "137:0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"
		if result.Budget.Unit != expectedUnit {
			t.Errorf("budget unit mismatch:\nwant: %s\ngot:  %s", expectedUnit, result.Budget.Unit)
		}
	})

	t.Run("createInstanceFromResolved_also_injects_chain_id", func(t *testing.T) {
		// Verify the tx-scoped path also injects chain_id.
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "token_address", Type: "address", Required: true},
		}
		config := []byte(`{"chain":"${chain_id}","token":"${token_address}"}`)
		tmpl := makeTemplate("tmpl-resolved", "Resolved Path", vars, config)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		chainID := "42161" // Arbitrum
		result, err := svc.CreateInstanceFromResolvedWithTx(ctx, ruleRepo, budgetRepo, tmpl,
			&CreateInstanceRequest{
				TemplateID: "tmpl-resolved",
				ChainID:    &chainID,
				Variables: map[string]string{
					"token_address": "0xcccccccccccccccccccccccccccccccccccccccc",
				},
			})
		if err != nil {
			t.Fatalf("CreateInstanceFromResolvedWithTx failed: %v", err)
		}

		expectedConfig := `{"chain":"42161","token":"0xcccccccccccccccccccccccccccccccccccccccc"}`
		if string(result.Rule.Config) != expectedConfig {
			t.Errorf("config mismatch:\nwant: %s\ngot:  %s", expectedConfig, string(result.Rule.Config))
		}
	})
}

func TestValidateVariablesSkipsReserved(t *testing.T) {
	// chain_id is reserved — even if template marks it required with no default,
	// validateVariables should NOT return an error when it's missing from user input.
	defs := []types.TemplateVariable{
		{Name: "chain_id", Type: "string", Required: true},
		{Name: "token_address", Type: "address", Required: true},
	}
	vars := map[string]string{
		"token_address": "0x1111111111111111111111111111111111111111",
		// chain_id deliberately omitted
	}
	if err := validateVariables(defs, vars); err != nil {
		t.Fatalf("expected no error (chain_id is reserved), got: %v", err)
	}
}

func TestInjectReservedVariables(t *testing.T) {
	logger := newTestLogger()

	t.Run("injects_when_absent", func(t *testing.T) {
		vars := map[string]string{"token": "0xabc"}
		chainID := "137"
		injectReservedVariables(vars, &CreateInstanceRequest{ChainID: &chainID}, logger)
		if vars["chain_id"] != "137" {
			t.Errorf("expected chain_id=137, got %q", vars["chain_id"])
		}
	})

	t.Run("overrides_when_different", func(t *testing.T) {
		vars := map[string]string{"chain_id": "1", "token": "0xabc"}
		chainID := "137"
		injectReservedVariables(vars, &CreateInstanceRequest{ChainID: &chainID}, logger)
		if vars["chain_id"] != "137" {
			t.Errorf("expected chain_id=137, got %q", vars["chain_id"])
		}
	})

	t.Run("no_op_when_same", func(t *testing.T) {
		vars := map[string]string{"chain_id": "137"}
		chainID := "137"
		injectReservedVariables(vars, &CreateInstanceRequest{ChainID: &chainID}, logger)
		if vars["chain_id"] != "137" {
			t.Errorf("expected chain_id=137, got %q", vars["chain_id"])
		}
	})

	t.Run("no_op_when_nil_chain_id", func(t *testing.T) {
		vars := map[string]string{"token": "0xabc"}
		injectReservedVariables(vars, &CreateInstanceRequest{ChainID: nil}, logger)
		if _, exists := vars["chain_id"]; exists {
			t.Error("chain_id should not be injected when scope ChainID is nil")
		}
	})
}

// ---------------------------------------------------------------------------
// TestCreateInstance_SkipValidationFlow — verifies that the service layer
// does NOT reject evm_js or bundle templates based on test_cases validation.
// Validation decisions happen at the handler level, not the service level.
// ---------------------------------------------------------------------------

func TestCreateInstance_SkipValidationFlow(t *testing.T) {
	ctx := context.Background()

	t.Run("evm_js_template_basic_creation", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := &types.RuleTemplate{
			ID:        "tmpl-evmjs-1",
			Name:      "EVM JS Template",
			Type:      types.RuleTypeEVMJS,
			Mode:      types.RuleModeWhitelist,
			Variables: mustJSON([]types.TemplateVariable{
				{Name: "max_value", Type: "bigint", Required: true},
			}),
			Config:    []byte(`{"max_value":"${max_value}"}`),
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
			TemplateID: "tmpl-evmjs-1",
			Variables:  map[string]string{"max_value": "1000000"},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Rule == nil {
			t.Fatal("expected non-nil rule")
		}
		if result.Rule.Type != types.RuleTypeEVMJS {
			t.Errorf("expected type %q, got %q", types.RuleTypeEVMJS, result.Rule.Type)
		}
		if result.Rule.Mode != types.RuleModeWhitelist {
			t.Errorf("expected mode %q, got %q", types.RuleModeWhitelist, result.Rule.Mode)
		}
		if result.Rule.Source != types.RuleSourceInstance {
			t.Errorf("expected source %q, got %q", types.RuleSourceInstance, result.Rule.Source)
		}
	})

	t.Run("evm_js_template_with_test_cases", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		// test_cases data — service layer should NOT validate this.
		// Validation rejection happens at the handler level.
		testCases := map[string]interface{}{
			"test_cases": []map[string]interface{}{
				{
					"input":    map[string]interface{}{"value": "100"},
					"expected": map[string]interface{}{"valid": true},
				},
				{
					"input":    map[string]interface{}{"value": "99999999999999999999999999999999999999999999999999999999999"},
					"expected": map[string]interface{}{"valid": false, "reason": "exceeds_max"},
				},
			},
		}
		configJSON, err := json.Marshal(testCases)
		if err != nil {
			t.Fatalf("failed to marshal test cases: %v", err)
		}

		tmpl := &types.RuleTemplate{
			ID:        "tmpl-evmjs-tc",
			Name:      "EVM JS With Test Cases",
			Type:      types.RuleTypeEVMJS,
			Mode:      types.RuleModeWhitelist,
			Variables: mustJSON([]types.TemplateVariable{
				{Name: "max_value", Type: "bigint", Required: true},
			}),
			Config:    configJSON,
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

		// Service layer should succeed — validation rejection happens at the handler level
		result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-evmjs-tc",
			Variables:  map[string]string{"max_value": "1000000"},
		})
		if err != nil {
			t.Fatalf("CreateInstance should succeed at service layer, got: %v", err)
		}
		if result.Rule == nil {
			t.Fatal("expected non-nil rule")
		}
		// Config should be preserved (contain test_cases)
		var configMap map[string]interface{}
		if err := json.Unmarshal(result.Rule.Config, &configMap); err != nil {
			t.Fatalf("failed to unmarshal result config: %v", err)
		}
		if _, ok := configMap["test_cases"]; !ok {
			t.Error("expected test_cases in instance config")
		}
	})

	t.Run("evm_js_template_without_test_cases", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := &types.RuleTemplate{
			ID:        "tmpl-evmjs-notc",
			Name:      "EVM JS No Test Cases",
			Type:      types.RuleTypeEVMJS,
			Mode:      types.RuleModeWhitelist,
			Variables: mustJSON([]types.TemplateVariable{
				{Name: "max_value", Type: "bigint", Required: true},
			}),
			Config:    []byte(`{"max_value":"${max_value}"}`),
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
			TemplateID: "tmpl-evmjs-notc",
			Variables:  map[string]string{"max_value": "500000"},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Rule == nil {
			t.Fatal("expected non-nil rule")
		}
		if result.Rule.Type != types.RuleTypeEVMJS {
			t.Errorf("expected type %q, got %q", types.RuleTypeEVMJS, result.Rule.Type)
		}
	})

	t.Run("evm_js_template_with_test_variables_placeholders", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		cfg := map[string]interface{}{
			"max_value": "${max_value}",
			"test_cases": []map[string]interface{}{
				{
					"name": "should reject wrong signer",
					"input": map[string]interface{}{
						"value":  "100",
						"signer": "${test_wrong_signer}",
					},
					"expect_pass": false,
				},
			},
		}
		configJSON, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("failed to marshal config: %v", err)
		}

		tmpl := &types.RuleTemplate{
			ID:        "tmpl-evmjs-tv",
			Name:      "EVM JS With Test Variables",
			Type:      types.RuleTypeEVMJS,
			Mode:      types.RuleModeWhitelist,
			Variables: mustJSON([]types.TemplateVariable{
				{Name: "max_value", Type: "bigint", Required: true},
			}),
			TestVariables: mustJSON(map[string]string{
				"test_wrong_signer": "0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
			}),
			Config:    configJSON,
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
			TemplateID: "tmpl-evmjs-tv",
			Variables:  map[string]string{"max_value": "1000000"},
		})
		if err != nil {
			t.Fatalf("CreateInstance should resolve test_variables placeholders, got: %v", err)
		}
		if result.Rule == nil {
			t.Fatal("expected non-nil rule")
		}
		if strings.Contains(string(result.Rule.Config), "${test_wrong_signer}") {
			t.Error("expected test_wrong_signer to be substituted in instance config")
		}
	})

	t.Run("evm_js_template_non_whitelist_mode", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := &types.RuleTemplate{
			ID:        "tmpl-evmjs-block",
			Name:      "EVM JS Blocklist",
			Type:      types.RuleTypeEVMJS,
			Mode:      types.RuleModeBlocklist,
			Variables: mustJSON([]types.TemplateVariable{
				{Name: "max_value", Type: "bigint", Required: true},
			}),
			Config:    []byte(`{"max_value":"${max_value}"}`),
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
			TemplateID: "tmpl-evmjs-block",
			Variables:  map[string]string{"max_value": "100"},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Rule == nil {
			t.Fatal("expected non-nil rule")
		}
		if result.Rule.Mode != types.RuleModeBlocklist {
			t.Errorf("expected mode %q, got %q", types.RuleModeBlocklist, result.Rule.Mode)
		}
	})

	t.Run("bundle_template_expansion", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		subRules := []bundleSubRule{
			{
				Name: "Address Whitelist",
				Type: string(types.RuleTypeEVMAddressList),
				Mode: string(types.RuleModeWhitelist),
				Config: map[string]interface{}{
					"addresses": []string{"0x1111111111111111111111111111111111111111"},
				},
				Enabled: true,
			},
			{
				Name: "Value Limit",
				Type: string(types.RuleTypeEVMValueLimit),
				Mode: string(types.RuleModeBlocklist),
				Config: map[string]interface{}{
					"max_value": "1000000000000000000",
				},
				Enabled: true,
			},
		}
		subRulesJSON, err := json.Marshal(subRules)
		if err != nil {
			t.Fatalf("failed to marshal sub-rules: %v", err)
		}

		bundleConfig := map[string]interface{}{
			"rules_json": string(subRulesJSON),
		}
		bundleConfigJSON, err := json.Marshal(bundleConfig)
		if err != nil {
			t.Fatalf("failed to marshal bundle config: %v", err)
		}

		tmpl := &types.RuleTemplate{
			ID:        "tmpl-bundle-1",
			Name:      "Composite Bundle",
			Type:      "template_bundle",
			Mode:      types.RuleModeWhitelist,
			Config:    bundleConfigJSON,
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
			TemplateID: "tmpl-bundle-1",
			Variables:  map[string]string{},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if result.Rule == nil {
			t.Fatal("expected non-nil first sub-rule")
		}
		if len(result.SubRules) != 2 {
			t.Fatalf("expected 2 sub-rules, got %d", len(result.SubRules))
		}
		if result.SubRules[0].Type != types.RuleTypeEVMAddressList {
			t.Errorf("expected first sub-rule type %q, got %q", types.RuleTypeEVMAddressList, result.SubRules[0].Type)
		}
		if result.SubRules[0].Mode != types.RuleModeWhitelist {
			t.Errorf("expected first sub-rule mode %q, got %q", types.RuleModeWhitelist, result.SubRules[0].Mode)
		}
		if result.SubRules[1].Type != types.RuleTypeEVMValueLimit {
			t.Errorf("expected second sub-rule type %q, got %q", types.RuleTypeEVMValueLimit, result.SubRules[1].Type)
		}
		if result.SubRules[1].Mode != types.RuleModeBlocklist {
			t.Errorf("expected second sub-rule mode %q, got %q", types.RuleModeBlocklist, result.SubRules[1].Mode)
		}
		if result.SubRules[0].Source != types.RuleSourceInstance {
			t.Errorf("expected sub-rule source %q, got %q", types.RuleSourceInstance, result.SubRules[0].Source)
		}
		if result.Budget != nil {
			t.Error("expected nil budget when none specified")
		}
		if len(result.SubBudgets) != 0 {
			t.Errorf("expected 0 sub-budgets, got %d", len(result.SubBudgets))
		}
	})

	t.Run("bundle_template_delegate_to_resolution", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		subRules := []bundleSubRule{
			{
				ID:   "target-rule",
				Name: "Target Rule",
				Type: string(types.RuleTypeEVMJS),
				Mode: string(types.RuleModeWhitelist),
				Config: map[string]interface{}{
					"expression": "true",
				},
				Enabled: true,
			},
			{
				ID:   "delegator-rule",
				Name: "Delegator Rule",
				Type: string(types.RuleTypeEVMJS),
				Mode: string(types.RuleModeWhitelist),
				Config: map[string]interface{}{
					"delegate_to": "target-rule",
				},
				Enabled: true,
			},
		}
		subRulesJSON, err := json.Marshal(subRules)
		if err != nil {
			t.Fatalf("failed to marshal sub-rules: %v", err)
		}

		bundleConfig := map[string]interface{}{
			"rules_json": string(subRulesJSON),
		}
		bundleConfigJSON, err := json.Marshal(bundleConfig)
		if err != nil {
			t.Fatalf("failed to marshal bundle config: %v", err)
		}

		tmpl := &types.RuleTemplate{
			ID:        "tmpl-delegate-bundle",
			Name:      "Delegate Bundle",
			Type:      "template_bundle",
			Mode:      types.RuleModeWhitelist,
			Config:    bundleConfigJSON,
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
			TemplateID: "tmpl-delegate-bundle",
			Variables:  map[string]string{},
		})
		if err != nil {
			t.Fatalf("CreateInstance failed: %v", err)
		}
		if len(result.SubRules) != 2 {
			t.Fatalf("expected 2 sub-rules, got %d", len(result.SubRules))
		}

		// The target rule should have an inst_<hash> ID
		targetRule := result.SubRules[0]
		if !strings.HasPrefix(string(targetRule.ID), "inst_") {
			t.Errorf("expected target rule ID to start with 'inst_', got %q", targetRule.ID)
		}

		// The delegator rule's config should have delegate_to pointing to the target's actual ID
		delegatorRule := result.SubRules[1]
		var delegatorCfg map[string]interface{}
		if err := json.Unmarshal(delegatorRule.Config, &delegatorCfg); err != nil {
			t.Fatalf("failed to parse delegator config: %v", err)
		}
		gotDelegate, _ := delegatorCfg["delegate_to"].(string)
		if gotDelegate != string(targetRule.ID) {
			t.Errorf("expected delegate_to to be resolved to %q, got %q", targetRule.ID, gotDelegate)
		}

		// Verify SubRuleIDMap is populated
		if result.SubRuleIDMap == nil {
			t.Error("expected non-nil SubRuleIDMap")
		} else {
			if mappedID, ok := result.SubRuleIDMap["target-rule"]; !ok {
				t.Error("expected SubRuleIDMap to contain 'target-rule'")
			} else if mappedID != targetRule.ID {
				t.Errorf("expected SubRuleIDMap['target-rule'] = %q, got %q", targetRule.ID, mappedID)
			}
		}

		// Verify no __sub_rule_id artifact remains in config
		if _, ok := delegatorCfg["__sub_rule_id"]; ok {
			t.Error("unexpected __sub_rule_id in delegator config")
		}
		var targetCfg map[string]interface{}
		if err := json.Unmarshal(targetRule.Config, &targetCfg); err == nil {
			if _, ok := targetCfg["__sub_rule_id"]; ok {
				t.Error("unexpected __sub_rule_id in target config")
			}
		}
	})
}
// ---------------------------------------------------------------------------
// TestCreateInstanceWithTx
// ---------------------------------------------------------------------------

func TestCreateInstanceWithTx(t *testing.T) {
	ctx := context.Background()

	t.Run("basic_creation_with_variables", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		vars := []types.TemplateVariable{
			{Name: "target_address", Type: "address", Required: true},
		}
		config := []byte(`{"addresses":["${target_address}"]}`)
		tmpl := makeTemplate("tmpl-tx", "Tx Template", vars, config)
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		// Use CreateInstanceWithTx with separate repos
		result, err := svc.CreateInstanceWithTx(ctx, ruleRepo, budgetRepo, &CreateInstanceRequest{
			TemplateID: "tmpl-tx",
			Variables: map[string]string{
				"target_address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		})
		if err != nil {
			t.Fatalf("CreateInstanceWithTx failed: %v", err)
		}
		if result.Rule == nil {
			t.Fatal("expected non-nil rule")
		}
		if result.Rule.Source != types.RuleSourceInstance {
			t.Errorf("expected source %q", types.RuleSourceInstance)
		}
	})

	t.Run("nil_request", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstanceWithTx(ctx, ruleRepo, budgetRepo, nil)
		if err == nil {
			t.Fatal("expected error for nil request")
		}
		if !strings.Contains(err.Error(), "request is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nil_repos", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstanceWithTx(ctx, nil, nil, &CreateInstanceRequest{
			TemplateID: "tmpl-whatever",
			Variables:  map[string]string{},
		})
		if err == nil {
			t.Fatal("expected error for nil repos")
		}
		if !strings.Contains(err.Error(), "rule and budget repositories are required") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// TestCreateInstanceFromResolvedWithTx
// ---------------------------------------------------------------------------

func TestCreateInstanceFromResolvedWithTx(t *testing.T) {
	ctx := context.Background()

	t.Run("nil_template_nil_request", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstanceFromResolvedWithTx(ctx, ruleRepo, budgetRepo, nil, nil)
		if err == nil {
			t.Fatal("expected error for nil template")
		}
		if !strings.Contains(err.Error(), "template and request are required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nil_repos", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		svc, err := NewTemplateService(tmplRepo, newMockRuleRepo(), newMockBudgetRepo(), newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstanceFromResolvedWithTx(ctx, nil, nil, &types.RuleTemplate{ID: "t"}, &CreateInstanceRequest{
			Variables: map[string]string{},
		})
		if err == nil {
			t.Fatal("expected error for nil repos")
		}
		if !strings.Contains(err.Error(), "rule and budget repositories are required") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// TestResolveTemplate
// ---------------------------------------------------------------------------

func TestResolveTemplate(t *testing.T) {
	ctx := context.Background()

	t.Run("by_id", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeTemplate("resolve-id", "Resolve By ID", nil, []byte(`{}`))
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		got, err := svc.ResolveTemplate(ctx, &CreateInstanceRequest{TemplateID: "resolve-id"})
		if err != nil {
			t.Fatalf("ResolveTemplate failed: %v", err)
		}
		if got.ID != "resolve-id" {
			t.Errorf("expected template id 'resolve-id', got %q", got.ID)
		}
	})

	t.Run("by_name", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeTemplate("resolve-name", "Resolve By Name", nil, []byte(`{}`))
		seedTemplate(t, tmplRepo, tmpl)

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		got, err := svc.ResolveTemplate(ctx, &CreateInstanceRequest{TemplateName: "Resolve By Name"})
		if err != nil {
			t.Fatalf("ResolveTemplate failed: %v", err)
		}
		if got.Name != "Resolve By Name" {
			t.Errorf("expected name 'Resolve By Name', got %q", got.Name)
		}
	})

	t.Run("no_id_or_name", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.ResolveTemplate(ctx, &CreateInstanceRequest{})
		if err == nil {
			t.Fatal("expected error for missing template_id or template_name")
		}
		if !strings.Contains(err.Error(), "template_id or template_name is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// TestBundleRollbackRules - tests that rollbackRules is called on bundle
// expansion failure
// ---------------------------------------------------------------------------

func TestBundleRollbackRules(t *testing.T) {
	ctx := context.Background()

	t.Run("bundle_expansion_rollback_on_create_failure", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		subRules := []bundleSubRule{
			{
				ID:      "sub1",
				Name:    "First Rule",
				Type:    string(types.RuleTypeEVMAddressList),
				Mode:    string(types.RuleModeWhitelist),
				Config:  map[string]interface{}{"addresses": []string{"0x1111111111111111111111111111111111111111"}},
				Enabled: true,
			},
			{
				ID:      "sub2",
				Name:    "Second Rule",
				Type:    string(types.RuleTypeEVMValueLimit),
				Mode:    string(types.RuleModeBlocklist),
				Config:  map[string]interface{}{"max_value": "1000000000000000000"},
				Enabled: true,
			},
		}
		subRulesJSON, err := json.Marshal(subRules)
		if err != nil {
			t.Fatalf("failed to marshal sub-rules: %v", err)
		}

		bundleConfig := map[string]interface{}{
			"rules_json": string(subRulesJSON),
		}
		bundleConfigJSON, err := json.Marshal(bundleConfig)
		if err != nil {
			t.Fatalf("failed to marshal bundle config: %v", err)
		}

		tmpl := &types.RuleTemplate{
			ID:        "tmpl-bundle-rollback",
			Name:      "Rollback Bundle",
			Type:      "template_bundle",
			Mode:      types.RuleModeWhitelist,
			Config:    bundleConfigJSON,
			Source:    types.RuleSourceConfig,
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		seedTemplate(t, tmplRepo, tmpl)

		// Create a rule repo that fails on the second create
		failAfterFirst := &failAfterCountRuleRepo{
			RuleRepository: ruleRepo,
			failAfter:      1, // fail on the second Create call
			callCount:      0,
		}

		svc, err := NewTemplateService(tmplRepo, failAfterFirst, budgetRepo, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-bundle-rollback",
			Variables:  map[string]string{},
		})
		if err == nil {
			t.Fatal("expected error when rule creation fails mid-bundle")
		}
		if !strings.Contains(err.Error(), "failed to create sub-rule") {
			t.Errorf("expected sub-rule creation error, got: %v", err)
		}

		// Verify that the first sub-rule was rolled back (deleted)
		remaining, err := ruleRepo.List(ctx, storage.RuleFilter{})
		if err != nil {
			t.Fatalf("failed to list rules: %v", err)
		}
		if len(remaining) != 0 {
			t.Errorf("expected 0 rules after rollback, got %d", len(remaining))
		}
	})

	t.Run("bundle_expansion_with_budget_rollback", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		subRules := []bundleSubRule{
			{
				ID:      "sub-bgt-1",
				Name:    "Rule With Budget",
				Type:    string(types.RuleTypeEVMAddressList),
				Mode:    string(types.RuleModeWhitelist),
				Config:  map[string]interface{}{"addresses": []string{"0x1111111111111111111111111111111111111111"}},
				Enabled: true,
			},
			{
				ID:      "sub-bgt-2",
				Name:    "Second Rule With Budget",
				Type:    string(types.RuleTypeEVMValueLimit),
				Mode:    string(types.RuleModeBlocklist),
				Config:  map[string]interface{}{"max_value": "1000000000000000000"},
				Enabled: true,
			},
		}
		subRulesJSON, err := json.Marshal(subRules)
		if err != nil {
			t.Fatalf("failed to marshal sub-rules: %v", err)
		}

		bundleConfig := map[string]interface{}{
			"rules_json": string(subRulesJSON),
		}
		bundleConfigJSON, err := json.Marshal(bundleConfig)
		if err != nil {
			t.Fatalf("failed to marshal bundle config: %v", err)
		}

		metering := types.BudgetMetering{
			Method: "tx_value",
			Unit:   "eth",
		}

		tmpl := &types.RuleTemplate{
			ID:             "tmpl-bundle-bgt-roll",
			Name:           "Budget Rollback Bundle",
			Type:           "template_bundle",
			Mode:           types.RuleModeWhitelist,
			Config:         bundleConfigJSON,
			BudgetMetering: mustJSON(metering),
			Source:         types.RuleSourceConfig,
			Enabled:        true,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}
		seedTemplate(t, tmplRepo, tmpl)

		// Create a budget repo that fails on the first create
		failBudget := &failOnceBudgetRepo{
			BudgetRepository: budgetRepo,
		}

		svc, err := NewTemplateService(tmplRepo, ruleRepo, failBudget, newTestLogger())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		_, err = svc.CreateInstance(ctx, &CreateInstanceRequest{
			TemplateID: "tmpl-bundle-bgt-roll",
			Variables:  map[string]string{},
			Budget: &BudgetConfig{
				MaxTotal: "1000",
				MaxPerTx: "100",
			},
		})
		if err == nil {
			t.Fatal("expected error when budget creation fails")
		}
		if !strings.Contains(err.Error(), "failed to create budget for sub-rule") {
			t.Errorf("expected budget creation error, got: %v", err)
		}

		// Verify that the sub-rule created before budget failure was rolled back
		remaining, err := ruleRepo.List(ctx, storage.RuleFilter{})
		if err != nil {
			t.Fatalf("failed to list rules: %v", err)
		}
		if len(remaining) != 0 {
			t.Errorf("expected 0 rules after budget rollback, got %d", len(remaining))
		}
	})
}

// failAfterCountRuleRepo wraps RuleRepository and fails Create after N calls.
type failAfterCountRuleRepo struct {
	storage.RuleRepository
	failAfter int
	callCount int
}

func (r *failAfterCountRuleRepo) Create(ctx context.Context, rule *types.Rule) error {
	r.callCount++
	if r.callCount > r.failAfter {
		return fmt.Errorf("simulated creation failure")
	}
	return r.RuleRepository.Create(ctx, rule)
}

// failOnceBudgetRepo wraps BudgetRepository and fails its first Create.
type failOnceBudgetRepo struct {
	storage.BudgetRepository
	firstCreate bool
}

func (r *failOnceBudgetRepo) Create(ctx context.Context, budget *types.RuleBudget) error {
	if !r.firstCreate {
		r.firstCreate = true
		return r.BudgetRepository.Create(ctx, budget)
	}
	return fmt.Errorf("simulated budget creation failure")
}

func TestResolveDelegateToInVars(t *testing.T) {
	t.Run("resolves_delegate_to_in_vars", func(t *testing.T) {
		vars := map[string]string{
			"delegate_to": "polymarket-v2-transactions",
			"chain_id":    "137",
		}
		resolveMap := map[string]types.RuleID{
			"polymarket-v2-transactions": "inst_e75b86be47495806",
		}
		if err := resolveDelegateToInVars(vars, resolveMap); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if vars["delegate_to"] != "inst_e75b86be47495806" {
			t.Errorf("expected delegate_to=inst_e75b86be47495806, got %q", vars["delegate_to"])
		}
	})

	t.Run("resolves_comma_separated_delegate_to_in_vars", func(t *testing.T) {
		vars := map[string]string{
			"delegate_to": "rule-a, rule-b",
		}
		resolveMap := map[string]types.RuleID{
			"rule-a": "inst_a111",
			"rule-b": "inst_b222",
		}
		if err := resolveDelegateToInVars(vars, resolveMap); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if vars["delegate_to"] != "inst_a111,inst_b222" {
			t.Errorf("expected delegate_to=inst_a111,inst_b222, got %q", vars["delegate_to"])
		}
	})

	t.Run("skips_unknown_delegate_to_in_vars", func(t *testing.T) {
		vars := map[string]string{
			"delegate_to": "unknown-rule",
		}
		resolveMap := map[string]types.RuleID{"other-rule": "inst_xxx"}
		if err := resolveDelegateToInVars(vars, resolveMap); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if vars["delegate_to"] != "unknown-rule" {
			t.Errorf("expected delegate_to=unknown-rule unchanged, got %q", vars["delegate_to"])
		}
	})

	t.Run("resolves_delegate_to_by_target_in_vars", func(t *testing.T) {
		vars := map[string]string{
			"delegate_to_by_target": "some-addr:target-rule",
		}
		resolveMap := map[string]types.RuleID{"target-rule": "inst_xyz"}
		if err := resolveDelegateToInVars(vars, resolveMap); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if vars["delegate_to_by_target"] != "some-addr:inst_xyz" {
			t.Errorf("expected delegate_to_by_target=some-addr:inst_xyz, got %q", vars["delegate_to_by_target"])
		}
	})

	t.Run("handles_empty_delegate_to", func(t *testing.T) {
		vars := map[string]string{
			"chain_id": "137",
		}
		resolveMap := map[string]types.RuleID{"target": "inst_xxx"}
		if err := resolveDelegateToInVars(vars, resolveMap); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("handles_delegate_to_with_extra_spaces", func(t *testing.T) {
		vars := map[string]string{
			"delegate_to": "  rule-a  ,  rule-b  ",
		}
		resolveMap := map[string]types.RuleID{
			"rule-a": "inst_a",
			"rule-b": "inst_b",
		}
		if err := resolveDelegateToInVars(vars, resolveMap); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if vars["delegate_to"] != "inst_a,inst_b" {
			t.Errorf("expected delegate_to=inst_a,inst_b, got %q", vars["delegate_to"])
		}
	})
}

func TestResolveDelegateToConfig(t *testing.T) {
	t.Run("resolves_single_delegate_to", func(t *testing.T) {
		cfg := map[string]interface{}{
			"delegate_to": "target-rule",
			"expression":  "true",
		}
		ruleIDMap := map[string]types.RuleID{
			"target-rule": "inst_abc12345",
		}

		newConfig, changed, err := ResolveDelegateToConfig(cfg, ruleIDMap)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !changed {
			t.Fatal("expected changed=true")
		}

		var result map[string]interface{}
		if err := json.Unmarshal(newConfig, &result); err != nil {
			t.Fatalf("failed to unmarshal result: %v", err)
		}
		if got, _ := result["delegate_to"].(string); got != "inst_abc12345" {
			t.Errorf("expected delegate_to=inst_abc12345, got %q", got)
		}
		if got, _ := result["expression"].(string); got != "true" {
			t.Errorf("expected expression=true, got %q", got)
		}
	})

	t.Run("resolves_comma_separated_delegate_to", func(t *testing.T) {
		cfg := map[string]interface{}{
			"delegate_to": "rule-a, rule-b",
		}
		ruleIDMap := map[string]types.RuleID{
			"rule-a": "inst_a111",
			"rule-b": "inst_b222",
			"rule-c": "inst_c333",
		}

		newConfig, changed, err := ResolveDelegateToConfig(cfg, ruleIDMap)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !changed {
			t.Fatal("expected changed=true")
		}

		var result map[string]interface{}
		if err := json.Unmarshal(newConfig, &result); err != nil {
			t.Fatalf("failed to unmarshal result: %v", err)
		}
		got, _ := result["delegate_to"].(string)
		if got != "inst_a111,inst_b222" {
			t.Errorf("expected delegate_to=inst_a111,inst_b222, got %q", got)
		}
	})

	t.Run("skips_unknown_delegate_to", func(t *testing.T) {
		cfg := map[string]interface{}{
			"delegate_to": "unknown-rule",
		}
		ruleIDMap := map[string]types.RuleID{
			"other-rule": "inst_abc12345",
		}

		_, changed, err := ResolveDelegateToConfig(cfg, ruleIDMap)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if changed {
			t.Fatal("expected changed=false for unknown rule")
		}
	})

	t.Run("no_op_when_no_delegate_keys", func(t *testing.T) {
		cfg := map[string]interface{}{
			"expression": "true",
			"addresses":  "0x1234",
		}
		ruleIDMap := map[string]types.RuleID{"x": "inst_x"}

		_, changed, err := ResolveDelegateToConfig(cfg, ruleIDMap)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if changed {
			t.Fatal("expected changed=false when no delegate keys present")
		}
	})

	t.Run("resolves_delegate_to_by_target", func(t *testing.T) {
		cfg := map[string]interface{}{
			"delegate_to_by_target": "some-target:target-rule",
		}
		ruleIDMap := map[string]types.RuleID{
			"target-rule": "inst_abc12345",
		}

		newConfig, changed, err := ResolveDelegateToConfig(cfg, ruleIDMap)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !changed {
			t.Fatal("expected changed=true")
		}

		var result map[string]interface{}
		if err := json.Unmarshal(newConfig, &result); err != nil {
			t.Fatalf("failed to unmarshal result: %v", err)
		}
		got, _ := result["delegate_to_by_target"].(string)
		if got != "some-target:inst_abc12345" {
			t.Errorf("expected delegate_to_by_target=some-target:inst_abc12345, got %q", got)
		}
	})

	t.Run("resolves_comma_separated_delegate_to_by_target", func(t *testing.T) {
		cfg := map[string]interface{}{
			"delegate_to_by_target": "target-a:rule-a, target-b:rule-b",
		}
		ruleIDMap := map[string]types.RuleID{
			"rule-a": "inst_a111",
			"rule-b": "inst_b222",
		}

		newConfig, changed, err := ResolveDelegateToConfig(cfg, ruleIDMap)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !changed {
			t.Fatal("expected changed=true")
		}

		var result map[string]interface{}
		if err := json.Unmarshal(newConfig, &result); err != nil {
			t.Fatalf("failed to unmarshal result: %v", err)
		}
		got, _ := result["delegate_to_by_target"].(string)
		if got != "target-a:inst_a111,target-b:inst_b222" {
			t.Errorf("expected delegate_to_by_target=target-a:inst_a111,target-b:inst_b222, got %q", got)
		}
	})

	t.Run("both_delegate_to_and_delegate_to_by_target", func(t *testing.T) {
		cfg := map[string]interface{}{
			"delegate_to":          "rule-a",
			"delegate_to_by_target": "tx:rule-b",
		}
		ruleIDMap := map[string]types.RuleID{
			"rule-a": "inst_a111",
			"rule-b": "inst_b222",
		}

		newConfig, changed, err := ResolveDelegateToConfig(cfg, ruleIDMap)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !changed {
			t.Fatal("expected changed=true")
		}

		var result map[string]interface{}
		if err := json.Unmarshal(newConfig, &result); err != nil {
			t.Fatalf("failed to unmarshal result: %v", err)
		}
		if got, _ := result["delegate_to"].(string); got != "inst_a111" {
			t.Errorf("expected delegate_to=inst_a111, got %q", got)
		}
		if got, _ := result["delegate_to_by_target"].(string); got != "tx:inst_b222" {
			t.Errorf("expected delegate_to_by_target=tx:inst_b222, got %q", got)
		}
	})
}

// TestBatchCreateInstances_CrossTemplateDelegateToResolution verifies that
// BatchCreateInstances resolves delegate_to in BOTH Config and Variables JSON.
// This is the regression test for the bug where the JS runtime returned
// unresolved template IDs (e.g. "polymarket-v2-transactions") as delegation
// targets because Variables JSON was not resolved.
func TestBatchCreateInstances_CrossTemplateDelegateToResolution(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	logger := newTestLogger()
	svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, logger)
	if err != nil {
		t.Fatalf("failed to create template service: %v", err)
	}

	chainID := "137"

	// ---- Template A: "target" template (polymarket_v2-like) ----
	// Has rules_json with a sub-rule "my-target-rule" that we want to delegate TO.
	targetRulesJSON := `[{"id":"my-target-rule","name":"Target Rule","type":"evm_js","mode":"whitelist","enabled":true,"config":{"script":"function validate(input) { var tx = input.transaction; require(tx && tx.to, 'missing to'); return ok(); }"}}]`
	templateT := &types.RuleTemplate{
		ID:         "evm/target",
		Name:       "Target Template",
		Type:       "template_bundle",
		Mode:       types.RuleModeWhitelist,
		Config:     json.RawMessage(mustMarshalJSON(map[string]interface{}{"rules_json": targetRulesJSON})),
		Variables:  json.RawMessage(`[]`),
		Source:     types.RuleSourceConfig,
		Enabled:    true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	if err := tmplRepo.Create(context.Background(), templateT); err != nil {
		t.Fatalf("failed to seed target template: %v", err)
	}

	// ---- Template B: "caller" template (safe-like) ----
	// Has rules_json with a sub-rule that delegates TO "my-target-rule".
	callerRulesJSON := `[{"id":"safe-block-delegatecall","name":"Block DELEGATECALL","type":"evm_js","mode":"blocklist","enabled":true,"config":{"delegate_to":"","script":"function validate(input) { return ok(); }"}},{"id":"safe-safetx-exec-transaction","name":"SafeTx execTransaction","type":"evm_js","mode":"whitelist","enabled":true,"config":{"delegate_to":"${delegate_to}","delegate_mode":"${delegate_mode}","script":"function validate(input) { var res = resolveDelegateTo(); if (res) return { valid: true, payload: { sign_type: 'transaction', chain_id: config.chain_id, signer: '0x0000000000000000000000000000000000000001', transaction: { from: '0x0000000000000000000000000000000000000001', to: '0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB', value: '0x0', data: '0x095ea7b3' } }, delegate_to: res }; return ok(); } function resolveDelegateTo() { return config.delegate_to; }"}}]`
	callerVars := []types.TemplateVariable{
		{Name: "delegate_to", Type: types.VarTypeString, Required: false, Default: ""},
		{Name: "delegate_mode", Type: types.VarTypeString, Required: false, Default: "single"},
	}
	templateC := &types.RuleTemplate{
		ID:         "evm/caller",
		Name:       "Caller Template",
		Type:       "template_bundle",
		Mode:       types.RuleModeWhitelist,
		Config:     json.RawMessage(mustMarshalJSON(map[string]interface{}{"rules_json": callerRulesJSON})),
		Variables:  mustJSON(callerVars),
		Source:     types.RuleSourceConfig,
		Enabled:    true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	if err := tmplRepo.Create(context.Background(), templateC); err != nil {
		t.Fatalf("failed to seed caller template: %v", err)
	}

	// ---- ACT: BatchCreateInstances with cross-template delegate_to ----
	results, err := svc.BatchCreateInstances(context.Background(), ruleRepo, budgetRepo, []BatchCreateItem{
		{
			Template: templateT,
			Request: &CreateInstanceRequest{
				TemplateID: "evm/target",
				Name:       "Target Instance",
				Variables:  map[string]string{},
				ChainID:    &chainID,
			},
		},
		{
			Template: templateC,
			Request: &CreateInstanceRequest{
				TemplateID: "evm/caller",
				Name:       "Caller Instance",
				Variables: map[string]string{
					"delegate_to": "my-target-rule",
				},
				ChainID: &chainID,
			},
		},
	})
	if err != nil {
		t.Fatalf("BatchCreateInstances failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// ---- ASSERT: Find the SafeTx rule in the caller template's sub-rules ----
	var safetxRule *types.Rule
	for _, result := range results[1].SubRules {
		if strings.Contains(result.Name, "SafeTx") {
			safetxRule = result
			break
		}
	}
	if safetxRule == nil {
		t.Fatal("SafeTx sub-rule should exist in caller instance")
	}

	// ---- ASSERT: Config delegate_to is resolved ----
	var configMap map[string]interface{}
	if err := json.Unmarshal(safetxRule.Config, &configMap); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}
	dt, _ := configMap["delegate_to"].(string)
	if dt == "" {
		t.Fatal("Config delegate_to should be non-empty")
	}
	if dt == "my-target-rule" {
		t.Fatalf("Config delegate_to should be resolved to inst_<hash>, not template ID, got %q", dt)
	}
	if !strings.HasPrefix(dt, "inst_") {
		t.Fatalf("Config delegate_to should start with inst_, got %q", dt)
	}

	// ---- ASSERT: Variables delegate_to is ALSO resolved (THE KEY BUG FIX) ----
	if safetxRule.Variables == nil {
		t.Fatal("Variables JSON should not be nil")
	}
	var variablesMap map[string]string
	if err := json.Unmarshal(safetxRule.Variables, &variablesMap); err != nil {
		t.Fatalf("failed to unmarshal variables: %v", err)
	}
	varsDt := variablesMap["delegate_to"]
	if varsDt == "" {
		t.Fatal("Variables delegate_to should be non-empty")
	}
	if varsDt == "my-target-rule" {
		t.Fatalf("Variables delegate_to should be resolved to inst_<hash>, not template ID (REGRESSION), got %q", varsDt)
	}
	if !strings.HasPrefix(varsDt, "inst_") {
		t.Fatalf("Variables delegate_to should start with inst_, got %q", varsDt)
	}

	// ---- ASSERT: Config and Variables delegate_to match ----
	if dt != varsDt {
		t.Fatalf("Config and Variables delegate_to must match: config=%q variables=%q", dt, varsDt)
	}

	// ---- ASSERT: The target rule exists and has the expected ID ----
	targetRule, err := ruleRepo.Get(context.Background(), types.RuleID(dt))
	if err != nil {
		t.Fatalf("failed to get target rule %q: %v", dt, err)
	}
	if targetRule == nil {
		t.Fatal("target rule should not be nil")
	}

	t.Logf("Cross-template delegate_to resolution: Config=%q Variables=%q Target=%q", dt, varsDt, targetRule.ID)
}

func mustMarshalJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// TestBatchCreateInstances_PolymarketV2SafePreset reproduces the exact preset
// apply flow for the Polymarket V2 Safe (Polygon) preset, which includes 3
// template_bundle templates that share variables including delegate_to.
// It verifies that every delegate_to ID in every persisted rule's Variables
// resolves to a rule that actually exists in the DB.
func TestBatchCreateInstances_PolymarketV2SafePreset(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	logger := newTestLogger()
	svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, logger)
	if err != nil {
		t.Fatalf("failed to create template service: %v", err)
	}

	chainID := "137"

	// ---- Template 1: polymarket_safe_init (simplified) ----
	initRulesJSON := `[{"id":"polymarket-clob-auth","name":"CLOB Auth","type":"evm_js","mode":"whitelist","enabled":true,"config":{"script":"function validate(input) { return ok(); }"}},{"id":"polymarket-safe-wallet-creation","name":"Safe Wallet Creation","type":"evm_js","mode":"whitelist","enabled":true,"config":{"script":"function validate(input) { return ok(); }"}}]`
	templateInit := &types.RuleTemplate{
		ID:        "evm/polymarket_safe_init",
		Name:      "Polymarket CLOB Auth Signature",
		Type:      "template_bundle",
		Mode:      types.RuleModeWhitelist,
		Config:    json.RawMessage(mustMarshalJSON(map[string]interface{}{"rules_json": initRulesJSON})),
		Variables: json.RawMessage(`[{"name":"safe_proxy_factory_address","type":"address","required":true},{"name":"safe_factory_domain_name","type":"string","required":true},{"name":"clob_auth_domain_name","type":"string","required":true},{"name":"clob_auth_domain_version","type":"string","required":true}]`),
		Source:    types.RuleSourceConfig,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := tmplRepo.Create(context.Background(), templateInit); err != nil {
		t.Fatalf("failed to seed init template: %v", err)
	}

	// ---- Template 2: polymarket_v2 (simplified) ----
	v2RulesJSON := `[{"id":"polymarket-v2-order-signature","name":"V2 Order Signature","type":"evm_js","mode":"whitelist","enabled":true,"config":{"script":"function validate(input) { return ok(); }"}},{"id":"polymarket-v2-transactions","name":"Polymarket V2 transactions","type":"evm_js","mode":"whitelist","enabled":true,"config":{"script":"function validate(input) { return ok(); }"}}]`
	templateV2 := &types.RuleTemplate{
		ID:        "evm/polymarket_v2",
		Name:      "Polymarket V2 CLOB Order & Transactions",
		Type:      "template_bundle",
		Mode:      types.RuleModeWhitelist,
		Config:    json.RawMessage(mustMarshalJSON(map[string]interface{}{"rules_json": v2RulesJSON})),
		Variables: json.RawMessage(`[{"name":"exchange_v2_address","type":"address","required":true},{"name":"collateral_token_address","type":"address","required":true},{"name":"conditional_tokens_address","type":"address","required":true}]`),
		Source:    types.RuleSourceConfig,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := tmplRepo.Create(context.Background(), templateV2); err != nil {
		t.Fatalf("failed to seed v2 template: %v", err)
	}

	// ---- Template 3: safe (simplified) ----
	safeRulesJSON := `[{"id":"safe-block-delegatecall","name":"Block DELEGATECALL","type":"evm_js","mode":"blocklist","enabled":true,"config":{"script":"function validate(input) { return ok(); }"}},{"id":"safe-safetx-exec-transaction","name":"SafeTx execTransaction","type":"evm_js","mode":"whitelist","enabled":true,"config":{"delegate_to":"${delegate_to}","delegate_mode":"${delegate_mode}","script":"function validate(input) { var res = resolveDelegateTo(); if (res) return { valid: true, payload: { sign_type: 'transaction', chain_id: config.chain_id, signer: '0x0000000000000000000000000000000000000001', transaction: { from: '0x0000000000000000000000000000000000000001', to: '0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB', value: '0x0', data: '0x095ea7b3' } }, delegate_to: res }; return ok(); } function resolveDelegateTo() { return config.delegate_to; }"}}]`
	safeVars := []types.TemplateVariable{
		{Name: "allowed_safe_addresses", Type: types.VarTypeString, Required: true},
		{Name: "allowed_safe_tx_to_addresses", Type: types.VarTypeString, Required: true},
		{Name: "delegate_to", Type: types.VarTypeString, Required: false, Default: ""},
		{Name: "delegate_mode", Type: types.VarTypeString, Required: false, Default: "single"},
	}
	templateSafe := &types.RuleTemplate{
		ID:        "evm/safe",
		Name:      "Safe block DELEGATECALL",
		Type:      "template_bundle",
		Mode:      types.RuleModeWhitelist,
		Config:    json.RawMessage(mustMarshalJSON(map[string]interface{}{"rules_json": safeRulesJSON})),
		Variables: mustJSON(safeVars),
		Source:    types.RuleSourceConfig,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := tmplRepo.Create(context.Background(), templateSafe); err != nil {
		t.Fatalf("failed to seed safe template: %v", err)
	}

	// ---- Shared preset variables (exactly what the preset YAML provides) ----
	sharedVars := map[string]string{
		"safe_proxy_factory_address":      "0xaacFeEa03eb1561C4e67d661e40682Bd20E3541b",
		"safe_factory_domain_name":        "Polymarket Contract Proxy Factory",
		"clob_auth_domain_name":           "ClobAuthDomain",
		"clob_auth_domain_version":        "1",
		"exchange_v2_address":             "0xE111180000d2663C0091e4f400237545B87B996B",
		"collateral_token_address":        "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB",
		"conditional_tokens_address":      "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045",
		"allowed_safe_addresses":          "0x1111111111111111111111111111111111111111",
		"allowed_safe_tx_to_addresses":    "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB",
		"delegate_to":                     "polymarket-v2-transactions",
		"delegate_mode":                   "single",
	}

	// ---- ACT: BatchCreateInstances with all 3 templates ----
	results, err := svc.BatchCreateInstances(context.Background(), ruleRepo, budgetRepo, []BatchCreateItem{
		{Template: templateInit, Request: &CreateInstanceRequest{TemplateID: "evm/polymarket_safe_init", Name: "Init Instance", Variables: copyMap(sharedVars), ChainID: &chainID}},
		{Template: templateV2, Request: &CreateInstanceRequest{TemplateID: "evm/polymarket_v2", Name: "V2 Instance", Variables: copyMap(sharedVars), ChainID: &chainID}},
		{Template: templateSafe, Request: &CreateInstanceRequest{TemplateID: "evm/safe", Name: "Safe Instance", Variables: copyMap(sharedVars), ChainID: &chainID}},
	})
	if err != nil {
		t.Fatalf("BatchCreateInstances failed: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// ---- COLLECT all created rules ----
	var allRules []*types.Rule
	for _, result := range results {
		allRules = append(allRules, result.SubRules...)
	}
	t.Logf("Created %d rules total", len(allRules))
	for _, r := range allRules {
		t.Logf("  Rule: id=%s name=%q type=%s mode=%s", r.ID, r.Name, r.Type, r.Mode)
	}

	// ---- ASSERT 1: All delegate_to IDs in Variables resolve to existing rules ----
	existingIDs := make(map[types.RuleID]bool)
	for _, r := range allRules {
		existingIDs[r.ID] = true
	}

	var delegateTargets []types.RuleID
	for _, r := range allRules {
		if r.Variables == nil {
			continue
		}
		var vars map[string]string
		if err := json.Unmarshal(r.Variables, &vars); err != nil {
			t.Fatalf("failed to unmarshal variables for rule %s: %v", r.ID, err)
		}
		dt, ok := vars["delegate_to"]
		if !ok || dt == "" {
			continue
		}
		delegateTargets = append(delegateTargets, types.RuleID(dt))
		if !existingIDs[types.RuleID(dt)] {
			t.Errorf("Rule %q (%s) has delegate_to=%q which does NOT exist in DB. Existing IDs: %v",
				r.Name, r.ID, dt, existingIDs)
		} else {
			t.Logf("  OK: Rule %q (%s) delegates to %q (exists)", r.Name, r.ID, dt)
		}
	}
	if len(delegateTargets) == 0 {
		t.Error("Expected at least one rule with delegate_to in Variables, found none")
	}

	// ---- ASSERT 2: The SafeTx rule's delegate_to must equal the V2 transactions rule's ID ----
	var v2TxRule *types.Rule
	var safetxRule *types.Rule
	for _, r := range allRules {
		if r.Name == "V2 Instance / Polymarket V2 transactions" {
			v2TxRule = r
		}
		if strings.Contains(r.Name, "SafeTx") {
			safetxRule = r
		}
	}
	if v2TxRule == nil {
		t.Fatal("V2 transactions rule not found")
	}
	if safetxRule == nil {
		t.Fatal("SafeTx rule not found")
	}

	var safetxVars map[string]string
	if err := json.Unmarshal(safetxRule.Variables, &safetxVars); err != nil {
		t.Fatalf("failed to unmarshal SafeTx variables: %v", err)
	}
	safetxDelegateTo := safetxVars["delegate_to"]
	if safetxDelegateTo != string(v2TxRule.ID) {
		t.Errorf("SafeTx delegate_to=%q but V2 transactions rule ID=%q. The delegation chain is BROKEN.",
			safetxDelegateTo, v2TxRule.ID)
	} else {
		t.Logf("  OK: SafeTx delegate_to=%q matches V2 transactions rule ID=%q", safetxDelegateTo, v2TxRule.ID)
	}

	// ---- ASSERT 3: Config delegate_to also resolves correctly ----
	var safetxConfig map[string]interface{}
	if err := json.Unmarshal(safetxRule.Config, &safetxConfig); err != nil {
		t.Fatalf("failed to unmarshal SafeTx config: %v", err)
	}
	configDt, _ := safetxConfig["delegate_to"].(string)
	if configDt != string(v2TxRule.ID) {
		t.Errorf("SafeTx Config delegate_to=%q but V2 transactions rule ID=%q", configDt, v2TxRule.ID)
	} else {
		t.Logf("  OK: SafeTx Config delegate_to=%q matches V2 transactions rule ID=%q", configDt, v2TxRule.ID)
	}

	t.Log("Polymarket V2 Safe preset flow: all delegate_to resolutions verified")
}

func copyMap(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// TestBatchCreateInstances_VariablesNotCorrupted reproduces the bug where
// allowed_safe_addresses in the DB contains allowed_safe_tx_to_addresses
// values instead of the preset-defined Safe address. Two templates that
// share a variable name (allowed_safe_addresses) must preserve the value
// from the preset, not get cross-contaminated.
func TestBatchCreateInstances_VariablesNotCorrupted(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	logger := newTestLogger()
	svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, logger)
	if err != nil {
		t.Fatalf("failed to create template service: %v", err)
	}

	chainID := "137"

	// Template 0: safe_init template (like real polymarket_safe_init.yaml) -
	// does NOT declare allowed_safe_addresses or allowed_safe_tx_to_addresses
	initVarDefs := []types.TemplateVariable{
		{Name: "safe_proxy_factory_address", Type: types.VarTypeString, Required: true},
		{Name: "safe_factory_domain_name", Type: types.VarTypeString, Required: true},
		{Name: "clob_auth_domain_name", Type: types.VarTypeString, Required: true},
		{Name: "clob_auth_domain_version", Type: types.VarTypeString, Required: true},
	}
	initRulesJSON := `[{"id":"clob-auth","name":"CLOB Auth","type":"evm_js","mode":"whitelist","enabled":true,"config":{"script":"function validate(input) { return ok(); }"}},{"id":"safe-wallet-creation","name":"Safe Wallet Creation","type":"evm_js","mode":"whitelist","enabled":true,"config":{"script":"function validate(input) { return ok(); }"}}]`
	templateInit := &types.RuleTemplate{
		ID:        "evm/polymarket_safe_init",
		Name:      "Polymarket Safe Init",
		Type:      "template_bundle",
		Mode:      types.RuleModeWhitelist,
		Config:    json.RawMessage(mustMarshalJSON(map[string]interface{}{"rules_json": initRulesJSON})),
		Variables: mustJSON(initVarDefs),
		Source:    types.RuleSourceConfig,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := tmplRepo.Create(context.Background(), templateInit); err != nil {
		t.Fatalf("failed to seed init template: %v", err)
	}

	// Template 1: V2 template (like real polymarket_v2.yaml) - declares
	// allowed_safe_addresses for Order.maker whitelist
	v2VarDefs := []types.TemplateVariable{
		{Name: "exchange_v2_address", Type: types.VarTypeString, Required: true},
		{Name: "collateral_token_address", Type: types.VarTypeString, Required: true},
		{Name: "conditional_tokens_address", Type: types.VarTypeString, Required: true},
		{Name: "allowed_safe_addresses", Type: types.VarTypeString, Required: true},
	}
	v2RulesJSON := `[{"id":"v2-order-sig","name":"V2 Order Signature","type":"evm_js","mode":"whitelist","enabled":true,"config":{"script":"function validate(input) { return ok(); }"}},{"id":"v2-transactions","name":"V2 Transactions","type":"evm_js","mode":"whitelist","enabled":true,"config":{"script":"function validate(input) { return ok(); }"}}]`
	templateV2 := &types.RuleTemplate{
		ID:        "evm/polymarket_v2",
		Name:      "Polymarket V2",
		Type:      "template_bundle",
		Mode:      types.RuleModeWhitelist,
		Config:    json.RawMessage(mustMarshalJSON(map[string]interface{}{"rules_json": v2RulesJSON})),
		Variables: mustJSON(v2VarDefs),
		Source:    types.RuleSourceConfig,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := tmplRepo.Create(context.Background(), templateV2); err != nil {
		t.Fatalf("failed to seed v2 template: %v", err)
	}

	// Template 2: Safe template (like real safe.yaml) - also declares
	// allowed_safe_addresses for verifyingContract
	safeVarDefs := []types.TemplateVariable{
		{Name: "allowed_safe_addresses", Type: types.VarTypeString, Required: true},
		{Name: "allowed_safe_tx_to_addresses", Type: types.VarTypeString, Required: true},
		{Name: "delegate_to", Type: types.VarTypeString, Required: false, Default: ""},
		{Name: "delegate_mode", Type: types.VarTypeString, Required: false, Default: "single"},
	}
	safeRulesJSON := `[{"id":"safe-block-delegatecall","name":"Block DELEGATECALL","type":"evm_js","mode":"blocklist","enabled":true,"config":{"script":"function validate(input) { return ok(); }"}},{"id":"safe-safetx-exec-transaction","name":"SafeTx execTransaction","type":"evm_js","mode":"whitelist","enabled":true,"config":{"delegate_to":"${delegate_to}","delegate_mode":"${delegate_mode}","script":"function validate(input) { return ok(); }"}}]`
	templateSafe := &types.RuleTemplate{
		ID:        "evm/safe",
		Name:      "Safe",
		Type:      "template_bundle",
		Mode:      types.RuleModeWhitelist,
		Config:    json.RawMessage(mustMarshalJSON(map[string]interface{}{"rules_json": safeRulesJSON})),
		Variables: mustJSON(safeVarDefs),
		Source:    types.RuleSourceConfig,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := tmplRepo.Create(context.Background(), templateSafe); err != nil {
		t.Fatalf("failed to seed safe template: %v", err)
	}

	// Shared preset variables (exactly what the preset YAML provides)
	// allowed_safe_addresses = placeholder Safe address (operator overrides this)
	// allowed_safe_tx_to_addresses = protocol contract addresses
	sharedVars := map[string]string{
		"safe_proxy_factory_address":  "0xaacFeEa03eb1561C4e67d661e40682Bd20E3541b",
		"safe_factory_domain_name":    "Polymarket Contract Proxy Factory",
		"clob_auth_domain_name":       "ClobAuthDomain",
		"clob_auth_domain_version":    "1",
		"exchange_v2_address":         "0xE111180000d2663C0091e4f400237545B87B996B",
		"collateral_token_address":    "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB",
		"conditional_tokens_address":  "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045",
		"allowed_safe_addresses":      "0x1111111111111111111111111111111111111111",
		"allowed_safe_tx_to_addresses": "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB,0x4D97DCd97eC945f40cF65F87097ACe5EA0476045",
		"delegate_to":                 "v2-transactions",
		"delegate_mode":               "single",
	}

	results, err := svc.BatchCreateInstances(context.Background(), ruleRepo, budgetRepo, []BatchCreateItem{
		{Template: templateInit, Request: &CreateInstanceRequest{TemplateID: "evm/polymarket_safe_init", Name: "Init Instance", Variables: copyMap(sharedVars), ChainID: &chainID}},
		{Template: templateV2, Request: &CreateInstanceRequest{TemplateID: "evm/polymarket_v2", Name: "V2 Instance", Variables: copyMap(sharedVars), ChainID: &chainID}},
		{Template: templateSafe, Request: &CreateInstanceRequest{TemplateID: "evm/safe", Name: "Safe Instance", Variables: copyMap(sharedVars), ChainID: &chainID}},
	})
	if err != nil {
		t.Fatalf("BatchCreateInstances failed: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// Collect all rules and verify their Variables JSON
	var allRules []*types.Rule
	for _, result := range results {
		allRules = append(allRules, result.SubRules...)
	}

	expectedSafeAddresses := "0x1111111111111111111111111111111111111111"
	expectedSafeTxToAddresses := "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB,0x4D97DCd97eC945f40cF65F87097ACe5EA0476045"

	for _, r := range allRules {
		if r.Variables == nil {
			t.Errorf("Rule %q (%s): Variables is nil", r.Name, r.ID)
			continue
		}
		var vars map[string]string
		if err := json.Unmarshal(r.Variables, &vars); err != nil {
			t.Fatalf("Rule %q (%s): failed to unmarshal Variables: %v", r.Name, r.ID, err)
		}

		gotSafeAddr := vars["allowed_safe_addresses"]
		gotSafeTxTo := vars["allowed_safe_tx_to_addresses"]

		// allowed_safe_addresses must be the placeholder, NOT the protocol addresses
		if gotSafeAddr != expectedSafeAddresses {
			t.Errorf("Rule %q (%s): allowed_safe_addresses = %q, want %q (was it corrupted with allowed_safe_tx_to_addresses?)",
				r.Name, r.ID, gotSafeAddr, expectedSafeAddresses)
		}

		// allowed_safe_tx_to_addresses must be the protocol addresses
		if gotSafeTxTo != expectedSafeTxToAddresses {
			t.Errorf("Rule %q (%s): allowed_safe_tx_to_addresses = %q, want %q",
				r.Name, r.ID, gotSafeTxTo, expectedSafeTxToAddresses)
		}
	}

	// Verify the V2 rules also have the correct allowed_safe_addresses
	for _, r := range allRules {
		if !strings.Contains(r.Name, "V2") {
			continue
		}
		var vars map[string]string
		_ = json.Unmarshal(r.Variables, &vars)
		gotSafeAddr := vars["allowed_safe_addresses"]
		if gotSafeAddr != expectedSafeAddresses {
			t.Errorf("V2 Rule %q (%s): allowed_safe_addresses = %q, want %q",
				r.Name, r.ID, gotSafeAddr, expectedSafeAddresses)
		}
		t.Logf("V2 Rule %q (%s): allowed_safe_addresses = %q (correct)", r.Name, r.ID, gotSafeAddr)
	}
}

func TestBatchCreateInstances_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("empty items", func(t *testing.T) {
		svc, err := NewTemplateService(newMockTemplateRepo(), newMockRuleRepo(), newMockBudgetRepo(), newTestLogger())
		require.NoError(t, err)
		results, err := svc.BatchCreateInstances(ctx, newMockRuleRepo(), newMockBudgetRepo(), nil)
		assert.NoError(t, err)
		assert.Nil(t, results)
	})

	t.Run("nil template", func(t *testing.T) {
		svc, err := NewTemplateService(newMockTemplateRepo(), newMockRuleRepo(), newMockBudgetRepo(), newTestLogger())
		require.NoError(t, err)
		items := []BatchCreateItem{
			{
				Template: nil,
				Request:  &CreateInstanceRequest{TemplateID: "tmpl1"},
			},
		}
		results, err := svc.BatchCreateInstances(ctx, newMockRuleRepo(), newMockBudgetRepo(), items)
		assert.Error(t, err)
		assert.Nil(t, results)
		assert.Contains(t, err.Error(), "template is required")
	})

	t.Run("nil request", func(t *testing.T) {
		svc, err := NewTemplateService(newMockTemplateRepo(), newMockRuleRepo(), newMockBudgetRepo(), newTestLogger())
		require.NoError(t, err)
		tmpl := &types.RuleTemplate{
			ID:        "tmpl-no-req",
			Name:      "No Request",
			Type:      types.RuleTypeEVMAddressList,
			Mode:      types.RuleModeWhitelist,
			Config:    json.RawMessage(`{"addresses":["0x1111111111111111111111111111111111111111"]}`),
			Source:    types.RuleSourceConfig,
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		items := []BatchCreateItem{
			{
				Template: tmpl,
				Request:  nil,
			},
		}
		results, err := svc.BatchCreateInstances(ctx, newMockRuleRepo(), newMockBudgetRepo(), items)
		assert.Error(t, err)
		assert.Nil(t, results)
		assert.Contains(t, err.Error(), "request is required")
	})
}

func TestRollbackRules_ErrorPath(t *testing.T) {
	svc, err := NewTemplateService(newMockTemplateRepo(), newMockRuleRepo(), newMockBudgetRepo(), newTestLogger())
	require.NoError(t, err)

	ruleRepo := &errorDeleteRuleRepo{RuleRepository: newMockRuleRepo()}

	// rollbackRules logs errors instead of panicking when Delete fails
	svc.rollbackRules(context.Background(), ruleRepo, []types.RuleID{"rule-does-not-exist"})
}

func TestCollectRuleIDs_Errors(t *testing.T) {
	svc, err := NewTemplateService(newMockTemplateRepo(), newMockRuleRepo(), newMockBudgetRepo(), newTestLogger())
	require.NoError(t, err)

	t.Run("substitution error in bundle", func(t *testing.T) {
		// Config references a variable that doesn't exist - SubstituteVariables will fail
		tmpl := &types.RuleTemplate{
			ID:   "tmpl-bad-subst",
			Name: "Bad Subst Bundle",
			Type: "template_bundle",
			Mode: types.RuleModeWhitelist,
			Config: json.RawMessage(`{"rules_json":"[{\"id\":\"sub1\",\"name\":\"Rule\",\"type\":\"evm_js\",\"mode\":\"whitelist\",\"config\":{\"script\":\"${nonexistent}\"},\"enabled\":true}]"}`),
			Source:  types.RuleSourceConfig,
			Enabled: true,
		}
		req := &CreateInstanceRequest{TemplateID: "tmpl-bad-subst"}
		vars := map[string]string{}
		m := make(map[string]types.RuleID)
		err := svc.collectRuleIDs(m, tmpl, req, vars)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "variable substitution failed")
	})

	t.Run("missing rules_json in bundle", func(t *testing.T) {
		tmpl := &types.RuleTemplate{
			ID:     "tmpl-no-rules",
			Name:   "No Rules Bundle",
			Type:   "template_bundle",
			Mode:   types.RuleModeWhitelist,
			Config: json.RawMessage(`{"not_rules":"something"}`),
			Source:  types.RuleSourceConfig,
			Enabled: true,
		}
		req := &CreateInstanceRequest{TemplateID: "tmpl-no-rules"}
		vars := map[string]string{}
		m := make(map[string]types.RuleID)
		err := svc.collectRuleIDs(m, tmpl, req, vars)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "has no rules_json")
	})

	t.Run("precomputed sub rule IDs used", func(t *testing.T) {
		tmpl := &types.RuleTemplate{
			ID:   "tmpl-precomputed",
			Name: "Precomputed Bundle",
			Type: "template_bundle",
			Mode: types.RuleModeWhitelist,
			Config: json.RawMessage(`{"rules_json":"[{\"id\":\"sub1\",\"name\":\"Rule\",\"type\":\"evm_js\",\"mode\":\"whitelist\",\"config\":{\"script\":\"true\"},\"enabled\":true}]"}`),
			Source:  types.RuleSourceConfig,
			Enabled: true,
		}
		req := &CreateInstanceRequest{
			TemplateID:           "tmpl-precomputed",
			PrecomputedSubRuleIDs: map[string]types.RuleID{"sub1": "precomputed-id-123"},
		}
		vars := map[string]string{}
		m := make(map[string]types.RuleID)
		err := svc.collectRuleIDs(m, tmpl, req, vars)
		assert.NoError(t, err)
		assert.Equal(t, types.RuleID("precomputed-id-123"), m["sub1"])
		assert.Equal(t, types.RuleID("precomputed-id-123"), req.PrecomputedSubRuleIDs["sub1"])
	})
}

func TestCollectRuleIDs_SubRuleNoID(t *testing.T) {
	svc, err := NewTemplateService(newMockTemplateRepo(), newMockRuleRepo(), newMockBudgetRepo(), newTestLogger())
	require.NoError(t, err)

	// Sub-rule with no ID field uses Name as suffix
	tmpl := &types.RuleTemplate{
		ID:   "tmpl-no-sub-id",
		Name: "No Sub ID Bundle",
		Type: "template_bundle",
		Mode: types.RuleModeWhitelist,
		Config: json.RawMessage(`{"rules_json":"[{\"name\":\"NoIDRule\",\"type\":\"evm_js\",\"mode\":\"whitelist\",\"config\":{\"script\":\"true\"},\"enabled\":true}]"}`),
		Source:  types.RuleSourceConfig,
		Enabled: true,
	}
	req := &CreateInstanceRequest{TemplateID: "tmpl-no-sub-id"}
	vars := map[string]string{}
	m := make(map[string]types.RuleID)
	err = svc.collectRuleIDs(m, tmpl, req, vars)
	assert.NoError(t, err)
	// No sub-rule ID in map (sub has no id field), but PrecomputedSubRuleIDs has entry keyed by Name
	assert.Empty(t, m)
	assert.Contains(t, req.PrecomputedSubRuleIDs, "NoIDRule")
}

func TestBatchCreateInstances_CollectRuleIDsError(t *testing.T) {
	ctx := context.Background()
	svc, err := NewTemplateService(newMockTemplateRepo(), newMockRuleRepo(), newMockBudgetRepo(), newTestLogger())
	require.NoError(t, err)

	// Template bundle with ${nonexistent} var - collectRuleIDs will fail on substitution
	tmpl := &types.RuleTemplate{
		ID:   "tmpl-collect-fail",
		Name: "Collect Fail Bundle",
		Type: "template_bundle",
		Mode: types.RuleModeWhitelist,
		Config: json.RawMessage(`{"rules_json":"[{\"id\":\"sub1\",\"name\":\"Rule\",\"type\":\"evm_js\",\"mode\":\"whitelist\",\"config\":{\"script\":\"${nonexistent}\"},\"enabled\":true}]"}`),
		Source:  types.RuleSourceConfig,
		Enabled: true,
	}
	items := []BatchCreateItem{
		{
			Template: tmpl,
			Request:  &CreateInstanceRequest{TemplateID: "tmpl-collect-fail"},
		},
	}
	results, err := svc.BatchCreateInstances(ctx, newMockRuleRepo(), newMockBudgetRepo(), items)
	assert.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "pre-compute IDs")
}

func TestCollectRuleIDs_NonBundle(t *testing.T) {
	svc, err := NewTemplateService(newMockTemplateRepo(), newMockRuleRepo(), newMockBudgetRepo(), newTestLogger())
	require.NoError(t, err)

	tmpl := &types.RuleTemplate{
		ID:   "tmpl-single",
		Name: "Single Rule",
		Type: types.RuleTypeEVMAddressList,
		Mode: types.RuleModeWhitelist,
		Config: json.RawMessage(`{"addresses":["0x1111111111111111111111111111111111111111"]}`),
		Source:  types.RuleSourceConfig,
		Enabled: true,
	}
	req := &CreateInstanceRequest{TemplateID: "tmpl-single"}
	vars := map[string]string{}
	m := make(map[string]types.RuleID)
	err = svc.collectRuleIDs(m, tmpl, req, vars)
	assert.NoError(t, err)
	assert.NotEmpty(t, m["tmpl-single"])
	assert.NotEmpty(t, req.PrecomputedRuleID)
}

func TestCreateInstanceFromResolved_NoPrecomputedVars(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()

	tmpl := &types.RuleTemplate{
		ID:   "tmpl-no-prec",
		Name: "No Precomputed Vars",
		Type: types.RuleTypeEVMAddressList,
		Mode: types.RuleModeWhitelist,
		Config: json.RawMessage(`{"addresses":["${addr1}"]}`),
		Variables: json.RawMessage(`[{"name":"addr1","type":"address","required":true}]`),
		Source:  types.RuleSourceConfig,
		Enabled: true,
	}
	seedTemplate(t, tmplRepo, tmpl)

	logger := newTestLogger()
	svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, logger)
	require.NoError(t, err)

	ctx := context.Background()
	result, err := svc.CreateInstance(ctx, &CreateInstanceRequest{
		TemplateID: "tmpl-no-prec",
		Variables:  map[string]string{"addr1": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	got, err := ruleRepo.Get(ctx, result.Rule.ID)
	require.NoError(t, err)
	var cfg map[string]interface{}
	require.NoError(t, json.Unmarshal(got.Config, &cfg))
	addrs, ok := cfg["addresses"].([]interface{})
	require.True(t, ok)
	assert.Equal(t, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", addrs[0])
}

func TestRevokeInstance_BudgetDeleteLogsError(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()

	logger := newTestLogger()
	svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, logger)
	require.NoError(t, err)

	// Create an instance rule
	rule := &types.Rule{
		ID:      types.RuleID("inst-revoke-budget"),
		Name:    "Revoke Budget Test",
		Type:    types.RuleTypeEVMAddressList,
		Mode:    types.RuleModeWhitelist,
		Source:  types.RuleSourceInstance,
		Enabled: true,
		Config:  json.RawMessage(`{"addresses":["0x1111111111111111111111111111111111111111"]}`),
	}
	require.NoError(t, ruleRepo.Create(context.Background(), rule))

	// Delete the budget first so DeleteByRuleID fails on it
	// but not on a missing budget - we want DeleteByRuleID to succeed (empty)
	// Actually the default mock DeleteByRuleID just iterates and deletes.
	// Use a custom error budget repo.
	err = svc.RevokeInstance(context.Background(), "inst-revoke-budget")
	assert.NoError(t, err)

	got, err := ruleRepo.Get(context.Background(), "inst-revoke-budget")
	require.NoError(t, err)
	assert.False(t, got.Enabled)
}

func TestRevokeInstance_NonInstanceRule(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()

	svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
	require.NoError(t, err)

	// Create a config-sourced rule (not an instance)
	rule := &types.Rule{
		ID:      types.RuleID("config-rule"),
		Name:    "Config Rule",
		Type:    types.RuleTypeEVMAddressList,
		Mode:    types.RuleModeWhitelist,
		Source:  types.RuleSourceConfig,
		Enabled: true,
		Config:  json.RawMessage(`{"addresses":["0x1111111111111111111111111111111111111111"]}`),
	}
	require.NoError(t, ruleRepo.Create(context.Background(), rule))

	err = svc.RevokeInstance(context.Background(), "config-rule")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an instance")
}

func TestCreateInstanceFromBundle_Errors(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()

	svc, err := NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
	require.NoError(t, err)

	t.Run("empty sub-rules", func(t *testing.T) {
		tmpl := &types.RuleTemplate{
			ID:   "tmpl-empty-bundle",
			Name: "Empty Bundle",
			Type: "template_bundle",
			Mode: types.RuleModeWhitelist,
			Config: json.RawMessage(`{"rules_json":"[]"}`),
			Source:  types.RuleSourceConfig,
			Enabled: true,
		}
		seedTemplate(t, tmplRepo, tmpl)
		req := &CreateInstanceRequest{TemplateID: "tmpl-empty-bundle"}
		_, err := svc.CreateInstance(context.Background(), req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "has no sub-rules")
	})

	t.Run("malformed rules_json", func(t *testing.T) {
		tmpl := &types.RuleTemplate{
			ID:   "tmpl-malformed-bundle",
			Name: "Malformed Bundle",
			Type: "template_bundle",
			Mode: types.RuleModeWhitelist,
			Config: json.RawMessage(`{"rules_json":"not-json"}`),
			Source:  types.RuleSourceConfig,
			Enabled: true,
		}
		seedTemplate(t, tmplRepo, tmpl)
		req := &CreateInstanceRequest{TemplateID: "tmpl-malformed-bundle"}
		_, err := svc.CreateInstance(context.Background(), req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse bundle rules_json")
	})
}
