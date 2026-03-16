package config

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestExpandFileRules(t *testing.T) {
	logger := newTestLogger()

	// Create temp directory for test files
	tmpDir, err := os.MkdirTemp("", "rule-init-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test rule file
	ruleFileContent := `rules:
  - name: "Test Rule 1"
    type: "evm_address_list"
    mode: "whitelist"
    enabled: true
    config:
      addresses:
        - "0x1234567890abcdef1234567890abcdef12345678"

  - name: "Test Rule 2"
    type: "evm_value_limit"
    mode: "whitelist"
    enabled: true
    config:
      max_value: "1000000000000000000"
`
	ruleFilePath := filepath.Join(tmpDir, "test-rules.yaml")
	if err := os.WriteFile(ruleFilePath, []byte(ruleFileContent), 0644); err != nil {
		t.Fatalf("failed to write test rule file: %v", err)
	}

	// Create initializer
	init := &RuleInitializer{
		logger:    logger,
		configDir: tmpDir,
	}

	// Test expanding file rules
	rules := []RuleConfig{
		{
			Name: "Inline Rule",
			Type: "evm_address_list",
			Mode: "whitelist",
			Config: map[string]interface{}{
				"addresses": []string{"0xabcd"},
			},
			Enabled: true,
		},
		{
			Name: "File Include",
			Type: "file",
			Config: map[string]interface{}{
				"path": "test-rules.yaml",
			},
		},
	}

	expanded, err := init.expandFileRules(rules)
	if err != nil {
		t.Fatalf("expandFileRules failed: %v", err)
	}

	// Should have 3 rules: 1 inline + 2 from file
	if len(expanded) != 3 {
		t.Errorf("expected 3 rules, got %d", len(expanded))
	}

	// Check order: inline rule first, then file rules
	if expanded[0].Name != "Inline Rule" {
		t.Errorf("expected first rule to be 'Inline Rule', got '%s'", expanded[0].Name)
	}
	if expanded[1].Name != "Test Rule 1" {
		t.Errorf("expected second rule to be 'Test Rule 1', got '%s'", expanded[1].Name)
	}
	if expanded[2].Name != "Test Rule 2" {
		t.Errorf("expected third rule to be 'Test Rule 2', got '%s'", expanded[2].Name)
	}
}

func TestExpandFileRules_NestedFiles(t *testing.T) {
	logger := newTestLogger()

	// Create temp directory for test files
	tmpDir, err := os.MkdirTemp("", "rule-init-nested-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create nested rule file
	nestedRuleContent := `rules:
  - name: "Nested Rule"
    type: "evm_value_limit"
    mode: "whitelist"
    enabled: true
    config:
      max_value: "1000"
`
	nestedFilePath := filepath.Join(tmpDir, "nested.yaml")
	if err := os.WriteFile(nestedFilePath, []byte(nestedRuleContent), 0644); err != nil {
		t.Fatalf("failed to write nested rule file: %v", err)
	}

	// Create parent rule file that includes nested file
	parentRuleContent := `rules:
  - name: "Parent Rule"
    type: "evm_address_list"
    mode: "whitelist"
    enabled: true
    config:
      addresses:
        - "0x1234"

  - name: "Include nested"
    type: "file"
    config:
      path: "nested.yaml"
`
	parentFilePath := filepath.Join(tmpDir, "parent.yaml")
	if err := os.WriteFile(parentFilePath, []byte(parentRuleContent), 0644); err != nil {
		t.Fatalf("failed to write parent rule file: %v", err)
	}

	// Create initializer
	init := &RuleInitializer{
		logger:    logger,
		configDir: tmpDir,
	}

	// Test with top-level file include
	rules := []RuleConfig{
		{
			Name: "Top Include",
			Type: "file",
			Config: map[string]interface{}{
				"path": "parent.yaml",
			},
		},
	}

	expanded, err := init.expandFileRules(rules)
	if err != nil {
		t.Fatalf("expandFileRules failed: %v", err)
	}

	// Should have 2 rules: parent rule + nested rule
	if len(expanded) != 2 {
		t.Errorf("expected 2 rules, got %d", len(expanded))
	}

	if expanded[0].Name != "Parent Rule" {
		t.Errorf("expected first rule to be 'Parent Rule', got '%s'", expanded[0].Name)
	}
	if expanded[1].Name != "Nested Rule" {
		t.Errorf("expected second rule to be 'Nested Rule', got '%s'", expanded[1].Name)
	}
}

func TestExpandFileRules_MaxDepthExceeded(t *testing.T) {
	logger := newTestLogger()

	// Create temp directory for test files
	tmpDir, err := os.MkdirTemp("", "rule-init-depth-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a circular reference (file includes itself)
	circularContent := `rules:
  - name: "Circular Include"
    type: "file"
    config:
      path: "circular.yaml"
`
	circularPath := filepath.Join(tmpDir, "circular.yaml")
	if err := os.WriteFile(circularPath, []byte(circularContent), 0644); err != nil {
		t.Fatalf("failed to write circular rule file: %v", err)
	}

	// Create initializer
	init := &RuleInitializer{
		logger:    logger,
		configDir: tmpDir,
	}

	rules := []RuleConfig{
		{
			Name: "Start Circular",
			Type: "file",
			Config: map[string]interface{}{
				"path": "circular.yaml",
			},
		},
	}

	// Should fail due to max depth exceeded
	_, err = init.expandFileRules(rules)
	if err == nil {
		t.Error("expected error for circular reference, got nil")
	}
}

func TestExpandFileRules_FileNotFound(t *testing.T) {
	logger := newTestLogger()

	// Create temp directory for test files
	tmpDir, err := os.MkdirTemp("", "rule-init-notfound-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create initializer
	init := &RuleInitializer{
		logger:    logger,
		configDir: tmpDir,
	}

	rules := []RuleConfig{
		{
			Name: "Missing File",
			Type: "file",
			Config: map[string]interface{}{
				"path": "nonexistent.yaml",
			},
		},
	}

	// Should fail due to file not found
	_, err = init.expandFileRules(rules)
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestExpandFileRules_MissingPath(t *testing.T) {
	logger := newTestLogger()

	init := &RuleInitializer{
		logger:    logger,
		configDir: ".",
	}

	rules := []RuleConfig{
		{
			Name:   "Missing Path Config",
			Type:   "file",
			Config: map[string]interface{}{}, // No path specified
		},
	}

	// Should fail due to missing path
	_, err := init.expandFileRules(rules)
	if err == nil {
		t.Error("expected error for missing path, got nil")
	}
}

func TestExpandFileRules_EnvVarExpansion(t *testing.T) {
	logger := newTestLogger()

	// Create temp directory for test files
	tmpDir, err := os.MkdirTemp("", "rule-init-env-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Set environment variable
	os.Setenv("TEST_ADDRESS", "0xenv123456789abcdef")
	defer os.Unsetenv("TEST_ADDRESS")

	// Create rule file with env var
	ruleFileContent := `rules:
  - name: "Env Var Rule"
    type: "evm_address_list"
    mode: "whitelist"
    enabled: true
    config:
      addresses:
        - "${TEST_ADDRESS}"
`
	ruleFilePath := filepath.Join(tmpDir, "env-rules.yaml")
	if err := os.WriteFile(ruleFilePath, []byte(ruleFileContent), 0644); err != nil {
		t.Fatalf("failed to write test rule file: %v", err)
	}

	// Create initializer
	init := &RuleInitializer{
		logger:    logger,
		configDir: tmpDir,
	}

	rules := []RuleConfig{
		{
			Name: "Env File Include",
			Type: "file",
			Config: map[string]interface{}{
				"path": "env-rules.yaml",
			},
		},
	}

	expanded, err := init.expandFileRules(rules)
	if err != nil {
		t.Fatalf("expandFileRules failed: %v", err)
	}

	if len(expanded) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(expanded))
	}

	// Check that env var was expanded
	addresses, ok := expanded[0].Config["addresses"].([]interface{})
	if !ok {
		t.Fatalf("expected addresses to be []interface{}, got %T", expanded[0].Config["addresses"])
	}
	if len(addresses) != 1 {
		t.Fatalf("expected 1 address, got %d", len(addresses))
	}
	if addresses[0] != "0xenv123456789abcdef" {
		t.Errorf("expected env var to be expanded, got '%v'", addresses[0])
	}
}

// ===========================================================================
// SyncFromConfig tests (Fixes 1-4)
// ===========================================================================

// helper: create RuleInitializer with a MemoryRuleRepository
func newTestRuleInit(t *testing.T) (*RuleInitializer, *storage.MemoryRuleRepository) {
	t.Helper()
	repo := storage.NewMemoryRuleRepository()
	init, err := NewRuleInitializer(repo, newTestLogger())
	require.NoError(t, err)
	return init, repo
}

// helper: simple enabled rule config (id required)
func enabledRule(id, name, mode string) RuleConfig {
	return RuleConfig{
		Id:      id,
		Name:    name,
		Type:    "evm_address_list",
		Mode:    mode,
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"},
		},
	}
}

// Fix 2: Limit -1 ensures all config rules are fetched (no 1000 cap)
func TestSyncFromConfig_NoLimitCap(t *testing.T) {
	init, repo := newTestRuleInit(t)
	ctx := context.Background()

	// Sync 3 rules
	rules := []RuleConfig{
		enabledRule("rule-1", "Rule 1", "whitelist"),
		enabledRule("rule-2", "Rule 2", "whitelist"),
		enabledRule("rule-3", "Rule 3", "whitelist"),
	}
	require.NoError(t, init.SyncFromConfig(ctx, rules))

	// All 3 should exist
	configSource := types.RuleSourceConfig
	all, err := repo.List(ctx, storage.RuleFilter{Source: &configSource, Limit: -1})
	require.NoError(t, err)
	assert.Len(t, all, 3)
}

// Fix 1: Disabled rule that previously existed in DB gets disabled
func TestSyncFromConfig_DisabledRuleUpdatedInDB(t *testing.T) {
	init, repo := newTestRuleInit(t)
	ctx := context.Background()

	// First sync: enabled rule
	rules := []RuleConfig{enabledRule("my-rule", "My Rule", "whitelist")}
	require.NoError(t, init.SyncFromConfig(ctx, rules))

	// Get the rule ID
	ruleID := EffectiveRuleID(0, rules[0])
	rule, err := repo.Get(ctx, ruleID)
	require.NoError(t, err)
	assert.True(t, rule.Enabled)

	// Second sync: same rule now disabled
	rules[0].Enabled = false
	require.NoError(t, init.SyncFromConfig(ctx, rules))

	// Rule should still exist but be disabled
	rule, err = repo.Get(ctx, ruleID)
	require.NoError(t, err)
	assert.False(t, rule.Enabled, "rule should be disabled in DB")
}

// Fix 1: Disabled rule that never existed is not created
func TestSyncFromConfig_DisabledRuleNotCreated(t *testing.T) {
	init, repo := newTestRuleInit(t)
	ctx := context.Background()

	rules := []RuleConfig{
		{
			Id:      "never-active",
			Name:    "Never Active",
			Type:    "evm_address_list",
			Mode:    "whitelist",
			Enabled: false,
			Config: map[string]interface{}{
				"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"},
			},
		},
	}
	require.NoError(t, init.SyncFromConfig(ctx, rules))

	ruleID := EffectiveRuleID(0, rules[0])
	_, err := repo.Get(ctx, ruleID)
	assert.ErrorIs(t, err, types.ErrNotFound, "disabled rule that never existed should not be created")
}

// Fix 3: Transaction wrapping (verifies MemoryRuleRepository implements Transactional)
func TestSyncFromConfig_UsesTransaction(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()

	// Verify MemoryRuleRepository implements Transactional
	_, ok := storage.RuleRepository(repo).(storage.Transactional)
	assert.True(t, ok, "MemoryRuleRepository should implement Transactional")

	init, err := NewRuleInitializer(repo, newTestLogger())
	require.NoError(t, err)

	rules := []RuleConfig{enabledRule("tx-rule", "Tx Rule", "whitelist")}
	require.NoError(t, init.SyncFromConfig(context.Background(), rules))

	ruleID := EffectiveRuleID(0, rules[0])
	rule, err := repo.Get(context.Background(), ruleID)
	require.NoError(t, err)
	assert.Equal(t, "Tx Rule", rule.Name)
}

// Fix 4: Post-sync verification catches stale rules
func TestSyncFromConfig_VerificationDetectsStaleRules(t *testing.T) {
	init, repo := newTestRuleInit(t)
	ctx := context.Background()

	// Sync 2 rules
	rules := []RuleConfig{
		enabledRule("rule-a", "Rule A", "whitelist"),
		enabledRule("rule-b", "Rule B", "whitelist"),
	}
	require.NoError(t, init.SyncFromConfig(ctx, rules))

	// Remove Rule B from config — stale cleanup should delete it
	rules = rules[:1]
	require.NoError(t, init.SyncFromConfig(ctx, rules))

	// Only Rule A should remain
	configSource := types.RuleSourceConfig
	all, err := repo.List(ctx, storage.RuleFilter{Source: &configSource, Limit: -1})
	require.NoError(t, err)
	assert.Len(t, all, 1)
	assert.Equal(t, "Rule A", all[0].Name)
}

// SyncFromConfig creates new and updates existing rules
func TestSyncFromConfig_CreateAndUpdate(t *testing.T) {
	init, repo := newTestRuleInit(t)
	ctx := context.Background()

	rules := []RuleConfig{enabledRule("original", "Original", "whitelist")}
	rules[0].Id = "stable-id" // use custom ID so it stays stable across name changes
	require.NoError(t, init.SyncFromConfig(ctx, rules))

	ruleID := types.RuleID("stable-id")
	rule, err := repo.Get(ctx, ruleID)
	require.NoError(t, err)
	assert.Equal(t, "Original", rule.Name)

	// Update rule name
	rules[0].Name = "Updated"
	require.NoError(t, init.SyncFromConfig(ctx, rules))

	rule, err = repo.Get(ctx, ruleID)
	require.NoError(t, err)
	assert.Equal(t, "Updated", rule.Name)
}

// SyncFromConfig with empty rules deletes all stale config rules
func TestSyncFromConfig_EmptyRulesDeletesAll(t *testing.T) {
	init, repo := newTestRuleInit(t)
	ctx := context.Background()

	rules := []RuleConfig{enabledRule("to-delete", "To Delete", "whitelist")}
	require.NoError(t, init.SyncFromConfig(ctx, rules))

	// Now sync with empty rules
	require.NoError(t, init.SyncFromConfig(ctx, nil))

	configSource := types.RuleSourceConfig
	all, err := repo.List(ctx, storage.RuleFilter{Source: &configSource, Limit: -1})
	require.NoError(t, err)
	assert.Len(t, all, 0)
}

// SyncFromConfig rejects rules without explicit id
func TestSyncFromConfig_RequiresExplicitRuleID(t *testing.T) {
	init, _ := newTestRuleInit(t)
	ctx := context.Background()

	rules := []RuleConfig{
		{Name: "No ID", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}}},
	}

	err := init.SyncFromConfig(ctx, rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rules must have explicit id")
	assert.Contains(t, err.Error(), "No ID")
}

// SyncFromConfig rejects duplicate rule IDs
func TestSyncFromConfig_DuplicateRuleIDs(t *testing.T) {
	init, _ := newTestRuleInit(t)
	ctx := context.Background()

	rules := []RuleConfig{
		{Id: "dup", Name: "Rule 1", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}}},
		{Id: "dup", Name: "Rule 2", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}}},
	}

	err := init.SyncFromConfig(ctx, rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate rule id")
}

// createBudgetFromInstanceConfig requires budget.unit when budget block is present
func TestCreateBudgetFromInstanceConfig_RequiresUnit(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{ID: "r1", Variables: []byte("{}")}
	tmpl := &types.RuleTemplate{ID: "t1", BudgetMetering: []byte(`{"method":"count_only","unit":"fallback"}`)}

	// Budget map with max_total but no unit must fail
	noUnit := map[string]interface{}{"max_total": "1000"}
	err := createBudgetFromInstanceConfig(ctx, rule, tmpl, noUnit, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "budget.unit is required")
}

// mockBudgetRepoForCreate implements only Create for tests that need a non-nil BudgetRepository
type mockBudgetRepoForCreate struct{}

func (m *mockBudgetRepoForCreate) Create(ctx context.Context, budget *types.RuleBudget) error { return nil }
func (m *mockBudgetRepoForCreate) GetByRuleID(ctx context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error) {
	return nil, nil
}
func (m *mockBudgetRepoForCreate) Delete(ctx context.Context, id string) error   { return nil }
func (m *mockBudgetRepoForCreate) DeleteByRuleID(ctx context.Context, ruleID types.RuleID) error { return nil }
func (m *mockBudgetRepoForCreate) AtomicSpend(ctx context.Context, ruleID types.RuleID, unit, amount string) error {
	return nil
}
func (m *mockBudgetRepoForCreate) ResetBudget(ctx context.Context, ruleID types.RuleID, unit string, currentPeriodStart time.Time) error {
	return nil
}
func (m *mockBudgetRepoForCreate) ListByRuleID(ctx context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (m *mockBudgetRepoForCreate) ListByRuleIDs(ctx context.Context, ruleIDs []types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (m *mockBudgetRepoForCreate) MarkAlertSent(ctx context.Context, ruleID types.RuleID, unit string) error {
	return nil
}
func (m *mockBudgetRepoForCreate) CountByRuleID(_ context.Context, _ types.RuleID) (int, error) {
	return 0, nil
}
func (m *mockBudgetRepoForCreate) CreateOrGet(_ context.Context, budget *types.RuleBudget) (*types.RuleBudget, bool, error) {
	return budget, true, nil
}

// createBudgetFromInstanceConfig accepts empty for optional fields (template variable instantiated to empty)
func TestCreateBudgetFromInstanceConfig_AcceptsEmptyOptionalFields(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{ID: "r1", Variables: []byte(`{"max_transfer_amount":"","alert_pct":""}`)}
	tmpl := &types.RuleTemplate{ID: "t1", BudgetMetering: []byte(`{"method":"count_only","unit":"x"}`)}
	repo := &mockBudgetRepoForCreate{}

	// unit required; optional fields can be empty (e.g. ${max_transfer_amount} → "")
	budgetMap := map[string]interface{}{
		"unit":        "1:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
		"max_total":  "${max_transfer_amount}", // resolves to ""
		"max_per_tx": "",
		"alert_pct":  "",
	}
	err := createBudgetFromInstanceConfig(ctx, rule, tmpl, budgetMap, repo)
	require.NoError(t, err)
}

// =============================================================================
// resolveBudgetUnit unit tests (config-driven budget unit resolution)
// =============================================================================

func TestResolveBudgetUnit_FromBudgetMapWithVariables(t *testing.T) {
	rule := &types.Rule{
		ID:        "r1",
		Variables: []byte(`{"chain_id":"137","token_address":"0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"}`),
	}
	tmpl := &types.RuleTemplate{ID: "t1"}
	budgetMap := map[string]interface{}{"unit": "${chain_id}:${token_address}"}

	unit, err := resolveBudgetUnit(rule, tmpl, budgetMap)
	require.NoError(t, err)
	// Normalized to lowercase
	assert.Equal(t, "137:0x2791bca1f2de4661ed88a30c99a7a9449aa84174", unit)
}

func TestResolveBudgetUnit_FromTemplateMeteringFallback(t *testing.T) {
	rule := &types.Rule{ID: "r1", Variables: []byte(`{"chain_id":"56","token":"0xabc"}`)}
	tmpl := &types.RuleTemplate{
		ID:              "t1",
		BudgetMetering:  []byte(`{"method":"count_only","unit":"${chain_id}:${token}"}`),
	}
	budgetMap := map[string]interface{}{"unit": ":", "max_total": "100"} // invalid unit, triggers fallback

	unit, err := resolveBudgetUnit(rule, tmpl, budgetMap)
	require.NoError(t, err)
	assert.Equal(t, "56:0xabc", unit)
}

func TestResolveBudgetUnit_EmptyUnitError(t *testing.T) {
	rule := &types.Rule{ID: "r1", Variables: []byte("{}")}
	tmpl := &types.RuleTemplate{ID: "t1"}
	budgetMap := map[string]interface{}{"max_total": "100"} // no unit

	_, err := resolveBudgetUnit(rule, tmpl, budgetMap)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "budget.unit is required")
}

func TestResolveBudgetUnit_UnresolvedVariableError(t *testing.T) {
	rule := &types.Rule{ID: "r1", Variables: []byte(`{"chain_id":"137"}`)} // missing token_address
	tmpl := &types.RuleTemplate{ID: "t1"}
	budgetMap := map[string]interface{}{"unit": "${chain_id}:${token_address}"}

	_, err := resolveBudgetUnit(rule, tmpl, budgetMap)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve to a non-empty value")
	assert.Contains(t, err.Error(), "${")
}

func TestResolveBudgetUnit_Normalized(t *testing.T) {
	rule := &types.Rule{ID: "r1", Variables: []byte("{}")}
	tmpl := &types.RuleTemplate{ID: "t1"}
	budgetMap := map[string]interface{}{"unit": "137:0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"}

	unit, err := resolveBudgetUnit(rule, tmpl, budgetMap)
	require.NoError(t, err)
	assert.Equal(t, "137:0x2791bca1f2de4661ed88a30c99a7a9449aa84174", unit)
}

// =============================================================================
// syncBudgetFromConfig unit tests (diff: delete stale units, ensure current exists)
// =============================================================================

// spyBudgetRepo records calls for assertions; implements storage.BudgetRepository.
type spyBudgetRepo struct {
	listByRuleIDCalls   []types.RuleID
	listByRuleIDReturn  []*types.RuleBudget
	listErr             error // if set, ListByRuleID returns this error
	deleteCalls         []string // IDs deleted
	createCalls         []*types.RuleBudget
	getByRuleIDReturn   map[string]*types.RuleBudget // key "ruleID|unit"
	deleteByRuleIDCalls []types.RuleID
}

func (s *spyBudgetRepo) ListByRuleID(ctx context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error) {
	s.listByRuleIDCalls = append(s.listByRuleIDCalls, ruleID)
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.listByRuleIDReturn, nil
}
func (s *spyBudgetRepo) ListByRuleIDs(ctx context.Context, ruleIDs []types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (s *spyBudgetRepo) GetByRuleID(ctx context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error) {
	if s.getByRuleIDReturn != nil {
		if b, ok := s.getByRuleIDReturn[string(ruleID)+"|"+unit]; ok && b != nil {
			return b, nil
		}
	}
	return nil, types.ErrNotFound
}
func (s *spyBudgetRepo) Create(ctx context.Context, budget *types.RuleBudget) error {
	s.createCalls = append(s.createCalls, budget)
	return nil
}
func (s *spyBudgetRepo) Delete(ctx context.Context, id string) error {
	s.deleteCalls = append(s.deleteCalls, id)
	return nil
}
func (s *spyBudgetRepo) DeleteByRuleID(ctx context.Context, ruleID types.RuleID) error {
	s.deleteByRuleIDCalls = append(s.deleteByRuleIDCalls, ruleID)
	return nil
}
func (s *spyBudgetRepo) AtomicSpend(ctx context.Context, ruleID types.RuleID, unit, amount string) error { return nil }
func (s *spyBudgetRepo) ResetBudget(ctx context.Context, ruleID types.RuleID, unit string, t time.Time) error {
	return nil
}
func (s *spyBudgetRepo) MarkAlertSent(ctx context.Context, ruleID types.RuleID, unit string) error {
	return nil
}
func (s *spyBudgetRepo) CountByRuleID(_ context.Context, _ types.RuleID) (int, error) {
	return 0, nil
}
func (s *spyBudgetRepo) CreateOrGet(_ context.Context, budget *types.RuleBudget) (*types.RuleBudget, bool, error) {
	return budget, true, nil
}

func TestSyncBudgetFromConfig_DeletesStaleUnits(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{
		ID:        "rule-1",
		Variables: []byte(`{"chain_id":"137","token_address":"0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"}`),
	}
	tmpl := &types.RuleTemplate{ID: "t1"}
	budgetMap := map[string]interface{}{"unit": "${chain_id}:${token_address}", "max_total": "1000"}

	// Current config unit is 137:0x2791... (normalized). DB has old unit 56:0x... and current.
	currentUnit := "137:0x2791bca1f2de4661ed88a30c99a7a9449aa84174"
	spy := &spyBudgetRepo{
		listByRuleIDReturn: []*types.RuleBudget{
			{ID: "bdg-old", RuleID: "rule-1", Unit: "56:0xanother"},
			{ID: "bdg-current", RuleID: "rule-1", Unit: currentUnit},
		},
	}

	err := syncBudgetFromConfig(ctx, rule, tmpl, budgetMap, spy)
	require.NoError(t, err)

	// Stale unit (56:0xanother) must be deleted; current must remain (no delete for bdg-current).
	assert.Contains(t, spy.deleteCalls, "bdg-old")
	assert.NotContains(t, spy.deleteCalls, "bdg-current")
	// createBudgetFromInstanceConfig runs: GetByRuleID for current unit returns existing → no create. So we need to either return existing from GetByRuleID or accept that Create might be called with same unit (idempotent create). Our spy doesn't set getByRuleIDReturn so GetByRuleID returns ErrNotFound, so Create will be called. So createCalls has one entry. That's fine.
	assert.Len(t, spy.createCalls, 1)
	assert.Equal(t, currentUnit, spy.createCalls[0].Unit)
}

func TestSyncBudgetFromConfig_CreatesCurrentUnitIfMissing(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{
		ID:        "rule-2",
		Variables: []byte(`{"chain_id":"1","token_address":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"}`),
	}
	tmpl := &types.RuleTemplate{ID: "t1"}
	budgetMap := map[string]interface{}{"unit": "${chain_id}:${token_address}", "max_total": "500"}

	spy := &spyBudgetRepo{listByRuleIDReturn: nil} // no existing budgets

	err := syncBudgetFromConfig(ctx, rule, tmpl, budgetMap, spy)
	require.NoError(t, err)

	assert.Empty(t, spy.deleteCalls)
	assert.Len(t, spy.createCalls, 1)
	assert.Equal(t, "1:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", spy.createCalls[0].Unit)
	assert.Equal(t, "rule-2", string(spy.createCalls[0].RuleID))
}

func TestSyncBudgetFromConfig_IdempotentWhenCurrentExists(t *testing.T) {
	ctx := context.Background()
	currentUnit := "137:0x2791bca1f2de4661ed88a30c99a7a9449aa84174"
	rule := &types.Rule{
		ID:        "rule-3",
		Variables: []byte(`{"chain_id":"137","token_address":"0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"}`),
	}
	tmpl := &types.RuleTemplate{ID: "t1"}
	budgetMap := map[string]interface{}{"unit": "${chain_id}:${token_address}"}

	existing := &types.RuleBudget{ID: "bdg-existing", RuleID: "rule-3", Unit: currentUnit}
	spy := &spyBudgetRepo{
		listByRuleIDReturn: []*types.RuleBudget{existing},
		getByRuleIDReturn:  map[string]*types.RuleBudget{"rule-3|" + currentUnit: existing},
	}

	err := syncBudgetFromConfig(ctx, rule, tmpl, budgetMap, spy)
	require.NoError(t, err)

	// No stale units to delete
	assert.Empty(t, spy.deleteCalls)
	// createBudgetFromInstanceConfig: GetByRuleID returns existing → skip Create
	assert.Empty(t, spy.createCalls)
}

func TestSyncBudgetFromConfig_ListError(t *testing.T) {
	ctx := context.Background()
	rule := &types.Rule{ID: "r1", Variables: []byte("{}")}
	tmpl := &types.RuleTemplate{ID: "t1"}
	budgetMap := map[string]interface{}{"unit": "1:0xabc"}

	listFailing := &spyBudgetRepo{listErr: assert.AnError}
	err := syncBudgetFromConfig(ctx, rule, tmpl, budgetMap, listFailing)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list budgets")
}

// =============================================================================
// SyncFromConfig: deleting a rule from config deletes its budgets (config-driven diff)
// =============================================================================

func TestSyncFromConfig_DeletingRuleDeletesBudgets(t *testing.T) {
	init, _ := newTestRuleInit(t)
	spy := &spyBudgetRepo{}
	init.SetBudgetRepo(spy)
	ctx := context.Background()

	rules := []RuleConfig{
		enabledRule("rule-keep", "Keep", "whitelist"),
		enabledRule("rule-remove", "Remove", "whitelist"),
	}
	require.NoError(t, init.SyncFromConfig(ctx, rules))

	// Remove second rule from config
	require.NoError(t, init.SyncFromConfig(ctx, rules[:1]))

	// executeSyncBody must have called DeleteByRuleID for the removed rule
	removeID := EffectiveRuleID(1, rules[1])
	assert.Contains(t, spy.deleteByRuleIDCalls, removeID, "deleting rule from config should delete its budgets")
}
