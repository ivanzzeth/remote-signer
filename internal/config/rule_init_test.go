package config

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

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
