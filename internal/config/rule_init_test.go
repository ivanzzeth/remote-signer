package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
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
