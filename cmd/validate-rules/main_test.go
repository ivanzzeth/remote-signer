package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// projectRoot returns the project root (remote-signer repo).
func projectRoot(t *testing.T) string {
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	// main_test.go is in cmd/validate-rules; go up to repo root
	root := filepath.Join(dir, "..", "..")
	abs, err := filepath.Abs(root)
	require.NoError(t, err)
	return abs
}

// TestConfigExampleYAMLValidates ensures config.example.yaml loads, expands, and all
// enabled Solidity expression rules pass validation. Same pipeline as:
//   go run ./cmd/validate-rules/ -config config.example.yaml
// If this test fails, config.example.yaml or the expanded rules are broken; fix the
// config or the validator so that the example config validates.
func TestConfigExampleYAMLValidates(t *testing.T) {
	if _, err := exec.LookPath("forge"); err != nil {
		t.Skip("forge not found in PATH, skipping config.example.yaml validation")
	}

	root := projectRoot(t)
	configPath := filepath.Join(root, "config.example.yaml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatalf("config.example.yaml not found at %s", configPath)
	}

	cfg, err := config.Load(configPath)
	require.NoError(t, err, "load config.example.yaml")

	configDir := filepath.Dir(configPath)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))

	templates, err := config.ExpandTemplatesFromFiles(cfg.Templates, configDir, logger)
	require.NoError(t, err, "expand templates")

	rules, err := config.ExpandInstanceRules(cfg.Rules, templates)
	require.NoError(t, err, "expand instance rules")

	rules, err = config.ExpandFileRules(rules, configDir, logger)
	require.NoError(t, err, "expand file rules")

	// Collect enabled Solidity expression rules and convert to types.Rule
	var toValidate []*types.Rule
	for i, r := range rules {
		if !r.Enabled {
			continue
		}
		if r.Type != string(types.RuleTypeEVMSolidityExpression) {
			continue
		}
		rule, err := configRuleToTypesRule(i, r)
		require.NoError(t, err, "convert rule %q", r.Name)
		toValidate = append(toValidate, rule)
	}

	if len(toValidate) == 0 {
		t.Log("no enabled evm_solidity_expression rules in config.example.yaml (skipping batch validation)")
		return
	}

	evaluator, err := evm.NewSolidityRuleEvaluator(evm.SolidityEvaluatorConfig{
		Timeout: 120 * time.Second,
	}, logger)
	require.NoError(t, err)

	validator, err := evm.NewSolidityRuleValidator(evaluator, logger)
	require.NoError(t, err)

	ctx := context.Background()
	batchResult, err := validator.ValidateRulesBatch(ctx, toValidate)
	require.NoError(t, err, "batch validation must succeed for config.example.yaml")
	require.Len(t, batchResult.Results, len(toValidate), "result count mismatch")

	for i, result := range batchResult.Results {
		rule := toValidate[i]
		require.True(t, result.Valid, "rule %q must be valid: syntax=%v, failed_test_cases=%d, details=%s",
			rule.Name,
			result.SyntaxError,
			result.FailedTestCases,
			formatResultDetails(&result),
		)
	}
}

func configRuleToTypesRule(idx int, r config.RuleConfig) (*types.Rule, error) {
	configJSON, err := json.Marshal(r.Config)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	rule := &types.Rule{
		ID:          types.RuleID(fmt.Sprintf("test_%d", idx)),
		Name:        r.Name,
		Description: r.Description,
		Type:        types.RuleType(r.Type),
		Mode:        types.RuleMode(r.Mode),
		Source:      types.RuleSourceConfig,
		Config:      configJSON,
		Enabled:     r.Enabled,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if r.ChainType != "" {
		ct := types.ChainType(r.ChainType)
		rule.ChainType = &ct
	} else {
		ct := types.ChainTypeEVM
		rule.ChainType = &ct
	}
	if r.ChainID != "" {
		rule.ChainID = &r.ChainID
	}
	return rule, nil
}

func formatResultDetails(r *evm.ValidationResult) string {
	if r.SyntaxError != nil {
		return r.SyntaxError.Message
	}
	for _, tc := range r.TestCaseResults {
		if !tc.Passed {
			return fmt.Sprintf("test %q: %s", tc.Name, tc.Error)
		}
	}
	return ""
}
