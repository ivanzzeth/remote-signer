//go:build integration

package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TestAoriTemplate_AllTestCases loads evm/aori.yaml and validates every bundled
// test case with template test_variables (single-chain template validation path).
func TestAoriTemplate_AllTestCases(t *testing.T) {
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "rules", "templates", "evm", "aori.yaml"))
	require.NoError(t, err)

	var f struct {
		Variables     []types.TemplateVariable `yaml:"variables"`
		TestVariables map[string]string        `yaml:"test_variables"`
		Rules         []map[string]interface{} `yaml:"rules"`
	}
	require.NoError(t, yaml.Unmarshal(data, &f))

	resolvedVars := make(map[string]string)
	for _, v := range f.Variables {
		if v.Default != nil {
			resolvedVars[v.Name] = fmt.Sprint(v.Default)
		}
	}
	for k, v := range f.TestVariables {
		resolvedVars[k] = v
	}

	for i, rule := range f.Rules {
		if tcRaw, ok := rule["test_cases"]; ok {
			if cfg, ok := rule["config"].(map[string]interface{}); ok {
				cfg["test_cases"] = tcRaw
			} else {
				rule["config"] = map[string]interface{}{"test_cases": tcRaw}
			}
			delete(f.Rules[i], "test_cases")
		}
	}

	rulesConfig, err := json.Marshal(map[string]interface{}{"rules": f.Rules})
	require.NoError(t, err)

	results, allPassed := ValidateTemplateConfig(eval, "aori", rulesConfig, resolvedVars)
	assert.True(t, allPassed, "all aori template test cases should pass")
	for _, r := range results {
		t.Logf("Rule: %s valid=%v error=%q", r.RuleName, r.Valid, r.Error)
		if !r.Valid {
			t.Errorf("FAIL %s: %s", r.RuleName, r.Error)
		}
	}
	assert.Positive(t, len(results))
}
