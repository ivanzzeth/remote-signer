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
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TestUniswapTemplate_AllTestCases loads the uniswap template YAML and
// validates every test case against the JS evaluator. Covers V2/V3/V4
// swap, ERC20 approve, WETH, Permit2, and all reject paths.
func TestUniswapTemplate_AllTestCases(t *testing.T) {
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "rules", "templates", "evm", "uniswap.yaml"))
	require.NoError(t, err)

	var f struct {
		Variables     []types.TemplateVariable `yaml:"variables"`
		TestVariables map[string]string        `yaml:"test_variables"`
		Rules         []map[string]interface{} `yaml:"rules"`
	}
	require.NoError(t, yaml.Unmarshal(data, &f))

	// Resolve variables: defaults + test_variables
	resolvedVars := make(map[string]string)
	for _, v := range f.Variables {
		if v.Default != nil {
			resolvedVars[v.Name] = fmt.Sprint(v.Default)
		}
	}
	for k, v := range f.TestVariables {
		resolvedVars[k] = v
	}

	// Move test_cases from rule level into config (ValidateTemplateConfig expects them inside config)
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

	// Marshal rules as JSON config bundle for substitution
	rulesConfig, _ := json.Marshal(map[string]interface{}{"rules": f.Rules})
	resolvedConfig, err := service.SubstituteVariables(rulesConfig, resolvedVars)
	require.NoError(t, err)

	results, allPassed := ValidateTemplateConfig(eval, "uniswap", resolvedConfig, resolvedVars)
	assert.True(t, allPassed, "all uniswap template test cases should pass")

	// Print individual test case results for debugging
	for _, r := range results {
		t.Logf("Rule: %s valid=%v error=%q", r.RuleName, r.Valid, r.Error)
		if !r.Valid {
			t.Errorf("FAIL %s: %s", r.RuleName, r.Error)
		}
	}

	assert.Positive(t, len(results), "should have at least one rule result")
}
