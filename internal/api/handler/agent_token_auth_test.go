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

// agentPresetVars mirrors evm/agent preset composite variables.
var agentPresetVars = map[string]string{
	"trusted_contracts":     "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	"token_address":         "",
	"allowed_spenders":      "",
	"allowed_recipients":    "",
	"allowed_transfer_from": "",
	"max_transfer_amount":   "0",
	"max_approve_amount":    "-1",
	"allowed_approve_to":    "",
	"allowed_operators":     "",
	"auth_only":             "true",
}

func TestAgentTokenAuthTemplates_AgentModeTestCases(t *testing.T) {
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	templates := []string{"erc20.yaml", "erc721.yaml", "erc1155.yaml"}
	rulesDir := filepath.Join("..", "..", "..", "rules", "templates", "evm")

	for _, file := range templates {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(rulesDir, file))
			require.NoError(t, err)

			var f struct {
				Variables     []types.TemplateVariable `yaml:"variables"`
				TestVariables map[string]string        `yaml:"test_variables"`
				Rules         []map[string]interface{} `yaml:"rules"`
			}
			require.NoError(t, yaml.Unmarshal(data, &f))

			baseVars := make(map[string]string)
			for _, v := range f.Variables {
				if v.Default != nil {
					baseVars[v.Name] = fmt.Sprint(v.Default)
				}
			}
			for k, v := range f.TestVariables {
				baseVars[k] = v
			}
			for k, v := range agentPresetVars {
				baseVars[k] = v
			}

			agentCaseCount := 0
			for _, rule := range f.Rules {
				tcRaw, ok := rule["test_cases"]
				if !ok {
					continue
				}
				tcJSON, _ := json.Marshal(tcRaw)
				var cases []struct {
					Name       string                 `json:"name"`
					Variables  map[string]string      `json:"variables"`
					Input      map[string]interface{} `json:"input"`
					ExpectPass bool                   `json:"expect_pass"`
				}
				require.NoError(t, json.Unmarshal(tcJSON, &cases))

				script, _ := rule["config"].(map[string]interface{})["script"].(string)
				require.NotEmpty(t, script, "rule must have script")

				cfgMap := make(map[string]interface{})
				if cfg, ok := rule["config"].(map[string]interface{}); ok {
					for k, v := range cfg {
						if k != "script" && k != "test_cases" {
							cfgMap[k] = v
						}
					}
				}
				for k, v := range baseVars {
					cfgMap[k] = v
				}

				for _, tc := range cases {
					if len(tc.Variables) == 0 {
						continue
					}
					agentCaseCount++
					effectiveCfg := make(map[string]interface{}, len(cfgMap)+len(tc.Variables))
					for k, v := range cfgMap {
						effectiveCfg[k] = v
					}
					for k, v := range tc.Variables {
						effectiveCfg[k] = v
					}
					result := runJSTestCase(eval, script, effectiveCfg, evmhandlerJSRuleTestCase{
						Name:       tc.Name,
						Input:      tc.Input,
						Variables:  tc.Variables,
						ExpectPass: tc.ExpectPass,
					}, types.RuleModeWhitelist)
					if !result.Passed {
						t.Errorf("FAIL %s: %s", tc.Name, result.Reason)
					}
				}
			}
			assert.Positive(t, agentCaseCount, "%s should have agent-mode test cases with per-case variables", file)
		})
	}
}

func TestERC20Template_AllTestCases(t *testing.T) {
	runTemplateAllTestCases(t, "erc20.yaml")
}

func TestERC721Template_AllTestCases(t *testing.T) {
	runTemplateAllTestCases(t, "erc721.yaml")
}

func TestERC1155Template_AllTestCases(t *testing.T) {
	runTemplateAllTestCases(t, "erc1155.yaml")
}

func runTemplateAllTestCases(t *testing.T, filename string) {
	t.Helper()
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "rules", "templates", "evm", filename))
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

	rulesConfig, _ := json.Marshal(map[string]interface{}{"rules": f.Rules})
	resolvedConfig, err := service.SubstituteVariables(rulesConfig, resolvedVars)
	require.NoError(t, err)

	results, allPassed := ValidateTemplateConfig(eval, filename, resolvedConfig, resolvedVars)
	for _, r := range results {
		if !r.Valid {
			t.Errorf("FAIL %s: %s", r.RuleName, r.Error)
		}
	}
	assert.True(t, allPassed, "all %s template test cases should pass", filename)
}
