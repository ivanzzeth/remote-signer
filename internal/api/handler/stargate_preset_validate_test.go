//go:build integration

package handler

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func resolveAoriPresetVars(t *testing.T, aoriData []byte, presetDefaults map[string]string) map[string]string {
	t.Helper()
	var aoriFile struct {
		Variables     []types.TemplateVariable `yaml:"variables"`
		TestVariables map[string]string        `yaml:"test_variables"`
	}
	require.NoError(t, yaml.Unmarshal(aoriData, &aoriFile))
	resolvedVars := resolveTemplateDefaults(aoriFile.Variables, aoriFile.TestVariables)
	for k, v := range presetDefaults {
		resolvedVars[k] = v
	}
	return resolvedVars
}

func aoriRulesBundleJSON(t *testing.T, aoriData []byte) []byte {
	t.Helper()
	var aoriFile struct {
		Rules []map[string]interface{} `yaml:"rules"`
	}
	require.NoError(t, yaml.Unmarshal(aoriData, &aoriFile))
	for i, rule := range aoriFile.Rules {
		if tcRaw, ok := rule["test_cases"]; ok {
			cfg := rule["config"].(map[string]interface{})
			cfg["test_cases"] = tcRaw
			delete(aoriFile.Rules[i], "test_cases")
		}
	}
	rulesJSON, err := json.Marshal(map[string]interface{}{"rules": aoriFile.Rules})
	require.NoError(t, err)
	return rulesJSON
}

func loadStargatePresetDefaults(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "rules", "presets", "evm", "stargate.yaml"))
	if err != nil {
		data, err = os.ReadFile(filepath.Join(os.Getenv("HOME"), ".remote-signer", "rules", "presets", "evm", "stargate.yaml"))
	}
	require.NoError(t, err)
	var presetFile struct {
		Defaults map[string]string `yaml:"defaults"`
	}
	require.NoError(t, yaml.Unmarshal(data, &presetFile))
	return presetFile.Defaults
}

// Regression: preset validate merges Stargate allowed_dst_eids (includes 30101).
// Negative test must use dstEid NOT in that list (99999), not 30101.
func TestStargatePresetValidate_AoriTemplate(t *testing.T) {
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	aoriData, err := os.ReadFile(filepath.Join("..", "..", "..", "rules", "templates", "evm", "aori.yaml"))
	require.NoError(t, err)

	resolvedVars := resolveAoriPresetVars(t, aoriData, loadStargatePresetDefaults(t))
	rulesConfig := aoriRulesBundleJSON(t, aoriData)
	results, allPassed := ValidateTemplateConfig(eval, "Aori Order Signature", rulesConfig, resolvedVars)
	for _, r := range results {
		t.Logf("rule=%s valid=%v err=%q", r.RuleName, r.Valid, r.Error)
	}
	assert.True(t, allPassed)
}

func TestStargatePresetValidate_OldDstEid30101Negative_Fails(t *testing.T) {
	eval, err := evm.NewJSRuleEvaluator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	aoriData, err := os.ReadFile(filepath.Join("..", "..", "..", "rules", "templates", "evm", "aori.yaml"))
	require.NoError(t, err)
	stale := strings.Replace(string(aoriData), "dstEid: 99999", "dstEid: 30101", 1)

	resolvedVars := resolveAoriPresetVars(t, []byte(stale), loadStargatePresetDefaults(t))
	rulesConfig := aoriRulesBundleJSON(t, []byte(stale))
	results, allPassed := ValidateTemplateConfig(eval, "Aori Order Signature", rulesConfig, resolvedVars)
	assert.False(t, allPassed, "stale dstEid 30101 negative must fail under Stargate preset vars")
	require.NotEmpty(t, results)
	assert.False(t, results[0].Valid)
	assert.Contains(t, results[0].Error, "1 test case(s) failed")
	t.Logf("stale failure: %q", results[0].Error)
}
