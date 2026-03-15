package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/preset"
)

func TestSetStringsToMap(t *testing.T) {
	out := setStringsToMap(nil)
	assert.Empty(t, out)

	out = setStringsToMap([]string{})
	assert.Empty(t, out)

	out = setStringsToMap([]string{"a=1", "b=2"})
	assert.Equal(t, "1", out["a"])
	assert.Equal(t, "2", out["b"])

	out = setStringsToMap([]string{"key=value=with=equals"})
	assert.Equal(t, "value=with=equals", out["key"])

	out = setStringsToMap([]string{"noeq"})
	assert.Empty(t, out)
}

func TestGetPresetMeta_CLIUsage(t *testing.T) {
	data := []byte(`
template: "My Template"
template_path: "rules/templates/foo.yaml"
override_hints:
  - var1
  - var2
`)
	meta, err := preset.GetPresetMeta(data)
	require.NoError(t, err)
	assert.Equal(t, "My Template", meta.Template)
	assert.Equal(t, "rules/templates/foo.yaml", meta.TemplatePath)
	assert.Equal(t, []string{"var1", "var2"}, meta.OverrideHints)
}

func TestParsePresetFile_SingleRule(t *testing.T) {
	data := []byte(`
name: "Test Rule"
template: "Test Template"
chain_type: "evm"
chain_id: "137"
enabled: true
variables:
  chain_id: "137"
  allowed_safe_addresses: "0xaaa"
`)
	presetRules, err := preset.ParsePresetFile(data, nil)
	require.NoError(t, err)
	require.Len(t, presetRules, 1)
	rules := make([]config.RuleConfig, len(presetRules))
	for i, pr := range presetRules {
		rules[i] = presetRuleToRuleConfig(pr)
	}
	assert.Equal(t, "Test Rule", rules[0].Name)
	assert.Equal(t, "instance", rules[0].Type)
	assert.Equal(t, "evm", rules[0].ChainType)
	assert.Equal(t, "137", rules[0].ChainID)
	assert.Equal(t, "Test Template", rules[0].Config["template"])
	vars, _ := rules[0].Config["variables"].(map[string]interface{})
	require.NotNil(t, vars)
	assert.Equal(t, "137", vars["chain_id"])
	assert.Equal(t, "0xaaa", vars["allowed_safe_addresses"])
}

func TestParsePresetFile_OverridesApplied(t *testing.T) {
	data := []byte(`
name: "Test"
template: "T"
chain_type: "evm"
chain_id: "137"
enabled: true
variables:
  allowed_safe_addresses: "0xold"
`)
	overrides := map[string]string{"allowed_safe_addresses": "0xnew"}
	presetRules, err := preset.ParsePresetFile(data, overrides)
	require.NoError(t, err)
	require.Len(t, presetRules, 1)
	rules := make([]config.RuleConfig, len(presetRules))
	for i, pr := range presetRules {
		rules[i] = presetRuleToRuleConfig(pr)
	}
	vars, _ := rules[0].Config["variables"].(map[string]interface{})
	require.NotNil(t, vars)
	assert.Equal(t, "0xnew", vars["allowed_safe_addresses"])
}

func TestParsePresetFile_ArrayVariableNormalized(t *testing.T) {
	data := []byte(`
name: "Test"
template: "T"
chain_type: "evm"
chain_id: "1"
enabled: true
variables:
  allowed_safe_addresses:
    - "0xa"
    - "0xb"
`)
	presetRules, err := preset.ParsePresetFile(data, nil)
	require.NoError(t, err)
	require.Len(t, presetRules, 1)
	rules := make([]config.RuleConfig, len(presetRules))
	for i, pr := range presetRules {
		rules[i] = presetRuleToRuleConfig(pr)
	}
	vars, _ := rules[0].Config["variables"].(map[string]interface{})
	require.NotNil(t, vars)
	assert.Equal(t, "0xa,0xb", vars["allowed_safe_addresses"])
}

func TestParsePresetFile_NoTemplate(t *testing.T) {
	data := []byte(`
name: "X"
variables: {}
`)
	_, err := preset.ParsePresetFile(data, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no rules")
}

func TestListPresets_Integration(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "p.yaml"), []byte("template: \"Foo Template\"\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "m.yaml"), []byte(`
rules:
  - config:
      template: "A"
  - config:
      template: "B"
`), 0644))
	entries, err := preset.ListPresets(dir)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	ids := map[string][]string{}
	for _, e := range entries {
		ids[e.ID] = e.TemplateNames
	}
	assert.Equal(t, []string{"Foo Template"}, ids["p.yaml"])
	assert.Equal(t, []string{"A", "B"}, ids["m.yaml"])
}

func TestMergeRulesAndTemplateIntoConfig_InjectsTemplateAndAppendsRule(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	// Minimal valid config for config.Load (needs server, database, chains.evm.enabled, api_keys with valid key)
	// Ed25519 public key base64 (32 bytes) - use a valid one so ResolvePublicKey passes
	minimal := `server:
  host: "0.0.0.0"
  port: 8548
  tls:
    enabled: false
database:
  dsn: "file:./data/test.db"
chains:
  evm:
    enabled: true
api_keys:
  - id: "admin"
    name: "Admin"
    public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    admin: true
    enabled: true
    rate_limit: 100
`
	err := os.WriteFile(configPath, []byte(minimal), 0600)
	require.NoError(t, err)

	rule := config.RuleConfig{
		Name:      "Injected Rule",
		Type:      "instance",
		Mode:      "whitelist",
		ChainType: "evm",
		ChainID:   "137",
		Enabled:   true,
		Config: map[string]interface{}{
			"template": "Injected Template",
			"variables": map[string]interface{}{"chain_id": "137"},
		},
	}

	err = mergeRulesAndTemplateIntoConfig(configPath, []config.RuleConfig{rule}, "Injected Template", "rules/templates/injected.yaml")
	require.NoError(t, err)

	cfg, err := config.Load(configPath)
	require.NoError(t, err)
	require.Len(t, cfg.Templates, 1)
	assert.Equal(t, "Injected Template", cfg.Templates[0].Name)
	assert.Equal(t, "file", cfg.Templates[0].Type)
	assert.Equal(t, "rules/templates/injected.yaml", cfg.Templates[0].Config["path"])
	require.Len(t, cfg.Rules, 1)
	assert.Equal(t, "Injected Rule", cfg.Rules[0].Name)
}

func TestMergeRulesAndTemplateIntoConfig_DoesNotDuplicateTemplate(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	minimal := `server:
  host: "0.0.0.0"
  port: 8548
  tls:
    enabled: false
database:
  dsn: "file:./data/test.db"
chains:
  evm:
    enabled: true
templates:
  - name: "Existing"
    type: "file"
    enabled: true
    config:
      path: "rules/existing.yaml"
api_keys:
  - id: "admin"
    name: "Admin"
    public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    admin: true
    enabled: true
    rate_limit: 100
`
	err := os.WriteFile(configPath, []byte(minimal), 0600)
	require.NoError(t, err)

	rule := config.RuleConfig{
		Name: "R", Type: "instance", Mode: "whitelist",
		ChainType: "evm", ChainID: "1", Enabled: true,
		Config: map[string]interface{}{"template": "Existing", "variables": map[string]interface{}{}},
	}

	err = mergeRulesAndTemplateIntoConfig(configPath, []config.RuleConfig{rule}, "Existing", "rules/templates/existing.yaml")
	require.NoError(t, err)

	cfg, err := config.Load(configPath)
	require.NoError(t, err)
	// Should still have only one template (no duplicate)
	require.Len(t, cfg.Templates, 1)
	assert.Equal(t, "Existing", cfg.Templates[0].Name)
	require.Len(t, cfg.Rules, 1)
}

// TestMergeRulesAndTemplateIntoConfig_QuotesUnitWithColon ensures budget.unit values
// containing ':' (e.g. "${chain_id}:${token_address}") are written as quoted YAML so
// the colon is not parsed as key-value (mapping values are not allowed in this context).
func TestMergeRulesAndTemplateIntoConfig_QuotesUnitWithColon(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	minimal := `server:
  host: "0.0.0.0"
  port: 8548
  tls:
    enabled: false
database:
  dsn: "file:./data/test.db"
chains:
  evm:
    enabled: true
api_keys:
  - id: "admin"
    name: "Admin"
    public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    admin: true
    enabled: true
    rate_limit: 100
`
	require.NoError(t, os.WriteFile(configPath, []byte(minimal), 0600))

	rule := config.RuleConfig{
		Name: "ERC20 Budget", Type: "instance", Mode: "whitelist",
		ChainType: "evm", ChainID: "1", Enabled: true,
		Config: map[string]interface{}{
			"template": "ERC20 Template",
			"variables": map[string]interface{}{"chain_id": "1", "token_address": "0xabc"},
			"budget": map[string]interface{}{
				"unit": "${chain_id}:${token_address}",
				"max_total": "1000",
			},
		},
	}

	err := mergeRulesAndTemplateIntoConfig(configPath, []config.RuleConfig{rule}, "ERC20 Template", "rules/templates/erc20.yaml")
	require.NoError(t, err)

	raw, err := os.ReadFile(configPath)
	require.NoError(t, err)
	// Must be written quoted so YAML parser does not treat the colon as key-value
	assert.Contains(t, string(raw), `"${chain_id}:${token_address}"`, "budget.unit must be double-quoted in YAML output")
	// Round-trip: config.Load must parse without "mapping values are not allowed" error
	cfg, err := config.Load(configPath)
	require.NoError(t, err)
	require.Len(t, cfg.Rules, 1)
	// budget["unit"] after Load is env-expanded (${chain_id} etc.), so we only assert structure
	budget, _ := cfg.Rules[0].Config["budget"].(map[string]interface{})
	require.NotNil(t, budget)
	assert.Contains(t, budget, "unit")
}

func TestGetPresetVarsWithDescriptions(t *testing.T) {
	dir := t.TempDir()
	presetsDir := filepath.Join(dir, "presets")
	templatesDir := filepath.Join(dir, "rules", "templates")
	require.NoError(t, os.MkdirAll(presetsDir, 0755))
	require.NoError(t, os.MkdirAll(templatesDir, 0755))

	presetPath := filepath.Join(presetsDir, "test.yaml")
	err := os.WriteFile(presetPath, []byte(`
template: "Test Template"
template_path: "rules/templates/test.yaml"
override_hints:
  - addr
  - label
`), 0644)
	require.NoError(t, err)

	templatePath := filepath.Join(dir, "rules", "templates", "test.yaml")
	err = os.WriteFile(templatePath, []byte(`
variables:
  - name: addr
    type: address
    description: "Allowed address"
    required: true
  - name: label
    type: string
    description: "Optional label"
    required: false
rules: []
`), 0644)
	require.NoError(t, err)

	vars, err := getPresetVarsWithDescriptions(presetPath, dir)
	require.NoError(t, err)
	require.Len(t, vars, 2)
	assert.Equal(t, "addr", vars[0].Name)
	assert.Equal(t, "Allowed address", vars[0].Desc)
	assert.Equal(t, "label", vars[1].Name)
	assert.Equal(t, "Optional label", vars[1].Desc)
}

func TestGetPresetVarsWithDescriptions_NoOverrideHints(t *testing.T) {
	dir := t.TempDir()
	presetPath := filepath.Join(dir, "p.yaml")
	err := os.WriteFile(presetPath, []byte("template: \"T\"\n"), 0644)
	require.NoError(t, err)
	vars, err := getPresetVarsWithDescriptions(presetPath, dir)
	require.NoError(t, err)
	assert.Nil(t, vars)
}
