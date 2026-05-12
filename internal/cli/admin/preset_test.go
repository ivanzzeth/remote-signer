package admin

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

// The mergeRulesAndTemplateIntoConfig round-trip tests covered the
// preset-writes-into-config-yaml workflow that v0.3.0 retires (rules and
// templates are now managed exclusively via the admin API). The merge
// helper is preserved for offline preset previewing; coverage for the
// preset-application flow lives at the API/handler layer.

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
