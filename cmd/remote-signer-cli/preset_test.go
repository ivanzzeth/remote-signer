package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/config"
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

func TestGetPresetMeta(t *testing.T) {
	data := []byte(`
template: "My Template"
template_path: "rules/templates/foo.yaml"
override_hints:
  - var1
  - var2
`)
	meta := getPresetMeta(data)
	assert.Equal(t, "My Template", meta.template)
	assert.Equal(t, "rules/templates/foo.yaml", meta.templatePath)
	assert.Equal(t, []string{"var1", "var2"}, meta.overrideHints)

	// No override_hints
	data2 := []byte(`template: "T"`)
	meta2 := getPresetMeta(data2)
	assert.Equal(t, "T", meta2.template)
	assert.Empty(t, meta2.templatePath)
	assert.NotNil(t, meta2.overrideHints)
	assert.Empty(t, meta2.overrideHints)

	// Invalid YAML
	meta3 := getPresetMeta([]byte("not yaml"))
	assert.Empty(t, meta3.template)
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
	rules, err := parsePresetFile(data, nil)
	require.NoError(t, err)
	require.Len(t, rules, 1)
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
	rules, err := parsePresetFile(data, overrides)
	require.NoError(t, err)
	require.Len(t, rules, 1)
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
	rules, err := parsePresetFile(data, nil)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	vars, _ := rules[0].Config["variables"].(map[string]interface{})
	require.NotNil(t, vars)
	// Should be normalized to comma-separated string
	assert.Equal(t, "0xa,0xb", vars["allowed_safe_addresses"])
}

func TestParsePresetFile_NoTemplate(t *testing.T) {
	data := []byte(`
name: "X"
variables: {}
`)
	_, err := parsePresetFile(data, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no rules")
}

func TestPresetTemplateNames_Single(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "p.yaml")
	err := os.WriteFile(f, []byte("template: \"Foo Template\"\n"), 0644)
	require.NoError(t, err)
	name, err := presetTemplateNames(f)
	require.NoError(t, err)
	assert.Equal(t, "Foo Template", name)
}

func TestPresetTemplateNames_Multi(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "m.yaml")
	err := os.WriteFile(f, []byte(`
rules:
  - config:
      template: "A"
  - config:
      template: "B"
`), 0644)
	require.NoError(t, err)
	name, err := presetTemplateNames(f)
	require.NoError(t, err)
	assert.Equal(t, "A, B", name)
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

func TestNormalizeVariables(t *testing.T) {
	assert.Nil(t, normalizeVariables(nil))
	out := normalizeVariables(map[string]interface{}{
		"a": "scalar",
		"b": []interface{}{"x", "y"},
	})
	assert.Equal(t, "scalar", out["a"])
	assert.Equal(t, "x,y", out["b"])
}

func TestToMapStringInterface(t *testing.T) {
	assert.Nil(t, toMapStringInterface(nil))
	out := toMapStringInterface(map[string]interface{}{"k": "v"})
	assert.Equal(t, map[string]interface{}{"k": "v"}, out)
	// map[interface{}]interface{} (YAML unmarshal)
	out2 := toMapStringInterface(map[interface{}]interface{}{"k": "v"})
	assert.Equal(t, map[string]interface{}{"k": "v"}, out2)
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
