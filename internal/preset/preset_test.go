package preset

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPresetMeta_SingleRule(t *testing.T) {
	data := []byte(`
template: "My Template"
template_path: "rules/templates/foo.yaml"
override_hints:
  - var1
  - var2
`)
	meta, err := GetPresetMeta(data)
	require.NoError(t, err)
	assert.Equal(t, "My Template", meta.Template)
	assert.Equal(t, "rules/templates/foo.yaml", meta.TemplatePath)
	assert.Equal(t, []string{"var1", "var2"}, meta.OverrideHints)
}

func TestGetPresetMeta_NoOverrideHints(t *testing.T) {
	data := []byte(`template: "T"`)
	meta, err := GetPresetMeta(data)
	require.NoError(t, err)
	assert.Equal(t, "T", meta.Template)
	assert.Empty(t, meta.TemplatePath)
	assert.NotNil(t, meta.OverrideHints)
	assert.Empty(t, meta.OverrideHints)
}

func TestGetPresetMeta_Composite(t *testing.T) {
	data := []byte(`
template_paths:
  - "rules/templates/a.yaml"
  - "rules/templates/b.yaml"
template_names:
  - "A"
  - "B"
override_hints: []
`)
	meta, err := GetPresetMeta(data)
	require.NoError(t, err)
	assert.Empty(t, meta.Template)
	assert.Equal(t, []string{"rules/templates/a.yaml", "rules/templates/b.yaml"}, meta.TemplatePaths)
	assert.Equal(t, []string{"A", "B"}, meta.TemplateNames)
}

func TestGetPresetMeta_InvalidYAML(t *testing.T) {
	_, err := GetPresetMeta([]byte("[invalid"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse preset meta")
}

func TestGetPresetMeta_EmptyFields(t *testing.T) {
	meta, err := GetPresetMeta([]byte("{}"))
	require.NoError(t, err)
	assert.Empty(t, meta.Template)
	assert.Nil(t, meta.TemplatePaths)
	assert.Nil(t, meta.TemplateNames)
	assert.NotNil(t, meta.OverrideHints)
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
	rules, err := ParsePresetFile(data, nil)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "Test Rule", rules[0].Name)
	assert.Equal(t, "Test Template", rules[0].TemplateName)
	assert.Equal(t, "evm", rules[0].ChainType)
	assert.Equal(t, "137", rules[0].ChainID)
	assert.True(t, rules[0].Enabled)
	assert.Equal(t, "137", rules[0].Variables["chain_id"])
	assert.Equal(t, "0xaaa", rules[0].Variables["allowed_safe_addresses"])
}

func TestParsePresetFile_SingleRuleWithMode(t *testing.T) {
	data := []byte(`
name: "Block Rule"
template: "Block Template"
mode: "blocklist"
chain_type: "evm"
chain_id: "1"
enabled: true
variables:
  chain_id: "1"
`)
	rules, err := ParsePresetFile(data, nil)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "blocklist", rules[0].Mode)
}

func TestParsePresetFile_ModeDefaultsEmpty(t *testing.T) {
	data := []byte(`
name: "No Mode"
template: "T"
chain_type: "evm"
chain_id: "1"
enabled: true
`)
	rules, err := ParsePresetFile(data, nil)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "", rules[0].Mode)
}

func TestParsePresetFile_MultiRuleWithMode(t *testing.T) {
	data := []byte(`
rules:
  - name: "R1"
    type: "instance"
    mode: "blocklist"
    config:
      template: "T1"
      variables: {}
  - name: "R2"
    type: "instance"
    mode: "whitelist"
    config:
      template: "T2"
      variables: {}
`)
	rules, err := ParsePresetFile(data, nil)
	require.NoError(t, err)
	require.Len(t, rules, 2)
	assert.Equal(t, "blocklist", rules[0].Mode)
	assert.Equal(t, "whitelist", rules[1].Mode)
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
	rules, err := ParsePresetFile(data, overrides)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "0xnew", rules[0].Variables["allowed_safe_addresses"])
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
	rules, err := ParsePresetFile(data, nil)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "0xa,0xb", rules[0].Variables["allowed_safe_addresses"])
}

func TestParsePresetFile_NoTemplate(t *testing.T) {
	data := []byte(`
name: "X"
variables: {}
`)
	_, err := ParsePresetFile(data, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no rules")
}

func TestParsePresetFile_Composite(t *testing.T) {
	data := []byte(`
name: "Base"
template_paths:
  - "rules/a.yaml"
  - "rules/b.yaml"
template_names:
  - "A"
  - "B"
chain_type: "evm"
chain_id: "137"
enabled: true
variables:
  chain_id: "137"
`)
	rules, err := ParsePresetFile(data, nil)
	require.NoError(t, err)
	require.Len(t, rules, 2)
	assert.Equal(t, "Base (A)", rules[0].Name)
	assert.Equal(t, "A", rules[0].TemplateName)
	assert.Equal(t, "137", rules[0].Variables["chain_id"])
	assert.Equal(t, "Base (B)", rules[1].Name)
	assert.Equal(t, "B", rules[1].TemplateName)
}

func TestParsePresetFile_CompositeEmptyName(t *testing.T) {
	data := []byte(`
name: ""
template_paths: ["a.yaml"]
template_names: ["T"]
variables: {}
`)
	_, err := ParsePresetFile(data, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "composite preset requires non-empty name")
}

func TestParsePresetFile_CompositeSkipEmptyTemplateName(t *testing.T) {
	data := []byte(`
name: "Base"
template_paths:
  - "a.yaml"
  - "b.yaml"
template_names:
  - "A"
  - ""
variables: {}
`)
	rules, err := ParsePresetFile(data, nil)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "A", rules[0].TemplateName)
}

func TestParsePresetFile_CompositeNoRulesProduced(t *testing.T) {
	data := []byte(`
name: "Base"
template_paths: ["a.yaml"]
template_names: [""]
variables: {}
`)
	_, err := ParsePresetFile(data, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "composite preset produced no rules")
}

func TestParsePresetFile_MultiRule(t *testing.T) {
	data := []byte(`
rules:
  - name: "R1"
    type: "instance"
    mode: "whitelist"
    chain_type: "evm"
    chain_id: "137"
    enabled: true
    config:
      template: "T1"
      variables:
        x: "1"
  - name: "R2"
    type: "instance"
    config:
      template: "T2"
      variables:
        y: "2"
    chain_id: "56"
`)
	rules, err := ParsePresetFile(data, nil)
	require.NoError(t, err)
	require.Len(t, rules, 2)
	assert.Equal(t, "R1", rules[0].Name)
	assert.Equal(t, "T1", rules[0].TemplateName)
	assert.Equal(t, "1", rules[0].Variables["x"])
	assert.Equal(t, "R2", rules[1].Name)
	assert.Equal(t, "T2", rules[1].TemplateName)
	assert.Equal(t, "2", rules[1].Variables["y"])
}

func TestParsePresetFile_MultiRuleOverrides(t *testing.T) {
	data := []byte(`
rules:
  - name: "R"
    type: "instance"
    config:
      template: "T"
      variables:
        k: "old"
`)
	rules, err := ParsePresetFile(data, map[string]string{"k": "new"})
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "new", rules[0].Variables["k"])
}

func TestParsePresetFile_MultiRuleEmptyRules(t *testing.T) {
	data := []byte(`
rules: []
`)
	_, err := ParsePresetFile(data, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no rules")
}

func TestParsePresetFile_MultiRuleSkipEmptyTemplate(t *testing.T) {
	data := []byte(`
rules:
  - name: "R1"
    config:
      template: ""
      variables: {}
  - name: "R2"
    config:
      template: "T2"
      variables: {}
`)
	rules, err := ParsePresetFile(data, nil)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "T2", rules[0].TemplateName)
}

func TestParsePresetFile_BudgetScheduleSubstitution(t *testing.T) {
	data := []byte(`name: "Test"
template: "T"
chain_type: "evm"
chain_id: "137"
enabled: true
variables:
  chain_id: "137"
  max_amt: "1000"
budget:
  max_total: "${max_amt}"
  max_per_tx: "100"
schedule:
  period: "24h"
`)
	rules, err := ParsePresetFile(data, nil)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "1000", rules[0].Budget["max_total"])
	assert.Equal(t, "100", rules[0].Budget["max_per_tx"])
	assert.Equal(t, "24h", rules[0].Schedule["period"])
}

func TestParsePresetFile_BudgetUnitNotSubstituted(t *testing.T) {
	data := []byte(`name: "Test"
template: "T"
chain_type: "evm"
chain_id: "137"
enabled: true
variables:
  chain_id: "137"
  token_address: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"
budget:
  unit: "${chain_id}:${token_address}"
  max_total: "1000000"
`)
	rules, err := ParsePresetFile(data, nil)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	// unit must remain template form so config only needs variables changed when switching chains
	assert.Equal(t, "${chain_id}:${token_address}", rules[0].Budget["unit"])
	assert.Equal(t, "1000000", rules[0].Budget["max_total"])
}

func TestParsePresetFile_InvalidYAML(t *testing.T) {
	_, err := ParsePresetFile([]byte("not yaml"), nil)
	require.Error(t, err)
}

func TestParsePresetFile_EmptyOverrides(t *testing.T) {
	data := []byte(`
name: "R"
template: "T"
variables: { a: "1" }
`)
	rules, err := ParsePresetFile(data, map[string]string{})
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "1", rules[0].Variables["a"])
}

func TestTemplateNamesFromData_Single(t *testing.T) {
	data := []byte(`template: "Foo Template"`)
	names := TemplateNamesFromData(data)
	assert.Equal(t, []string{"Foo Template"}, names)
}

func TestTemplateNamesFromData_Composite(t *testing.T) {
	data := []byte(`
template_names:
  - "A"
  - "B"
`)
	names := TemplateNamesFromData(data)
	assert.Equal(t, []string{"A", "B"}, names)
}

func TestTemplateNamesFromData_Multi(t *testing.T) {
	data := []byte(`
rules:
  - config:
      template: "A"
  - config:
      template: "B"
`)
	names := TemplateNamesFromData(data)
	assert.Equal(t, []string{"A", "B"}, names)
}

func TestTemplateNamesFromData_InvalidYAML(t *testing.T) {
	names := TemplateNamesFromData([]byte("not yaml"))
	assert.Nil(t, names)
}

func TestTemplateNamesFromData_Empty(t *testing.T) {
	names := TemplateNamesFromData([]byte("{}"))
	assert.Nil(t, names)
}

func TestListPresets_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	entries, err := ListPresets(dir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestListPresets_NonYAMLIgnored(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.yaml"), []byte("template: T\n"), 0644))
	entries, err := ListPresets(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "b.yaml", entries[0].ID)
	assert.Equal(t, []string{"T"}, entries[0].TemplateNames)
}

func TestListPresets_ReadErrorSkipped(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "good.yaml"), []byte("template: T\n"), 0644))
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0755))
	// sub is a directory but we're listing dir; only good.yaml is a file
	entries, err := ListPresets(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestListPresets_MixedExtensions(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("template: A\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.yml"), []byte("template: B\n"), 0644))
	entries, err := ListPresets(dir)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	ids := []string{entries[0].ID, entries[1].ID}
	assert.Contains(t, ids, "a.yaml")
	assert.Contains(t, ids, "b.yml")
}

func TestListPresets_NoSuchDir(t *testing.T) {
	// When dir does not exist, ListPresets returns (nil, nil) so server can show empty list.
	entries, err := ListPresets("/nonexistent-dir-xyz")
	require.NoError(t, err)
	assert.Nil(t, entries)
}

func TestListPresets_DirNotExistReturnsNil(t *testing.T) {
	entries, err := ListPresets(filepath.Join(t.TempDir(), "missing"))
	require.NoError(t, err)
	assert.Nil(t, entries)
}
