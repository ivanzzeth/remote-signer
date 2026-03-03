package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestTemplateRulesJSON_ContainsPlaceholders verifies that after YAML unmarshal + JSON marshal,
// the rules_json string still contains domain placeholders (so substitution can run).
// If this fails, the root cause is YAML->struct or struct->JSON losing nested domain fields.
func TestTemplateRulesJSON_ContainsPlaceholders(t *testing.T) {
	configDir := findProjectRoot(t)
	templatePath := filepath.Join(configDir, "rules", "templates", "polymarket.safe.template.yaml")
	data, err := os.ReadFile(templatePath)
	if err != nil {
		t.Skipf("template file not found: %v", err)
		return
	}

	var fileContent templateFileContent
	if err := yaml.Unmarshal(data, &fileContent); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}
	if len(fileContent.Rules) == 0 {
		t.Fatal("no rules in template")
	}

	rulesJSON, err := json.Marshal(fileContent.Rules)
	if err != nil {
		t.Fatalf("json marshal rules: %v", err)
	}
	s := string(rulesJSON)

	// Placeholders that must appear in rules_json for substitution to fill domain
	needles := []string{
		"verifyingContract",
		"${allowed_safe_address_for_testing}",
		"${chain_id}",
	}
	for _, needle := range needles {
		if !strings.Contains(s, needle) {
			t.Errorf("rules_json missing %q (len=%d). First 500 chars: %s", needle, len(s), s[:min(500, len(s))])
		}
	}
}

// TestSubstituteThenUnmarshal_DomainFilled verifies: rulesJSON (with placeholders) ->
// substitute with variables -> json.Unmarshal into []RuleConfig -> domain.verifyingContract is set.
// Does not depend on config.Load (no TLS etc).
func TestSubstituteThenUnmarshal_DomainFilled(t *testing.T) {
	configDir := findProjectRoot(t)
	templatePath := filepath.Join(configDir, "rules", "templates", "polymarket.safe.template.yaml")
	data, err := os.ReadFile(templatePath)
	if err != nil {
		t.Skipf("template file not found: %v", err)
		return
	}
	var fileContent templateFileContent
	if err := yaml.Unmarshal(data, &fileContent); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}
	rulesJSON, err := json.Marshal(fileContent.Rules)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}

	variables := make(map[string]string)
	for k, v := range fileContent.TestVariables {
		variables[k] = v
	}
	resolved, err := substituteVarsInString(string(rulesJSON), variables)
	if err != nil {
		t.Fatalf("substitute: %v", err)
	}
	if !strings.Contains(resolved, "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837") {
		t.Error("resolved JSON does not contain substituted address")
	}

	var templateRules []RuleConfig
	if err := json.Unmarshal([]byte(resolved), &templateRules); err != nil {
		t.Fatalf("json unmarshal resolved: %v", err)
	}

	var safetxRule *RuleConfig
	for i := range templateRules {
		if strings.Contains(templateRules[i].Name, "SafeTx") && strings.Contains(templateRules[i].Name, "Signature") {
			safetxRule = &templateRules[i]
			break
		}
	}
	if safetxRule == nil {
		t.Fatal("SafeTx Signature rule not found")
	}

	tcList, _ := safetxRule.Config["test_cases"].([]interface{})
	if len(tcList) == 0 {
		t.Fatal("no test_cases in SafeTx rule config")
	}
	firstTC, _ := tcList[0].(map[string]interface{})
	if firstTC == nil {
		t.Fatal("first test case is not map[string]interface{}")
	}
	input, _ := firstTC["input"].(map[string]interface{})
	if input == nil {
		t.Fatal("input is nil or not map")
	}
	typedData, _ := input["typed_data"].(map[string]interface{})
	if typedData == nil {
		t.Fatal("typed_data is nil or not map")
	}
	domain, _ := typedData["domain"].(map[string]interface{})
	if domain == nil {
		t.Fatal("domain is nil or not map")
	}
	vc, _ := domain["verifyingContract"].(string)
	if vc == "" {
		t.Errorf("domain.verifyingContract is empty after substitute+unmarshal; domain keys: %v", keys(domain))
	}
	chainID, _ := domain["chainId"].(string)
	if chainID == "" {
		t.Errorf("domain.chainId is empty")
	}
}

func findProjectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "config.yaml")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("project root (config.yaml) not found — skipping environment-dependent test")
		}
		dir = parent
	}
}

func keys(m map[string]interface{}) []string {
	var k []string
	for s := range m {
		k = append(k, s)
	}
	return k
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestConfigVariables_Type verifies how YAML unmarshals nested "variables" into RuleConfig.Config.
// If variables ends up as map[interface{}]interface{}, expandInstanceRule must handle it.
func TestConfigVariables_Type(t *testing.T) {
	yamlBytes := []byte(`
name: "Test Instance"
type: "instance"
mode: "whitelist"
enabled: true
config:
  template: "Some Template"
  variables:
    chain_id: "137"
    allowed_safe_address_for_testing: "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837"
`)
	var rule RuleConfig
	if err := yaml.Unmarshal(yamlBytes, &rule); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}
	v := rule.Config["variables"]
	if v == nil {
		t.Fatal("Config[\"variables\"] is nil")
	}
	_, okStr := v.(map[string]interface{})
	_, okIface := v.(map[interface{}]interface{})
	if !okStr && !okIface {
		t.Errorf("variables type is %T (expected map[string]interface{} or map[interface{}]interface{})", v)
	}
	// Ensure we can extract the address with the same logic as expandInstanceRule
	variables := make(map[string]string)
	if vars, ok := rule.Config["variables"].(map[string]interface{}); ok {
		for k, val := range vars {
			variables[k] = fmt.Sprintf("%v", val)
		}
	} else if vars, ok := rule.Config["variables"].(map[interface{}]interface{}); ok {
		for k, val := range vars {
			if sk, ok := k.(string); ok {
				variables[sk] = fmt.Sprintf("%v", val)
			}
		}
	}
	if variables["allowed_safe_address_for_testing"] != "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837" {
		t.Errorf("got variables %v", variables)
	}
}

// TestE2E_ExpandInstanceRule_DomainFilled runs the full expand path (templates from file + instance rule with variables)
// without loading config.yaml (so no TLS validation). Verifies SafeTx rule gets domain.verifyingContract set.
func TestE2E_ExpandInstanceRule_DomainFilled(t *testing.T) {
	configDir := findProjectRoot(t)
	templatePath := filepath.Join(configDir, "rules", "templates", "polymarket.safe.template.yaml")
	if _, err := os.Stat(templatePath); err != nil {
		t.Skipf("template file not found: %v", err)
		return
	}

	// Same structure as config.yaml: one template (file), one instance rule with variables
	templates := []TemplateConfig{
		{
			Name: "Polymarket Safe Template",
			Type: TemplateFileType,
			Config: map[string]interface{}{
				"path": "rules/templates/polymarket.safe.template.yaml",
			},
			Enabled: true,
		},
	}
	instanceVariables := map[string]interface{}{
		"chain_id":                         "137",
		"allowed_safe_address_for_testing": "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837",
		"allowed_safe_addresses":            "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837",
		"ctf_exchange_address":             "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E",
		"neg_risk_adapter_address":          "0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296",
		"neg_risk_exchange_address":        "0xC5d563A36AE78145C45a50134d48A1215220f80a",
		"conditional_tokens_address":       "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045",
		"safe_proxy_factory_address":       "0xaacFeEa03eb1561C4e67d661e40682Bd8B8982E",
		"usdc_bridged_address":             "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
		"clob_auth_domain_name":            "ClobAuthDomain",
		"clob_auth_domain_version":         "1",
		"ctf_exchange_domain_name":          "Polymarket CTF Exchange",
		"ctf_exchange_domain_version":      "1",
		"safe_factory_domain_name":         "Polymarket Contract Proxy Factory",
	}
	rules := []RuleConfig{
		{
			Name: "Polymarket Safe rules (Polygon)",
			Type: "instance",
			Mode: "whitelist",
			Config: map[string]interface{}{
				"template":  "Polymarket Safe Template",
				"variables": instanceVariables,
			},
			Enabled: true,
		},
	}

	expandedTemplates, err := ExpandTemplatesFromFiles(templates, configDir, nil)
	if err != nil {
		t.Fatalf("expand templates: %v", err)
	}
	if len(expandedTemplates) == 0 {
		t.Fatal("no templates after expand")
	}
	expandedRules, err := ExpandInstanceRules(rules, expandedTemplates)
	if err != nil {
		t.Fatalf("expand instance rules: %v", err)
	}

	var safetxRule *RuleConfig
	for i := range expandedRules {
		if strings.Contains(expandedRules[i].Name, "SafeTx") && strings.Contains(expandedRules[i].Name, "Signature") {
			safetxRule = &expandedRules[i]
			break
		}
	}
	if safetxRule == nil {
		t.Fatal("SafeTx Signature rule not found in expanded rules")
	}

	tcList, _ := safetxRule.Config["test_cases"].([]interface{})
	if len(tcList) == 0 {
		t.Fatal("no test_cases in SafeTx rule config")
	}
	firstTC, _ := tcList[0].(map[string]interface{})
	if firstTC == nil {
		t.Fatal("first test case is not map[string]interface{}")
	}
	input, _ := firstTC["input"].(map[string]interface{})
	if input == nil {
		t.Fatal("input is nil or not map")
	}
	typedData, _ := input["typed_data"].(map[string]interface{})
	if typedData == nil {
		t.Fatal("typed_data is nil or not map")
	}
	domain, _ := typedData["domain"].(map[string]interface{})
	if domain == nil {
		t.Fatal("domain is nil or not map")
	}
	vc, _ := domain["verifyingContract"].(string)
	if vc == "" {
		t.Errorf("domain.verifyingContract is empty after E2E expand; domain keys: %v", keys(domain))
	}
	if vc != "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837" {
		t.Errorf("domain.verifyingContract = %q", vc)
	}
}
