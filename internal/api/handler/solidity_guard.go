package handler

import (
	"encoding/json"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// templateContainsSolidity returns true if tmpl is an evm_solidity_expression
// single-rule template, or a template_bundle whose config contains one or more
// evm_solidity_expression sub-rules.
func templateContainsSolidity(tmpl *types.RuleTemplate) bool {
	if tmpl.Type == types.RuleTypeEVMSolidityExpression {
		return true
	}
	if tmpl.Type != "template_bundle" {
		return false
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(tmpl.Config, &cfg); err != nil {
		return false
	}

	// Form 1: rules_json string (registry-sourced templates)
	if rulesJSON, ok := cfg["rules_json"].(string); ok && rulesJSON != "" {
		var rules []struct {
			Type string `json:"type"`
		}
		if json.Unmarshal([]byte(rulesJSON), &rules) == nil {
			for _, r := range rules {
				if r.Type == string(types.RuleTypeEVMSolidityExpression) {
					return true
				}
			}
		}
	}

	// Form 2: rules array (API-created templates)
	if rulesRaw, ok := cfg["rules"]; ok {
		rulesBytes, _ := json.Marshal(rulesRaw)
		var rules []struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(rulesBytes, &rules) == nil {
			for _, r := range rules {
				if r.Type == string(types.RuleTypeEVMSolidityExpression) {
					return true
				}
			}
		}
	}

	return false
}
