package evm

import (
	"encoding/json"
	"fmt"

	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// EffectiveConfig returns a rule's Config with its Variables (+Matrix + chain
// scope) substituted into the template-form placeholders — the same resolution
// the rule engine applies at evaluation. Instance rules persist Config in
// template form (${var}), so validation and tooling that read the stored Config
// (e.g. running a rule's test cases) must resolve it first, otherwise inputs
// like "${first:allowed_safe_addresses}" or "${chain_id}" reach the evaluator
// unresolved.
func EffectiveConfig(r *types.Rule) []byte {
	chainID := ""
	if r.ChainID != nil {
		chainID = *r.ChainID
	}
	return rule.EffectiveRule(r, chainID).Config
}

// RuleConfigObject returns the `config` object the JS evaluator passes to a
// rule's script — the rule's Variables overlaid with the per-chain Matrix row
// and chain_id (see resolveRuleConfig, the runtime path). Exported so that
// test-case validation runs each rule against the SAME config object the engine
// uses at evaluation, rather than the rule's stored Config keys. Instance rules
// no longer carry variable values as Config keys (they live only in Variables),
// so validation must resolve the config object from Variables here.
func RuleConfigObject(r *types.Rule) map[string]interface{} {
	chainID := ""
	if r.ChainID != nil {
		chainID = *r.ChainID
	}
	return resolveRuleConfig(r, chainID)
}

// RuleConfigObjectForChain resolves config for a specific request chain. Matrix
// presets store per-chain overrides in Matrix and leave Rule.ChainID empty; test
// case validation must pass the test input's chain_id so matrix rows apply.
func RuleConfigObjectForChain(r *types.Rule, chainID string) map[string]interface{} {
	if chainID == "" && r.ChainID != nil {
		chainID = *r.ChainID
	}
	return resolveRuleConfig(r, chainID)
}

// RuleVarMapForChain returns string variables for ${var} substitution on a chain.
func RuleVarMapForChain(r *types.Rule, chainID string) map[string]string {
	cfg := RuleConfigObjectForChain(r, chainID)
	out := make(map[string]string, len(cfg))
	for k, v := range cfg {
		out[k] = fmt.Sprintf("%v", v)
	}
	return out
}

// SubstituteTestCaseInput resolves ${var} placeholders in a test case input using
// per-chain variables (matrix row + chain_id), matching runtime evaluation.
func SubstituteTestCaseInput(input map[string]interface{}, vars map[string]string) (map[string]interface{}, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	sub := rule.SubstituteConfigVars(raw, vars)
	var out map[string]interface{}
	if err := json.Unmarshal(sub, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ChainIDFromTestInput reads chain_id from a template-form test case input.
func ChainIDFromTestInput(input map[string]interface{}) string {
	if input == nil {
		return ""
	}
	v, ok := input["chain_id"]
	if !ok || v == nil {
		return ""
	}
	switch n := v.(type) {
	case float64:
		return fmt.Sprintf("%d", int(n))
	case int:
		return fmt.Sprintf("%d", n)
	case int64:
		return fmt.Sprintf("%d", n)
	case string:
		return n
	default:
		return fmt.Sprintf("%v", v)
	}
}
