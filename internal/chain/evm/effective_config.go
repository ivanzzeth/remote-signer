package evm

import (
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
