package validate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigRuleID(t *testing.T) {
	id := configRuleID(0, "", "")
	assert.Contains(t, id, "cfg_")
	assert.Len(t, id, 4+16) // "cfg_" + 16 hex chars (8 bytes)

	id2 := configRuleID(0, "custom_name", "")
	assert.Contains(t, id2, "cfg_")
	assert.NotEqual(t, id, id2)
}

func TestEffectiveRuleID(t *testing.T) {
	cfg := RuleConfig{Id: "explicit_id"}
	assert.Equal(t, "explicit_id", effectiveRuleID(0, cfg))

	cfg2 := RuleConfig{Name: "from_name", Type: "evm_solidity"}
	id := effectiveRuleID(5, cfg2)
	assert.Contains(t, id, "cfg_")

	cfg3 := RuleConfig{}
	id3 := effectiveRuleID(5, cfg3)
	assert.Contains(t, id3, "cfg_")
}
