package rule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScopeDynamicUnit(t *testing.T) {
	assert.Equal(t, "137:sign_count", ScopeDynamicUnit("137", "sign_count"))
	assert.Equal(t, "sign_count", ScopeDynamicUnit("", "sign_count"))
}

func TestFormatUnitDisplay(t *testing.T) {
	assert.Equal(t, "chain 137 · signatures", FormatUnitDisplay("137:sign_count"))
	assert.Equal(t, "signatures", FormatUnitDisplay("sign_count"))
}

func TestEnforcesBudgetLimit(t *testing.T) {
	assert.True(t, EnforcesBudgetLimit("500"))
	assert.False(t, EnforcesBudgetLimit("-1"))
	assert.False(t, EnforcesBudgetLimit(""))
}

func TestIsKnownUnitFamily(t *testing.T) {
	known := map[string]bool{"sign_count": true}
	assert.True(t, IsKnownUnitFamily("137:sign_count", known))
	assert.True(t, IsKnownUnitFamily("sign_count", known))
	assert.False(t, IsKnownUnitFamily("56:0xabc:permit", known))
}
