package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// APIKey.TableName()
// ---------------------------------------------------------------------------

func TestAPIKey_TableName(t *testing.T) {
	assert.Equal(t, "api_keys", APIKey{}.TableName())
}

// ---------------------------------------------------------------------------
// APIKey Role helpers
// ---------------------------------------------------------------------------

func TestAPIKey_IsAdmin(t *testing.T) {
	k := &APIKey{Role: RoleAdmin}
	assert.True(t, k.IsAdmin())
	assert.False(t, k.IsDev())
	assert.False(t, k.IsAgent())
	assert.False(t, k.IsStrategy())
}

func TestAPIKey_IsDev(t *testing.T) {
	k := &APIKey{Role: RoleDev}
	assert.True(t, k.IsDev())
	assert.False(t, k.IsAdmin())
}

func TestAPIKey_IsAgent(t *testing.T) {
	k := &APIKey{Role: RoleAgent}
	assert.True(t, k.IsAgent())
	assert.False(t, k.IsAdmin())
}

func TestAPIKey_IsStrategy(t *testing.T) {
	k := &APIKey{Role: RoleStrategy}
	assert.True(t, k.IsStrategy())
	assert.False(t, k.IsAdmin())
}

// ---------------------------------------------------------------------------
// IsValidAPIKeyRole
// ---------------------------------------------------------------------------

func TestIsValidAPIKeyRole(t *testing.T) {
	assert.True(t, IsValidAPIKeyRole("admin"))
	assert.True(t, IsValidAPIKeyRole("dev"))
	assert.True(t, IsValidAPIKeyRole("agent"))
	assert.True(t, IsValidAPIKeyRole("strategy"))
	assert.False(t, IsValidAPIKeyRole("unknown"))
	assert.False(t, IsValidAPIKeyRole(""))
}
