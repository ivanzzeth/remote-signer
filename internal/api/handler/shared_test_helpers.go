package handler

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// adminCtx returns a context carrying an admin API key.
func adminCtx(t *testing.T) context.Context {
	t.Helper()
	return context.WithValue(context.Background(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "admin", Role: types.RoleAdmin})
}

// mustJSONP marshals v to JSON, failing the test on error.
func mustJSONP(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// contextWithKey returns a context with an API key for testing.
func contextWithKey(t *testing.T, role types.APIKeyRole, id string) context.Context {
	t.Helper()
	return context.WithValue(context.Background(), middleware.APIKeyContextKey,
		&types.APIKey{ID: id, Role: role, Enabled: true})
}
