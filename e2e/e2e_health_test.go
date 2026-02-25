//go:build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthCheck(t *testing.T) {
	health, err := adminClient.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ok", health.Status)
}
