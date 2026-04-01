package evm

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/service"
)

// TestNewSignHandler tests constructor validation for SignHandler.
// ServeHTTP tests are deferred because SignService is a concrete struct
// with many dependencies that cannot be easily stubbed.
func TestNewSignHandler(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)

	t.Run("nil_sign_service_returns_error", func(t *testing.T) {
		_, err := NewSignHandler(nil, nil, accessSvc, slog.Default())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sign service is required")
	})

	t.Run("nil_access_service_returns_error", func(t *testing.T) {
		_, err := NewSignHandler(new(service.SignService), nil, nil, slog.Default())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access service is required")
	})

	t.Run("nil_logger_returns_error", func(t *testing.T) {
		_, err := NewSignHandler(new(service.SignService), nil, accessSvc, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})

	t.Run("valid_args", func(t *testing.T) {
		h, err := NewSignHandler(new(service.SignService), nil, accessSvc, slog.Default())
		require.NoError(t, err)
		assert.NotNil(t, h)
	})
}
