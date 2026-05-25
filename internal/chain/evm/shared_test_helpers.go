package evm

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// newTestRPCServer creates a test RPC server and client pair.
func newTestRPCServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *RPCProvider) {
	t.Helper()
	srv := httptest.NewServer(handler)
	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)
	return srv, provider
}

// newTestLogger returns a logger that discards all output.
func newTestLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// mustNewRegistry creates a SignerRegistry or fails the test.
func mustNewRegistry(t *testing.T) *SignerRegistry {
	t.Helper()
	r, err := NewSignerRegistry(SignerConfig{})
	require.NoError(t, err)
	return r
}

// testLogger returns a logger suitable for use in tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

// strPtr returns a pointer to the given string.
func strPtr(s string) *string {
	return &s
}
