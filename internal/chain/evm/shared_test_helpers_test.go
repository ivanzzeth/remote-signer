package evm

import (
	"encoding/hex"
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

// mockPasswordProvider returns a fixed password (or error) for any address.
//
// ⚠️ It lived in coverage_boost_test.go, which meant the ordinary provider tests
// could not compile without a file whose stated purpose is moving a coverage
// number. Shared test infrastructure belongs here — see TESTING.md.
type mockPasswordProvider struct {
	password []byte
	err      error
}

func (m *mockPasswordProvider) GetPassword(address string, config KeystoreConfig) ([]byte, error) {
	return m.password, m.err
}

// transferCalldata is an ERC20 transfer(to, 1) call, used by several tests that
// need a well-formed payload without caring what is in it.
func transferCalldata() []byte {
	b, _ := hex.DecodeString(
		"a9059cbb" +
			"0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc4" +
			"0000000000000000000000000000000000000000000000000000000000000001",
	)
	return b
}
