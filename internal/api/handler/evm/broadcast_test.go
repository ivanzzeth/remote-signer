package evm

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
)

// newTestRPCProvider creates an RPCProvider pointing to a dummy URL.
// Used for validation tests that return before making actual RPC calls.
func newTestRPCProvider(t *testing.T) *evm.RPCProvider {
	t.Helper()
	p, err := evm.NewRPCProvider("https://localhost:1", "")
	require.NoError(t, err)
	return p
}

// --- Constructor tests ---

func TestNewBroadcastHandler(t *testing.T) {
	t.Run("nil_rpc_provider_returns_error", func(t *testing.T) {
		_, err := NewBroadcastHandler(nil, slog.Default())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rpc provider is required")
	})

	t.Run("nil_logger_returns_error", func(t *testing.T) {
		_, err := NewBroadcastHandler(newTestRPCProvider(t), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})

	t.Run("valid_args", func(t *testing.T) {
		h, err := NewBroadcastHandler(newTestRPCProvider(t), slog.Default())
		require.NoError(t, err)
		assert.NotNil(t, h)
	})
}

// --- ServeHTTP validation tests ---
// These tests exercise the validation paths that return before calling RPCProvider.

func TestBroadcastHandler_MethodNotAllowed(t *testing.T) {
	h, err := NewBroadcastHandler(newTestRPCProvider(t), slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/broadcast", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestBroadcastHandler_InvalidBody(t *testing.T) {
	h, err := NewBroadcastHandler(newTestRPCProvider(t), slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/broadcast", bytes.NewBufferString("bad json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestBroadcastHandler_MissingChainID(t *testing.T) {
	h, err := NewBroadcastHandler(newTestRPCProvider(t), slog.Default())
	require.NoError(t, err)

	body := BroadcastRequest{SignedTxHex: "0xf86c"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/broadcast", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Contains(t, resp.Error, "chain_id")
}

func TestBroadcastHandler_InvalidChainID(t *testing.T) {
	h, err := NewBroadcastHandler(newTestRPCProvider(t), slog.Default())
	require.NoError(t, err)

	body := BroadcastRequest{ChainID: "abc", SignedTxHex: "0xf86c"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/broadcast", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestBroadcastHandler_MissingSignedTx(t *testing.T) {
	h, err := NewBroadcastHandler(newTestRPCProvider(t), slog.Default())
	require.NoError(t, err)

	body := BroadcastRequest{ChainID: "1"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/broadcast", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Contains(t, resp.Error, "signed_tx_hex")
}

func TestBroadcastHandler_InvalidSignedTxHex(t *testing.T) {
	h, err := NewBroadcastHandler(newTestRPCProvider(t), slog.Default())
	require.NoError(t, err)

	body := BroadcastRequest{ChainID: "1", SignedTxHex: "not-hex"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/broadcast", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
