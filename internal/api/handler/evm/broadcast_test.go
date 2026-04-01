package evm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock Broadcaster ---

type mockBroadcaster struct {
	sendFn func(ctx context.Context, chainID, signedTxHex string) (string, error)
}

func (m *mockBroadcaster) SendRawTransaction(ctx context.Context, chainID, signedTxHex string) (string, error) {
	if m.sendFn != nil {
		return m.sendFn(ctx, chainID, signedTxHex)
	}
	return "", fmt.Errorf("not implemented")
}

// --- Helpers ---

func newTestBroadcastHandler(t *testing.T, b Broadcaster) *BroadcastHandler {
	t.Helper()
	h, err := NewBroadcastHandler(b, slog.Default())
	require.NoError(t, err)
	return h
}

func doBroadcastRequest(t *testing.T, h *BroadcastHandler, method string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var buf *bytes.Buffer
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		buf = bytes.NewBuffer(data)
	} else {
		buf = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, "/api/v1/evm/broadcast", buf)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// --- Constructor tests ---

func TestNewBroadcastHandler(t *testing.T) {
	t.Run("nil_broadcaster_returns_error", func(t *testing.T) {
		_, err := NewBroadcastHandler(nil, slog.Default())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rpc provider is required")
	})

	t.Run("nil_logger_returns_error", func(t *testing.T) {
		_, err := NewBroadcastHandler(&mockBroadcaster{}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})

	t.Run("valid_args", func(t *testing.T) {
		h, err := NewBroadcastHandler(&mockBroadcaster{}, slog.Default())
		require.NoError(t, err)
		assert.NotNil(t, h)
	})
}

// --- ServeHTTP validation tests ---

func TestBroadcastHandler_MethodNotAllowed(t *testing.T) {
	h := newTestBroadcastHandler(t, &mockBroadcaster{})
	rec := doBroadcastRequest(t, h, http.MethodGet, nil)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestBroadcastHandler_InvalidBody(t *testing.T) {
	h := newTestBroadcastHandler(t, &mockBroadcaster{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/broadcast", bytes.NewBufferString("bad json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestBroadcastHandler_MissingChainID(t *testing.T) {
	h := newTestBroadcastHandler(t, &mockBroadcaster{})
	body := BroadcastRequest{SignedTxHex: "0xf86c"}
	rec := doBroadcastRequest(t, h, http.MethodPost, body)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "chain_id")
}

func TestBroadcastHandler_InvalidChainID(t *testing.T) {
	h := newTestBroadcastHandler(t, &mockBroadcaster{})
	body := BroadcastRequest{ChainID: "abc", SignedTxHex: "0xf86c"}
	rec := doBroadcastRequest(t, h, http.MethodPost, body)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestBroadcastHandler_MissingSignedTx(t *testing.T) {
	h := newTestBroadcastHandler(t, &mockBroadcaster{})
	body := BroadcastRequest{ChainID: "1"}
	rec := doBroadcastRequest(t, h, http.MethodPost, body)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "signed_tx_hex")
}

func TestBroadcastHandler_InvalidSignedTxHex(t *testing.T) {
	h := newTestBroadcastHandler(t, &mockBroadcaster{})
	body := BroadcastRequest{ChainID: "1", SignedTxHex: "not-hex"}
	rec := doBroadcastRequest(t, h, http.MethodPost, body)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// --- ServeHTTP success/error tests (using mock) ---

func TestBroadcastHandler_Success(t *testing.T) {
	b := &mockBroadcaster{
		sendFn: func(_ context.Context, chainID, signedTxHex string) (string, error) {
			assert.Equal(t, "1", chainID)
			assert.Equal(t, "0xf86c", signedTxHex)
			return "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", nil
		},
	}
	h := newTestBroadcastHandler(t, b)
	body := BroadcastRequest{ChainID: "1", SignedTxHex: "0xf86c"}
	rec := doBroadcastRequest(t, h, http.MethodPost, body)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp BroadcastResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", resp.TxHash)
}

func TestBroadcastHandler_RPCError(t *testing.T) {
	b := &mockBroadcaster{
		sendFn: func(_ context.Context, _, _ string) (string, error) {
			return "", fmt.Errorf("nonce too low")
		},
	}
	h := newTestBroadcastHandler(t, b)
	body := BroadcastRequest{ChainID: "1", SignedTxHex: "0xf86c"}
	rec := doBroadcastRequest(t, h, http.MethodPost, body)
	assert.Equal(t, http.StatusBadGateway, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Contains(t, resp.Error, "nonce too low")
}
