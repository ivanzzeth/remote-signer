package evm

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// mockRPCServer creates a test HTTP server that responds to JSON-RPC requests.
// handler maps method names to response hex strings.
func mockRPCServer(t *testing.T, handler map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Logf("mock rpc: decode error: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		result, ok := handler[req.Method]
		if !ok {
			resp := fmt.Sprintf(`{"jsonrpc":"2.0","error":{"code":-32601,"message":"method not found: %s"},"id":%d}`, req.Method, req.ID)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(resp))
			return
		}

		resp := fmt.Sprintf(`{"jsonrpc":"2.0","result":"%s","id":%d}`, result, req.ID)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(resp))
	}))
}

// mockRPCServerFunc creates a test HTTP server with a custom handler function.
// fn receives the JSON-RPC request and returns (result hex string, error).
func mockRPCServerFunc(t *testing.T, fn func(req jsonRPCRequest) (string, error)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		result, err := fn(req)
		if err != nil {
			resp := fmt.Sprintf(`{"jsonrpc":"2.0","error":{"code":-32000,"message":"%s"},"id":%d}`, err.Error(), req.ID)
			_, _ = w.Write([]byte(resp))
			return
		}
		resp := fmt.Sprintf(`{"jsonrpc":"2.0","result":"%s","id":%d}`, result, req.ID)
		_, _ = w.Write([]byte(resp))
	}))
}

// abiEncodeUint256 encodes a uint256 value as 32-byte hex.
func abiEncodeUint256(v int) string {
	b := new(big.Int).SetInt64(int64(v))
	padded := make([]byte, 32)
	bBytes := b.Bytes()
	copy(padded[32-len(bBytes):], bBytes)
	return "0x" + hex.EncodeToString(padded)
}

// abiEncodeString encodes a string as ABI-encoded bytes (offset + length + data).
func abiEncodeString(s string) string {
	data := []byte(s)
	// offset (32 bytes pointing to 0x20)
	offset := make([]byte, 32)
	offset[31] = 0x20
	// length
	length := make([]byte, 32)
	lenBig := new(big.Int).SetInt64(int64(len(data)))
	lenBytes := lenBig.Bytes()
	copy(length[32-len(lenBytes):], lenBytes)
	// data padded to 32 bytes
	paddedLen := ((len(data) + 31) / 32) * 32
	padded := make([]byte, paddedLen)
	copy(padded, data)
	var buf []byte
	buf = append(buf, offset...)
	buf = append(buf, length...)
	buf = append(buf, padded...)
	return "0x" + hex.EncodeToString(buf)
}

// abiEncodeBool encodes a bool as 32-byte hex.
func abiEncodeBool(v bool) string {
	b := make([]byte, 32)
	if v {
		b[31] = 1
	}
	return "0x" + hex.EncodeToString(b)
}

// newTestEvaluator creates a JSRuleEvaluator for use in tests.
func newTestEvaluator(t *testing.T) *JSRuleEvaluator {
	t.Helper()
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)
	return e
}
