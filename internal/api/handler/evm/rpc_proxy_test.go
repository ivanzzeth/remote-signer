package evm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
)

// stubProxyBackend records each call and returns canned responses or
// errors. Tests poke at lastMethod/lastParams to verify what the
// handler actually forwarded.
type stubProxyBackend struct {
	resultFor map[string]json.RawMessage
	errFor    map[string]error
	lastChain string
	lastMethod string
	lastParams []interface{}
	calls     int
}

func (s *stubProxyBackend) DoWalletProxyRPC(
	_ context.Context, chainID, method string, params []interface{},
) (json.RawMessage, error) {
	s.lastChain = chainID
	s.lastMethod = method
	s.lastParams = params
	s.calls++
	if err, ok := s.errFor[method]; ok {
		return nil, err
	}
	if res, ok := s.resultFor[method]; ok {
		return res, nil
	}
	return json.RawMessage(`null`), nil
}

func proxyLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(new(bytes.Buffer), &slog.HandlerOptions{Level: slog.LevelError}))
}

func postProxy(t *testing.T, h http.Handler, chainID string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rpc/"+chainID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestNewRPCProxyHandler_Validation(t *testing.T) {
	_, err := NewRPCProxyHandler(nil, proxyLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "backend")

	_, err = NewRPCProxyHandler(&stubProxyBackend{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger")

	h, err := NewRPCProxyHandler(&stubProxyBackend{}, proxyLogger())
	require.NoError(t, err)
	assert.NotNil(t, h)
}

func TestRPCProxy_ForwardsAllowedRead(t *testing.T) {
	stub := &stubProxyBackend{
		resultFor: map[string]json.RawMessage{
			"eth_blockNumber": json.RawMessage(`"0x123"`),
		},
	}
	h, err := NewRPCProxyHandler(stub, proxyLogger())
	require.NoError(t, err)

	rec := postProxy(t, h, "1",
		`{"jsonrpc":"2.0","id":7,"method":"eth_blockNumber","params":[]}`)
	require.Equal(t, http.StatusOK, rec.Code)

	var env jsonRPCEnvelope
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&env))
	assert.Equal(t, "2.0", env.JSONRPC)
	assert.JSONEq(t, `7`, string(env.ID))
	assert.JSONEq(t, `"0x123"`, string(env.Result))
	assert.Nil(t, env.Error)

	assert.Equal(t, "1", stub.lastChain)
	assert.Equal(t, "eth_blockNumber", stub.lastMethod)
}

func TestRPCProxy_BlocksSignMethods(t *testing.T) {
	stub := &stubProxyBackend{}
	h, err := NewRPCProxyHandler(stub, proxyLogger())
	require.NoError(t, err)

	// Every sign-shaped method should 403 BEFORE touching the backend
	// (calls counter stays at 0 across the run).
	signMethods := []string{
		"eth_sendTransaction",
		"eth_sign",
		"personal_sign",
		"eth_signTransaction",
		"eth_signTypedData",
		"eth_signTypedData_v3",
		"eth_signTypedData_v4",
	}
	// JSON-RPC convention: allowlist rejection returns HTTP 200 with
	// the standard "method not found" error code (-32601) in the
	// envelope. See ServeHTTP's docstring for why we don't use 4xx.
	for _, m := range signMethods {
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":[]}`, m)
		rec := postProxy(t, h, "1", body)
		assert.Equal(t, http.StatusOK, rec.Code, "method %s should 200 + envelope error", m)
		var env jsonRPCEnvelope
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&env))
		require.NotNil(t, env.Error, "method %s should carry envelope error", m)
		assert.Equal(t, -32601, env.Error.Code)
		assert.Contains(t, env.Error.Message, "not allowed")
	}
	assert.Equal(t, 0, stub.calls, "backend must not be called for blocked methods")
}

func TestRPCProxy_AllowsEthSendRawTransaction(t *testing.T) {
	// eth_sendRawTransaction broadcasts an already-signed tx. The
	// dApp gives us the signed bytes — daemon key material isn't
	// involved — so this MUST be allowed (Uniswap depends on it).
	// Distinguishes it from eth_sendTransaction which is blocked.
	stub := &stubProxyBackend{
		resultFor: map[string]json.RawMessage{
			"eth_sendRawTransaction": json.RawMessage(`"0xabc"`),
		},
	}
	h, err := NewRPCProxyHandler(stub, proxyLogger())
	require.NoError(t, err)

	rec := postProxy(t, h, "1",
		`{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0xdeadbeef"]}`)
	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	assert.Equal(t, 1, stub.calls)
}

func TestRPCProxy_BadChainID(t *testing.T) {
	h, err := NewRPCProxyHandler(&stubProxyBackend{}, proxyLogger())
	require.NoError(t, err)

	// Empty chain id — handler bails at path parsing before
	// touching the backend.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rpc/",
		strings.NewReader(`{"jsonrpc":"2.0","method":"eth_blockNumber"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRPCProxy_BadJSON(t *testing.T) {
	// Pre-envelope failure: the body itself isn't JSON-RPC, so the
	// handler returns the daemon-flat HTTP-level error shape (400 +
	// `{"error":"..."}`). SDK callers handle this via APIError.
	h, err := NewRPCProxyHandler(&stubProxyBackend{}, proxyLogger())
	require.NoError(t, err)
	rec := postProxy(t, h, "1", "this is not json")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var flat map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&flat))
	assert.Contains(t, flat["error"], "invalid JSON-RPC body")
}

func TestRPCProxy_MissingMethod(t *testing.T) {
	// Body parsed OK but `method` field absent — JSON-RPC convention
	// makes this a -32600 "invalid request" inside a 200 envelope.
	h, err := NewRPCProxyHandler(&stubProxyBackend{}, proxyLogger())
	require.NoError(t, err)
	rec := postProxy(t, h, "1", `{"jsonrpc":"2.0","id":1}`)
	assert.Equal(t, http.StatusOK, rec.Code)
	var env jsonRPCEnvelope
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&env))
	require.NotNil(t, env.Error)
	assert.Equal(t, -32600, env.Error.Code)
}

func TestRPCProxy_NonPOST(t *testing.T) {
	h, err := NewRPCProxyHandler(&stubProxyBackend{}, proxyLogger())
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rpc/1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestRPCProxy_UpstreamErrorInEnvelope(t *testing.T) {
	// Upstream RPC went sideways — handler must surface the real
	// error message so operators investigating "why doesn't this
	// dApp work" see "execution reverted: …" instead of a generic
	// internal error. JSON-RPC convention: HTTP 200 + envelope error
	// (code -32603, "internal error") even when the upstream is at
	// fault, so SDKs can pattern-match without HTTP-status guessing.
	stub := &stubProxyBackend{
		errFor: map[string]error{
			"eth_call": errors.New("rpc error -32000: execution reverted: SafeERC20"),
		},
	}
	h, err := NewRPCProxyHandler(stub, proxyLogger())
	require.NoError(t, err)
	rec := postProxy(t, h, "1",
		`{"jsonrpc":"2.0","id":2,"method":"eth_call","params":[]}`)
	assert.Equal(t, http.StatusOK, rec.Code)
	var env jsonRPCEnvelope
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&env))
	require.NotNil(t, env.Error)
	assert.Equal(t, -32603, env.Error.Code)
	assert.Contains(t, env.Error.Message, "execution reverted: SafeERC20")
}

// Integration: drive the *real* RPCProvider against an httptest
// upstream, going through handler → provider → upstream and back. The
// stub-backed tests above pin the request-parsing + allowlist; this
// one pins the full forwarding path including the JSON-RPC envelope
// the provider builds for the upstream.
func TestRPCProxy_Integration_RealProvider(t *testing.T) {
	// Fake upstream — echoes a fixed result regardless of input but
	// records the request body so we can verify the provider sent
	// the right method through. URL shape `/{chainID}` matches what
	// RPCProvider.rpcURL produces.
	var lastBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.True(t, strings.HasPrefix(r.URL.Path, "/1"),
			"upstream URL should embed chainID, got %s", r.URL.Path)
		lastBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0xdead"}`))
	}))
	defer upstream.Close()

	provider, err := evmchain.NewRPCProvider(upstream.URL, "")
	require.NoError(t, err)
	h, err := NewRPCProxyHandler(provider, proxyLogger())
	require.NoError(t, err)

	rec := postProxy(t, h, "1",
		`{"jsonrpc":"2.0","id":42,"method":"eth_blockNumber","params":[]}`)
	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())

	var env jsonRPCEnvelope
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&env))
	assert.JSONEq(t, `42`, string(env.ID))
	assert.JSONEq(t, `"0xdead"`, string(env.Result))

	// Verify the upstream actually saw eth_blockNumber — proves the
	// method survived the inbound parse → provider → upstream hop.
	var upstreamReq struct {
		Method string `json:"method"`
	}
	require.NoError(t, json.Unmarshal(lastBody, &upstreamReq))
	assert.Equal(t, "eth_blockNumber", upstreamReq.Method)
}

func TestRPCProxy_Integration_BlockedMethodNeverHitsUpstream(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits++
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"0x0"}`))
	}))
	defer upstream.Close()

	provider, err := evmchain.NewRPCProvider(upstream.URL, "")
	require.NoError(t, err)
	h, err := NewRPCProxyHandler(provider, proxyLogger())
	require.NoError(t, err)

	// HTTP 200 + envelope error (JSON-RPC convention) — see ServeHTTP
	// docstring. The defence-in-depth assertion is "upstream not hit".
	rec := postProxy(t, h, "1",
		`{"jsonrpc":"2.0","id":1,"method":"personal_sign","params":["0xdead","0xabc"]}`)
	assert.Equal(t, http.StatusOK, rec.Code)
	var env jsonRPCEnvelope
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&env))
	require.NotNil(t, env.Error)
	assert.Equal(t, 0, upstreamHits, "blocked method must never reach the upstream RPC")
}

func TestRPCProxy_PassesParamsThrough(t *testing.T) {
	stub := &stubProxyBackend{}
	h, err := NewRPCProxyHandler(stub, proxyLogger())
	require.NoError(t, err)

	body := `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0xABC","data":"0xdead"},"latest"]}`
	rec := postProxy(t, h, "137", body)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "137", stub.lastChain)
	require.Len(t, stub.lastParams, 2)
	// The tx object survives as a map[string]interface{}.
	txObj, ok := stub.lastParams[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "0xABC", txObj["to"])
	assert.Equal(t, "latest", stub.lastParams[1])
}
