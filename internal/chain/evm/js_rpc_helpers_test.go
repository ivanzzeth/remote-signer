package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
			w.Write([]byte(resp))
			return
		}

		resp := fmt.Sprintf(`{"jsonrpc":"2.0","result":"%s","id":%d}`, result, req.ID)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(resp))
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
			w.Write([]byte(resp))
			return
		}
		resp := fmt.Sprintf(`{"jsonrpc":"2.0","result":"%s","id":%d}`, result, req.ID)
		w.Write([]byte(resp))
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

func newTestEvaluator(t *testing.T) *JSRuleEvaluator {
	t.Helper()
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)
	return e
}

func TestJSRPC_Web3CallInScript(t *testing.T) {
	// Mock RPC server returns decimals=6 for any eth_call
	srv := mockRPCServer(t, map[string]string{
		"eth_call": abiEncodeUint256(6),
	})
	defer srv.Close()

	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)

	cache, err := NewTokenMetadataCache(nil, provider, 0)
	require.NoError(t, err)

	rpcCtx := &RPCInjectionContext{
		ChainID:  "1",
		Provider: provider,
		Cache:    cache,
		Counter:  NewRPCCallCounter(10),
		Ctx:      context.Background(),
	}

	e := newTestEvaluator(t)
	// Script uses web3.call to get data
	script := `function validate(input) {
		var result = web3.call("0x0000000000000000000000000000000000000001", "0x313ce567");
		if (result !== "") {
			return { valid: true, reason: "got result" };
		}
		return { valid: false, reason: "no result" };
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, rpcCtx)
	assert.True(t, res.Valid, "expected valid=true, got reason=%s", res.Reason)
}

func TestJSRPC_ERC20DecimalsInScript(t *testing.T) {
	srv := mockRPCServer(t, map[string]string{
		"eth_call": abiEncodeUint256(18),
	})
	defer srv.Close()

	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)
	cache, err := NewTokenMetadataCache(nil, provider, 0)
	require.NoError(t, err)

	rpcCtx := &RPCInjectionContext{
		ChainID:  "1",
		Provider: provider,
		Cache:    cache,
		Counter:  NewRPCCallCounter(10),
		Ctx:      context.Background(),
	}

	e := newTestEvaluator(t)
	script := `function validate(input) {
		var dec = erc20.decimals("0x0000000000000000000000000000000000000001");
		if (dec === 18) {
			return { valid: true };
		}
		return { valid: false, reason: "expected 18 got " + dec };
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, rpcCtx)
	assert.True(t, res.Valid, "expected valid=true, got reason=%s", res.Reason)
}

func TestJSRPC_ERC20SymbolInScript(t *testing.T) {
	srv := mockRPCServer(t, map[string]string{
		"eth_call": abiEncodeString("USDC"),
	})
	defer srv.Close()

	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)
	cache, err := NewTokenMetadataCache(nil, provider, 0)
	require.NoError(t, err)

	rpcCtx := &RPCInjectionContext{
		ChainID:  "1",
		Provider: provider,
		Cache:    cache,
		Counter:  NewRPCCallCounter(10),
		Ctx:      context.Background(),
	}

	e := newTestEvaluator(t)
	script := `function validate(input) {
		var sym = erc20.symbol("0x0000000000000000000000000000000000000001");
		if (sym === "USDC") {
			return { valid: true };
		}
		return { valid: false, reason: "expected USDC got " + sym };
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, rpcCtx)
	assert.True(t, res.Valid, "expected valid=true, got reason=%s", res.Reason)
}

func TestJSRPC_IsERC721InScript(t *testing.T) {
	// Mock: supportsInterface returns true, decimals() returns error (genuine NFT)
	decimalsSelector := hex.EncodeToString(selectorDecimals)
	srv := mockRPCServerFunc(t, func(req jsonRPCRequest) (string, error) {
		if req.Method != "eth_call" {
			return "", fmt.Errorf("unexpected method")
		}
		// Extract calldata from params to distinguish calls
		if params, ok := req.Params[0].(map[string]interface{}); ok {
			if data, ok := params["data"].(string); ok {
				if strings.Contains(data, decimalsSelector) {
					return "", fmt.Errorf("execution reverted") // no decimals = genuine NFT
				}
			}
		}
		// Default: supportsInterface returns true
		return abiEncodeBool(true), nil
	})
	defer srv.Close()

	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)
	cache, err := NewTokenMetadataCache(nil, provider, 0)
	require.NoError(t, err)

	rpcCtx := &RPCInjectionContext{
		ChainID:  "1",
		Provider: provider,
		Cache:    cache,
		Counter:  NewRPCCallCounter(10),
		Ctx:      context.Background(),
	}

	e := newTestEvaluator(t)
	script := `function validate(input) {
		if (isERC721("0x0000000000000000000000000000000000000001")) {
			return { valid: true };
		}
		return { valid: false, reason: "expected ERC721" };
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, rpcCtx)
	assert.True(t, res.Valid, "expected valid=true, got reason=%s", res.Reason)
}

func TestJSRPC_IsERC721_AntiSpoofing_ReturnsERC20WhenHasDecimals(t *testing.T) {
	// Mock: supportsInterface returns true AND decimals returns 18 = spoofing detected
	srv := mockRPCServer(t, map[string]string{
		"eth_call": abiEncodeBool(true), // both supportsInterface and decimals return "valid" response
	})
	defer srv.Close()

	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)
	cache, err := NewTokenMetadataCache(nil, provider, 0)
	require.NoError(t, err)

	rpcCtx := &RPCInjectionContext{
		ChainID:  "1",
		Provider: provider,
		Cache:    cache,
		Counter:  NewRPCCallCounter(10),
		Ctx:      context.Background(),
	}

	e := newTestEvaluator(t)
	// When a contract claims ERC721 but also has decimals(), isERC721 should return false
	script := `function validate(input) {
		if (isERC721("0x0000000000000000000000000000000000000001")) {
			return { valid: false, reason: "should not be ERC721 when contract has decimals" };
		}
		return { valid: true, reason: "correctly detected ERC20 spoofing" };
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, rpcCtx)
	assert.True(t, res.Valid, "expected anti-spoofing to detect ERC20, got reason=%s", res.Reason)
}

func TestJSRPC_RateLimitExceeded(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		resp := fmt.Sprintf(`{"jsonrpc":"2.0","result":"%s","id":1}`, abiEncodeUint256(6))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(resp))
	}))
	defer srv.Close()

	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)
	cache, err := NewTokenMetadataCache(nil, provider, 0)
	require.NoError(t, err)

	// Only allow 2 RPC calls
	rpcCtx := &RPCInjectionContext{
		ChainID:  "1",
		Provider: provider,
		Cache:    cache,
		Counter:  NewRPCCallCounter(2),
		Ctx:      context.Background(),
	}

	e := newTestEvaluator(t)
	// Script tries to call decimals 3 times — should fail on 3rd
	script := `function validate(input) {
		erc20.decimals("0x0000000000000000000000000000000000000001");
		erc20.decimals("0x0000000000000000000000000000000000000002");
		erc20.decimals("0x0000000000000000000000000000000000000003");
		return { valid: true };
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, rpcCtx)
	assert.False(t, res.Valid, "expected rate limit to block 3rd call")
	assert.Contains(t, res.Reason, "rpc call limit exceeded")
}

func TestJSRPC_StubsWhenNilRPCContext(t *testing.T) {
	e := newTestEvaluator(t)
	// web3.call should throw when RPC is not configured
	script := `function validate(input) {
		try {
			web3.call("0x0000000000000000000000000000000000000001", "0x313ce567");
			return { valid: false, reason: "should have thrown" };
		} catch(e) {
			return { valid: true, reason: e.message || String(e) };
		}
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, nil)
	assert.True(t, res.Valid, "stub should throw: reason=%s", res.Reason)
	assert.Contains(t, res.Reason, "rpc not configured")
}

func TestJSRPC_WriteMethodBlocked(t *testing.T) {
	for _, method := range []string{"eth_sendTransaction", "eth_sendRawTransaction", "eth_sign"} {
		t.Run(method, func(t *testing.T) {
			provider, err := NewRPCProvider("http://localhost:1", "")
			require.NoError(t, err)
			_, err = provider.doRPC(context.Background(), "1", method, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "blocked")
		})
	}
}

func TestJSRPC_OnlyAllowedMethods(t *testing.T) {
	provider, err := NewRPCProvider("http://localhost:1", "")
	require.NoError(t, err)
	_, err = provider.doRPC(context.Background(), "1", "eth_getBalance", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed")
}

func TestJSRPC_Web3GetCodeInScript(t *testing.T) {
	bytecode := "0x6080604052"
	srv := mockRPCServer(t, map[string]string{
		"eth_getCode": bytecode,
	})
	defer srv.Close()

	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)
	cache, err := NewTokenMetadataCache(nil, provider, 0)
	require.NoError(t, err)

	rpcCtx := &RPCInjectionContext{
		ChainID:  "1",
		Provider: provider,
		Cache:    cache,
		Counter:  NewRPCCallCounter(10),
		Ctx:      context.Background(),
	}

	e := newTestEvaluator(t)
	script := `function validate(input) {
		var code = web3.getCode("0x0000000000000000000000000000000000000001");
		if (code === "0x6080604052") {
			return { valid: true };
		}
		return { valid: false, reason: "unexpected code: " + code };
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, rpcCtx)
	assert.True(t, res.Valid, "expected valid=true, got reason=%s", res.Reason)
}

func TestJSRPC_ERC165SupportsInterfaceInScript(t *testing.T) {
	srv := mockRPCServer(t, map[string]string{
		"eth_call": abiEncodeBool(true),
	})
	defer srv.Close()

	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)
	cache, err := NewTokenMetadataCache(nil, provider, 0)
	require.NoError(t, err)

	rpcCtx := &RPCInjectionContext{
		ChainID:  "1",
		Provider: provider,
		Cache:    cache,
		Counter:  NewRPCCallCounter(10),
		Ctx:      context.Background(),
	}

	e := newTestEvaluator(t)
	script := `function validate(input) {
		var supports = erc165.supportsInterface("0x0000000000000000000000000000000000000001", "0x80ac58cd");
		if (supports) {
			return { valid: true };
		}
		return { valid: false, reason: "expected true" };
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, rpcCtx)
	assert.True(t, res.Valid, "expected valid=true, got reason=%s", res.Reason)
}

func TestRPCProvider_URLBuilding(t *testing.T) {
	p, err := NewRPCProvider("https://evm-gateway.example.com/chain/evm", "mykey123")
	require.NoError(t, err)
	url := p.rpcURL("137")
	assert.Equal(t, "https://evm-gateway.example.com/chain/evm/137/api_key/mykey123", url)

	p2, err := NewRPCProvider("https://evm-gateway.example.com/chain/evm/", "")
	require.NoError(t, err)
	url2 := p2.rpcURL("1")
	assert.Equal(t, "https://evm-gateway.example.com/chain/evm/1", url2)
}

func TestRPCProvider_EmptyBaseURL(t *testing.T) {
	_, err := NewRPCProvider("", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base_url is required")
}

func TestRPCCallCounter(t *testing.T) {
	c := NewRPCCallCounter(3)
	require.NoError(t, c.Increment())
	require.NoError(t, c.Increment())
	require.NoError(t, c.Increment())
	err := c.Increment()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "limit exceeded")
}

func TestDecodeUint8FromHex(t *testing.T) {
	// 6 encoded as uint256
	result, err := decodeUint8FromHex(abiEncodeUint256(6))
	require.NoError(t, err)
	assert.Equal(t, 6, result)

	result, err = decodeUint8FromHex(abiEncodeUint256(18))
	require.NoError(t, err)
	assert.Equal(t, 18, result)

	_, err = decodeUint8FromHex("")
	require.Error(t, err)
}

func TestDecodeStringFromHex(t *testing.T) {
	result, err := decodeStringFromHex(abiEncodeString("USDC"))
	require.NoError(t, err)
	assert.Equal(t, "USDC", result)

	result, err = decodeStringFromHex(abiEncodeString("Wrapped Ether"))
	require.NoError(t, err)
	assert.Equal(t, "Wrapped Ether", result)
}

func TestDecodeBoolFromHex(t *testing.T) {
	assert.True(t, decodeBoolFromHex(abiEncodeBool(true)))
	assert.False(t, decodeBoolFromHex(abiEncodeBool(false)))
	assert.False(t, decodeBoolFromHex(""))
}

func TestJSRPC_InvalidAddressThrows(t *testing.T) {
	srv := mockRPCServer(t, map[string]string{
		"eth_call": abiEncodeUint256(6),
	})
	defer srv.Close()

	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)
	cache, err := NewTokenMetadataCache(nil, provider, 0)
	require.NoError(t, err)

	rpcCtx := &RPCInjectionContext{
		ChainID:  "1",
		Provider: provider,
		Cache:    cache,
		Counter:  NewRPCCallCounter(10),
		Ctx:      context.Background(),
	}

	e := newTestEvaluator(t)
	script := `function validate(input) {
		web3.call("not_an_address", "0x313ce567");
		return { valid: true };
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, rpcCtx)
	assert.False(t, res.Valid, "expected invalid address to cause failure")
	assert.True(t, strings.Contains(res.Reason, "invalid address"), "reason should mention invalid address: %s", res.Reason)
}

func TestJSRPC_ERC20NameInScript(t *testing.T) {
	srv := mockRPCServer(t, map[string]string{
		"eth_call": abiEncodeString("USD Coin"),
	})
	defer srv.Close()

	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)
	cache, err := NewTokenMetadataCache(nil, provider, 0)
	require.NoError(t, err)

	rpcCtx := &RPCInjectionContext{
		ChainID:  "1",
		Provider: provider,
		Cache:    cache,
		Counter:  NewRPCCallCounter(10),
		Ctx:      context.Background(),
	}

	e := newTestEvaluator(t)
	script := `function validate(input) {
		var name = erc20.name("0x0000000000000000000000000000000000000001");
		if (name === "USD Coin") {
			return { valid: true };
		}
		return { valid: false, reason: "expected USD Coin got " + name };
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, rpcCtx)
	assert.True(t, res.Valid, "expected valid=true, got reason=%s", res.Reason)
}

func TestJSRPC_SetRPCProviderOnEvaluator(t *testing.T) {
	srv := mockRPCServer(t, map[string]string{
		"eth_call": abiEncodeUint256(6),
	})
	defer srv.Close()

	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)
	cache, err := NewTokenMetadataCache(nil, provider, 0)
	require.NoError(t, err)

	e := newTestEvaluator(t)
	e.SetRPCProvider(provider, cache)

	// buildRPCContext should return non-nil
	rpcCtx := e.buildRPCContext(context.Background(), "1")
	require.NotNil(t, rpcCtx)
	assert.Equal(t, "1", rpcCtx.ChainID)

	// Without SetRPCProvider, buildRPCContext returns nil
	e2 := newTestEvaluator(t)
	rpcCtx2 := e2.buildRPCContext(context.Background(), "1")
	assert.Nil(t, rpcCtx2)
}

// --- Security fix tests ---

func TestValidateChainID(t *testing.T) {
	tests := []struct {
		chainID string
		valid   bool
	}{
		{"1", true},
		{"137", true},
		{"42161", true},
		{"", false},
		{"0", false},
		{"abc", false},
		{"1/../../secret", false},
		{"1; DROP TABLE", false},
		{"-1", false},
		{"0x1", false},
		{"00001", true}, // leading zeros are harmless; ParseUint accepts it as 1
	}
	for _, tt := range tests {
		err := ValidateChainID(tt.chainID)
		if tt.valid {
			assert.NoError(t, err, "chainID=%q should be valid", tt.chainID)
		} else {
			assert.Error(t, err, "chainID=%q should be invalid", tt.chainID)
		}
	}
}

func TestValidateHexData(t *testing.T) {
	tests := []struct {
		data  string
		valid bool
	}{
		{"0x313ce567", true},
		{"0x", true},
		{"0xabcdef1234567890", true},
		{"313ce567", false},       // missing 0x
		{"0xZZZZ", false},          // invalid hex
		{"0x123", false},           // odd length
	}
	for _, tt := range tests {
		err := ValidateHexData(tt.data)
		if tt.valid {
			assert.NoError(t, err, "data=%q should be valid", tt.data)
		} else {
			assert.Error(t, err, "data=%q should be invalid", tt.data)
		}
	}
}

func TestJSRPC_InvalidHexDataThrows(t *testing.T) {
	srv := mockRPCServer(t, map[string]string{
		"eth_call": abiEncodeUint256(6),
	})
	defer srv.Close()

	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)
	cache, err := NewTokenMetadataCache(nil, provider, 0)
	require.NoError(t, err)

	rpcCtx := &RPCInjectionContext{
		ChainID:  "1",
		Provider: provider,
		Cache:    cache,
		Counter:  NewRPCCallCounter(10),
		Ctx:      context.Background(),
	}

	e := newTestEvaluator(t)
	// Pass invalid hex data to web3.call
	script := `function validate(input) {
		web3.call("0x0000000000000000000000000000000000000001", "not_hex");
		return { valid: true };
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, rpcCtx)
	assert.False(t, res.Valid, "expected invalid hex to cause failure")
	assert.Contains(t, res.Reason, "data must start with 0x")
}

func TestJSRPC_BuildRPCContext_InvalidChainID(t *testing.T) {
	srv := mockRPCServer(t, map[string]string{
		"eth_call": abiEncodeUint256(6),
	})
	defer srv.Close()

	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)
	cache, err := NewTokenMetadataCache(nil, provider, 0)
	require.NoError(t, err)

	e := newTestEvaluator(t)
	e.SetRPCProvider(provider, cache)

	// SSRF attempt: non-numeric chain_id should return nil (disabled RPC)
	rpcCtx := e.buildRPCContext(context.Background(), "1/../../admin")
	assert.Nil(t, rpcCtx, "path traversal chain_id should disable RPC")

	rpcCtx2 := e.buildRPCContext(context.Background(), "abc")
	assert.Nil(t, rpcCtx2, "non-numeric chain_id should disable RPC")
}

func TestJSRPC_CircuitBreaker(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Always return 500 to trigger circuit breaker
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)

	// Make enough failing calls to trip the breaker
	for i := 0; i < circuitBreakerThreshold+1; i++ {
		_, _ = provider.Call(context.Background(), "1", "0x0000000000000000000000000000000000000001", "0x313ce567")
	}

	// Next call should fail fast (circuit open)
	_, err = provider.Call(context.Background(), "1", "0x0000000000000000000000000000000000000001", "0x313ce567")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "circuit breaker open")
}

func TestJSRPC_NoRedirects(t *testing.T) {
	// Create a server that returns a redirect
	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://evil.example.com", http.StatusFound)
	}))
	defer redirectSrv.Close()

	provider, err := NewRPCProvider(redirectSrv.URL, "")
	require.NoError(t, err)

	_, err = provider.Call(context.Background(), "1", "0x0000000000000000000000000000000000000001", "0x313ce567")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect")
}

func TestDecodeUint8FromHex_RejectsOver77(t *testing.T) {
	// Value 78 should be rejected (max valid decimals is 77)
	_, err := decodeUint8FromHex(abiEncodeUint256(78))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of valid range")

	// Value 77 should be accepted
	result, err := decodeUint8FromHex(abiEncodeUint256(77))
	require.NoError(t, err)
	assert.Equal(t, 77, result)
}
