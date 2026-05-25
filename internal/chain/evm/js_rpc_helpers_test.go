//go:build integration

package evm

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		_, _ = w.Write([]byte(resp))
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
