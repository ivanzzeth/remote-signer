package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJSTimeout_PureJS_StillTimesOut verifies that a JS rule with NO RPC calls
// still times out at the JS budget (20ms).
func TestJSTimeout_PureJS_StillTimesOut(t *testing.T) {
	e := newTestEvaluator(t)
	// Infinite loop — should be interrupted by the JS timer
	script := `function validate(input) {
		while(true) {}
		return { valid: true };
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}

	start := time.Now()
	res := e.wrappedValidate(script, input, nil, nil)
	elapsed := time.Since(start)

	assert.False(t, res.Valid, "infinite loop should timeout")
	assert.Contains(t, res.Reason, "timeout")
	// Should timeout within a reasonable margin of the 20ms budget (allow up to 200ms for scheduling)
	assert.Less(t, elapsed, 500*time.Millisecond, "timeout should fire quickly, took %s", elapsed)
}

// TestJSTimeout_RPCCallDoesNotConsumeJSBudget verifies that RPC call time
// is NOT counted against the JS execution budget. A mock RPC server sleeps
// for 100ms per call. The JS script does minimal work — it should NOT timeout
// even though total wall-clock time exceeds 20ms.
func TestJSTimeout_RPCCallDoesNotConsumeJSBudget(t *testing.T) {
	// Mock RPC server that takes 100ms to respond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		var req jsonRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp := fmt.Sprintf(`{"jsonrpc":"2.0","result":"%s","id":%d}`, abiEncodeUint256(18), req.ID)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(resp))
	}))
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
	// Script makes 2 RPC calls (200ms+ total wall time), but JS computation is trivial
	script := `function validate(input) {
		var d1 = erc20.decimals("0x0000000000000000000000000000000000000001");
		var d2 = erc20.decimals("0x0000000000000000000000000000000000000002");
		if (d1 === 18 && d2 === 18) {
			return { valid: true, reason: "ok" };
		}
		return { valid: false, reason: "unexpected decimals" };
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, rpcCtx)
	assert.True(t, res.Valid, "JS should NOT timeout during RPC calls, got reason=%s", res.Reason)
}

// TestJSTimeout_CumulativeRPCTimeExceedsLimit verifies that cumulative RPC
// duration is tracked and enforced independently.
func TestJSTimeout_CumulativeRPCTimeExceedsLimit(t *testing.T) {
	// Each RPC call takes 200ms; set max total time to 300ms — 2nd call should exceed limit
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		var req jsonRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp := fmt.Sprintf(`{"jsonrpc":"2.0","result":"%s","id":%d}`, abiEncodeUint256(6), req.ID)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(resp))
	}))
	defer srv.Close()

	provider, err := NewRPCProvider(srv.URL, "")
	require.NoError(t, err)
	cache, err := NewTokenMetadataCache(nil, provider, 0)
	require.NoError(t, err)

	counter := NewRPCCallCounter(10)
	counter.maxTotalTime = 300 * time.Millisecond // override for test

	rpcCtx := &RPCInjectionContext{
		ChainID:  "1",
		Provider: provider,
		Cache:    cache,
		Counter:  counter,
		Ctx:      context.Background(),
	}

	e := newTestEvaluator(t)
	// Script tries 3 RPC calls — cumulative time will exceed 300ms after 2nd call
	script := `function validate(input) {
		erc20.decimals("0x0000000000000000000000000000000000000001");
		erc20.decimals("0x0000000000000000000000000000000000000002");
		erc20.decimals("0x0000000000000000000000000000000000000003");
		return { valid: true };
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, rpcCtx)
	assert.False(t, res.Valid, "should fail when cumulative RPC time exceeds limit")
	assert.Contains(t, res.Reason, "rpc cumulative time limit exceeded")
}

// TestJSTimeout_RPCCallCountLimitStillWorks verifies that the existing RPC call
// count limit still functions correctly alongside the new duration tracking.
func TestJSTimeout_RPCCallCountLimitStillWorks(t *testing.T) {
	srv := mockRPCServer(t, map[string]string{
		"eth_call": abiEncodeUint256(6),
	})
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
	// Script tries 3 calls — should fail on count limit
	script := `function validate(input) {
		erc20.decimals("0x0000000000000000000000000000000000000001");
		erc20.decimals("0x0000000000000000000000000000000000000002");
		erc20.decimals("0x0000000000000000000000000000000000000003");
		return { valid: true };
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, rpcCtx)
	assert.False(t, res.Valid, "should fail on RPC call count limit")
	assert.Contains(t, res.Reason, "rpc call limit exceeded")
}

// TestRPCCallCounter_AddDuration verifies cumulative duration tracking.
func TestRPCCallCounter_AddDuration(t *testing.T) {
	c := NewRPCCallCounter(10)
	c.maxTotalTime = 500 * time.Millisecond

	require.NoError(t, c.AddDuration(200*time.Millisecond))
	assert.Equal(t, 200*time.Millisecond, c.CumulativeDuration())

	require.NoError(t, c.AddDuration(200*time.Millisecond))
	assert.Equal(t, 400*time.Millisecond, c.CumulativeDuration())

	// This should exceed the 500ms limit
	err := c.AddDuration(200 * time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rpc cumulative time limit exceeded")
}

// TestJSTimeout_Web3CallAlsoPausesTimer verifies that web3.call (which doesn't
// go through the token metadata cache) also pauses the JS timer correctly.
func TestJSTimeout_Web3CallAlsoPausesTimer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		var req jsonRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp := fmt.Sprintf(`{"jsonrpc":"2.0","result":"%s","id":%d}`, abiEncodeUint256(42), req.ID)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(resp))
	}))
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
	// web3.call takes 100ms+ wall time but JS computation is trivial
	script := `function validate(input) {
		var result = web3.call("0x0000000000000000000000000000000000000001", "0x313ce567");
		if (result !== "") {
			return { valid: true, reason: "ok" };
		}
		return { valid: false, reason: "no result" };
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, rpcCtx)
	assert.True(t, res.Valid, "web3.call should not consume JS budget, got reason=%s", res.Reason)
}
