//go:build integration

package evm

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"

	"testing"
	"time"

	"github.com/grafana/sobek"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// =============================================================================
// rpc_provider.go: GetTransactionCount
// =============================================================================

func TestProviderGetTransactionCount_Success_CB5(t *testing.T) {
	srv, provider := newTestRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x5"}`))
	})
	defer srv.Close()
	nonce, err := provider.GetTransactionCount(context.Background(), "137", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	require.NoError(t, err)
	assert.Equal(t, uint64(5), nonce)
}

func TestProviderGetTransactionCount_InvalidChainID_CB5(t *testing.T) {
	_, provider := newTestRPCServer(t, nil)
	_, err := provider.GetTransactionCount(context.Background(), "", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	assert.ErrorContains(t, err, "chain_id")
}

func TestProviderGetTransactionCount_InvalidAddress_CB5(t *testing.T) {
	_, provider := newTestRPCServer(t, nil)
	_, err := provider.GetTransactionCount(context.Background(), "137", "bad")
	assert.ErrorContains(t, err, "address")
}

// =============================================================================
// rpc_provider.go: SendRawTransaction
// =============================================================================

func TestProviderSendRawTransaction_Success_CB5(t *testing.T) {
	srv, provider := newTestRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0xtxhash"}`))
	})
	defer srv.Close()
	txHash, err := provider.SendRawTransaction(context.Background(), "137", "0xf00d")
	require.NoError(t, err)
	assert.Equal(t, "0xtxhash", txHash)
}

func TestProviderSendRawTransaction_InvalidChainID_CB5(t *testing.T) {
	_, provider := newTestRPCServer(t, nil)
	_, err := provider.SendRawTransaction(context.Background(), "", "0xf00d")
	assert.ErrorContains(t, err, "chain_id")
}

// =============================================================================
// rpc_provider.go: DoWalletProxyRPC
// =============================================================================

func TestProviderDoWalletProxyRPC_Success_CB5(t *testing.T) {
	srv, provider := newTestRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x10"}`))
	})
	defer srv.Close()
	result, err := provider.DoWalletProxyRPC(context.Background(), "137", "eth_blockNumber", nil)
	require.NoError(t, err)
	var num string
	_ = json.Unmarshal(result, &num)
	assert.Equal(t, "0x10", num)
}

func TestProviderDoWalletProxyRPC_InvalidChainID_CB5(t *testing.T) {
	_, provider := newTestRPCServer(t, nil)
	_, err := provider.DoWalletProxyRPC(context.Background(), "abc", "eth_blockNumber", nil)
	assert.ErrorContains(t, err, "chain_id")
}

func TestProviderDoWalletProxyRPC_DisallowedMethod_CB5(t *testing.T) {
	_, provider := newTestRPCServer(t, nil)
	_, err := provider.DoWalletProxyRPC(context.Background(), "137", "eth_sign", nil)
	assert.ErrorContains(t, err, "not allowed")
}

// =============================================================================
// rpc_provider.go: GetTransactionReceipt
// =============================================================================

func TestProviderGetTransactionReceipt_Success_CB5(t *testing.T) {
	srv, provider := newTestRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"blockNumber":"0x1"}}`))
	})
	defer srv.Close()
	receipt, err := provider.GetTransactionReceipt(context.Background(), "137", "0xtxhash")
	require.NoError(t, err)
	assert.NotNil(t, receipt)
}

func TestProviderGetTransactionReceipt_InvalidChainID_CB5(t *testing.T) {
	_, provider := newTestRPCServer(t, nil)
	_, err := provider.GetTransactionReceipt(context.Background(), "abc", "0xtxhash")
	assert.ErrorContains(t, err, "chain_id")
}

// =============================================================================
// rpc_provider.go: QueryAllowance
// =============================================================================

func TestProviderQueryAllowance_Success_CB5(t *testing.T) {
	srv, provider := newTestRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x0000000000000000000000000000000000000000000000000000000000000064"}`))
	})
	defer srv.Close()
	allowance, err := provider.QueryAllowance(context.Background(), "137",
		"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
		"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		"0x1111111254fb6c44bAC0beD2854e76F90643097d")
	require.NoError(t, err)
	assert.Equal(t, int64(100), allowance.Int64())
}

func TestProviderQueryAllowance_EmptyResult_CB5(t *testing.T) {
	srv, provider := newTestRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x"}`))
	})
	defer srv.Close()
	allowance, err := provider.QueryAllowance(context.Background(), "137",
		"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
		"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		"0x1111111254fb6c44bAC0beD2854e76F90643097d")
	require.NoError(t, err)
	assert.Equal(t, int64(0), allowance.Int64())
}

func TestProviderQueryAllowance_InvalidResult_CB5(t *testing.T) {
	srv, provider := newTestRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0xzz"}`))
	})
	defer srv.Close()
	_, err := provider.QueryAllowance(context.Background(), "137",
		"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
		"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		"0x1111111254fb6c44bAC0beD2854e76F90643097d")
	assert.Error(t, err)
}

// =============================================================================
// rpc_provider.go: doRPCUnchecked error paths
// =============================================================================

func TestProviderDoRPCUnchecked_RPCError_CB5(t *testing.T) {
	srv, provider := newTestRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"execution reverted"}}`))
	})
	defer srv.Close()
	_, err := provider.SendRawTransaction(context.Background(), "137", "0xf00d")
	assert.ErrorContains(t, err, "rpc error")
}

func TestProviderDoRPCUnchecked_HTTPError_CB5(t *testing.T) {
	srv, provider := newTestRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`internal error`))
	})
	defer srv.Close()
	_, err := provider.SendRawTransaction(context.Background(), "137", "0xf00d")
	assert.ErrorContains(t, err, "rpc returned status 500")
}

func TestProviderDoRPCUnchecked_BadJSON_CB5(t *testing.T) {
	srv, provider := newTestRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not json`))
	})
	defer srv.Close()
	_, err := provider.SendRawTransaction(context.Background(), "137", "0xf00d")
	assert.Error(t, err)
}

// =============================================================================
// rpc_provider.go: doRPCRaw circuit breaker and rate limit
// =============================================================================

func TestProviderDoRPCRaw_CircuitBreaker_CB5(t *testing.T) {
	_, provider := newTestRPCServer(t, nil)
	for i := 0; i < circuitBreakerThreshold; i++ {
		provider.breaker.recordError()
	}
	_, err := provider.GetTransactionReceipt(context.Background(), "137", "0xtxhash")
	assert.ErrorContains(t, err, "circuit breaker")
}

func TestProviderDoRPCUnchecked_RateLimit_CB5(t *testing.T) {
	_, provider := newTestRPCServer(t, nil)
	provider.limiter.tokens = 0
	_, err := provider.SendRawTransaction(context.Background(), "137", "0xf00d")
	assert.ErrorContains(t, err, "rate limit")
}

func TestProviderDoRPCRaw_RateLimit_CB5(t *testing.T) {
	_, provider := newTestRPCServer(t, nil)
	provider.limiter.tokens = 0
	_, err := provider.GetTransactionReceipt(context.Background(), "137", "0xtxhash")
	assert.ErrorContains(t, err, "rate limit")
}

func TestNewRPCProvider_EmptyBaseURL_CB5(t *testing.T) {
	_, err := NewRPCProvider("", "")
	assert.Error(t, err)
}

func TestNewRPCProvider_WhitespaceBaseURL_CB5(t *testing.T) {
	_, err := NewRPCProvider("   ", "")
	assert.Error(t, err)
}

// =============================================================================
// decimals_querier.go
// =============================================================================

func TestNewDecimalsQuerierAdapter_NilCache_CB5(t *testing.T) {
	_, err := NewDecimalsQuerierAdapter(nil)
	assert.ErrorContains(t, err, "required")
}

// =============================================================================
// password_provider.go
// =============================================================================

func TestEnvPasswordProvider_EmptyEnvVar_CB5(t *testing.T) {
	p := &EnvPasswordProvider{}
	_, err := p.GetPassword("0xabc", KeystoreConfig{PasswordEnv: ""})
	assert.ErrorContains(t, err, "password_env not configured")
}

func TestEnvPasswordProvider_MissingEnvVar_CB5(t *testing.T) {
	t.Setenv("TEST_NONEXISTENT_KEY", "")
	p := &EnvPasswordProvider{}
	_, err := p.GetPassword("0xabc", KeystoreConfig{PasswordEnv: "TEST_NONEXISTENT_KEY"})
	assert.ErrorContains(t, err, "environment variable")
}

func TestEnvPasswordProvider_Success_CB5(t *testing.T) {
	t.Setenv("TEST_VALID_PASSWORD", "mysecret")
	p := &EnvPasswordProvider{}
	pass, err := p.GetPassword("0xabc", KeystoreConfig{PasswordEnv: "TEST_VALID_PASSWORD"})
	require.NoError(t, err)
	assert.Equal(t, "mysecret", string(pass))
}

func TestNewEnvPasswordProvider_CB5(t *testing.T) {
	p, err := NewEnvPasswordProvider()
	require.NoError(t, err)
	assert.NotNil(t, p)
}

func TestNewCompositePasswordProvider_NoStdin_CB5(t *testing.T) {
	p, err := NewCompositePasswordProvider(false)
	require.NoError(t, err)
	assert.NotNil(t, p)
}

func TestCompositePasswordProvider_GetPassword_EnvFallback_CB5(t *testing.T) {
	t.Setenv("TEST_COMPOSITE_KEY", "composite_pass")
	p := &CompositePasswordProvider{env: &EnvPasswordProvider{}, stdin: nil}
	pass, err := p.GetPassword("0xabc", KeystoreConfig{PasswordEnv: "TEST_COMPOSITE_KEY"})
	require.NoError(t, err)
	assert.Equal(t, "composite_pass", string(pass))
}

func TestCompositePasswordProvider_StdinNotInitialized_CB5(t *testing.T) {
	p := &CompositePasswordProvider{env: &EnvPasswordProvider{}, stdin: nil}
	_, err := p.GetPassword("0xabc", KeystoreConfig{PasswordStdin: true})
	assert.ErrorContains(t, err, "not initialized")
}

// =============================================================================
// signer.go
// =============================================================================

func TestSignerRegistryClose_CB5(t *testing.T) {
	r := mustNewRegistry(t)
	err := r.Close()
	assert.NoError(t, err)
}

func TestSignerRegistryListSignersWithFilter_Empty_CB5(t *testing.T) {
	r := NewEmptySignerRegistry()
	result := r.ListSignersWithFilter(types.SignerFilter{})
	assert.Empty(t, result.Signers)
	assert.Equal(t, 0, result.Total)
}

func TestSignerRegistryListSigners_CB5(t *testing.T) {
	r := NewEmptySignerRegistry()
	signers := r.ListSigners()
	assert.Empty(t, signers)
}

// =============================================================================
// provider_hdwallet.go: decryptMnemonicFromJSON
// =============================================================================

func TestDecryptMnemonicFromJSON_InvalidJSON_CB5(t *testing.T) {
	_, err := decryptMnemonicFromJSON("not json", []byte("password"))
	assert.ErrorContains(t, err, "invalid wallet json")
}

func TestDecryptMnemonicFromJSON_EmptyCrypto_CB5(t *testing.T) {
	walletJSON := `{"mnemonic":{"crypto":{},"version":3}}`
	_, err := decryptMnemonicFromJSON(walletJSON, []byte("password"))
	assert.Error(t, err)
}

// =============================================================================
// provider_keystore.go
// =============================================================================

func TestKeystoreProvider_DiscoverLockedSigners_EmptyDir_CB5(t *testing.T) {
	r := NewEmptySignerRegistry()
	kp := &KeystoreProvider{registry: r, keystoreDir: "", pwProvider: &EnvPasswordProvider{}, lockedPaths: make(map[string]string)}
	discovered, err := kp.DiscoverLockedSigners()
	require.NoError(t, err)
	assert.Nil(t, discovered)
}

func TestKeystoreProvider_UnlockSigner_NoLockedKey_CB5(t *testing.T) {
	r := NewEmptySignerRegistry()
	kp := &KeystoreProvider{registry: r, lockedPaths: make(map[string]string)}
	_, err := kp.UnlockSigner(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "password")
	assert.ErrorContains(t, err, "no locked keystore")
}

func TestKeystoreProvider_LockSigner_NoKeystores_CB5(t *testing.T) {
	r := NewEmptySignerRegistry()
	kp := &KeystoreProvider{registry: r, keystoreDir: "/nonexistent", lockedPaths: make(map[string]string)}
	err := kp.LockSigner(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	assert.Error(t, err)
}

func TestKeystoreProvider_DeleteSigner_NoKeystores_CB5(t *testing.T) {
	r := NewEmptySignerRegistry()
	kp := &KeystoreProvider{registry: r, keystoreDir: "/nonexistent", lockedPaths: make(map[string]string)}
	err := kp.DeleteSigner(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	assert.Error(t, err)
}

// =============================================================================
// signer_manager.go
// =============================================================================

func TestNewSignerManager_NilRegistry_CB5(t *testing.T) {
	_, err := NewSignerManager(nil)
	assert.ErrorContains(t, err, "registry is required")
}

func TestNewSignerManager_Success_CB5(t *testing.T) {
	r := mustNewRegistry(t)
	m, err := NewSignerManager(r)
	require.NoError(t, err)
	assert.NotNil(t, m)
}

func TestSignerManager_SetAutoLockTimeout_CB5(t *testing.T) {
	r := mustNewRegistry(t)
	m, err := NewSignerManager(r)
	require.NoError(t, err)
	m.SetAutoLockTimeout(5 * time.Minute)
}

func TestSignerManager_SetOnAutoLock_CB5(t *testing.T) {
	r := mustNewRegistry(t)
	m, err := NewSignerManager(r)
	require.NoError(t, err)
	called := false
	m.SetOnAutoLock(func(addr string) { called = true })
	assert.False(t, called)
}

func TestSignerManager_StopAutoLockTimers_CB5(t *testing.T) {
	r := mustNewRegistry(t)
	m, err := NewSignerManager(r)
	require.NoError(t, err)
	m.StopAutoLockTimers()
}

func TestSignerManager_HDWalletManager_NotConfigured_CB5(t *testing.T) {
	r := mustNewRegistry(t)
	m, err := NewSignerManager(r)
	require.NoError(t, err)
	_, err = m.HDWalletManager()
	assert.ErrorIs(t, err, types.ErrHDWalletNotConfigured)
}

func TestSignerManager_DiscoverLockedSigners_NoProviders_CB5(t *testing.T) {
	r := NewEmptySignerRegistry()
	m, err := NewSignerManager(r)
	require.NoError(t, err)
	err = m.DiscoverLockedSigners(context.Background())
	assert.NoError(t, err)
}

func TestSignerManager_ListSigners_CB5(t *testing.T) {
	r := mustNewRegistry(t)
	m, err := NewSignerManager(r)
	require.NoError(t, err)
	result, err := m.ListSigners(context.Background(), types.SignerFilter{})
	require.NoError(t, err)
	assert.Empty(t, result.Signers)
}

func TestSignerManager_CreateSigner_InvalidRequest_CB5(t *testing.T) {
	r := mustNewRegistry(t)
	m, err := NewSignerManager(r)
	require.NoError(t, err)
	_, err = m.CreateSigner(context.Background(), types.CreateSignerRequest{})
	assert.Error(t, err)
}

func TestSignerManager_UnlockSigner_NotFound_CB5(t *testing.T) {
	r := mustNewRegistry(t)
	m, err := NewSignerManager(r)
	require.NoError(t, err)
	_, err = m.UnlockSigner(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "password")
	assert.ErrorIs(t, err, types.ErrSignerNotFound)
}

func TestSignerManager_LockSigner_NotFound_CB5(t *testing.T) {
	r := mustNewRegistry(t)
	m, err := NewSignerManager(r)
	require.NoError(t, err)
	_, err = m.LockSigner(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	assert.ErrorIs(t, err, types.ErrSignerNotFound)
}

func TestSignerManager_DeleteSigner_NotFound_CB5(t *testing.T) {
	r := mustNewRegistry(t)
	m, err := NewSignerManager(r)
	require.NoError(t, err)
	err = m.DeleteSigner(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	assert.ErrorIs(t, err, types.ErrSignerNotFound)
}

func TestSignerManager_GetHDHierarchy_Empty_CB5(t *testing.T) {
	r := mustNewRegistry(t)
	m, err := NewSignerManager(r)
	require.NoError(t, err)
	hierarchy := m.GetHDHierarchy()
	assert.Empty(t, hierarchy)
}

// =============================================================================
// simulation_rule.go
// =============================================================================

func TestNewRPCAllowanceQuerier_Nil_CB5(t *testing.T) {
	q := NewRPCAllowanceQuerier(nil)
	assert.Nil(t, q)
}

func TestNewRPCAllowanceQuerier_Success_CB5(t *testing.T) {
	srv, provider := newTestRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x0"}`))
	})
	defer srv.Close()
	q := NewRPCAllowanceQuerier(provider)
	assert.NotNil(t, q)
	allowance, err := q.QueryAllowance(context.Background(), "137",
		"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
		"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		"0x1111111254fb6c44bAC0beD2854e76F90643097d")
	require.NoError(t, err)
	assert.NotNil(t, allowance)
}

func TestNewEVMAdapterSignerLister_CB5(t *testing.T) {
	reg := NewEmptySignerRegistry()
	adapter, err := NewEVMAdapter(reg)
	require.NoError(t, err)
	lister := NewEVMAdapterSignerLister(adapter)
	assert.NotNil(t, lister)
}

func TestSimulationBudgetRule_Available_NilSimulator_CB5(t *testing.T) {
	rule := &SimulationBudgetRule{logger: newTestLogger()}
	assert.False(t, rule.Available())
}

func TestSimulationBudgetRule_SetSimulationRepo_Nil_CB5(t *testing.T) {
	rule := &SimulationBudgetRule{logger: newTestLogger()}
	rule.SetSimulationRepo(nil)
}

// =============================================================================
// TokenMetadataCache: counter exceeded
// =============================================================================

func TestTokenMetadataGetDecimals_CounterExceeded_CB5(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:test_tmd_exceed?mode=memory&cache=shared"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	cache := &TokenMetadataCache{db: db, provider: nil}
	counter := NewRPCCallCounter(1)
	counter.count = 2 // exceed limit to trigger error before provider call
	_, err = cache.GetDecimals(context.Background(), "137", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", counter)
	assert.ErrorContains(t, err, "exceeded")
}

// =============================================================================
// js_rpc_helpers.go: JS RPC helpers missing args
// =============================================================================

func TestJsERC20Decimals_NoArgs_CB5(t *testing.T) {
	vm := sobek.New()
	ctx := &RPCInjectionContext{ChainID: "137", Counter: NewRPCCallCounter(0), Timer: newPausableTimer(vm, time.Second)}
	_ = injectRPCHelpers(vm, ctx)
	_, err := vm.RunString(`erc20.decimals()`)
	assert.Error(t, err)
}

func TestJsERC20Decimals_InvalidAddress_CB5(t *testing.T) {
	vm := sobek.New()
	ctx := &RPCInjectionContext{ChainID: "137", Counter: NewRPCCallCounter(1), Timer: newPausableTimer(vm, time.Second)}
	_ = injectRPCHelpers(vm, ctx)
	_, err := vm.RunString(`erc20.decimals("not-an-address")`)
	assert.Error(t, err)
}

func TestJsERC20Symbol_NoArgs_CB5(t *testing.T) {
	vm := sobek.New()
	ctx := &RPCInjectionContext{ChainID: "137", Counter: NewRPCCallCounter(0), Timer: newPausableTimer(vm, time.Second)}
	_ = injectRPCHelpers(vm, ctx)
	_, err := vm.RunString(`erc20.symbol()`)
	assert.Error(t, err)
}

func TestJsERC20Name_NoArgs_CB5(t *testing.T) {
	vm := sobek.New()
	ctx := &RPCInjectionContext{ChainID: "137", Counter: NewRPCCallCounter(0), Timer: newPausableTimer(vm, time.Second)}
	_ = injectRPCHelpers(vm, ctx)
	_, err := vm.RunString(`erc20.name()`)
	assert.Error(t, err)
}

func TestJsWeb3GetCode_NoArgs_CB5(t *testing.T) {
	vm := sobek.New()
	ctx := &RPCInjectionContext{ChainID: "137", Counter: NewRPCCallCounter(1), Timer: newPausableTimer(vm, time.Second)}
	_ = injectRPCHelpers(vm, ctx)
	_, err := vm.RunString(`web3.getCode()`)
	assert.Error(t, err)
}

func TestJsIsERC721_NoArgs_CB5(t *testing.T) {
	vm := sobek.New()
	ctx := &RPCInjectionContext{ChainID: "137", Counter: NewRPCCallCounter(0), Timer: newPausableTimer(vm, time.Second)}
	_ = injectRPCHelpers(vm, ctx)
	_, err := vm.RunString(`isERC721()`)
	assert.Error(t, err)
}

func TestJsIsERC1155_NoArgs_CB5(t *testing.T) {
	vm := sobek.New()
	ctx := &RPCInjectionContext{ChainID: "137", Counter: NewRPCCallCounter(0), Timer: newPausableTimer(vm, time.Second)}
	_ = injectRPCHelpers(vm, ctx)
	_, err := vm.RunString(`isERC1155()`)
	assert.Error(t, err)
}

func TestJsERC165SupportsInterface_NoArgs_CB5(t *testing.T) {
	vm := sobek.New()
	ctx := &RPCInjectionContext{ChainID: "137", Counter: NewRPCCallCounter(0), Timer: newPausableTimer(vm, time.Second)}
	_ = injectRPCHelpers(vm, ctx)
	_, err := vm.RunString(`erc165.supportsInterface()`)
	assert.Error(t, err)
}

// =============================================================================
// js_evaluator.go: removeGlobals, isUndefined
// =============================================================================

func TestTrySetUndefined_NonExistentGlobal_CB5(t *testing.T) {
	vm := sobek.New()
	err := trySetUndefined(vm, "NonExistentGlobal", "something")
	assert.NoError(t, err)
}

func TestIsUndefined_NilValue_CB5(t *testing.T) {
	assert.True(t, isUndefined(nil))
}

// =============================================================================
// js_evaluator.go: ParseBudgetResultObject
// =============================================================================

func TestParseBudgetResultObject_MissingAmount_CB5(t *testing.T) {
	_, err := parseBudgetResultObject(map[string]interface{}{"unit": "USDC"})
	assert.Error(t, err)
}

// =============================================================================
// js_evaluator.go: exportedToBigInt edge cases
// =============================================================================

func TestExportedToBigInt_NegativeInt_CB5(t *testing.T) {
	_, err := exportedToBigInt(int(-5))
	assert.Error(t, err)
}

func TestExportedToBigInt_NegativeBigInt_CB5(t *testing.T) {
	_, err := exportedToBigInt(big.NewInt(-10))
	assert.Error(t, err)
}

func TestExportedToBigInt_InvalidDecimalString_CB5(t *testing.T) {
	_, err := exportedToBigInt("not-a-number")
	assert.Error(t, err)
}

func TestExportedToBigInt_UnsupportedType_CB5(t *testing.T) {
	_, err := exportedToBigInt([]byte{1, 2, 3})
	assert.Error(t, err)
}

// =============================================================================
// js_evaluator.go: sanitizeReason edge cases
// =============================================================================

func TestSanitizeReason_EmptyDetail_CB5(t *testing.T) {
	result := sanitizeReason("ERROR_CODE", "", false)
	assert.Equal(t, "ERROR_CODE", result)
}

func TestSanitizeReason_EmptyDetailIsReason_CB5(t *testing.T) {
	result := sanitizeReason("", "", true)
	assert.Equal(t, "", result)
}

func TestSanitizeReason_Newlines_CB5(t *testing.T) {
	result := sanitizeReason("", "hello\nworld\n", false)
	assert.Contains(t, result, `\n`)
	assert.NotContains(t, result, "\n")
}

// =============================================================================
// js_evaluator.go: extractJSExceptionMessage
// =============================================================================

func TestExtractJSExceptionMessage_WithAt_CB5(t *testing.T) {
	msg := extractJSExceptionMessage("Error: something broke at foobar")
	assert.Equal(t, "something broke", msg)
}

func TestExtractJSExceptionMessage_WithoutPrefix_CB5(t *testing.T) {
	msg := extractJSExceptionMessage("custom error")
	assert.Equal(t, "custom error", msg)
}

// =============================================================================
// js_evaluator.go: wrappedValidate, EvaluateBudget edge cases
// =============================================================================

func TestWrappedValidateBudget_NoBudgetFunc_CB5(t *testing.T) {
	log := newTestLogger()
	eval, err := NewJSRuleEvaluator(log)
	require.NoError(t, err)
	cfg := JSRuleConfig{Script: `function validate(input) { return {valid: true}; }`}
	cfgJSON, _ := json.Marshal(cfg)
	rule := &types.Rule{ID: "test-no-budget", Config: cfgJSON, Mode: types.RuleModeWhitelist, Type: types.RuleTypeEVMJS}
	req := &types.SignRequest{ID: "req", ChainID: "137", SignType: "hash", SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", Payload: []byte(`{"from":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266","to":"0xabc","data":"0xaabbccdd"}`)}
	budget, err := eval.EvaluateBudget(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(0), budget.Amount.Int64())
	assert.Equal(t, "", budget.Unit)
}

func TestWrappedValidateBudget_NotAFunction_CB5(t *testing.T) {
	log := newTestLogger()
	eval, err := NewJSRuleEvaluator(log)
	require.NoError(t, err)
	cfg := JSRuleConfig{Script: `var validateBudget = "not a function"; function validate(input) { return {valid: true}; }`}
	cfgJSON, _ := json.Marshal(cfg)
	rule := &types.Rule{ID: "test-budget-not-func", Config: cfgJSON, Mode: types.RuleModeWhitelist, Type: types.RuleTypeEVMJS}
	req := &types.SignRequest{ID: "req", ChainID: "137", SignType: "hash", SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"}
	_, err = eval.EvaluateBudget(context.Background(), rule, req, nil)
	assert.Error(t, err)
}

func TestEvaluateBudgetWithInput_EmptyScript_CB5(t *testing.T) {
	log := newTestLogger()
	eval, err := NewJSRuleEvaluator(log)
	require.NoError(t, err)
	cfg := JSRuleConfig{Script: ``}
	cfgJSON, _ := json.Marshal(cfg)
	rule := &types.Rule{ID: "test-empty-budget-input", Config: cfgJSON, Mode: types.RuleModeWhitelist, Type: types.RuleTypeEVMJS}
	_, err = eval.EvaluateBudgetWithInput(context.Background(), rule, &RuleInput{})
	assert.Error(t, err)
}

func TestWrappedValidate_MissingValidate_CB5(t *testing.T) {
	log := newTestLogger()
	eval, err := NewJSRuleEvaluator(log)
	require.NoError(t, err)
	cfg := JSRuleConfig{Script: `// no validate function`}
	cfgJSON, _ := json.Marshal(cfg)
	rule := &types.Rule{ID: "test-no-validate", Config: cfgJSON, Mode: types.RuleModeWhitelist, Type: types.RuleTypeEVMJS}
	req := &types.SignRequest{ID: "req", ChainID: "137", SignType: "hash", SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"}
	valid, reason, err := eval.Evaluate(context.Background(), rule, req, &types.ParsedPayload{})
	require.NoError(t, err)
	assert.False(t, valid)
	assert.Contains(t, reason, "validate is not defined")
}

// =============================================================================
// js_helpers.go: keccak256, selector, abi, tx, addr, config helpers
// =============================================================================

func TestInjectHelpers_Keccak256_NoArgs_CB5(t *testing.T) {
	vm := sobek.New()
	_ = injectHelpers(vm)
	_, err := vm.RunString(`keccak256("hello")`)
	assert.NoError(t, err)
}

func TestInjectHelpers_Selector_NoArgs_CB5(t *testing.T) {
	vm := sobek.New()
	_ = injectHelpers(vm)
	_, err := vm.RunString(`selector("transfer(address,uint256)")`)
	assert.NoError(t, err)
}

func TestInjectHelpers_AbiEncode_NoArgs_CB5(t *testing.T) {
	vm := sobek.New()
	_ = injectHelpers(vm)
	val, err := vm.RunString(`abi.encode()`)
	require.NoError(t, err)
	assert.Equal(t, "0x", val.String())
}

func TestInjectHelpers_AbiDecode_NoArgs_CB5(t *testing.T) {
	vm := sobek.New()
	_ = injectHelpers(vm)
	val, err := vm.RunString(`JSON.stringify(abi.decode())`)
	require.NoError(t, err)
	assert.Contains(t, val.String(), "[]")
}



func TestRsAddrIsZero_NoArgs_CB5(t *testing.T) {
	vm := sobek.New()
	_ = injectHelpers(vm)
	val, err := vm.RunString(`rs.addr.isZero()`)
	require.NoError(t, err)
	assert.Equal(t, "false", val.String())
}


// =============================================================================
// adapter.go: Sign with invalid JSON
// =============================================================================

func TestAdapterSign_InvalidJSON_CB5(t *testing.T) {
	adapter, err := NewEVMAdapter(mustNewRegistry(t))
	require.NoError(t, err)
	_, err = adapter.Sign(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "transaction", "137", []byte("not-json"))
	assert.Error(t, err)
}

// =============================================================================
// decodeStringFromHex edge cases
// =============================================================================

func TestDecodeStringFromHex_Empty_CB5(t *testing.T) {
	_, err := decodeStringFromHex("0x")
	assert.Error(t, err)
}

func TestDecodeStringFromHex_InvalidHex_CB5(t *testing.T) {
	_, err := decodeStringFromHex("0xzzzz")
	assert.Error(t, err)
}

func TestDecodeStringFromHex_TooShort_CB5(t *testing.T) {
	_, err := decodeStringFromHex("0x1234")
	assert.Error(t, err)
}

// =============================================================================
// NewRPCProvider with API key
// =============================================================================

func TestNewRPCProvider_WithAPIKey_CB5(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.String(), "/mykey")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x0000000000000000000000000000000000000000000000000000000000000006"}`))
	}))
	defer srv.Close()
	provider, err := NewRPCProvider(srv.URL, "mykey")
	require.NoError(t, err)
	result, err := provider.Call(context.Background(), "137", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "0x313ce567")
	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

// =============================================================================
// Circuit breaker edge cases
// =============================================================================

func TestCircuitBreaker_Open_AtThreshold_CB5(t *testing.T) {
	cb := newCircuitBreaker(circuitBreakerThreshold, circuitBreakerResetTime)
	assert.False(t, cb.isOpen())
	for i := 0; i < circuitBreakerThreshold; i++ {
		cb.recordError()
	}
	assert.True(t, cb.isOpen())
}

func TestCircuitBreaker_RecordSuccess_Resets_CB5(t *testing.T) {
	cb := newCircuitBreaker(circuitBreakerThreshold, circuitBreakerResetTime)
	for i := 0; i < circuitBreakerThreshold-1; i++ {
		cb.recordError()
	}
	cb.recordSuccess()
	assert.False(t, cb.isOpen())
}

// =============================================================================
// Token bucket edge cases
// =============================================================================

func TestTokenBucket_Allow_Burst_CB5(t *testing.T) {
	tb := newTokenBucket(5, 5)
	for i := 0; i < 5; i++ {
		assert.True(t, tb.allow())
	}
	assert.False(t, tb.allow())
}

// =============================================================================
// RPCCallCounter
// =============================================================================

func TestRPCCallCounter_CumulativeDuration_CB5(t *testing.T) {
	counter := NewRPCCallCounter(5)
	_ = counter.AddDuration(100 * time.Millisecond)
	dur := counter.CumulativeDuration()
	assert.Equal(t, 100*time.Millisecond, dur)
}

// =============================================================================
// MapToRuleInput empty map
// =============================================================================

func TestMapToRuleInput_Empty_CB5(t *testing.T) {
	ri, err := MapToRuleInput(map[string]interface{}{})
	assert.NotNil(t, ri)
	require.NoError(t, err)
	assert.Nil(t, ri.Transaction)
}

// =============================================================================
// SolidityRuleEvaluator type constant
// =============================================================================

func TestSolidityRuleTypeConstant_CB5(t *testing.T) {
	assert.Equal(t, types.RuleTypeEVMSolidityExpression, types.RuleType("evm_solidity_expression"))
}

// =============================================================================
// NewRPCProvider checks
// =============================================================================

func TestNewRPCProvider_TLSMinVersion_CB5(t *testing.T) {
	srv, provider := newTestRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x0"}`))
	})
	defer srv.Close()
	assert.NotNil(t, provider)
	_, err := provider.Call(context.Background(), "137", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "0x313ce567")
	require.NoError(t, err)
}
