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

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock HDWalletManager ---

type mockHDWalletManager struct {
	createWalletFn      func(ctx context.Context, params types.CreateHDWalletParams) (*evmchain.HDWalletInfo, error)
	importWalletFn      func(ctx context.Context, params types.ImportHDWalletParams) (*evmchain.HDWalletInfo, error)
	deriveAddressFn     func(ctx context.Context, primaryAddr string, index uint32) (*types.SignerInfo, error)
	deriveAddressesFn   func(ctx context.Context, primaryAddr string, start, count uint32) ([]types.SignerInfo, error)
	listHDWalletsFn     func() []evmchain.HDWalletInfo
	listDerivedAddrsFn  func(primaryAddr string) ([]types.SignerInfo, error)
}

func (m *mockHDWalletManager) CreateHDWallet(ctx context.Context, params types.CreateHDWalletParams) (*evmchain.HDWalletInfo, error) {
	if m.createWalletFn != nil {
		return m.createWalletFn(ctx, params)
	}
	return &evmchain.HDWalletInfo{
		PrimaryAddress: "0x1234567890abcdef1234567890abcdef12345678",
		BasePath:       "m/44'/60'/0'/0",
		DerivedCount:   1,
		Derived: []types.SignerInfo{
			{Address: "0x1234567890abcdef1234567890abcdef12345678", Type: "hd_wallet", Enabled: true},
		},
	}, nil
}

func (m *mockHDWalletManager) ImportHDWallet(ctx context.Context, params types.ImportHDWalletParams) (*evmchain.HDWalletInfo, error) {
	if m.importWalletFn != nil {
		return m.importWalletFn(ctx, params)
	}
	return &evmchain.HDWalletInfo{
		PrimaryAddress: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
		BasePath:       "m/44'/60'/0'/0",
		DerivedCount:   1,
		Derived: []types.SignerInfo{
			{Address: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd", Type: "hd_wallet", Enabled: true},
		},
	}, nil
}

func (m *mockHDWalletManager) DeriveAddress(ctx context.Context, primaryAddr string, index uint32) (*types.SignerInfo, error) {
	if m.deriveAddressFn != nil {
		return m.deriveAddressFn(ctx, primaryAddr, index)
	}
	return &types.SignerInfo{
		Address: fmt.Sprintf("0x%040x", index+1),
		Type:    "hd_wallet",
		Enabled: true,
	}, nil
}

func (m *mockHDWalletManager) DeriveAddresses(ctx context.Context, primaryAddr string, start, count uint32) ([]types.SignerInfo, error) {
	if m.deriveAddressesFn != nil {
		return m.deriveAddressesFn(ctx, primaryAddr, start, count)
	}
	result := make([]types.SignerInfo, count)
	for i := uint32(0); i < count; i++ {
		result[i] = types.SignerInfo{
			Address: fmt.Sprintf("0x%040x", start+i+1),
			Type:    "hd_wallet",
			Enabled: true,
		}
	}
	return result, nil
}

func (m *mockHDWalletManager) ListHDWallets() []evmchain.HDWalletInfo {
	if m.listHDWalletsFn != nil {
		return m.listHDWalletsFn()
	}
	return []evmchain.HDWalletInfo{
		{
			PrimaryAddress: "0x1111111111111111111111111111111111111111",
			BasePath:       "m/44'/60'/0'/0",
			DerivedCount:   2,
		},
	}
}

func (m *mockHDWalletManager) ListDerivedAddresses(primaryAddr string) ([]types.SignerInfo, error) {
	if m.listDerivedAddrsFn != nil {
		return m.listDerivedAddrsFn(primaryAddr)
	}
	return []types.SignerInfo{
		{Address: "0x2222222222222222222222222222222222222222", Type: "hd_wallet", Enabled: true},
		{Address: "0x3333333333333333333333333333333333333333", Type: "hd_wallet", Enabled: true},
	}, nil
}

func (m *mockHDWalletManager) ListPrimaryAddresses() []string {
	wallets := m.ListHDWallets()
	out := make([]string, 0, len(wallets))
	for _, w := range wallets {
		if w.PrimaryAddress != "" {
			out = append(out, w.PrimaryAddress)
		}
	}
	return out
}

// --- Mock SignerManager ---

type mockSignerManager struct {
	hdWalletMgr    *mockHDWalletManager
	hdWalletMgrErr error
}

func (m *mockSignerManager) CreateSigner(_ context.Context, _ types.CreateSignerRequest) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockSignerManager) ListSigners(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
	return types.SignerListResult{}, fmt.Errorf("not implemented in mock")
}

func (m *mockSignerManager) HDWalletManager() (evmchain.HDWalletManager, error) {
	if m.hdWalletMgrErr != nil {
		return nil, m.hdWalletMgrErr
	}
	return m.hdWalletMgr, nil
}

func (m *mockSignerManager) DiscoverLockedSigners(_ context.Context) error {
	return nil
}

func (m *mockSignerManager) UnlockSigner(_ context.Context, _ string, _ string) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockSignerManager) LockSigner(_ context.Context, _ string) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

// --- Test helpers ---

func newTestHDWalletHandler(t *testing.T, sm evmchain.SignerManager) *HDWalletHandler {
	t.Helper()
	logger := slog.Default()
	h, err := NewHDWalletHandler(sm, logger, false)
	require.NoError(t, err)
	return h
}

func newDefaultMockSignerManager() *mockSignerManager {
	return &mockSignerManager{
		hdWalletMgr: &mockHDWalletManager{},
	}
}

// adminAPIKey returns a test admin API key for injection into request context.
func adminAPIKey() *types.APIKey {
	return &types.APIKey{
		ID:    "test-admin",
		Name:  "Test Admin",
		Admin: true,
	}
}

func doRequest(handler http.Handler, method, path string, body interface{}) *httptest.ResponseRecorder {
	return doRequestWithAPIKey(handler, method, path, body, adminAPIKey())
}

func doRequestWithAPIKey(handler http.Handler, method, path string, body interface{}, apiKey *types.APIKey) *httptest.ResponseRecorder {
	var reqBody *bytes.Buffer
	if body != nil {
		data, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(data)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != nil {
		ctx := context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey)
		req = req.WithContext(ctx)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	err := json.NewDecoder(rec.Body).Decode(v)
	require.NoError(t, err, "failed to decode response body: %s", rec.Body.String())
}

// --- Constructor tests ---

func TestNewHDWalletHandler_NilSignerManager(t *testing.T) {
	_, err := NewHDWalletHandler(nil, slog.Default(), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signer manager is required")
}

func TestNewHDWalletHandler_NilLogger(t *testing.T) {
	sm := newDefaultMockSignerManager()
	_, err := NewHDWalletHandler(sm, nil, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

// --- CreateWallet tests ---

func TestHDWalletHandler_CreateWallet(t *testing.T) {
	sm := newDefaultMockSignerManager()
	h := newTestHDWalletHandler(t, sm)

	body := map[string]interface{}{
		"action":   "create",
		"password": "test-password-123",
	}
	rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets", body)

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var resp hdWalletResponse
	decodeJSON(t, rec, &resp)
	assert.Equal(t, "0x1234567890abcdef1234567890abcdef12345678", resp.PrimaryAddress)
	assert.Equal(t, "m/44'/60'/0'/0", resp.BasePath)
	assert.Equal(t, 1, resp.DerivedCount)
	require.Len(t, resp.Derived, 1)
	assert.Equal(t, "0x1234567890abcdef1234567890abcdef12345678", resp.Derived[0].Address)
	assert.Equal(t, "hd_wallet", resp.Derived[0].Type)
	assert.True(t, resp.Derived[0].Enabled)
}

func TestHDWalletHandler_CreateWallet_DefaultAction(t *testing.T) {
	sm := newDefaultMockSignerManager()
	h := newTestHDWalletHandler(t, sm)

	// Empty action defaults to "create"
	body := map[string]interface{}{
		"password": "test-password-123",
	}
	rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets", body)

	assert.Equal(t, http.StatusCreated, rec.Code)

	var resp hdWalletResponse
	decodeJSON(t, rec, &resp)
	assert.NotEmpty(t, resp.PrimaryAddress)
}

func TestHDWalletHandler_CreateWallet_WithEntropyBits(t *testing.T) {
	var capturedParams types.CreateHDWalletParams
	sm := newDefaultMockSignerManager()
	sm.hdWalletMgr.createWalletFn = func(_ context.Context, params types.CreateHDWalletParams) (*evmchain.HDWalletInfo, error) {
		// Copy strings defensively: secure.ZeroString will zero the backing array after handler returns.
		params.Password = string([]byte(params.Password))
		capturedParams = params
		return &evmchain.HDWalletInfo{
			PrimaryAddress: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			BasePath:       "m/44'/60'/0'/0",
			DerivedCount:   1,
		}, nil
	}
	h := newTestHDWalletHandler(t, sm)

	body := map[string]interface{}{
		"action":       "create",
		"password":     "test-password-123",
		"entropy_bits": 128,
	}
	rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets", body)

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "test-password-123", capturedParams.Password)
	assert.Equal(t, 128, capturedParams.EntropyBits)
}

func TestHDWalletHandler_CreateWallet_AlreadyExists(t *testing.T) {
	sm := newDefaultMockSignerManager()
	sm.hdWalletMgr.createWalletFn = func(_ context.Context, _ types.CreateHDWalletParams) (*evmchain.HDWalletInfo, error) {
		return nil, fmt.Errorf("wallet already exists")
	}
	h := newTestHDWalletHandler(t, sm)

	body := map[string]interface{}{
		"action":   "create",
		"password": "test-password-123",
	}
	rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets", body)

	assert.Equal(t, http.StatusConflict, rec.Code)

	var errResp map[string]string
	decodeJSON(t, rec, &errResp)
	assert.Contains(t, errResp["error"], "already exists")
}

func TestHDWalletHandler_CreateWallet_InternalError(t *testing.T) {
	sm := newDefaultMockSignerManager()
	sm.hdWalletMgr.createWalletFn = func(_ context.Context, _ types.CreateHDWalletParams) (*evmchain.HDWalletInfo, error) {
		return nil, fmt.Errorf("something went wrong")
	}
	h := newTestHDWalletHandler(t, sm)

	body := map[string]interface{}{
		"action":   "create",
		"password": "test-password-123",
	}
	rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets", body)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// --- ImportWallet tests ---

func TestHDWalletHandler_ImportWallet(t *testing.T) {
	var capturedParams types.ImportHDWalletParams
	sm := newDefaultMockSignerManager()
	sm.hdWalletMgr.importWalletFn = func(_ context.Context, params types.ImportHDWalletParams) (*evmchain.HDWalletInfo, error) {
		// Copy strings defensively: secure.ZeroString will zero the backing array after handler returns.
		params.Password = string([]byte(params.Password))
		params.Mnemonic = string([]byte(params.Mnemonic))
		capturedParams = params
		return &evmchain.HDWalletInfo{
			PrimaryAddress: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
			BasePath:       "m/44'/60'/0'/0",
			DerivedCount:   1,
			Derived: []types.SignerInfo{
				{Address: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd", Type: "hd_wallet", Enabled: true},
			},
		}, nil
	}
	h := newTestHDWalletHandler(t, sm)

	body := map[string]interface{}{
		"action":   "import",
		"password": "import-pw",
		"mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
	}
	rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets", body)

	assert.Equal(t, http.StatusCreated, rec.Code)

	var resp hdWalletResponse
	decodeJSON(t, rec, &resp)
	assert.Equal(t, "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd", resp.PrimaryAddress)
	assert.Equal(t, "m/44'/60'/0'/0", resp.BasePath)
	assert.Equal(t, 1, resp.DerivedCount)
	require.Len(t, resp.Derived, 1)

	assert.Equal(t, "import-pw", capturedParams.Password)
	assert.Equal(t, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", capturedParams.Mnemonic)
}

func TestHDWalletHandler_ImportWallet_AlreadyExists(t *testing.T) {
	sm := newDefaultMockSignerManager()
	sm.hdWalletMgr.importWalletFn = func(_ context.Context, _ types.ImportHDWalletParams) (*evmchain.HDWalletInfo, error) {
		return nil, fmt.Errorf("wallet already exists")
	}
	h := newTestHDWalletHandler(t, sm)

	body := map[string]interface{}{
		"action":   "import",
		"password": "pw",
		"mnemonic": "test mnemonic words here abandon abandon abandon abandon abandon abandon abandon about",
	}
	rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets", body)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

// --- ListWallets tests ---

func TestHDWalletHandler_ListWallets(t *testing.T) {
	sm := newDefaultMockSignerManager()
	sm.hdWalletMgr.listHDWalletsFn = func() []evmchain.HDWalletInfo {
		return []evmchain.HDWalletInfo{
			{
				PrimaryAddress: "0x1111111111111111111111111111111111111111",
				BasePath:       "m/44'/60'/0'/0",
				DerivedCount:   3,
			},
			{
				PrimaryAddress: "0x2222222222222222222222222222222222222222",
				BasePath:       "m/44'/60'/0'/0",
				DerivedCount:   1,
			},
		}
	}
	h := newTestHDWalletHandler(t, sm)

	rec := doRequest(h, http.MethodGet, "/api/v1/evm/hd-wallets", nil)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var resp listHDWalletsResponse
	decodeJSON(t, rec, &resp)
	require.Len(t, resp.Wallets, 2)
	assert.Equal(t, "0x1111111111111111111111111111111111111111", resp.Wallets[0].PrimaryAddress)
	assert.Equal(t, 3, resp.Wallets[0].DerivedCount)
	assert.Equal(t, "0x2222222222222222222222222222222222222222", resp.Wallets[1].PrimaryAddress)
	assert.Equal(t, 1, resp.Wallets[1].DerivedCount)
}

func TestHDWalletHandler_ListWallets_Empty(t *testing.T) {
	sm := newDefaultMockSignerManager()
	sm.hdWalletMgr.listHDWalletsFn = func() []evmchain.HDWalletInfo {
		return []evmchain.HDWalletInfo{}
	}
	h := newTestHDWalletHandler(t, sm)

	rec := doRequest(h, http.MethodGet, "/api/v1/evm/hd-wallets", nil)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp listHDWalletsResponse
	decodeJSON(t, rec, &resp)
	assert.Len(t, resp.Wallets, 0)
}

// --- DeriveAddress tests ---

func TestHDWalletHandler_DeriveAddress(t *testing.T) {
	sm := newDefaultMockSignerManager()
	h := newTestHDWalletHandler(t, sm)

	index := uint32(5)
	body := deriveRequest{Index: &index}
	rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp deriveResponse
	decodeJSON(t, rec, &resp)
	require.Len(t, resp.Derived, 1)
	assert.Equal(t, "hd_wallet", resp.Derived[0].Type)
	assert.True(t, resp.Derived[0].Enabled)
}

func TestHDWalletHandler_DeriveAddress_CapturedParams(t *testing.T) {
	var capturedAddr string
	var capturedIndex uint32
	sm := newDefaultMockSignerManager()
	sm.hdWalletMgr.deriveAddressFn = func(_ context.Context, primaryAddr string, index uint32) (*types.SignerInfo, error) {
		capturedAddr = primaryAddr
		capturedIndex = index
		return &types.SignerInfo{
			Address: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			Type:    "hd_wallet",
			Enabled: true,
		}, nil
	}
	h := newTestHDWalletHandler(t, sm)

	index := uint32(42)
	body := deriveRequest{Index: &index}
	rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "0x1111111111111111111111111111111111111111", capturedAddr)
	assert.Equal(t, uint32(42), capturedIndex)

	var resp deriveResponse
	decodeJSON(t, rec, &resp)
	require.Len(t, resp.Derived, 1)
	assert.Equal(t, "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", resp.Derived[0].Address)
}

func TestHDWalletHandler_DeriveAddress_Error(t *testing.T) {
	sm := newDefaultMockSignerManager()
	sm.hdWalletMgr.deriveAddressFn = func(_ context.Context, _ string, _ uint32) (*types.SignerInfo, error) {
		return nil, fmt.Errorf("derivation failed")
	}
	h := newTestHDWalletHandler(t, sm)

	index := uint32(0)
	body := deriveRequest{Index: &index}
	rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	var errResp map[string]string
	decodeJSON(t, rec, &errResp)
	assert.Contains(t, errResp["error"], "derivation failed")
}

// --- DeriveBatch tests ---

func TestHDWalletHandler_DeriveBatch(t *testing.T) {
	sm := newDefaultMockSignerManager()
	h := newTestHDWalletHandler(t, sm)

	start := uint32(0)
	count := uint32(3)
	body := deriveRequest{Start: &start, Count: &count}
	rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp deriveResponse
	decodeJSON(t, rec, &resp)
	require.Len(t, resp.Derived, 3)
	for _, d := range resp.Derived {
		assert.Equal(t, "hd_wallet", d.Type)
		assert.True(t, d.Enabled)
	}
}

func TestHDWalletHandler_DeriveBatch_CapturedParams(t *testing.T) {
	var capturedAddr string
	var capturedStart, capturedCount uint32
	sm := newDefaultMockSignerManager()
	sm.hdWalletMgr.deriveAddressesFn = func(_ context.Context, primaryAddr string, start, count uint32) ([]types.SignerInfo, error) {
		capturedAddr = primaryAddr
		capturedStart = start
		capturedCount = count
		return []types.SignerInfo{
			{Address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Type: "hd_wallet", Enabled: true},
			{Address: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Type: "hd_wallet", Enabled: true},
		}, nil
	}
	h := newTestHDWalletHandler(t, sm)

	start := uint32(10)
	count := uint32(2)
	body := deriveRequest{Start: &start, Count: &count}
	rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets/0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD/derive", body)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD", capturedAddr)
	assert.Equal(t, uint32(10), capturedStart)
	assert.Equal(t, uint32(2), capturedCount)
}

func TestHDWalletHandler_DeriveBatch_Error(t *testing.T) {
	sm := newDefaultMockSignerManager()
	sm.hdWalletMgr.deriveAddressesFn = func(_ context.Context, _ string, _, _ uint32) ([]types.SignerInfo, error) {
		return nil, fmt.Errorf("batch derivation failed")
	}
	h := newTestHDWalletHandler(t, sm)

	start := uint32(0)
	count := uint32(5)
	body := deriveRequest{Start: &start, Count: &count}
	rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// --- ListDerived tests ---

func TestHDWalletHandler_ListDerived(t *testing.T) {
	sm := newDefaultMockSignerManager()
	sm.hdWalletMgr.listDerivedAddrsFn = func(primaryAddr string) ([]types.SignerInfo, error) {
		assert.Equal(t, "0x1111111111111111111111111111111111111111", primaryAddr)
		return []types.SignerInfo{
			{Address: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Type: "hd_wallet", Enabled: true},
			{Address: "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", Type: "hd_wallet", Enabled: false},
		}, nil
	}
	h := newTestHDWalletHandler(t, sm)

	rec := doRequest(h, http.MethodGet, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derived", nil)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp listDerivedResponse
	decodeJSON(t, rec, &resp)
	require.Len(t, resp.Derived, 2)
	assert.Equal(t, "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", resp.Derived[0].Address)
	assert.True(t, resp.Derived[0].Enabled)
	assert.Equal(t, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", resp.Derived[1].Address)
	assert.False(t, resp.Derived[1].Enabled)
}

func TestHDWalletHandler_ListDerived_Error(t *testing.T) {
	sm := newDefaultMockSignerManager()
	sm.hdWalletMgr.listDerivedAddrsFn = func(_ string) ([]types.SignerInfo, error) {
		return nil, fmt.Errorf("wallet not found")
	}
	h := newTestHDWalletHandler(t, sm)

	rec := doRequest(h, http.MethodGet, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derived", nil)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	var errResp map[string]string
	decodeJSON(t, rec, &errResp)
	assert.Contains(t, errResp["error"], "wallet not found")
}

// --- Validation error tests ---

func TestHDWalletHandler_ValidationErrors(t *testing.T) {
	t.Run("missing password on create", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		h := newTestHDWalletHandler(t, sm)

		body := map[string]interface{}{
			"action": "create",
		}
		rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets", body)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "password is required")
	})

	t.Run("missing password on import", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		h := newTestHDWalletHandler(t, sm)

		body := map[string]interface{}{
			"action":   "import",
			"mnemonic": "test mnemonic",
		}
		rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets", body)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "password is required")
	})

	t.Run("missing mnemonic on import", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		h := newTestHDWalletHandler(t, sm)

		body := map[string]interface{}{
			"action":   "import",
			"password": "test-password",
		}
		rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets", body)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "mnemonic is required for import")
	})

	t.Run("invalid action", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		h := newTestHDWalletHandler(t, sm)

		body := map[string]interface{}{
			"action":   "delete",
			"password": "test-password",
		}
		rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets", body)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "action must be 'create' or 'import'")
	})

	t.Run("invalid JSON body", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		h := newTestHDWalletHandler(t, sm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/hd-wallets", bytes.NewBufferString("{invalid json"))
		req.Header.Set("Content-Type", "application/json")
		ctx := context.WithValue(req.Context(), middleware.APIKeyContextKey, adminAPIKey())
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "invalid request body")
	})

	t.Run("invalid address in path", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		h := newTestHDWalletHandler(t, sm)

		rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets/not-an-address/derive", map[string]interface{}{"index": 0})

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "invalid path or address")
	})

	t.Run("address too short", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		h := newTestHDWalletHandler(t, sm)

		rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets/0x1234/derive", map[string]interface{}{"index": 0})

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("unknown action path", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		h := newTestHDWalletHandler(t, sm)

		rec := doRequest(h, http.MethodGet, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/unknown", nil)

		assert.Equal(t, http.StatusNotFound, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "unknown action")
	})

	t.Run("derive missing index and start+count", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		h := newTestHDWalletHandler(t, sm)

		body := map[string]interface{}{}
		rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "either 'index' or 'start'+'count' is required")
	})

	t.Run("derive count zero", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		h := newTestHDWalletHandler(t, sm)

		start := uint32(0)
		count := uint32(0)
		body := deriveRequest{Start: &start, Count: &count}
		rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "count must be between 1 and 100")
	})

	t.Run("derive count exceeds 100", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		h := newTestHDWalletHandler(t, sm)

		start := uint32(0)
		count := uint32(101)
		body := deriveRequest{Start: &start, Count: &count}
		rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var errResp map[string]string
		decodeJSON(t, rec, &errResp)
		assert.Contains(t, errResp["error"], "count must be between 1 and 100")
	})

	t.Run("derive with invalid JSON body", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		h := newTestHDWalletHandler(t, sm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", bytes.NewBufferString("{bad"))
		req.Header.Set("Content-Type", "application/json")
		ctx := context.WithValue(req.Context(), middleware.APIKeyContextKey, adminAPIKey())
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

// --- Method not allowed tests ---

func TestHDWalletHandler_MethodNotAllowed(t *testing.T) {
	t.Run("PUT on root", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		h := newTestHDWalletHandler(t, sm)

		rec := doRequest(h, http.MethodPut, "/api/v1/evm/hd-wallets", nil)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("DELETE on root", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		h := newTestHDWalletHandler(t, sm)

		rec := doRequest(h, http.MethodDelete, "/api/v1/evm/hd-wallets", nil)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("GET on derive", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		h := newTestHDWalletHandler(t, sm)

		rec := doRequest(h, http.MethodGet, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", nil)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("POST on derived", func(t *testing.T) {
		sm := newDefaultMockSignerManager()
		h := newTestHDWalletHandler(t, sm)

		rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derived", nil)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})
}

// --- HDWalletManager not configured tests ---

func TestHDWalletHandler_HDWalletNotConfigured(t *testing.T) {
	t.Run("create when not configured", func(t *testing.T) {
		sm := &mockSignerManager{
			hdWalletMgrErr: types.ErrHDWalletNotConfigured,
		}
		h := newTestHDWalletHandler(t, sm)

		body := map[string]interface{}{
			"action":   "create",
			"password": "test",
		}
		rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets", body)

		assert.Equal(t, http.StatusNotImplemented, rec.Code)
	})

	t.Run("list when not configured", func(t *testing.T) {
		sm := &mockSignerManager{
			hdWalletMgrErr: types.ErrHDWalletNotConfigured,
		}
		h := newTestHDWalletHandler(t, sm)

		rec := doRequest(h, http.MethodGet, "/api/v1/evm/hd-wallets", nil)

		assert.Equal(t, http.StatusNotImplemented, rec.Code)
	})

	t.Run("derive when not configured", func(t *testing.T) {
		sm := &mockSignerManager{
			hdWalletMgrErr: types.ErrHDWalletNotConfigured,
		}
		h := newTestHDWalletHandler(t, sm)

		index := uint32(0)
		body := deriveRequest{Index: &index}
		rec := doRequest(h, http.MethodPost, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derive", body)

		assert.Equal(t, http.StatusNotImplemented, rec.Code)
	})

	t.Run("list derived when not configured", func(t *testing.T) {
		sm := &mockSignerManager{
			hdWalletMgrErr: types.ErrHDWalletNotConfigured,
		}
		h := newTestHDWalletHandler(t, sm)

		rec := doRequest(h, http.MethodGet, "/api/v1/evm/hd-wallets/0x1111111111111111111111111111111111111111/derived", nil)

		assert.Equal(t, http.StatusNotImplemented, rec.Code)
	})
}

// --- Trailing slash normalization ---

func TestHDWalletHandler_TrailingSlash(t *testing.T) {
	sm := newDefaultMockSignerManager()
	h := newTestHDWalletHandler(t, sm)

	rec := doRequest(h, http.MethodGet, "/api/v1/evm/hd-wallets/", nil)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp listHDWalletsResponse
	decodeJSON(t, rec, &resp)
	assert.NotNil(t, resp.Wallets)
}
