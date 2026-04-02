package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// --- Mock SignerManager for signer tests ---

type signerMockSignerManager struct {
	listSignersFn    func(ctx context.Context, filter types.SignerFilter) (types.SignerListResult, error)
	createSignerFn   func(ctx context.Context, req types.CreateSignerRequest) (*types.SignerInfo, error)
	getHDHierarchyFn func() map[string]evmchain.HDHierarchyInfo
}

func (m *signerMockSignerManager) CreateSigner(ctx context.Context, req types.CreateSignerRequest) (*types.SignerInfo, error) {
	if m.createSignerFn != nil {
		return m.createSignerFn(ctx, req)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *signerMockSignerManager) ListSigners(ctx context.Context, filter types.SignerFilter) (types.SignerListResult, error) {
	if m.listSignersFn != nil {
		return m.listSignersFn(ctx, filter)
	}
	return types.SignerListResult{}, fmt.Errorf("not implemented")
}

func (m *signerMockSignerManager) HDWalletManager() (evmchain.HDWalletManager, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *signerMockSignerManager) DiscoverLockedSigners(ctx context.Context) error {
	return nil
}

func (m *signerMockSignerManager) UnlockSigner(ctx context.Context, address string, password string) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *signerMockSignerManager) LockSigner(ctx context.Context, address string) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *signerMockSignerManager) DeleteSigner(ctx context.Context, address string) error {
	return fmt.Errorf("not implemented")
}

func (m *signerMockSignerManager) GetHDHierarchy() map[string]evmchain.HDHierarchyInfo {
	if m.getHDHierarchyFn != nil {
		return m.getHDHierarchyFn()
	}
	return nil
}

// --- Stub repos for access service ---

type signerStubOwnershipRepo struct {
	ownerships []*types.SignerOwnership
}

func (s *signerStubOwnershipRepo) Upsert(_ context.Context, _ *types.SignerOwnership) error {
	return nil
}
func (s *signerStubOwnershipRepo) Get(_ context.Context, _ string) (*types.SignerOwnership, error) {
	return nil, types.ErrNotFound
}
func (s *signerStubOwnershipRepo) GetByOwner(_ context.Context, ownerID string) ([]*types.SignerOwnership, error) {
	var result []*types.SignerOwnership
	for _, o := range s.ownerships {
		if o.OwnerID == ownerID {
			result = append(result, o)
		}
	}
	return result, nil
}
func (s *signerStubOwnershipRepo) Delete(_ context.Context, _ string) error                { return nil }
func (s *signerStubOwnershipRepo) UpdateOwner(_ context.Context, _, _ string) error         { return nil }
func (s *signerStubOwnershipRepo) CountByOwner(_ context.Context, _ string) (int64, error)  { return 0, nil }
func (s *signerStubOwnershipRepo) CountByOwnerAndType(_ context.Context, _ string, _ types.SignerType) (int64, error) {
	return 0, nil
}
func (s *signerStubOwnershipRepo) GetBoth(_ context.Context, senderAddress, recipientAddress string) (*types.SignerOwnership, *types.SignerOwnership, error) {
	// Simple stub: return nil for both (signer ownership not used in these tests)
	return nil, nil, nil
}

type signerStubAccessRepo struct{}

func (s *signerStubAccessRepo) Grant(_ context.Context, _ *types.SignerAccess) error { return nil }
func (s *signerStubAccessRepo) Revoke(_ context.Context, _, _ string) error          { return nil }
func (s *signerStubAccessRepo) List(_ context.Context, _ string) ([]*types.SignerAccess, error) {
	return nil, nil
}
func (s *signerStubAccessRepo) HasAccess(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}
func (s *signerStubAccessRepo) HasAccessViaWallet(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}
func (s *signerStubAccessRepo) DeleteBySigner(_ context.Context, _ string) error { return nil }
func (s *signerStubAccessRepo) DeleteByAPIKey(_ context.Context, _ string) error { return nil }
func (s *signerStubAccessRepo) ListAccessibleAddresses(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

type signerStubAPIKeyRepo struct {
	listFn func(ctx context.Context, filter storage.APIKeyFilter) ([]*types.APIKey, error)
}

func (s *signerStubAPIKeyRepo) Create(_ context.Context, _ *types.APIKey) error { return nil }
func (s *signerStubAPIKeyRepo) Get(_ context.Context, _ string) (*types.APIKey, error) {
	return nil, types.ErrNotFound
}
func (s *signerStubAPIKeyRepo) Update(_ context.Context, _ *types.APIKey) error { return nil }
func (s *signerStubAPIKeyRepo) Delete(_ context.Context, _ string) error        { return nil }
func (s *signerStubAPIKeyRepo) List(ctx context.Context, filter storage.APIKeyFilter) ([]*types.APIKey, error) {
	if s.listFn != nil {
		return s.listFn(ctx, filter)
	}
	return nil, nil
}
func (s *signerStubAPIKeyRepo) UpdateLastUsed(_ context.Context, _ string) error { return nil }
func (s *signerStubAPIKeyRepo) Count(_ context.Context, _ storage.APIKeyFilter) (int, error) {
	return 0, nil
}
func (s *signerStubAPIKeyRepo) DeleteBySourceExcluding(_ context.Context, _ string, _ []string) (int64, error) {
	return 0, nil
}
func (s *signerStubAPIKeyRepo) BackfillSource(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

func newSignerTestAccessService(t *testing.T) *service.SignerAccessService {
	t.Helper()
	svc, err := service.NewSignerAccessService(
		&signerStubOwnershipRepo{},
		&signerStubAccessRepo{},
		&signerStubAPIKeyRepo{},
		nil,
		slog.Default(),
	)
	require.NoError(t, err)
	return svc
}

func newSignerTestAccessServiceWithOwnerships(t *testing.T, ownerships []*types.SignerOwnership) *service.SignerAccessService {
	t.Helper()
	svc, err := service.NewSignerAccessService(
		&signerStubOwnershipRepo{ownerships: ownerships},
		&signerStubAccessRepo{},
		&signerStubAPIKeyRepo{},
		nil,
		slog.Default(),
	)
	require.NoError(t, err)
	return svc
}

// --- Test helpers ---

func doSignerRequest(t *testing.T, handler http.Handler, method, path string, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeSignerListResponse(t *testing.T, rec *httptest.ResponseRecorder) ListSignersResponse {
	t.Helper()
	var resp ListSignersResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err, "failed to decode response: %s", rec.Body.String())
	return resp
}

var allSigners = []types.SignerInfo{
	{Address: "0x1111111111111111111111111111111111111111", Type: "keystore", Enabled: true},
	{Address: "0x2222222222222222222222222222222222222222", Type: "private_key", Enabled: true},
	{Address: "0x3333333333333333333333333333333333333333", Type: "hd_wallet", Enabled: true},
}

func newSignerManagerWithAll() *signerMockSignerManager {
	return &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{
				Signers: allSigners,
				Total:   3,
				HasMore: false,
			}, nil
		},
	}
}

// --- Constructor tests ---

func TestNewSignerHandler(t *testing.T) {
	t.Run("nil signer manager returns error", func(t *testing.T) {
		accessSvc := newSignerTestAccessService(t)
		_, err := NewSignerHandler(nil, accessSvc, slog.Default(), false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signer manager is required")
	})

	t.Run("nil access service returns error", func(t *testing.T) {
		_, err := NewSignerHandler(&signerMockSignerManager{}, nil, slog.Default(), false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access service is required")
	})

	t.Run("nil logger returns error", func(t *testing.T) {
		accessSvc := newSignerTestAccessService(t)
		_, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, nil, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})

	t.Run("all deps provided", func(t *testing.T) {
		accessSvc := newSignerTestAccessService(t)
		h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
		require.NoError(t, err)
		require.NotNil(t, h)
	})
}

// --- Non-admin filtering tests ---

func TestListSigners_NonAdmin_SeesOwned(t *testing.T) {
	sm := newSignerManagerWithAll()

	// Register ownership of all signers for the dev key
	ownerships := []*types.SignerOwnership{
		{SignerAddress: "0x1111111111111111111111111111111111111111", OwnerID: "non-admin-all"},
		{SignerAddress: "0x2222222222222222222222222222222222222222", OwnerID: "non-admin-all"},
		{SignerAddress: "0x3333333333333333333333333333333333333333", OwnerID: "non-admin-all"},
	}
	accessSvc := newSignerTestAccessServiceWithOwnerships(t, ownerships)

	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	apiKey := &types.APIKey{
		ID:      "non-admin-all",
		Name:    "full-access-key",
		Role:    types.RoleDev,
		Enabled: true,
	}

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers", apiKey)
	assert.Equal(t, http.StatusOK, rec.Code)

	resp := decodeSignerListResponse(t, rec)
	assert.Equal(t, 3, resp.Total)
	assert.Len(t, resp.Signers, 3)
}

// --- Admin listing tests ---

func TestListSigners_Admin_SeesOwned(t *testing.T) {
	sm := newSignerManagerWithAll()

	// Register ownership of all signers for the admin key
	ownerships := []*types.SignerOwnership{
		{SignerAddress: "0x1111111111111111111111111111111111111111", OwnerID: "admin-key"},
		{SignerAddress: "0x2222222222222222222222222222222222222222", OwnerID: "admin-key"},
		{SignerAddress: "0x3333333333333333333333333333333333333333", OwnerID: "admin-key"},
	}
	accessSvc := newSignerTestAccessServiceWithOwnerships(t, ownerships)

	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	adminAPIKey := &types.APIKey{
		ID:   "admin-key",
		Name: "admin",
		Role: types.RoleAdmin,
	}

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers", adminAPIKey)
	assert.Equal(t, http.StatusOK, rec.Code)

	resp := decodeSignerListResponse(t, rec)
	assert.Equal(t, 3, resp.Total)
	assert.Len(t, resp.Signers, 3)
}

func TestListSigners_Unauthorized(t *testing.T) {
	sm := newSignerManagerWithAll()
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	// No API key in context
	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers", nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestListSigners_IncludesHDParentInJSON exercises GET /api/v1/evm/signers JSON shape for derived HD addresses
// (same path the CLI uses). Hierarchy keys are EIP-55; signer addresses may be lowercase in storage.
func TestListSigners_IncludesHDParentInJSON(t *testing.T) {
	derivedLower := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	derivedKey := common.HexToAddress(derivedLower).Hex()
	primary := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{
				Signers: []types.SignerInfo{
					{Address: derivedLower, Type: string(types.SignerTypeHDWallet), Enabled: true, Locked: false},
				},
				Total: 1,
			}, nil
		},
		getHDHierarchyFn: func() map[string]evmchain.HDHierarchyInfo {
			return map[string]evmchain.HDHierarchyInfo{
				derivedKey: {ParentAddress: primary, DerivationIndex: 2},
			}
		},
	}

	ownerships := []*types.SignerOwnership{
		{SignerAddress: derivedLower, OwnerID: "admin-key", Status: types.SignerOwnershipActive},
	}
	accessSvc := newSignerTestAccessServiceWithOwnerships(t, ownerships)

	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	adminAPIKey := &types.APIKey{
		ID:   "admin-key",
		Name: "admin",
		Role: types.RoleAdmin,
	}

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers", adminAPIKey)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp ListSignersResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Signers, 1)
	assert.Equal(t, primary, resp.Signers[0].HDParentAddress)
	require.NotNil(t, resp.Signers[0].HDDerivationIndex)
	assert.Equal(t, uint32(2), *resp.Signers[0].HDDerivationIndex)
}

// TestListSigners_GroupByWallet tests group_by_wallet=true returns wallets instead of flat signer list
func TestListSigners_GroupByWallet(t *testing.T) {
	primaryAddr := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	derived1 := "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	derived2 := "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	keystore1 := "0x1111111111111111111111111111111111111111"
	keystore2 := "0x2222222222222222222222222222222222222222"

	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{
				Signers: []types.SignerInfo{
					{Address: primaryAddr, Type: string(types.SignerTypeHDWallet), Enabled: true, Locked: false},
					{Address: derived1, Type: string(types.SignerTypeHDWallet), Enabled: true, Locked: false},
					{Address: derived2, Type: string(types.SignerTypeHDWallet), Enabled: true, Locked: false},
					{Address: keystore1, Type: string(types.SignerTypeKeystore), Enabled: false, Locked: true},
					{Address: keystore2, Type: string(types.SignerTypeKeystore), Enabled: false, Locked: true},
				},
				Total: 5,
			}, nil
		},
		getHDHierarchyFn: func() map[string]evmchain.HDHierarchyInfo {
			return map[string]evmchain.HDHierarchyInfo{
				common.HexToAddress(primaryAddr).Hex(): {ParentAddress: primaryAddr, DerivationIndex: 0},
				common.HexToAddress(derived1).Hex():    {ParentAddress: primaryAddr, DerivationIndex: 1},
				common.HexToAddress(derived2).Hex():    {ParentAddress: primaryAddr, DerivationIndex: 2},
			}
		},
	}

	ownerships := []*types.SignerOwnership{
		{SignerAddress: primaryAddr, OwnerID: "admin-key", Status: types.SignerOwnershipActive},
		{SignerAddress: derived1, OwnerID: "admin-key", Status: types.SignerOwnershipActive},
		{SignerAddress: derived2, OwnerID: "admin-key", Status: types.SignerOwnershipActive},
		{SignerAddress: keystore1, OwnerID: "admin-key", Status: types.SignerOwnershipActive},
		{SignerAddress: keystore2, OwnerID: "admin-key", Status: types.SignerOwnershipActive},
	}
	accessSvc := newSignerTestAccessServiceWithOwnerships(t, ownerships)

	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	adminAPIKey := &types.APIKey{
		ID:   "admin-key",
		Name: "admin",
		Role: types.RoleAdmin,
	}

	// Test with group_by_wallet=true
	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?group_by_wallet=true", adminAPIKey)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp ListWalletsResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	// Should have 3 wallets: 1 HD wallet + 2 keystore wallets
	assert.Equal(t, 3, resp.Total)
	assert.Len(t, resp.Wallets, 3)

	// Find the HD wallet
	var hdWallet *WalletResponse
	for i := range resp.Wallets {
		if resp.Wallets[i].WalletID == primaryAddr {
			hdWallet = &resp.Wallets[i]
			break
		}
	}
	require.NotNil(t, hdWallet, "HD wallet should be in response")
	assert.Equal(t, "hd_wallet", hdWallet.WalletType)
	assert.Equal(t, primaryAddr, hdWallet.PrimaryAddress)
	assert.Equal(t, 3, hdWallet.SignerCount, "HD wallet should have 3 signers (primary + 2 derived)")
	assert.True(t, hdWallet.Enabled)
	assert.False(t, hdWallet.Locked)

	// Check keystore wallets
	keystoreCount := 0
	for i := range resp.Wallets {
		if resp.Wallets[i].WalletType == "keystore" {
			keystoreCount++
			assert.Equal(t, 1, resp.Wallets[i].SignerCount, "keystore wallet should have 1 signer")
			assert.False(t, resp.Wallets[i].Enabled)
			assert.True(t, resp.Wallets[i].Locked)
		}
	}
	assert.Equal(t, 2, keystoreCount, "should have 2 keystore wallets")
}

// TestListWalletSigners tests /api/v1/evm/wallets/{wallet_id}/signers endpoint
func TestListWalletSigners(t *testing.T) {
	primaryAddr := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	derived1 := "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	derived2 := "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	keystore1 := "0x1111111111111111111111111111111111111111"

	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{
				Signers: []types.SignerInfo{
					{Address: primaryAddr, Type: string(types.SignerTypeHDWallet), Enabled: true, Locked: false},
					{Address: derived1, Type: string(types.SignerTypeHDWallet), Enabled: true, Locked: false},
					{Address: derived2, Type: string(types.SignerTypeHDWallet), Enabled: true, Locked: false},
					{Address: keystore1, Type: string(types.SignerTypeKeystore), Enabled: false, Locked: true},
				},
				Total: 4,
			}, nil
		},
		getHDHierarchyFn: func() map[string]evmchain.HDHierarchyInfo {
			return map[string]evmchain.HDHierarchyInfo{
				common.HexToAddress(primaryAddr).Hex(): {ParentAddress: primaryAddr, DerivationIndex: 0},
				common.HexToAddress(derived1).Hex():    {ParentAddress: primaryAddr, DerivationIndex: 1},
				common.HexToAddress(derived2).Hex():    {ParentAddress: primaryAddr, DerivationIndex: 2},
			}
		},
	}

	ownerships := []*types.SignerOwnership{
		{SignerAddress: primaryAddr, OwnerID: "admin-key", Status: types.SignerOwnershipActive},
		{SignerAddress: derived1, OwnerID: "admin-key", Status: types.SignerOwnershipActive},
		{SignerAddress: derived2, OwnerID: "admin-key", Status: types.SignerOwnershipActive},
		{SignerAddress: keystore1, OwnerID: "admin-key", Status: types.SignerOwnershipActive},
	}
	accessSvc := newSignerTestAccessServiceWithOwnerships(t, ownerships)

	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	adminAPIKey := &types.APIKey{
		ID:   "admin-key",
		Name: "admin",
		Role: types.RoleAdmin,
	}

	t.Run("list HD wallet signers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/wallets/"+primaryAddr+"/signers", nil)
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, adminAPIKey))
		rec := httptest.NewRecorder()

		h.HandleWalletSigners(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)

		var resp WalletSignersResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

		assert.Equal(t, primaryAddr, resp.WalletID)
		assert.Equal(t, "hd_wallet", resp.WalletType)
		assert.Equal(t, 3, resp.Total)
		assert.Len(t, resp.Signers, 3)

		// Check ordering by derivation index
		assert.Equal(t, primaryAddr, resp.Signers[0].Address)
		require.NotNil(t, resp.Signers[0].HDDerivationIndex)
		assert.Equal(t, uint32(0), *resp.Signers[0].HDDerivationIndex)

		assert.Equal(t, derived1, resp.Signers[1].Address)
		require.NotNil(t, resp.Signers[1].HDDerivationIndex)
		assert.Equal(t, uint32(1), *resp.Signers[1].HDDerivationIndex)

		assert.Equal(t, derived2, resp.Signers[2].Address)
		require.NotNil(t, resp.Signers[2].HDDerivationIndex)
		assert.Equal(t, uint32(2), *resp.Signers[2].HDDerivationIndex)
	})

	t.Run("list keystore wallet signers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/wallets/"+keystore1+"/signers", nil)
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, adminAPIKey))
		rec := httptest.NewRecorder()

		h.HandleWalletSigners(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)

		var resp WalletSignersResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

		assert.Equal(t, keystore1, resp.WalletID)
		assert.Equal(t, "keystore", resp.WalletType)
		assert.Equal(t, 1, resp.Total)
		assert.Len(t, resp.Signers, 1)
		assert.Equal(t, keystore1, resp.Signers[0].Address)
	})

	t.Run("non-existent wallet returns empty", func(t *testing.T) {
		nonExistent := "0x9999999999999999999999999999999999999999"
		req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/wallets/"+nonExistent+"/signers", nil)
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, adminAPIKey))
		rec := httptest.NewRecorder()

		h.HandleWalletSigners(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)

		var resp WalletSignersResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

		assert.Equal(t, nonExistent, resp.WalletID)
		assert.Equal(t, 0, resp.Total)
		assert.Empty(t, resp.Signers)
	})
}
