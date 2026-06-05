package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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
func (s *signerStubOwnershipRepo) Get(_ context.Context, addr string) (*types.SignerOwnership, error) {
	for _, o := range s.ownerships {
		if strings.EqualFold(o.SignerAddress, addr) {
			return o, nil
		}
	}
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
func (s *signerStubOwnershipRepo) GetByStatus(_ context.Context, status types.SignerOwnershipStatus) ([]*types.SignerOwnership, error) {
	var result []*types.SignerOwnership
	for _, o := range s.ownerships {
		if o.Status == status {
			result = append(result, o)
		}
	}
	return result, nil
}
func (s *signerStubOwnershipRepo) Delete(_ context.Context, _ string) error         { return nil }
func (s *signerStubOwnershipRepo) UpdateOwner(_ context.Context, _, _ string) error { return nil }
func (s *signerStubOwnershipRepo) CountByOwner(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
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
	assert.Equal(t, primary, resp.Signers[0].PrimaryAddress)
	require.NotNil(t, resp.Signers[0].HDDerivationIndex)
	assert.Equal(t, uint32(2), *resp.Signers[0].HDDerivationIndex)
}

// TestListSigners_ExcludeHDDerived verifies exclude_hd_derived omits derivation index > 0 from the flat list.
func TestListSigners_ExcludeHDDerived(t *testing.T) {
	primaryAddr := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	derived1 := "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	derived2 := "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"

	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{
				Signers: []types.SignerInfo{
					{Address: primaryAddr, Type: string(types.SignerTypeHDWallet), Enabled: true, Locked: false},
					{Address: derived1, Type: string(types.SignerTypeHDWallet), Enabled: true, Locked: false},
					{Address: derived2, Type: string(types.SignerTypeHDWallet), Enabled: true, Locked: false},
				},
				Total: 3,
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
	}
	accessSvc := newSignerTestAccessServiceWithOwnerships(t, ownerships)

	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	adminAPIKey := &types.APIKey{
		ID:   "admin-key",
		Name: "admin",
		Role: types.RoleAdmin,
	}

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?exclude_hd_derived=true", adminAPIKey)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp ListSignersResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Signers, 1)
	assert.Equal(t, primaryAddr, resp.Signers[0].Address)

	recAll := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers", adminAPIKey)
	require.Equal(t, http.StatusOK, recAll.Code)

	var respAll ListSignersResponse
	require.NoError(t, json.NewDecoder(recAll.Body).Decode(&respAll))
	require.Len(t, respAll.Signers, 3)
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

// --- ?api_key_id / ?locked / ?enabled filter tests ---

// Fixture with a deliberate mix of locked/unlocked + enabled/disabled
// rows owned by two different keys, so each filter can be exercised in
// isolation and combined without ambiguity in the assertions.
const (
	filterAddrA = "0xAAAA111111111111111111111111111111111111" // owner-1, enabled, unlocked
	filterAddrB = "0xBBBB222222222222222222222222222222222222" // owner-1, enabled, locked
	filterAddrC = "0xCCCC333333333333333333333333333333333333" // owner-1, disabled, unlocked
	filterAddrD = "0xDDDD444444444444444444444444444444444444" // owner-2, enabled, unlocked
	filterAddrE = "0xEEEE555555555555555555555555555555555555" // owner-2, pending_approval
)

func newFilterSignerManager() *signerMockSignerManager {
	return &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{
				Signers: []types.SignerInfo{
					{Address: filterAddrA, Type: string(types.SignerTypeKeystore), Enabled: true, Locked: false},
					{Address: filterAddrB, Type: string(types.SignerTypeKeystore), Enabled: true, Locked: true},
					{Address: filterAddrC, Type: string(types.SignerTypeKeystore), Enabled: false, Locked: false},
					{Address: filterAddrD, Type: string(types.SignerTypeKeystore), Enabled: true, Locked: false},
					{Address: filterAddrE, Type: string(types.SignerTypeKeystore), Enabled: true, Locked: false},
				},
				Total: 5,
			}, nil
		},
	}
}

func filterOwnerships() []*types.SignerOwnership {
	return []*types.SignerOwnership{
		{SignerAddress: filterAddrA, OwnerID: "owner-1", Status: types.SignerOwnershipActive},
		{SignerAddress: filterAddrB, OwnerID: "owner-1", Status: types.SignerOwnershipActive},
		{SignerAddress: filterAddrC, OwnerID: "owner-1", Status: types.SignerOwnershipActive},
		{SignerAddress: filterAddrD, OwnerID: "owner-2", Status: types.SignerOwnershipActive},
		{SignerAddress: filterAddrE, OwnerID: "owner-2", Status: types.SignerOwnershipPendingApproval},
	}
}

func TestListSigners_Filter_Locked(t *testing.T) {
	h, err := NewSignerHandler(newFilterSignerManager(), newSignerTestAccessServiceWithOwnerships(t, filterOwnerships()), slog.Default(), false)
	require.NoError(t, err)
	admin := &types.APIKey{ID: "owner-1", Role: types.RoleAdmin}

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?locked=true", admin)
	require.Equal(t, http.StatusOK, rec.Code)
	resp := decodeSignerListResponse(t, rec)
	assert.Equal(t, 1, resp.Total)
	require.Len(t, resp.Signers, 1)
	assert.Equal(t, filterAddrB, resp.Signers[0].Address)

	rec = doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?locked=false", admin)
	require.Equal(t, http.StatusOK, rec.Code)
	resp = decodeSignerListResponse(t, rec)
	// owner-1 sees A + C (locked=false among their owned set; B is locked, excluded)
	assert.Equal(t, 2, resp.Total)
}

func TestListSigners_Filter_Enabled(t *testing.T) {
	h, err := NewSignerHandler(newFilterSignerManager(), newSignerTestAccessServiceWithOwnerships(t, filterOwnerships()), slog.Default(), false)
	require.NoError(t, err)
	admin := &types.APIKey{ID: "owner-1", Role: types.RoleAdmin}

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?enabled=false", admin)
	require.Equal(t, http.StatusOK, rec.Code)
	resp := decodeSignerListResponse(t, rec)
	assert.Equal(t, 1, resp.Total)
	require.Len(t, resp.Signers, 1)
	assert.Equal(t, filterAddrC, resp.Signers[0].Address)
}

func TestListSigners_Filter_Combined_LockedAndEnabled(t *testing.T) {
	h, err := NewSignerHandler(newFilterSignerManager(), newSignerTestAccessServiceWithOwnerships(t, filterOwnerships()), slog.Default(), false)
	require.NoError(t, err)
	admin := &types.APIKey{ID: "owner-1", Role: types.RoleAdmin}

	// Only A is enabled && unlocked among owner-1's set.
	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?enabled=true&locked=false", admin)
	require.Equal(t, http.StatusOK, rec.Code)
	resp := decodeSignerListResponse(t, rec)
	require.Len(t, resp.Signers, 1)
	assert.Equal(t, filterAddrA, resp.Signers[0].Address)
}

func TestListSigners_Filter_LockedInvalid_400(t *testing.T) {
	h, err := NewSignerHandler(newFilterSignerManager(), newSignerTestAccessServiceWithOwnerships(t, filterOwnerships()), slog.Default(), false)
	require.NoError(t, err)
	admin := &types.APIKey{ID: "owner-1", Role: types.RoleAdmin}

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?locked=maybe", admin)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestListSigners_Filter_APIKeyID_AdminViewsOtherKey(t *testing.T) {
	h, err := NewSignerHandler(newFilterSignerManager(), newSignerTestAccessServiceWithOwnerships(t, filterOwnerships()), slog.Default(), false)
	require.NoError(t, err)
	admin := &types.APIKey{ID: "owner-1", Role: types.RoleAdmin}

	// Admin owner-1 asks "what does owner-2 see?". Should hit owner-2's
	// owned+access set (active + pending signers owned by owner-2).
	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?api_key_id=owner-2", admin)
	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	resp := decodeSignerListResponse(t, rec)
	require.Len(t, resp.Signers, 2)
	assert.Equal(t, 2, resp.Total)
	addrs := []string{resp.Signers[0].Address, resp.Signers[1].Address}
	assert.Contains(t, addrs, filterAddrD)
	assert.Contains(t, addrs, filterAddrE)
}

func TestListSigners_Filter_APIKeyID_NonAdminCrossKey_403(t *testing.T) {
	h, err := NewSignerHandler(newFilterSignerManager(), newSignerTestAccessServiceWithOwnerships(t, filterOwnerships()), slog.Default(), false)
	require.NoError(t, err)
	nonAdmin := &types.APIKey{ID: "owner-1", Role: types.RoleDev}

	// Non-admin owner-1 attempts to peek at owner-2's signers.
	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?api_key_id=owner-2", nonAdmin)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestListSigners_Filter_APIKeyID_NonAdminSelf_200(t *testing.T) {
	h, err := NewSignerHandler(newFilterSignerManager(), newSignerTestAccessServiceWithOwnerships(t, filterOwnerships()), slog.Default(), false)
	require.NoError(t, err)
	nonAdmin := &types.APIKey{ID: "owner-1", Role: types.RoleDev}

	// Non-admin pinning their own key is a no-op vs. default behavior,
	// but must NOT 403 — otherwise a UI that always sends the filter
	// would break for non-admin operators.
	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?api_key_id=owner-1", nonAdmin)
	require.Equal(t, http.StatusOK, rec.Code)
	resp := decodeSignerListResponse(t, rec)
	// owner-1 sees A + B + C (their own three).
	assert.Equal(t, 3, resp.Total)
}

func TestListSigners_Filter_OwnershipStatus_PendingApproval_AdminGlobal(t *testing.T) {
	h, err := NewSignerHandler(newFilterSignerManager(), newSignerTestAccessServiceWithOwnerships(t, filterOwnerships()), slog.Default(), false)
	require.NoError(t, err)
	admin := &types.APIKey{ID: "owner-1", Role: types.RoleAdmin}

	// Default admin view (owner-1 scope) does not include owner-2's pending signer.
	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers", admin)
	require.Equal(t, http.StatusOK, rec.Code)
	resp := decodeSignerListResponse(t, rec)
	assert.Equal(t, 3, resp.Total)

	// Global pending queue surfaces cross-key signers without api_key_id guesswork.
	rec = doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?ownership_status=pending_approval", admin)
	require.Equal(t, http.StatusOK, rec.Code)
	resp = decodeSignerListResponse(t, rec)
	require.Len(t, resp.Signers, 1)
	assert.Equal(t, 1, resp.Total)
	assert.Equal(t, filterAddrE, resp.Signers[0].Address)
	assert.Equal(t, "owner-2", resp.Signers[0].OwnerID)
	assert.Equal(t, "pending_approval", resp.Signers[0].Status)
}

func TestListSigners_Filter_OwnershipStatus_PendingApproval_NonAdmin_403(t *testing.T) {
	h, err := NewSignerHandler(newFilterSignerManager(), newSignerTestAccessServiceWithOwnerships(t, filterOwnerships()), slog.Default(), false)
	require.NoError(t, err)
	nonAdmin := &types.APIKey{ID: "owner-1", Role: types.RoleAgent}

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?ownership_status=pending_approval", nonAdmin)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestListSigners_Filter_OwnershipStatus_Invalid_400(t *testing.T) {
	h, err := NewSignerHandler(newFilterSignerManager(), newSignerTestAccessServiceWithOwnerships(t, filterOwnerships()), slog.Default(), false)
	require.NoError(t, err)
	admin := &types.APIKey{ID: "owner-1", Role: types.RoleAdmin}

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?ownership_status=active", admin)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
