package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

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
	listSignersFn  func(ctx context.Context, filter types.SignerFilter) (types.SignerListResult, error)
	createSignerFn func(ctx context.Context, req types.CreateSignerRequest) (*types.SignerInfo, error)
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

type signerStubAccessRepo struct{}

func (s *signerStubAccessRepo) Grant(_ context.Context, _ *types.SignerAccess) error { return nil }
func (s *signerStubAccessRepo) Revoke(_ context.Context, _, _ string) error          { return nil }
func (s *signerStubAccessRepo) List(_ context.Context, _ string) ([]*types.SignerAccess, error) {
	return nil, nil
}
func (s *signerStubAccessRepo) HasAccess(_ context.Context, _, _ string) (bool, error) {
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
