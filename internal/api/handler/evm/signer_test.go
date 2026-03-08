package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
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

// --- Mock APIKeyRepository ---

type mockAPIKeyRepo struct {
	listFn func(ctx context.Context, filter storage.APIKeyFilter) ([]*types.APIKey, error)
}

func (m *mockAPIKeyRepo) Create(_ context.Context, _ *types.APIKey) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAPIKeyRepo) Get(_ context.Context, _ string) (*types.APIKey, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAPIKeyRepo) Update(_ context.Context, _ *types.APIKey) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAPIKeyRepo) Delete(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAPIKeyRepo) List(ctx context.Context, filter storage.APIKeyFilter) ([]*types.APIKey, error) {
	if m.listFn != nil {
		return m.listFn(ctx, filter)
	}
	return nil, nil
}

func (m *mockAPIKeyRepo) UpdateLastUsed(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAPIKeyRepo) Count(_ context.Context, _ storage.APIKeyFilter) (int, error) {
	return 0, fmt.Errorf("not implemented")
}

func (m *mockAPIKeyRepo) DeleteBySourceExcluding(_ context.Context, _ string, _ []string) (int64, error) {
	return 0, fmt.Errorf("not implemented")
}

func (m *mockAPIKeyRepo) BackfillSource(_ context.Context, _ string) (int64, error) {
	return 0, fmt.Errorf("not implemented")
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
		_, err := NewSignerHandler(nil, nil, slog.Default(), false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signer manager is required")
	})

	t.Run("nil logger returns error", func(t *testing.T) {
		_, err := NewSignerHandler(&signerMockSignerManager{}, nil, nil, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})

	t.Run("nil apiKeyRepo is allowed", func(t *testing.T) {
		h, err := NewSignerHandler(&signerMockSignerManager{}, nil, slog.Default(), false)
		require.NoError(t, err)
		require.NotNil(t, h)
		assert.Nil(t, h.apiKeyRepo)
	})

	t.Run("all deps provided", func(t *testing.T) {
		h, err := NewSignerHandler(&signerMockSignerManager{}, &mockAPIKeyRepo{}, slog.Default(), false)
		require.NoError(t, err)
		require.NotNil(t, h)
	})
}

// --- Non-admin filtering tests ---

func TestListSigners_NonAdmin_FilteredByAllowedSigners(t *testing.T) {
	sm := newSignerManagerWithAll()

	h, err := NewSignerHandler(sm, nil, slog.Default(), false)
	require.NoError(t, err)

	// Non-admin key that can only access signer 0x1111...
	apiKey := &types.APIKey{
		ID:             "non-admin-key",
		Name:           "dev-key",
		Admin:          false,
		Enabled:        true,
		AllowedSigners: pq.StringArray{"0x1111111111111111111111111111111111111111"},
	}

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers", apiKey)
	assert.Equal(t, http.StatusOK, rec.Code)

	resp := decodeSignerListResponse(t, rec)
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.Signers, 1)
	assert.Equal(t, "0x1111111111111111111111111111111111111111", resp.Signers[0].Address)
}

func TestListSigners_NonAdmin_EmptyAllowed_SeesAll(t *testing.T) {
	sm := newSignerManagerWithAll()

	h, err := NewSignerHandler(sm, nil, slog.Default(), false)
	require.NoError(t, err)

	// Non-admin key with empty AllowedSigners -> sees all
	apiKey := &types.APIKey{
		ID:      "non-admin-all",
		Name:    "full-access-key",
		Admin:   false,
		Enabled: true,
		// AllowedSigners is empty -> all signers visible
	}

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers", apiKey)
	assert.Equal(t, http.StatusOK, rec.Code)

	resp := decodeSignerListResponse(t, rec)
	assert.Equal(t, 3, resp.Total)
	assert.Len(t, resp.Signers, 3)
}

func TestListSigners_NonAdmin_CaseInsensitiveFilter(t *testing.T) {
	sm := newSignerManagerWithAll()

	h, err := NewSignerHandler(sm, nil, slog.Default(), false)
	require.NoError(t, err)

	// AllowedSigners has uppercase address, signers have lowercase
	apiKey := &types.APIKey{
		ID:             "non-admin-case",
		Name:           "case-key",
		Admin:          false,
		Enabled:        true,
		AllowedSigners: pq.StringArray{"0X1111111111111111111111111111111111111111"},
	}

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers", apiKey)
	assert.Equal(t, http.StatusOK, rec.Code)

	resp := decodeSignerListResponse(t, rec)
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.Signers, 1)
}

func TestListSigners_NonAdmin_PaginationOnFiltered(t *testing.T) {
	// Create 5 signers, non-admin can see 3
	signers := []types.SignerInfo{
		{Address: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Type: "keystore", Enabled: true},
		{Address: "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", Type: "keystore", Enabled: true},
		{Address: "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", Type: "keystore", Enabled: true},
		{Address: "0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", Type: "keystore", Enabled: true},
		{Address: "0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", Type: "keystore", Enabled: true},
	}

	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{
				Signers: signers,
				Total:   5,
				HasMore: false,
			}, nil
		},
	}

	h, err := NewSignerHandler(sm, nil, slog.Default(), false)
	require.NoError(t, err)

	apiKey := &types.APIKey{
		ID:    "paginated-key",
		Name:  "paginated",
		Admin: false,
		AllowedSigners: pq.StringArray{
			"0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
			"0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
		},
	}

	// Request page 1 (limit=2, offset=0) -> should get first 2 of 3 allowed
	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?limit=2&offset=0", apiKey)
	assert.Equal(t, http.StatusOK, rec.Code)

	resp := decodeSignerListResponse(t, rec)
	assert.Equal(t, 3, resp.Total)
	assert.Len(t, resp.Signers, 2)
	assert.True(t, resp.HasMore)

	// Request page 2 (limit=2, offset=2) -> should get last 1 of 3 allowed
	rec = doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?limit=2&offset=2", apiKey)
	assert.Equal(t, http.StatusOK, rec.Code)

	resp = decodeSignerListResponse(t, rec)
	assert.Equal(t, 3, resp.Total)
	assert.Len(t, resp.Signers, 1)
	assert.False(t, resp.HasMore)
}

// --- Admin enrichment tests ---

func TestListSigners_Admin_EnrichedWithAllowedKeys(t *testing.T) {
	sm := newSignerManagerWithAll()

	apiKeyRepo := &mockAPIKeyRepo{
		listFn: func(_ context.Context, _ storage.APIKeyFilter) ([]*types.APIKey, error) {
			return []*types.APIKey{
				{
					ID:             "admin-key",
					Name:           "admin",
					Admin:          true,
					AllowedSigners: pq.StringArray{}, // empty = all
				},
				{
					ID:   "dev-key",
					Name: "dev-key",
					AllowedSigners: pq.StringArray{
						"0x1111111111111111111111111111111111111111",
						"0x2222222222222222222222222222222222222222",
					},
				},
				{
					ID:             "readonly-key",
					Name:           "readonly",
					AllowedSigners: pq.StringArray{}, // empty = all
				},
			}, nil
		},
	}

	h, err := NewSignerHandler(sm, apiKeyRepo, slog.Default(), false)
	require.NoError(t, err)

	adminAPIKey := &types.APIKey{
		ID:    "admin-key",
		Name:  "admin",
		Admin: true,
	}

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers", adminAPIKey)
	assert.Equal(t, http.StatusOK, rec.Code)

	resp := decodeSignerListResponse(t, rec)
	assert.Equal(t, 3, resp.Total)
	assert.Len(t, resp.Signers, 3)

	// Signer 0x1111 should be accessible by: admin (unrestricted), dev-key (explicit), readonly (unrestricted)
	signer1 := resp.Signers[0]
	assert.Equal(t, "0x1111111111111111111111111111111111111111", signer1.Address)
	require.Len(t, signer1.AllowedKeys, 3) // admin + readonly (unrestricted) + dev-key (explicit)
	// Unrestricted keys come first, then explicit
	assert.Equal(t, "unrestricted", signer1.AllowedKeys[0].AccessType)
	assert.Equal(t, "unrestricted", signer1.AllowedKeys[1].AccessType)
	assert.Equal(t, "explicit", signer1.AllowedKeys[2].AccessType)

	// Signer 0x3333 should be accessible by: admin (unrestricted), readonly (unrestricted) only
	signer3 := resp.Signers[2]
	assert.Equal(t, "0x3333333333333333333333333333333333333333", signer3.Address)
	require.Len(t, signer3.AllowedKeys, 2) // admin + readonly (unrestricted)
	assert.Equal(t, "unrestricted", signer3.AllowedKeys[0].AccessType)
	assert.Equal(t, "unrestricted", signer3.AllowedKeys[1].AccessType)
}

func TestListSigners_Admin_NoApiKeyRepo_NoEnrichment(t *testing.T) {
	sm := newSignerManagerWithAll()

	// apiKeyRepo is nil -> no enrichment
	h, err := NewSignerHandler(sm, nil, slog.Default(), false)
	require.NoError(t, err)

	adminAPIKey := &types.APIKey{
		ID:    "admin-key",
		Name:  "admin",
		Admin: true,
	}

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers", adminAPIKey)
	assert.Equal(t, http.StatusOK, rec.Code)

	resp := decodeSignerListResponse(t, rec)
	assert.Len(t, resp.Signers, 3)

	// No AllowedKeys on any signer (omitempty -> not present)
	for _, s := range resp.Signers {
		assert.Empty(t, s.AllowedKeys)
	}
}

func TestListSigners_Unauthorized(t *testing.T) {
	sm := newSignerManagerWithAll()
	h, err := NewSignerHandler(sm, nil, slog.Default(), false)
	require.NoError(t, err)

	// No API key in context
	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers", nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
