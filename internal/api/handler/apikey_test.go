package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------------------------------------------------------------------------
// Mock API key repository
// ---------------------------------------------------------------------------

type mockAPIKeyRepo struct {
	createFn                func(ctx context.Context, key *types.APIKey) error
	getFn                   func(ctx context.Context, id string) (*types.APIKey, error)
	updateFn                func(ctx context.Context, key *types.APIKey) error
	deleteFn                func(ctx context.Context, id string) error
	listFn                  func(ctx context.Context, filter storage.APIKeyFilter) ([]*types.APIKey, error)
	countFn                 func(ctx context.Context, filter storage.APIKeyFilter) (int, error)
	updateLastUsedFn        func(ctx context.Context, id string) error
	deleteBySourceExclFn    func(ctx context.Context, source string, excludeIDs []string) (int64, error)
	backfillSourceFn        func(ctx context.Context, defaultSource string) (int64, error)

	// stored keys for default implementations
	keys map[string]*types.APIKey
}

func newMockAPIKeyRepo() *mockAPIKeyRepo {
	return &mockAPIKeyRepo{
		keys: make(map[string]*types.APIKey),
	}
}

func (r *mockAPIKeyRepo) Create(ctx context.Context, key *types.APIKey) error {
	if r.createFn != nil {
		return r.createFn(ctx, key)
	}
	if _, exists := r.keys[key.ID]; exists {
		return fmt.Errorf("duplicate key ID: %s", key.ID)
	}
	now := time.Now()
	key.CreatedAt = now
	key.UpdatedAt = now
	cp := *key
	r.keys[key.ID] = &cp
	return nil
}

func (r *mockAPIKeyRepo) Get(ctx context.Context, id string) (*types.APIKey, error) {
	if r.getFn != nil {
		return r.getFn(ctx, id)
	}
	key, ok := r.keys[id]
	if !ok {
		return nil, types.ErrNotFound
	}
	cp := *key
	return &cp, nil
}

func (r *mockAPIKeyRepo) Update(ctx context.Context, key *types.APIKey) error {
	if r.updateFn != nil {
		return r.updateFn(ctx, key)
	}
	if _, exists := r.keys[key.ID]; !exists {
		return types.ErrNotFound
	}
	key.UpdatedAt = time.Now()
	cp := *key
	r.keys[key.ID] = &cp
	return nil
}

func (r *mockAPIKeyRepo) Delete(ctx context.Context, id string) error {
	if r.deleteFn != nil {
		return r.deleteFn(ctx, id)
	}
	if _, exists := r.keys[id]; !exists {
		return types.ErrNotFound
	}
	delete(r.keys, id)
	return nil
}

func (r *mockAPIKeyRepo) List(ctx context.Context, filter storage.APIKeyFilter) ([]*types.APIKey, error) {
	if r.listFn != nil {
		return r.listFn(ctx, filter)
	}
	var out []*types.APIKey
	for _, key := range r.keys {
		if filter.Source != "" && key.Source != filter.Source {
			continue
		}
		if filter.EnabledOnly && !key.Enabled {
			continue
		}
		cp := *key
		out = append(out, &cp)
	}
	if filter.Offset > 0 && filter.Offset < len(out) {
		out = out[filter.Offset:]
	} else if filter.Offset >= len(out) && filter.Offset > 0 {
		out = nil
	}
	if filter.Limit > 0 && filter.Limit < len(out) {
		out = out[:filter.Limit]
	}
	return out, nil
}

func (r *mockAPIKeyRepo) Count(ctx context.Context, filter storage.APIKeyFilter) (int, error) {
	if r.countFn != nil {
		return r.countFn(ctx, filter)
	}
	count := 0
	for _, key := range r.keys {
		if filter.Source != "" && key.Source != filter.Source {
			continue
		}
		if filter.EnabledOnly && !key.Enabled {
			continue
		}
		count++
	}
	return count, nil
}

func (r *mockAPIKeyRepo) UpdateLastUsed(ctx context.Context, id string) error {
	if r.updateLastUsedFn != nil {
		return r.updateLastUsedFn(ctx, id)
	}
	return nil
}

func (r *mockAPIKeyRepo) DeleteBySourceExcluding(ctx context.Context, source string, excludeIDs []string) (int64, error) {
	if r.deleteBySourceExclFn != nil {
		return r.deleteBySourceExclFn(ctx, source, excludeIDs)
	}
	return 0, nil
}

func (r *mockAPIKeyRepo) BackfillSource(ctx context.Context, defaultSource string) (int64, error) {
	if r.backfillSourceFn != nil {
		return r.backfillSourceFn(ctx, defaultSource)
	}
	return 0, nil
}

// seed adds a key directly into the mock repo.
func (r *mockAPIKeyRepo) seed(key *types.APIKey) {
	cp := *key
	r.keys[key.ID] = &cp
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func apikeyLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func apikeyAdminKey() *types.APIKey {
	return &types.APIKey{
		ID:      "admin-key-1",
		Name:    "Admin Key",
		Enabled: true,
		Role:    types.RoleAdmin,
		Source:  types.APIKeySourceAPI,
	}
}

func doAPIKeyCollectionRequest(t *testing.T, h *APIKeyHandler, method, path string, body any, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewBuffer(b)
	} else {
		bodyReader = bytes.NewBuffer(nil)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func doAPIKeyItemRequest(t *testing.T, h *APIKeyHandler, method, path string, body any, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewBuffer(b)
	} else {
		bodyReader = bytes.NewBuffer(nil)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rr := httptest.NewRecorder()
	h.ServeKeyHTTP(rr, req)
	return rr
}

func makeTestAPIKey(id, name, source string, enabled bool) *types.APIKey {
	now := time.Now()
	return &types.APIKey{
		ID:           id,
		Name:         name,
		PublicKeyHex: "abcdef1234567890",
		Source:       source,
		Enabled:      enabled,
		Role:         types.RoleStrategy,
		RateLimit:    100,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// ---------------------------------------------------------------------------
// Tests: NewAPIKeyHandler
// ---------------------------------------------------------------------------

func TestNewAPIKeyHandler(t *testing.T) {
	repo := newMockAPIKeyRepo()
	logger := apikeyLogger()

	t.Run("valid_args", func(t *testing.T) {
		h, err := NewAPIKeyHandler(repo, logger, false)
		require.NoError(t, err)
		assert.NotNil(t, h)
	})

	t.Run("nil_repo_returns_error", func(t *testing.T) {
		_, err := NewAPIKeyHandler(nil, logger, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "API key repository is required")
	})

	t.Run("nil_logger_returns_error", func(t *testing.T) {
		_, err := NewAPIKeyHandler(repo, nil, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})
}

// ---------------------------------------------------------------------------
// Tests: List
// ---------------------------------------------------------------------------

func TestAPIKeyHandler_List_Success(t *testing.T) {
	repo := newMockAPIKeyRepo()
	repo.seed(makeTestAPIKey("key-1", "Key One", types.APIKeySourceAPI, true))
	repo.seed(makeTestAPIKey("key-2", "Key Two", types.APIKeySourceConfig, true))

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, h, http.MethodGet, "/api/v1/api-keys", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var resp ListAPIKeysResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 2, resp.Total)
	assert.Equal(t, 2, len(resp.Keys))

	// Verify response fields are populated
	for _, k := range resp.Keys {
		assert.NotEmpty(t, k.ID)
		assert.NotEmpty(t, k.Name)
		assert.NotEmpty(t, k.Source)
	}
}

func TestAPIKeyHandler_List_WithSourceFilter(t *testing.T) {
	repo := newMockAPIKeyRepo()
	repo.seed(makeTestAPIKey("key-api-1", "API Key", types.APIKeySourceAPI, true))
	repo.seed(makeTestAPIKey("key-cfg-1", "Config Key", types.APIKeySourceConfig, true))

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, h, http.MethodGet, "/api/v1/api-keys?source=api", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ListAPIKeysResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 1, resp.Total)
	assert.Equal(t, 1, len(resp.Keys))
	assert.Equal(t, "api", resp.Keys[0].Source)
}

func TestAPIKeyHandler_List_WithEnabledFilter(t *testing.T) {
	repo := newMockAPIKeyRepo()
	repo.seed(makeTestAPIKey("key-en", "Enabled Key", types.APIKeySourceAPI, true))
	repo.seed(makeTestAPIKey("key-dis", "Disabled Key", types.APIKeySourceAPI, false))

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, h, http.MethodGet, "/api/v1/api-keys?enabled=true", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ListAPIKeysResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 1, resp.Total)
	assert.Equal(t, 1, len(resp.Keys))
	assert.True(t, resp.Keys[0].Enabled)
}

func TestAPIKeyHandler_List_InvalidEnabledParam(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, h, http.MethodGet, "/api/v1/api-keys?enabled=notbool", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "invalid enabled parameter")
}

func TestAPIKeyHandler_List_InvalidLimitParam(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, h, http.MethodGet, "/api/v1/api-keys?limit=abc", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "invalid limit parameter")
}

func TestAPIKeyHandler_List_NegativeLimitParam(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, h, http.MethodGet, "/api/v1/api-keys?limit=-1", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAPIKeyHandler_List_LimitClamping(t *testing.T) {
	repo := newMockAPIKeyRepo()
	// Track the filter passed to List
	var capturedFilter storage.APIKeyFilter
	repo.listFn = func(_ context.Context, filter storage.APIKeyFilter) ([]*types.APIKey, error) {
		capturedFilter = filter
		return nil, nil
	}
	repo.countFn = func(_ context.Context, filter storage.APIKeyFilter) (int, error) {
		return 0, nil
	}

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, h, http.MethodGet, "/api/v1/api-keys?limit=500", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)
	// limit > 100 should be clamped to 100
	assert.Equal(t, 100, capturedFilter.Limit)
}

func TestAPIKeyHandler_List_InvalidOffsetParam(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, h, http.MethodGet, "/api/v1/api-keys?offset=abc", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAPIKeyHandler_List_NegativeOffsetParam(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, h, http.MethodGet, "/api/v1/api-keys?offset=-5", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAPIKeyHandler_List_Error(t *testing.T) {
	repo := newMockAPIKeyRepo()
	repo.listFn = func(_ context.Context, _ storage.APIKeyFilter) ([]*types.APIKey, error) {
		return nil, fmt.Errorf("database connection lost")
	}

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, h, http.MethodGet, "/api/v1/api-keys", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "failed to list API keys")
}

func TestAPIKeyHandler_List_CountError(t *testing.T) {
	repo := newMockAPIKeyRepo()
	repo.countFn = func(_ context.Context, _ storage.APIKeyFilter) (int, error) {
		return 0, fmt.Errorf("count query timeout")
	}

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, h, http.MethodGet, "/api/v1/api-keys", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "failed to count API keys")
}

func TestAPIKeyHandler_List_Empty(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, h, http.MethodGet, "/api/v1/api-keys", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ListAPIKeysResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 0, resp.Total)
	assert.NotNil(t, resp.Keys)
	assert.Equal(t, 0, len(resp.Keys))
}

// ---------------------------------------------------------------------------
// Tests: Get
// ---------------------------------------------------------------------------

func TestAPIKeyHandler_Get_Success(t *testing.T) {
	repo := newMockAPIKeyRepo()
	key := makeTestAPIKey("key-get-1", "Get Key", types.APIKeySourceAPI, true)
	repo.seed(key)

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyItemRequest(t, h, http.MethodGet, "/api/v1/api-keys/key-get-1", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp APIKeyResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "key-get-1", resp.ID)
	assert.Equal(t, "Get Key", resp.Name)
	assert.Equal(t, "api", resp.Source)
	assert.True(t, resp.Enabled)
}

func TestAPIKeyHandler_Get_NotFound(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyItemRequest(t, h, http.MethodGet, "/api/v1/api-keys/nonexistent", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusNotFound, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Equal(t, "API key not found", errResp["error"])
}

func TestAPIKeyHandler_Get_InternalError(t *testing.T) {
	repo := newMockAPIKeyRepo()
	repo.getFn = func(_ context.Context, _ string) (*types.APIKey, error) {
		return nil, fmt.Errorf("database error")
	}

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyItemRequest(t, h, http.MethodGet, "/api/v1/api-keys/key-1", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAPIKeyHandler_Get_NoPublicKey(t *testing.T) {
	repo := newMockAPIKeyRepo()
	key := makeTestAPIKey("key-nopub", "No Pub Key", types.APIKeySourceAPI, true)
	key.PublicKeyHex = "secret_public_key_hex_value"
	repo.seed(key)

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyItemRequest(t, h, http.MethodGet, "/api/v1/api-keys/key-nopub", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	// Verify public_key is NOT in the response body
	bodyBytes := rr.Body.Bytes()
	assert.NotContains(t, string(bodyBytes), "public_key")
	assert.NotContains(t, string(bodyBytes), "secret_public_key_hex_value")
}

func TestAPIKeyHandler_Get_EmptyID(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	// Path with no ID after prefix
	rr := doAPIKeyItemRequest(t, h, http.MethodGet, "/api/v1/api-keys/", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "API key ID is required")
}

// ---------------------------------------------------------------------------
// Tests: Create
// ---------------------------------------------------------------------------

func TestAPIKeyHandler_Create_Success(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	reqBody := CreateAPIKeyRequest{
		ID:        "my-new-key",
		Name:      "My New Key",
		PublicKey: "abcdef1234567890abcdef1234567890",
		Role:      "strategy",
	}

	rr := doAPIKeyCollectionRequest(t, h, http.MethodPost, "/api/v1/api-keys", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp APIKeyResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "my-new-key", resp.ID)
	assert.Equal(t, "My New Key", resp.Name)
	assert.Equal(t, types.APIKeySourceAPI, resp.Source)
	assert.True(t, resp.Enabled)
	assert.Equal(t, 100, resp.RateLimit) // default rate limit

	// Verify key is stored
	stored, storeErr := repo.Get(context.Background(), "my-new-key")
	require.NoError(t, storeErr)
	assert.Equal(t, types.APIKeySourceAPI, stored.Source)
}

func TestAPIKeyHandler_Create_WithCustomRateLimit(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	reqBody := CreateAPIKeyRequest{
		ID:        "rate-key",
		Name:      "Rate Key",
		PublicKey: "abcdef",
		Role:      "admin",
		RateLimit: 50,
	}

	rr := doAPIKeyCollectionRequest(t, h, http.MethodPost, "/api/v1/api-keys", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp APIKeyResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 50, resp.RateLimit)
}

func TestAPIKeyHandler_Create_ReadOnly(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), true) // readOnly=true
	require.NoError(t, err)

	reqBody := CreateAPIKeyRequest{
		ID:        "should-fail",
		Name:      "Should Fail",
		PublicKey: "abcdef",
	}

	rr := doAPIKeyCollectionRequest(t, h, http.MethodPost, "/api/v1/api-keys", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusForbidden, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "API key management is disabled")
}

func TestAPIKeyHandler_Create_InvalidID_Empty(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	reqBody := CreateAPIKeyRequest{
		ID:        "",
		Name:      "Empty ID",
		PublicKey: "abcdef",
	}

	rr := doAPIKeyCollectionRequest(t, h, http.MethodPost, "/api/v1/api-keys", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Equal(t, "id is required", errResp["error"])
}

func TestAPIKeyHandler_Create_InvalidID_TooLong(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	longID := strings.Repeat("a", 65)
	reqBody := CreateAPIKeyRequest{
		ID:        longID,
		Name:      "Too Long ID",
		PublicKey: "abcdef",
	}

	rr := doAPIKeyCollectionRequest(t, h, http.MethodPost, "/api/v1/api-keys", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "at most 64 characters")
}

func TestAPIKeyHandler_Create_InvalidID_SpecialChars(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	badIDs := []string{"key with spaces", "key@special", "key/slash", "key.dot", "key_underscore"}
	for _, id := range badIDs {
		t.Run(id, func(t *testing.T) {
			reqBody := CreateAPIKeyRequest{
				ID:        id,
				Name:      "Bad ID",
				PublicKey: "abcdef",
			}

			rr := doAPIKeyCollectionRequest(t, h, http.MethodPost, "/api/v1/api-keys", reqBody, apikeyAdminKey())
			assert.Equal(t, http.StatusBadRequest, rr.Code)

			var errResp map[string]string
			require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
			assert.Contains(t, errResp["error"], "alphanumeric characters and hyphens")
		})
	}
}

func TestAPIKeyHandler_Create_ValidIDWithHyphens(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	reqBody := CreateAPIKeyRequest{
		ID:        "my-key-123",
		Name:      "Hyphen Key",
		PublicKey: "abcdef",
		Role:      "admin",
	}

	rr := doAPIKeyCollectionRequest(t, h, http.MethodPost, "/api/v1/api-keys", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusCreated, rr.Code)
}

func TestAPIKeyHandler_Create_MissingName(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	reqBody := CreateAPIKeyRequest{
		ID:        "valid-id",
		Name:      "",
		PublicKey: "abcdef",
	}

	rr := doAPIKeyCollectionRequest(t, h, http.MethodPost, "/api/v1/api-keys", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Equal(t, "name is required", errResp["error"])
}

func TestAPIKeyHandler_Create_NameTooLong(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	reqBody := CreateAPIKeyRequest{
		ID:        "valid-id",
		Name:      strings.Repeat("n", 256),
		PublicKey: "abcdef",
	}

	rr := doAPIKeyCollectionRequest(t, h, http.MethodPost, "/api/v1/api-keys", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "at most 255 characters")
}

func TestAPIKeyHandler_Create_MissingPublicKey(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	reqBody := CreateAPIKeyRequest{
		ID:        "valid-id",
		Name:      "Valid Name",
		PublicKey: "",
	}

	rr := doAPIKeyCollectionRequest(t, h, http.MethodPost, "/api/v1/api-keys", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Equal(t, "public_key is required", errResp["error"])
}

func TestAPIKeyHandler_Create_DuplicateID(t *testing.T) {
	repo := newMockAPIKeyRepo()
	repo.seed(makeTestAPIKey("dup-key", "Existing", types.APIKeySourceAPI, true))

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	reqBody := CreateAPIKeyRequest{
		ID:        "dup-key",
		Name:      "Duplicate",
		PublicKey: "abcdef",
		Role:      "admin",
	}

	rr := doAPIKeyCollectionRequest(t, h, http.MethodPost, "/api/v1/api-keys", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "failed to create API key")
}

func TestAPIKeyHandler_Create_InvalidJSON(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", bytes.NewBufferString("{broken json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apikeyAdminKey()))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "invalid request body")
}

func TestAPIKeyHandler_Create_MethodNotAllowed(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyCollectionRequest(t, h, http.MethodPut, "/api/v1/api-keys", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Equal(t, "method not allowed", errResp["error"])
}

func TestAPIKeyHandler_Create_RepoGetFailsAfterCreate(t *testing.T) {
	repo := newMockAPIKeyRepo()
	callCount := 0
	repo.getFn = func(_ context.Context, id string) (*types.APIKey, error) {
		callCount++
		// First call during create's re-fetch fails
		return nil, fmt.Errorf("transient error")
	}

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	reqBody := CreateAPIKeyRequest{
		ID:        "get-fail-key",
		Name:      "Get Fail Key",
		PublicKey: "abcdef",
		Role:      "admin",
	}

	rr := doAPIKeyCollectionRequest(t, h, http.MethodPost, "/api/v1/api-keys", reqBody, apikeyAdminKey())
	// Should still return 201 even if re-fetch fails
	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp APIKeyResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "get-fail-key", resp.ID)
}

// ---------------------------------------------------------------------------
// Tests: Update
// ---------------------------------------------------------------------------

func TestAPIKeyHandler_Update_Success(t *testing.T) {
	repo := newMockAPIKeyRepo()
	key := makeTestAPIKey("upd-key", "Original", types.APIKeySourceAPI, true)
	repo.seed(key)

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	newName := "Updated Name"
	newEnabled := false
	newRateLimit := 50
	reqBody := UpdateAPIKeyRequest{
		Name:      &newName,
		Enabled:   &newEnabled,
		RateLimit: &newRateLimit,
	}

	rr := doAPIKeyItemRequest(t, h, http.MethodPut, "/api/v1/api-keys/upd-key", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp APIKeyResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "Updated Name", resp.Name)
	assert.False(t, resp.Enabled)
	assert.Equal(t, 50, resp.RateLimit)
}

func TestAPIKeyHandler_Update_AllFields(t *testing.T) {
	repo := newMockAPIKeyRepo()
	key := makeTestAPIKey("upd-all", "Original", types.APIKeySourceAPI, true)
	repo.seed(key)

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	newName := "All Updated"
	newEnabled := false
	newRole := "admin"
	newRateLimit := 200
	reqBody := UpdateAPIKeyRequest{
		Name:      &newName,
		Enabled:   &newEnabled,
		Role:      &newRole,
		RateLimit: &newRateLimit,
	}

	rr := doAPIKeyItemRequest(t, h, http.MethodPut, "/api/v1/api-keys/upd-all", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp APIKeyResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "All Updated", resp.Name)
	assert.False(t, resp.Enabled)
	assert.Equal(t, types.RoleAdmin, resp.Role)
	assert.Equal(t, 200, resp.RateLimit)
}

func TestAPIKeyHandler_Update_ReadOnly(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), true)
	require.NoError(t, err)

	newName := "Updated"
	reqBody := UpdateAPIKeyRequest{Name: &newName}

	rr := doAPIKeyItemRequest(t, h, http.MethodPut, "/api/v1/api-keys/some-key", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusForbidden, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "API key management is disabled")
}

func TestAPIKeyHandler_Update_ConfigSource(t *testing.T) {
	repo := newMockAPIKeyRepo()
	key := makeTestAPIKey("cfg-key", "Config Key", types.APIKeySourceConfig, true)
	repo.seed(key)

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	newName := "Updated"
	reqBody := UpdateAPIKeyRequest{Name: &newName}

	rr := doAPIKeyItemRequest(t, h, http.MethodPut, "/api/v1/api-keys/cfg-key", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusForbidden, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "cannot modify config-sourced API key")
}

func TestAPIKeyHandler_Update_NotFound(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	newName := "Updated"
	reqBody := UpdateAPIKeyRequest{Name: &newName}

	rr := doAPIKeyItemRequest(t, h, http.MethodPut, "/api/v1/api-keys/nonexistent", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestAPIKeyHandler_Update_InternalGetError(t *testing.T) {
	repo := newMockAPIKeyRepo()
	repo.getFn = func(_ context.Context, _ string) (*types.APIKey, error) {
		return nil, fmt.Errorf("database error")
	}

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	newName := "Updated"
	reqBody := UpdateAPIKeyRequest{Name: &newName}

	rr := doAPIKeyItemRequest(t, h, http.MethodPut, "/api/v1/api-keys/some-key", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAPIKeyHandler_Update_InvalidJSON(t *testing.T) {
	repo := newMockAPIKeyRepo()
	key := makeTestAPIKey("bad-json-key", "Bad JSON Key", types.APIKeySourceAPI, true)
	repo.seed(key)

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/api-keys/bad-json-key", bytes.NewBufferString("{broken"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apikeyAdminKey()))

	rr := httptest.NewRecorder()
	h.ServeKeyHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "invalid request body")
}

func TestAPIKeyHandler_Update_EmptyName(t *testing.T) {
	repo := newMockAPIKeyRepo()
	key := makeTestAPIKey("empty-name-key", "Original", types.APIKeySourceAPI, true)
	repo.seed(key)

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	emptyName := ""
	reqBody := UpdateAPIKeyRequest{Name: &emptyName}

	rr := doAPIKeyItemRequest(t, h, http.MethodPut, "/api/v1/api-keys/empty-name-key", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "name must not be empty")
}

func TestAPIKeyHandler_Update_NameTooLong(t *testing.T) {
	repo := newMockAPIKeyRepo()
	key := makeTestAPIKey("long-name-key", "Original", types.APIKeySourceAPI, true)
	repo.seed(key)

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	longName := strings.Repeat("n", 256)
	reqBody := UpdateAPIKeyRequest{Name: &longName}

	rr := doAPIKeyItemRequest(t, h, http.MethodPut, "/api/v1/api-keys/long-name-key", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "at most 255 characters")
}

func TestAPIKeyHandler_Update_RepoUpdateError(t *testing.T) {
	repo := newMockAPIKeyRepo()
	key := makeTestAPIKey("upd-err-key", "Update Err Key", types.APIKeySourceAPI, true)
	repo.seed(key)
	repo.updateFn = func(_ context.Context, _ *types.APIKey) error {
		return fmt.Errorf("constraint violation")
	}

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	newName := "New Name"
	reqBody := UpdateAPIKeyRequest{Name: &newName}

	rr := doAPIKeyItemRequest(t, h, http.MethodPut, "/api/v1/api-keys/upd-err-key", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "failed to update API key")
}

// ---------------------------------------------------------------------------
// Tests: Delete
// ---------------------------------------------------------------------------

func TestAPIKeyHandler_Delete_Success(t *testing.T) {
	repo := newMockAPIKeyRepo()
	key := makeTestAPIKey("del-key", "Delete Key", types.APIKeySourceAPI, true)
	repo.seed(key)

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyItemRequest(t, h, http.MethodDelete, "/api/v1/api-keys/del-key", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Verify key is gone
	_, getErr := repo.Get(context.Background(), "del-key")
	assert.ErrorIs(t, getErr, types.ErrNotFound)
}

func TestAPIKeyHandler_Delete_ReadOnly(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), true)
	require.NoError(t, err)

	rr := doAPIKeyItemRequest(t, h, http.MethodDelete, "/api/v1/api-keys/some-key", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusForbidden, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "API key management is disabled")
}

func TestAPIKeyHandler_Delete_ConfigSource(t *testing.T) {
	repo := newMockAPIKeyRepo()
	key := makeTestAPIKey("cfg-del-key", "Config Key", types.APIKeySourceConfig, true)
	repo.seed(key)

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyItemRequest(t, h, http.MethodDelete, "/api/v1/api-keys/cfg-del-key", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusForbidden, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "cannot delete config-sourced API key")
}

func TestAPIKeyHandler_Delete_NotFound(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyItemRequest(t, h, http.MethodDelete, "/api/v1/api-keys/nonexistent", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestAPIKeyHandler_Delete_InternalGetError(t *testing.T) {
	repo := newMockAPIKeyRepo()
	repo.getFn = func(_ context.Context, _ string) (*types.APIKey, error) {
		return nil, fmt.Errorf("database error")
	}

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyItemRequest(t, h, http.MethodDelete, "/api/v1/api-keys/some-key", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAPIKeyHandler_Delete_RepoDeleteError(t *testing.T) {
	repo := newMockAPIKeyRepo()
	key := makeTestAPIKey("del-err-key", "Delete Err Key", types.APIKeySourceAPI, true)
	repo.seed(key)
	repo.deleteFn = func(_ context.Context, _ string) error {
		return fmt.Errorf("foreign key constraint")
	}

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyItemRequest(t, h, http.MethodDelete, "/api/v1/api-keys/del-err-key", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "failed to delete API key")
}

func TestAPIKeyHandler_Delete_RepoDeleteNotFoundRace(t *testing.T) {
	// Get succeeds but Delete returns not found (race condition)
	repo := newMockAPIKeyRepo()
	key := makeTestAPIKey("del-race-key", "Race Key", types.APIKeySourceAPI, true)
	repo.seed(key)
	repo.deleteFn = func(_ context.Context, _ string) error {
		return types.ErrNotFound
	}

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyItemRequest(t, h, http.MethodDelete, "/api/v1/api-keys/del-race-key", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// ---------------------------------------------------------------------------
// Tests: ServeKeyHTTP method routing
// ---------------------------------------------------------------------------

func TestAPIKeyHandler_ServeKeyHTTP_MethodNotAllowed(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	methods := []string{http.MethodPost, http.MethodPatch}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			rr := doAPIKeyItemRequest(t, h, method, "/api/v1/api-keys/some-key", nil, apikeyAdminKey())
			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: toAPIKeyResponse
// ---------------------------------------------------------------------------

func TestToAPIKeyResponse_BasicFields(t *testing.T) {
	key := &types.APIKey{
		ID:      "resp-test",
		Name:    "Response Test",
		Source:  types.APIKeySourceAPI,
		Enabled: true,
	}

	resp := toAPIKeyResponse(key)
	assert.Equal(t, "resp-test", resp.ID)
	assert.Equal(t, "Response Test", resp.Name)
	assert.True(t, resp.Enabled)
}

func TestToAPIKeyResponse_IncludesOptionalTimeFields(t *testing.T) {
	now := time.Now()
	expires := now.Add(24 * time.Hour)
	key := &types.APIKey{
		ID:         "resp-time",
		Name:       "Time Test",
		Source:     types.APIKeySourceAPI,
		Enabled:    true,
		LastUsedAt: &now,
		ExpiresAt:  &expires,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	resp := toAPIKeyResponse(key)
	assert.NotNil(t, resp.LastUsedAt)
	assert.NotNil(t, resp.ExpiresAt)
	assert.False(t, resp.CreatedAt.IsZero())
	assert.False(t, resp.UpdatedAt.IsZero())
}

// ---------------------------------------------------------------------------
// Tests: Create with no context API key (audit logger branch)
// ---------------------------------------------------------------------------

func TestAPIKeyHandler_Create_NoContextAPIKey(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	reqBody := CreateAPIKeyRequest{
		ID:        "no-ctx-key",
		Name:      "No Context Key",
		PublicKey: "abcdef",
		Role:      "admin",
	}

	// Request without API key in context
	b, marshalErr := json.Marshal(reqBody)
	require.NoError(t, marshalErr)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	// No API key in context

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	// Should still succeed (audit logger is nil, no context key needed for creation logic)
	assert.Equal(t, http.StatusCreated, rr.Code)
}

// ---------------------------------------------------------------------------
// Tests: Security Validations (rate limit, public key length, last admin, arrays)
// ---------------------------------------------------------------------------

func TestAPIKeyHandler_Create_RateLimitBounds(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		rateLimit int
		wantCode  int
	}{
		{"negative", "rl-neg", -1, http.StatusBadRequest},
		{"zero_defaults_to_100", "rl-zero", 0, http.StatusCreated},
		{"valid_min", "rl-min", 1, http.StatusCreated},
		{"valid_max", "rl-max", 10000, http.StatusCreated},
		{"exceeds_max", "rl-over", 10001, http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockAPIKeyRepo()
			h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
			require.NoError(t, err)

			reqBody := CreateAPIKeyRequest{
				ID:        tc.id,
				Name:      "Rate Limit Test",
				PublicKey: "abcdef",
				Role:      "admin",
				RateLimit: tc.rateLimit,
			}

			rr := doAPIKeyCollectionRequest(t, h, http.MethodPost, "/api/v1/api-keys", reqBody, apikeyAdminKey())
			assert.Equal(t, tc.wantCode, rr.Code)
		})
	}
}

func TestAPIKeyHandler_Create_PublicKeyTooLong(t *testing.T) {
	repo := newMockAPIKeyRepo()
	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	reqBody := CreateAPIKeyRequest{
		ID:        "pk-long",
		Name:      "Long PK",
		PublicKey: strings.Repeat("a", 129),
	}

	rr := doAPIKeyCollectionRequest(t, h, http.MethodPost, "/api/v1/api-keys", reqBody, apikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "public_key exceeds maximum length")
}

func TestAPIKeyHandler_Update_RateLimitBounds(t *testing.T) {
	tests := []struct {
		name      string
		rateLimit int
		wantCode  int
	}{
		{"negative", -1, http.StatusBadRequest},
		{"zero", 0, http.StatusBadRequest},
		{"valid", 50, http.StatusOK},
		{"exceeds_max", 10001, http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockAPIKeyRepo()
			key := makeTestAPIKey("rl-upd-key", "RL Key", types.APIKeySourceAPI, true)
			repo.seed(key)

			h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
			require.NoError(t, err)

			rl := tc.rateLimit
			reqBody := UpdateAPIKeyRequest{RateLimit: &rl}

			rr := doAPIKeyItemRequest(t, h, http.MethodPut, "/api/v1/api-keys/rl-upd-key", reqBody, apikeyAdminKey())
			assert.Equal(t, tc.wantCode, rr.Code)
		})
	}
}

func TestAPIKeyHandler_Delete_LastAdminKey(t *testing.T) {
	repo := newMockAPIKeyRepo()
	// Only one admin key
	adminKey := makeTestAPIKey("only-admin", "Only Admin", types.APIKeySourceAPI, true)
	adminKey.Role = types.RoleAdmin
	repo.seed(adminKey)

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyItemRequest(t, h, http.MethodDelete, "/api/v1/api-keys/only-admin", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp["error"], "cannot delete the last admin API key")
}

func TestAPIKeyHandler_Delete_AdminKeyWithOtherAdmins(t *testing.T) {
	repo := newMockAPIKeyRepo()
	// Two admin keys
	admin1 := makeTestAPIKey("admin-1", "Admin 1", types.APIKeySourceAPI, true)
	admin1.Role = types.RoleAdmin
	admin2 := makeTestAPIKey("admin-2", "Admin 2", types.APIKeySourceAPI, true)
	admin2.Role = types.RoleAdmin
	repo.seed(admin1)
	repo.seed(admin2)

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyItemRequest(t, h, http.MethodDelete, "/api/v1/api-keys/admin-1", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Verify admin-1 is deleted, admin-2 still exists
	_, err = repo.Get(context.Background(), "admin-1")
	assert.ErrorIs(t, err, types.ErrNotFound)
	_, err = repo.Get(context.Background(), "admin-2")
	assert.NoError(t, err)
}

func TestAPIKeyHandler_Delete_NonAdminKeySkipsAdminCheck(t *testing.T) {
	repo := newMockAPIKeyRepo()
	// Non-admin key — should skip the admin count check entirely
	key := makeTestAPIKey("non-admin", "Non Admin", types.APIKeySourceAPI, true)
	key.Role = types.RoleStrategy
	repo.seed(key)

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyItemRequest(t, h, http.MethodDelete, "/api/v1/api-keys/non-admin", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestAPIKeyHandler_Delete_AdminCountError(t *testing.T) {
	repo := newMockAPIKeyRepo()
	adminKey := makeTestAPIKey("admin-err", "Admin Err", types.APIKeySourceAPI, true)
	adminKey.Role = types.RoleAdmin
	repo.seed(adminKey)
	repo.countFn = func(_ context.Context, _ storage.APIKeyFilter) (int, error) {
		return 0, fmt.Errorf("count error")
	}

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyItemRequest(t, h, http.MethodDelete, "/api/v1/api-keys/admin-err", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestAPIKeyHandler_Delete_AdminListError(t *testing.T) {
	repo := newMockAPIKeyRepo()
	adminKey := makeTestAPIKey("admin-lerr", "Admin ListErr", types.APIKeySourceAPI, true)
	adminKey.Role = types.RoleAdmin
	repo.seed(adminKey)
	repo.listFn = func(_ context.Context, _ storage.APIKeyFilter) ([]*types.APIKey, error) {
		return nil, fmt.Errorf("list error")
	}

	h, err := NewAPIKeyHandler(repo, apikeyLogger(), false)
	require.NoError(t, err)

	rr := doAPIKeyItemRequest(t, h, http.MethodDelete, "/api/v1/api-keys/admin-lerr", nil, apikeyAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}
