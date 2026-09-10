package handler

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// This file holds the API-key test fixtures and nothing else. The tests that
// used to live here moved to apikey_routes_test.go (proposal S4) — they drive
// the API-key endpoints, and after decomposition an endpoint is reachable only
// through the route that names it, which means driving them requires
// internal/api's route registration. internal/api imports this package, so an
// in-package test cannot import it back; apikey_routes_test.go is therefore
// `package handler_test`, which can.
//
// ⚠️ Which is why the mock below is exported despite living in a _test.go file:
// identifiers declared in package handler's test files are visible to package
// handler_test in the same directory (the standard export_test.go idiom), and
// exported is the only way that external package can set its fields.
// ⛔ It stays here rather than moving with the tests because it is not the
// API-key tests' private property — NewMockAPIKeyRepo is what rbac_ownership,
// preset, coverage_boost, coverage_edge and handler_helpers build their fixtures
// from. A copy in the external package would be a second mock drifting from
// this one.

// ---------------------------------------------------------------------------
// Mock API key repository
// ---------------------------------------------------------------------------

type MockAPIKeyRepo struct {
	CreateFn             func(ctx context.Context, key *types.APIKey) error
	GetFn                func(ctx context.Context, id string) (*types.APIKey, error)
	UpdateFn             func(ctx context.Context, key *types.APIKey) error
	DeleteFn             func(ctx context.Context, id string) error
	ListFn               func(ctx context.Context, filter storage.APIKeyFilter) ([]*types.APIKey, error)
	CountFn              func(ctx context.Context, filter storage.APIKeyFilter) (int, error)
	UpdateLastUsedFn     func(ctx context.Context, id string) error
	DeleteBySourceExclFn func(ctx context.Context, source string, excludeIDs []string) (int64, error)
	BackfillSourceFn     func(ctx context.Context, defaultSource string) (int64, error)

	// stored keys for default implementations
	keys map[string]*types.APIKey
}

func NewMockAPIKeyRepo() *MockAPIKeyRepo {
	return &MockAPIKeyRepo{
		keys: make(map[string]*types.APIKey),
	}
}

func (r *MockAPIKeyRepo) Create(ctx context.Context, key *types.APIKey) error {
	if r.CreateFn != nil {
		return r.CreateFn(ctx, key)
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

func (r *MockAPIKeyRepo) Get(ctx context.Context, id string) (*types.APIKey, error) {
	if r.GetFn != nil {
		return r.GetFn(ctx, id)
	}
	key, ok := r.keys[id]
	if !ok {
		return nil, types.ErrNotFound
	}
	cp := *key
	return &cp, nil
}

func (r *MockAPIKeyRepo) Update(ctx context.Context, key *types.APIKey) error {
	if r.UpdateFn != nil {
		return r.UpdateFn(ctx, key)
	}
	if _, exists := r.keys[key.ID]; !exists {
		return types.ErrNotFound
	}
	key.UpdatedAt = time.Now()
	cp := *key
	r.keys[key.ID] = &cp
	return nil
}

func (r *MockAPIKeyRepo) Delete(ctx context.Context, id string) error {
	if r.DeleteFn != nil {
		return r.DeleteFn(ctx, id)
	}
	if _, exists := r.keys[id]; !exists {
		return types.ErrNotFound
	}
	delete(r.keys, id)
	return nil
}

func (r *MockAPIKeyRepo) List(ctx context.Context, filter storage.APIKeyFilter) ([]*types.APIKey, error) {
	if r.ListFn != nil {
		return r.ListFn(ctx, filter)
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

func (r *MockAPIKeyRepo) Count(ctx context.Context, filter storage.APIKeyFilter) (int, error) {
	if r.CountFn != nil {
		return r.CountFn(ctx, filter)
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

func (r *MockAPIKeyRepo) UpdateLastUsed(ctx context.Context, id string) error {
	if r.UpdateLastUsedFn != nil {
		return r.UpdateLastUsedFn(ctx, id)
	}
	return nil
}

func (r *MockAPIKeyRepo) DeleteBySourceExcluding(ctx context.Context, source string, excludeIDs []string) (int64, error) {
	if r.DeleteBySourceExclFn != nil {
		return r.DeleteBySourceExclFn(ctx, source, excludeIDs)
	}
	return 0, nil
}

func (r *MockAPIKeyRepo) BackfillSource(ctx context.Context, defaultSource string) (int64, error) {
	if r.BackfillSourceFn != nil {
		return r.BackfillSourceFn(ctx, defaultSource)
	}
	return 0, nil
}

// seed adds a key directly into the mock repo.
func (r *MockAPIKeyRepo) Seed(key *types.APIKey) {
	cp := *key
	r.keys[key.ID] = &cp
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func ApikeyLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func ApikeyAdminKey() *types.APIKey {
	return &types.APIKey{
		ID:      "admin-key-1",
		Name:    "Admin Key",
		Enabled: true,
		Role:    types.RoleAdmin,
		Source:  types.APIKeySourceAPI,
	}
}

func MakeTestAPIKey(id, name, source string, enabled bool) *types.APIKey {
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

// ---------------------------------------------------------------------------
// Tests that stayed in package handler
//
// ⚠️ These two reach toAPIKeyResponse, which is unexported, so they could not
// move to apikey_routes_test.go with the rest (proposal §2.4: a decomposition is
// a file *split*, not a move). They were never route tests — they call a pure
// conversion function and never touch a request.
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

// doAPIKeyEndpoint drives one API-key endpoint function directly, setting the
// {id} path value the mux would have set. Its callers are in
// coverage_boost_test.go, which cannot leave package handler (other tests in it
// call unexported methods) and therefore cannot route through the production
// patterns — internal/api imports this package. ⛔ It is not a route table: the caller
// names the endpoint it means, and the path string is only what the handler
// logs. Tests that want the real routing are in apikey_routes_test.go.
func doAPIKeyEndpoint(t *testing.T, fn http.HandlerFunc, method, path, id string, caller *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if caller != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, caller))
	}
	req.SetPathValue("id", id)
	rr := httptest.NewRecorder()
	fn(rr, req)
	return rr
}
