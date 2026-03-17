package config

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ===========================================================================
// In-memory mock repositories for testing (no external dependencies)
// ===========================================================================

// --- mockAPIKeyRepository ---

type mockAPIKeyRepository struct {
	mu   sync.Mutex
	keys map[string]*types.APIKey
}

func newMockAPIKeyRepo() *mockAPIKeyRepository {
	return &mockAPIKeyRepository{keys: make(map[string]*types.APIKey)}
}

func (m *mockAPIKeyRepository) Create(_ context.Context, key *types.APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[key.ID]; ok {
		return fmt.Errorf("key already exists: %s", key.ID)
	}
	clone := *key
	m.keys[key.ID] = &clone
	return nil
}

func (m *mockAPIKeyRepository) Get(_ context.Context, id string) (*types.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k, ok := m.keys[id]; ok {
		clone := *k
		return &clone, nil
	}
	return nil, types.ErrNotFound
}

func (m *mockAPIKeyRepository) Update(_ context.Context, key *types.APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[key.ID]; !ok {
		return types.ErrNotFound
	}
	clone := *key
	m.keys[key.ID] = &clone
	return nil
}

func (m *mockAPIKeyRepository) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[id]; !ok {
		return types.ErrNotFound
	}
	delete(m.keys, id)
	return nil
}

func (m *mockAPIKeyRepository) List(_ context.Context, _ storage.APIKeyFilter) ([]*types.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*types.APIKey
	for _, k := range m.keys {
		clone := *k
		out = append(out, &clone)
	}
	return out, nil
}

func (m *mockAPIKeyRepository) UpdateLastUsed(_ context.Context, _ string) error {
	return nil
}

func (m *mockAPIKeyRepository) Count(_ context.Context, _ storage.APIKeyFilter) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.keys), nil
}

func (m *mockAPIKeyRepository) DeleteBySourceExcluding(_ context.Context, source string, excludeIDs []string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	excludeSet := make(map[string]bool, len(excludeIDs))
	for _, id := range excludeIDs {
		excludeSet[id] = true
	}
	var deleted int64
	for id, k := range m.keys {
		if k.Source == source && !excludeSet[id] {
			delete(m.keys, id)
			deleted++
		}
	}
	return deleted, nil
}

func (m *mockAPIKeyRepository) BackfillSource(_ context.Context, defaultSource string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var count int64
	for _, k := range m.keys {
		if k.Source == "" {
			k.Source = defaultSource
			count++
		}
	}
	return count, nil
}

// --- mockRuleRepository ---

type mockRuleRepository struct {
	mu    sync.Mutex
	rules map[types.RuleID]*types.Rule
}

func newMockRuleRepo() *mockRuleRepository {
	return &mockRuleRepository{rules: make(map[types.RuleID]*types.Rule)}
}

func (m *mockRuleRepository) Create(_ context.Context, rule *types.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rules[rule.ID]; ok {
		return fmt.Errorf("rule already exists: %s", rule.ID)
	}
	clone := *rule
	m.rules[rule.ID] = &clone
	return nil
}

func (m *mockRuleRepository) Get(_ context.Context, id types.RuleID) (*types.Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rules[id]; ok {
		clone := *r
		return &clone, nil
	}
	return nil, types.ErrNotFound
}

func (m *mockRuleRepository) Update(_ context.Context, rule *types.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rules[rule.ID]; !ok {
		return types.ErrNotFound
	}
	clone := *rule
	m.rules[rule.ID] = &clone
	return nil
}

func (m *mockRuleRepository) Delete(_ context.Context, id types.RuleID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rules[id]; !ok {
		return types.ErrNotFound
	}
	delete(m.rules, id)
	return nil
}

func (m *mockRuleRepository) List(_ context.Context, filter storage.RuleFilter) ([]*types.Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*types.Rule
	for _, r := range m.rules {
		if filter.Source != nil && r.Source != *filter.Source {
			continue
		}
		clone := *r
		out = append(out, &clone)
	}
	return out, nil
}

func (m *mockRuleRepository) Count(_ context.Context, _ storage.RuleFilter) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rules), nil
}

func (m *mockRuleRepository) ListByChainType(_ context.Context, _ types.ChainType) ([]*types.Rule, error) {
	return nil, nil
}

func (m *mockRuleRepository) IncrementMatchCount(_ context.Context, _ types.RuleID) error {
	return nil
}

func (m *mockRuleRepository) RunInTransaction(_ context.Context, fn func(storage.RuleRepository) error) error {
	return fn(m)
}

// --- mockTemplateRepository ---

type mockTemplateRepository struct {
	mu        sync.Mutex
	templates map[string]*types.RuleTemplate
}

func newMockTemplateRepo() *mockTemplateRepository {
	return &mockTemplateRepository{templates: make(map[string]*types.RuleTemplate)}
}

func (m *mockTemplateRepository) Create(_ context.Context, tmpl *types.RuleTemplate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.templates[tmpl.ID]; ok {
		return fmt.Errorf("template already exists: %s", tmpl.ID)
	}
	clone := *tmpl
	m.templates[tmpl.ID] = &clone
	return nil
}

func (m *mockTemplateRepository) Get(_ context.Context, id string) (*types.RuleTemplate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.templates[id]; ok {
		clone := *t
		return &clone, nil
	}
	return nil, types.ErrNotFound
}

func (m *mockTemplateRepository) GetByName(_ context.Context, name string) (*types.RuleTemplate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.templates {
		if t.Name == name {
			clone := *t
			return &clone, nil
		}
	}
	return nil, types.ErrNotFound
}

func (m *mockTemplateRepository) Update(_ context.Context, tmpl *types.RuleTemplate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.templates[tmpl.ID]; !ok {
		return types.ErrNotFound
	}
	clone := *tmpl
	m.templates[tmpl.ID] = &clone
	return nil
}

func (m *mockTemplateRepository) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.templates[id]; !ok {
		return types.ErrNotFound
	}
	delete(m.templates, id)
	return nil
}

func (m *mockTemplateRepository) List(_ context.Context, filter storage.TemplateFilter) ([]*types.RuleTemplate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*types.RuleTemplate
	for _, t := range m.templates {
		if filter.Source != nil && t.Source != *filter.Source {
			continue
		}
		clone := *t
		out = append(out, &clone)
	}
	return out, nil
}

func (m *mockTemplateRepository) Count(_ context.Context, _ storage.TemplateFilter) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.templates), nil
}

// --- error repositories ---

type errorRuleRepository struct {
	listErr   error
	getErr    error
	createErr error
	updateErr error
	deleteErr error
}

func (e *errorRuleRepository) Create(_ context.Context, _ *types.Rule) error     { return e.createErr }
func (e *errorRuleRepository) Get(_ context.Context, _ types.RuleID) (*types.Rule, error) {
	if e.getErr != nil {
		return nil, e.getErr
	}
	return nil, types.ErrNotFound
}
func (e *errorRuleRepository) Update(_ context.Context, _ *types.Rule) error     { return e.updateErr }
func (e *errorRuleRepository) Delete(_ context.Context, _ types.RuleID) error    { return e.deleteErr }
func (e *errorRuleRepository) List(_ context.Context, _ storage.RuleFilter) ([]*types.Rule, error) {
	return nil, e.listErr
}
func (e *errorRuleRepository) Count(_ context.Context, _ storage.RuleFilter) (int, error) {
	return 0, nil
}
func (e *errorRuleRepository) ListByChainType(_ context.Context, _ types.ChainType) ([]*types.Rule, error) {
	return nil, nil
}
func (e *errorRuleRepository) IncrementMatchCount(_ context.Context, _ types.RuleID) error {
	return nil
}

func (e *errorRuleRepository) RunInTransaction(_ context.Context, fn func(storage.RuleRepository) error) error {
	return fn(e)
}

type errorTemplateRepository struct {
	listErr   error
	getErr    error
	createErr error
	updateErr error
	deleteErr error
}

func (e *errorTemplateRepository) Create(_ context.Context, _ *types.RuleTemplate) error {
	return e.createErr
}
func (e *errorTemplateRepository) Get(_ context.Context, _ string) (*types.RuleTemplate, error) {
	if e.getErr != nil {
		return nil, e.getErr
	}
	return nil, types.ErrNotFound
}
func (e *errorTemplateRepository) GetByName(_ context.Context, _ string) (*types.RuleTemplate, error) {
	return nil, types.ErrNotFound
}
func (e *errorTemplateRepository) Update(_ context.Context, _ *types.RuleTemplate) error {
	return e.updateErr
}
func (e *errorTemplateRepository) Delete(_ context.Context, _ string) error { return e.deleteErr }
func (e *errorTemplateRepository) List(_ context.Context, _ storage.TemplateFilter) ([]*types.RuleTemplate, error) {
	return nil, e.listErr
}
func (e *errorTemplateRepository) Count(_ context.Context, _ storage.TemplateFilter) (int, error) {
	return 0, nil
}

type errorAPIKeyRepository struct {
	getErr                  error
	createErr               error
	updateErr               error
	backfillSourceErr       error
	deleteBySourceExclErr   error
}

func (e *errorAPIKeyRepository) Create(_ context.Context, _ *types.APIKey) error { return e.createErr }
func (e *errorAPIKeyRepository) Get(_ context.Context, _ string) (*types.APIKey, error) {
	if e.getErr != nil {
		return nil, e.getErr
	}
	return nil, types.ErrNotFound
}
func (e *errorAPIKeyRepository) Update(_ context.Context, _ *types.APIKey) error { return e.updateErr }
func (e *errorAPIKeyRepository) Delete(_ context.Context, _ string) error        { return nil }
func (e *errorAPIKeyRepository) List(_ context.Context, _ storage.APIKeyFilter) ([]*types.APIKey, error) {
	return nil, nil
}
func (e *errorAPIKeyRepository) UpdateLastUsed(_ context.Context, _ string) error { return nil }
func (e *errorAPIKeyRepository) Count(_ context.Context, _ storage.APIKeyFilter) (int, error) {
	return 0, nil
}
func (e *errorAPIKeyRepository) DeleteBySourceExcluding(_ context.Context, _ string, _ []string) (int64, error) {
	return 0, e.deleteBySourceExclErr
}
func (e *errorAPIKeyRepository) BackfillSource(_ context.Context, _ string) (int64, error) {
	return 0, e.backfillSourceErr
}

// --- wrapper repos for targeted failures ---

type failUpdateAPIKeyRepo struct {
	base      storage.APIKeyRepository
	updateErr error
}

func (f *failUpdateAPIKeyRepo) Create(ctx context.Context, key *types.APIKey) error {
	return f.base.Create(ctx, key)
}
func (f *failUpdateAPIKeyRepo) Get(ctx context.Context, id string) (*types.APIKey, error) {
	return f.base.Get(ctx, id)
}
func (f *failUpdateAPIKeyRepo) Update(_ context.Context, _ *types.APIKey) error { return f.updateErr }
func (f *failUpdateAPIKeyRepo) Delete(ctx context.Context, id string) error {
	return f.base.Delete(ctx, id)
}
func (f *failUpdateAPIKeyRepo) List(ctx context.Context, filter storage.APIKeyFilter) ([]*types.APIKey, error) {
	return f.base.List(ctx, filter)
}
func (f *failUpdateAPIKeyRepo) UpdateLastUsed(ctx context.Context, id string) error {
	return f.base.UpdateLastUsed(ctx, id)
}
func (f *failUpdateAPIKeyRepo) Count(ctx context.Context, filter storage.APIKeyFilter) (int, error) {
	return f.base.Count(ctx, filter)
}
func (f *failUpdateAPIKeyRepo) DeleteBySourceExcluding(ctx context.Context, source string, excludeIDs []string) (int64, error) {
	return f.base.DeleteBySourceExcluding(ctx, source, excludeIDs)
}
func (f *failUpdateAPIKeyRepo) BackfillSource(ctx context.Context, defaultSource string) (int64, error) {
	return f.base.BackfillSource(ctx, defaultSource)
}

type failUpdateRuleRepo struct {
	base      storage.RuleRepository
	updateErr error
}

func (f *failUpdateRuleRepo) Create(ctx context.Context, rule *types.Rule) error {
	return f.base.Create(ctx, rule)
}
func (f *failUpdateRuleRepo) Get(ctx context.Context, id types.RuleID) (*types.Rule, error) {
	return f.base.Get(ctx, id)
}
func (f *failUpdateRuleRepo) Update(_ context.Context, _ *types.Rule) error { return f.updateErr }
func (f *failUpdateRuleRepo) Delete(ctx context.Context, id types.RuleID) error {
	return f.base.Delete(ctx, id)
}
func (f *failUpdateRuleRepo) List(ctx context.Context, filter storage.RuleFilter) ([]*types.Rule, error) {
	return f.base.List(ctx, filter)
}
func (f *failUpdateRuleRepo) Count(ctx context.Context, filter storage.RuleFilter) (int, error) {
	return f.base.Count(ctx, filter)
}
func (f *failUpdateRuleRepo) ListByChainType(ctx context.Context, ct types.ChainType) ([]*types.Rule, error) {
	return f.base.ListByChainType(ctx, ct)
}
func (f *failUpdateRuleRepo) IncrementMatchCount(ctx context.Context, id types.RuleID) error {
	return f.base.IncrementMatchCount(ctx, id)
}

func (f *failUpdateRuleRepo) RunInTransaction(ctx context.Context, fn func(storage.RuleRepository) error) error {
	return fn(f)
}

type failDeleteRuleRepo struct {
	base      storage.RuleRepository
	deleteErr error
}

func (f *failDeleteRuleRepo) Create(ctx context.Context, rule *types.Rule) error {
	return f.base.Create(ctx, rule)
}
func (f *failDeleteRuleRepo) Get(ctx context.Context, id types.RuleID) (*types.Rule, error) {
	return f.base.Get(ctx, id)
}
func (f *failDeleteRuleRepo) Update(ctx context.Context, rule *types.Rule) error {
	return f.base.Update(ctx, rule)
}
func (f *failDeleteRuleRepo) Delete(_ context.Context, _ types.RuleID) error { return f.deleteErr }
func (f *failDeleteRuleRepo) List(ctx context.Context, filter storage.RuleFilter) ([]*types.Rule, error) {
	return f.base.List(ctx, filter)
}
func (f *failDeleteRuleRepo) Count(ctx context.Context, filter storage.RuleFilter) (int, error) {
	return f.base.Count(ctx, filter)
}
func (f *failDeleteRuleRepo) ListByChainType(ctx context.Context, ct types.ChainType) ([]*types.Rule, error) {
	return f.base.ListByChainType(ctx, ct)
}
func (f *failDeleteRuleRepo) IncrementMatchCount(ctx context.Context, id types.RuleID) error {
	return f.base.IncrementMatchCount(ctx, id)
}

func (f *failDeleteRuleRepo) RunInTransaction(ctx context.Context, fn func(storage.RuleRepository) error) error {
	return fn(f)
}

type failUpdateTemplateRepo struct {
	base      storage.TemplateRepository
	updateErr error
}

func (f *failUpdateTemplateRepo) Create(ctx context.Context, tmpl *types.RuleTemplate) error {
	return f.base.Create(ctx, tmpl)
}
func (f *failUpdateTemplateRepo) Get(ctx context.Context, id string) (*types.RuleTemplate, error) {
	return f.base.Get(ctx, id)
}
func (f *failUpdateTemplateRepo) GetByName(ctx context.Context, name string) (*types.RuleTemplate, error) {
	return f.base.GetByName(ctx, name)
}
func (f *failUpdateTemplateRepo) Update(_ context.Context, _ *types.RuleTemplate) error {
	return f.updateErr
}
func (f *failUpdateTemplateRepo) Delete(ctx context.Context, id string) error {
	return f.base.Delete(ctx, id)
}
func (f *failUpdateTemplateRepo) List(ctx context.Context, filter storage.TemplateFilter) ([]*types.RuleTemplate, error) {
	return f.base.List(ctx, filter)
}
func (f *failUpdateTemplateRepo) Count(ctx context.Context, filter storage.TemplateFilter) (int, error) {
	return f.base.Count(ctx, filter)
}

type failDeleteTemplateRepo struct {
	base      storage.TemplateRepository
	deleteErr error
}

func (f *failDeleteTemplateRepo) Create(ctx context.Context, tmpl *types.RuleTemplate) error {
	return f.base.Create(ctx, tmpl)
}
func (f *failDeleteTemplateRepo) Get(ctx context.Context, id string) (*types.RuleTemplate, error) {
	return f.base.Get(ctx, id)
}
func (f *failDeleteTemplateRepo) GetByName(ctx context.Context, name string) (*types.RuleTemplate, error) {
	return f.base.GetByName(ctx, name)
}
func (f *failDeleteTemplateRepo) Update(ctx context.Context, tmpl *types.RuleTemplate) error {
	return f.base.Update(ctx, tmpl)
}
func (f *failDeleteTemplateRepo) Delete(_ context.Context, _ string) error { return f.deleteErr }
func (f *failDeleteTemplateRepo) List(ctx context.Context, filter storage.TemplateFilter) ([]*types.RuleTemplate, error) {
	return f.base.List(ctx, filter)
}
func (f *failDeleteTemplateRepo) Count(ctx context.Context, filter storage.TemplateFilter) (int, error) {
	return f.base.Count(ctx, filter)
}

// ===========================================================================
// Helper
// ===========================================================================

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// hexPubKey is a valid 64-char hex Ed25519 public key for test use.
const hexPubKey = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

// ===========================================================================
// NewAPIKeyInitializer
// ===========================================================================

func TestNewAPIKeyInitializer_Success(t *testing.T) {
	init, err := NewAPIKeyInitializer(newMockAPIKeyRepo(), testLogger())
	require.NoError(t, err)
	require.NotNil(t, init)
}

func TestNewAPIKeyInitializer_NilRepo(t *testing.T) {
	_, err := NewAPIKeyInitializer(nil, testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key repository is required")
}

func TestNewAPIKeyInitializer_NilLogger(t *testing.T) {
	_, err := NewAPIKeyInitializer(newMockAPIKeyRepo(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

// ===========================================================================
// APIKeyInitializer.SyncFromConfig
// ===========================================================================

func TestAPIKeySyncFromConfig_EmptyKeys(t *testing.T) {
	repo := newMockAPIKeyRepo()
	init, err := NewAPIKeyInitializer(repo, testLogger())
	require.NoError(t, err)

	err = init.SyncFromConfig(context.Background(), nil)
	assert.NoError(t, err)
}

func TestAPIKeySyncFromConfig_CreateNewKey(t *testing.T) {
	repo := newMockAPIKeyRepo()
	init, err := NewAPIKeyInitializer(repo, testLogger())
	require.NoError(t, err)

	keys := []APIKeyConfig{
		{
			ID:        "test-key-1",
			Name:      "Test Key",
			PublicKey: hexPubKey,
			Enabled:   true,
			RateLimit: 200,
			Role:      "admin",
		},
	}

	err = init.SyncFromConfig(context.Background(), keys)
	require.NoError(t, err)

	saved, err := repo.Get(context.Background(), "test-key-1")
	require.NoError(t, err)
	assert.Equal(t, "Test Key", saved.Name)
	assert.Equal(t, hexPubKey, saved.PublicKeyHex)
	assert.Equal(t, 200, saved.RateLimit)
	assert.Equal(t, types.RoleAdmin, saved.Role)
	assert.True(t, saved.Enabled)
}

func TestAPIKeySyncFromConfig_UpdateExistingKey(t *testing.T) {
	repo := newMockAPIKeyRepo()
	init, err := NewAPIKeyInitializer(repo, testLogger())
	require.NoError(t, err)

	_ = repo.Create(context.Background(), &types.APIKey{
		ID:           "test-key-1",
		Name:         "Old Name",
		PublicKeyHex: hexPubKey,
		RateLimit:    50,
		Enabled:      true,
	})

	keys := []APIKeyConfig{
		{
			ID:        "test-key-1",
			Name:      "Updated Name",
			PublicKey: hexPubKey,
			Enabled:   true,
			RateLimit: 300,
		},
	}

	err = init.SyncFromConfig(context.Background(), keys)
	require.NoError(t, err)

	saved, err := repo.Get(context.Background(), "test-key-1")
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", saved.Name)
	assert.Equal(t, 300, saved.RateLimit)
}

func TestAPIKeySyncFromConfig_SkipDisabledKey(t *testing.T) {
	repo := newMockAPIKeyRepo()
	init, err := NewAPIKeyInitializer(repo, testLogger())
	require.NoError(t, err)

	keys := []APIKeyConfig{
		{ID: "disabled-key", Name: "Disabled", Enabled: false},
	}

	err = init.SyncFromConfig(context.Background(), keys)
	require.NoError(t, err)

	_, err = repo.Get(context.Background(), "disabled-key")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestAPIKeySyncFromConfig_DefaultRateLimit(t *testing.T) {
	repo := newMockAPIKeyRepo()
	init, err := NewAPIKeyInitializer(repo, testLogger())
	require.NoError(t, err)

	keys := []APIKeyConfig{
		{ID: "default-rate", Name: "Default Rate", PublicKey: hexPubKey, Enabled: true, RateLimit: 0},
	}

	err = init.SyncFromConfig(context.Background(), keys)
	require.NoError(t, err)

	saved, err := repo.Get(context.Background(), "default-rate")
	require.NoError(t, err)
	assert.Equal(t, 100, saved.RateLimit)
}

func TestAPIKeySyncFromConfig_ResolvePublicKeyError(t *testing.T) {
	repo := newMockAPIKeyRepo()
	init, err := NewAPIKeyInitializer(repo, testLogger())
	require.NoError(t, err)

	keys := []APIKeyConfig{
		{ID: "bad-key", Name: "Bad", Enabled: true}, // no public key
	}

	err = init.SyncFromConfig(context.Background(), keys)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to sync API key bad-key")
}

func TestAPIKeySyncFromConfig_CreateError(t *testing.T) {
	repo := &errorAPIKeyRepository{createErr: fmt.Errorf("db write failed")}
	init, err := NewAPIKeyInitializer(repo, testLogger())
	require.NoError(t, err)

	keys := []APIKeyConfig{
		{ID: "test-key", Name: "Test", PublicKey: hexPubKey, Enabled: true},
	}

	err = init.SyncFromConfig(context.Background(), keys)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create key")
}

func TestAPIKeySyncFromConfig_UpdateError(t *testing.T) {
	repo := newMockAPIKeyRepo()
	_ = repo.Create(context.Background(), &types.APIKey{
		ID: "test-key", Name: "Old", PublicKeyHex: hexPubKey, Enabled: true,
	})

	init := &APIKeyInitializer{
		repo:   &failUpdateAPIKeyRepo{base: repo, updateErr: fmt.Errorf("db update failed")},
		logger: testLogger(),
	}

	keys := []APIKeyConfig{
		{ID: "test-key", Name: "Updated", PublicKey: hexPubKey, Enabled: true},
	}

	err := init.SyncFromConfig(context.Background(), keys)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update key")
}

func TestAPIKeySyncFromConfig_GetError(t *testing.T) {
	repo := &errorAPIKeyRepository{getErr: fmt.Errorf("db read failed")}
	init, err := NewAPIKeyInitializer(repo, testLogger())
	require.NoError(t, err)

	keys := []APIKeyConfig{
		{ID: "test-key", Name: "Test", PublicKey: hexPubKey, Enabled: true},
	}

	err = init.SyncFromConfig(context.Background(), keys)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check existing key")
}

func TestAPIKeySyncFromConfig_MultipleKeys(t *testing.T) {
	repo := newMockAPIKeyRepo()
	init, err := NewAPIKeyInitializer(repo, testLogger())
	require.NoError(t, err)

	keys := []APIKeyConfig{
		{ID: "key1", Name: "Key 1", PublicKey: hexPubKey, Enabled: true},
		{ID: "key2", Name: "Key 2", PublicKey: hexPubKey, Enabled: true},
		{ID: "key3", Name: "Key 3", Enabled: false},
	}

	err = init.SyncFromConfig(context.Background(), keys)
	require.NoError(t, err)

	_, err = repo.Get(context.Background(), "key1")
	assert.NoError(t, err)
	_, err = repo.Get(context.Background(), "key2")
	assert.NoError(t, err)
	_, err = repo.Get(context.Background(), "key3")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

// ===========================================================================
// APIKeyInitializer.SyncFromConfig - Source management tests
// ===========================================================================

func TestAPIKeyInitializer_SyncFromConfig_BackfillSource(t *testing.T) {
	// Existing keys with empty source should get backfilled to "config"
	repo := newMockAPIKeyRepo()
	ctx := context.Background()

	// Pre-populate with keys that have empty source (simulating legacy data)
	_ = repo.Create(ctx, &types.APIKey{
		ID: "legacy-key-1", Name: "Legacy 1", PublicKeyHex: hexPubKey, Enabled: true, Source: "",
	})
	_ = repo.Create(ctx, &types.APIKey{
		ID: "legacy-key-2", Name: "Legacy 2", PublicKeyHex: hexPubKey, Enabled: true, Source: "",
	})

	init, err := NewAPIKeyInitializer(repo, testLogger())
	require.NoError(t, err)

	// Sync with config that includes one of the legacy keys
	keys := []APIKeyConfig{
		{ID: "legacy-key-1", Name: "Legacy 1 Updated", PublicKey: hexPubKey, Enabled: true},
	}
	err = init.SyncFromConfig(ctx, keys)
	require.NoError(t, err)

	// Both legacy keys should now have source="config" (backfill runs first)
	k1, err := repo.Get(ctx, "legacy-key-1")
	require.NoError(t, err)
	assert.Equal(t, types.APIKeySourceConfig, k1.Source)

	// legacy-key-2 was backfilled to "config" then deleted as stale
	_, err = repo.Get(ctx, "legacy-key-2")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestAPIKeyInitializer_SyncFromConfig_DeletesStaleConfigKeys(t *testing.T) {
	// Config has [A, B], DB has [A, B, C] (source=config) -> C gets deleted
	repo := newMockAPIKeyRepo()
	ctx := context.Background()

	_ = repo.Create(ctx, &types.APIKey{
		ID: "key-a", Name: "A", PublicKeyHex: hexPubKey, Enabled: true, Source: types.APIKeySourceConfig,
	})
	_ = repo.Create(ctx, &types.APIKey{
		ID: "key-b", Name: "B", PublicKeyHex: hexPubKey, Enabled: true, Source: types.APIKeySourceConfig,
	})
	_ = repo.Create(ctx, &types.APIKey{
		ID: "key-c", Name: "C", PublicKeyHex: hexPubKey, Enabled: true, Source: types.APIKeySourceConfig,
	})

	init, err := NewAPIKeyInitializer(repo, testLogger())
	require.NoError(t, err)

	keys := []APIKeyConfig{
		{ID: "key-a", Name: "A", PublicKey: hexPubKey, Enabled: true},
		{ID: "key-b", Name: "B", PublicKey: hexPubKey, Enabled: true},
	}
	err = init.SyncFromConfig(ctx, keys)
	require.NoError(t, err)

	// A and B should still exist
	_, err = repo.Get(ctx, "key-a")
	assert.NoError(t, err)
	_, err = repo.Get(ctx, "key-b")
	assert.NoError(t, err)

	// C should be deleted (stale config key)
	_, err = repo.Get(ctx, "key-c")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestAPIKeyInitializer_SyncFromConfig_PreservesAPIKeys(t *testing.T) {
	// Config has [A], DB has [A(config), B(api)] -> B preserved
	repo := newMockAPIKeyRepo()
	ctx := context.Background()

	_ = repo.Create(ctx, &types.APIKey{
		ID: "key-a", Name: "A", PublicKeyHex: hexPubKey, Enabled: true, Source: types.APIKeySourceConfig,
	})
	_ = repo.Create(ctx, &types.APIKey{
		ID: "key-b", Name: "B API", PublicKeyHex: hexPubKey, Enabled: true, Source: types.APIKeySourceAPI,
	})

	init, err := NewAPIKeyInitializer(repo, testLogger())
	require.NoError(t, err)

	keys := []APIKeyConfig{
		{ID: "key-a", Name: "A Updated", PublicKey: hexPubKey, Enabled: true},
	}
	err = init.SyncFromConfig(ctx, keys)
	require.NoError(t, err)

	// A should be updated
	a, err := repo.Get(ctx, "key-a")
	require.NoError(t, err)
	assert.Equal(t, "A Updated", a.Name)

	// B (source=api) should be preserved
	b, err := repo.Get(ctx, "key-b")
	require.NoError(t, err)
	assert.Equal(t, "B API", b.Name)
	assert.Equal(t, types.APIKeySourceAPI, b.Source)
}

func TestAPIKeyInitializer_SyncFromConfig_SetsSourceOnCreate(t *testing.T) {
	// New key from config gets source="config"
	repo := newMockAPIKeyRepo()
	ctx := context.Background()

	init, err := NewAPIKeyInitializer(repo, testLogger())
	require.NoError(t, err)

	keys := []APIKeyConfig{
		{ID: "new-key", Name: "New", PublicKey: hexPubKey, Enabled: true},
	}
	err = init.SyncFromConfig(ctx, keys)
	require.NoError(t, err)

	saved, err := repo.Get(ctx, "new-key")
	require.NoError(t, err)
	assert.Equal(t, types.APIKeySourceConfig, saved.Source)
}

func TestAPIKeyInitializer_SyncFromConfig_SetsSourceOnUpdate(t *testing.T) {
	// Updated key retains source="config"
	repo := newMockAPIKeyRepo()
	ctx := context.Background()

	_ = repo.Create(ctx, &types.APIKey{
		ID: "existing-key", Name: "Old", PublicKeyHex: hexPubKey, Enabled: true, Source: types.APIKeySourceConfig,
	})

	init, err := NewAPIKeyInitializer(repo, testLogger())
	require.NoError(t, err)

	keys := []APIKeyConfig{
		{ID: "existing-key", Name: "Updated", PublicKey: hexPubKey, Enabled: true},
	}
	err = init.SyncFromConfig(ctx, keys)
	require.NoError(t, err)

	saved, err := repo.Get(ctx, "existing-key")
	require.NoError(t, err)
	assert.Equal(t, "Updated", saved.Name)
	assert.Equal(t, types.APIKeySourceConfig, saved.Source)
}

func TestAPIKeyInitializer_SyncFromConfig_BackfillError(t *testing.T) {
	// BackfillSource returns error -> SyncFromConfig fails
	repo := &errorAPIKeyRepository{backfillSourceErr: fmt.Errorf("backfill db error")}
	init, err := NewAPIKeyInitializer(repo, testLogger())
	require.NoError(t, err)

	keys := []APIKeyConfig{
		{ID: "test-key", Name: "Test", PublicKey: hexPubKey, Enabled: true},
	}
	err = init.SyncFromConfig(context.Background(), keys)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to backfill source")
	assert.Contains(t, err.Error(), "backfill db error")
}

func TestAPIKeyInitializer_SyncFromConfig_DeleteStaleError(t *testing.T) {
	// DeleteBySourceExcluding returns error -> SyncFromConfig fails
	repo := &errorAPIKeyRepository{deleteBySourceExclErr: fmt.Errorf("delete stale db error")}
	init, err := NewAPIKeyInitializer(repo, testLogger())
	require.NoError(t, err)

	keys := []APIKeyConfig{
		{ID: "test-key", Name: "Test", PublicKey: hexPubKey, Enabled: true},
	}
	err = init.SyncFromConfig(context.Background(), keys)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to clean stale config keys")
	assert.Contains(t, err.Error(), "delete stale db error")
}

// ===========================================================================
// NewRuleInitializer
// ===========================================================================

func TestNewRuleInitializer_Success(t *testing.T) {
	ri, err := NewRuleInitializer(newMockRuleRepo(), testLogger())
	require.NoError(t, err)
	require.NotNil(t, ri)
}

func TestNewRuleInitializer_NilRepo(t *testing.T) {
	_, err := NewRuleInitializer(nil, testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rule repository is required")
}

func TestNewRuleInitializer_NilLogger(t *testing.T) {
	_, err := NewRuleInitializer(newMockRuleRepo(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

// ===========================================================================
// RuleInitializer.SetConfigDir
// ===========================================================================

func TestRuleInitializer_SetConfigDir(t *testing.T) {
	ri, err := NewRuleInitializer(newMockRuleRepo(), testLogger())
	require.NoError(t, err)
	assert.Equal(t, ".", ri.configDir)
	ri.SetConfigDir("/custom/dir")
	assert.Equal(t, "/custom/dir", ri.configDir)
}

// ===========================================================================
// EffectiveRuleID / generateRuleID / effectiveRuleID
// ===========================================================================

func TestEffectiveRuleID_WithCustomID(t *testing.T) {
	ruleCfg := RuleConfig{Id: "my-custom-id", Name: "Test", Type: "evm_address_list"}
	id := EffectiveRuleID(0, ruleCfg)
	assert.Equal(t, types.RuleID("my-custom-id"), id)
}

func TestEffectiveRuleID_WithCustomIDWhitespace(t *testing.T) {
	ruleCfg := RuleConfig{Id: "  spaced-id  ", Name: "Test", Type: "evm_address_list"}
	id := EffectiveRuleID(0, ruleCfg)
	assert.Equal(t, types.RuleID("spaced-id"), id)
}

func TestEffectiveRuleID_WithEmptyID(t *testing.T) {
	ruleCfg := RuleConfig{Name: "Test", Type: "evm_address_list"}
	id := EffectiveRuleID(0, ruleCfg)
	assert.True(t, len(string(id)) > 0)
	assert.Contains(t, string(id), "cfg_")
}

func TestEffectiveRuleID_Deterministic(t *testing.T) {
	ruleCfg := RuleConfig{Name: "Test", Type: "evm_address_list"}
	id1 := EffectiveRuleID(0, ruleCfg)
	id2 := EffectiveRuleID(0, ruleCfg)
	assert.Equal(t, id1, id2)
}

func TestEffectiveRuleID_DifferentIndex(t *testing.T) {
	ruleCfg := RuleConfig{Name: "Test", Type: "evm_address_list"}
	id0 := EffectiveRuleID(0, ruleCfg)
	id1 := EffectiveRuleID(1, ruleCfg)
	assert.NotEqual(t, id0, id1)
}

func TestRuleInitializer_generateRuleID(t *testing.T) {
	ri, err := NewRuleInitializer(newMockRuleRepo(), testLogger())
	require.NoError(t, err)
	ruleCfg := RuleConfig{Name: "Test", Type: "evm_address_list"}
	id := ri.generateRuleID(0, ruleCfg)
	expected := EffectiveRuleID(0, ruleCfg)
	assert.Equal(t, expected, id)
}

func TestRuleInitializer_effectiveRuleID(t *testing.T) {
	ri, err := NewRuleInitializer(newMockRuleRepo(), testLogger())
	require.NoError(t, err)
	ruleCfg := RuleConfig{Id: "explicit-id", Name: "Test", Type: "evm_address_list"}
	id := ri.effectiveRuleID(0, ruleCfg)
	assert.Equal(t, types.RuleID("explicit-id"), id)
}

// ===========================================================================
// RuleInitializer.SyncFromConfig
// ===========================================================================

func TestRuleSyncFromConfig_EmptyRules(t *testing.T) {
	repo := newMockRuleRepo()
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)

	err = ri.SyncFromConfig(context.Background(), nil)
	assert.NoError(t, err)
}

func TestRuleSyncFromConfig_CreateNewRule(t *testing.T) {
	repo := newMockRuleRepo()
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)

	rules := []RuleConfig{
		{
			Id: "allow-addr", Name: "Allow Addr", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}},
		},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.NoError(t, err)

	ruleID := EffectiveRuleID(0, rules[0])
	saved, err := repo.Get(context.Background(), ruleID)
	require.NoError(t, err)
	assert.Equal(t, "Allow Addr", saved.Name)
	assert.Equal(t, types.RuleType("evm_address_list"), saved.Type)
	assert.Equal(t, types.RuleMode("whitelist"), saved.Mode)
	assert.Equal(t, types.RuleSourceConfig, saved.Source)
}

func TestRuleSyncFromConfig_UpdateExistingRule(t *testing.T) {
	repo := newMockRuleRepo()
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)

	rules := []RuleConfig{
		{
			Id: "rule-1", Name: "Rule 1", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}},
		},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.NoError(t, err)

	rules[0].Name = "Rule 1 Updated"
	err = ri.SyncFromConfig(context.Background(), rules)
	require.NoError(t, err)

	ruleID := EffectiveRuleID(0, rules[0])
	saved, err := repo.Get(context.Background(), ruleID)
	require.NoError(t, err)
	assert.Equal(t, "Rule 1 Updated", saved.Name)
}

func TestRuleSyncFromConfig_DeleteStaleRules(t *testing.T) {
	repo := newMockRuleRepo()
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)

	rules := []RuleConfig{
		{
			Id: "a", Name: "A", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}},
		},
		{
			Id: "b", Name: "B", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}},
		},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.NoError(t, err)

	// Now remove B
	err = ri.SyncFromConfig(context.Background(), rules[:1])
	require.NoError(t, err)

	ruleAID := EffectiveRuleID(0, rules[0])
	_, err = repo.Get(context.Background(), ruleAID)
	assert.NoError(t, err)

	ruleBID := EffectiveRuleID(1, rules[1])
	_, err = repo.Get(context.Background(), ruleBID)
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestRuleSyncFromConfig_SkipDisabledRule(t *testing.T) {
	repo := newMockRuleRepo()
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)

	rules := []RuleConfig{
		{
			Id: "disabled", Name: "Disabled", Type: "evm_address_list", Mode: "whitelist", Enabled: false,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}},
		},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.NoError(t, err)

	ruleID := EffectiveRuleID(0, rules[0])
	_, err = repo.Get(context.Background(), ruleID)
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestRuleSyncFromConfig_InvalidMode(t *testing.T) {
	repo := newMockRuleRepo()
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)

	rules := []RuleConfig{
		{
			Id: "bad-mode", Name: "Bad Mode", Type: "evm_address_list", Mode: "invalid_mode", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}},
		},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mode")
}

func TestRuleSyncFromConfig_DuplicateRuleIDs(t *testing.T) {
	repo := newMockRuleRepo()
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)

	rules := []RuleConfig{
		{Id: "dup-id", Name: "R1", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}}},
		{Id: "dup-id", Name: "R2", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}}},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate rule id")
}

func TestRuleSyncFromConfig_WithCustomID(t *testing.T) {
	repo := newMockRuleRepo()
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)

	rules := []RuleConfig{
		{
			Id: "stable-rule", Name: "Stable", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}},
		},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.NoError(t, err)

	saved, err := repo.Get(context.Background(), "stable-rule")
	require.NoError(t, err)
	assert.Equal(t, types.RuleID("stable-rule"), saved.ID)
}

func TestRuleSyncFromConfig_WithScopeFields(t *testing.T) {
	repo := newMockRuleRepo()
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)

	rules := []RuleConfig{
		{
			Id: "scoped", Name: "Scoped", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			ChainType: "evm", ChainID: "1", APIKeyID: "api-key-1",
			SignerAddress: "0x1234567890abcdef1234567890abcdef12345678",
			Config:        map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}},
		},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.NoError(t, err)

	ruleID := EffectiveRuleID(0, rules[0])
	saved, err := repo.Get(context.Background(), ruleID)
	require.NoError(t, err)
	require.NotNil(t, saved.ChainType)
	assert.Equal(t, types.ChainType("evm"), *saved.ChainType)
	require.NotNil(t, saved.ChainID)
	assert.Equal(t, "1", *saved.ChainID)
	assert.Equal(t, "config", saved.Owner)
	assert.Equal(t, []string{"*"}, []string(saved.AppliedTo))
	assert.Equal(t, types.RuleStatusActive, saved.Status)
	require.NotNil(t, saved.SignerAddress)
}

func TestRuleSyncFromConfig_DefaultChainTypeEVM(t *testing.T) {
	repo := newMockRuleRepo()
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)

	rules := []RuleConfig{
		{
			Id: "no-chain", Name: "No Chain", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}},
		},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.NoError(t, err)

	ruleID := EffectiveRuleID(0, rules[0])
	saved, err := repo.Get(context.Background(), ruleID)
	require.NoError(t, err)
	require.NotNil(t, saved.ChainType)
	assert.Equal(t, types.ChainTypeEVM, *saved.ChainType)
}

func TestRuleSyncFromConfig_InvalidChainType(t *testing.T) {
	repo := newMockRuleRepo()
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)

	rules := []RuleConfig{
		{
			Id: "bad-chain", Name: "Bad Chain", Type: "evm_address_list", Mode: "whitelist", ChainType: "not_a_chain", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}},
		},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid chain_type")
}

func TestRuleSyncFromConfig_InvalidSignerAddress(t *testing.T) {
	repo := newMockRuleRepo()
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)

	rules := []RuleConfig{
		{
			Id: "bad-signer", Name: "Bad Signer", Type: "evm_address_list", Mode: "whitelist", SignerAddress: "not-an-address", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}},
		},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signer_address")
}

func TestRuleSyncFromConfig_WithVariables(t *testing.T) {
	repo := newMockRuleRepo()
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)

	rules := []RuleConfig{
		{
			Id: "with-vars", Name: "With Vars", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			Config:    map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}},
			Variables: map[string]interface{}{"chain_id": "1", "label": "mainnet"},
		},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.NoError(t, err)

	ruleID := EffectiveRuleID(0, rules[0])
	saved, err := repo.Get(context.Background(), ruleID)
	require.NoError(t, err)
	require.NotNil(t, saved.Variables)
	var vars map[string]interface{}
	err = json.Unmarshal(saved.Variables, &vars)
	require.NoError(t, err)
	assert.Equal(t, "1", vars["chain_id"])
}

func TestRuleSyncFromConfig_ListError(t *testing.T) {
	repo := &errorRuleRepository{listErr: fmt.Errorf("db list failed")}
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)

	rules := []RuleConfig{
		{Id: "test", Name: "Test", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}}},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list config rules")
}

func TestRuleSyncFromConfig_FileRulesFromFile(t *testing.T) {
	dir := t.TempDir()
	ruleFile := filepath.Join(dir, "rules.yaml")
	ruleYAML := `
rules:
  - id: "file-rule"
    name: "File Rule"
    type: "evm_address_list"
    mode: "whitelist"
    enabled: true
    config:
      addresses:
        - "0x1234567890abcdef1234567890abcdef12345678"
`
	require.NoError(t, os.WriteFile(ruleFile, []byte(ruleYAML), 0644))

	repo := newMockRuleRepo()
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)
	ri.SetConfigDir(dir)

	rules := []RuleConfig{
		{Name: "Include File", Type: RuleFileType, Config: map[string]interface{}{"path": "rules.yaml"}},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.NoError(t, err)
	assert.Equal(t, 1, len(repo.rules))
}

func TestRuleSyncFromConfig_CreateError(t *testing.T) {
	repo := &errorRuleRepository{createErr: fmt.Errorf("db create failed")}
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)

	rules := []RuleConfig{
		{Id: "test", Name: "Test", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}}},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create rule")
}

func TestRuleSyncFromConfig_GetNonNotFoundError(t *testing.T) {
	repo := &errorRuleRepository{getErr: fmt.Errorf("db read failed")}
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)

	rules := []RuleConfig{
		{Id: "test", Name: "Test", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}}},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check existing rule")
}

func TestRuleSyncFromConfig_UpdateError(t *testing.T) {
	baseRepo := newMockRuleRepo()
	ri, err := NewRuleInitializer(baseRepo, testLogger())
	require.NoError(t, err)

	rules := []RuleConfig{
		{Id: "test", Name: "Test", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}}},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.NoError(t, err)

	ri2 := &RuleInitializer{
		repo:      &failUpdateRuleRepo{base: baseRepo, updateErr: fmt.Errorf("db update failed")},
		logger:    testLogger(),
		configDir: ".",
	}

	err = ri2.SyncFromConfig(context.Background(), rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update rule")
}

func TestRuleSyncFromConfig_DeleteError(t *testing.T) {
	repo := newMockRuleRepo()
	ri, err := NewRuleInitializer(repo, testLogger())
	require.NoError(t, err)

	rules := []RuleConfig{
		{Id: "to-delete", Name: "To Delete", Type: "evm_address_list", Mode: "whitelist", Enabled: true,
			Config: map[string]interface{}{"addresses": []interface{}{"0x1234567890abcdef1234567890abcdef12345678"}}},
	}

	err = ri.SyncFromConfig(context.Background(), rules)
	require.NoError(t, err)

	ri2 := &RuleInitializer{
		repo:      &failDeleteRuleRepo{base: repo, deleteErr: fmt.Errorf("db delete failed")},
		logger:    testLogger(),
		configDir: ".",
	}

	err = ri2.SyncFromConfig(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete stale config rule")
}

// ===========================================================================
// loadRulesFromFile (instance method)
// ===========================================================================

func TestRuleInitializer_loadRulesFromFile(t *testing.T) {
	dir := t.TempDir()
	ruleFile := filepath.Join(dir, "rules.yaml")
	ruleYAML := `
rules:
  - name: "Loaded Rule"
    type: "evm_address_list"
    mode: "whitelist"
    enabled: true
    config:
      addresses:
        - "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
`
	require.NoError(t, os.WriteFile(ruleFile, []byte(ruleYAML), 0644))

	ri, err := NewRuleInitializer(newMockRuleRepo(), testLogger())
	require.NoError(t, err)
	ri.SetConfigDir(dir)

	fileCfg := RuleConfig{
		Name: "File Include", Type: RuleFileType,
		Config: map[string]interface{}{"path": "rules.yaml"},
	}

	loaded, err := ri.loadRulesFromFile(fileCfg)
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "Loaded Rule", loaded[0].Name)
}

// ===========================================================================
// loadRulesFromFileStatic error cases (not already in rule_init_test.go)
// ===========================================================================

func TestLoadRulesFromFileStatic_NonStringPath(t *testing.T) {
	cfg := RuleConfig{
		Name: "Bad Path", Type: RuleFileType,
		Config: map[string]interface{}{"path": 42},
	}
	_, err := loadRulesFromFileStatic(cfg, ".", testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path must be a string")
}

func TestLoadRulesFromFileStatic_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(f, []byte("{{invalid"), 0644))

	cfg := RuleConfig{
		Name: "Bad YAML", Type: RuleFileType,
		Config: map[string]interface{}{"path": f},
	}
	_, err := loadRulesFromFileStatic(cfg, ".", testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse rule file")
}

func TestLoadRulesFromFileStatic_NilLogger(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "rules.yaml")
	require.NoError(t, os.WriteFile(f, []byte("rules:\n  - name: R\n    type: evm_address_list\n    mode: whitelist\n    enabled: true\n    config:\n      addresses:\n        - \"0x1234567890abcdef1234567890abcdef12345678\"\n"), 0644))

	cfg := RuleConfig{
		Name: "Rule", Type: RuleFileType,
		Config: map[string]interface{}{"path": "rules.yaml"},
	}
	result, err := loadRulesFromFileStatic(cfg, dir, nil)
	require.NoError(t, err)
	require.Len(t, result, 1)
}

// ===========================================================================
// expandFileRulesWithDepth - direct call
// ===========================================================================

func TestExpandFileRulesWithDepth_MaxDepthDirect(t *testing.T) {
	_, err := expandFileRulesWithDepth(nil, ".", testLogger(), 11, 10)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum rule file inclusion depth")
}

// ===========================================================================
// NewTemplateInitializer
// ===========================================================================

func TestNewTemplateInitializer_Success(t *testing.T) {
	ti, err := NewTemplateInitializer(newMockTemplateRepo(), testLogger())
	require.NoError(t, err)
	require.NotNil(t, ti)
}

func TestNewTemplateInitializer_NilRepo(t *testing.T) {
	_, err := NewTemplateInitializer(nil, testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "template repository is required")
}

func TestNewTemplateInitializer_NilLogger(t *testing.T) {
	_, err := NewTemplateInitializer(newMockTemplateRepo(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

// ===========================================================================
// TemplateInitializer.SetConfigDir
// ===========================================================================

func TestTemplateInitializer_SetConfigDir(t *testing.T) {
	ti, err := NewTemplateInitializer(newMockTemplateRepo(), testLogger())
	require.NoError(t, err)
	assert.Equal(t, ".", ti.configDir)
	ti.SetConfigDir("/custom/dir")
	assert.Equal(t, "/custom/dir", ti.configDir)
}

// ===========================================================================
// TemplateInitializer.generateTemplateID
// ===========================================================================

func TestTemplateInitializer_generateTemplateID_Deterministic(t *testing.T) {
	ti, err := NewTemplateInitializer(newMockTemplateRepo(), testLogger())
	require.NoError(t, err)
	tmpl := TemplateConfig{Name: "Test", Type: "evm_js"}
	id1 := ti.generateTemplateID(0, tmpl)
	id2 := ti.generateTemplateID(0, tmpl)
	assert.Equal(t, id1, id2)
	assert.Contains(t, id1, "tmpl_cfg_")
}

func TestTemplateInitializer_generateTemplateID_DifferentIndex(t *testing.T) {
	ti, err := NewTemplateInitializer(newMockTemplateRepo(), testLogger())
	require.NoError(t, err)
	tmpl := TemplateConfig{Name: "Test", Type: "evm_js"}
	id0 := ti.generateTemplateID(0, tmpl)
	id1 := ti.generateTemplateID(1, tmpl)
	assert.NotEqual(t, id0, id1)
}

// ===========================================================================
// TemplateInitializer.SyncFromConfig
// ===========================================================================

func TestTemplateSyncFromConfig_EmptyTemplates(t *testing.T) {
	repo := newMockTemplateRepo()
	ti, err := NewTemplateInitializer(repo, testLogger())
	require.NoError(t, err)
	err = ti.SyncFromConfig(context.Background(), nil)
	assert.NoError(t, err)
}

func TestTemplateSyncFromConfig_CreateNewTemplate(t *testing.T) {
	repo := newMockTemplateRepo()
	ti, err := NewTemplateInitializer(repo, testLogger())
	require.NoError(t, err)

	templates := []TemplateConfig{
		{
			Name: "My Template", Description: "Desc", Type: "evm_js", Mode: "whitelist", Enabled: true,
			Config:    map[string]interface{}{"expression": "true"},
			Variables: []TemplateVarConfig{{Name: "chain_id", Type: "string", Required: true}},
		},
	}

	err = ti.SyncFromConfig(context.Background(), templates)
	require.NoError(t, err)
	assert.Equal(t, 1, len(repo.templates))

	for _, tmpl := range repo.templates {
		assert.Equal(t, "My Template", tmpl.Name)
		assert.Equal(t, types.RuleType("evm_js"), tmpl.Type)
		assert.Equal(t, types.RuleSourceConfig, tmpl.Source)
	}
}

func TestTemplateSyncFromConfig_UpdateExisting(t *testing.T) {
	repo := newMockTemplateRepo()
	ti, err := NewTemplateInitializer(repo, testLogger())
	require.NoError(t, err)

	templates := []TemplateConfig{
		{Name: "T1", Type: "evm_js", Mode: "whitelist", Enabled: true,
			Config: map[string]interface{}{"expression": "true"}},
	}

	err = ti.SyncFromConfig(context.Background(), templates)
	require.NoError(t, err)

	templates[0].Name = "T1 Updated"
	err = ti.SyncFromConfig(context.Background(), templates)
	require.NoError(t, err)

	for _, tmpl := range repo.templates {
		assert.Equal(t, "T1 Updated", tmpl.Name)
	}
}

func TestTemplateSyncFromConfig_DeleteStaleTemplates(t *testing.T) {
	repo := newMockTemplateRepo()
	ti, err := NewTemplateInitializer(repo, testLogger())
	require.NoError(t, err)

	templates := []TemplateConfig{
		{Name: "A", Type: "evm_js", Mode: "whitelist", Enabled: true, Config: map[string]interface{}{"expression": "true"}},
		{Name: "B", Type: "evm_js", Mode: "blocklist", Enabled: true, Config: map[string]interface{}{"expression": "false"}},
	}

	err = ti.SyncFromConfig(context.Background(), templates)
	require.NoError(t, err)
	assert.Equal(t, 2, len(repo.templates))

	err = ti.SyncFromConfig(context.Background(), templates[:1])
	require.NoError(t, err)
	assert.Equal(t, 1, len(repo.templates))
}

func TestTemplateSyncFromConfig_SkipDisabled(t *testing.T) {
	repo := newMockTemplateRepo()
	ti, err := NewTemplateInitializer(repo, testLogger())
	require.NoError(t, err)

	templates := []TemplateConfig{
		{Name: "Disabled", Type: "evm_js", Mode: "whitelist", Enabled: false, Config: map[string]interface{}{"expression": "true"}},
	}

	err = ti.SyncFromConfig(context.Background(), templates)
	require.NoError(t, err)
	assert.Equal(t, 0, len(repo.templates))
}

func TestTemplateSyncFromConfig_InvalidMode(t *testing.T) {
	repo := newMockTemplateRepo()
	ti, err := NewTemplateInitializer(repo, testLogger())
	require.NoError(t, err)

	templates := []TemplateConfig{
		{Name: "Bad Mode", Type: "evm_js", Mode: "invalid", Enabled: true, Config: map[string]interface{}{"expression": "true"}},
	}

	err = ti.SyncFromConfig(context.Background(), templates)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mode")
}

func TestTemplateSyncFromConfig_InvalidType(t *testing.T) {
	repo := newMockTemplateRepo()
	ti, err := NewTemplateInitializer(repo, testLogger())
	require.NoError(t, err)

	templates := []TemplateConfig{
		{Name: "Bad Type", Type: "unknown_type", Mode: "whitelist", Enabled: true, Config: map[string]interface{}{"expression": "true"}},
	}

	err = ti.SyncFromConfig(context.Background(), templates)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown type")
}

func TestTemplateSyncFromConfig_TemplateBundleType(t *testing.T) {
	repo := newMockTemplateRepo()
	ti, err := NewTemplateInitializer(repo, testLogger())
	require.NoError(t, err)

	templates := []TemplateConfig{
		{Name: "Bundle", Type: "template_bundle", Mode: "whitelist", Enabled: true, Config: map[string]interface{}{"rules_json": "[]"}},
	}

	err = ti.SyncFromConfig(context.Background(), templates)
	require.NoError(t, err)
	assert.Equal(t, 1, len(repo.templates))
}

func TestTemplateSyncFromConfig_ListError(t *testing.T) {
	repo := &errorTemplateRepository{listErr: fmt.Errorf("db list failed")}
	ti, err := NewTemplateInitializer(repo, testLogger())
	require.NoError(t, err)

	templates := []TemplateConfig{
		{Name: "Test", Type: "evm_js", Mode: "whitelist", Enabled: true, Config: map[string]interface{}{"expression": "true"}},
	}

	err = ti.SyncFromConfig(context.Background(), templates)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list config templates")
}

func TestTemplateSyncFromConfig_CreateError(t *testing.T) {
	repo := &errorTemplateRepository{createErr: fmt.Errorf("db create failed")}
	ti, err := NewTemplateInitializer(repo, testLogger())
	require.NoError(t, err)

	templates := []TemplateConfig{
		{Name: "Test", Type: "evm_js", Mode: "whitelist", Enabled: true, Config: map[string]interface{}{"expression": "true"}},
	}

	err = ti.SyncFromConfig(context.Background(), templates)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create template")
}

func TestTemplateSyncFromConfig_UpdateError(t *testing.T) {
	baseRepo := newMockTemplateRepo()
	ti, err := NewTemplateInitializer(baseRepo, testLogger())
	require.NoError(t, err)

	templates := []TemplateConfig{
		{Name: "Test", Type: "evm_js", Mode: "whitelist", Enabled: true, Config: map[string]interface{}{"expression": "true"}},
	}

	err = ti.SyncFromConfig(context.Background(), templates)
	require.NoError(t, err)

	ti2 := &TemplateInitializer{
		repo:      &failUpdateTemplateRepo{base: baseRepo, updateErr: fmt.Errorf("db update failed")},
		logger:    testLogger(),
		configDir: ".",
	}

	err = ti2.SyncFromConfig(context.Background(), templates)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update template")
}

func TestTemplateSyncFromConfig_GetNonNotFoundError(t *testing.T) {
	repo := &errorTemplateRepository{getErr: fmt.Errorf("db read failed")}
	ti, err := NewTemplateInitializer(repo, testLogger())
	require.NoError(t, err)

	templates := []TemplateConfig{
		{Name: "Test", Type: "evm_js", Mode: "whitelist", Enabled: true, Config: map[string]interface{}{"expression": "true"}},
	}

	err = ti.SyncFromConfig(context.Background(), templates)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check existing template")
}

func TestTemplateSyncFromConfig_DeleteError(t *testing.T) {
	repo := newMockTemplateRepo()
	ti, err := NewTemplateInitializer(repo, testLogger())
	require.NoError(t, err)

	templates := []TemplateConfig{
		{Name: "To Delete", Type: "evm_js", Mode: "whitelist", Enabled: true, Config: map[string]interface{}{"expression": "true"}},
	}

	err = ti.SyncFromConfig(context.Background(), templates)
	require.NoError(t, err)

	ti2 := &TemplateInitializer{
		repo:      &failDeleteTemplateRepo{base: repo, deleteErr: fmt.Errorf("db delete failed")},
		logger:    testLogger(),
		configDir: ".",
	}

	err = ti2.SyncFromConfig(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete stale config template")
}

func TestTemplateSyncFromConfig_WithBudgetAndTestVars(t *testing.T) {
	repo := newMockTemplateRepo()
	ti, err := NewTemplateInitializer(repo, testLogger())
	require.NoError(t, err)

	templates := []TemplateConfig{
		{
			Name: "Budget", Type: "evm_js", Mode: "whitelist", Enabled: true,
			Config:         map[string]interface{}{"expression": "true"},
			BudgetMetering: map[string]interface{}{"method": "tx_value", "unit": "eth"},
			TestVariables:  map[string]string{"chain_id": "1"},
		},
	}

	err = ti.SyncFromConfig(context.Background(), templates)
	require.NoError(t, err)

	for _, tmpl := range repo.templates {
		assert.NotNil(t, tmpl.BudgetMetering)
		assert.NotNil(t, tmpl.TestVariables)
	}
}

// ===========================================================================
// TemplateInitializer.expandFileTemplates and loadTemplateFromFile
// ===========================================================================

func TestTemplateInitializer_expandFileTemplates(t *testing.T) {
	dir := t.TempDir()
	tmplFile := filepath.Join(dir, "template.yaml")
	tmplYAML := `
variables:
  - name: chain_id
    type: string
    required: true
rules:
  - name: "Template Rule"
    type: "evm_address_list"
    mode: "whitelist"
    enabled: true
    config:
      addresses:
        - "0x1234567890abcdef1234567890abcdef12345678"
`
	require.NoError(t, os.WriteFile(tmplFile, []byte(tmplYAML), 0644))

	ti, err := NewTemplateInitializer(newMockTemplateRepo(), testLogger())
	require.NoError(t, err)
	ti.SetConfigDir(dir)

	templates := []TemplateConfig{
		{Name: "File Template", Type: TemplateFileType, Enabled: true,
			Config: map[string]interface{}{"path": "template.yaml"}},
	}

	expanded, err := ti.expandFileTemplates(templates)
	require.NoError(t, err)
	require.Len(t, expanded, 1)
	assert.Equal(t, "File Template", expanded[0].Name)
	assert.Equal(t, "template_bundle", expanded[0].Type)
}

func TestTemplateInitializer_loadTemplateFromFile(t *testing.T) {
	dir := t.TempDir()
	tmplFile := filepath.Join(dir, "template.yaml")
	tmplYAML := `
variables:
  - name: addr
    type: address
    required: true
budget_metering:
  method: count_only
  unit: auth
test_variables:
  addr: "0x1234567890abcdef1234567890abcdef12345678"
rules:
  - name: "Inner Rule"
    type: "evm_address_list"
    mode: "whitelist"
    enabled: true
    config:
      addresses:
        - "${addr}"
`
	require.NoError(t, os.WriteFile(tmplFile, []byte(tmplYAML), 0644))

	ti, err := NewTemplateInitializer(newMockTemplateRepo(), testLogger())
	require.NoError(t, err)
	ti.SetConfigDir(dir)

	fileCfg := TemplateConfig{
		Name: "My File Template", Description: "Desc", Type: TemplateFileType, Enabled: true,
		Config: map[string]interface{}{"path": "template.yaml"},
	}

	loaded, err := ti.loadTemplateFromFile(fileCfg)
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "My File Template", loaded[0].Name)
	assert.Equal(t, "template_bundle", loaded[0].Type)
	assert.Len(t, loaded[0].Variables, 1)
	assert.NotNil(t, loaded[0].BudgetMetering)
	assert.NotNil(t, loaded[0].TestVariables)
}

// ===========================================================================
// GetLoadedTemplates
// ===========================================================================

func TestTemplateInitializer_GetLoadedTemplates(t *testing.T) {
	dir := t.TempDir()
	tmplFile := filepath.Join(dir, "template.yaml")
	tmplYAML := `
variables: []
rules:
  - name: "Rule"
    type: "evm_address_list"
    mode: "whitelist"
    enabled: true
    config:
      addresses: ["0x1234567890abcdef1234567890abcdef12345678"]
`
	require.NoError(t, os.WriteFile(tmplFile, []byte(tmplYAML), 0644))

	ti, err := NewTemplateInitializer(newMockTemplateRepo(), testLogger())
	require.NoError(t, err)
	ti.SetConfigDir(dir)

	templates := []TemplateConfig{
		{Name: "T1", Type: TemplateFileType, Enabled: true, Config: map[string]interface{}{"path": "template.yaml"}},
		{Name: "T2", Type: "evm_js", Mode: "whitelist", Enabled: true, Config: map[string]interface{}{"expression": "true"}},
	}

	loaded, err := ti.GetLoadedTemplates(templates)
	require.NoError(t, err)
	assert.Len(t, loaded, 2)
}

// ===========================================================================
// TemplateSyncFromConfig with file templates (integration)
// ===========================================================================

func TestTemplateSyncFromConfig_FileTemplate(t *testing.T) {
	dir := t.TempDir()
	tmplFile := filepath.Join(dir, "template.yaml")
	tmplYAML := `
variables:
  - name: chain_id
    type: string
    required: true
rules:
  - name: "File Rule"
    type: "evm_address_list"
    mode: "whitelist"
    enabled: true
    config:
      addresses:
        - "0x1234567890abcdef1234567890abcdef12345678"
`
	require.NoError(t, os.WriteFile(tmplFile, []byte(tmplYAML), 0644))

	repo := newMockTemplateRepo()
	ti, err := NewTemplateInitializer(repo, testLogger())
	require.NoError(t, err)
	ti.SetConfigDir(dir)

	templates := []TemplateConfig{
		{Name: "File Template", Type: TemplateFileType, Enabled: true, Config: map[string]interface{}{"path": "template.yaml"}},
	}

	err = ti.SyncFromConfig(context.Background(), templates)
	require.NoError(t, err)
	assert.Equal(t, 1, len(repo.templates))
}

// ===========================================================================
// extractTestCasesOverrides
// ===========================================================================

func TestExtractTestCasesOverrides_Nil(t *testing.T) {
	result := extractTestCasesOverrides(nil)
	assert.Nil(t, result)
}

func TestExtractTestCasesOverrides_NoField(t *testing.T) {
	config := map[string]interface{}{"template": "my-template"}
	result := extractTestCasesOverrides(config)
	assert.Nil(t, result)
}

func TestExtractTestCasesOverrides_NilField(t *testing.T) {
	config := map[string]interface{}{"test_cases_overrides": nil}
	result := extractTestCasesOverrides(config)
	assert.Nil(t, result)
}

func TestExtractTestCasesOverrides_ValidOverrides(t *testing.T) {
	config := map[string]interface{}{
		"test_cases_overrides": map[string]interface{}{
			"rule-name": []interface{}{
				map[string]interface{}{
					"name": "override test", "input": map[string]interface{}{"key": "value"}, "expect_pass": true,
				},
			},
		},
	}

	result := extractTestCasesOverrides(config)
	require.NotNil(t, result)
	require.Len(t, result["rule-name"], 1)
	assert.Equal(t, "override test", result["rule-name"][0].Name)
	assert.True(t, result["rule-name"][0].ExpectPass)
}

func TestExtractTestCasesOverrides_InvalidJSON(t *testing.T) {
	config := map[string]interface{}{
		"test_cases_overrides": make(chan int),
	}
	result := extractTestCasesOverrides(config)
	assert.Nil(t, result)
}

func TestExtractTestCasesOverrides_InvalidStructure(t *testing.T) {
	config := map[string]interface{}{
		"test_cases_overrides": "just a string",
	}
	result := extractTestCasesOverrides(config)
	assert.Nil(t, result)
}

func TestExtractTestCasesOverrides_MultipleRules(t *testing.T) {
	config := map[string]interface{}{
		"test_cases_overrides": map[string]interface{}{
			"rule-a": []interface{}{
				map[string]interface{}{"name": "test a", "input": map[string]interface{}{"to": "0xaaa"}, "expect_pass": false, "expect_reason": "blocked"},
			},
			"rule-b": []interface{}{
				map[string]interface{}{"name": "test b", "input": map[string]interface{}{"to": "0xbbb"}, "expect_pass": true},
			},
		},
	}

	result := extractTestCasesOverrides(config)
	require.NotNil(t, result)
	require.Len(t, result["rule-a"], 1)
	assert.False(t, result["rule-a"][0].ExpectPass)
	assert.Equal(t, "blocked", result["rule-a"][0].ExpectReason)
	require.Len(t, result["rule-b"], 1)
}

// ===========================================================================
// expandInstanceRule - improve coverage from 66%
// ===========================================================================

func TestExpandInstanceRule_DisabledTemplateNoRulesJSON(t *testing.T) {
	templates := map[string]TemplateConfig{
		"tmpl": {Name: "tmpl", Enabled: false, Config: map[string]interface{}{}},
	}
	rule := RuleConfig{Type: "instance", Name: "inst", Config: map[string]interface{}{"template": "tmpl"}}
	result, err := expandInstanceRule(rule, templates)
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestExpandInstanceRule_EnabledTemplateNoRulesJSON(t *testing.T) {
	templates := map[string]TemplateConfig{
		"tmpl": {Name: "tmpl", Enabled: true, Config: map[string]interface{}{}},
	}
	rule := RuleConfig{Type: "instance", Name: "inst", Config: map[string]interface{}{"template": "tmpl"}}
	_, err := expandInstanceRule(rule, templates)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has no rules_json")
}

func TestExpandInstanceRule_BasicExpansion(t *testing.T) {
	rulesJSON := `[{"name":"Rule","type":"evm_address_list","mode":"whitelist","enabled":true,"config":{"addresses":["0x1234567890abcdef1234567890abcdef12345678"]}}]`
	templates := map[string]TemplateConfig{
		"tmpl": {Name: "tmpl", Enabled: true, Config: map[string]interface{}{"rules_json": rulesJSON}},
	}
	rule := RuleConfig{
		Type: "instance", Name: "inst", Enabled: true,
		ChainType: "evm", ChainID: "1", APIKeyID: "key1",
		SignerAddress: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Config:        map[string]interface{}{"template": "tmpl"},
	}
	result, err := expandInstanceRule(rule, templates)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "Rule", result[0].Name)
	assert.Equal(t, "evm", result[0].ChainType)
	assert.Equal(t, "1", result[0].ChainID)
	assert.Equal(t, "key1", result[0].APIKeyID)
	assert.True(t, result[0].Enabled)
}

func TestExpandInstanceRule_WithVariables(t *testing.T) {
	rulesJSON := `[{"name":"Rule","type":"evm_address_list","mode":"whitelist","enabled":true,"config":{"addresses":["${addr}"]}}]`
	templates := map[string]TemplateConfig{
		"tmpl": {Name: "tmpl", Enabled: true, Config: map[string]interface{}{"rules_json": rulesJSON}},
	}
	rule := RuleConfig{
		Type: "instance", Name: "inst", Enabled: true,
		Config: map[string]interface{}{
			"template":  "tmpl",
			"variables": map[string]interface{}{"addr": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		},
	}
	result, err := expandInstanceRule(rule, templates)
	require.NoError(t, err)
	require.Len(t, result, 1)
	configJSON, _ := json.Marshal(result[0].Config)
	assert.Contains(t, string(configJSON), "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	assert.Equal(t, "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", result[0].Variables["addr"])
}

func TestExpandInstanceRule_WithConfigID(t *testing.T) {
	rulesJSON := `[{"name":"Rule","type":"evm_address_list","mode":"whitelist","enabled":true,"config":{"addresses":["0x1234567890abcdef1234567890abcdef12345678"]}}]`
	templates := map[string]TemplateConfig{
		"tmpl": {Name: "tmpl", Enabled: true, Config: map[string]interface{}{"rules_json": rulesJSON}},
	}
	rule := RuleConfig{
		Type: "instance", Name: "inst", Enabled: true,
		Config: map[string]interface{}{"template": "tmpl", "id": "stable-id"},
	}
	result, err := expandInstanceRule(rule, templates)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "stable-id", result[0].Id)
}

func TestExpandInstanceRule_WithTestCasesOverrides(t *testing.T) {
	rulesJSON := `[{"name":"OverrideRule","type":"evm_address_list","mode":"whitelist","enabled":true,"config":{"addresses":["0x1234567890abcdef1234567890abcdef12345678"]},"test_cases":[{"name":"original","input":{},"expect_pass":true}]}]`
	templates := map[string]TemplateConfig{
		"tmpl": {Name: "tmpl", Enabled: true, Config: map[string]interface{}{"rules_json": rulesJSON}},
	}
	rule := RuleConfig{
		Type: "instance", Name: "inst", Enabled: true,
		Config: map[string]interface{}{
			"template": "tmpl",
			"test_cases_overrides": map[string]interface{}{
				"OverrideRule": []interface{}{
					map[string]interface{}{"name": "overridden", "input": map[string]interface{}{"key": "val"}, "expect_pass": false},
				},
			},
		},
	}
	result, err := expandInstanceRule(rule, templates)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Len(t, result[0].TestCases, 1)
	assert.Equal(t, "overridden", result[0].TestCases[0].Name)
	assert.False(t, result[0].TestCases[0].ExpectPass)
}

func TestExpandInstanceRule_MapInterfaceInterfaceVariables(t *testing.T) {
	rulesJSON := `[{"name":"Rule","type":"evm_address_list","mode":"whitelist","enabled":true,"config":{"addresses":["${addr}"]}}]`
	templates := map[string]TemplateConfig{
		"tmpl": {Name: "tmpl", Enabled: true, Config: map[string]interface{}{"rules_json": rulesJSON}},
	}
	vars := map[interface{}]interface{}{"addr": "0xcccccccccccccccccccccccccccccccccccccccc"}
	rule := RuleConfig{
		Type: "instance", Name: "inst", Enabled: true,
		Config: map[string]interface{}{"template": "tmpl", "variables": vars},
	}
	result, err := expandInstanceRule(rule, templates)
	require.NoError(t, err)
	require.Len(t, result, 1)
	configJSON, _ := json.Marshal(result[0].Config)
	assert.Contains(t, string(configJSON), "0xcccccccccccccccccccccccccccccccccccccccc")
}

func TestExpandInstanceRule_MultipleRulesNoConfigID(t *testing.T) {
	rulesJSON := `[{"name":"R1","type":"evm_address_list","mode":"whitelist","enabled":true,"config":{"addresses":["0x1234567890abcdef1234567890abcdef12345678"]}},{"name":"R2","type":"evm_address_list","mode":"whitelist","enabled":true,"config":{"addresses":["0x1234567890abcdef1234567890abcdef12345678"]}}]`
	templates := map[string]TemplateConfig{
		"tmpl": {Name: "tmpl", Enabled: true, Config: map[string]interface{}{"rules_json": rulesJSON}},
	}
	rule := RuleConfig{
		Type: "instance", Name: "inst", Enabled: true,
		Config: map[string]interface{}{"template": "tmpl", "id": "should-not-apply"},
	}
	result, err := expandInstanceRule(rule, templates)
	require.NoError(t, err)
	require.Len(t, result, 2)
	assert.Equal(t, "", result[0].Id)
	assert.Equal(t, "", result[1].Id)
}

func TestExpandInstanceRules_MixedTypes(t *testing.T) {
	rulesJSON := `[{"name":"From Template","type":"evm_address_list","mode":"whitelist","enabled":true,"config":{"addresses":["0x1234567890abcdef1234567890abcdef12345678"]}}]`
	templates := []TemplateConfig{
		{Name: "tmpl", Enabled: true, Config: map[string]interface{}{"rules_json": rulesJSON}},
	}
	rules := []RuleConfig{
		{Name: "Regular", Type: "evm_address_list", Mode: "whitelist"},
		{Name: "Instance", Type: "instance", Enabled: true, Config: map[string]interface{}{"template": "tmpl"}},
	}
	result, err := ExpandInstanceRules(rules, templates)
	require.NoError(t, err)
	require.Len(t, result, 2)
	assert.Equal(t, "Regular", result[0].Name)
	assert.Equal(t, "From Template", result[1].Name)
}

// ===========================================================================
// ExpandTemplatesFromFiles - disabled file template passthrough
// ===========================================================================

func TestExpandTemplatesFromFiles_DisabledFileTemplate(t *testing.T) {
	templates := []TemplateConfig{
		{Name: "Disabled", Type: TemplateFileType, Enabled: false,
			Config: map[string]interface{}{"path": "/nonexistent/path.yaml"}},
	}
	result, err := ExpandTemplatesFromFiles(templates, ".", testLogger())
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.False(t, result[0].Enabled)
}

// ===========================================================================
// loadTemplateFromFileStatic additional error cases
// ===========================================================================

func TestLoadTemplateFromFileStatic_NonStringPath(t *testing.T) {
	cfg := TemplateConfig{Name: "Bad", Type: TemplateFileType, Config: map[string]interface{}{"path": 12345}}
	_, err := loadTemplateFromFileStatic(cfg, ".", testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path must be a string")
}

func TestLoadTemplateFromFileStatic_FileNotFound(t *testing.T) {
	cfg := TemplateConfig{Name: "Missing", Type: TemplateFileType,
		Config: map[string]interface{}{"path": "/nonexistent/file.yaml"}}
	_, err := loadTemplateFromFileStatic(cfg, ".", testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read template file")
}

func TestLoadTemplateFromFileStatic_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(f, []byte("{{invalid"), 0644))
	cfg := TemplateConfig{Name: "Bad", Type: TemplateFileType, Config: map[string]interface{}{"path": f}}
	_, err := loadTemplateFromFileStatic(cfg, ".", testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse template file")
}

func TestLoadTemplateFromFileStatic_AbsolutePath(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "template.yaml")
	tmplYAML := `
variables:
  - name: x
    type: string
    required: true
rules:
  - name: "R"
    type: "evm_address_list"
    mode: "whitelist"
    enabled: true
    config:
      addresses: ["0x1234567890abcdef1234567890abcdef12345678"]
`
	require.NoError(t, os.WriteFile(f, []byte(tmplYAML), 0644))
	cfg := TemplateConfig{Name: "Abs", Type: TemplateFileType, Config: map[string]interface{}{"path": f}}
	result, err := loadTemplateFromFileStatic(cfg, "/some/other/dir", testLogger())
	require.NoError(t, err)
	require.Len(t, result, 1)
}

func TestLoadTemplateFromFileStatic_NilLogger(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "template.yaml")
	tmplYAML := `
variables: []
rules:
  - name: "R"
    type: "evm_address_list"
    mode: "whitelist"
    enabled: true
    config:
      addresses: ["0x1234567890abcdef1234567890abcdef12345678"]
`
	require.NoError(t, os.WriteFile(f, []byte(tmplYAML), 0644))
	cfg := TemplateConfig{Name: "No Logger", Type: TemplateFileType, Config: map[string]interface{}{"path": "template.yaml"}}
	result, err := loadTemplateFromFileStatic(cfg, dir, nil)
	require.NoError(t, err)
	require.Len(t, result, 1)
}

func TestLoadTemplateFromFileStatic_EmptyRules(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "empty.yaml")
	require.NoError(t, os.WriteFile(f, []byte("variables:\n  - name: x\n    type: string\n    required: true\nrules: []\n"), 0644))
	cfg := TemplateConfig{Name: "Empty", Type: TemplateFileType, Config: map[string]interface{}{"path": "empty.yaml"}}
	result, err := loadTemplateFromFileStatic(cfg, dir, testLogger())
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.NotEqual(t, "template_bundle", result[0].Type)
}

// ===========================================================================
// fillInMappingArrays - additional coverage
// ===========================================================================

func TestFillInMappingArrays_NilConfig(t *testing.T) {
	rule := &RuleConfig{}
	err := fillInMappingArrays(rule, nil)
	assert.NoError(t, err)
}

func TestFillInMappingArrays_NoInMappingExpressions(t *testing.T) {
	rule := &RuleConfig{Config: map[string]interface{}{"expression": "to == 0x1234"}}
	err := fillInMappingArrays(rule, map[string]string{"addr": "0xaa"})
	assert.NoError(t, err)
	_, found := rule.Config["in_mapping_arrays"]
	assert.False(t, found)
}

func TestFillInMappingArrays_WithInExpression(t *testing.T) {
	rule := &RuleConfig{Config: map[string]interface{}{"expression": "in(to, allowedAddrs)"}}
	vars := map[string]string{"allowedAddrs": "0xaa,0xbb, 0xcc"}
	err := fillInMappingArrays(rule, vars)
	assert.NoError(t, err)
	arr := rule.Config["in_mapping_arrays"].(map[string][]string)
	assert.Equal(t, []string{"0xaa", "0xbb", "0xcc"}, arr["allowedAddrs"])
}

func TestFillInMappingArrays_VariableNotFound(t *testing.T) {
	rule := &RuleConfig{Config: map[string]interface{}{"expression": "in(to, unknownVar)"}}
	err := fillInMappingArrays(rule, map[string]string{})
	assert.NoError(t, err)
	_, found := rule.Config["in_mapping_arrays"]
	assert.False(t, found)
}

func TestFillInMappingArrays_MultipleKeys(t *testing.T) {
	rule := &RuleConfig{Config: map[string]interface{}{
		"expression":            "in(to, addrs)",
		"typed_data_expression": "in(spender, spenders)",
	}}
	vars := map[string]string{"addrs": "0xaa,0xbb", "spenders": "0xcc"}
	err := fillInMappingArrays(rule, vars)
	assert.NoError(t, err)
	arr := rule.Config["in_mapping_arrays"].(map[string][]string)
	assert.Len(t, arr, 2)
}

// ===========================================================================
// ExpandFileRules (top-level)
// ===========================================================================

func TestExpandFileRules_NoFileRules(t *testing.T) {
	rules := []RuleConfig{{Name: "Regular", Type: "evm_address_list", Mode: "whitelist"}}
	expanded, err := ExpandFileRules(rules, ".", testLogger())
	require.NoError(t, err)
	require.Len(t, expanded, 1)
}

func TestExpandFileRules_FileRuleLoadError(t *testing.T) {
	rules := []RuleConfig{
		{Name: "Bad", Type: RuleFileType, Config: map[string]interface{}{"path": "/nonexistent/file.yaml"}},
	}
	_, err := ExpandFileRules(rules, ".", testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load rules from file")
}

// ===========================================================================
// ExpandEnvWithDefaults - additional edge case
// ===========================================================================

func TestExpandEnvWithDefaults_EmptyDefault(t *testing.T) {
	os.Unsetenv("TEST_EMPTY_DEF")
	result := ExpandEnvWithDefaults("${TEST_EMPTY_DEF:-}")
	assert.Equal(t, "", result)
}

// ===========================================================================
// ValidateDelegationTargets
// ===========================================================================

func TestValidateDelegationTargets_Valid(t *testing.T) {
	rules := []RuleConfig{
		{Id: "parent-rule", Name: "Parent", Type: "evm_js", Config: map[string]interface{}{"delegate_to": "child-rule"}},
		{Id: "child-rule", Name: "Child", Type: "evm_js"},
	}
	err := ValidateDelegationTargets(rules)
	assert.NoError(t, err)
}

func TestValidateDelegationTargets_MissingTarget(t *testing.T) {
	rules := []RuleConfig{
		{Id: "parent-rule", Name: "Parent", Type: "evm_js", Config: map[string]interface{}{"delegate_to": "nonexistent"}},
	}
	err := ValidateDelegationTargets(rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
	assert.Contains(t, err.Error(), "non-existent target")
}

func TestValidateDelegationTargets_NoDelegateTo(t *testing.T) {
	rules := []RuleConfig{
		{Id: "rule-a", Name: "A", Type: "evm_address_list"},
		{Id: "rule-b", Name: "B", Type: "evm_js"},
	}
	err := ValidateDelegationTargets(rules)
	assert.NoError(t, err)
}

func TestValidateDelegationTargets_UnresolvedVariable(t *testing.T) {
	rules := []RuleConfig{
		{Id: "parent-rule", Name: "Parent", Type: "evm_js", Config: map[string]interface{}{"delegate_to": "${some_var}"}},
	}
	err := ValidateDelegationTargets(rules)
	assert.NoError(t, err, "unresolved variables in delegate_to should be skipped, not treated as missing targets")
}

func TestValidateDelegationTargets_MultipleTargets(t *testing.T) {
	rules := []RuleConfig{
		{Id: "parent", Name: "Parent", Type: "evm_js", Config: map[string]interface{}{"delegate_to": "child-a,child-b"}},
		{Id: "child-a", Name: "Child A", Type: "evm_js"},
		{Id: "child-b", Name: "Child B", Type: "evm_js"},
	}
	err := ValidateDelegationTargets(rules)
	assert.NoError(t, err)
}

func TestValidateDelegationTargets_MultipleTargets_OneMissing(t *testing.T) {
	rules := []RuleConfig{
		{Id: "parent", Name: "Parent", Type: "evm_js", Config: map[string]interface{}{"delegate_to": "child-a,missing-child"}},
		{Id: "child-a", Name: "Child A", Type: "evm_js"},
	}
	err := ValidateDelegationTargets(rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing-child")
}
