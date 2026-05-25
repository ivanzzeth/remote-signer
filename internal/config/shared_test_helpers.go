package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"

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

func (m *mockRuleRepository) ValidateDelegateRefs(_ context.Context, _ *types.Rule) error {
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

func (m *mockTemplateRepository) Upsert(_ context.Context, tmpl *types.RuleTemplate) (bool, error) {
	if tmpl == nil {
		return false, fmt.Errorf("template cannot be nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.templates[tmpl.ID]; ok {
		if existing.ContentHash != "" && existing.ContentHash == tmpl.ContentHash {
			return false, nil
		}
		clone := *tmpl
		m.templates[tmpl.ID] = &clone
		return true, nil
	}
	clone := *tmpl
	m.templates[tmpl.ID] = &clone
	return true, nil
}

func (m *mockTemplateRepository) ListIDsBySource(_ context.Context, source types.RuleSource) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []string
	for id, t := range m.templates {
		if t.Source == source {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (m *mockTemplateRepository) DeleteMany(_ context.Context, ids []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		delete(m.templates, id)
	}
	return nil
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

func (e *errorRuleRepository) ValidateDelegateRefs(_ context.Context, _ *types.Rule) error {
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
func (e *errorTemplateRepository) Upsert(_ context.Context, _ *types.RuleTemplate) (bool, error) {
	return false, nil
}
func (e *errorTemplateRepository) ListIDsBySource(_ context.Context, _ types.RuleSource) ([]string, error) {
	return nil, nil
}
func (e *errorTemplateRepository) DeleteMany(_ context.Context, _ []string) error {
	return nil
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

func (f *failUpdateRuleRepo) ValidateDelegateRefs(_ context.Context, _ *types.Rule) error {
	return nil
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

func (f *failDeleteRuleRepo) ValidateDelegateRefs(_ context.Context, _ *types.Rule) error {
	return nil
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
func (f *failUpdateTemplateRepo) Upsert(ctx context.Context, tmpl *types.RuleTemplate) (bool, error) {
	return f.base.Upsert(ctx, tmpl)
}
func (f *failUpdateTemplateRepo) ListIDsBySource(ctx context.Context, source types.RuleSource) ([]string, error) {
	return f.base.ListIDsBySource(ctx, source)
}
func (f *failUpdateTemplateRepo) DeleteMany(ctx context.Context, ids []string) error {
	return f.base.DeleteMany(ctx, ids)
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
func (f *failDeleteTemplateRepo) Upsert(ctx context.Context, tmpl *types.RuleTemplate) (bool, error) {
	return f.base.Upsert(ctx, tmpl)
}
func (f *failDeleteTemplateRepo) ListIDsBySource(ctx context.Context, source types.RuleSource) ([]string, error) {
	return f.base.ListIDsBySource(ctx, source)
}
func (f *failDeleteTemplateRepo) DeleteMany(ctx context.Context, ids []string) error {
	return f.base.DeleteMany(ctx, ids)
}

// ===========================================================================
// Helper
// ===========================================================================

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// hexPubKey is a valid 64-char hex Ed25519 public key for test use.
const hexPubKey = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

