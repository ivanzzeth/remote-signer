package storage

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// MemoryRuleRepository is an in-memory RuleRepository for validation and tests.
// All methods are safe for concurrent use.
type MemoryRuleRepository struct {
	mu    sync.RWMutex
	rules map[types.RuleID]*types.Rule
	list  []*types.Rule // insertion order for List
}

// NewMemoryRuleRepository creates an empty in-memory rule repository.
func NewMemoryRuleRepository() *MemoryRuleRepository {
	return &MemoryRuleRepository{
		rules: make(map[types.RuleID]*types.Rule),
		list:  nil,
	}
}

// Create stores a new rule. Fails if ID already exists.
func (r *MemoryRuleRepository) Create(ctx context.Context, rule *types.Rule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.rules[rule.ID]; exists {
		return fmt.Errorf("rule %s already exists", rule.ID)
	}
	clone := cloneRule(rule)
	r.rules[rule.ID] = clone
	r.list = append(r.list, clone)
	return nil
}

// Get returns a rule by ID.
func (r *MemoryRuleRepository) Get(ctx context.Context, id types.RuleID) (*types.Rule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rule, ok := r.rules[id]
	if !ok {
		return nil, types.ErrNotFound
	}
	return cloneRule(rule), nil
}

// Update replaces an existing rule.
func (r *MemoryRuleRepository) Update(ctx context.Context, rule *types.Rule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.rules[rule.ID]; !exists {
		return types.ErrNotFound
	}
	clone := cloneRule(rule)
	r.rules[rule.ID] = clone
	for i, existing := range r.list {
		if existing.ID == rule.ID {
			r.list[i] = clone
			break
		}
	}
	return nil
}

// Delete removes a rule by ID.
func (r *MemoryRuleRepository) Delete(ctx context.Context, id types.RuleID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.rules[id]; !exists {
		return types.ErrNotFound
	}
	delete(r.rules, id)
	for i, rule := range r.list {
		if rule.ID == id {
			r.list = append(r.list[:i], r.list[i+1:]...)
			break
		}
	}
	return nil
}

// List returns rules matching the filter. Scope fields (ChainType, ChainID, APIKeyID, SignerAddress)
// use same semantics as GORM: rule field nil = applies to all; include when rule field is nil OR equals filter.
func (r *MemoryRuleRepository) List(ctx context.Context, filter RuleFilter) ([]*types.Rule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*types.Rule
	for _, rule := range r.list {
		if filter.ChainType != nil && rule.ChainType != nil && *rule.ChainType != *filter.ChainType {
			continue
		}
		if filter.ChainID != nil && rule.ChainID != nil && *rule.ChainID != *filter.ChainID {
			continue
		}
		if filter.APIKeyID != nil && rule.APIKeyID != nil && *rule.APIKeyID != *filter.APIKeyID {
			continue
		}
		if filter.SignerAddress != nil && rule.SignerAddress != nil && !strings.EqualFold(*rule.SignerAddress, *filter.SignerAddress) {
			continue
		}
		if filter.Type != nil && rule.Type != *filter.Type {
			continue
		}
		if filter.Source != nil && rule.Source != *filter.Source {
			continue
		}
		if filter.EnabledOnly && !rule.Enabled {
			continue
		}
		out = append(out, cloneRule(rule))
	}
	if filter.Offset > 0 && filter.Offset < len(out) {
		out = out[filter.Offset:]
	}
	limit := filter.Limit
	if limit == 0 {
		limit = 100 // same default as GormRuleRepository (API pagination)
	}
	// limit == -1 means "no limit" (security-critical paths like rule engine evaluation)
	if limit > 0 && limit < len(out) {
		out = out[:limit]
	}
	return out, nil
}

// Count returns the number of rules matching the filter.
func (r *MemoryRuleRepository) Count(ctx context.Context, filter RuleFilter) (int, error) {
	list, err := r.List(ctx, filter)
	if err != nil {
		return 0, err
	}
	return len(list), nil
}

// ListByChainType returns enabled rules for the given chain type.
func (r *MemoryRuleRepository) ListByChainType(ctx context.Context, chainType types.ChainType) ([]*types.Rule, error) {
	return r.List(ctx, RuleFilter{ChainType: &chainType, EnabledOnly: true})
}

// IncrementMatchCount is a no-op for in-memory repo.
func (r *MemoryRuleRepository) IncrementMatchCount(ctx context.Context, id types.RuleID) error {
	return nil
}

func cloneRule(r *types.Rule) *types.Rule {
	if r == nil {
		return nil
	}
	clone := *r
	if r.ChainType != nil {
		ct := *r.ChainType
		clone.ChainType = &ct
	}
	if r.ChainID != nil {
		s := *r.ChainID
		clone.ChainID = &s
	}
	if r.APIKeyID != nil {
		s := *r.APIKeyID
		clone.APIKeyID = &s
	}
	if r.SignerAddress != nil {
		s := *r.SignerAddress
		clone.SignerAddress = &s
	}
	return &clone
}
