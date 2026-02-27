package storage

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// RuleFilter for querying rules
type RuleFilter struct {
	ChainType     *types.ChainType
	ChainID       *string
	APIKeyID      *string
	SignerAddress *string
	Type          *types.RuleType
	Source        *types.RuleSource
	EnabledOnly   bool
	Offset        int
	Limit         int
}

// RuleRepository defines the interface for rule persistence
type RuleRepository interface {
	Create(ctx context.Context, rule *types.Rule) error
	Get(ctx context.Context, id types.RuleID) (*types.Rule, error)
	Update(ctx context.Context, rule *types.Rule) error
	Delete(ctx context.Context, id types.RuleID) error
	List(ctx context.Context, filter RuleFilter) ([]*types.Rule, error)
	Count(ctx context.Context, filter RuleFilter) (int, error)
	ListByChainType(ctx context.Context, chainType types.ChainType) ([]*types.Rule, error)
	IncrementMatchCount(ctx context.Context, id types.RuleID) error
}

// GormRuleRepository implements RuleRepository using GORM
type GormRuleRepository struct {
	db *gorm.DB
}

// NewGormRuleRepository creates a new GORM-based rule repository
func NewGormRuleRepository(db *gorm.DB) (*GormRuleRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	return &GormRuleRepository{db: db}, nil
}

// Create creates a new rule
func (r *GormRuleRepository) Create(ctx context.Context, rule *types.Rule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}
	return r.db.WithContext(ctx).Create(rule).Error
}

// Get retrieves a rule by ID
func (r *GormRuleRepository) Get(ctx context.Context, id types.RuleID) (*types.Rule, error) {
	var rule types.Rule
	err := r.db.WithContext(ctx).First(&rule, "id = ?", id).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, types.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get rule: %w", err)
	}
	return &rule, nil
}

// Update updates an existing rule
func (r *GormRuleRepository) Update(ctx context.Context, rule *types.Rule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}
	return r.db.WithContext(ctx).Save(rule).Error
}

// Delete deletes a rule by ID
func (r *GormRuleRepository) Delete(ctx context.Context, id types.RuleID) error {
	result := r.db.WithContext(ctx).Delete(&types.Rule{}, "id = ?", id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete rule: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}

// List returns rules matching the filter
func (r *GormRuleRepository) List(ctx context.Context, filter RuleFilter) ([]*types.Rule, error) {
	query := r.db.WithContext(ctx).Model(&types.Rule{})

	if filter.ChainType != nil {
		// Match rules with specific chain type OR nil (applies to all chains)
		query = query.Where("chain_type = ? OR chain_type IS NULL", *filter.ChainType)
	}
	if filter.ChainID != nil {
		query = query.Where("chain_id = ? OR chain_id IS NULL", *filter.ChainID)
	}
	if filter.APIKeyID != nil {
		query = query.Where("api_key_id = ? OR api_key_id IS NULL", *filter.APIKeyID)
	}
	if filter.SignerAddress != nil {
		query = query.Where("signer_address = ? OR signer_address IS NULL", *filter.SignerAddress)
	}
	if filter.Type != nil {
		query = query.Where("type = ?", *filter.Type)
	}
	if filter.Source != nil {
		query = query.Where("source = ?", *filter.Source)
	}
	if filter.EnabledOnly {
		query = query.Where("enabled = ?", true)
		// Also filter out expired rules
		query = query.Where("expires_at IS NULL OR expires_at > ?", time.Now())
	}

	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}
	if filter.Limit > 0 {
		query = query.Limit(filter.Limit)
	} else if filter.Limit != -1 {
		// Limit == -1 means "no limit" (used by security-critical paths like rule engine evaluation).
		// Limit == 0 (default) applies a safe default for API pagination.
		query = query.Limit(100) // default limit for API pagination
	}
	// When filter.Limit == -1, no LIMIT clause is applied (fetch all matching rules)

	query = query.Order("created_at DESC")

	var rules []*types.Rule
	err := query.Find(&rules).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}
	return rules, nil
}

// Count returns the total count of rules matching the filter (ignoring Offset/Limit)
func (r *GormRuleRepository) Count(ctx context.Context, filter RuleFilter) (int, error) {
	query := r.db.WithContext(ctx).Model(&types.Rule{})

	if filter.ChainType != nil {
		query = query.Where("chain_type = ? OR chain_type IS NULL", *filter.ChainType)
	}
	if filter.ChainID != nil {
		query = query.Where("chain_id = ? OR chain_id IS NULL", *filter.ChainID)
	}
	if filter.APIKeyID != nil {
		query = query.Where("api_key_id = ? OR api_key_id IS NULL", *filter.APIKeyID)
	}
	if filter.SignerAddress != nil {
		query = query.Where("signer_address = ? OR signer_address IS NULL", *filter.SignerAddress)
	}
	if filter.Type != nil {
		query = query.Where("type = ?", *filter.Type)
	}
	if filter.Source != nil {
		query = query.Where("source = ?", *filter.Source)
	}
	if filter.EnabledOnly {
		query = query.Where("enabled = ?", true)
		query = query.Where("expires_at IS NULL OR expires_at > ?", time.Now())
	}

	var count int64
	if err := query.Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count rules: %w", err)
	}
	return int(count), nil
}

// ListByChainType returns all enabled rules for a specific chain type
func (r *GormRuleRepository) ListByChainType(ctx context.Context, chainType types.ChainType) ([]*types.Rule, error) {
	return r.List(ctx, RuleFilter{
		ChainType:   &chainType,
		EnabledOnly: true,
	})
}

// IncrementMatchCount increments the match count for a rule
func (r *GormRuleRepository) IncrementMatchCount(ctx context.Context, id types.RuleID) error {
	now := time.Now()
	result := r.db.WithContext(ctx).Model(&types.Rule{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"match_count":     gorm.Expr("match_count + 1"),
			"last_matched_at": now,
		})
	if result.Error != nil {
		return fmt.Errorf("failed to increment match count: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}
