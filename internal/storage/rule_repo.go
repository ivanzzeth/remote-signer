package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// RuleFilter for querying rules
type RuleFilter struct {
	ChainType     *types.ChainType
	ChainID       *string
	Owner         *string
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
	// ValidateDelegateRefs checks that all delegate_to and delegate_to_by_target
	// inst_<hash> references in a rule's config exist as rules in the database.
	// This enforces referential integrity for references embedded in the JSONB
	// config column. No-op for rules without delegate references.
	ValidateDelegateRefs(ctx context.Context, rule *types.Rule) error
}

// Transactional is implemented by repositories that support atomic operations.
// This is optional — callers should type-assert before use.
type Transactional interface {
	RunInTransaction(ctx context.Context, fn func(txRepo RuleRepository) error) error
}

// RuleBudgetTransactional provides a transaction spanning both RuleRepository
// and BudgetRepository, used when rule updates must be atomic with budget changes.
type RuleBudgetTransactional interface {
	RunInRuleBudgetTransaction(ctx context.Context, fn func(txRule RuleRepository, txBudget BudgetRepository) error) error
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

// RunInTransaction runs fn inside a database transaction.
// A new GormRuleRepository backed by the transaction is passed to fn.
func (r *GormRuleRepository) RunInTransaction(ctx context.Context, fn func(txRepo RuleRepository) error) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txRepo := &GormRuleRepository{db: tx}
		return fn(txRepo)
	})
}

// RunInRuleBudgetTransaction runs fn within a database transaction, passing
// both a transactional RuleRepository and BudgetRepository so that rule
// and budget mutations are atomic.
func (r *GormRuleRepository) RunInRuleBudgetTransaction(ctx context.Context, fn func(txRule RuleRepository, txBudget BudgetRepository) error) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txRule := &GormRuleRepository{db: tx}
		txBudget := &GormBudgetRepository{db: tx}
		return fn(txRule, txBudget)
	})
}

// Create creates a new rule
func (r *GormRuleRepository) Create(ctx context.Context, rule *types.Rule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}
	// Reject empty Type at the storage boundary. The whitelist engine's
	// fail-open path silently skips rules whose Type has no registered
	// evaluator — leaving an empty-type row in the DB makes every
	// matching sign request fall through to manual approval with no
	// visible error. Block it here so future bundle-instantiator /
	// template-substitution bugs surface at Create time, not at sign
	// time. See commit 3d9feba for the original incident.
	if rule.Type == "" {
		return fmt.Errorf("rule.type is required: empty type makes the engine silently skip the rule (no evaluator registered for \"\"). If you meant a bundle, instantiate via the template service instead of writing directly")
	}
	normalizeRuleForPersist(rule)
	return r.db.WithContext(ctx).Create(rule).Error
}

// normalizeRuleForPersist fills in fields that must not be NULL at the DB
// layer with the engine's semantic defaults. This keeps callers (config
// loaders, TUI helpers, test harnesses) from having to know the exact NOT
// NULL surface — and stops empty AppliedTo from quietly failing inserts and
// dropping the entire rule, which manifests downstream as the misleading
// "no matching rule and manual approval is disabled" error during signing.
// ValidateDelegateRefs checks that all delegate_to and delegate_to_by_target
// references in a rule's config JSON point to existing rules in the database.
// This enforces referential integrity for the inst_<hash> rule ID references
// embedded inside the JSONB config column, where a standard SQL FK cannot reach.
// Only validates inst_-prefixed rule IDs; YAML template IDs are skipped.
func (r *GormRuleRepository) ValidateDelegateRefs(ctx context.Context, rule *types.Rule) error {
	if rule == nil || len(rule.Config) == 0 {
		return nil
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(rule.Config, &cfg); err != nil {
		return fmt.Errorf("failed to parse config for delegate validation: %w", err)
	}

	// Collect inst_<hash> targets from delegate_to
	var targets []string
	if d, _ := cfg["delegate_to"].(string); d != "" {
		for _, part := range strings.Split(d, ",") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "inst_") {
				targets = append(targets, part)
			}
		}
	}

	// Collect from delegate_to_by_target: "target-name:inst_<hash>,..."
	if dtbt, _ := cfg["delegate_to_by_target"].(string); dtbt != "" {
		for _, pair := range strings.Split(dtbt, ",") {
			pair = strings.TrimSpace(pair)
			idx := strings.Index(pair, ":")
			if idx <= 0 {
				continue
			}
			rulePart := strings.TrimSpace(pair[idx+1:])
			if strings.HasPrefix(rulePart, "inst_") {
				targets = append(targets, rulePart)
			}
		}
	}

	if len(targets) == 0 {
		return nil
	}

	// Deduplicate
	seen := make(map[string]bool, len(targets))
	unique := make([]string, 0, len(targets))
	for _, t := range targets {
		if !seen[t] {
			seen[t] = true
			unique = append(unique, t)
		}
	}

	// Batch check existence — count matching rows
	var count int64
	if err := r.db.WithContext(ctx).Model(&types.Rule{}).
		Where("id IN ?", unique).
		Count(&count).Error; err != nil {
		return fmt.Errorf("failed to check delegate targets: %w", err)
	}
	if int(count) != len(unique) {
		// Build a set of found IDs
		found := make(map[string]bool, count)
		var foundRules []struct{ ID string }
		if err := r.db.WithContext(ctx).Model(&types.Rule{}).
			Select("id").
			Where("id IN ?", unique).
			Find(&foundRules).Error; err == nil {
			for _, fr := range foundRules {
				found[fr.ID] = true
			}
		}
		var missing []string
		for _, t := range unique {
			if !found[t] {
				missing = append(missing, t)
			}
		}
		return fmt.Errorf("delegate target(s) not found in database: %v", missing)
	}

	return nil
}

func normalizeRuleForPersist(rule *types.Rule) {
	if len(rule.AppliedTo) == 0 {
		// The whitelist engine treats len==0 as "applies to all callers"
		// (see scope.go ruleAppliesToCaller). Mirror that here so the row
		// survives the NOT NULL constraint with semantically-identical
		// behaviour.
		rule.AppliedTo = []string{"*"}
	}
	if rule.Status == "" {
		rule.Status = types.RuleStatusActive
	}
	if rule.Owner == "" {
		rule.Owner = "config"
	}
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
	normalizeRuleForPersist(rule)
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
	if filter.Owner != nil {
		query = query.Where("owner = ?", *filter.Owner)
	}
	if filter.SignerAddress != nil {
		query = query.Where("LOWER(signer_address) = LOWER(?) OR signer_address IS NULL", *filter.SignerAddress)
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
	if filter.Owner != nil {
		query = query.Where("owner = ?", *filter.Owner)
	}
	if filter.SignerAddress != nil {
		query = query.Where("LOWER(signer_address) = LOWER(?) OR signer_address IS NULL", *filter.SignerAddress)
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
