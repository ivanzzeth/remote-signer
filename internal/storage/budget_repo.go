package storage

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// BudgetRepository defines the interface for budget persistence
type BudgetRepository interface {
	Create(ctx context.Context, budget *types.RuleBudget) error
	// CreateOrGet atomically creates a budget record or returns the existing one.
	// SECURITY: Uses INSERT ... ON CONFLICT DO NOTHING (upsert) to prevent TOCTOU
	// race conditions where concurrent requests both find "not found" and both try to create.
	// Returns the budget (created or existing) and a bool indicating if it was created (true) or already existed (false).
	CreateOrGet(ctx context.Context, budget *types.RuleBudget) (*types.RuleBudget, bool, error)
	GetByRuleID(ctx context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error)
	// CountByRuleID returns the number of distinct budget units for a rule.
	// SECURITY: Used to enforce MaxDynamicUnits limit to prevent budget amplification attacks.
	CountByRuleID(ctx context.Context, ruleID types.RuleID) (int, error)
	Delete(ctx context.Context, id string) error
	DeleteByRuleID(ctx context.Context, ruleID types.RuleID) error
	// AtomicSpend atomically increments spent amount and tx count.
	// Returns ErrBudgetExceeded if the spend would exceed limits.
	// Uses SQL-level conditional UPDATE to prevent race conditions.
	AtomicSpend(ctx context.Context, ruleID types.RuleID, unit string, amount string) error
	// ResetBudget resets spent/txCount/alertSent for a new period.
	// Uses conditional WHERE to ensure idempotent reset (only resets if in old period).
	ResetBudget(ctx context.Context, ruleID types.RuleID, unit string, currentPeriodStart time.Time) error
	ListByRuleID(ctx context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error)
	ListByRuleIDs(ctx context.Context, ruleIDs []types.RuleID) ([]*types.RuleBudget, error)
	// MarkAlertSent sets alert_sent=true for the given rule+unit budget.
	// This prevents duplicate alert notifications within the same period.
	MarkAlertSent(ctx context.Context, ruleID types.RuleID, unit string) error
}

// ErrBudgetExceeded indicates the budget limit has been reached
var ErrBudgetExceeded = fmt.Errorf("budget exceeded")

// GormBudgetRepository implements BudgetRepository using GORM
type GormBudgetRepository struct {
	db *gorm.DB
}

// NewGormBudgetRepository creates a new GORM-based budget repository
func NewGormBudgetRepository(db *gorm.DB) (*GormBudgetRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	return &GormBudgetRepository{db: db}, nil
}

// Create creates a new budget record
func (r *GormBudgetRepository) Create(ctx context.Context, budget *types.RuleBudget) error {
	if budget == nil {
		return fmt.Errorf("budget cannot be nil")
	}
	now := time.Now()
	budget.CreatedAt = now
	budget.UpdatedAt = now
	return r.db.WithContext(ctx).Create(budget).Error
}

// CreateOrGet atomically creates a budget record or returns the existing one.
// Uses a transaction with INSERT + SELECT to handle concurrent creation safely.
func (r *GormBudgetRepository) CreateOrGet(ctx context.Context, budget *types.RuleBudget) (*types.RuleBudget, bool, error) {
	if budget == nil {
		return nil, false, fmt.Errorf("budget cannot be nil")
	}

	var result types.RuleBudget
	created := false

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Try to find existing
		findErr := tx.First(&result, "id = ?", budget.ID).Error
		if findErr == nil {
			// Already exists
			return nil
		}
		if findErr != gorm.ErrRecordNotFound {
			return fmt.Errorf("failed to check existing budget: %w", findErr)
		}

		// Not found — create
		now := time.Now()
		budget.CreatedAt = now
		budget.UpdatedAt = now
		createErr := tx.Create(budget).Error
		if createErr != nil {
			// Could be a race: another goroutine created it between our SELECT and INSERT.
			// Try to fetch again.
			retryErr := tx.First(&result, "id = ?", budget.ID).Error
			if retryErr == nil {
				return nil // Lost race, use existing
			}
			return fmt.Errorf("failed to create budget: %w", createErr)
		}
		result = *budget
		created = true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return &result, created, nil
}

// GetByRuleID retrieves a budget by rule ID and unit
func (r *GormBudgetRepository) GetByRuleID(ctx context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error) {
	var budget types.RuleBudget
	err := r.db.WithContext(ctx).First(&budget, "rule_id = ? AND unit = ?", ruleID, unit).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, types.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get budget: %w", err)
	}
	return &budget, nil
}

// CountByRuleID returns the number of distinct budget units for a rule.
func (r *GormBudgetRepository) CountByRuleID(ctx context.Context, ruleID types.RuleID) (int, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&types.RuleBudget{}).Where("rule_id = ?", ruleID).Count(&count).Error
	if err != nil {
		return 0, fmt.Errorf("failed to count budgets: %w", err)
	}
	return int(count), nil
}

// Delete deletes a budget by ID
func (r *GormBudgetRepository) Delete(ctx context.Context, id string) error {
	result := r.db.WithContext(ctx).Delete(&types.RuleBudget{}, "id = ?", id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete budget: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}

// DeleteByRuleID deletes all budgets for a rule
func (r *GormBudgetRepository) DeleteByRuleID(ctx context.Context, ruleID types.RuleID) error {
	result := r.db.WithContext(ctx).Delete(&types.RuleBudget{}, "rule_id = ?", ruleID)
	if result.Error != nil {
		return fmt.Errorf("failed to delete budgets: %w", result.Error)
	}
	return nil
}

// AtomicSpend atomically increments the spent amount and tx count for a budget.
// Uses conditional WHERE clause to prevent exceeding limits in concurrent scenarios.
// Returns ErrBudgetExceeded if the spend would exceed max_total or max_tx_count.
func (r *GormBudgetRepository) AtomicSpend(ctx context.Context, ruleID types.RuleID, unit string, amount string) error {
	// Use raw SQL for atomic conditional update
	// The WHERE clause ensures we only update if within budget
	result := r.db.WithContext(ctx).Exec(`
		UPDATE rule_budgets
		SET spent = CAST(CAST(spent AS NUMERIC) + CAST(? AS NUMERIC) AS TEXT),
		    tx_count = tx_count + 1,
		    updated_at = ?
		WHERE rule_id = ? AND unit = ?
		  AND (max_total = '-1' OR CAST(spent AS NUMERIC) + CAST(? AS NUMERIC) <= CAST(max_total AS NUMERIC))
		  AND (max_tx_count = 0 OR tx_count < max_tx_count)
	`, amount, time.Now(), ruleID, unit, amount)

	if result.Error != nil {
		return fmt.Errorf("failed to atomic spend: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrBudgetExceeded
	}

	return nil
}

// ResetBudget resets the budget for a new period.
// Uses conditional WHERE on updated_at to ensure idempotent reset.
// Only resets if the budget was last updated before the current period start.
func (r *GormBudgetRepository) ResetBudget(ctx context.Context, ruleID types.RuleID, unit string, currentPeriodStart time.Time) error {
	result := r.db.WithContext(ctx).Exec(`
		UPDATE rule_budgets
		SET spent = '0',
		    tx_count = 0,
		    alert_sent = false,
		    updated_at = ?
		WHERE rule_id = ? AND unit = ?
		  AND updated_at < ?
	`, time.Now(), ruleID, unit, currentPeriodStart)

	if result.Error != nil {
		return fmt.Errorf("failed to reset budget: %w", result.Error)
	}

	// RowsAffected == 0 is OK — means already reset (idempotent)
	return nil
}

// ListByRuleID returns all budgets for a specific rule
func (r *GormBudgetRepository) ListByRuleID(ctx context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error) {
	var budgets []*types.RuleBudget
	err := r.db.WithContext(ctx).Where("rule_id = ?", ruleID).Find(&budgets).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list budgets: %w", err)
	}
	return budgets, nil
}

// MarkAlertSent sets alert_sent=true for the given rule+unit budget.
func (r *GormBudgetRepository) MarkAlertSent(ctx context.Context, ruleID types.RuleID, unit string) error {
	result := r.db.WithContext(ctx).Exec(`
		UPDATE rule_budgets
		SET alert_sent = true,
		    updated_at = ?
		WHERE rule_id = ? AND unit = ?
	`, time.Now(), ruleID, unit)
	if result.Error != nil {
		return fmt.Errorf("failed to mark alert sent: %w", result.Error)
	}
	return nil
}

// ListByRuleIDs returns all budgets for the given rule IDs
func (r *GormBudgetRepository) ListByRuleIDs(ctx context.Context, ruleIDs []types.RuleID) ([]*types.RuleBudget, error) {
	if len(ruleIDs) == 0 {
		return nil, nil
	}
	var budgets []*types.RuleBudget
	err := r.db.WithContext(ctx).Where("rule_id IN ?", ruleIDs).Find(&budgets).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list budgets: %w", err)
	}
	return budgets, nil
}
