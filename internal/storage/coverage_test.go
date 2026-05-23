package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// =============================================================================
// MemoryRuleRepository: RunInTransaction
// =============================================================================

func TestMemoryRuleRepo_RunInTransaction(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	// RunInTransaction should execute the fn passing the same repo
	err := repo.RunInTransaction(ctx, func(txRepo RuleRepository) error {
		rule := &types.Rule{ID: "tx-rule-1", Name: "created-in-tx", Enabled: true}
		return txRepo.Create(ctx, rule)
	})
	require.NoError(t, err)

	// Verify the rule was created
	rule, err := repo.Get(ctx, "tx-rule-1")
	require.NoError(t, err)
	assert.Equal(t, "created-in-tx", rule.Name)
}

func TestMemoryRuleRepo_RunInTransaction_Error(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	// RunInTransaction should propagate errors from fn
	err := repo.RunInTransaction(ctx, func(txRepo RuleRepository) error {
		return types.ErrInvalidInput
	})
	assert.ErrorIs(t, err, types.ErrInvalidInput)
}

func TestMemoryRuleRepo_RunInTransaction_WithMultipleOps(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	err := repo.RunInTransaction(ctx, func(txRepo RuleRepository) error {
		if err := txRepo.Create(ctx, &types.Rule{ID: "multi-1", Enabled: true}); err != nil {
			return err
		}
		if err := txRepo.Create(ctx, &types.Rule{ID: "multi-2", Enabled: true}); err != nil {
			return err
		}
		return txRepo.Update(ctx, &types.Rule{ID: "multi-1", Enabled: false})
	})
	require.NoError(t, err)

	// Verify both rules exist and multi-1 was updated
	r1, _ := repo.Get(ctx, "multi-1")
	assert.False(t, r1.Enabled)

	r2, _ := repo.Get(ctx, "multi-2")
	assert.True(t, r2.Enabled)
}
