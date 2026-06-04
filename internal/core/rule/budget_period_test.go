package rule

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestCurrentPeriodStart_AndNeedsPeriodReset(t *testing.T) {
	period := 24 * time.Hour
	start := time.Date(2026, 5, 28, 22, 40, 27, 0, time.UTC)
	periodCopy := period
	startCopy := start
	rule := &types.Rule{
		CreatedAt:         start,
		BudgetPeriod:      &periodCopy,
		BudgetPeriodStart: &startCopy,
	}

	now := start.Add(49 * time.Hour) // period index 2
	cps, ok := CurrentPeriodStart(rule, now)
	require.True(t, ok)
	assert.Equal(t, start.Add(48*time.Hour), cps)

	budget := &types.RuleBudget{
		UpdatedAt: start.Add(25 * time.Hour), // previous period
		CreatedAt: start,
	}
	needs, wantStart := NeedsPeriodReset(rule, budget, now)
	assert.True(t, needs)
	assert.Equal(t, cps, wantStart)

	budget.UpdatedAt = now.Add(-time.Hour) // current period
	needs, _ = NeedsPeriodReset(rule, budget, now)
	assert.False(t, needs)
}

func TestNeedsPeriodReset_ZeroUpdatedAtUsesCreatedAt(t *testing.T) {
	period := time.Hour
	start := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	rule := &types.Rule{
		CreatedAt:         start,
		BudgetPeriod:      &period,
		BudgetPeriodStart: &start,
	}
	budget := &types.RuleBudget{
		CreatedAt: start,
	}
	now := start.Add(90 * time.Minute)
	needs, _ := NeedsPeriodReset(rule, budget, now)
	assert.True(t, needs)
}
