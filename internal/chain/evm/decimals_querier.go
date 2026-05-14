package evm

import (
	"context"
	"fmt"

	"github.com/ivanzzeth/remote-signer/internal/core/rule"
)

// DecimalsQuerierAdapter adapts TokenMetadataCache to the rule.DecimalsQuerier interface.
// It wraps the RPC-backed token metadata cache and provides a simplified API for
// the budget checker to auto-query ERC20 decimals.
type DecimalsQuerierAdapter struct {
	cache *TokenMetadataCache
}

// Verify interface compliance at compile time.
var _ rule.DecimalsQuerier = (*DecimalsQuerierAdapter)(nil)

// NewDecimalsQuerierAdapter creates a new adapter. cache must not be nil.
func NewDecimalsQuerierAdapter(cache *TokenMetadataCache) (*DecimalsQuerierAdapter, error) {
	if cache == nil {
		return nil, fmt.Errorf("token metadata cache is required")
	}
	return &DecimalsQuerierAdapter{cache: cache}, nil
}

// QueryDecimals queries ERC20 decimals for the given token address on the given chain.
// Uses a generous per-call counter (1 call allowed) since the budget checker caches results.
func (a *DecimalsQuerierAdapter) QueryDecimals(ctx context.Context, chainID, address string) (int, error) {
	// Allow 1 RPC call per query; the BudgetChecker caches results so this is called at most once per token.
	counter := NewRPCCallCounter(1)
	return a.cache.GetDecimals(ctx, chainID, address, counter)
}
