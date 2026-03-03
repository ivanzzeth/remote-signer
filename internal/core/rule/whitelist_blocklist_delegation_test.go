package rule

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// =============================================================================
// Mock repository that supports configurable List error for blocklist tests
// =============================================================================

// blocklistTestRepo lets tests control exactly which rules List returns and
// whether it returns an error.  It embeds mockRuleRepository so Get and other
// methods still work via the default implementation.
type blocklistTestRepo struct {
	mockRuleRepository
	listRules []*types.Rule
	listErr   error
}

func (r *blocklistTestRepo) List(ctx context.Context, filter storage.RuleFilter) ([]*types.Rule, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	return r.listRules, nil
}

// =============================================================================
// Tests for evaluateBlocklistForRequest
// =============================================================================

// TestEvaluateBlocklistForRequest_NoBlocklistRules verifies that when the
// repository returns rules but none are blocklist mode, the method returns
// (nil, nil) -- i.e. no block, no error.
func TestEvaluateBlocklistForRequest_NoBlocklistRules(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Only whitelist rules in the repo -- no blocklist rules at all.
	repo := &blocklistTestRepo{
		listRules: []*types.Rule{
			{
				ID:      "allow-1",
				Name:    "whitelist rule",
				Type:    "mock_type",
				Mode:    types.RuleModeWhitelist,
				Enabled: true,
			},
		},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	engine.RegisterEvaluator(&mockEvaluator{
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			t.Fatal("evaluator should not be called for whitelist rules in blocklist check")
			return false, "", nil
		},
	})

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		APIKeyID:      "key-1",
		SignType:      "transaction",
	}

	result, evalErr := engine.evaluateBlocklistForRequest(context.Background(), req, nil)
	assert.NoError(t, evalErr)
	assert.Nil(t, result, "no blocklist rules => nil result")
}

// TestEvaluateBlocklistForRequest_BlocklistViolated verifies that when a
// blocklist rule's evaluator reports a violation (returns true), the method
// returns an EvaluationResult with Blocked=true and BlockedBy set.
func TestEvaluateBlocklistForRequest_BlocklistViolated(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	blockRule := &types.Rule{
		ID:      "block-1",
		Name:    "blacklisted address",
		Type:    "mock_block",
		Mode:    types.RuleModeBlocklist,
		Enabled: true,
	}
	repo := &blocklistTestRepo{
		listRules: []*types.Rule{blockRule},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	engine.RegisterEvaluator(&customTypeEvaluator{
		ruleType: "mock_block",
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			return true, "address is blacklisted", nil // violated
		},
	})

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		APIKeyID:      "key-1",
		SignType:      "transaction",
	}

	result, evalErr := engine.evaluateBlocklistForRequest(context.Background(), req, nil)
	require.NoError(t, evalErr)
	require.NotNil(t, result, "violated blocklist should return a result")
	assert.True(t, result.Blocked)
	assert.Equal(t, types.RuleID("block-1"), result.BlockedBy.ID)
	assert.Equal(t, "address is blacklisted", result.BlockReason)
}

// TestEvaluateBlocklistForRequest_BlocklistNotViolated verifies that when
// blocklist rules exist but none report a violation, the method returns
// (nil, nil).
func TestEvaluateBlocklistForRequest_BlocklistNotViolated(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	blockRule := &types.Rule{
		ID:      "block-1",
		Name:    "value limit",
		Type:    "mock_block",
		Mode:    types.RuleModeBlocklist,
		Enabled: true,
	}
	repo := &blocklistTestRepo{
		listRules: []*types.Rule{blockRule},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	engine.RegisterEvaluator(&customTypeEvaluator{
		ruleType: "mock_block",
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			return false, "", nil // not violated
		},
	})

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		APIKeyID:      "key-1",
		SignType:      "transaction",
	}

	result, evalErr := engine.evaluateBlocklistForRequest(context.Background(), req, nil)
	assert.NoError(t, evalErr)
	assert.Nil(t, result, "no violation => nil result")
}

// TestEvaluateBlocklistForRequest_EvaluatorError_FailClosed verifies Fail-Closed
// behavior: when a blocklist rule's evaluator returns an error, the method
// returns a RuleEvaluationError wrapping ErrRuleEvaluationFailed.
func TestEvaluateBlocklistForRequest_EvaluatorError_FailClosed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	blockRule := &types.Rule{
		ID:      "block-1",
		Name:    "broken evaluator",
		Type:    "mock_block",
		Mode:    types.RuleModeBlocklist,
		Enabled: true,
	}
	repo := &blocklistTestRepo{
		listRules: []*types.Rule{blockRule},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	engine.RegisterEvaluator(&customTypeEvaluator{
		ruleType: "mock_block",
		evaluateFunc: func(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
			return false, "", fmt.Errorf("evaluator crashed")
		},
	})

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		APIKeyID:      "key-1",
		SignType:      "transaction",
	}

	result, evalErr := engine.evaluateBlocklistForRequest(context.Background(), req, nil)
	assert.Nil(t, result, "on error, result should be nil")
	require.Error(t, evalErr)

	// Verify the error is a RuleEvaluationError with the correct rule ID.
	var ruleErr *RuleEvaluationError
	require.ErrorAs(t, evalErr, &ruleErr)
	assert.Equal(t, types.RuleID("block-1"), ruleErr.RuleID)
	assert.Equal(t, "broken evaluator", ruleErr.RuleName)

	// Verify it wraps ErrRuleEvaluationFailed for callers using errors.Is.
	assert.ErrorIs(t, evalErr, ErrRuleEvaluationFailed)
}

// TestEvaluateBlocklistForRequest_MissingEvaluator_FailClosed verifies
// Fail-Closed behavior: when no evaluator is registered for a blocklist rule's
// type, the method returns a RuleEvaluationError.
func TestEvaluateBlocklistForRequest_MissingEvaluator_FailClosed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	blockRule := &types.Rule{
		ID:      "block-1",
		Name:    "unregistered type",
		Type:    "nonexistent_type",
		Mode:    types.RuleModeBlocklist,
		Enabled: true,
	}
	repo := &blocklistTestRepo{
		listRules: []*types.Rule{blockRule},
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)
	// Intentionally do NOT register any evaluator for "nonexistent_type".

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		APIKeyID:      "key-1",
		SignType:      "transaction",
	}

	result, evalErr := engine.evaluateBlocklistForRequest(context.Background(), req, nil)
	assert.Nil(t, result, "on error, result should be nil")
	require.Error(t, evalErr)

	var ruleErr *RuleEvaluationError
	require.ErrorAs(t, evalErr, &ruleErr)
	assert.Equal(t, types.RuleID("block-1"), ruleErr.RuleID)
	assert.Contains(t, ruleErr.Error(), "no evaluator registered")
	assert.ErrorIs(t, evalErr, ErrRuleEvaluationFailed)
}

// TestEvaluateBlocklistForRequest_RepoError verifies that when
// repo.List returns an error, the method propagates it.
func TestEvaluateBlocklistForRequest_RepoError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	repo := &blocklistTestRepo{
		listErr: fmt.Errorf("database connection lost"),
	}

	engine, err := NewWhitelistRuleEngine(repo, logger)
	require.NoError(t, err)

	req := &types.SignRequest{
		ID:            "req-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		APIKeyID:      "key-1",
		SignType:      "transaction",
	}

	result, evalErr := engine.evaluateBlocklistForRequest(context.Background(), req, nil)
	assert.Nil(t, result)
	require.Error(t, evalErr)
	assert.Contains(t, evalErr.Error(), "failed to list rules")
	assert.Contains(t, evalErr.Error(), "database connection lost")
}
