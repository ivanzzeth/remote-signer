package evm

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// delegationRuleRepo is an in-memory RuleRepository for delegation tests.
type delegationRuleRepo struct {
	rules map[types.RuleID]*types.Rule
	list  []*types.Rule // order for List()
}

func (r *delegationRuleRepo) Create(ctx context.Context, rule *types.Rule) error { return nil }
func (r *delegationRuleRepo) Update(ctx context.Context, rule *types.Rule) error { return nil }
func (r *delegationRuleRepo) Delete(ctx context.Context, id types.RuleID) error  { return nil }
func (r *delegationRuleRepo) Count(ctx context.Context, filter storage.RuleFilter) (int, error) {
	return len(r.list), nil
}
func (r *delegationRuleRepo) ListByChainType(ctx context.Context, chainType types.ChainType) ([]*types.Rule, error) {
	return r.list, nil
}

func (r *delegationRuleRepo) Get(ctx context.Context, id types.RuleID) (*types.Rule, error) {
	if rule, ok := r.rules[id]; ok {
		return rule, nil
	}
	return nil, types.ErrNotFound
}

func (r *delegationRuleRepo) List(ctx context.Context, filter storage.RuleFilter) ([]*types.Rule, error) {
	return r.list, nil
}

func (r *delegationRuleRepo) IncrementMatchCount(ctx context.Context, id types.RuleID) error {
	return nil
}

func TestDelegation_Single_AllowedByDelegateRule(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Target rule: simple allow
	targetScript := `function validate(i){ return { valid: true }; }`
	targetConfig := mustMarshalJSON(map[string]interface{}{
		"script": targetScript,
	})
	targetRule := &types.Rule{
		ID:         "rule-target",
		Name:       "Target",
		Type:       types.RuleTypeEVMJS,
		Mode:       types.RuleModeWhitelist,
		Config:     targetConfig,
		ChainType:     delegationPtrChainType(types.ChainTypeEVM),
		ChainID:       delegationStrPtr("1"),
		Owner:      "api1",
		SignerAddress:  delegationStrPtr("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
		Enabled:    true,
	}

	// Delegate rule: valid + payload (inner tx) + delegate_to in config
	delegateScript := `function validate(i){
		return {
			valid: true,
			payload: {
				sign_type: "transaction",
				chain_id: 1,
				signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
				transaction: { from: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", to: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", value: "0xde0b6b3a7640000", data: "0x" }
			}
		};
	}`
	delegateConfig := mustMarshalJSON(map[string]interface{}{
		"script":         delegateScript,
		"delegate_to":    "rule-target",
		"delegate_mode":  "single",
	})
	delegateRule := &types.Rule{
		ID:         "rule-delegate",
		Name:       "Delegate",
		Type:       types.RuleTypeEVMJS,
		Mode:       types.RuleModeWhitelist,
		Config:     delegateConfig,
		ChainType:     delegationPtrChainType(types.ChainTypeEVM),
		ChainID:       delegationStrPtr("1"),
		Owner:      "api1",
		SignerAddress:  delegationStrPtr("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
		Enabled:    true,
	}

	repo := &delegationRuleRepo{
		rules: map[types.RuleID]*types.Rule{"rule-target": targetRule, "rule-delegate": delegateRule},
		list:  []*types.Rule{delegateRule, targetRule}, // delegate first so it is tried first
	}

	engine, err := rule.NewWhitelistRuleEngine(repo, log,
		rule.WithDelegationPayloadConverter(DelegatePayloadToSignRequest),
	)
	require.NoError(t, err)
	jsEval, err := NewJSRuleEvaluator(log)
	require.NoError(t, err)
	engine.RegisterEvaluator(jsEval)

	req := &types.SignRequest{
		ID:             "req-1",
		APIKeyID:       "api1",
		ChainType:      types.ChainTypeEVM,
		ChainID:        "1",
		SignerAddress:  "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:       SignTypeTransaction,
		Payload:        []byte(`{"transaction":{"to":"0x742d35Cc6634C0532925a3b844Bc454e4438f44e","value":"1000000000000000000","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	parsed := &types.ParsedPayload{
		Recipient: strPtrForRuleInput("0x742d35Cc6634C0532925a3b844Bc454e4438f44e"),
		Value:     strPtrForRuleInput("1000000000000000000"),
	}

	result, err := engine.EvaluateWithResult(context.Background(), req, parsed)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed, "delegation chain should allow")
	// AllowedBy may be the delegate (first matcher) or the leaf target; both indicate delegation succeeded
	assert.True(t, result.AllowedBy.ID == "rule-delegate" || result.AllowedBy.ID == "rule-target", "AllowedBy should be delegate or target, got %s", result.AllowedBy.ID)
}

// TestDelegation_ScriptReturnedDelegateTo ensures script-returned delegate_to overrides/configures delegation target.
func TestDelegation_ScriptReturnedDelegateTo(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	targetRule := &types.Rule{
		ID: "rule-target", Name: "Target", Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist,
		Config: mustMarshalJSON(map[string]interface{}{"script": `function validate(i){ return { valid: true }; }`}),
		ChainType: delegationPtrChainType(types.ChainTypeEVM), ChainID: delegationStrPtr("1"),
		Owner: "api1", SignerAddress: delegationStrPtr("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"), Enabled: true,
	}
	// No delegate_to in config; script returns delegate_to so delegation still happens
	delegateScript := `function validate(i){
		return { valid: true, payload: { sign_type: "transaction", chain_id: 1, signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", transaction: { from: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", to: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", value: "0x0", data: "0x" } }, delegate_to: "rule-target" };
	}`
	delegateRule := &types.Rule{
		ID: "rule-delegate", Name: "Delegate", Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist,
		Config: mustMarshalJSON(map[string]interface{}{"script": delegateScript}),
		ChainType: delegationPtrChainType(types.ChainTypeEVM), ChainID: delegationStrPtr("1"),
		Owner: "api1", SignerAddress: delegationStrPtr("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"), Enabled: true,
	}

	repo := &delegationRuleRepo{
		rules: map[types.RuleID]*types.Rule{"rule-target": targetRule, "rule-delegate": delegateRule},
		list:  []*types.Rule{delegateRule, targetRule},
	}
	engine, err := rule.NewWhitelistRuleEngine(repo, log, rule.WithDelegationPayloadConverter(DelegatePayloadToSignRequest))
	require.NoError(t, err)
	jsEval, _ := NewJSRuleEvaluator(log)
	engine.RegisterEvaluator(jsEval)

	req := &types.SignRequest{
		ID: "req-1", APIKeyID: "api1", ChainType: types.ChainTypeEVM, ChainID: "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", SignType: SignTypeTransaction,
		Payload: []byte(`{"transaction":{"to":"0x742d35Cc6634C0532925a3b844Bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	parsed := &types.ParsedPayload{Recipient: strPtrForRuleInput("0x742d35Cc6634C0532925a3b844Bc454e4438f44e"), Value: strPtrForRuleInput("0")}

	result, err := engine.EvaluateWithResult(context.Background(), req, parsed)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed, "script-returned delegate_to should delegate and allow")
}

func TestDelegation_Cycle_Rejected(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// A delegates to B; B delegates to A → cycle
	payloadScript := `function validate(i){ return { valid: true, payload: { sign_type: "transaction", chain_id: 1, signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", transaction: { from: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", to: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", value: "0x0", data: "0x" } } }; }`
	configA := mustMarshalJSON(map[string]interface{}{
		"script":        payloadScript,
		"delegate_to":   "rule-b",
		"delegate_mode": "single",
	})
	ruleA := &types.Rule{
		ID: "rule-a", Name: "A", Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist, Config: configA,
		ChainType: delegationPtrChainType(types.ChainTypeEVM), ChainID: delegationStrPtr("1"), Owner: "api1", SignerAddress: delegationStrPtr("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"), Enabled: true,
	}

	configB := mustMarshalJSON(map[string]interface{}{
		"script":        payloadScript,
		"delegate_to":   "rule-a",
		"delegate_mode": "single",
	})
	ruleB := &types.Rule{
		ID: "rule-b", Name: "B", Type: types.RuleTypeEVMJS, Mode: types.RuleModeWhitelist, Config: configB,
		ChainType: delegationPtrChainType(types.ChainTypeEVM), ChainID: delegationStrPtr("1"), Owner: "api1", SignerAddress: delegationStrPtr("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"), Enabled: true,
	}

	repo := &delegationRuleRepo{
		rules: map[types.RuleID]*types.Rule{"rule-a": ruleA, "rule-b": ruleB},
		list:  []*types.Rule{ruleA, ruleB},
	}

	engine, err := rule.NewWhitelistRuleEngine(repo, log, rule.WithDelegationPayloadConverter(DelegatePayloadToSignRequest))
	require.NoError(t, err)
	jsEval, _ := NewJSRuleEvaluator(log)
	engine.RegisterEvaluator(jsEval)

	req := &types.SignRequest{
		ID: "req-1", APIKeyID: "api1", ChainType: types.ChainTypeEVM, ChainID: "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", SignType: SignTypeTransaction,
		Payload: []byte(`{"transaction":{"to":"0x742d35Cc6634C0532925a3b844Bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	parsed := &types.ParsedPayload{Recipient: strPtrForRuleInput("0x742d35Cc6634C0532925a3b844Bc454e4438f44e"), Value: strPtrForRuleInput("0")}

	result, err := engine.EvaluateWithResult(context.Background(), req, parsed)
	require.NoError(t, err)
	// Cycle: A → B → A; engine should not allow (cycle detected)
	assert.False(t, result.Allowed, "cycle should be rejected")
}

func delegationPtrChainType(c types.ChainType) *types.ChainType { return &c }
func delegationStrPtr(s string) *string                          { return &s }
