//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// TestPreset_Apply_MatchCountIncrements is P1 #5 in MISSING_COVERAGE.md.
//
// Closes the loop preset → instantiate → engine evaluates → match_count
// increments. The bundle-template bug masked exactly this signal: rules
// were created with the wrong shape, evaluation silently skipped them,
// and match_count stayed at zero — but neither the preset apply nor the
// rule list surface said anything was wrong. By asserting the counter
// moves after a *known matching* sign request, this test catches any
// future regression that lands a "ghost rule" the engine refuses to run.
//
// Uses the test-only `evm/e2e_preset` template (single rule,
// evm_address_list whitelist) so the assertion stays simple: sign a tx
// to the whitelisted address, then re-fetch the rule and verify
// match_count >= 1.
func TestPreset_Apply_MatchCountIncrements(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)
	ensureGuardResumed(t)

	allowed := "0x000000000000000000000000000000000000aBcD"

	applyResp, err := adminClient.Presets.ApplyWithVariables(
		ctx, "e2e_minimal.preset",
		map[string]string{"allowed_address": allowed},
	)
	require.NoError(t, err)
	require.Len(t, applyResp.Results, 1)
	cleanupApplyResults(t, applyResp.Results)

	var ruleMap map[string]any
	require.NoError(t, json.Unmarshal(applyResp.Results[0].Rule, &ruleMap))
	ruleID, _ := ruleMap["id"].(string)
	require.NotEmpty(t, ruleID, "preset apply must return the instantiated rule's id")

	// Baseline match_count before the sign.
	before, err := adminClient.EVM.Rules.Get(ctx, ruleID)
	require.NoError(t, err)
	beforeCount := before.MatchCount

	// Send a transaction that the rule WILL match (recipient is the
	// whitelisted address from preset variables). evm_address_list
	// matches against transaction.to.
	txPayload := []byte(`{"transaction":{"to":"` + allowed + `","value":"0","gas":21000,"gasPrice":"1000000000","txType":"legacy","nonce":0}}`)
	signResp, err := adminClient.EVM.Sign.Execute(ctx, &evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      evm.SignTypeTransaction,
		Payload:       txPayload,
	})
	require.NoError(t, err,
		"sign MUST succeed — the recipient address is in the whitelist applied from the preset")
	require.NotNil(t, signResp)
	assert.Equal(t, "completed", string(signResp.Status),
		"status MUST be 'completed' — the engine evaluated the rule and auto-approved. 'pending' here means the engine skipped the rule (no evaluator / wrong shape).")

	// Re-fetch the rule and assert match_count moved by at least 1.
	// Strict-equality on +1 would be flaky if any other test in the
	// same run triggered the rule, so use >=.
	after, err := adminClient.EVM.Rules.Get(ctx, ruleID)
	require.NoError(t, err)
	assert.Greater(t, after.MatchCount, beforeCount,
		"rule.match_count MUST advance after a matching sign — same count means the engine never selected this rule (was the type field dropped? evaluator missing?)")
	if after.LastMatchedAt == nil {
		t.Error("rule.last_matched_at MUST be set after a successful match; nil means the audit path didn't record the match either")
	}
}

// TestPreset_Apply_BundleTemplate_ExpandsSubRules is P2 #10 in
// MISSING_COVERAGE.md.
//
// The single-template preset apply path already returns one rule per
// template_id. For BUNDLE templates the registry expands the top-level
// `rules:` array into one persisted rule per sub-rule entry, server-side.
// The bundle bug landed because the dispatch never fired and only the
// "primary" rule got created (with type="" — the engine then skipped it).
//
// This test exercises the shipped `evm/agent` bundle template (2 sub-rules:
// agent-sign whitelist + agent-safety blocklist) and asserts that after
// preset apply BOTH rules exist in the rule list. Without the fix the
// list would only show one rule (or zero with the type="" landing in
// a row the rule engine ignores).
func TestPreset_Apply_BundleTemplate_ExpandsSubRules(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	// Snapshot existing rule IDs so we can diff after apply.
	before, err := adminClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	require.NoError(t, err)
	beforeIDs := make(map[string]struct{}, len(before.Rules))
	for _, r := range before.Rules {
		beforeIDs[r.ID] = struct{}{}
	}

	applyResp, err := adminClient.Presets.ApplyWithVariables(ctx, "agent.preset.js", nil)
	require.NoError(t, err)
	require.NotEmpty(t, applyResp.Results, "preset apply must produce at least one Result")
	cleanupApplyResults(t, applyResp.Results)

	// Find every rule created since the snapshot — these are the
	// bundle's expansion plus the apply-response primary.
	after, err := adminClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	require.NoError(t, err)
	var newlyCreated []evm.Rule
	for _, r := range after.Rules {
		if _, seen := beforeIDs[r.ID]; !seen {
			newlyCreated = append(newlyCreated, r)
		}
	}

	// Bundle expansion: the shipped evm/agent template declares two
	// sub-rules (agent-sign whitelist, agent-safety blocklist). Apply
	// MUST produce at least these two rules; if it produced exactly
	// one (or zero new types), the bundle dispatch is broken again.
	require.GreaterOrEqual(t, len(newlyCreated), 2,
		"bundle preset apply MUST create one rule per sub-rule in the bundle (evm/agent has 2: agent-sign + agent-safety); got %d new rules — bundle dispatch likely fell through to single-rule path",
		len(newlyCreated))

	// Each created rule MUST carry a non-empty, valid evaluator type.
	// This is the closest layer to the original bug: even if rows
	// exist, type="" leaves them invisible to the engine.
	var seenWhitelist, seenBlocklist bool
	for _, r := range newlyCreated {
		assert.NotEmpty(t, r.Type,
			"bundle-expanded rule %q MUST carry a non-empty type — empty type means the engine has no evaluator and silently skips this row",
			r.ID)
		assert.NotEqual(t, "template_bundle", r.Type,
			"bundle-expanded rule %q MUST be the SUB-RULE's type, not the bundle meta-type (template_bundle); the instantiator failed to expand",
			r.ID)
		switch r.Mode {
		case "whitelist":
			seenWhitelist = true
		case "blocklist":
			seenBlocklist = true
		}
	}
	// agent template carries both modes; a missing one means the
	// dispatch dropped a sub-rule. Sub-rule order isn't fixed so we
	// assert the set, not the slice.
	assert.True(t, seenWhitelist,
		"bundle expansion MUST produce the whitelist sub-rule (agent-sign)")
	assert.True(t, seenBlocklist,
		"bundle expansion MUST produce the blocklist sub-rule (agent-safety)")
}
