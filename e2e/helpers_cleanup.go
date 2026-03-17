//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/pkg/client/presets"
)

// cleanupApplyResults registers a t.Cleanup that revokes/deletes all rules
// created by a preset apply response.
func cleanupApplyResults(t *testing.T, results []presets.ApplyResultItem) {
	t.Helper()
	var ruleIDs []string
	for _, result := range results {
		var ruleMap map[string]interface{}
		if err := json.Unmarshal(result.Rule, &ruleMap); err == nil {
			if id, ok := ruleMap["id"].(string); ok {
				ruleIDs = append(ruleIDs, id)
			}
		}
	}
	t.Cleanup(func() {
		ctx := context.Background()
		for _, id := range ruleIDs {
			if _, err := adminClient.Templates.RevokeInstance(ctx, id); err != nil {
				if delErr := adminClient.EVM.Rules.Delete(ctx, id); delErr != nil {
					t.Logf("Warning: failed to cleanup rule %s: %v", id, delErr)
				}
			}
		}
	})
}

// snapshotRules records the current set of rule IDs and registers a t.Cleanup
// that deletes any rules added during the test. This prevents state leakage
// between tests without requiring each test to manually track its created rules.
func snapshotRules(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	before, err := adminClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	if err != nil {
		t.Logf("Warning: snapshotRules failed to list rules: %v", err)
		return
	}
	existing := make(map[string]bool, len(before.Rules))
	for _, r := range before.Rules {
		existing[r.ID] = true
	}
	t.Cleanup(func() {
		cleanCtx := context.Background()
		after, err := adminClient.EVM.Rules.List(cleanCtx, &evm.ListRulesFilter{Limit: 1000})
		if err != nil {
			t.Logf("Warning: snapshotRules cleanup failed to list rules: %v", err)
			return
		}
		for _, r := range after.Rules {
			if !existing[r.ID] {
				if delErr := adminClient.EVM.Rules.Delete(cleanCtx, r.ID); delErr != nil {
					t.Logf("Warning: snapshotRules failed to delete rule %s: %v", r.ID, delErr)
				}
			}
		}
	})
}
