//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_PresetApply_KeyPresets applies all important production presets and
// verifies they create the expected rules. Covers: predict, staking, erc20,
// native_transfer, weth, agent, global_blocklist, meta_transaction,
// eip4337_userop, erc721, dex_swap.
//
// Each preset uses operator_overrides to make all variables optional, so
// applying with zero overrides uses defaults from the preset file.
func TestE2E_PresetApply_KeyPresets(t *testing.T) {
	ensureGuardResumed(t)
	skipIfPresetAPIDisabled(t)
	ctx := context.Background()

	tests := []struct {
		name          string
		presetID      string
		wantRuleCount int // expected number of rules created
		skipReason    string // non-empty = skip with this reason
	}{
		{
			// predict_auth (1) + predict_enable_trading_js bundle (2) + predict_trading_js bundle (3) = 6
			name:          "predict_eoa_bnb_js",
			presetID:      "evm/predict_eoa_bnb_js",
			wantRuleCount: 6,
		},
		{
			name:          "staking",
			presetID:      "evm/staking",
			wantRuleCount: 1, // staking-ops
		},
		{
			// erc20 bundle: erc20-transfer-limit + erc20-approve-limit
			name:          "erc20",
			presetID:      "evm/erc20",
			wantRuleCount: 2,
		},
		{
			name:          "native_transfer",
			presetID:      "evm/native_transfer",
			wantRuleCount: 1, // native-transfer-limit
		},
		{
			name:          "weth",
			presetID:      "evm/weth",
			wantRuleCount: 1, // weth-deposit-withdraw
		},
		{
			name:          "global_blocklist",
			presetID:      "evm/global_blocklist",
			wantRuleCount: 1, // global-blocklist
		},
		{
			// agent bundle: agent-sign + agent-safety
			name:          "agent",
			presetID:      "evm/agent",
			wantRuleCount: 2,
		},
		{
			name:          "meta_transaction",
			presetID:      "evm/meta_transaction",
			wantRuleCount: 1, // meta-transaction
		},
		{
			name:          "eip4337_userop",
			presetID:      "evm/eip4337_userop",
			wantRuleCount: 1, // eip4337-userop
		},
		{
			name:          "erc721",
			presetID:      "evm/erc721",
			wantRuleCount: 1, // erc721-transfer-approve
		},
		{
			name:          "dex_swap",
			presetID:      "evm/dex_swap",
			wantRuleCount: 1, // dex-swap
		},
		{
			name:          "uniswap_v2",
			presetID:      "evm/uniswap_v2",
			wantRuleCount: 1,
			skipReason:    "matrix expansion not supported post-migration (chain_id embedded in matrix)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipReason != "" {
				t.Skip(tt.skipReason)
			}

			snapshotRules(t)

			resp, err := adminClient.Presets.ApplyWithVariables(ctx, tt.presetID, nil)
			require.NoError(t, err, "preset %s should apply successfully", tt.presetID)
			require.NotNil(t, resp)
			require.Len(t, resp.Results, tt.wantRuleCount,
				"preset %s should create %d rules", tt.presetID, tt.wantRuleCount)

			// Verify each created rule is fetchable via the API.
			// Decode to map first to avoid type mismatches (e.g. budget_period
			// is stored as *time.Duration in Go but serialised as a JSON number,
			// confusing the SDK's string-typed BudgetPeriod field).
			for i, result := range resp.Results {
				var ruleMap map[string]interface{}
				err := json.Unmarshal(result.Rule, &ruleMap)
				require.NoError(t, err, "result %d should be valid JSON", i)
				ruleID, _ := ruleMap["id"].(string)
				require.NotEmpty(t, ruleID, "result %d should have a rule ID", i)

				fetched, err := adminClient.EVM.Rules.Get(ctx, ruleID)
				require.NoError(t, err, "rule %s should be fetchable via API", ruleID)
				require.NotNil(t, fetched)
				assert.True(t, fetched.Enabled, "rule %s should be enabled", ruleID)
				t.Logf("  [%s] rule %s: %s (type=%s, mode=%s)", tt.name, ruleID, ruleMap["name"], ruleMap["type"], ruleMap["mode"])
			}
		})
	}
}

// TestE2E_PresetApply_VerifyConfigs applies key presets and verifies their
// resolved config values (chain_id, budget, schedule) are correct.
func TestE2E_PresetApply_VerifyConfigs(t *testing.T) {
	ensureGuardResumed(t)
	skipIfPresetAPIDisabled(t)
	ctx := context.Background()

	t.Run("staking default chain_id", func(t *testing.T) {
		snapshotRules(t)

		resp, err := adminClient.Presets.ApplyWithVariables(ctx, "evm/staking", nil)
		require.NoError(t, err)
		require.Len(t, resp.Results, 1)

		var ruleMap map[string]interface{}
		require.NoError(t, json.Unmarshal(resp.Results[0].Rule, &ruleMap))

		chainID, _ := ruleMap["chain_id"].(string)
		assert.Equal(t, "1", chainID, "staking preset chain_id should default to 1")
	})

	t.Run("erc20 default variables", func(t *testing.T) {
		snapshotRules(t)

		resp, err := adminClient.Presets.ApplyWithVariables(ctx, "evm/erc20", nil)
		require.NoError(t, err)
		require.Len(t, resp.Results, 2)

		for _, result := range resp.Results {
			var ruleMap map[string]interface{}
			require.NoError(t, json.Unmarshal(result.Rule, &ruleMap))
			// Non-empty config means variable substitution succeeded
			cfgRaw, _ := ruleMap["config"].(string)
			assert.NotEmpty(t, cfgRaw, "rule should have resolved config")
		}
	})

	t.Run("agent bundle sub-rules", func(t *testing.T) {
		snapshotRules(t)

		resp, err := adminClient.Presets.ApplyWithVariables(ctx, "evm/agent", nil)
		require.NoError(t, err)
		require.Len(t, resp.Results, 2, "agent preset should create 2 sub-rules")

		var hasSign, hasSafety bool
		for _, result := range resp.Results {
			var ruleMap map[string]interface{}
			require.NoError(t, json.Unmarshal(result.Rule, &ruleMap))
			name, _ := ruleMap["name"].(string)
			mode, _ := ruleMap["mode"].(string)
			t.Logf("Agent sub-rule: name=%s, mode=%s", name, mode)
			if mode == "whitelist" {
				hasSign = true
			}
			if mode == "blocklist" {
				hasSafety = true
			}
		}
		assert.True(t, hasSign, "agent preset should include a whitelist rule (agent-sign)")
		assert.True(t, hasSafety, "agent preset should include a blocklist rule (agent-safety)")
	})

	t.Run("global_blocklist mode", func(t *testing.T) {
		snapshotRules(t)

		resp, err := adminClient.Presets.ApplyWithVariables(ctx, "evm/global_blocklist", nil)
		require.NoError(t, err)
		require.Len(t, resp.Results, 1)

		var ruleMap map[string]interface{}
		require.NoError(t, json.Unmarshal(resp.Results[0].Rule, &ruleMap))
		mode, _ := ruleMap["mode"].(string)
		assert.Equal(t, "blocklist", mode, "global_blocklist should be in blocklist mode")
	})

	t.Run("predict chain_id", func(t *testing.T) {
		snapshotRules(t)

		resp, err := adminClient.Presets.ApplyWithVariables(ctx, "evm/predict_eoa_bnb_js", nil)
		require.NoError(t, err)
		require.Len(t, resp.Results, 6)

		for _, result := range resp.Results {
			var ruleMap map[string]interface{}
			require.NoError(t, json.Unmarshal(result.Rule, &ruleMap))
			chainID, _ := ruleMap["chain_id"].(string)
			assert.Equal(t, "56", chainID, "predict preset chain_id should default to 56")
			break // just check the first rule
		}
	})
}
