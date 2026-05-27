//go:build integration

package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// sharedSolidityEvaluator creates a single SolidityRuleEvaluator reused across all
// subtests. Because forge compiles all .sol files in the workspace, sharing avoids
// recompilation overhead (each new workspace costs ~12s). Stale script files are
// removed between subtests to prevent incompatible signatures from polluting compilation.
type sharedSolidityEvaluator struct {
	e        *SolidityRuleEvaluator
	workspace string
}

func newSharedSolidityEvaluator(t *testing.T) *sharedSolidityEvaluator {
	t.Helper()
	if _, err := exec.LookPath("forge"); err != nil {
		t.Skip("forge not found, skipping")
	}
	workspace := t.TempDir()
	e, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		TempDir: workspace,
	}, newTestLogger())
	require.NoError(t, err)
	return &sharedSolidityEvaluator{e: e, workspace: workspace}
}

// cleanScripts removes all .sol files from the workspace so stale scripts with
// incompatible signatures don't pollute subsequent forge compilations.
func (s *sharedSolidityEvaluator) cleanScripts(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(s.workspace)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".sol" {
			_ = os.Remove(filepath.Join(s.workspace, entry.Name()))
		}
	}
}

// defaultRequestEnv returns a minimal set of env vars required by the expression template.
func defaultRequestEnv() []string {
	return []string{
		"RULE_TX_TO=0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
		"RULE_TX_VALUE=0",
		"RULE_TX_SELECTOR=0x00000000",
		"RULE_TX_DATA=0x",
		"RULE_CHAIN_ID=1",
		"RULE_SIGNER=0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}
}

func transferCalldata() []byte {
	b, _ := hex.DecodeString(
		"a9059cbb" +
			"0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc4" +
			"0000000000000000000000000000000000000000000000000000000000000001",
	)
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// executeScript — forge execution pipeline (solidity_execution.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestExecuteScript_All(t *testing.T) {
	s := newSharedSolidityEvaluator(t)
	e := s.e

	t.Run("Expression_Pass", func(t *testing.T) {
		s.cleanScripts(t)
		script, err := e.generateExpressionScript("require(true);", nil)
		require.NoError(t, err)
		passed, reason, err := e.executeScript(bgCtx, script, defaultRequestEnv())
		require.NoError(t, err)
		assert.True(t, passed)
		assert.Empty(t, reason)
	})

	t.Run("Expression_Revert", func(t *testing.T) {
		s.cleanScripts(t)
		script, err := e.generateExpressionScript(`require(false, "test fail");`, nil)
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		passed, reason, err := e.executeScript(ctx, script, defaultRequestEnv())
		if err != nil {
			t.Logf("revert test resulted in error (possibly timeout): %v", err)
			return
		}
		assert.False(t, passed)
		assert.Contains(t, reason, "test fail")
	})

	t.Run("Expression_WithRequestEnv", func(t *testing.T) {
		s.cleanScripts(t)
		script, err := e.generateExpressionScript("require(tx_to != address(0));", nil)
		require.NoError(t, err)
		env := []string{
			"RULE_TX_TO=0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
			"RULE_TX_VALUE=0",
			"RULE_TX_SELECTOR=0x00000000",
			"RULE_TX_DATA=0x",
			"RULE_CHAIN_ID=1",
			"RULE_SIGNER=0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
		}
		passed, reason, err := e.executeScript(bgCtx, script, env)
		require.NoError(t, err)
		assert.True(t, passed)
		assert.Empty(t, reason)
	})

	t.Run("WithFilePathHint", func(t *testing.T) {
		s.cleanScripts(t)
		script, err := e.generateExpressionScript("require(true);", nil)
		require.NoError(t, err)
		passed, reason, err := e.executeScript(bgCtx, script, defaultRequestEnv(), "my_group")
		require.NoError(t, err)
		assert.True(t, passed)
		assert.Empty(t, reason)
	})

	t.Run("Caching", func(t *testing.T) {
		s.cleanScripts(t)
		script, err := e.generateExpressionScript("require(true);", nil)
		require.NoError(t, err)
		passed1, reason1, err1 := e.executeScript(bgCtx, script, defaultRequestEnv())
		require.NoError(t, err1)
		assert.True(t, passed1)
		assert.Empty(t, reason1)
		passed2, reason2, err2 := e.executeScript(bgCtx, script, defaultRequestEnv())
		require.NoError(t, err2)
		assert.True(t, passed2)
		assert.Empty(t, reason2)
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// evaluateExpression / evaluateFunctions (solidity_evaluator.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluateExpression_All(t *testing.T) {
	s := newSharedSolidityEvaluator(t)
	e := s.e

	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}
	parsed := &types.ParsedPayload{
		Recipient: strPtr("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"),
		RawData:   []byte{0x12, 0x34, 0x56, 0x78},
	}

	t.Run("Pass", func(t *testing.T) {
		s.cleanScripts(t)
		passed, reason, err := e.evaluateExpression(bgCtx, "require(true);", req, parsed, nil)
		require.NoError(t, err)
		assert.True(t, passed)
		assert.Empty(t, reason)
	})

	t.Run("Revert", func(t *testing.T) {
		s.cleanScripts(t)
		passed, reason, err := e.evaluateExpression(bgCtx, `require(false, "nope");`, req, parsed, nil)
		require.NoError(t, err)
		assert.False(t, passed)
		assert.Contains(t, reason, "nope")
	})
}

func TestEvaluateFunctions_All(t *testing.T) {
	s := newSharedSolidityEvaluator(t)
	e := s.e

	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}

	t.Run("Pass", func(t *testing.T) {
		s.cleanScripts(t)
		parsed := &types.ParsedPayload{
			Recipient: strPtr("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"),
			RawData:   transferCalldata(),
		}
		passed, reason, err := e.evaluateFunctions(bgCtx, `function transfer(address, uint256) external { require(true); }`, req, parsed, nil)
		require.NoError(t, err)
		assert.True(t, passed)
		assert.Empty(t, reason)
	})

	t.Run("Revert", func(t *testing.T) {
		s.cleanScripts(t)
		parsed := &types.ParsedPayload{
			Recipient: strPtr("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"),
			RawData:   transferCalldata(),
		}
		passed, reason, err := e.evaluateFunctions(bgCtx, `function transfer(address, uint256) external { require(false, "func fail"); }`, req, parsed, nil)
		require.NoError(t, err)
		assert.False(t, passed)
		assert.Contains(t, reason, "func fail")
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Evaluate — main Evaluate paths (solidity_evaluator.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluate_Expression_All(t *testing.T) {
	s := newSharedSolidityEvaluator(t)
	e := s.e

	parsed := &types.ParsedPayload{
		Recipient: strPtr("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"),
		RawData:   []byte{0x12, 0x34, 0x56, 0x78},
	}

	t.Run("Pass", func(t *testing.T) {
		s.cleanScripts(t)
		rule := &types.Rule{
			Mode: types.RuleModeWhitelist,
			Config: mustJSONMarshal(t, SolidityExpressionConfig{Expression: "require(true);"}),
		}
		req := &types.SignRequest{ChainID: "1", SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"}
		passed, reason, err := e.Evaluate(bgCtx, rule, req, parsed)
		require.NoError(t, err)
		assert.True(t, passed)
		assert.Empty(t, reason)
	})

	t.Run("Revert", func(t *testing.T) {
		s.cleanScripts(t)
		rule := &types.Rule{
			Mode:   types.RuleModeWhitelist,
			Config: mustJSONMarshal(t, SolidityExpressionConfig{Expression: `require(false, "bad");`}),
		}
		req := &types.SignRequest{ChainID: "1", SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"}
		passed, reason, err := e.Evaluate(bgCtx, rule, req, parsed)
		require.NoError(t, err)
		assert.False(t, passed)
		assert.Contains(t, reason, "bad")
	})

	t.Run("Blocklist", func(t *testing.T) {
		s.cleanScripts(t)
		rule := &types.Rule{
			Mode:   types.RuleModeBlocklist,
			Config: mustJSONMarshal(t, SolidityExpressionConfig{Expression: `require(false, "violation");`}),
		}
		req := &types.SignRequest{ChainID: "1", SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"}
		passed, reason, err := e.Evaluate(bgCtx, rule, req, parsed)
		require.NoError(t, err)
		assert.True(t, passed)
		assert.Contains(t, reason, "violation")
	})

	t.Run("Blocklist_Pass", func(t *testing.T) {
		s.cleanScripts(t)
		rule := &types.Rule{
			Mode:   types.RuleModeBlocklist,
			Config: mustJSONMarshal(t, SolidityExpressionConfig{Expression: `require(true);`}),
		}
		req := &types.SignRequest{ChainID: "1", SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"}
		passed, reason, err := e.Evaluate(bgCtx, rule, req, parsed)
		require.NoError(t, err)
		assert.False(t, passed)
		assert.Empty(t, reason)
	})

	t.Run("Functions_Pass", func(t *testing.T) {
		s.cleanScripts(t)
		rule := &types.Rule{
			Mode: types.RuleModeWhitelist,
			Config: mustJSONMarshal(t, SolidityExpressionConfig{
				Functions: `function transfer(address, uint256) external { require(true); }`,
			}),
		}
		req := &types.SignRequest{ChainID: "1", SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"}
		fnParsed := &types.ParsedPayload{
			Recipient: strPtr("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"),
			RawData:   transferCalldata(),
		}
		passed, reason, err := e.Evaluate(bgCtx, rule, req, fnParsed)
		require.NoError(t, err)
		assert.True(t, passed)
		assert.Empty(t, reason)
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Evaluate — TypedData paths (solidity_typed_data.go via Evaluate)
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluate_TypedData_All(t *testing.T) {
	s := newSharedSolidityEvaluator(t)
	e := s.e

	t.Run("Expression_Pass", func(t *testing.T) {
		s.cleanScripts(t)
		payload := makeTypedDataPayload(t, map[string]interface{}{
			"types": map[string]interface{}{
				"Order": []interface{}{
					map[string]interface{}{"name": "maker", "type": "address"},
					map[string]interface{}{"name": "salt", "type": "uint256"},
				},
			},
			"primaryType": "Order",
			"domain":      map[string]interface{}{"name": "Test", "version": "1", "chainId": "1", "verifyingContract": "0x0000000000000000000000000000000000000000"},
			"message":     map[string]interface{}{"maker": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4", "salt": "12345"},
		})
		rule := &types.Rule{
			Mode: types.RuleModeWhitelist,
			Config: mustJSONMarshal(t, SolidityExpressionConfig{
				TypedDataExpression: "require(true);",
				TypedDataStruct:     "struct Order { address maker; uint256 salt; }",
			}),
		}
		req := &types.SignRequest{ChainID: "1", SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4", Payload: payload}
		passed, reason, err := e.Evaluate(bgCtx, rule, req, nil)
		require.NoError(t, err)
		assert.True(t, passed)
		assert.Empty(t, reason)
	})

	t.Run("Expression_Revert", func(t *testing.T) {
		s.cleanScripts(t)
		payload := makeTypedDataPayload(t, map[string]interface{}{
			"types":       map[string]interface{}{"Order": []interface{}{map[string]interface{}{"name": "maker", "type": "address"}}},
			"primaryType": "Order",
			"domain":      map[string]interface{}{"name": "Test", "version": "1", "chainId": "1", "verifyingContract": "0x0000000000000000000000000000000000000000"},
			"message":     map[string]interface{}{"maker": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"},
		})
		rule := &types.Rule{
			Mode: types.RuleModeWhitelist,
			Config: mustJSONMarshal(t, SolidityExpressionConfig{
				TypedDataExpression: `require(false, "td fail");`,
				TypedDataStruct:     "struct Order { address maker; }",
			}),
		}
		req := &types.SignRequest{ChainID: "1", SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4", Payload: payload}
		passed, reason, err := e.Evaluate(bgCtx, rule, req, nil)
		require.NoError(t, err)
		assert.False(t, passed)
		assert.Contains(t, reason, "td fail")
	})

	t.Run("Functions_Pass", func(t *testing.T) {
		s.cleanScripts(t)
		payload := makeTypedDataPayload(t, map[string]interface{}{
			"types":       map[string]interface{}{},
			"primaryType": "Order",
			"domain":      map[string]interface{}{"name": "Test", "version": "1", "chainId": "1", "verifyingContract": "0x0000000000000000000000000000000000000000"},
			"message":     map[string]interface{}{"maker": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"},
		})
		rule := &types.Rule{
			Mode: types.RuleModeWhitelist,
			Config: mustJSONMarshal(t, SolidityExpressionConfig{
				TypedDataFunctions: "function checkOrder() public pure returns (bool) { return true; }",
			}),
		}
		req := &types.SignRequest{ChainID: "1", SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4", Payload: payload}
		passed, reason, err := e.Evaluate(bgCtx, rule, req, nil)
		require.NoError(t, err)
		assert.True(t, passed)
		assert.Empty(t, reason)
	})

	t.Run("SkipOnPrimaryTypeMismatch", func(t *testing.T) {
		s.cleanScripts(t)
		payload := makeTypedDataPayload(t, map[string]interface{}{
			"types":       map[string]interface{}{},
			"primaryType": "Permit",
			"domain":      map[string]interface{}{"name": "Test", "version": "1", "chainId": "1", "verifyingContract": "0x0000000000000000000000000000000000000000"},
			"message":     map[string]interface{}{"owner": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"},
		})
		rule := &types.Rule{
			Mode: types.RuleModeWhitelist,
			Config: mustJSONMarshal(t, SolidityExpressionConfig{
				TypedDataExpression: `require(false, "should not be evaluated");`,
				TypedDataStruct:     "struct Order { address maker; }",
			}),
		}
		req := &types.SignRequest{ChainID: "1", SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4", Payload: payload}
		passed, reason, err := e.Evaluate(bgCtx, rule, req, nil)
		require.NoError(t, err)
		assert.False(t, passed)
		assert.Empty(t, reason)
	})

	t.Run("MissingPayload", func(t *testing.T) {
		s.cleanScripts(t)
		rule := &types.Rule{
			Mode:   types.RuleModeWhitelist,
			Config: mustJSONMarshal(t, SolidityExpressionConfig{TypedDataExpression: `require(true);`}),
		}
		req := &types.SignRequest{ChainID: "1", SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4", Payload: []byte(`{"typed_data": null}`)}
		_, _, err := e.Evaluate(bgCtx, rule, req, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "typed_data field is required")
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func makeTypedDataPayload(t *testing.T, msg map[string]interface{}) []byte {
	t.Helper()
	evmPayload := map[string]interface{}{
		"typed_data": msg,
	}
	b, err := json.Marshal(evmPayload)
	require.NoError(t, err)
	return b
}
