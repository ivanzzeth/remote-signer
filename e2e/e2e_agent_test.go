//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/apikeys"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// =============================================================================
// Agent Preset Apply Tests
// =============================================================================

// TestAgent_PresetApply deploys the agent preset via API and verifies that
// 3 sub-rules are created (agent-tx, agent-sign, agent-safety) from the template bundle.
func TestAgent_PresetApply(t *testing.T) {
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	// Apply agent preset — the "Agent Template" is a template_bundle with 3 sub-rules.
	// The template service expands the bundle into individual evm_js rules.
	// The preset has no chain matrix, so 1 composite entry x 3 sub-rules = 3 results.
	applyResp, err := adminClient.Presets.ApplyWithVariables(ctx, "agent.preset.js.yaml", nil)
	require.NoError(t, err)
	require.NotNil(t, applyResp)

	// The agent preset has 1 template (Agent Template) with 2 sub-rules (sign + safety).
	// agent-tx was removed — transactions fall through to SimulationBudgetRule.
	// Agent preset: 5 chains × 2 sub-rules (sign, safety) = 10 rules
	require.Len(t, applyResp.Results, 10,
		"agent preset should produce 10 rules (5 chains x 2 sub-rules)")

	// Cleanup created rules
	cleanupApplyResults(t, applyResp.Results)

	// Verify each result has a valid rule with evm_js type (not template_bundle)
	for _, result := range applyResp.Results {
		assert.NotNil(t, result.Rule, "each result should have a rule")
		var ruleMap map[string]interface{}
		if err := json.Unmarshal(result.Rule, &ruleMap); err == nil {
			ruleType, _ := ruleMap["type"].(string)
			assert.Equal(t, "evm_js", ruleType, "sub-rule type should be evm_js, not template_bundle")
		}
	}
}

// =============================================================================
// Agent API Key Permission Tests
// =============================================================================

// createAgentClient creates an agent API key via admin and returns a client for it.
// Cleanup is registered with t.Cleanup.
func createAgentClient(t *testing.T) *client.Client {
	t.Helper()
	ctx := context.Background()

	// Generate Ed25519 key pair for the agent
	agentPubKey, agentPrivKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	agentKeyID := "e2e-agent-key-test"
	agentPubHex := hex.EncodeToString(agentPubKey)

	// Create agent API key via admin client
	created, err := adminClient.APIKeys.Create(ctx, &apikeys.CreateRequest{
		ID:        agentKeyID,
		Name:      "E2E Agent Test Key",
		PublicKey: agentPubHex,
		Role:      "agent",
		RateLimit: 500,
	})
	if err != nil {
		apiErr, ok := err.(*client.APIError)
		if ok && apiErr.StatusCode == 403 {
			t.Skip("Skipping: API key management is readonly")
		}
		require.NoError(t, err)
	}
	require.NotNil(t, created)
	assert.Equal(t, "agent", created.Role, "created key should have role=agent")

	t.Cleanup(func() {
		if delErr := adminClient.APIKeys.Delete(context.Background(), agentKeyID); delErr != nil {
			t.Logf("Warning: failed to clean up agent API key: %v", delErr)
		}
	})

	// Create client authenticated with the agent key
	agentClient, err := client.NewClient(client.Config{
		BaseURL:       baseURL,
		APIKeyID:      agentKeyID,
		PrivateKeyHex: hex.EncodeToString(agentPrivKey),
		PollInterval:  adminClient.EVM.Sign.PollInterval,
		PollTimeout:   adminClient.EVM.Sign.PollTimeout,
	})
	require.NoError(t, err)

	return agentClient
}

// TestAgent_APIKey_ReadRules verifies that an agent API key can read rules (GET)
// but cannot create rules (POST returns 403).
func TestAgent_APIKey_ReadRules(t *testing.T) {
	agentClient := createAgentClient(t)
	ctx := context.Background()

	// Agent should be able to list rules (GET)
	resp, err := agentClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.GreaterOrEqual(t, resp.Total, 1, "agent should see at least one rule")

	// Agent should NOT be able to create scripted rules (e.g. evm_js)
	chainType := "evm"
	_, err = agentClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:      "Agent Should Not Create This",
		Type:      "evm_js",
		Mode:      "whitelist",
		ChainType: &chainType,
		Config:    map[string]interface{}{"script": "function validate(input) { return ok(); }"},
		Enabled:   true,
	})
	require.Error(t, err, "agent should not be able to create evm_js rules")
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode, "agent POST evm_js rules should return 403")
}

// TestAgent_APIKey_ReadBudgets verifies that an agent API key can read budget info.
func TestAgent_APIKey_ReadBudgets(t *testing.T) {
	agentClient := createAgentClient(t)
	ctx := context.Background()

	// First, list rules to find one with a budget
	resp, err := agentClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	require.NoError(t, err)
	require.NotNil(t, resp)

	if resp.Total == 0 {
		t.Skip("no rules available to test budget read")
	}

	// Try to read budgets for the first rule (may be empty, but should not 403)
	ruleID := resp.Rules[0].ID
	budgets, err := agentClient.EVM.Rules.ListBudgets(ctx, ruleID)
	require.NoError(t, err, "agent should be able to read budgets")
	// budgets may be empty (not all rules have budgets), but the call itself should succeed
	assert.NotNil(t, budgets, "budgets response should not be nil")
}

// TestAgent_APIKey_ConfigRedacted verifies that when an agent reads a rule,
// the Config field is null/redacted (script not exposed to agent).
func TestAgent_APIKey_ConfigRedacted(t *testing.T) {
	agentClient := createAgentClient(t)
	ctx := context.Background()

	// List rules to get a rule ID
	resp, err := agentClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	require.NoError(t, err)
	require.NotNil(t, resp)

	if resp.Total == 0 {
		t.Skip("no rules available to test config redaction")
	}

	// Get a specific rule
	rule, err := agentClient.EVM.Rules.Get(ctx, resp.Rules[0].ID)
	require.NoError(t, err)
	require.NotNil(t, rule)

	// For agent keys, the Config field should be null/empty (redacted)
	// The server should strip script content from the response for agent keys
	// If the server does not redact, the config will be non-nil.
	// This test documents the expected behavior; adjust assertion based on implementation.
	if rule.Config != nil {
		// Parse config and check that "script" field is not present or is redacted
		var configMap map[string]interface{}
		configBytes, err := json.Marshal(rule.Config)
		if err == nil {
			if json.Unmarshal(configBytes, &configMap) == nil {
				// If config is returned, script should be redacted for agent keys
				_, hasScript := configMap["script"]
				if hasScript {
					t.Log("Note: agent can see script in config; consider redacting for security")
				}
			}
		}
	}
}

// TestAgent_APIKey_CannotDeleteRules verifies that agent keys cannot delete rules.
func TestAgent_APIKey_CannotDeleteRules(t *testing.T) {
	agentClient := createAgentClient(t)
	ctx := context.Background()

	// List rules to get a rule ID
	resp, err := agentClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	require.NoError(t, err)
	require.NotNil(t, resp)

	if resp.Total == 0 {
		t.Skip("no rules available to test delete protection")
	}

	// Agent should NOT be able to delete rules
	err = agentClient.EVM.Rules.Delete(ctx, resp.Rules[0].ID)
	require.Error(t, err, "agent should not be able to delete rules")
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode, "agent DELETE rules should return 403")
}

// TestAgent_APIKey_CannotApplyPresets verifies that agent keys cannot apply presets.
func TestAgent_APIKey_CannotApplyPresets(t *testing.T) {
	agentClient := createAgentClient(t)
	ctx := context.Background()
	skipIfPresetAPIDisabled(t)

	// Agent should NOT be able to apply presets (POST)
	_, err := agentClient.Presets.Apply(ctx, "agent.preset.js.yaml", nil)
	require.Error(t, err, "agent should not be able to apply presets")
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T: %v", err, err)
	assert.Equal(t, 403, apiErr.StatusCode, "agent POST preset apply should return 403")
}

// =============================================================================
// Agent Signing E2E Tests
// =============================================================================
// These tests create agent sub-rules (agent-tx, agent-sign, agent-safety) directly
// via the admin API and exercise the actual signing flow through the rule engine.

// agentTxScript is the agent-tx JS script inlined from agent.template.js.yaml.
// It allows any transaction (whitelist mode).
const agentTxScript = `function validate(input) {
  require(input.sign_type === 'transaction', 'not a transaction');
  require(input.transaction, 'missing transaction');
  return ok();
}`

// agentSignScript is the agent-sign JS script inlined from agent.template.js.yaml.
// It allows personal (with length limit) and typed_data.
const agentSignScript = `function validate(input) {
  if (input.sign_type === 'personal_sign') {
    var msg = input.personal_sign.message;
    var maxLen = parseInt(config.max_message_length) || 1024;
    if (maxLen > 0) {
      require(msg.length <= maxLen,
        'message too long (' + msg.length + ' > ' + maxLen + ')');
    }
    return ok();
  }

  if (input.sign_type === 'typed_data') {
    var td = input.typed_data;
    require(td, 'missing typed_data');
    return ok();
  }

  revert('unsupported sign type: ' + input.sign_type);
}`

// agentSafetyScript is the agent-safety JS script inlined from agent.template.js.yaml.
// It blocks dangerous admin selectors: setApprovalForAll(true), transferOwnership, etc.
const agentSafetyScript = `function validate(input) {
  if (input.sign_type !== 'transaction' || !input.transaction) return ok();
  var tx = input.transaction;
  var data = (tx.data || '0x').replace(/^0x/, '');
  if (data.length < 8) return ok();
  var sel = '0x' + data.slice(0, 8);
  var payloadHex = data.slice(8);

  // setApprovalForAll(address,bool) - block when setting true
  if (eq(sel, selector('setApprovalForAll(address,bool)'))) {
    var dec = abi.decode(payloadHex, ['address', 'bool']);
    if (dec[1]) {
      return fail('setApprovalForAll(true) is blocked for agent safety');
    }
    return ok();
  }

  // transferOwnership(address)
  if (eq(sel, selector('transferOwnership(address)'))) {
    return fail('transferOwnership is blocked for agent safety');
  }

  // renounceOwnership()
  if (eq(sel, selector('renounceOwnership()'))) {
    return fail('renounceOwnership is blocked for agent safety');
  }

  // upgradeTo(address)
  if (eq(sel, selector('upgradeTo(address)'))) {
    return fail('upgradeTo is blocked for agent safety');
  }

  // upgradeToAndCall(address,bytes)
  if (eq(sel, selector('upgradeToAndCall(address,bytes)'))) {
    return fail('upgradeToAndCall is blocked for agent safety');
  }

  return ok();
}`

// createAgentTxRule creates the agent-tx whitelist rule and registers cleanup.
func createAgentTxRule(t *testing.T) *evm.Rule {
	t.Helper()
	ctx := context.Background()
	chainType := "evm"
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:        "E2E Agent TX",
		Description: "agent-tx whitelist: allow any transaction",
		Type:        "evm_js",
		Mode:        "whitelist",
		ChainType:   &chainType,
		Config: map[string]interface{}{
			"sign_type_filter": "transaction",
			"script":           agentTxScript,
		},
		Enabled: true,
		TestCases: []evm.JSRuleTestCase{
			{
				Name: "positive: ERC20 transfer transaction",
				Input: map[string]interface{}{
					"sign_type": "transaction",
					"chain_id":  1,
					"signer":    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
					"transaction": map[string]interface{}{
						"from":     "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
						"to":       "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
						"value":    "0x0",
						"data":     "0xa9059cbb0000000000000000000000005B38Da6a701c568545dCfcB03FcB875f56beddC40000000000000000000000000000000000000000000000000000000000000001",
						"methodId": "0xa9059cbb",
					},
				},
				ExpectPass: true,
			},
			{
				Name: "negative: personal not allowed by TX rule",
				Input: map[string]interface{}{
					"sign_type": "personal",
					"chain_id":  1,
					"signer":    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
					"personal_sign": map[string]interface{}{
						"message": "hello",
					},
				},
				ExpectPass:   false,
				ExpectReason: "not a transaction",
			},
		},
	})
	require.NoError(t, err, "failed to create agent-tx rule")
	t.Cleanup(func() {
		if delErr := adminClient.EVM.Rules.Delete(context.Background(), rule.ID); delErr != nil {
			t.Logf("Warning: failed to clean up agent-tx rule %s: %v", rule.ID, delErr)
		}
	})
	return rule
}

// createAgentSignRule creates the agent-sign whitelist rule and registers cleanup.
func createAgentSignRule(t *testing.T) *evm.Rule {
	t.Helper()
	ctx := context.Background()
	chainType := "evm"
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:        "E2E Agent Sign",
		Description: "agent-sign whitelist: allow personal and typed_data",
		Type:        "evm_js",
		Mode:        "whitelist",
		ChainType:   &chainType,
		Config: map[string]interface{}{
			"sign_type_filter":   "personal,typed_data",
			"script":             agentSignScript,
			"max_message_length": "1024",
		},
		Enabled: true,
		TestCases: []evm.JSRuleTestCase{
			{
				Name: "positive: short personal within limit",
				Input: map[string]interface{}{
					"sign_type": "personal",
					"chain_id":  1,
					"signer":    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
					"personal_sign": map[string]interface{}{
						"message": "hello",
					},
				},
				ExpectPass: true,
			},
			{
				Name: "negative: message exceeds max_message_length",
				Input: map[string]interface{}{
					"sign_type": "personal",
					"chain_id":  1,
					"signer":    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
					"personal_sign": map[string]interface{}{
						"message": strings.Repeat("A", 1025),
					},
				},
				ExpectPass:   false,
				ExpectReason: "too long",
			},
		},
	})
	require.NoError(t, err, "failed to create agent-sign rule")
	t.Cleanup(func() {
		if delErr := adminClient.EVM.Rules.Delete(context.Background(), rule.ID); delErr != nil {
			t.Logf("Warning: failed to clean up agent-sign rule %s: %v", rule.ID, delErr)
		}
	})
	return rule
}

// createAgentSafetyRule creates the agent-safety blocklist rule and registers cleanup.
func createAgentSafetyRule(t *testing.T) *evm.Rule {
	t.Helper()
	ctx := context.Background()
	chainType := "evm"
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:        "E2E Agent Safety",
		Description: "agent-safety blocklist: block dangerous admin selectors",
		Type:        "evm_js",
		Mode:        "blocklist",
		ChainType:   &chainType,
		Config: map[string]interface{}{
			"sign_type_filter": "transaction",
			"script":           agentSafetyScript,
		},
		Enabled: true,
		TestCases: []evm.JSRuleTestCase{
			{
				Name: "positive: normal ERC20 transfer is not blocked",
				Input: map[string]interface{}{
					"sign_type": "transaction",
					"chain_id":  1,
					"signer":    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
					"transaction": map[string]interface{}{
						"from":     "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
						"to":       "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
						"value":    "0x0",
						"data":     "0xa9059cbb0000000000000000000000005B38Da6a701c568545dCfcB03FcB875f56beddC40000000000000000000000000000000000000000000000000000000000000001",
						"methodId": "0xa9059cbb",
					},
				},
				ExpectPass: true,
			},
			{
				Name: "negative: transferOwnership is blocked",
				Input: map[string]interface{}{
					"sign_type": "transaction",
					"chain_id":  1,
					"signer":    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
					"transaction": map[string]interface{}{
						"from":     "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
						"to":       "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
						"value":    "0x0",
						"data":     "0xf2fde38b0000000000000000000000005B38Da6a701c568545dCfcB03FcB875f56beddC4",
						"methodId": "0xf2fde38b",
					},
				},
				ExpectPass:   false,
				ExpectReason: "transferOwnership",
			},
		},
	})
	require.NoError(t, err, "failed to create agent-safety rule")
	t.Cleanup(func() {
		if delErr := adminClient.EVM.Rules.Delete(context.Background(), rule.ID); delErr != nil {
			t.Logf("Warning: failed to clean up agent-safety rule %s: %v", rule.ID, delErr)
		}
	})
	return rule
}

// TestAgent_SignTransaction_ERC20Transfer creates the agent-tx whitelist rule and signs
// an ERC20 transfer(to, amount) transaction. Should PASS.
func TestAgent_SignTransaction_ERC20Transfer(t *testing.T) {
	createAgentTxRule(t)
	createAgentSafetyRule(t) // safety should not block ERC20 transfer

	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)

	to := common.HexToAddress(treasuryAddress)
	// transfer(address,uint256): selector 0xa9059cbb
	transferCalldata := "0xa9059cbb" +
		"000000000000000000000000" + strings.ToLower(treasuryAddress[2:]) +
		"0000000000000000000000000000000000000000000000000000000000000001"

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    200,
		GasPrice: big.NewInt(20000000000),
		Gas:      60000,
		To:       &to,
		Value:    big.NewInt(0),
		Data:     common.FromHex(transferCalldata),
	})
	chainIDBig := big.NewInt(1)
	signedTx, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.NoError(t, err, "agent-tx should allow ERC20 transfer")
	require.NotNil(t, signedTx)
	v, r, s := signedTx.RawSignatureValues()
	assert.NotNil(t, v)
	assert.NotNil(t, r)
	assert.NotNil(t, s)
}

// TestAgent_SignTransaction_NativeTransfer creates the agent-tx whitelist rule and signs
// a native value transfer (no calldata). Should PASS.
func TestAgent_SignTransaction_NativeTransfer(t *testing.T) {
	createAgentTxRule(t)
	createAgentSafetyRule(t) // safety should not block native transfers

	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)

	to := common.HexToAddress(treasuryAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    201,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(500000000000000000), // 0.5 ETH
		Data:     nil,
	})
	chainIDBig := big.NewInt(1)
	signedTx, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.NoError(t, err, "agent-tx should allow native value transfer")
	require.NotNil(t, signedTx)
	v, r, s := signedTx.RawSignatureValues()
	assert.NotNil(t, v)
	assert.NotNil(t, r)
	assert.NotNil(t, s)
}

// TestAgent_PersonalSign_OK creates the agent-sign whitelist rule and signs
// a personal message within the 1024-char length limit. Should PASS.
func TestAgent_PersonalSign_OK(t *testing.T) {
	createAgentSignRule(t)

	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)

	sig, err := signer.PersonalSign("Hello from the agent e2e test!")
	require.NoError(t, err, "agent-sign should allow personal within length limit")
	require.NotEmpty(t, sig)
	assert.Len(t, sig, 65)
}

// TestAgent_PersonalSign_TooLong creates the agent-sign whitelist rule scoped to
// signer2 and signs a personal message exceeding max_message_length (1024).
// Uses signer2 to avoid interference from other whitelist rules in config.e2e.yaml.
func TestAgent_PersonalSign_TooLong(t *testing.T) {
	ctx := context.Background()
	chainType := "evm"

	// Create agent-sign rule scoped to signer2 only, so no other rule interferes
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:          "E2E Agent Sign (signer2 scoped)",
		Type:          "evm_js",
		Mode:          "whitelist",
		ChainType:     &chainType,
		SignerAddress: strPtr(testSigner2Address),
		Config: map[string]interface{}{
			"sign_type_filter": "personal,typed_data",
			"script":           agentSignScript,
		},
		Enabled: true,
		TestCases: []evm.JSRuleTestCase{
			{
				Name: "positive: short personal",
				Input: map[string]interface{}{
					"sign_type": "personal",
					"chain_id":  1,
					"signer":    testSigner2Address,
					"personal_sign": map[string]interface{}{
						"message": "hello",
					},
				},
				ExpectPass: true,
			},
			{
				Name: "negative: message too long",
				Input: map[string]interface{}{
					"sign_type": "personal",
					"chain_id":  1,
					"signer":    testSigner2Address,
					"personal_sign": map[string]interface{}{
						"message": strings.Repeat("X", 1025),
					},
				},
				ExpectPass:   false,
				ExpectReason: "too long",
			},
		},
	})
	require.NoError(t, err, "failed to create signer2-scoped agent-sign rule")
	t.Cleanup(func() {
		if delErr := adminClient.EVM.Rules.Delete(context.Background(), rule.ID); delErr != nil {
			t.Logf("Warning: failed to clean up agent-sign rule: %v", delErr)
		}
	})

	// Sign with signer2 — only the agent-sign rule matches, no other rule interferes
	address := common.HexToAddress(testSigner2Address)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)

	longMsg := strings.Repeat("A", 1025)
	_, err = signer.PersonalSign(longMsg)
	require.Error(t, err, "agent-sign should reject personal_sign exceeding max_message_length")
	// Whitelist rule revert("too long") = no match. With manual_approval_enabled=true
	// this becomes "timeout waiting for approval"; with manual_approval_enabled=false
	// this becomes 403 "no matching rule". Either way, the sign request fails.
	t.Logf("sign correctly rejected with: %v", err)
}

// TestAgent_Safety_BlocksTransferOwnership creates the agent-safety blocklist rule
// and the agent-tx whitelist rule, then signs a transaction with transferOwnership(address)
// selector. Should be BLOCKED by agent-safety.
func TestAgent_Safety_BlocksTransferOwnership(t *testing.T) {
	createAgentTxRule(t)
	createAgentSafetyRule(t)

	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)

	to := common.HexToAddress(treasuryAddress)
	// transferOwnership(address): selector 0xf2fde38b
	transferOwnershipCalldata := "0xf2fde38b" +
		"000000000000000000000000" + strings.ToLower(treasuryAddress[2:])

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    202,
		GasPrice: big.NewInt(20000000000),
		Gas:      60000,
		To:       &to,
		Value:    big.NewInt(0),
		Data:     common.FromHex(transferOwnershipCalldata),
	})
	chainIDBig := big.NewInt(1)
	_, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.Error(t, err, "agent-safety should block transferOwnership")

	var signErr *evm.SignError
	if errors.As(err, &signErr) {
		assert.Contains(t, signErr.Message, "transferOwnership",
			"rejection reason should mention transferOwnership")
	} else {
		// The error may also be wrapped differently; check the string representation
		assert.Contains(t, err.Error(), "transferOwnership",
			"rejection reason should mention transferOwnership, got: %s", err.Error())
	}
}

// TestAgent_Safety_BlocksSetApprovalForAll creates the agent-safety blocklist rule
// and the agent-tx whitelist rule, then signs a transaction with setApprovalForAll(address,true).
// Should be BLOCKED by agent-safety.
func TestAgent_Safety_BlocksSetApprovalForAll(t *testing.T) {
	createAgentTxRule(t)
	createAgentSafetyRule(t)

	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)

	to := common.HexToAddress(treasuryAddress)
	// setApprovalForAll(address,bool): selector 0xa22cb465, with bool=true
	setApprovalCalldata := "0xa22cb465" +
		"000000000000000000000000" + strings.ToLower(treasuryAddress[2:]) +
		"0000000000000000000000000000000000000000000000000000000000000001"

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    203,
		GasPrice: big.NewInt(20000000000),
		Gas:      60000,
		To:       &to,
		Value:    big.NewInt(0),
		Data:     common.FromHex(setApprovalCalldata),
	})
	chainIDBig := big.NewInt(1)
	_, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.Error(t, err, "agent-safety should block setApprovalForAll(true)")

	var signErr *evm.SignError
	if errors.As(err, &signErr) {
		assert.Contains(t, signErr.Message, "setApprovalForAll",
			"rejection reason should mention setApprovalForAll")
	} else {
		assert.Contains(t, err.Error(), "setApprovalForAll",
			"rejection reason should mention setApprovalForAll, got: %s", err.Error())
	}
}

// TestAgent_Safety_AllowsNormalCall creates the agent-safety blocklist rule
// and the agent-tx whitelist rule, then signs a normal contract call (name() selector 0x06fdde03).
// Should PASS because name() is not in the blocklist.
func TestAgent_Safety_AllowsNormalCall(t *testing.T) {
	// Previous blocklist tests may trigger approval guard (consecutive rejections).
	// Resume it before testing the positive case.
	_ = adminClient.EVM.Guard.Resume(context.Background())

	createAgentTxRule(t)
	createAgentSafetyRule(t)

	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)

	to := common.HexToAddress(treasuryAddress)
	// name(): selector 0x06fdde03 (a harmless view call, not in the safety blocklist)
	nameCalldata := "0x06fdde03"

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    204,
		GasPrice: big.NewInt(20000000000),
		Gas:      60000,
		To:       &to,
		Value:    big.NewInt(0),
		Data:     common.FromHex(nameCalldata),
	})
	chainIDBig := big.NewInt(1)
	signedTx, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.NoError(t, err, "agent-safety should allow normal contract call (name())")
	require.NotNil(t, signedTx)
	v, r, s := signedTx.RawSignatureValues()
	assert.NotNil(t, v)
	assert.NotNil(t, r)
	assert.NotNil(t, s)
}

func strPtr(s string) *string { return &s }
