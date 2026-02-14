package evm

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// testLogger returns a logger suitable for use in tests
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

// =============================================================================
// CanBatchEvaluate Tests
// =============================================================================

func TestSolidityRuleEvaluator_CanBatchEvaluate_EmptyRules(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{}
	assert.False(t, evaluator.CanBatchEvaluate(nil))
	assert.False(t, evaluator.CanBatchEvaluate([]*types.Rule{}))
}

func TestSolidityRuleEvaluator_CanBatchEvaluate_SingleRule(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{}

	config := SolidityExpressionConfig{
		TypedDataExpression: `require(value <= 100, "limit");`,
	}
	configBytes, _ := json.Marshal(config)

	rules := []*types.Rule{
		{ID: "rule1", Config: configBytes},
	}

	// Single rule is always "batchable"
	assert.True(t, evaluator.CanBatchEvaluate(rules))
}

func TestSolidityRuleEvaluator_CanBatchEvaluate_AllTypedDataExpression(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{}

	config1 := SolidityExpressionConfig{
		TypedDataExpression: `require(value <= 100, "limit1");`,
	}
	config2 := SolidityExpressionConfig{
		TypedDataExpression: `require(value <= 200, "limit2");`,
	}
	configBytes1, _ := json.Marshal(config1)
	configBytes2, _ := json.Marshal(config2)

	rules := []*types.Rule{
		{ID: "rule1", Config: configBytes1},
		{ID: "rule2", Config: configBytes2},
	}

	// Multiple TypedDataExpression rules can be batched
	assert.True(t, evaluator.CanBatchEvaluate(rules))
}

func TestSolidityRuleEvaluator_CanBatchEvaluate_MixedModes(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{}

	config1 := SolidityExpressionConfig{
		TypedDataExpression: `require(value <= 100, "limit1");`,
	}
	config2 := SolidityExpressionConfig{
		Expression: `require(tx_value <= 100, "limit2");`,
	}
	configBytes1, _ := json.Marshal(config1)
	configBytes2, _ := json.Marshal(config2)

	rules := []*types.Rule{
		{ID: "rule1", Config: configBytes1},
		{ID: "rule2", Config: configBytes2},
	}

	// Mixed modes cannot be batched
	assert.False(t, evaluator.CanBatchEvaluate(rules))
}

func TestSolidityRuleEvaluator_CanBatchEvaluate_AllExpression(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{}

	config1 := SolidityExpressionConfig{
		Expression: `require(tx_value <= 100, "limit1");`,
	}
	config2 := SolidityExpressionConfig{
		Expression: `require(tx_value <= 200, "limit2");`,
	}
	configBytes1, _ := json.Marshal(config1)
	configBytes2, _ := json.Marshal(config2)

	rules := []*types.Rule{
		{ID: "rule1", Config: configBytes1},
		{ID: "rule2", Config: configBytes2},
	}

	// Expression mode rules cannot be batched (only TypedDataExpression supported)
	assert.False(t, evaluator.CanBatchEvaluate(rules))
}

func TestSolidityRuleEvaluator_CanBatchEvaluate_AllFunctions(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{}

	config1 := SolidityExpressionConfig{
		Functions: `function foo() external {}`,
	}
	config2 := SolidityExpressionConfig{
		Functions: `function bar() external {}`,
	}
	configBytes1, _ := json.Marshal(config1)
	configBytes2, _ := json.Marshal(config2)

	rules := []*types.Rule{
		{ID: "rule1", Config: configBytes1},
		{ID: "rule2", Config: configBytes2},
	}

	// Functions mode rules cannot be batched
	assert.False(t, evaluator.CanBatchEvaluate(rules))
}

func TestSolidityRuleEvaluator_CanBatchEvaluate_InvalidConfig(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{}

	// Need at least 2 rules to trigger the JSON parsing path (single rule short-circuits to true)
	rules := []*types.Rule{
		{ID: "rule1", Config: []byte("invalid json")},
		{ID: "rule2", Config: []byte("also invalid")},
	}

	// Invalid config cannot be batched
	assert.False(t, evaluator.CanBatchEvaluate(rules))
}

// =============================================================================
// preprocessRulesForBatch Tests
// =============================================================================

func TestSolidityRuleEvaluator_preprocessRulesForBatch_SignTypeFilterMismatch(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{logger: testLogger()}

	config := SolidityExpressionConfig{
		TypedDataExpression: `require(value <= 100, "limit");`,
		SignTypeFilter:      "typed_data",
	}
	configBytes, _ := json.Marshal(config)

	rules := []*types.Rule{
		{ID: "rule1", Config: configBytes},
	}

	req := &types.SignRequest{
		SignType: "transaction", // Doesn't match filter
	}

	contexts, err := evaluator.preprocessRulesForBatch(rules, req)
	require.NoError(t, err)
	require.Len(t, contexts, 1)
	assert.True(t, contexts[0].skipped, "Rule should be skipped due to SignTypeFilter mismatch")
}

func TestSolidityRuleEvaluator_preprocessRulesForBatch_PrimaryTypeMismatch(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{logger: testLogger()}

	config := SolidityExpressionConfig{
		TypedDataExpression: `require(order.salt > 0, "invalid salt");`,
		TypedDataStruct: `struct Order {
			uint256 salt;
		}`,
	}
	configBytes, _ := json.Marshal(config)

	rules := []*types.Rule{
		{ID: "rule1", Config: configBytes},
	}

	// Create typed data with different primaryType
	typedData := &TypedDataPayload{
		PrimaryType: "Permit", // Doesn't match Order
		Domain: TypedDataDomain{
			Name:    "TestDomain",
			Version: "1",
		},
		Message: map[string]interface{}{
			"value": "100",
		},
	}
	evmPayload := EVMSignPayload{TypedData: typedData}
	payload, _ := json.Marshal(evmPayload)

	req := &types.SignRequest{
		SignType: "typed_data",
		Payload:  payload,
	}

	contexts, err := evaluator.preprocessRulesForBatch(rules, req)
	require.NoError(t, err)
	require.Len(t, contexts, 1)
	assert.True(t, contexts[0].skipped, "Rule should be skipped due to primaryType mismatch")
}

func TestSolidityRuleEvaluator_preprocessRulesForBatch_TypedDataExpressionMode(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{logger: testLogger()}

	config := SolidityExpressionConfig{
		TypedDataExpression: `require(value <= 100, "limit");`,
	}
	configBytes, _ := json.Marshal(config)

	rules := []*types.Rule{
		{ID: "rule1", Config: configBytes},
	}

	typedData := &TypedDataPayload{
		PrimaryType: "Permit",
		Domain: TypedDataDomain{
			Name:    "TestDomain",
			Version: "1",
		},
		Message: map[string]interface{}{
			"value": "50",
		},
	}
	evmPayload := EVMSignPayload{TypedData: typedData}
	payload, _ := json.Marshal(evmPayload)

	req := &types.SignRequest{
		SignType: "typed_data",
		Payload:  payload,
	}

	contexts, err := evaluator.preprocessRulesForBatch(rules, req)
	require.NoError(t, err)
	require.Len(t, contexts, 1)
	assert.False(t, contexts[0].skipped)
	assert.Equal(t, evalModeTypedDataExpression, contexts[0].mode)
	assert.NotNil(t, contexts[0].typedData)
}

func TestSolidityRuleEvaluator_preprocessRulesForBatch_FunctionsMode(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{logger: testLogger()}

	config := SolidityExpressionConfig{
		Functions: `function foo() external {}`,
	}
	configBytes, _ := json.Marshal(config)

	rules := []*types.Rule{
		{ID: "rule1", Config: configBytes},
	}

	req := &types.SignRequest{}

	contexts, err := evaluator.preprocessRulesForBatch(rules, req)
	require.NoError(t, err)
	require.Len(t, contexts, 1)
	// Functions mode is skipped in batch (not supported yet)
	assert.True(t, contexts[0].skipped)
	assert.Equal(t, evalModeFunctions, contexts[0].mode)
}

func TestSolidityRuleEvaluator_preprocessRulesForBatch_ExpressionMode(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{logger: testLogger()}

	config := SolidityExpressionConfig{
		Expression: `require(tx_value <= 100, "limit");`,
	}
	configBytes, _ := json.Marshal(config)

	rules := []*types.Rule{
		{ID: "rule1", Config: configBytes},
	}

	req := &types.SignRequest{}

	contexts, err := evaluator.preprocessRulesForBatch(rules, req)
	require.NoError(t, err)
	require.Len(t, contexts, 1)
	// Expression mode is skipped in batch (not supported yet)
	assert.True(t, contexts[0].skipped)
	assert.Equal(t, evalModeExpression, contexts[0].mode)
}

func TestSolidityRuleEvaluator_preprocessRulesForBatch_InvalidConfig(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{logger: testLogger()}

	rules := []*types.Rule{
		{ID: "rule1", Config: []byte("invalid json")},
	}

	req := &types.SignRequest{}

	_, err := evaluator.preprocessRulesForBatch(rules, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid config")
}

func TestSolidityRuleEvaluator_preprocessRulesForBatch_InvalidTypedDataPayload(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{logger: testLogger()}

	config := SolidityExpressionConfig{
		TypedDataExpression: `require(value <= 100, "limit");`,
	}
	configBytes, _ := json.Marshal(config)

	rules := []*types.Rule{
		{ID: "rule1", Config: configBytes},
	}

	req := &types.SignRequest{
		Payload: []byte("invalid json"),
	}

	_, err := evaluator.preprocessRulesForBatch(rules, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse typed data")
}

func TestSolidityRuleEvaluator_preprocessRulesForBatch_InvalidStructDefinition(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{logger: testLogger()}

	config := SolidityExpressionConfig{
		TypedDataExpression: `require(value <= 100, "limit");`,
		TypedDataStruct:     `invalid struct syntax`,
	}
	configBytes, _ := json.Marshal(config)

	rules := []*types.Rule{
		{ID: "rule1", Config: configBytes},
	}

	typedData := &TypedDataPayload{
		PrimaryType: "Permit",
		Domain:      TypedDataDomain{Name: "Test", Version: "1"},
		Message:     map[string]interface{}{"value": "100"},
	}
	evmPayload := EVMSignPayload{TypedData: typedData}
	payload, _ := json.Marshal(evmPayload)

	req := &types.SignRequest{
		Payload: payload,
	}

	_, err := evaluator.preprocessRulesForBatch(rules, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse typed_data_struct")
}

// =============================================================================
// generateBatchEvaluationScript Tests
// =============================================================================

func TestSolidityRuleEvaluator_generateBatchEvaluationScript_NoApplicableRules(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{logger: testLogger()}

	// All rules skipped
	contexts := []*ruleEvalContext{
		{skipped: true},
		{skipped: true},
	}

	_, _, err := evaluator.generateBatchEvaluationScript(contexts, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no applicable rules")
}

func TestSolidityRuleEvaluator_generateBatchEvaluationScript_SingleRule(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{logger: testLogger()}

	typedData := &TypedDataPayload{
		PrimaryType: "Permit",
		Domain: TypedDataDomain{
			Name:              "TestToken",
			Version:           "1",
			ChainId:           "1",
			VerifyingContract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
		},
		Message: map[string]interface{}{
			"value": "100",
		},
	}

	contexts := []*ruleEvalContext{
		{
			rule: &types.Rule{ID: "rule1"},
			config: SolidityExpressionConfig{
				TypedDataExpression: `require(value <= 100, "limit");`,
			},
			mode:      evalModeTypedDataExpression,
			typedData: typedData,
			skipped:   false,
		},
	}

	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}

	script, ruleIndices, err := evaluator.generateBatchEvaluationScript(contexts, req, nil)
	require.NoError(t, err)

	// Check script contains expected elements
	assert.Contains(t, script, "contract BatchRuleEvaluatorTest")
	assert.Contains(t, script, "function test_rule_0()")
	assert.Contains(t, script, `require(value <= 100, "limit");`)

	// Check rule indices
	assert.Len(t, ruleIndices, 1)
	assert.Equal(t, 0, ruleIndices[0])
}

func TestSolidityRuleEvaluator_generateBatchEvaluationScript_MultipleRules(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{logger: testLogger()}

	typedData := &TypedDataPayload{
		PrimaryType: "Permit",
		Domain: TypedDataDomain{
			Name:    "TestToken",
			Version: "1",
		},
		Message: map[string]interface{}{
			"value":   "100",
			"spender": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
		},
	}

	contexts := []*ruleEvalContext{
		{
			rule: &types.Rule{ID: "rule1"},
			config: SolidityExpressionConfig{
				TypedDataExpression: `require(value <= 100, "limit1");`,
			},
			mode:      evalModeTypedDataExpression,
			typedData: typedData,
			skipped:   false,
		},
		{
			rule: &types.Rule{ID: "rule2"},
			config: SolidityExpressionConfig{
				TypedDataExpression: `require(value <= 200, "limit2");`,
			},
			mode:      evalModeTypedDataExpression,
			typedData: typedData,
			skipped:   false,
		},
	}

	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}

	script, ruleIndices, err := evaluator.generateBatchEvaluationScript(contexts, req, nil)
	require.NoError(t, err)

	// Check script contains both test functions
	assert.Contains(t, script, "function test_rule_0()")
	assert.Contains(t, script, "function test_rule_1()")
	assert.Contains(t, script, `require(value <= 100, "limit1");`)
	assert.Contains(t, script, `require(value <= 200, "limit2");`)

	// Check rule indices
	assert.Len(t, ruleIndices, 2)
	assert.Equal(t, 0, ruleIndices[0])
	assert.Equal(t, 1, ruleIndices[1])
}

func TestSolidityRuleEvaluator_generateBatchEvaluationScript_WithStructDef(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{logger: testLogger()}

	structDef, err := parseStructDefinition(`struct Order {
		uint256 salt;
		address maker;
	}`)
	require.NoError(t, err)

	typedData := &TypedDataPayload{
		PrimaryType: "Order",
		Domain: TypedDataDomain{
			Name:    "TestExchange",
			Version: "1",
		},
		Message: map[string]interface{}{
			"salt":  "12345",
			"maker": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
		},
	}

	contexts := []*ruleEvalContext{
		{
			rule: &types.Rule{ID: "rule1"},
			config: SolidityExpressionConfig{
				TypedDataExpression: `require(order.salt > 0, "invalid salt");`,
			},
			mode:      evalModeTypedDataExpression,
			typedData: typedData,
			structDef: structDef,
			skipped:   false,
		},
	}

	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}

	script, _, err := evaluator.generateBatchEvaluationScript(contexts, req, nil)
	require.NoError(t, err)

	// Check script contains struct definition
	assert.Contains(t, script, "struct Order")
	assert.Contains(t, script, "uint256 salt;")
	assert.Contains(t, script, "address maker;")
	// Check script contains struct instance
	assert.Contains(t, script, "Order memory order = Order")
}

func TestSolidityRuleEvaluator_generateBatchEvaluationScript_SkipsSkippedRules(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{logger: testLogger()}

	typedData := &TypedDataPayload{
		PrimaryType: "Permit",
		Domain:      TypedDataDomain{Name: "Test", Version: "1"},
		Message:     map[string]interface{}{"value": "100"},
	}

	contexts := []*ruleEvalContext{
		{
			rule:      &types.Rule{ID: "rule1"},
			skipped:   true, // This rule is skipped
			typedData: typedData,
		},
		{
			rule: &types.Rule{ID: "rule2"},
			config: SolidityExpressionConfig{
				TypedDataExpression: `require(value <= 200, "limit2");`,
			},
			mode:      evalModeTypedDataExpression,
			typedData: typedData,
			skipped:   false,
		},
		{
			rule:      &types.Rule{ID: "rule3"},
			skipped:   true, // This rule is also skipped
			typedData: typedData,
		},
	}

	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}

	script, ruleIndices, err := evaluator.generateBatchEvaluationScript(contexts, req, nil)
	require.NoError(t, err)

	// Should only have one test function
	assert.Contains(t, script, "function test_rule_0()")
	assert.NotContains(t, script, "function test_rule_1()")

	// Rule index should map to the non-skipped rule
	assert.Len(t, ruleIndices, 1)
	assert.Equal(t, 1, ruleIndices[0]) // Maps to contexts[1]
}

// =============================================================================
// parseBatchTestOutput Tests
// =============================================================================

func TestSolidityRuleEvaluator_parseBatchTestOutput_AllPassed(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{}

	output := `
[PASS] test_rule_0()
[PASS] test_rule_1()
[PASS] test_rule_2()
`

	ruleIndices := map[int]int{
		0: 0,
		1: 1,
		2: 2,
	}

	results := evaluator.parseBatchTestOutput(output, ruleIndices)

	assert.Len(t, results, 3)
	assert.True(t, results[0].passed)
	assert.True(t, results[1].passed)
	assert.True(t, results[2].passed)
}

func TestSolidityRuleEvaluator_parseBatchTestOutput_AllFailed(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{}

	output := `
[FAIL: limit exceeded] test_rule_0()
[FAIL: invalid address] test_rule_1()
`

	ruleIndices := map[int]int{
		0: 0,
		1: 1,
	}

	results := evaluator.parseBatchTestOutput(output, ruleIndices)

	assert.Len(t, results, 2)
	assert.False(t, results[0].passed)
	assert.Equal(t, "limit exceeded", results[0].reason)
	assert.False(t, results[1].passed)
	assert.Equal(t, "invalid address", results[1].reason)
}

func TestSolidityRuleEvaluator_parseBatchTestOutput_Mixed(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{}

	output := `
[PASS] test_rule_0()
[FAIL: limit exceeded] test_rule_1()
[PASS] test_rule_2()
`

	ruleIndices := map[int]int{
		0: 0,
		1: 1,
		2: 2,
	}

	results := evaluator.parseBatchTestOutput(output, ruleIndices)

	assert.Len(t, results, 3)
	assert.True(t, results[0].passed)
	assert.False(t, results[1].passed)
	assert.Equal(t, "limit exceeded", results[1].reason)
	assert.True(t, results[2].passed)
}

func TestSolidityRuleEvaluator_parseBatchTestOutput_EmptyReason(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{}

	output := `[FAIL: ] test_rule_0()`

	ruleIndices := map[int]int{0: 0}

	results := evaluator.parseBatchTestOutput(output, ruleIndices)

	assert.Len(t, results, 1)
	assert.False(t, results[0].passed)
	assert.Empty(t, results[0].reason)
}

func TestSolidityRuleEvaluator_parseBatchTestOutput_NoMatches(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{}

	output := `Some random output without test results`

	ruleIndices := map[int]int{0: 0, 1: 1}

	results := evaluator.parseBatchTestOutput(output, ruleIndices)

	assert.Len(t, results, 0)
}

func TestSolidityRuleEvaluator_parseBatchTestOutput_NonSequentialIndices(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{}

	output := `
[PASS] test_rule_0()
[PASS] test_rule_2()
`

	// Rule indices map to non-sequential context indices
	ruleIndices := map[int]int{
		0: 5,
		2: 10,
	}

	results := evaluator.parseBatchTestOutput(output, ruleIndices)

	assert.Len(t, results, 2)
	assert.True(t, results[5].passed)
	assert.True(t, results[10].passed)
}

// =============================================================================
// EvaluateBatch Edge Cases Tests
// =============================================================================

func TestSolidityRuleEvaluator_EvaluateBatch_EmptyRules(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{logger: testLogger()}

	results, err := evaluator.EvaluateBatch(nil, nil, nil, nil)
	require.NoError(t, err)
	assert.Nil(t, results)

	results, err = evaluator.EvaluateBatch(nil, []*types.Rule{}, nil, nil)
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestSolidityRuleEvaluator_EvaluateBatch_AllSkipped(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{logger: testLogger()}

	// Rules with SignTypeFilter that won't match
	config1 := SolidityExpressionConfig{
		TypedDataExpression: `require(value <= 100, "limit1");`,
		SignTypeFilter:      "typed_data",
	}
	config2 := SolidityExpressionConfig{
		TypedDataExpression: `require(value <= 200, "limit2");`,
		SignTypeFilter:      "typed_data",
	}
	configBytes1, _ := json.Marshal(config1)
	configBytes2, _ := json.Marshal(config2)

	rules := []*types.Rule{
		{ID: "rule1", Config: configBytes1},
		{ID: "rule2", Config: configBytes2},
	}

	req := &types.SignRequest{
		SignType: "transaction", // Doesn't match filter
	}

	results, err := evaluator.EvaluateBatch(nil, rules, req, nil)
	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.True(t, results[0].Skipped)
	assert.True(t, results[1].Skipped)
}

func TestSolidityRuleEvaluator_EvaluateBatch_PreprocessError(t *testing.T) {
	evaluator := &SolidityRuleEvaluator{logger: testLogger()}

	// Rules with invalid config
	rules := []*types.Rule{
		{ID: "rule1", Config: []byte("invalid json")},
		{ID: "rule2", Config: []byte("also invalid")},
	}

	req := &types.SignRequest{SignType: "typed_data"}

	_, err := evaluator.EvaluateBatch(context.Background(), rules, req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to preprocess rules")
}

func TestSolidityRuleEvaluator_EvaluateBatch_MixedSkippedAndApplicable(t *testing.T) {
	// Use a non-existent temp dir to trigger write error
	evaluator := &SolidityRuleEvaluator{
		logger:  testLogger(),
		tempDir: "/non/existent/path/that/will/fail",
	}

	// First rule will be skipped (SignTypeFilter mismatch)
	config1 := SolidityExpressionConfig{
		TypedDataExpression: `require(value <= 100, "limit");`,
		SignTypeFilter:      "personal_sign",
	}
	// Second rule will be applicable
	config2 := SolidityExpressionConfig{
		TypedDataExpression: `require(value <= 200, "limit");`,
		SignTypeFilter:      "typed_data",
	}
	configBytes1, _ := json.Marshal(config1)
	configBytes2, _ := json.Marshal(config2)

	rules := []*types.Rule{
		{ID: "rule1", Config: configBytes1},
		{ID: "rule2", Config: configBytes2},
	}

	// Create typed data payload
	typedData := &TypedDataPayload{
		PrimaryType: "Permit",
		Domain:      TypedDataDomain{Name: "Test", Version: "1"},
		Message:     map[string]any{"value": "50"},
	}
	evmPayload := EVMSignPayload{TypedData: typedData}
	payload, _ := json.Marshal(evmPayload)

	req := &types.SignRequest{
		SignType: "typed_data",
		Payload:  payload,
	}

	// This will fail at executeBatchScript because temp dir doesn't exist
	_, err := evaluator.EvaluateBatch(context.Background(), rules, req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "batch script execution failed")
}

// =============================================================================
// evaluationMode Tests
// =============================================================================

func TestEvaluationMode_Values(t *testing.T) {
	// Ensure mode constants have expected values
	assert.Equal(t, evaluationMode(0), evalModeExpression)
	assert.Equal(t, evaluationMode(1), evalModeFunctions)
	assert.Equal(t, evaluationMode(2), evalModeTypedDataExpression)
	assert.Equal(t, evaluationMode(3), evalModeTypedDataFunctions)
}

// =============================================================================
// ruleEvalContext Tests
// =============================================================================

func TestRuleEvalContext_Fields(t *testing.T) {
	rule := &types.Rule{ID: "test-rule"}
	config := SolidityExpressionConfig{
		TypedDataExpression: `require(value > 0, "invalid");`,
	}
	structDef := &StructDefinition{Name: "Order"}
	typedData := &TypedDataPayload{PrimaryType: "Order"}

	ctx := &ruleEvalContext{
		rule:      rule,
		config:    config,
		mode:      evalModeTypedDataExpression,
		structDef: structDef,
		typedData: typedData,
		skipped:   false,
	}

	assert.Equal(t, rule, ctx.rule)
	assert.Equal(t, config.TypedDataExpression, ctx.config.TypedDataExpression)
	assert.Equal(t, evalModeTypedDataExpression, ctx.mode)
	assert.Equal(t, structDef, ctx.structDef)
	assert.Equal(t, typedData, ctx.typedData)
	assert.False(t, ctx.skipped)
}

// =============================================================================
// batchTestResult Tests
// =============================================================================

func TestBatchTestResult_Fields(t *testing.T) {
	result := &batchTestResult{
		passed: true,
		reason: "success",
		err:    nil,
	}

	assert.True(t, result.passed)
	assert.Equal(t, "success", result.reason)
	assert.Nil(t, result.err)

	result2 := &batchTestResult{
		passed: false,
		reason: "limit exceeded",
		err:    nil,
	}

	assert.False(t, result2.passed)
	assert.Equal(t, "limit exceeded", result2.reason)
}
