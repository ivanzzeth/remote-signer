package evm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─────────────────────────────────────────────────────────────────────────────
// NewJSRuleValidator
// ─────────────────────────────────────────────────────────────────────────────

func TestNewJSRuleValidator_NilEvaluator(t *testing.T) {
	_, err := NewJSRuleValidator(nil, testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "evaluator is required")
}

func TestNewJSRuleValidator_NilLogger(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	_, err := NewJSRuleValidator(e, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

func TestNewJSRuleValidator_Success(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	v, err := NewJSRuleValidator(e, testLogger())
	require.NoError(t, err)
	assert.NotNil(t, v)
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidateRule
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateRule_EmptyScript(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	v, _ := NewJSRuleValidator(e, testLogger())
	result, err := v.ValidateRule(context.Background(), "", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "script is empty")
	assert.False(t, result.Valid)
}

func TestValidateRule_NoTestCases(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	v, _ := NewJSRuleValidator(e, testLogger())
	result, err := v.ValidateRule(context.Background(), `function validate(i){return ok();}`, nil, nil)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, 0, result.FailedTestCases)
}

func TestValidateRule_PassingTestCase(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	v, _ := NewJSRuleValidator(e, testLogger())

	script := `function validate(i){ if (i.signer === "0x70997970C51812dc3A010C7d01b50e0d17dc79C8") return ok(); return fail("wrong signer"); }`
	testCases := []JSTestCase{
		{
			Name:       "correct signer",
			Input:      map[string]interface{}{"signer": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "sign_type": "transaction", "chain_id": float64(1)},
			ExpectPass: true,
		},
	}
	result, err := v.ValidateRule(context.Background(), script, testCases, nil)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, 0, result.FailedTestCases)
	require.Len(t, result.TestCaseResults, 1)
	assert.True(t, result.TestCaseResults[0].Passed)
}

func TestValidateRule_FailingTestCase_ExpectedPassButFailed(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	v, _ := NewJSRuleValidator(e, testLogger())

	script := `function validate(i){ return fail("always fails"); }`
	testCases := []JSTestCase{
		{
			Name:       "should pass",
			Input:      map[string]interface{}{"signer": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "sign_type": "transaction", "chain_id": float64(1)},
			ExpectPass: true, // expects pass but script fails
		},
	}
	result, err := v.ValidateRule(context.Background(), script, testCases, nil)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Equal(t, 1, result.FailedTestCases)
	require.Len(t, result.TestCaseResults, 1)
	assert.False(t, result.TestCaseResults[0].Passed)
	assert.Contains(t, result.TestCaseResults[0].Error, "expected pass but got")
}

func TestValidateRule_FailingTestCase_ExpectedFailButPassed(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	v, _ := NewJSRuleValidator(e, testLogger())

	script := `function validate(i){ return ok(); }`
	testCases := []JSTestCase{
		{
			Name:       "should fail",
			Input:      map[string]interface{}{"signer": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "sign_type": "transaction", "chain_id": float64(1)},
			ExpectPass: false, // expects fail but script passes
		},
	}
	result, err := v.ValidateRule(context.Background(), script, testCases, nil)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Equal(t, 1, result.FailedTestCases)
	assert.Contains(t, result.TestCaseResults[0].Error, "expected fail but passed")
}

func TestValidateRule_ReasonMismatch(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	v, _ := NewJSRuleValidator(e, testLogger())

	script := `function validate(i){ return fail("actual reason"); }`
	testCases := []JSTestCase{
		{
			Name:         "reason check",
			Input:        map[string]interface{}{"signer": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "sign_type": "transaction", "chain_id": float64(1)},
			ExpectPass:   false,
			ExpectReason: "expected reason", // doesn't match actual
		},
	}
	result, err := v.ValidateRule(context.Background(), script, testCases, nil)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Equal(t, 1, result.FailedTestCases)
	assert.Contains(t, result.TestCaseResults[0].Error, "expected reason containing")
}

func TestValidateRule_ReasonMatch(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	v, _ := NewJSRuleValidator(e, testLogger())

	script := `function validate(i){ return fail("value too high"); }`
	testCases := []JSTestCase{
		{
			Name:         "reason check",
			Input:        map[string]interface{}{"signer": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "sign_type": "transaction", "chain_id": float64(1)},
			ExpectPass:   false,
			ExpectReason: "too high", // substring match
		},
	}
	result, err := v.ValidateRule(context.Background(), script, testCases, nil)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, 0, result.FailedTestCases)
}

func TestValidateRule_WithTestVariables(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	v, _ := NewJSRuleValidator(e, testLogger())

	script := `function validate(i){ if (config.threshold === "100") return ok(); return fail("wrong config"); }`
	testCases := []JSTestCase{
		{
			Name:       "config check",
			Input:      map[string]interface{}{"signer": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "sign_type": "transaction", "chain_id": float64(1)},
			ExpectPass: true,
		},
	}
	vars := map[string]string{"threshold": "100"}
	result, err := v.ValidateRule(context.Background(), script, testCases, vars)
	require.NoError(t, err)
	assert.True(t, result.Valid)
}

func TestValidateRule_MultipleTestCases(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	v, _ := NewJSRuleValidator(e, testLogger())

	script := `function validate(i){ if (i.signer === "0x0000000000000000000000000000000000000001") return ok(); return fail("wrong signer"); }`
	testCases := []JSTestCase{
		{
			Name:       "pass case",
			Input:      map[string]interface{}{"signer": "0x0000000000000000000000000000000000000001", "sign_type": "transaction", "chain_id": float64(1)},
			ExpectPass: true,
		},
		{
			Name:       "fail case",
			Input:      map[string]interface{}{"signer": "0x0000000000000000000000000000000000000002", "sign_type": "transaction", "chain_id": float64(1)},
			ExpectPass: false,
		},
	}
	result, err := v.ValidateRule(context.Background(), script, testCases, nil)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, 0, result.FailedTestCases)
	assert.Len(t, result.TestCaseResults, 2)
}

func TestValidateRule_ExpectBudgetAmount_Pass(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	v, _ := NewJSRuleValidator(e, testLogger())

	script := `function validate(i){ return ok(); }
function validateBudget(i){ return 7n; }`
	testCases := []JSTestCase{
		{
			Name:               "budget amount",
			Input:              map[string]interface{}{"sign_type": "transaction", "chain_id": float64(1), "signer": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"},
			ExpectPass:         true,
			ExpectBudgetAmount: "7",
		},
	}
	result, err := v.ValidateRule(context.Background(), script, testCases, nil)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Len(t, result.TestCaseResults, 1)
	assert.True(t, result.TestCaseResults[0].Passed)
}

func TestValidateRule_ExpectBudgetAmount_Mismatch(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	v, _ := NewJSRuleValidator(e, testLogger())

	script := `function validate(i){ return ok(); }
function validateBudget(i){ return 7n; }`
	testCases := []JSTestCase{
		{
			Name:               "wrong expected amount",
			Input:              map[string]interface{}{"sign_type": "transaction", "chain_id": float64(1), "signer": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"},
			ExpectPass:         true,
			ExpectBudgetAmount: "99",
		},
	}
	result, err := v.ValidateRule(context.Background(), script, testCases, nil)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Equal(t, 1, result.FailedTestCases)
	assert.Contains(t, result.TestCaseResults[0].Error, "expect_budget_amount 99 but got 7")
}

func TestValidateRule_NilInput(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	v, _ := NewJSRuleValidator(e, testLogger())

	script := `function validate(i){ return ok(); }`
	testCases := []JSTestCase{
		{
			Name:       "nil input",
			Input:      nil, // MapToRuleInput returns error for nil
			ExpectPass: true,
		},
	}
	result, err := v.ValidateRule(context.Background(), script, testCases, nil)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Equal(t, 1, result.FailedTestCases)
	assert.Contains(t, result.TestCaseResults[0].Error, "invalid input")
}

// ─────────────────────────────────────────────────────────────────────────────
// MapToRuleInput
// ─────────────────────────────────────────────────────────────────────────────

func TestMapToRuleInput_Nil(t *testing.T) {
	_, err := MapToRuleInput(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "input is nil")
}

func TestMapToRuleInput_Valid(t *testing.T) {
	input := map[string]interface{}{
		"sign_type": "transaction",
		"chain_id":  float64(1),
		"signer":    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
	}
	result, err := MapToRuleInput(input)
	require.NoError(t, err)
	assert.Equal(t, "transaction", result.SignType)
	assert.Equal(t, int64(1), result.ChainID)
	assert.Equal(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", result.Signer)
}

func TestMapToRuleInput_Empty(t *testing.T) {
	input := map[string]interface{}{}
	result, err := MapToRuleInput(input)
	require.NoError(t, err)
	assert.Equal(t, "", result.SignType)
}

func TestMapToRuleInput_WithTransaction(t *testing.T) {
	input := map[string]interface{}{
		"sign_type": "transaction",
		"chain_id":  float64(1),
		"signer":    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		"transaction": map[string]interface{}{
			"from":  "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
			"to":    "0x742d35cc6634c0532925a3b844bc454e4438f44e",
			"value": "0x0",
			"data":  "0x",
		},
	}
	result, err := MapToRuleInput(input)
	require.NoError(t, err)
	require.NotNil(t, result.Transaction)
	assert.Equal(t, "0x742d35cc6634c0532925a3b844bc454e4438f44e", result.Transaction.To)
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidateJSCodeSecurity
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateJSCodeSecurity(t *testing.T) {
	tests := []struct {
		name        string
		code        string
		expectError bool
	}{
		// Safe code - should pass
		{
			name:        "safe validate function",
			code:        `function validate(i){ if (i.signer === "0xABC") return ok(); return fail("wrong signer"); }`,
			expectError: false,
		},
		{
			name:        "safe config usage",
			code:        `function validate(i){ if (config.threshold === "100") return ok(); return fail("wrong config"); }`,
			expectError: false,
		},
		{
			name:        "safe string containing process word",
			code:        `function validate(i){ return fail("processing data"); }`,
			expectError: false,
		},
		{
			name:        "safe arrow function",
			code:        `const check = (x) => x > 0;`,
			expectError: false,
		},
		{
			name:        "safe object property access",
			code:        `function validate(i){ return i.transaction.to === config.allowed_address ? ok() : fail("bad to"); }`,
			expectError: false,
		},

		// Dangerous patterns - should fail
		{
			name:        "__proto__ - prototype pollution",
			code:        `obj.__proto__.isAdmin = true;`,
			expectError: true,
		},
		{
			name:        "constructor.constructor - sandbox escape",
			code:        `"".constructor.constructor("return this")();`,
			expectError: true,
		},
		{
			name:        "constructor . constructor with spaces",
			code:        `"".constructor . constructor("return this")();`,
			expectError: true,
		},
		{
			name:        "child_process - command execution",
			code:        `require('child_process').exec('rm -rf /');`,
			expectError: true,
		},
		{
			name:        "dynamic import()",
			code:        `const m = await import('fs');`,
			expectError: true,
		},
		{
			name:        "Object.getPrototypeOf",
			code:        `Object.getPrototypeOf(obj);`,
			expectError: true,
		},
		{
			name:        "Object.setPrototypeOf",
			code:        `Object.setPrototypeOf(obj, null);`,
			expectError: true,
		},
		{
			name:        "Object.defineProperty",
			code:        `Object.defineProperty(obj, 'key', {get: ()=> globalThis});`,
			expectError: true,
		},
		{
			name:        "new Function() - dynamic code execution",
			code:        `const evil = new Function("return this")();`,
			expectError: true,
		},
		{
			name:        "Function( without new",
			code:        `const evil = Function("return this")();`,
			expectError: true,
		},

		// Edge cases
		{
			name:        "__proto__ in string literal still detected",
			code:        `var s = "__proto__";`,
			expectError: true,
		},
		{
			name:        "child_process in comment still detected",
			code:        `// require('child_process')`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateJSCodeSecurity(tt.code)

			if tt.expectError {
				require.NotNil(t, err, "expected security error but got nil")
				assert.Contains(t, err.Message, "dangerous pattern detected",
					"error message should indicate dangerous pattern")
			} else {
				assert.Nil(t, err, "expected no security error but got: %v", err)
			}
		})
	}
}

func TestValidateRule_SecurityCheckBlocks(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	v, _ := NewJSRuleValidator(e, testLogger())

	script := `function validate(i){ "".constructor.constructor("return this")(); return ok(); }`
	result, err := v.ValidateRule(context.Background(), script, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "security check failed")
	assert.False(t, result.Valid)
}
