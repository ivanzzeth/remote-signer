package evm

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// NewJSRuleEvaluator
// ─────────────────────────────────────────────────────────────────────────────

func TestNewJSRuleEvaluator_NilLogger(t *testing.T) {
	_, err := NewJSRuleEvaluator(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

// ─────────────────────────────────────────────────────────────────────────────
// sanitizeReason
// ─────────────────────────────────────────────────────────────────────────────

func TestSanitizeReason(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		detail   string
		isReason bool
		expected string
	}{
		{"code only", "script_error", "", false, "script_error"},
		{"empty code empty detail isReason", "", "", true, ""},
		{"empty code empty detail not reason", "", "", false, "script_error"},
		{"code with detail", "timeout", "ctx deadline", false, "timeout: ctx deadline"},
		{"reason mode just detail", "", "some reason text", true, "some reason text"},
		{"control chars stripped", "", "bad\x00char\x01here", true, "badcharhere"},
		{"newlines escaped", "", "line1\nline2", true, "line1\\nline2"},
		{"long string truncated", "", strings.Repeat("a", 200), true, strings.Repeat("a", 120)},
		{"code with long detail", "err", strings.Repeat("b", 200), false, "err: " + strings.Repeat("b", 120)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := sanitizeReason(tc.code, tc.detail, tc.isReason)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// isUndefined
// ─────────────────────────────────────────────────────────────────────────────

func TestIsUndefined_Nil(t *testing.T) {
	assert.True(t, isUndefined(nil))
}

// ─────────────────────────────────────────────────────────────────────────────
// parseDelegateToIDs
// ─────────────────────────────────────────────────────────────────────────────

func TestParseDelegateToIDs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []types.RuleID
	}{
		{"empty", "", nil},
		{"single", "rule-1", []types.RuleID{"rule-1"}},
		{"multiple", "rule-1,rule-2,rule-3", []types.RuleID{"rule-1", "rule-2", "rule-3"}},
		{"with spaces", " rule-1 , rule-2 ", []types.RuleID{"rule-1", "rule-2"}},
		{"template placeholder", "${rule_id}", nil},
		{"mixed with placeholder", "rule-1,${rule_id},rule-2", []types.RuleID{"rule-1", "rule-2"}},
		{"all placeholders", "${a},${b}", nil},
		{"empty parts", "rule-1,,rule-2", []types.RuleID{"rule-1", "rule-2"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDelegateToIDs(tc.input)
			if tc.want == nil {
				assert.Nil(t, got)
			} else {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// AppliesToSignType
// ─────────────────────────────────────────────────────────────────────────────

func TestAppliesToSignType_EmptyFilter(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	cfg := mustMarshalJSON(map[string]string{"script": "function validate(i){return ok();}"})
	rule := &types.Rule{Config: cfg}
	assert.True(t, e.AppliesToSignType(rule, "transaction"))
	assert.True(t, e.AppliesToSignType(rule, "typed_data"))
	assert.True(t, e.AppliesToSignType(rule, "personal"))
}

func TestAppliesToSignType_InvalidConfig(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	rule := &types.Rule{Config: []byte(`{invalid`)}
	// Invalid config should default to applying to all types
	assert.True(t, e.AppliesToSignType(rule, "transaction"))
}

func TestAppliesToSignType_PersonalVariants(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	cfg := mustMarshalJSON(map[string]string{
		"script":           "function validate(i){return ok();}",
		"sign_type_filter": "personal",
	})
	rule := &types.Rule{Config: cfg}
	assert.True(t, e.AppliesToSignType(rule, "personal"))
	assert.True(t, e.AppliesToSignType(rule, "eip191"))
	assert.False(t, e.AppliesToSignType(rule, "transaction"))
}

func TestAppliesToSignType_PersonalSignVariant(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	cfg := mustMarshalJSON(map[string]string{
		"script":           "function validate(i){return ok();}",
		"sign_type_filter": "personal_sign",
	})
	rule := &types.Rule{Config: cfg}
	assert.True(t, e.AppliesToSignType(rule, "personal"))
	assert.True(t, e.AppliesToSignType(rule, "eip191"))
}

func TestAppliesToSignType_EIP191Variant(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	cfg := mustMarshalJSON(map[string]string{
		"script":           "function validate(i){return ok();}",
		"sign_type_filter": "eip191",
	})
	rule := &types.Rule{Config: cfg}
	assert.True(t, e.AppliesToSignType(rule, "personal"))
	assert.True(t, e.AppliesToSignType(rule, "eip191"))
}

func TestAppliesToSignType_TransactionOnly(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	cfg := mustMarshalJSON(map[string]string{
		"script":           "function validate(i){return ok();}",
		"sign_type_filter": "transaction",
	})
	rule := &types.Rule{Config: cfg}
	assert.True(t, e.AppliesToSignType(rule, "transaction"))
	assert.False(t, e.AppliesToSignType(rule, "typed_data"))
	assert.False(t, e.AppliesToSignType(rule, "personal"))
}

func TestAppliesToSignType_TypedDataOnly(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	cfg := mustMarshalJSON(map[string]string{
		"script":           "function validate(i){return ok();}",
		"sign_type_filter": "typed_data",
	})
	rule := &types.Rule{Config: cfg}
	assert.True(t, e.AppliesToSignType(rule, "typed_data"))
	assert.False(t, e.AppliesToSignType(rule, "transaction"))
}

func TestAppliesToSignType_DefaultPassthrough(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	cfg := mustMarshalJSON(map[string]string{
		"script":           "function validate(i){return ok();}",
		"sign_type_filter": "custom_type",
	})
	rule := &types.Rule{Config: cfg}
	assert.True(t, e.AppliesToSignType(rule, "custom_type"))
	assert.False(t, e.AppliesToSignType(rule, "transaction"))
}

func TestAppliesToSignType_CommaSeparatedWithSpaces(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	cfg := mustMarshalJSON(map[string]string{
		"script":           "function validate(i){return ok();}",
		"sign_type_filter": " typed_data , personal ",
	})
	rule := &types.Rule{Config: cfg}
	assert.True(t, e.AppliesToSignType(rule, "typed_data"))
	assert.True(t, e.AppliesToSignType(rule, "personal"))
	assert.False(t, e.AppliesToSignType(rule, "transaction"))
}

func TestAppliesToSignType_EmptyCommaEntries(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	cfg := mustMarshalJSON(map[string]string{
		"script":           "function validate(i){return ok();}",
		"sign_type_filter": "transaction,,typed_data",
	})
	rule := &types.Rule{Config: cfg}
	assert.True(t, e.AppliesToSignType(rule, "transaction"))
	assert.True(t, e.AppliesToSignType(rule, "typed_data"))
}

// ─────────────────────────────────────────────────────────────────────────────
// wrappedValidate edge cases
// ─────────────────────────────────────────────────────────────────────────────

func TestWrappedValidate_EmptyReturnReason(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	// Script returns valid=false with no reason → should get default message
	script := `function validate(i){ return { valid: false }; }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "script returned valid=false with empty reason")
}

func TestWrappedValidate_UndefinedReturn(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ return undefined; }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "invalid_shape")
}

func TestWrappedValidate_NonObjectReturn(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ return "just a string"; }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "invalid_shape")
}

func TestWrappedValidate_NoValidateFunction(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `var x = 42;`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "validate is not defined")
}

func TestWrappedValidate_ValidateNotFunction(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `var validate = "not a function";`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "validate is not a function")
}

func TestWrappedValidate_ScriptSyntaxError(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i) { return { valid: true ` // unclosed brace
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "script_error")
}

func TestWrappedValidate_ScriptRuntimeError(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ throw new Error("boom"); }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "script_error")
}

func TestWrappedValidate_WithConfig(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ return { valid: config.max_value === "100" }; }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, map[string]interface{}{"max_value": "100"})
	assert.True(t, res.Valid)
}

func TestWrappedValidate_PayloadAndDelegateTo(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ return { valid: true, reason: "ok", payload: { key: "value" }, delegate_to: "rule-2" }; }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid)
	assert.Equal(t, "rule-2", res.DelegateTo)
	assert.NotNil(t, res.Payload)
}

func TestWrappedValidate_NilInput(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ return ok(); }`
	res := e.wrappedValidate(script, nil, nil)
	// nil input → ruleInputToMap returns nil → input is set to nil in VM
	assert.True(t, res.Valid)
}

func TestWrappedValidate_FailHelper(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ return fail("bad transaction"); }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "bad transaction")
}

func TestWrappedValidate_FailHelperNoArg(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ return fail(); }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	// Empty reason from fail() → default message
	assert.Contains(t, res.Reason, "script returned valid=false with empty reason")
}

// ─────────────────────────────────────────────────────────────────────────────
// Evaluate edge cases
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluate_InvalidConfig(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: []byte(`{invalid_json`),
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	_, _, err := e.Evaluate(context.Background(), rule, req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid evm_js config")
}

func TestEvaluate_EmptyScript(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	cfg := mustMarshalJSON(map[string]string{"script": ""})
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: cfg,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	_, _, err := e.Evaluate(context.Background(), rule, req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "evm_js rule script is empty")
}

func TestEvaluate_FromNotDerivable(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	cfg := mustMarshalJSON(map[string]string{"script": "function validate(i){return ok();}"})
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: cfg,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "", // empty → ErrFromNotDerivable
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	_, _, err := e.Evaluate(context.Background(), rule, req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "from address not derivable")
}

func TestEvaluate_WithVariables(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ return { valid: config.threshold === "50" }; }`
	cfg := mustMarshalJSON(map[string]string{"script": script})
	variables, _ := json.Marshal(map[string]string{"threshold": "50"})
	rule := &types.Rule{
		ID:        "test",
		Type:      types.RuleTypeEVMJS,
		Mode:      types.RuleModeWhitelist,
		Config:    cfg,
		Variables: variables,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	matched, _, err := e.Evaluate(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.True(t, matched)
}

func TestEvaluate_InvalidVariablesJSON(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	cfg := mustMarshalJSON(map[string]string{"script": "function validate(i){return ok();}"})
	rule := &types.Rule{
		ID:        "test",
		Type:      types.RuleTypeEVMJS,
		Mode:      types.RuleModeWhitelist,
		Config:    cfg,
		Variables: []byte(`{invalid`),
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	_, _, err := e.Evaluate(context.Background(), rule, req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid rule variables JSON")
}

// ─────────────────────────────────────────────────────────────────────────────
// EvaluateWithDelegation edge cases
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluateWithDelegation_FromNotDerivable(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	cfg := mustMarshalJSON(map[string]string{"script": "function validate(i){return ok();}"})
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: cfg,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	_, _, _, err := e.EvaluateWithDelegation(context.Background(), rule, req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "from address not derivable")
}

func TestEvaluateWithDelegation_InvalidConfig(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: []byte(`{invalid}`),
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	_, _, _, err := e.EvaluateWithDelegation(context.Background(), rule, req, nil)
	require.Error(t, err)
}

func TestEvaluateWithDelegation_EmptyScript(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	cfg := mustMarshalJSON(map[string]string{"script": ""})
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: cfg,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	_, _, _, err := e.EvaluateWithDelegation(context.Background(), rule, req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "script is empty")
}

func TestEvaluateWithDelegation_InvalidVariables(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	cfg := mustMarshalJSON(map[string]string{"script": "function validate(i){return ok();}"})
	rule := &types.Rule{
		ID:        "test",
		Type:      types.RuleTypeEVMJS,
		Mode:      types.RuleModeWhitelist,
		Config:    cfg,
		Variables: []byte(`{invalid`),
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	_, _, _, err := e.EvaluateWithDelegation(context.Background(), rule, req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid rule variables JSON")
}

func TestEvaluateWithDelegation_BlocklistViolation(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){return{valid:false,reason:"blocked"};}`
	cfg := mustMarshalJSON(map[string]string{"script": script})
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeBlocklist,
		Config: cfg,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	matched, reason, deleg, err := e.EvaluateWithDelegation(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.True(t, matched)
	assert.Contains(t, reason, "blocked")
	assert.Nil(t, deleg)
}

func TestEvaluateWithDelegation_BlocklistNoViolation(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){return ok();}`
	cfg := mustMarshalJSON(map[string]string{"script": script})
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeBlocklist,
		Config: cfg,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	matched, _, deleg, err := e.EvaluateWithDelegation(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.False(t, matched)
	assert.Nil(t, deleg)
}

func TestEvaluateWithDelegation_WhitelistReject(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){return{valid:false,reason:"no"};}`
	cfg := mustMarshalJSON(map[string]string{"script": script})
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: cfg,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	matched, reason, deleg, err := e.EvaluateWithDelegation(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.False(t, matched)
	assert.Contains(t, reason, "no")
	assert.Nil(t, deleg)
}

func TestEvaluateWithDelegation_WithDelegation_Single(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ return { valid: true, payload: { signer: i.signer, chain_id: i.chain_id, sign_type: "transaction" }, delegate_to: "rule-2" }; }`
	cfg := mustMarshalJSON(map[string]interface{}{
		"script":      script,
		"delegate_to": "rule-2",
	})
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: cfg,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	matched, _, deleg, err := e.EvaluateWithDelegation(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.True(t, matched)
	require.NotNil(t, deleg)
	assert.Equal(t, "single", deleg.Mode)
	assert.Contains(t, deleg.TargetRuleIDs, types.RuleID("rule-2"))
}

func TestEvaluateWithDelegation_NoDelegation_NoPayload(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	// delegate_to set but no payload → no delegation
	script := `function validate(i){ return { valid: true, delegate_to: "rule-2" }; }`
	cfg := mustMarshalJSON(map[string]string{"script": script})
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: cfg,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	matched, _, deleg, err := e.EvaluateWithDelegation(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.True(t, matched)
	assert.Nil(t, deleg, "no delegation when payload is nil")
}

func TestEvaluateWithDelegation_TemplatePlaceholder(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	// delegate_to is a template placeholder → should be treated as no delegation
	script := `function validate(i){ return { valid: true, payload: { key: "v" } }; }`
	cfg := mustMarshalJSON(map[string]interface{}{
		"script":      script,
		"delegate_to": "${rule_id}",
	})
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: cfg,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	matched, _, deleg, err := e.EvaluateWithDelegation(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.True(t, matched)
	assert.Nil(t, deleg)
}

func TestEvaluateWithDelegation_PerItemMode(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ return { valid: true, payload: { items: [{ signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", chain_id: 1, sign_type: "transaction" }] }, delegate_to: "rule-2" }; }`
	cfg := mustMarshalJSON(map[string]interface{}{
		"script":        script,
		"delegate_to":   "rule-2",
		"delegate_mode": "per_item",
		"items_key":     "items",
	})
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: cfg,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	matched, _, deleg, err := e.EvaluateWithDelegation(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.True(t, matched)
	require.NotNil(t, deleg)
	assert.Equal(t, "per_item", deleg.Mode)
	assert.Equal(t, "items", deleg.ItemsKey)
}

func TestEvaluateWithDelegation_PerItemDefaultItemsKey(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ return { valid: true, payload: { items: [{ signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", chain_id: 1, sign_type: "transaction" }] }, delegate_to: "rule-2" }; }`
	cfg := mustMarshalJSON(map[string]interface{}{
		"script":        script,
		"delegate_to":   "rule-2",
		"delegate_mode": "per_item",
		// items_key not specified → default "items"
	})
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: cfg,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	matched, _, deleg, err := e.EvaluateWithDelegation(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.True(t, matched)
	require.NotNil(t, deleg)
	assert.Equal(t, "items", deleg.ItemsKey)
}

func TestEvaluateWithDelegation_PerItemPayloadNotMap(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	// payload is an array not a map → per_item check should return no delegation
	script := `function validate(i){ return { valid: true, payload: [1, 2, 3], delegate_to: "rule-2" }; }`
	cfg := mustMarshalJSON(map[string]interface{}{
		"script":        script,
		"delegate_to":   "rule-2",
		"delegate_mode": "per_item",
	})
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: cfg,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	matched, _, deleg, err := e.EvaluateWithDelegation(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.True(t, matched)
	assert.Nil(t, deleg, "per_item with non-map payload should not produce delegation")
}

func TestEvaluateWithDelegation_PerItemMissingItemsKey(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ return { valid: true, payload: { other: "data" }, delegate_to: "rule-2" }; }`
	cfg := mustMarshalJSON(map[string]interface{}{
		"script":        script,
		"delegate_to":   "rule-2",
		"delegate_mode": "per_item",
		"items_key":     "items",
	})
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: cfg,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	matched, _, deleg, err := e.EvaluateWithDelegation(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.True(t, matched)
	assert.Nil(t, deleg, "per_item with missing items_key should not produce delegation")
}

func TestEvaluateWithDelegation_PerItemNotArray(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	// items is a string not an array → should not produce delegation
	script := `function validate(i){ return { valid: true, payload: { items: "not_array" }, delegate_to: "rule-2" }; }`
	cfg := mustMarshalJSON(map[string]interface{}{
		"script":        script,
		"delegate_to":   "rule-2",
		"delegate_mode": "per_item",
	})
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: cfg,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	matched, _, deleg, err := e.EvaluateWithDelegation(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.True(t, matched)
	assert.Nil(t, deleg)
}

func TestEvaluateWithDelegation_DelegateModeTemplatePlaceholder(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ return { valid: true, payload: { key: "v" }, delegate_to: "rule-2" }; }`
	cfg := mustMarshalJSON(map[string]interface{}{
		"script":        script,
		"delegate_to":   "rule-2",
		"delegate_mode": "${mode}",
	})
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: cfg,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	matched, _, deleg, err := e.EvaluateWithDelegation(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.True(t, matched)
	require.NotNil(t, deleg)
	assert.Equal(t, "single", deleg.Mode, "template placeholder should default to single")
}

func TestEvaluateWithDelegation_MultipleTargets(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ return { valid: true, payload: { key: "v" }, delegate_to: "rule-1,rule-2,rule-3" }; }`
	cfg := mustMarshalJSON(map[string]string{"script": script})
	rule := &types.Rule{
		ID:     "test",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: cfg,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	matched, _, deleg, err := e.EvaluateWithDelegation(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.True(t, matched)
	require.NotNil(t, deleg)
	assert.Len(t, deleg.TargetRuleIDs, 3)
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidateWithInput
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateWithInput(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ return ok(); }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.ValidateWithInput(script, input, nil)
	assert.True(t, res.Valid)
}

func TestValidateWithInput_Fail(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ return fail("bad"); }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.ValidateWithInput(script, input, nil)
	assert.False(t, res.Valid)
}
