package evm

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// NewMessagePatternRuleValidator
// ─────────────────────────────────────────────────────────────────────────────

func TestNewMessagePatternRuleValidator(t *testing.T) {
	v, err := NewMessagePatternRuleValidator(testLogger())
	require.NoError(t, err)
	assert.NotNil(t, v)
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidateRule
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateRule_InvalidConfig(t *testing.T) {
	v, _ := NewMessagePatternRuleValidator(testLogger())
	rule := &types.Rule{
		ID:     "test",
		Config: []byte(`{invalid`),
		Mode:   types.RuleModeWhitelist,
	}
	result, err := v.ValidateRule(context.Background(), rule)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.NotNil(t, result.SyntaxError)
	assert.Contains(t, result.SyntaxError.Message, "invalid config")
}

func TestValidateRule_NoPatterns(t *testing.T) {
	v, _ := NewMessagePatternRuleValidator(testLogger())
	cfg, _ := json.Marshal(MessagePatternConfig{
		TestCases: []MessagePatternTestCase{
			{Name: "p", Input: MessagePatternTestInput{RawMessage: "hi"}, ExpectPass: true},
			{Name: "n", Input: MessagePatternTestInput{RawMessage: "no"}, ExpectPass: false},
		},
	})
	rule := &types.Rule{ID: "test", Config: cfg, Mode: types.RuleModeWhitelist}
	result, err := v.ValidateRule(context.Background(), rule)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Contains(t, result.SyntaxError.Message, "no patterns configured")
}

func TestValidateRule_InvalidRegex(t *testing.T) {
	v, _ := NewMessagePatternRuleValidator(testLogger())
	cfg, _ := json.Marshal(MessagePatternConfig{
		Pattern: "[invalid(regex",
		TestCases: []MessagePatternTestCase{
			{Name: "p", Input: MessagePatternTestInput{RawMessage: "hi"}, ExpectPass: true},
			{Name: "n", Input: MessagePatternTestInput{RawMessage: "no"}, ExpectPass: false},
		},
	})
	rule := &types.Rule{ID: "test", Config: cfg, Mode: types.RuleModeWhitelist}
	result, err := v.ValidateRule(context.Background(), rule)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Contains(t, result.SyntaxError.Message, "invalid regex pattern")
}

func TestValidateRule_TooFewTestCases(t *testing.T) {
	v, _ := NewMessagePatternRuleValidator(testLogger())
	cfg, _ := json.Marshal(MessagePatternConfig{
		Pattern: "hello",
		TestCases: []MessagePatternTestCase{
			{Name: "only one", Input: MessagePatternTestInput{RawMessage: "hello"}, ExpectPass: true},
		},
	})
	rule := &types.Rule{ID: "test", Config: cfg, Mode: types.RuleModeWhitelist}
	_, err := v.ValidateRule(context.Background(), rule)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 2 test cases")
}

func TestValidateRule_NoPositiveTestCase(t *testing.T) {
	v, _ := NewMessagePatternRuleValidator(testLogger())
	cfg, _ := json.Marshal(MessagePatternConfig{
		Pattern: "hello",
		TestCases: []MessagePatternTestCase{
			{Name: "neg1", Input: MessagePatternTestInput{RawMessage: "world"}, ExpectPass: false},
			{Name: "neg2", Input: MessagePatternTestInput{RawMessage: "foo"}, ExpectPass: false},
		},
	})
	rule := &types.Rule{ID: "test", Config: cfg, Mode: types.RuleModeWhitelist}
	_, err := v.ValidateRule(context.Background(), rule)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one positive test case")
}

func TestValidateRule_NoNegativeTestCase(t *testing.T) {
	v, _ := NewMessagePatternRuleValidator(testLogger())
	cfg, _ := json.Marshal(MessagePatternConfig{
		Pattern: "hello",
		TestCases: []MessagePatternTestCase{
			{Name: "pos1", Input: MessagePatternTestInput{RawMessage: "hello"}, ExpectPass: true},
			{Name: "pos2", Input: MessagePatternTestInput{RawMessage: "hello world"}, ExpectPass: true},
		},
	})
	rule := &types.Rule{ID: "test", Config: cfg, Mode: types.RuleModeWhitelist}
	_, err := v.ValidateRule(context.Background(), rule)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one negative test case")
}

func TestValidateRule_AllPass_Whitelist(t *testing.T) {
	v, _ := NewMessagePatternRuleValidator(testLogger())
	cfg, _ := json.Marshal(MessagePatternConfig{
		Pattern: "^hello",
		TestCases: []MessagePatternTestCase{
			{Name: "match", Input: MessagePatternTestInput{RawMessage: "hello world"}, ExpectPass: true},
			{Name: "no match", Input: MessagePatternTestInput{RawMessage: "goodbye world"}, ExpectPass: false},
		},
	})
	rule := &types.Rule{
		ID:     "test",
		Config: cfg,
		Mode:   types.RuleModeWhitelist,
	}
	result, err := v.ValidateRule(context.Background(), rule)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, 0, result.FailedTestCases)
	assert.Len(t, result.TestCaseResults, 2)
}

func TestValidateRule_TestCaseFails_ExpectedMatchButNoMatch(t *testing.T) {
	v, _ := NewMessagePatternRuleValidator(testLogger())
	cfg, _ := json.Marshal(MessagePatternConfig{
		Pattern: "^hello",
		TestCases: []MessagePatternTestCase{
			{Name: "should match but wont", Input: MessagePatternTestInput{RawMessage: "goodbye"}, ExpectPass: true},
			{Name: "no match", Input: MessagePatternTestInput{RawMessage: "goodbye world"}, ExpectPass: false},
		},
	})
	rule := &types.Rule{
		ID:     "test",
		Config: cfg,
		Mode:   types.RuleModeWhitelist,
	}
	result, err := v.ValidateRule(context.Background(), rule)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Equal(t, 1, result.FailedTestCases)
	assert.Contains(t, result.TestCaseResults[0].Error, "expected match but pattern did not match")
}

func TestValidateRule_TestCaseFails_ExpectedNoMatchButMatched(t *testing.T) {
	v, _ := NewMessagePatternRuleValidator(testLogger())
	cfg, _ := json.Marshal(MessagePatternConfig{
		Pattern: "hello",
		TestCases: []MessagePatternTestCase{
			{Name: "match", Input: MessagePatternTestInput{RawMessage: "hello"}, ExpectPass: true},
			{Name: "should not match but does", Input: MessagePatternTestInput{RawMessage: "hello world"}, ExpectPass: false},
		},
	})
	rule := &types.Rule{
		ID:     "test",
		Config: cfg,
		Mode:   types.RuleModeWhitelist,
	}
	result, err := v.ValidateRule(context.Background(), rule)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Equal(t, 1, result.FailedTestCases)
	assert.Contains(t, result.TestCaseResults[1].Error, "expected no match but got")
}

func TestValidateRule_WithSignType(t *testing.T) {
	v, _ := NewMessagePatternRuleValidator(testLogger())
	cfg, _ := json.Marshal(MessagePatternConfig{
		Pattern: "^test",
		TestCases: []MessagePatternTestCase{
			{Name: "match personal", Input: MessagePatternTestInput{RawMessage: "test message", SignType: "personal"}, ExpectPass: true},
			{Name: "no match", Input: MessagePatternTestInput{RawMessage: "other"}, ExpectPass: false},
		},
	})
	rule := &types.Rule{
		ID:     "test",
		Config: cfg,
		Mode:   types.RuleModeWhitelist,
	}
	result, err := v.ValidateRule(context.Background(), rule)
	require.NoError(t, err)
	assert.True(t, result.Valid)
}

func TestValidateRule_WithMultiplePatterns(t *testing.T) {
	v, _ := NewMessagePatternRuleValidator(testLogger())
	cfg, _ := json.Marshal(MessagePatternConfig{
		Patterns: []string{"^hello", "^world"},
		TestCases: []MessagePatternTestCase{
			{Name: "match first", Input: MessagePatternTestInput{RawMessage: "hello there"}, ExpectPass: true},
			{Name: "match second", Input: MessagePatternTestInput{RawMessage: "world peace"}, ExpectPass: true},
			{Name: "no match", Input: MessagePatternTestInput{RawMessage: "goodbye"}, ExpectPass: false},
		},
	})
	rule := &types.Rule{
		ID:     "test",
		Config: cfg,
		Mode:   types.RuleModeWhitelist,
	}
	result, err := v.ValidateRule(context.Background(), rule)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, 0, result.FailedTestCases)
}

// ─────────────────────────────────────────────────────────────────────────────
// MessagePatternEvaluator.AppliesToSignType
// ─────────────────────────────────────────────────────────────────────────────

func TestMessagePatternEvaluator_AppliesToSignType_DefaultSignTypes(t *testing.T) {
	e, _ := NewMessagePatternEvaluator()
	cfg, _ := json.Marshal(MessagePatternConfig{Pattern: "test"})
	rule := &types.Rule{Config: cfg}

	// Default: applies to personal and eip191 only
	assert.True(t, e.AppliesToSignType(rule, "personal"))
	assert.True(t, e.AppliesToSignType(rule, "eip191"))
	assert.False(t, e.AppliesToSignType(rule, "transaction"))
	assert.False(t, e.AppliesToSignType(rule, "typed_data"))
}

func TestMessagePatternEvaluator_AppliesToSignType_CustomSignTypes(t *testing.T) {
	e, _ := NewMessagePatternEvaluator()
	cfg, _ := json.Marshal(MessagePatternConfig{
		Pattern:   "test",
		SignTypes: []string{"personal", "typed_data"},
	})
	rule := &types.Rule{Config: cfg}

	assert.True(t, e.AppliesToSignType(rule, "personal"))
	assert.True(t, e.AppliesToSignType(rule, "typed_data"))
	assert.False(t, e.AppliesToSignType(rule, "transaction"))
}

func TestMessagePatternEvaluator_AppliesToSignType_InvalidConfig(t *testing.T) {
	e, _ := NewMessagePatternEvaluator()
	rule := &types.Rule{Config: []byte(`{invalid`)}
	// Invalid config → returns true (let Evaluate handle the error)
	assert.True(t, e.AppliesToSignType(rule, "transaction"))
}
