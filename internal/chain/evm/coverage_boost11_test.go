//go:build integration

// Package evm provides EVM-specific chain logic for the Remote Signer.
package evm

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// solidity_execution.go -- pure Go helpers

func TestIsDecimalString(t *testing.T) {
	assert.True(t, isDecimalString("12345"))
	assert.True(t, isDecimalString("0"))
	assert.False(t, isDecimalString(""))
	assert.False(t, isDecimalString("12a34"))
	assert.False(t, isDecimalString("-1"))
	assert.False(t, isDecimalString("12.34"))
}

func TestIsHexString(t *testing.T) {
	assert.True(t, isHexString("abcdef"))
	assert.True(t, isHexString("ABCDEF"))
	assert.True(t, isHexString("0123456789"))
	assert.False(t, isHexString(""))
	assert.False(t, isHexString("0x123"))
	assert.False(t, isHexString("ghijkl"))
}

func TestNewParseRevertReasonAll(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected string
	}{
		{"FAIL pattern", "[FAIL: out of gas] test()\n", "out of gas"},
		{"FAIL pattern empty reason", "[FAIL:] test()\n", ""},
		{"return_data JSON", `{"traces":{"return_data": "nope"}}`, "nope"},
		{"return_data null", `{"traces":{"return_data": null}}`, ""},
		{"script failed", "Error: script failed: arithmetic error\n", "arithmetic error"},
		{"revert pattern", "revert: insufficient funds\n", "insufficient funds"},
		{"Error pattern", "Error: something broke\n", "something broke"},
		{"panic pattern", "Panic(0x12)\n", "panic: 0x12"},
		{"no match", "nothing useful here\n", ""},
		{"compiler error", "Error: Compiler run failed\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRevertReason([]byte(tt.output))
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestSafeForgeEnv(t *testing.T) {
	env := safeForgeEnv()
	assert.Contains(t, env, "FOUNDRY_FFI=false")
	assert.Contains(t, env, "FOUNDRY_FS_PERMISSIONS=[]")
	hasPATH := false
	for _, e := range env {
		if len(e) >= 5 && e[:5] == "PATH=" {
			hasPATH = true
			break
		}
	}
	assert.True(t, hasPATH, "PATH should be included in safe forge env")
}

// signer.go -- normalizeAddress, resolvePrivateKey

func TestNewNormalizeAddress(t *testing.T) {
	result := normalizeAddress("0x1234567890abcdef1234567890abcdef12345678")
	assert.Len(t, result, 42)
	assert.Equal(t, "0x", result[:2])
}

func TestResolvePrivateKey_DirectHex(t *testing.T) {
	key := "0000000000000000000000000000000000000000000000000000000000000001"
	got := resolvePrivateKey(key)
	assert.Equal(t, key, got)

	got = resolvePrivateKey("0x" + key)
	assert.Equal(t, key, got)
}

func TestResolvePrivateKey_NonHexShort(t *testing.T) {
	got := resolvePrivateKey("MY_KEY")
	assert.Equal(t, "", got)

	os.Setenv("MY_KEY", "secret")
	defer os.Unsetenv("MY_KEY")
	got = resolvePrivateKey("MY_KEY")
	assert.Equal(t, "secret", got)
}

func TestResolvePrivateKey_InvalidHexInKeyLength(t *testing.T) {
	defer os.Unsetenv("ZZ_NOT_HEX")
	os.Setenv("ZZ_NOT_HEX", "fallback_val")
	got := resolvePrivateKey("ZZ_NOT_HEX")
	assert.Equal(t, "fallback_val", got)
}

// password_provider.go -- EnvPasswordProvider empty env

func TestNewEnvPasswordProvider_GetPassword_EmptyEnv(t *testing.T) {
	p, err := NewEnvPasswordProvider()
	require.NoError(t, err)

	os.Setenv("TEST_EMPTY_ENV_PW", "")
	defer os.Unsetenv("TEST_EMPTY_ENV_PW")

	_, err = p.GetPassword("0x1234", KeystoreConfig{PasswordEnv: "TEST_EMPTY_ENV_PW"})
	assert.ErrorContains(t, err, "environment variable TEST_EMPTY_ENV_PW is empty")
}

// js_rule_input_map.go -- ruleInputToMap

func TestNewRuleInputToMap_Nil(t *testing.T) {
	m, err := ruleInputToMap(nil)
	require.NoError(t, err)
	assert.Nil(t, m)
}

func TestNewRuleInputToMap_Valid(t *testing.T) {
	m, err := ruleInputToMap(&RuleInput{Signer: "0xabc"})
	require.NoError(t, err)
	assert.Equal(t, "0xabc", m["signer"])
}

// signer.go -- Registry pure functions

func TestNewSignerRegistry_Empty(t *testing.T) {
	r := NewEmptySignerRegistry()
	require.NotNil(t, r)
	assert.Equal(t, 0, r.SignerCount())
	assert.Equal(t, 0, r.TotalCount())

	_, exists := r.GetSignerInfo("0x123")
	assert.False(t, exists)

	err := r.LockSigner("0x123")
	assert.ErrorIs(t, err, types.ErrSignerNotFound)

	_, err = r.GetSigner("0x123")
	assert.ErrorIs(t, err, types.ErrSignerNotFound)

	assert.False(t, r.HasSigner("0x123"))
	assert.False(t, r.IsLocked("0x123"))

	r.UnregisterSigner("0x123") // no-op

	info := r.ListSigners()
	assert.Empty(t, info)

	result := r.ListSignersWithFilter(types.SignerFilter{Offset: 0, Limit: 10})
	assert.Empty(t, result.Signers)
	assert.Equal(t, 0, result.Total)
	assert.False(t, result.HasMore)
}

func TestNewSignerRegistryWithProvider_NilProvider2(t *testing.T) {
	_, err := NewSignerRegistryWithProvider(SignerConfig{}, nil)
	assert.ErrorContains(t, err, "password provider is required")
}

func TestNewSignerRegistryWithProvider_EmptyConfig(t *testing.T) {
	provider, err := NewEnvPasswordProvider()
	require.NoError(t, err)

	r, err := NewSignerRegistryWithProvider(SignerConfig{}, provider)
	require.NoError(t, err)
	require.NotNil(t, r)
	assert.Equal(t, 0, r.SignerCount())
}

func TestSignerRegistry_RegisterLockedSigner(t *testing.T) {
	r := NewEmptySignerRegistry()
	err := r.RegisterLockedSigner("0xabc", types.SignerInfo{Address: "0xabc", Type: "keystore"})
	require.NoError(t, err)
	assert.True(t, r.IsLocked("0xabc"))
	assert.True(t, r.HasSigner("0xabc"))
	assert.Equal(t, 1, r.TotalCount())
	assert.Equal(t, 0, r.SignerCount())

	err = r.RegisterLockedSigner("0xabc", types.SignerInfo{Address: "0xabc"})
	assert.ErrorIs(t, err, types.ErrAlreadyExists)
}

func TestSignerRegistry_UnlockSigner(t *testing.T) {
	r := NewEmptySignerRegistry()
	err := r.RegisterLockedSigner("0xabc", types.SignerInfo{Address: "0xabc", Type: "keystore"})
	require.NoError(t, err)

	err = r.UnlockSigner("0xabc", nil)
	require.NoError(t, err)
	assert.False(t, r.IsLocked("0xabc"))

	err = r.UnlockSigner("0xabc", nil)
	assert.ErrorIs(t, err, types.ErrSignerNotLocked)

	err = r.UnlockSigner("0x999", nil)
	assert.ErrorIs(t, err, types.ErrSignerNotFound)
}

func TestSignerRegistry_LockUnlockCycle(t *testing.T) {
	r := NewEmptySignerRegistry()
	err := r.RegisterLockedSigner("0xabc", types.SignerInfo{Address: "0xabc", Type: "keystore"})
	require.NoError(t, err)

	err = r.UnlockSigner("0xabc", nil)
	require.NoError(t, err)

	err = r.LockSigner("0xabc")
	require.NoError(t, err)
	assert.True(t, r.IsLocked("0xabc"))

	err = r.LockSigner("0xabc")
	assert.ErrorIs(t, err, types.ErrSignerLocked)

	err = r.LockSigner("0x999")
	assert.ErrorIs(t, err, types.ErrSignerNotFound)
}

func TestSignerRegistry_Close(t *testing.T) {
	r := NewEmptySignerRegistry()
	err := r.Close()
	require.NoError(t, err)
}


// delegation_convert.go -- DelegatePayloadToSignRequest edge cases

func TestNewDelegatePayloadToSignRequest_NilPayload(t *testing.T) {
	_, _, err := DelegatePayloadToSignRequest(bgCtx, nil, "")
	assert.ErrorContains(t, err, "delegation payload is nil")
}

func TestNewDelegatePayloadToSignRequest_MissingSigner(t *testing.T) {
	_, _, err := DelegatePayloadToSignRequest(bgCtx, map[string]interface{}{}, "")
	assert.ErrorContains(t, err, "delegation payload missing signer")
}

func TestDelegatePayloadToSignRequest_FromRuleInput(t *testing.T) {
	req, parsed, err := DelegatePayloadToSignRequest(bgCtx, &RuleInput{
		Signer:   "0xabc",
		ChainID:  1,
		SignType: "personal_sign",
		PersonalSign: &RuleInputPersonalSign{
			Message: "hello",
		},
	}, "")
	require.NoError(t, err)
	require.NotNil(t, req)
	require.NotNil(t, parsed)
	assert.Equal(t, "personal", req.SignType)
	assert.Equal(t, "0xabc", req.SignerAddress)
	assert.NotEmpty(t, req.Payload)
}

// password_provider.go

func TestEnvPasswordProvider_GetPassword_NoEnv(t *testing.T) {
	p, err := NewEnvPasswordProvider()
	require.NoError(t, err)

	_, err = p.GetPassword("0x1234", KeystoreConfig{PasswordEnv: ""})
	assert.ErrorContains(t, err, "password_env not configured")
}

func TestCompositePasswordProvider_GetPassword_EnvFallback(t *testing.T) {
	os.Setenv("TEST_COMPOSITE_PW", "composite_val")
	defer os.Unsetenv("TEST_COMPOSITE_PW")

	p, err := NewCompositePasswordProvider(false)
	require.NoError(t, err)

	pw, err := p.GetPassword("0x1234", KeystoreConfig{PasswordEnv: "TEST_COMPOSITE_PW"})
	require.NoError(t, err)
	assert.Equal(t, []byte("composite_val"), pw)
}

func TestCompositePasswordProvider_StdinNotConfigured(t *testing.T) {
	p, err := NewCompositePasswordProvider(false)
	require.NoError(t, err)

	_, err = p.GetPassword("0x1234", KeystoreConfig{PasswordStdin: true})
	assert.ErrorContains(t, err, "stdin password provider not initialized")
}

// provider_privatekey.go

func TestNewPrivateKeyProvider_NilRegistry(t *testing.T) {
	_, err := NewPrivateKeyProvider(nil, nil)
	assert.ErrorContains(t, err, "registry is required")
}

// provider_hdwallet.go -- appendUniqueUint32

func TestAppendUniqueUint32(t *testing.T) {
	got := appendUniqueUint32(nil, 5)
	assert.Equal(t, []uint32{5}, got)

	got = appendUniqueUint32([]uint32{1, 2, 3}, 2)
	assert.Equal(t, []uint32{1, 2, 3}, got)

	got = appendUniqueUint32([]uint32{1, 2, 3}, 4)
	assert.Equal(t, []uint32{1, 2, 3, 4}, got)
}

// solidity_batch_exec.go -- parseBatchTestOutput

func TestParseBatchTestOutput_Pass(t *testing.T) {
	e := &SolidityRuleEvaluator{}
	output := "\n[PASS] test_rule_0()\n[PASS] test_rule_1()\n"
	ruleIndices := map[int]int{0: 0, 1: 1}
	results := e.parseBatchTestOutput(output, ruleIndices)
	require.Len(t, results, 2)
	assert.True(t, results[0].passed)
	assert.True(t, results[1].passed)
}

func TestParseBatchTestOutput_Fail(t *testing.T) {
	e := &SolidityRuleEvaluator{}
	output := "\n[FAIL: not enough balance] test_rule_0()\n[PASS] test_rule_1()\n"
	ruleIndices := map[int]int{0: 0, 1: 1}
	results := e.parseBatchTestOutput(output, ruleIndices)
	require.Len(t, results, 2)
	assert.False(t, results[0].passed)
	assert.Equal(t, "not enough balance", results[0].reason)
	assert.True(t, results[1].passed)
}

func TestParseBatchTestOutput_Empty(t *testing.T) {
	e := &SolidityRuleEvaluator{}
	results := e.parseBatchTestOutput("no matches here", map[int]int{0: 0})
	assert.Empty(t, results)
}

// solidity_batch_exec.go -- generateBatchEvaluationScript

func TestGenerateBatchEvalScript_NoContexts(t *testing.T) {
	e := &SolidityRuleEvaluator{
		scriptCache:    make(map[string]string),
		executionCache: make(map[string]*executionResult),
	}
	_, _, err := e.generateBatchEvaluationScript(nil, &types.SignRequest{}, nil)
	assert.ErrorContains(t, err, "no applicable rules")
}

func TestGenerateBatchEvalScript_AllSkipped(t *testing.T) {
	e := &SolidityRuleEvaluator{
		scriptCache:    make(map[string]string),
		executionCache: make(map[string]*executionResult),
	}
	contexts := []*ruleEvalContext{
		{skipped: true},
		{skipped: true},
	}
	_, _, err := e.generateBatchEvaluationScript(contexts, &types.SignRequest{}, nil)
	assert.ErrorContains(t, err, "no applicable rules")
}

// internal_transfer_evaluator.go

func TestInternalTransferEvaluator_Evaluate_NotTransaction(t *testing.T) {
	e, err := NewInternalTransferEvaluator(nil)
	require.NoError(t, err)

	passed, reason, err := e.Evaluate(bgCtx, &types.Rule{}, &types.SignRequest{SignType: "typed_eip712"}, nil)
	require.NoError(t, err)
	assert.False(t, passed)
	assert.Empty(t, reason)
}

func TestInternalTransferEvaluator_Evaluate_NilParsed(t *testing.T) {
	e, err := NewInternalTransferEvaluator(nil)
	require.NoError(t, err)

	passed, reason, err := e.Evaluate(bgCtx, &types.Rule{}, &types.SignRequest{SignType: "transaction"}, nil)
	require.NoError(t, err)
	assert.False(t, passed)
	assert.Empty(t, reason)
}

func TestInternalTransferEvaluator_Evaluate_NilRecipient(t *testing.T) {
	e, err := NewInternalTransferEvaluator(nil)
	require.NoError(t, err)

	passed, reason, err := e.Evaluate(bgCtx, &types.Rule{}, &types.SignRequest{SignType: "transaction"}, &types.ParsedPayload{})
	require.NoError(t, err)
	assert.False(t, passed)
	assert.Empty(t, reason)
}

func TestInternalTransferEvaluator_Evaluate_InvalidConfig(t *testing.T) {
	e, err := NewInternalTransferEvaluator(nil)
	require.NoError(t, err)

	parsed := &types.ParsedPayload{Recipient: strPtr("0x123")}
	passed, reason, err := e.Evaluate(bgCtx, &types.Rule{Config: []byte("{invalid}"), Mode: types.RuleModeWhitelist},
		&types.SignRequest{SignType: "transaction"}, parsed)
	assert.Error(t, err)
	assert.False(t, passed)
	assert.Empty(t, reason)
}

func TestInternalTransferEvaluator_Evaluate_UnsupportedMatchMode(t *testing.T) {
	e, err := NewInternalTransferEvaluator(nil)
	require.NoError(t, err)

	parsed := &types.ParsedPayload{Recipient: strPtr("0x123")}
	passed, reason, err := e.Evaluate(bgCtx, &types.Rule{Config: []byte(`{"match_mode":"user_id"}`), Mode: types.RuleModeWhitelist},
		&types.SignRequest{SignType: "transaction"}, parsed)
	assert.ErrorContains(t, err, "unsupported match_mode")
	assert.False(t, passed)
	assert.Empty(t, reason)
}

func TestInternalTransferEvaluator_Evaluate_NilRepo(t *testing.T) {
	e, err := NewInternalTransferEvaluator(nil)
	require.NoError(t, err)

	parsed := &types.ParsedPayload{Recipient: strPtr("0x123")}
	passed, reason, err := e.Evaluate(bgCtx, &types.Rule{Config: []byte(`{"match_mode":"owner_id"}`), Mode: types.RuleModeWhitelist},
		&types.SignRequest{SignType: "transaction"}, parsed)
	assert.ErrorContains(t, err, "ownership repository not configured")
	assert.False(t, passed)
	assert.Empty(t, reason)
}

func TestInternalTransferEvaluator_Evaluate_EmptyCalldata(t *testing.T) {
	mockRepo := &mockSignerOwnershipRepo{}
	e, err := NewInternalTransferEvaluator(mockRepo)
	require.NoError(t, err)

	parsed := &types.ParsedPayload{Recipient: strPtr("0x123")}
	passed, reason, err := e.Evaluate(bgCtx, &types.Rule{Config: []byte(`{"match_mode":"owner_id"}`), Mode: types.RuleModeWhitelist},
		&types.SignRequest{SignType: "transaction", SignerAddress: "0xabc"}, parsed)
	require.NoError(t, err)
	assert.False(t, passed)
	assert.Empty(t, reason)
}

// Helpers

type mockSignerOwnershipRepo struct{}

func (m *mockSignerOwnershipRepo) GetBoth(_ context.Context, _, _ string) (*types.SignerOwnership, *types.SignerOwnership, error) {
	return nil, nil, nil
}
func (m *mockSignerOwnershipRepo) Upsert(_ context.Context, _ *types.SignerOwnership) error {
	return nil
}
func (m *mockSignerOwnershipRepo) Get(_ context.Context, _ string) (*types.SignerOwnership, error) {
	return nil, types.ErrNotFound
}
func (m *mockSignerOwnershipRepo) GetByOwner(_ context.Context, _ string) ([]*types.SignerOwnership, error) {
	return nil, nil
}
func (m *mockSignerOwnershipRepo) Delete(_ context.Context, _ string) error {
	return nil
}
func (m *mockSignerOwnershipRepo) UpdateOwner(_ context.Context, _, _ string) error {
	return nil
}
func (m *mockSignerOwnershipRepo) CountByOwner(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
func (m *mockSignerOwnershipRepo) CountByOwnerAndType(_ context.Context, _ string, _ types.SignerType) (int64, error) {
	return 0, nil
}
