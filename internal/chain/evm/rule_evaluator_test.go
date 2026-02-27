package evm

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─────────────────────────────────────────────────────────────────────────────
// AddressListEvaluator
// ─────────────────────────────────────────────────────────────────────────────

func TestAddressListEvaluator_Type(t *testing.T) {
	e, err := NewAddressListEvaluator()
	require.NoError(t, err)
	assert.Equal(t, types.RuleTypeEVMAddressList, e.Type())
}

func TestAddressListEvaluator_Evaluate(t *testing.T) {
	e, _ := NewAddressListEvaluator()
	ctx := context.Background()

	addr1 := "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
	addr2 := "0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2"
	nonListAddr := "0x0000000000000000000000000000000000000001"

	cfg, _ := json.Marshal(AddressListConfig{Addresses: []string{addr1, addr2}})

	tests := []struct {
		name        string
		mode        types.RuleMode
		recipient   *string
		wantMatched bool
		wantReason  string
	}{
		{"whitelist match", types.RuleModeWhitelist, &addr1, true, "recipient " + addr1 + " in whitelist"},
		{"whitelist no match", types.RuleModeWhitelist, &nonListAddr, false, ""},
		{"blocklist match", types.RuleModeBlocklist, &addr1, true, "recipient " + addr1 + " in blocklist"},
		{"blocklist no match", types.RuleModeBlocklist, &nonListAddr, false, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &types.Rule{Mode: tc.mode, Config: cfg}
			parsed := &types.ParsedPayload{Recipient: tc.recipient}
			matched, reason, err := e.Evaluate(ctx, r, &types.SignRequest{}, parsed)
			require.NoError(t, err)
			assert.Equal(t, tc.wantMatched, matched)
			if tc.wantReason != "" {
				assert.Contains(t, reason, tc.wantReason)
			}
		})
	}
}

func TestAddressListEvaluator_CaseInsensitive(t *testing.T) {
	e, _ := NewAddressListEvaluator()
	ctx := context.Background()

	addrLower := "0x5b38da6a701c568545dcfcb03fcb875f56beddc4"
	addrUpper := "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"

	cfg, _ := json.Marshal(AddressListConfig{Addresses: []string{addrUpper}})
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: cfg}
	parsed := &types.ParsedPayload{Recipient: &addrLower}

	matched, _, err := e.Evaluate(ctx, r, &types.SignRequest{}, parsed)
	require.NoError(t, err)
	assert.True(t, matched, "should match case-insensitively")
}

func TestAddressListEvaluator_NilParsed(t *testing.T) {
	e, _ := NewAddressListEvaluator()
	ctx := context.Background()
	cfg, _ := json.Marshal(AddressListConfig{Addresses: []string{"0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"}})
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: cfg}

	// nil parsed
	matched, _, err := e.Evaluate(ctx, r, &types.SignRequest{}, nil)
	require.NoError(t, err)
	assert.False(t, matched)

	// nil recipient
	matched, _, err = e.Evaluate(ctx, r, &types.SignRequest{}, &types.ParsedPayload{Recipient: nil})
	require.NoError(t, err)
	assert.False(t, matched)
}

func TestAddressListEvaluator_InvalidConfig(t *testing.T) {
	e, _ := NewAddressListEvaluator()
	ctx := context.Background()
	addr := "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: []byte(`{invalid`)}
	parsed := &types.ParsedPayload{Recipient: &addr}

	_, _, err := e.Evaluate(ctx, r, &types.SignRequest{}, parsed)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid address list config")
}

// ─────────────────────────────────────────────────────────────────────────────
// ContractMethodEvaluator
// ─────────────────────────────────────────────────────────────────────────────

func TestContractMethodEvaluator_Type(t *testing.T) {
	e, err := NewContractMethodEvaluator()
	require.NoError(t, err)
	assert.Equal(t, types.RuleTypeEVMContractMethod, e.Type())
}

func TestContractMethodEvaluator_Evaluate(t *testing.T) {
	e, _ := NewContractMethodEvaluator()
	ctx := context.Background()

	contract := "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
	method := "0xa9059cbb"
	otherMethod := "0x095ea7b3"
	otherContract := "0x0000000000000000000000000000000000000001"

	cfg, _ := json.Marshal(ContractMethodConfig{
		Contract:   contract,
		MethodSigs: []string{method},
	})

	tests := []struct {
		name        string
		contract    *string
		methodSig   *string
		wantMatched bool
	}{
		{"match contract+method", &contract, &method, true},
		{"wrong method", &contract, &otherMethod, false},
		{"wrong contract", &otherContract, &method, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &types.Rule{Mode: types.RuleModeWhitelist, Config: cfg}
			parsed := &types.ParsedPayload{Contract: tc.contract, MethodSig: tc.methodSig}
			matched, _, err := e.Evaluate(ctx, r, &types.SignRequest{}, parsed)
			require.NoError(t, err)
			assert.Equal(t, tc.wantMatched, matched)
		})
	}
}

func TestContractMethodEvaluator_CaseInsensitive(t *testing.T) {
	e, _ := NewContractMethodEvaluator()
	ctx := context.Background()

	contractUpper := "0xA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48"
	contractLower := "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
	method := "0xa9059cbb"
	methodUpper := "0xA9059CBB"

	cfg, _ := json.Marshal(ContractMethodConfig{
		Contract:   contractUpper,
		MethodSigs: []string{method},
	})
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: cfg}

	// Lower contract should match upper
	parsed := &types.ParsedPayload{Contract: &contractLower, MethodSig: &methodUpper}
	matched, _, err := e.Evaluate(ctx, r, &types.SignRequest{}, parsed)
	require.NoError(t, err)
	assert.True(t, matched, "should match case-insensitively")
}

func TestContractMethodEvaluator_NilParsed(t *testing.T) {
	e, _ := NewContractMethodEvaluator()
	ctx := context.Background()
	cfg, _ := json.Marshal(ContractMethodConfig{Contract: "0xabc", MethodSigs: []string{"0x12345678"}})
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: cfg}

	// nil parsed
	matched, _, err := e.Evaluate(ctx, r, &types.SignRequest{}, nil)
	require.NoError(t, err)
	assert.False(t, matched)

	// nil contract
	method := "0x12345678"
	matched, _, err = e.Evaluate(ctx, r, &types.SignRequest{}, &types.ParsedPayload{Contract: nil, MethodSig: &method})
	require.NoError(t, err)
	assert.False(t, matched)

	// nil method
	contract := "0xabc"
	matched, _, err = e.Evaluate(ctx, r, &types.SignRequest{}, &types.ParsedPayload{Contract: &contract, MethodSig: nil})
	require.NoError(t, err)
	assert.False(t, matched)
}

func TestContractMethodEvaluator_InvalidConfig(t *testing.T) {
	e, _ := NewContractMethodEvaluator()
	ctx := context.Background()
	contract := "0xabc"
	method := "0x12345678"
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: []byte(`not json`)}
	parsed := &types.ParsedPayload{Contract: &contract, MethodSig: &method}

	_, _, err := e.Evaluate(ctx, r, &types.SignRequest{}, parsed)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid contract method config")
}

func TestContractMethodEvaluator_MultipleMethodSigs(t *testing.T) {
	e, _ := NewContractMethodEvaluator()
	ctx := context.Background()

	contract := "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
	transferSel := "0xa9059cbb"
	approveSel := "0x095ea7b3"
	unknownSel := "0x06fdde03"

	cfg, _ := json.Marshal(ContractMethodConfig{
		Contract:   contract,
		MethodSigs: []string{transferSel, approveSel},
	})
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: cfg}

	// transfer matches
	parsed := &types.ParsedPayload{Contract: &contract, MethodSig: &transferSel}
	matched, _, err := e.Evaluate(ctx, r, &types.SignRequest{}, parsed)
	require.NoError(t, err)
	assert.True(t, matched)

	// approve matches
	parsed = &types.ParsedPayload{Contract: &contract, MethodSig: &approveSel}
	matched, _, err = e.Evaluate(ctx, r, &types.SignRequest{}, parsed)
	require.NoError(t, err)
	assert.True(t, matched)

	// unknown doesn't match
	parsed = &types.ParsedPayload{Contract: &contract, MethodSig: &unknownSel}
	matched, _, err = e.Evaluate(ctx, r, &types.SignRequest{}, parsed)
	require.NoError(t, err)
	assert.False(t, matched)
}

// ─────────────────────────────────────────────────────────────────────────────
// ValueLimitEvaluator
// ─────────────────────────────────────────────────────────────────────────────

func TestValueLimitEvaluator_Type(t *testing.T) {
	e, err := NewValueLimitEvaluator()
	require.NoError(t, err)
	assert.Equal(t, types.RuleTypeEVMValueLimit, e.Type())
}

func TestValueLimitEvaluator_Whitelist(t *testing.T) {
	e, _ := NewValueLimitEvaluator()
	ctx := context.Background()

	cfg, _ := json.Marshal(ValueLimitConfig{MaxValue: "1000000000000000000"}) // 1 ETH

	tests := []struct {
		name        string
		value       string
		wantMatched bool
	}{
		{"within limit", "500000000000000000", true},      // 0.5 ETH
		{"exactly at limit", "1000000000000000000", true},  // 1 ETH
		{"exceeds limit", "2000000000000000000", false},    // 2 ETH
		{"zero value", "0", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &types.Rule{Mode: types.RuleModeWhitelist, Config: cfg}
			v := tc.value
			parsed := &types.ParsedPayload{Value: &v}
			matched, _, err := e.Evaluate(ctx, r, &types.SignRequest{}, parsed)
			require.NoError(t, err)
			assert.Equal(t, tc.wantMatched, matched)
		})
	}
}

func TestValueLimitEvaluator_Blocklist(t *testing.T) {
	e, _ := NewValueLimitEvaluator()
	ctx := context.Background()

	cfg, _ := json.Marshal(ValueLimitConfig{MaxValue: "1000000000000000000"}) // 1 ETH

	tests := []struct {
		name        string
		value       string
		wantMatched bool // true = violation (should block)
	}{
		{"within limit - no violation", "500000000000000000", false},
		{"exactly at limit - no violation", "1000000000000000000", false},
		{"exceeds limit - violation", "2000000000000000000", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &types.Rule{Mode: types.RuleModeBlocklist, Config: cfg}
			v := tc.value
			parsed := &types.ParsedPayload{Value: &v}
			matched, reason, err := e.Evaluate(ctx, r, &types.SignRequest{}, parsed)
			require.NoError(t, err)
			assert.Equal(t, tc.wantMatched, matched)
			if tc.wantMatched {
				assert.Contains(t, reason, "exceeds limit")
			}
		})
	}
}

func TestValueLimitEvaluator_NilParsed(t *testing.T) {
	e, _ := NewValueLimitEvaluator()
	ctx := context.Background()
	cfg, _ := json.Marshal(ValueLimitConfig{MaxValue: "1000000000000000000"})
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: cfg}

	// nil parsed
	matched, _, err := e.Evaluate(ctx, r, &types.SignRequest{}, nil)
	require.NoError(t, err)
	assert.False(t, matched)

	// nil value
	matched, _, err = e.Evaluate(ctx, r, &types.SignRequest{}, &types.ParsedPayload{Value: nil})
	require.NoError(t, err)
	assert.False(t, matched)
}

func TestValueLimitEvaluator_InvalidConfig(t *testing.T) {
	e, _ := NewValueLimitEvaluator()
	ctx := context.Background()
	v := "100"
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: []byte(`{bad json`)}
	parsed := &types.ParsedPayload{Value: &v}

	_, _, err := e.Evaluate(ctx, r, &types.SignRequest{}, parsed)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid value limit config")
}

func TestValueLimitEvaluator_InvalidMaxValue(t *testing.T) {
	e, _ := NewValueLimitEvaluator()
	ctx := context.Background()
	v := "100"
	cfg, _ := json.Marshal(ValueLimitConfig{MaxValue: "not_a_number"})
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: cfg}
	parsed := &types.ParsedPayload{Value: &v}

	_, _, err := e.Evaluate(ctx, r, &types.SignRequest{}, parsed)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid max_value")
}

func TestValueLimitEvaluator_InvalidTxValue(t *testing.T) {
	e, _ := NewValueLimitEvaluator()
	ctx := context.Background()
	v := "not_a_number"
	cfg, _ := json.Marshal(ValueLimitConfig{MaxValue: "1000"})
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: cfg}
	parsed := &types.ParsedPayload{Value: &v}

	_, _, err := e.Evaluate(ctx, r, &types.SignRequest{}, parsed)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid transaction value")
}

// ─────────────────────────────────────────────────────────────────────────────
// SignerRestrictionEvaluator
// ─────────────────────────────────────────────────────────────────────────────

func TestSignerRestrictionEvaluator_Type(t *testing.T) {
	e, err := NewSignerRestrictionEvaluator()
	require.NoError(t, err)
	assert.Equal(t, types.RuleTypeSignerRestriction, e.Type())
}

func TestSignerRestrictionEvaluator_Evaluate(t *testing.T) {
	e, _ := NewSignerRestrictionEvaluator()
	ctx := context.Background()

	allowed1 := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	allowed2 := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
	disallowed := "0x0000000000000000000000000000000000000001"

	cfg, _ := json.Marshal(SignerRestrictionConfig{AllowedSigners: []string{allowed1, allowed2}})
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: cfg}

	tests := []struct {
		name        string
		signer      string
		wantMatched bool
	}{
		{"allowed signer 1", allowed1, true},
		{"allowed signer 2", allowed2, true},
		{"disallowed signer", disallowed, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &types.SignRequest{SignerAddress: tc.signer}
			matched, _, err := e.Evaluate(ctx, r, req, nil)
			require.NoError(t, err)
			assert.Equal(t, tc.wantMatched, matched)
		})
	}
}

func TestSignerRestrictionEvaluator_CaseInsensitive(t *testing.T) {
	e, _ := NewSignerRestrictionEvaluator()
	ctx := context.Background()

	allowedMixed := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	cfg, _ := json.Marshal(SignerRestrictionConfig{AllowedSigners: []string{allowedMixed}})
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: cfg}

	// request with lowercase
	req := &types.SignRequest{SignerAddress: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"}
	matched, _, err := e.Evaluate(ctx, r, req, nil)
	require.NoError(t, err)
	assert.True(t, matched, "should match case-insensitively")
}

func TestSignerRestrictionEvaluator_InvalidConfig(t *testing.T) {
	e, _ := NewSignerRestrictionEvaluator()
	ctx := context.Background()
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: []byte(`{invalid`)}
	req := &types.SignRequest{SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"}

	_, _, err := e.Evaluate(ctx, r, req, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signer restriction config")
}

func TestSignerRestrictionEvaluator_EmptyAllowList(t *testing.T) {
	e, _ := NewSignerRestrictionEvaluator()
	ctx := context.Background()
	cfg, _ := json.Marshal(SignerRestrictionConfig{AllowedSigners: []string{}})
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: cfg}
	req := &types.SignRequest{SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"}

	matched, _, err := e.Evaluate(ctx, r, req, nil)
	require.NoError(t, err)
	assert.False(t, matched, "empty allow list should match nothing")
}

// ─────────────────────────────────────────────────────────────────────────────
// SignTypeRestrictionEvaluator
// ─────────────────────────────────────────────────────────────────────────────

func TestSignTypeRestrictionEvaluator_Type(t *testing.T) {
	e, err := NewSignTypeRestrictionEvaluator()
	require.NoError(t, err)
	assert.Equal(t, types.RuleTypeSignTypeRestriction, e.Type())
}

func TestSignTypeRestrictionEvaluator_Evaluate(t *testing.T) {
	e, _ := NewSignTypeRestrictionEvaluator()
	ctx := context.Background()

	cfg, _ := json.Marshal(SignTypeRestrictionConfig{AllowedSignTypes: []string{"transaction", "typed_data"}})
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: cfg}

	tests := []struct {
		name        string
		signType    string
		wantMatched bool
	}{
		{"allowed transaction", "transaction", true},
		{"allowed typed_data", "typed_data", true},
		{"disallowed personal", "personal", false},
		{"disallowed hash", "hash", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &types.SignRequest{SignType: tc.signType}
			matched, _, err := e.Evaluate(ctx, r, req, nil)
			require.NoError(t, err)
			assert.Equal(t, tc.wantMatched, matched)
		})
	}
}

func TestSignTypeRestrictionEvaluator_CaseInsensitive(t *testing.T) {
	e, _ := NewSignTypeRestrictionEvaluator()
	ctx := context.Background()

	cfg, _ := json.Marshal(SignTypeRestrictionConfig{AllowedSignTypes: []string{"Transaction"}})
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: cfg}

	req := &types.SignRequest{SignType: "transaction"}
	matched, _, err := e.Evaluate(ctx, r, req, nil)
	require.NoError(t, err)
	assert.True(t, matched, "should match case-insensitively")
}

func TestSignTypeRestrictionEvaluator_InvalidConfig(t *testing.T) {
	e, _ := NewSignTypeRestrictionEvaluator()
	ctx := context.Background()
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: []byte(`{invalid json`)}
	req := &types.SignRequest{SignType: "transaction"}

	_, _, err := e.Evaluate(ctx, r, req, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid sign type restriction config")
}

func TestSignTypeRestrictionEvaluator_EmptyAllowList(t *testing.T) {
	e, _ := NewSignTypeRestrictionEvaluator()
	ctx := context.Background()
	cfg, _ := json.Marshal(SignTypeRestrictionConfig{AllowedSignTypes: []string{}})
	r := &types.Rule{Mode: types.RuleModeWhitelist, Config: cfg}
	req := &types.SignRequest{SignType: "transaction"}

	matched, _, err := e.Evaluate(ctx, r, req, nil)
	require.NoError(t, err)
	assert.False(t, matched, "empty allow list should match nothing")
}
