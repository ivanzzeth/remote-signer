package rule

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TestRuleScopeMatches_DelegationTarget_RealData reproduces the exact scenario that fails in production:
// Target rule polymarket#transactions (chain_id 137, chain_type evm); req2 is what the delegation
// converter produces from Safe buildPayload. We build req2 with the same shape the converter outputs
// (ChainID "137", ChainType evm) so we can verify ruleScopeMatches(rule, req2) without importing evm (cycle).
func TestRuleScopeMatches_DelegationTarget_RealData(t *testing.T) {
	// req2 shape produced by evm.DelegatePayloadToSignRequest for the Safe delegation payload
	// (chain_id 137, signer 0x88..., sign_type transaction). See delegation_convert.go.
	req2 := &types.SignRequest{
		ChainType:     types.ChainTypeEVM,
		ChainID:       "137",
		SignerAddress: "0x88eD75e9eCE373997221E3c0229e74007C1AD718",
		APIKeyID:      "",
	}

	// Target rule polymarket#transactions as stored in DB: chain_id 137, chain_type evm, no signer/api_key scope
	ct := types.ChainTypeEVM
	chainID := "137"
	rule := &types.Rule{
		ID:            "polymarket#transactions",
		ChainType:     &ct,
		ChainID:       &chainID,
		SignerAddress: nil,
	}

	got := ruleScopeMatches(rule, req2)
	if !got {
		// Report exact mismatch for root cause
		if rule.ChainType != nil && *rule.ChainType != req2.ChainType {
			t.Errorf("ChainType mismatch: rule=%q req=%q", string(*rule.ChainType), string(req2.ChainType))
		}
		if rule.ChainID != nil && *rule.ChainID != req2.ChainID {
			t.Errorf("ChainID mismatch: rule=%q (len=%d) req=%q (len=%d)",
				*rule.ChainID, len(*rule.ChainID), req2.ChainID, len(req2.ChainID))
		}
		if rule.Owner != "" && rule.Owner != req2.APIKeyID {
			t.Errorf("Owner mismatch: rule=%q req=%q", rule.Owner, req2.APIKeyID)
		}
		if rule.SignerAddress != nil && *rule.SignerAddress != req2.SignerAddress {
			t.Errorf("SignerAddress mismatch: rule=%q req=%q", *rule.SignerAddress, req2.SignerAddress)
		}
		t.Fatalf("ruleScopeMatches(rule, req2) = false; see above for first mismatch")
	}
}

// TestRuleScopeMatches_ConverterOutputShape ensures the evm converter produces req2 with
// ChainID/ChainType that match DB rule scope. Run from evm package: delegation_convert_test.go
// mirrors this so we don't have an import cycle; this test only documents expected shape.
func TestRuleScopeMatches_ExpectedReq2Shape(t *testing.T) {
	req2 := &types.SignRequest{
		ChainType: types.ChainTypeEVM,
		ChainID:   "137",
	}
	ct := types.ChainTypeEVM
	chainID := "137"
	rule := &types.Rule{ChainType: &ct, ChainID: &chainID}
	require.True(t, ruleScopeMatches(rule, req2), "canonical shape must match")
}

