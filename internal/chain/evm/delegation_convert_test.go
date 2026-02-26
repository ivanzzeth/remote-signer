package evm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TestDelegatePayloadToSignRequest_PolymarketSplitShape ensures the converter output for the real
// Safe delegation payload (Polymarket split) has ChainID "137" and ChainType evm so that
// ruleScopeMatches(targetRule, req2) can match when target rule has chain_id 137.
func TestDelegatePayloadToSignRequest_PolymarketSplitShape(t *testing.T) {
	payload := map[string]interface{}{
		"sign_type": "transaction",
		"chain_id":  float64(137),
		"signer":    "0x88eD75e9eCE373997221E3c0229e74007C1AD718",
		"transaction": map[string]interface{}{
			"from":  "0x88eD75e9eCE373997221E3c0229e74007C1AD718",
			"to":    "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045",
			"value": "0x0",
			"data":  "0x72ce42750000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa84174",
		},
	}

	req2, _, err := DelegatePayloadToSignRequest(context.Background(), payload, "single")
	require.NoError(t, err)
	require.NotNil(t, req2)

	require.Equal(t, types.ChainTypeEVM, req2.ChainType, "ChainType must be evm for scope match")
	require.Equal(t, "137", req2.ChainID, "ChainID must be \"137\" for polymarket#transactions rule scope")
	require.Equal(t, "0x88eD75e9eCE373997221E3c0229e74007C1AD718", req2.SignerAddress)
}
