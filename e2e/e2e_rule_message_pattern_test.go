//go:build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
)

func TestRule_MessagePattern_AllowsMatching(t *testing.T) {
	ctx := context.Background()
	chainType := "evm"
	rule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:      "E2E MessagePattern Allow",
		Type:      "message_pattern",
		Mode:      "whitelist",
		ChainType: &chainType,
		Config: map[string]interface{}{
			"pattern":     "^E2E-msg-ok$",
			"sign_types": []string{"personal"},
		},
		Enabled: true,
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, rule.ID) }()
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)
	sig, err := signer.PersonalSign("E2E-msg-ok")
	require.NoError(t, err, "message_pattern positive: matching message should be allowed")
	assert.Len(t, sig, 65)
}

func TestRule_MessagePattern_RejectsMatchingBlocklist(t *testing.T) {
	ctx := context.Background()
	chainType := "evm"
	rule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:      "E2E MessagePattern Blocklist",
		Type:      "message_pattern",
		Mode:      "blocklist",
		ChainType: &chainType,
		Config: map[string]interface{}{
			"pattern":     "^E2E-block-msg$",
			"sign_types": []string{"personal"},
		},
		Enabled: true,
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, rule.ID) }()
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)
	_, err = signer.PersonalSign("E2E-block-msg")
	require.Error(t, err, "message_pattern negative: message matching blocklist pattern should be rejected")
}
