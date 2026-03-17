//go:build e2e

package e2e

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

func TestRule_ValueLimitWhitelist_AllowsUnderLimit(t *testing.T) {
	snapshotRules(t)
	if useExternalServer {
		t.Skip("Value limit rule is in config.e2e.yaml")
	}
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	to := common.HexToAddress(treasuryAddress)
	fiveEth := new(big.Int).Mul(big.NewInt(5), big.NewInt(1e18))
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    104,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    fiveEth,
		Data:     nil,
	})
	chainIDBig := big.NewInt(1)
	signedTx, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.NoError(t, err, "Value limit whitelist should allow tx under 10 ETH")
	require.NotNil(t, signedTx)
}

func TestRule_ValueLimitRuleBlocks(t *testing.T) {
	snapshotRules(t)
	ctx := context.Background()
	createReq := &evm.CreateRuleRequest{
		Name:    "Test Value Limit - Block High Value",
		Type:    "evm_value_limit",
		Mode:    "blocklist",
		Enabled: true,
		Config:  map[string]interface{}{"max_value": "100000000000000000"},
	}
	created, err := adminClient.EVM.Rules.Create(ctx, createReq)
	require.NoError(t, err)
	t.Cleanup(func() { _ = adminClient.EVM.Rules.Delete(context.Background(), created.ID) })
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	to := common.HexToAddress(treasuryAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    10,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(1000000000000000000),
		Data:     nil,
	})
	chainIDBig := big.NewInt(1)
	_, err = signer.SignTransactionWithChainID(tx, chainIDBig)
	require.Error(t, err, "Transaction exceeding value limit should be blocked")
}

// 100 ETH in wei, from rules/treasury.example.yaml "Treasury transfer limit"
const treasuryExampleMaxValueWei = "100000000000000000000"

// TestTreasuryExample_ValueLimitAllowsUnder100ETH mirrors rules/treasury.example.yaml
// "Treasury transfer limit": evm_value_limit whitelist max 100 ETH; allow when value <= max.
func TestTreasuryExample_ValueLimitAllowsUnder100ETH(t *testing.T) {
	snapshotRules(t)
	ctx := context.Background()
	chainType := "evm"
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:      "E2E Treasury Example - Treasury transfer limit",
		Type:      "evm_value_limit",
		Mode:      "whitelist",
		ChainType: &chainType,
		Config:    map[string]interface{}{"max_value": treasuryExampleMaxValueWei},
		Enabled:   true,
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	addr := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, addr, chainID)
	to := common.HexToAddress(treasuryAddress)
	// 50 ETH, under 100 ETH limit
	fiftyEth := new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18))
	tx := types.NewTx(&types.LegacyTx{
		Nonce: 111, GasPrice: big.NewInt(20000000000), Gas: 21000,
		To: &to, Value: fiftyEth, Data: nil,
	})
	signedTx, err := signer.SignTransactionWithChainID(tx, big.NewInt(1))
	require.NoError(t, err, "tx with 50 ETH should pass (treasury.example value limit equivalent)")
	require.NotNil(t, signedTx)
}

// TestTreasuryExample_ValueLimitBlocksOver100ETH mirrors rules/treasury.example.yaml:
// use a blocklist rule so that value > 100 ETH is explicitly blocked (same policy as "allow only when value <= 100").
func TestTreasuryExample_ValueLimitBlocksOver100ETH(t *testing.T) {
	snapshotRules(t)
	ctx := context.Background()
	chainType := "evm"
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:      "E2E Treasury Example - Block value over 100 ETH",
		Type:      "evm_value_limit",
		Mode:      "blocklist",
		ChainType: &chainType,
		Config:    map[string]interface{}{"max_value": treasuryExampleMaxValueWei},
		Enabled:   true,
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	addr := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, addr, chainID)
	to := common.HexToAddress(treasuryAddress)
	// 101 ETH, over 100 ETH -> blocklist should block
	overLimit := new(big.Int).Mul(big.NewInt(101), big.NewInt(1e18))
	tx := types.NewTx(&types.LegacyTx{
		Nonce: 112, GasPrice: big.NewInt(20000000000), Gas: 21000,
		To: &to, Value: overLimit, Data: nil,
	})
	_, err = signer.SignTransactionWithChainID(tx, big.NewInt(1))
	require.Error(t, err, "tx with 101 ETH should be blocked (treasury.example value limit equivalent)")
}
