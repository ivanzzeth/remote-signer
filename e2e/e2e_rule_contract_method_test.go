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

func TestRule_ContractMethod_AllowsTransfer(t *testing.T) {
	snapshotRules(t)
	ctx := context.Background()
	chainType := "evm"
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:      "E2E ContractMethod Transfer",
		Type:      "evm_contract_method",
		Mode:      "whitelist",
		ChainType: &chainType,
		Config:    map[string]interface{}{"method_sigs": []string{"0xa9059cbb"}},
		Enabled:   true,
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	to := common.HexToAddress(treasuryAddress)
	transferCalldata := "0xa9059cbb" +
		"000000000000000000000000" + treasuryAddress[2:] +
		"0000000000000000000000000000000000000000000000000de0b6b3a7640000"
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    106,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(0),
		Data:     common.FromHex(transferCalldata),
	})
	chainIDBig := big.NewInt(1)
	signedTx, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.NoError(t, err, "evm_contract_method positive: tx with allowed selector should be allowed")
	require.NotNil(t, signedTx)
}

func TestRule_ContractMethod_BlocklistBlocksApproval(t *testing.T) {
	snapshotRules(t)
	ctx := context.Background()
	chainType := "evm"
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:      "E2E ContractMethod Blocklist",
		Type:      "evm_contract_method",
		Mode:      "blocklist",
		ChainType: &chainType,
		Config: map[string]interface{}{
			"contract":    treasuryAddress,
			"method_sigs": []string{"0x095ea7b3"},
		},
		Enabled: true,
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	to := common.HexToAddress(treasuryAddress)
	approveCalldata := "0x095ea7b3" +
		"000000000000000000000000" + treasuryAddress[2:] +
		"0000000000000000000000000000000000000000000000000de0b6b3a7640000"
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    107,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(0),
		Data:     common.FromHex(approveCalldata),
	})
	chainIDBig := big.NewInt(1)
	_, err = signer.SignTransactionWithChainID(tx, chainIDBig)
	require.Error(t, err, "evm_contract_method negative: blocklist rule should block approve tx")
}
