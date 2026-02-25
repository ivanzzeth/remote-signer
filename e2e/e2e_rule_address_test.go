//go:build e2e

package e2e

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
)

// Addresses from rules/treasury.example.yaml for equivalent e2e coverage
const treasuryExampleBackup = "0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2"

func TestRule_TransactionToTreasuryPasses(t *testing.T) {
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)
	to := common.HexToAddress(treasuryAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    100,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(100000000000000000),
		Data:     nil,
	})
	chainIDBig := big.NewInt(1)
	signedTx, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.NoError(t, err, "Transaction to treasury address should pass whitelist rule")
	require.NotNil(t, signedTx)
	v, r, s := signedTx.RawSignatureValues()
	assert.NotNil(t, v)
	assert.NotNil(t, r)
	assert.NotNil(t, s)
}

func TestRule_AddressWhitelist_RejectsNonListedAddress(t *testing.T) {
	if useExternalServer {
		t.Skip("evm_address_list and signer_restriction are from config.e2e.yaml")
	}
	secondSigner := common.HexToAddress(testSigner2Address)
	signer := adminClient.GetSigner(secondSigner, chainID)
	nonListedAddr := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	to := common.HexToAddress(nonListedAddr)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    105,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(0),
		Data:     nil,
	})
	chainIDBig := big.NewInt(1)
	_, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.Error(t, err, "evm_address_list negative: tx to non-listed address should not be allowed (no whitelist match)")
}

// TestTreasuryExample_AddressWhitelistAllowsListedAddresses mirrors rules/treasury.example.yaml
// "Allow transfers to treasury": evm_address_list whitelist with main + backup treasury.
func TestTreasuryExample_AddressWhitelistAllowsListedAddresses(t *testing.T) {
	ctx := context.Background()
	chainType := "evm"
	rule, err := adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name:      "E2E Treasury Example - Allow transfers to treasury",
		Type:      "evm_address_list",
		Mode:      "whitelist",
		ChainType: &chainType,
		Config: map[string]interface{}{
			"addresses": []string{treasuryAddress, treasuryExampleBackup},
		},
		Enabled: true,
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.DeleteRule(ctx, rule.ID) }()

	addr := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(addr, chainID)
	chainIDBig := big.NewInt(1)

	// Main treasury: should pass
	toMain := common.HexToAddress(treasuryAddress)
	txMain := types.NewTx(&types.LegacyTx{
		Nonce:    108, GasPrice: big.NewInt(20000000000), Gas: 21000,
		To: &toMain, Value: big.NewInt(100000000000000000), Data: nil,
	})
	signedMain, err := signer.SignTransactionWithChainID(txMain, chainIDBig)
	require.NoError(t, err, "tx to main treasury should pass (treasury.example equivalent)")
	require.NotNil(t, signedMain)

	// Backup treasury: should pass
	toBackup := common.HexToAddress(treasuryExampleBackup)
	txBackup := types.NewTx(&types.LegacyTx{
		Nonce:    109, GasPrice: big.NewInt(20000000000), Gas: 21000,
		To: &toBackup, Value: big.NewInt(100000000000000000), Data: nil,
	})
	signedBackup, err := signer.SignTransactionWithChainID(txBackup, chainIDBig)
	require.NoError(t, err, "tx to backup treasury should pass (treasury.example equivalent)")
	require.NotNil(t, signedBackup)
	// Non-listed address reject is covered by TestRule_AddressWhitelist_RejectsNonListedAddress;
	// here we only assert both listed addresses (main + backup treasury) pass.
}
