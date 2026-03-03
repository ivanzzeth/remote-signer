//go:build e2e

package e2e

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

func TestRule_SolidityBlocklist_PassesForNormalAddress(t *testing.T) {
	if useExternalServer {
		t.Skip("Solidity blocklist rule is in config.e2e.yaml")
	}
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	to := common.HexToAddress(treasuryAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    103,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(100000000000000000),
		Data:     nil,
	})
	chainIDBig := big.NewInt(1)
	signedTx, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.NoError(t, err, "Solidity blocklist should pass for normal address (mirror rule test_cases)")
	require.NotNil(t, signedTx)
}

func TestRule_TransactionToBurnAddressBlocked(t *testing.T) {
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	to := common.HexToAddress(burnAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    101,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(100000000000000000),
		Data:     nil,
	})
	chainIDBig := big.NewInt(1)
	_, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.Error(t, err, "Transaction to burn address should be blocked by blocklist rule")
	var signErr *evm.SignError
	require.True(t, errors.As(err, &signErr), "expected SignError")
	require.Contains(t, signErr.Message, "blocked: burn address", "rejection reason should match rule test_cases expect_reason")
}

// Zero address from rules/security.example.yaml "Block malicious addresses" test_cases
const zeroAddress = "0x0000000000000000000000000000000000000000"

// TestSecurityExample_BlocklistBlocksZeroAddress mirrors rules/security.example.yaml
// test_cases "should block zero address" (expect_reason: "blocked: zero address").
// Creates the same blocklist rule via API so the test does not depend on config.
func TestSecurityExample_BlocklistBlocksZeroAddress(t *testing.T) {
	ctx := context.Background()
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:    "E2E Security Example - Block malicious addresses",
		Type:    "evm_solidity_expression",
		Mode:    "blocklist",
		Enabled: true,
		Config: map[string]interface{}{
			"expression": "require(to != 0x000000000000000000000000000000000000dEaD, \"blocked: burn address\");\nrequire(to != address(0), \"blocked: zero address\");",
		},
	})
	if err != nil {
		t.Skipf("CreateRule evm_solidity_expression failed (e.g. Foundry not available): %v", err)
	}
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	to := common.HexToAddress(zeroAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    102,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(100000000000000000),
		Data:     nil,
	})
	chainIDBig := big.NewInt(1)
	_, err = signer.SignTransactionWithChainID(tx, chainIDBig)
	require.Error(t, err, "transaction to zero address should be blocked (security.example equivalent)")
	var signErr *evm.SignError
	require.True(t, errors.As(err, &signErr), "expected SignError")
	require.Contains(t, signErr.Message, "blocked: zero address", "rejection reason should match security.example test_cases expect_reason")
}
