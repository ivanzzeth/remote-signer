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

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

func TestRule_SignTypeRestrictionAllowsPersonalSign(t *testing.T) {
	snapshotRules(t)
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	sig, err := signer.PersonalSign("Test sign type restriction allows personal_sign")
	require.NoError(t, err, "Sign type restriction should allow personal_sign")
	assert.Len(t, sig, 65)
}

func TestRule_SignTypeRestrictionAllowsTransaction(t *testing.T) {
	snapshotRules(t)
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	to := common.HexToAddress(treasuryAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    102,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(100000000000000000),
		Data:     nil,
	})
	chainIDBig := big.NewInt(1)
	signedTx, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.NoError(t, err, "Sign type restriction should allow transaction signing")
	require.NotNil(t, signedTx)
}

func TestRule_SignTypeRestrictionAllowsHashSign(t *testing.T) {
	snapshotRules(t)
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	hash := common.HexToHash("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	sig, err := signer.SignHash(hash)
	require.NoError(t, err, "Sign type restriction should allow hash signing")
	assert.Len(t, sig, 65)
}

func TestRule_CreateSignTypeRestrictionViaAPI(t *testing.T) {
	snapshotRules(t)
	ctx := context.Background()
	createReq := &evm.CreateRuleRequest{
		Name:    "Test Sign Type Restriction via API",
		Type:    "sign_type_restriction",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"allowed_sign_types": []string{"personal", "transaction"}},
	}
	created, err := adminClient.EVM.Rules.Create(ctx, createReq)
	require.NoError(t, err)
	t.Cleanup(func() { _ = adminClient.EVM.Rules.Delete(context.Background(), created.ID) })
	assert.Equal(t, "sign_type_restriction", string(created.Type))
	assert.Equal(t, "whitelist", string(created.Mode))
}

// TestSecurityExample_SignTypeAllowsPersonalTypedDataTransaction mirrors rules/security.example.yaml
// "Allowed signing methods": personal, typed_data, transaction are allowed. We assert personal and
// transaction pass; hash is not in the example whitelist but config.e2e may allow it, so we do not assert hash rejected.
func TestSecurityExample_SignTypeAllowsPersonalTypedDataTransaction(t *testing.T) {
	snapshotRules(t)
	ctx := context.Background()
	createReq := &evm.CreateRuleRequest{
		Name:    "E2E Security Example - Allowed signing methods",
		Type:    "sign_type_restriction",
		Mode:    "whitelist",
		Enabled: true,
		Config:  map[string]interface{}{"allowed_sign_types": []string{"personal", "typed_data", "transaction"}},
	}
	created, err := adminClient.EVM.Rules.Create(ctx, createReq)
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, created.ID) }()

	addr := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, addr, chainID)

	// personal: allowed by security.example
	_, err = signer.PersonalSign("security.example equivalent")
	require.NoError(t, err)
	// transaction: allowed by security.example
	to := common.HexToAddress(treasuryAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce: 113, GasPrice: big.NewInt(20000000000), Gas: 21000,
		To: &to, Value: big.NewInt(0), Data: nil,
	})
	_, err = signer.SignTransactionWithChainID(tx, big.NewInt(1))
	require.NoError(t, err)
}

func TestRule_SignTypeRestrictionBlocksDisallowedType(t *testing.T) {
	snapshotRules(t)
	ctx := context.Background()
	createReq := &evm.CreateRuleRequest{
		Name:    "Test Sign Type Blocklist - Only Transaction",
		Type:    "sign_type_restriction",
		Mode:    "blocklist",
		Enabled: true,
		Config:  map[string]interface{}{"allowed_sign_types": []string{"personal"}},
	}
	created, err := adminClient.EVM.Rules.Create(ctx, createReq)
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, created.ID) }()
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	_, err = signer.PersonalSign("This should be blocked")
	require.Error(t, err, "Personal sign should be blocked by sign_type_restriction blocklist")
}
