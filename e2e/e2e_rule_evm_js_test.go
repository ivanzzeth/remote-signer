//go:build e2e

package e2e

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ivanzzeth/ethsig/eip712"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// TestRule_JSBlocklistBlocksBurnAddress verifies that an evm_js rule with mode blocklist
// blocks a transaction when the script returns invalid (e2e coverage for JS blocklist).
func TestRule_JSBlocklistBlocksBurnAddress(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()
	// Use zero address so we don't rely on the server's default burn-address blocklist
	blockedAddr := "0x0000000000000000000000000000000000000000"
	script := `function validate(input) {
	  if (input.transaction && input.transaction.to) {
	    var to = (input.transaction.to || "").toLowerCase();
	    if (to === "0x0000000000000000000000000000000000000000") return fail("blocked: zero address");
	  }
	  return ok();
	}`

	chainType := "evm"
	rule, err := adminClient.EVM.Rules.Create(ctx, &evm.CreateRuleRequest{
		Name:        "E2E JS Blocklist Zero Address",
		Description: "evm_js blocklist for e2e",
		Type:        "evm_js",
		Mode:        "blocklist",
		ChainType:   &chainType,
		Config: map[string]interface{}{
			"script": script,
		},
		Enabled: true,
	})
	require.NoError(t, err)
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, rule.ID) }()

	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	to := common.HexToAddress(blockedAddr)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    102,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(0),
		Data:     nil,
	})
	chainIDBig := big.NewInt(1)
	_, err = signer.SignTransactionWithChainID(tx, chainIDBig)
	require.Error(t, err, "Transaction to zero address should be blocked by evm_js blocklist rule")
}

func TestRule_SignRequestMatchesWhitelistRule(t *testing.T) {
	ensureGuardResumed(t)
	// With Example 8 (signer_restriction) and Example 9 (sign_type_restriction),
	// personal_sign is auto-approved for the test signer
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)

	sig, err := signer.PersonalSign("This should match the whitelist rule")
	require.NoError(t, err)
	assert.Len(t, sig, 65)
}

// TestRule_DelegationSinglePasses verifies config-file delegation: evm_js rule returns valid+payload,
// delegate_to in config points to target rule; engine delegates and target allows.
// config.e2e.yaml defines "Delegate Single" (script returns valid+payload) and "Delegate Target" (always allows).
func TestRule_DelegationSinglePasses(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("delegation e2e uses config.e2e.yaml rules (Delegate Single / Delegate Target)")
	}

	ctx := context.Background()

	// Optional: assert config has correct delegation target
	rulesResp, err := adminClient.EVM.Rules.List(ctx, &evm.ListRulesFilter{Limit: 1000})
	require.NoError(t, err)
	var targetID, delegateSingleID string
	for _, r := range rulesResp.Rules {
		if r.Name == "Delegate Target" {
			targetID = r.ID
		}
		if r.Name == "Delegate Single" {
			delegateSingleID = r.ID
		}
	}
	require.NotEmpty(t, targetID, "Delegate Target rule must exist in config")
	require.NotEmpty(t, delegateSingleID, "Delegate Single rule must exist in config")

	// Submit a transaction sign request: Delegate Single matches, returns valid+payload, delegate_to in config;
	// engine delegates to Delegate Target which allows.
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)

	to := common.HexToAddress(treasuryAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    300,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(0),
		Data:     nil,
	})
	chainIDBig := big.NewInt(1)
	signedTx, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.NoError(t, err, "Delegation chain (Delegate Single -> Delegate Target) should allow")
	require.NotNil(t, signedTx)

	v, r, s := signedTx.RawSignatureValues()
	assert.NotNil(t, v)
	assert.NotNil(t, r)
	assert.NotNil(t, s)

	_ = targetID // used only when asserting config
}

// TestRule_SafeMultisendERC20Chain verifies the full delegation chain Safe => Multisend => ERC20.
// Submits a SafeTx (typed_data) where the inner tx is to the multisend contract with one ERC20 transfer;
// Safe rule delegates to Multisend rule, which decodes the batch and delegates per_item to ERC20 rule.
func TestRule_SafeMultisendERC20Chain(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Safe=>Multisend=>ERC20 chain uses config.e2e.yaml instance rules")
	}

	// Addresses from config.e2e.yaml
	safeAddress := "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
	multisendAddress := "0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761"
	usdcAddress := "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
	recipient := "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"

	// Gnosis MultiSend packed: op(1) + to(20) + value(32) + dataLen(32) + data. One tx: CALL to USDC, transfer(recipient, 0)
	transferCalldata := "a9059cbb" + // transfer(address,uint256)
		strings.Repeat("0", 24) + strings.ToLower(recipient[2:]) + // address 32 bytes
		"0000000000000000000000000000000000000000000000000000000000000000"   // amount
	batch := "00" + // CALL
		strings.Repeat("0", 24) + strings.ToLower(usdcAddress[2:]) + // to 20 bytes
		"0000000000000000000000000000000000000000000000000000000000000000" + // value
		"0000000000000000000000000000000000000000000000000000000000000044" + // dataLen 68
		transferCalldata
	batchBytes := len(batch) / 2
	// ABI-encode multiSend(bytes): selector + offset(32) + length + raw bytes
	multiSendSelector := "8d80ff0a" // keccak256("multiSend(bytes)")[:4]
	encodedBytes := "0000000000000000000000000000000000000000000000000000000000000020" +
		fmt.Sprintf("%064x", batchBytes) + batch
	safeTxData := "0x" + multiSendSelector + encodedBytes

	typedData := eip712.TypedData{
		Types: eip712.Types{
			"EIP712Domain": {
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"SafeTx": {
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "data", Type: "bytes"},
				{Name: "operation", Type: "uint8"},
				{Name: "safeTxGas", Type: "uint256"},
				{Name: "baseGas", Type: "uint256"},
				{Name: "gasPrice", Type: "uint256"},
				{Name: "gasToken", Type: "address"},
				{Name: "refundReceiver", Type: "address"},
				{Name: "nonce", Type: "uint256"},
			},
		},
		PrimaryType: "SafeTx",
		Domain: eip712.TypedDataDomain{
			ChainId:           "1",
			VerifyingContract: safeAddress,
		},
		Message: map[string]interface{}{
			"to":               multisendAddress,
			"value":            "0",
			"data":             safeTxData,
			"operation":        "0",
			"safeTxGas":        "0",
			"baseGas":          "0",
			"gasPrice":         "0",
			"gasToken":         "0x0000000000000000000000000000000000000000",
			"refundReceiver":   "0x0000000000000000000000000000000000000000",
			"nonce":            "0",
		},
	}

	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	sig, err := signer.SignTypedData(typedData)
	require.NoError(t, err, "Safe=>Multisend=>ERC20 chain should allow and return signature")
	require.Len(t, sig, 65)
}

// TestRule_SafeMultisendMultiDelegate verifies Multisend with multiple delegation targets (ERC20, ERC721).
// Batch has two items: ERC20 transfer and ERC721 transferFrom; each item is validated by the matching rule (erc20 or erc721).
func TestRule_SafeMultisendMultiDelegate(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Safe=>Multisend=>(ERC20|ERC721) uses config.e2e.yaml instance rules")
	}

	safeAddress := "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
	multisendAddress := "0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761"
	usdcAddress := "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
	nftAddress := "0xBC4ca0EdA7647A8aB7C2061c2E118A18a936f13D"
	recipient := "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
	signerAddr := strings.ToLower(testSignerAddress[2:])

	// Item 1: CALL to USDC, transfer(recipient, 0)
	erc20Calldata := "a9059cbb" +
		strings.Repeat("0", 24) + strings.ToLower(recipient[2:]) +
		"0000000000000000000000000000000000000000000000000000000000000000"
	item1 := "00" +
		strings.Repeat("0", 24) + strings.ToLower(usdcAddress[2:]) +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000044" +
		erc20Calldata

	// Item 2: CALL to NFT, transferFrom(signer, recipient, tokenId=1)
	erc721Calldata := "23b872dd" +
		strings.Repeat("0", 24) + signerAddr +
		strings.Repeat("0", 24) + strings.ToLower(recipient[2:]) +
		"0000000000000000000000000000000000000000000000000000000000000001"
	item2 := "00" +
		strings.Repeat("0", 24) + strings.ToLower(nftAddress[2:]) +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000064" +
		erc721Calldata

	batch := item1 + item2
	batchBytes := len(batch) / 2
	multiSendSelector := "8d80ff0a"
	encodedBytes := "0000000000000000000000000000000000000000000000000000000000000020" +
		fmt.Sprintf("%064x", batchBytes) + batch
	safeTxData := "0x" + multiSendSelector + encodedBytes

	typedData := eip712.TypedData{
		Types: eip712.Types{
			"EIP712Domain": {
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"SafeTx": {
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "data", Type: "bytes"},
				{Name: "operation", Type: "uint8"},
				{Name: "safeTxGas", Type: "uint256"},
				{Name: "baseGas", Type: "uint256"},
				{Name: "gasPrice", Type: "uint256"},
				{Name: "gasToken", Type: "address"},
				{Name: "refundReceiver", Type: "address"},
				{Name: "nonce", Type: "uint256"},
			},
		},
		PrimaryType: "SafeTx",
		Domain: eip712.TypedDataDomain{
			ChainId:           "1",
			VerifyingContract: safeAddress,
		},
		Message: map[string]interface{}{
			"to":               multisendAddress,
			"value":            "0",
			"data":             safeTxData,
			"operation":        "0",
			"safeTxGas":        "0",
			"baseGas":          "0",
			"gasPrice":         "0",
			"gasToken":         "0x0000000000000000000000000000000000000000",
			"refundReceiver":   "0x0000000000000000000000000000000000000000",
			"nonce":            "0",
		},
	}

	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	sig, err := signer.SignTypedData(typedData)
	require.NoError(t, err, "Safe=>Multisend=>(ERC20|ERC721) multi-delegate should allow and return signature")
	require.Len(t, sig, 65)
}

// TestRule_PolymarketSafeChain verifies the combined Polymarket JS + Safe JS template chain (same effect as polymarket_safe.template.yaml).
// Submits a SafeTx (typed_data) on chain 137 with inner call USDC.e approve(CTF Exchange, max);
// Safe rule (safe-polymarket) delegates to polymarket-transactions which validates the Polymarket calls.
func TestRule_PolymarketSafeChain(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Polymarket Safe chain uses config.e2e.yaml instance rules (Polymarket + Safe Polymarket)")
	}

	// Addresses from config.e2e.yaml Polymarket / Safe Polymarket instances (Polygon)
	const polygonChainID = "137"
	safeAddress := "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837"
	usdcAddress := "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"
	ctfExchangeAddress := "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E"
	// approve(spender=CTF Exchange, amount=max uint256)
	approveCalldata := "095ea7b3" +
		strings.Repeat("0", 24) + strings.ToLower(ctfExchangeAddress[2:]) +
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	typedData := eip712.TypedData{
		Types: eip712.Types{
			"EIP712Domain": {
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"SafeTx": {
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "data", Type: "bytes"},
				{Name: "operation", Type: "uint8"},
				{Name: "safeTxGas", Type: "uint256"},
				{Name: "baseGas", Type: "uint256"},
				{Name: "gasPrice", Type: "uint256"},
				{Name: "gasToken", Type: "address"},
				{Name: "refundReceiver", Type: "address"},
				{Name: "nonce", Type: "uint256"},
			},
		},
		PrimaryType: "SafeTx",
		Domain: eip712.TypedDataDomain{
			ChainId:           polygonChainID,
			VerifyingContract: safeAddress,
		},
		Message: map[string]interface{}{
			"to":               usdcAddress,
			"value":            "0",
			"data":             "0x" + approveCalldata,
			"operation":        "0",
			"safeTxGas":        "0",
			"baseGas":          "0",
			"gasPrice":         "0",
			"gasToken":         "0x0000000000000000000000000000000000000000",
			"refundReceiver":   "0x0000000000000000000000000000000000000000",
			"nonce":            "0",
		},
	}

	address := common.HexToAddress(testSignerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, polygonChainID)
	sig, err := signer.SignTypedData(typedData)
	require.NoError(t, err, "Polymarket Safe chain (SafeTx => polymarket-transactions) should allow and return signature")
	require.Len(t, sig, 65)
}

// TestRule_PolymarketSafeChain_CTFSetApprovalForAll mirrors polymarket_safe.template.yaml test case:
// "should pass SafeTx with CTF setApprovalForAll to Exchange (real tx 0x4f1356ad)".
func TestRule_PolymarketSafeChain_CTFSetApprovalForAll(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Polymarket Safe chain uses config.e2e.yaml instance rules")
	}

	const polygonChainID = "137"
	safeAddress := "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837"
	ctfAddress := "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045"
	ctfExchangeAddress := "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E"
	setApprovalCalldata := "a22cb465" +
		strings.Repeat("0", 24) + strings.ToLower(ctfExchangeAddress[2:]) +
		"0000000000000000000000000000000000000000000000000000000000000001"

	typedData := eip712.TypedData{
		Types: eip712.Types{
			"EIP712Domain": {
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"SafeTx": {
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "data", Type: "bytes"},
				{Name: "operation", Type: "uint8"},
				{Name: "safeTxGas", Type: "uint256"},
				{Name: "baseGas", Type: "uint256"},
				{Name: "gasPrice", Type: "uint256"},
				{Name: "gasToken", Type: "address"},
				{Name: "refundReceiver", Type: "address"},
				{Name: "nonce", Type: "uint256"},
			},
		},
		PrimaryType: "SafeTx",
		Domain: eip712.TypedDataDomain{
			ChainId:           polygonChainID,
			VerifyingContract: safeAddress,
		},
		Message: map[string]interface{}{
			"to":               ctfAddress,
			"value":            "0",
			"data":             "0x" + setApprovalCalldata,
			"operation":        "0",
			"safeTxGas":        "0",
			"baseGas":          "0",
			"gasPrice":         "0",
			"gasToken":         "0x0000000000000000000000000000000000000000",
			"refundReceiver":   "0x0000000000000000000000000000000000000000",
			"nonce":            "0",
		},
	}

	address := common.HexToAddress(testSignerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, polygonChainID)
	sig, err := signer.SignTypedData(typedData)
	require.NoError(t, err, "SafeTx with CTF setApprovalForAll(Exchange, true) should pass")
	require.Len(t, sig, 65)
}

// TestRule_PolymarketSafeChain_RejectDelegateCall mirrors polymarket_safe.template.yaml test case:
// "should reject SafeTx with DELEGATECALL".
func TestRule_PolymarketSafeChain_RejectDelegateCall(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Polymarket Safe chain uses config.e2e.yaml instance rules")
	}
	const polygonChainID = "137"
	safeAddress := "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837"
	usdcAddress := "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"
	ctfExchangeAddress := "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E"
	approveCalldata := "095ea7b3" +
		strings.Repeat("0", 24) + strings.ToLower(ctfExchangeAddress[2:]) +
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	typedData := eip712.TypedData{
		Types: eip712.Types{
			"EIP712Domain": {
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"SafeTx": {
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "data", Type: "bytes"},
				{Name: "operation", Type: "uint8"},
				{Name: "safeTxGas", Type: "uint256"},
				{Name: "baseGas", Type: "uint256"},
				{Name: "gasPrice", Type: "uint256"},
				{Name: "gasToken", Type: "address"},
				{Name: "refundReceiver", Type: "address"},
				{Name: "nonce", Type: "uint256"},
			},
		},
		PrimaryType: "SafeTx",
		Domain: eip712.TypedDataDomain{
			ChainId:           polygonChainID,
			VerifyingContract: safeAddress,
		},
		Message: map[string]interface{}{
			"to":               usdcAddress,
			"value":            "0",
			"data":             "0x" + approveCalldata,
			"operation":        "1", // DELEGATECALL: must be rejected
			"safeTxGas":        "0",
			"baseGas":          "0",
			"gasPrice":         "0",
			"gasToken":         "0x0000000000000000000000000000000000000000",
			"refundReceiver":   "0x0000000000000000000000000000000000000000",
			"nonce":            "0",
		},
	}

	address := common.HexToAddress(testSignerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, polygonChainID)
	_, err := signer.SignTypedData(typedData)
	require.Error(t, err)
	var signErr *evm.SignError
	require.True(t, errors.As(err, &signErr), "expected SignError")
	require.Contains(t, signErr.Message, "only CALL", "rejection reason should mention only CALL")
}

// TestRule_PolymarketSafeChain_CTFRedeemPositions mirrors polymarket_safe.template.yaml complex case:
// "should pass SafeTx with CTF redeemPositions (real tx 0x714b3d)" — Polygon tx, inner redeemPositions(USDC.e, 0x0, conditionId, [1,2]).
func TestRule_PolymarketSafeChain_CTFRedeemPositions(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Polymarket Safe chain uses config.e2e.yaml instance rules")
	}

	const polygonChainID = "137"
	safeAddress := "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837"
	ctfAddress := "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045"
	// redeemPositions(address,bytes32,bytes32,uint256[]) — collateralToken=USDC.e, parentCollectionId=0x0, conditionId=0xbd42fb9a..., indexSets=[1,2]
	// From polymarket_safe.template.yaml test case "should pass SafeTx with CTF redeemPositions (real tx 0x714b3d)"
	redeemPositionsData := "0x01b7037c0000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa841740000000000000000000000000000000000000000000000000000000000000000bd42fb9ac3870c35193d69ca1ad5ea00363d8ee6aba80b910a2003c370597cae0000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"

	typedData := eip712.TypedData{
		Types: eip712.Types{
			"EIP712Domain": {
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"SafeTx": {
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "data", Type: "bytes"},
				{Name: "operation", Type: "uint8"},
				{Name: "safeTxGas", Type: "uint256"},
				{Name: "baseGas", Type: "uint256"},
				{Name: "gasPrice", Type: "uint256"},
				{Name: "gasToken", Type: "address"},
				{Name: "refundReceiver", Type: "address"},
				{Name: "nonce", Type: "uint256"},
			},
		},
		PrimaryType: "SafeTx",
		Domain: eip712.TypedDataDomain{
			ChainId:           polygonChainID,
			VerifyingContract: safeAddress,
		},
		Message: map[string]interface{}{
			"to":               ctfAddress,
			"value":            "0",
			"data":             redeemPositionsData,
			"operation":        "0",
			"safeTxGas":        "217890",
			"baseGas":          "0",
			"gasPrice":         "0",
			"gasToken":         "0x0000000000000000000000000000000000000000",
			"refundReceiver":   "0x0000000000000000000000000000000000000000",
			"nonce":            "0",
		},
	}

	address := common.HexToAddress(testSignerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, polygonChainID)
	sig, err := signer.SignTypedData(typedData)
	require.NoError(t, err, "SafeTx with CTF redeemPositions (real tx 0x714b3d) should pass")
	require.Len(t, sig, 65)
}

// TestRule_PolymarketSafeChain_ExecTransactionCTFRedeemPositions mirrors polymarket_safe.template.yaml complex case:
// "should pass execTransaction with real CTF redeemPositions (real tx 0x714b3d)" — raw tx to Safe with execTransaction(CTF, 0, redeemPositions(...), ...).
func TestRule_PolymarketSafeChain_ExecTransactionCTFRedeemPositions(t *testing.T) {
	ensureGuardResumed(t)
	if useExternalServer {
		t.Skip("Polymarket Safe chain uses config.e2e.yaml instance rules")
	}

	const polygonChainID = "137"
	safeAddress := "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837"
	// execTransaction(CTF, 0, redeemPositions(USDC.e,0x0,conditionId,[1,2]), 0, 217890, 0, 0, 0x0, 0x0, sig) — from YAML "should pass execTransaction with real CTF redeemPositions (real tx 0x714b3d)"
	execTxDataHex := "0x6a7612020000000000000000000000004d97dcd97ec945f40cf65f87097ace5ea047604500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000353220000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000000e401b7037c0000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa841740000000000000000000000000000000000000000000000000000000000000000bd42fb9ac3870c35193d69ca1ad5ea00363d8ee6aba80b910a2003c370597cae0000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041afaaa7d5183bb28c20af45dc009544b9358e971c25e8335261debdc43b756b3b1cd75457fc9d60ae0b7bd2e45deaf93aa80446f41061424a4d0f46712449e02b1b00000000000000000000000000000000000000000000000000000000000000"

	execTxData, err := hex.DecodeString(strings.TrimPrefix(execTxDataHex, "0x"))
	require.NoError(t, err)

	safe := common.HexToAddress(safeAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(0),
		Gas:      300000,
		To:       &safe,
		Value:    big.NewInt(0),
		Data:     execTxData,
	})

	chainIDBig := big.NewInt(137)
	address := common.HexToAddress(testSignerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, polygonChainID)
	_, err = signer.SignTransactionWithChainID(tx, chainIDBig)
	require.NoError(t, err, "execTransaction with real CTF redeemPositions (real tx 0x714b3d) should pass")
}
