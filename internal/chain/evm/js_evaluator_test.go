package evm

import (
	"context"
	"encoding/json"
	"log/slog"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestJSRuleEvaluator_Type(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)
	assert.Equal(t, types.RuleTypeEVMJS, e.Type())
}

func TestJSRuleEvaluator_AppliesToSignType_CommaSeparated(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)
	config := mustMarshalJSON(map[string]string{"sign_type_filter": "typed_data,transaction"})
	rule := &types.Rule{ID: "safe", Type: types.RuleTypeEVMJS, Config: config}
	assert.True(t, e.AppliesToSignType(rule, "typed_data"), "typed_data should match")
	assert.True(t, e.AppliesToSignType(rule, "transaction"), "transaction should match")
	assert.False(t, e.AppliesToSignType(rule, "personal"), "personal should not match")
	assert.False(t, e.AppliesToSignType(rule, "hash"), "hash should not match")
}

func TestJSRuleEvaluator_wrappedValidate_Minimal(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)
	script := `function validate(i){ return { valid: true }; }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, nil)
	assert.True(t, res.Valid, "expected valid=true, got reason=%s", res.Reason)
}

func TestJSRuleEvaluator_Evaluate_WhitelistPass(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	script := `function validate(i){ return { valid: true }; }`
	config := mustMarshalJSON(map[string]string{"script": script})
	rule := &types.Rule{
		ID:     "test-js-1",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: config,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"1000000000000000000","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	parsed := &types.ParsedPayload{
		Recipient: strPtrForRuleInput("0x742d35cc6634c0532925a3b844bc454e4438f44e"),
		Value:     strPtrForRuleInput("1000000000000000000"),
	}

	// Build same RuleInput as Evaluate would; run wrappedValidate to isolate script_error
	ruleInput, err := BuildRuleInput(req, parsed)
	require.NoError(t, err)
	res := e.wrappedValidate(script, ruleInput, nil, nil)
	require.True(t, res.Valid, "wrappedValidate with full RuleInput should pass: reason=%s", res.Reason)

	matched, reason, err := e.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err, "reason: %s", reason)
	assert.True(t, matched, "expected whitelist match: reason=%s", reason)
	assert.Empty(t, reason)
}

func mustMarshalJSON(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// TestPolymarketV2_TemplateTestCases verifies the Polymarket V2 CLOB Order EIP-712
// signature validation script using inline scenarios adapted from the YAML template.
// It tests rs.addr.toChecksumList, domain validation, maker whitelist enforcement,
// and signer matching — the core security logic for Polymarket V2 orders.
func TestPolymarketV2_TemplateTestCases(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	// JS script from rules/templates/evm/polymarket_v2.yaml — polymarket-v2-order-signature rule.
	// Note: ValidateWithInput passes config as a Go map, which Sobek wraps as a JS object.
	// Object keys are reachable via dot notation (config.allowed_safe_addresses).
	script := `function validate(input) {
		var ctx = rs.typedData.require(input, 'Order');
		var domain = ctx.domain || {};
		var msg = ctx.message || {};
		var allowedContracts = [config.exchange_v2_address, config.neg_risk_exchange_v2_address];
		rs.typedData.requireDomain(domain, {
			name: config.v2_exchange_domain_name,
			version: config.v2_exchange_domain_version,
			chainId: parseInt(config.chain_id, 10),
			allowedContracts: allowedContracts
		});
		require(String(msg.signer || '').trim() !== '', 'missing signer');
		var safeStr = String(config.allowed_safe_addresses);
		rs.addr.requireInList((msg.maker || '').trim(), rs.addr.toChecksumList(safeStr), 'maker must be allowed Safe address');
		rs.typedData.requireSignerMatch((msg.signer || '').trim(), (input.signer || '').trim(), 'order signer must match signing key');
		return ok();
	}`

	// Config values matching the template's test_variables.
	config := map[string]interface{}{
		"exchange_v2_address":            "0xE111180000d2663C0091e4f400237545B87B996B",
		"neg_risk_exchange_v2_address":   "0xe2222d279d744050d28e00520010520000310F59",
		"collateral_token_address":       "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB",
		"conditional_tokens_address":     "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045",
		"ctf_collateral_adapter_address": "0xADa100874d00e3331D00F2007a9c336a65009718",
		"neg_risk_ctf_collateral_adapter_address": "0xAdA200001000ef00D07553cEE7006808F895c6F1",
		"collateral_onramp_address":             "0x93070a847efEf7F70739046A929D47a521F5B8ee",
		"collateral_offramp_address":            "0x2957922Eb93258b93368531d39fAcCA3B4dC5854",
		"usdc_address":                          "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
		"usdc_bridged_address":                  "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
		"neg_risk_adapter_address":              "0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296",
		"allowed_safe_addresses":                "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837",
		"allowed_safe_address_for_testing":      "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837",
		"chain_id":                              "137",
		"v2_exchange_domain_name":               "Polymarket CTF Exchange",
		"v2_exchange_domain_version":            "2",
	}

	exchangeV2 := "0xE111180000d2663C0091e4f400237545B87B996B"
	negRiskExchangeV2 := "0xe2222d279d744050d28e00520010520000310F59"
	safeAddress := "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837"

	tests := []struct {
		name          string
		input         *RuleInput
		expectPass    bool
		expectReason  string
	}{
		{
			name: "valid Order with ExchangeV2",
			input: &RuleInput{
				SignType: "typed_data",
				ChainID:  137,
				Signer:   safeAddress,
				TypedData: &RuleInputTypedData{
					PrimaryType: "Order",
					Domain: TypedDataDomain{
						Name:              "Polymarket CTF Exchange",
						Version:           "2",
						ChainId:           "137",
						VerifyingContract: exchangeV2,
					},
					Message: map[string]interface{}{
						"salt":          "12345",
						"maker":         safeAddress,
						"signer":        safeAddress,
						"tokenId":       "1",
						"makerAmount":   "1000000000000000000",
						"takerAmount":   "1000000000000000000",
						"side":          "0",
						"signatureType": "0",
						"timestamp":     "1704067200",
						"metadata":      "0x0000000000000000000000000000000000000000000000000000000000000000",
						"builder":       "0x0000000000000000000000000000000000000000000000000000000000000000",
						"expiration":    "1893456000",
					},
				},
			},
			expectPass: true,
		},
		{
			name: "valid Order with NegRiskExchangeV2",
			input: &RuleInput{
				SignType: "typed_data",
				ChainID:  137,
				Signer:   safeAddress,
				TypedData: &RuleInputTypedData{
					PrimaryType: "Order",
					Domain: TypedDataDomain{
						Name:              "Polymarket CTF Exchange",
						Version:           "2",
						ChainId:           "137",
						VerifyingContract: negRiskExchangeV2,
					},
					Message: map[string]interface{}{
						"salt":          "12345",
						"maker":         safeAddress,
						"signer":        safeAddress,
						"tokenId":       "1",
						"makerAmount":   "1000000000000000000",
						"takerAmount":   "1000000000000000000",
						"side":          "0",
						"signatureType": "0",
						"timestamp":     "1704067200",
						"metadata":      "0x0000000000000000000000000000000000000000000000000000000000000000",
						"builder":       "0x0000000000000000000000000000000000000000000000000000000000000000",
						"expiration":    "1893456000",
					},
				},
			},
			expectPass: true,
		},
		{
			name: "reject wrong domain version",
			input: &RuleInput{
				SignType: "typed_data",
				ChainID:  137,
				Signer:   safeAddress,
				TypedData: &RuleInputTypedData{
					PrimaryType: "Order",
					Domain: TypedDataDomain{
						Name:              "Polymarket CTF Exchange",
						Version:           "1", // wrong version
						ChainId:           "137",
						VerifyingContract: exchangeV2,
					},
					Message: map[string]interface{}{
						"salt":          "12345",
						"maker":         safeAddress,
						"signer":        safeAddress,
						"tokenId":       "1",
						"makerAmount":   "1000000000000000000",
						"takerAmount":   "1000000000000000000",
						"side":          "0",
						"signatureType": "0",
						"timestamp":     "1704067200",
						"metadata":      "0x0000000000000000000000000000000000000000000000000000000000000000",
						"builder":       "0x0000000000000000000000000000000000000000000000000000000000000000",
						"expiration":    "1893456000",
					},
				},
			},
			expectPass:   false,
			expectReason: "invalid domain version",
		},
		{
			name: "reject maker not in whitelist",
			input: &RuleInput{
				SignType: "typed_data",
				ChainID:  137,
				Signer:   safeAddress,
				TypedData: &RuleInputTypedData{
					PrimaryType: "Order",
					Domain: TypedDataDomain{
						Name:              "Polymarket CTF Exchange",
						Version:           "2",
						ChainId:           "137",
						VerifyingContract: exchangeV2,
					},
					Message: map[string]interface{}{
						"salt":          "12345",
						"maker":         "0xDEADDEADDEADDEADDEADDEADDEADDEADDEADDEAD",
						"signer":        safeAddress,
						"tokenId":       "1",
						"makerAmount":   "1000000000000000000",
						"takerAmount":   "1000000000000000000",
						"side":          "0",
						"signatureType": "0",
						"timestamp":     "1704067200",
						"metadata":      "0x0000000000000000000000000000000000000000000000000000000000000000",
						"builder":       "0x0000000000000000000000000000000000000000000000000000000000000000",
						"expiration":    "1893456000",
					},
				},
			},
			expectPass:   false,
			expectReason: "maker must be allowed Safe address",
		},
		{
			name: "reject signer mismatch",
			input: &RuleInput{
				SignType: "typed_data",
				ChainID:  137,
				Signer:   safeAddress,
				TypedData: &RuleInputTypedData{
					PrimaryType: "Order",
					Domain: TypedDataDomain{
						Name:              "Polymarket CTF Exchange",
						Version:           "2",
						ChainId:           "137",
						VerifyingContract: exchangeV2,
					},
					Message: map[string]interface{}{
						"salt":          "12345",
						"maker":         safeAddress,
						"signer":        "0x1111111111111111111111111111111111111111",
						"tokenId":       "1",
						"makerAmount":   "1000000000000000000",
						"takerAmount":   "1000000000000000000",
						"side":          "0",
						"signatureType": "0",
						"timestamp":     "1704067200",
						"metadata":      "0x0000000000000000000000000000000000000000000000000000000000000000",
						"builder":       "0x0000000000000000000000000000000000000000000000000000000000000000",
						"expiration":    "1893456000",
					},
				},
			},
			expectPass:   false,
			expectReason: "order signer must match signing key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := e.ValidateWithInput(script, tc.input, config)
			if tc.expectPass {
				assert.True(t, res.Valid, "expected pass, got reason=%s", res.Reason)
			} else {
				assert.False(t, res.Valid, "expected fail")
				if tc.expectReason != "" {
					assert.Contains(t, res.Reason, tc.expectReason)
				}
			}
		})
	}
}

// TestAddrToChecksumList_Direct verifies that rs.addr.toChecksumList works correctly
// from within the JS sandbox, converting both arrays and comma-separated strings
// into checksummed address lists. This is the core helper used by Polymarket V2
// and other templates that accept comma-delimited address config values.
func TestAddrToChecksumList_Direct(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	tests := []struct {
		name   string
		script string
	}{
		{
			name: "comma-separated string to checksum list",
			script: `function validate(i) {
				var list = rs.addr.toChecksumList("0x742d35cc6634c0532925a3b844bc454e4438f44e,0x1111111111111111111111111111111111111111");
				if (list.length !== 2) return fail("expected 2 addresses, got " + list.length);
				if (list[0] !== "0x742d35Cc6634C0532925a3b844Bc454e4438f44e") return fail("first addr checksum wrong: " + list[0]);
				if (list[1] !== "0x1111111111111111111111111111111111111111") return fail("second addr checksum wrong: " + list[1]);
				return ok();
			}`,
		},
		{
			name: "JS array to checksum list",
			script: `function validate(i) {
				var list = rs.addr.toChecksumList(["0x742d35cc6634c0532925a3b844bc454e4438f44e", "0x1111111111111111111111111111111111111111"]);
				if (list.length !== 2) return fail("expected 2 addresses, got " + list.length);
				if (list[0] !== "0x742d35Cc6634C0532925a3b844Bc454e4438f44e") return fail("first addr checksum wrong: " + list[0]);
				return ok();
			}`,
		},
		{
			name: "empty config string produces empty list",
			script: `function validate(i) {
				var list = rs.addr.toChecksumList("");
				if (list.length !== 0) return fail("expected empty list, got " + list.length);
				return ok();
			}`,
		},
		{
			name: "single address string",
			script: `function validate(i) {
				var list = rs.addr.toChecksumList("0x742d35cc6634c0532925a3b844bc454e4438f44e");
				if (list.length !== 1) return fail("expected 1 address, got " + list.length);
				if (list[0] !== "0x742d35Cc6634C0532925a3b844Bc454e4438f44e") return fail("checksum wrong: " + list[0]);
				return ok();
			}`,
		},
	}

	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := e.wrappedValidate(tc.script, input, nil, nil)
			assert.True(t, res.Valid, "reason=%s", res.Reason)
		})
	}
}

func TestPolymarketV2_TransactionTestCases(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	// JS script from rules/templates/evm/polymarket_v2.yaml — polymarket-v2-transactions rule.
	script := `function validate(input) {
		require(input.sign_type === 'transaction', 'sign_type must be transaction');
		var tx = input.transaction;
		require(tx && tx.to, 'missing transaction or to');
		var toAddr = (tx.to || '').trim();
		var data = (tx.data || '0x').replace(/^0x/, '');
		if (data.length < 8) {
			revert('missing function selector');
		}
		var calldata = rs.tx.getCalldata(tx);
		require(calldata.valid, 'calldata too short');
		var sel = calldata.selector.toLowerCase();
		var approveSel = '0x095ea7b3';
		var setApprovalSel = '0xa22cb465';
		var splitSel = '0x72ce4275';
		var mergeSel = '0x9e7212ad';
		var redeemSel = '0x01b7037c';
		var wrapSel = '0xe9b44a0c';
		var unwrapSel = '0x095b3356';
		var pUSD = toChecksum(config.collateral_token_address);
		var ctf = toChecksum(config.conditional_tokens_address);
		var ctfAdapter = toChecksum(config.ctf_collateral_adapter_address);
		var negCtfAdapter = toChecksum(config.neg_risk_ctf_collateral_adapter_address);
		var onramp = toChecksum(config.collateral_onramp_address);
		var offramp = toChecksum(config.collateral_offramp_address);
		var usdc = toChecksum(config.usdc_address);
		var usdce = toChecksum(config.usdc_bridged_address);
		var exchangeV2 = toChecksum(config.exchange_v2_address);
		var negExchangeV2 = toChecksum(config.neg_risk_exchange_v2_address);
		var negAdapter = toChecksum(config.neg_risk_adapter_address);
		if (eq(toAddr, pUSD)) {
			require(sel === approveSel, 'unsupported pUSD operation');
			require(data.length >= 8 + 64 + 64, 'invalid approve data length');
			var dec = abi.decode(calldata.payloadHex, ['address', 'uint256']);
			require(dec && dec.length >= 1, 'approve decode failed');
			var allowedSpenders = [exchangeV2, negExchangeV2, negAdapter, ctfAdapter, negCtfAdapter, offramp];
			rs.addr.requireInList(dec[0], allowedSpenders, 'spender must be allowed V2 protocol contract');
			return ok();
		}
		if (eq(toAddr, ctf)) {
			if (sel === setApprovalSel) {
				require(data.length >= 8 + 64 + 64, 'invalid setApprovalForAll data length');
				var d = abi.decode(calldata.payloadHex, ['address', 'bool']);
				require(d && d.length >= 2 && d[1], 'approval must be true');
				var allowedOps = [exchangeV2, negExchangeV2, ctfAdapter, negCtfAdapter];
				rs.addr.requireInList(d[0], allowedOps, 'operator must be allowed V2 protocol contract');
				return ok();
			}
			if (sel === splitSel || sel === mergeSel || sel === redeemSel) {
				return ok();
			}
			revert('unsupported CTF operation');
		}
		if (eq(toAddr, ctfAdapter)) {
			require(sel === splitSel || sel === mergeSel || sel === redeemSel, 'unsupported CtfCollateralAdapter operation');
			if (sel === splitSel || sel === mergeSel) {
				require(data.length >= 8 + 164 * 2, 'invalid split/merge data length');
				var dec2 = abi.decode(calldata.payloadHex, ['address', 'bytes32', 'bytes32', 'uint256[]', 'uint256']);
				require(dec2 && dec2.length >= 2, 'split/merge decode failed');
				require(rs.addr.inList(toChecksum(dec2[0]), [pUSD]), 'collateral must be pUSD');
				return ok();
			}
			if (sel === redeemSel) {
				require(data.length >= 8 + 132 * 2, 'invalid redeem data length');
				var dec3 = abi.decode(calldata.payloadHex, ['address', 'bytes32', 'bytes32', 'uint256[]']);
				require(dec3 && dec3.length >= 1, 'redeem decode failed');
				require(rs.addr.inList(toChecksum(dec3[0]), [pUSD]), 'collateral must be pUSD');
				return ok();
			}
		}
		if (eq(toAddr, negCtfAdapter)) {
			require(sel === splitSel || sel === mergeSel || sel === redeemSel, 'unsupported NegRiskCtfCollateralAdapter operation');
			if (sel === splitSel || sel === mergeSel) {
				require(data.length >= 8 + 164 * 2, 'invalid split/merge data length');
				var dec4 = abi.decode(calldata.payloadHex, ['address', 'bytes32', 'bytes32', 'uint256[]', 'uint256']);
				require(dec4 && dec4.length >= 2, 'split/merge decode failed');
				require(rs.addr.inList(toChecksum(dec4[0]), [pUSD]), 'collateral must be pUSD');
				return ok();
			}
			if (sel === redeemSel) {
				require(data.length >= 8 + 132 * 2, 'invalid redeem data length');
				var dec5 = abi.decode(calldata.payloadHex, ['address', 'bytes32', 'bytes32', 'uint256[]']);
				require(dec5 && dec5.length >= 1, 'redeem decode failed');
				require(rs.addr.inList(toChecksum(dec5[0]), [pUSD]), 'collateral must be pUSD');
				return ok();
			}
		}
		if (eq(toAddr, onramp)) {
			require(sel === wrapSel, 'unsupported onramp operation');
			require(data.length >= 8 + 64 * 3, 'invalid wrap data length');
			var wrapDec = abi.decode(calldata.payloadHex, ['address', 'address', 'uint256']);
			require(wrapDec && wrapDec.length >= 1, 'wrap decode failed');
			var allowedAssets = [usdc, usdce];
			rs.addr.requireInList(wrapDec[0], allowedAssets, 'wrap asset must be USDC or USDC.e');
			return ok();
		}
		if (eq(toAddr, offramp)) {
			require(sel === unwrapSel, 'unsupported offramp operation');
			require(data.length >= 8 + 64 * 3, 'invalid unwrap data length');
			var unwrapDec = abi.decode(calldata.payloadHex, ['address', 'address', 'uint256']);
			require(unwrapDec && unwrapDec.length >= 1, 'unwrap decode failed');
			require(rs.addr.inList(toChecksum(unwrapDec[0]), [usdc, usdce]), 'unwrap asset must be USDC or USDC.e');
			return ok();
		}
		if (eq(toAddr, usdce) || eq(toAddr, usdc)) {
			require(sel === approveSel, 'unsupported USDC/USDC.e operation');
			require(data.length >= 8 + 64 + 64, 'invalid approve data length');
			var usdcDec = abi.decode(calldata.payloadHex, ['address', 'uint256']);
			require(usdcDec && usdcDec.length >= 1, 'approve decode failed');
			require(eq(toChecksum(usdcDec[0]), onramp), 'approve spender must be CollateralOnramp');
			return ok();
		}
		revert('unsupported target contract');
	}`

	config := map[string]interface{}{
		"exchange_v2_address":            "0xE111180000d2663C0091e4f400237545B87B996B",
		"neg_risk_exchange_v2_address":   "0xe2222d279d744050d28e00520010520000310F59",
		"collateral_token_address":       "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB",
		"conditional_tokens_address":     "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045",
		"ctf_collateral_adapter_address": "0xADa100874d00e3331D00F2007a9c336a65009718",
		"neg_risk_ctf_collateral_adapter_address": "0xAdA200001000ef00D07553cEE7006808F895c6F1",
		"collateral_onramp_address":             "0x93070a847efEf7F70739046A929D47a521F5B8ee",
		"collateral_offramp_address":            "0x2957922Eb93258b93368531d39fAcCA3B4dC5854",
		"usdc_address":                          "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
		"usdc_bridged_address":                  "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
		"neg_risk_adapter_address":              "0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296",
		"allowed_safe_addresses":                "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837",
		"allowed_safe_address_for_testing":      "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837",
		"chain_id":                        "137",
		"v2_exchange_domain_name":         "Polymarket CTF Exchange",
		"v2_exchange_domain_version":      "2",
	}

	pUSD := "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB"
	ctf := "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045"
	exchangeV2 := "0xE111180000d2663C0091e4f400237545B87B996B"
	negRiskExchangeV2 := "0xe2222d279d744050d28e00520010520000310F59"
	negAdapter := "0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296"
	ctfAdapter := "0xADa100874d00e3331D00F2007a9c336a65009718"
	negCtfAdapter := "0xAdA200001000ef00D07553cEE7006808F895c6F1"
	offramp := "0x2957922Eb93258b93368531d39fAcCA3B4dC5854"
	onramp := "0x93070a847efEf7F70739046A929D47a521F5B8ee"
	usdc := "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"
	usdce := "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"
	safeAddress := "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837"
	dead := "0xDEADDEADDEADDEADDEADDEADDEADDEADDEADDEAD"

	// Helper to build approve calldata: approve(spender, amount)
	approveData := func(spender string) string {
		spenderPadded := "000000000000000000000000" + spender[2:]
		amount := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		return "0x095ea7b3" + spenderPadded + amount
	}

	// Helper: setApprovalForAll(operator, approved)
	setApprovalData := func(operator string, approved bool) string {
		opPadded := "000000000000000000000000" + operator[2:]
		approvedHex := "0000000000000000000000000000000000000000000000000000000000000000"
		if approved {
			approvedHex = "0000000000000000000000000000000000000000000000000000000000000001"
		}
		return "0xa22cb465" + opPadded + approvedHex
	}

	// Helper: wrap(asset, recipient, amount)
	wrapData := func(asset string) string {
		assetPadded := "000000000000000000000000" + asset[2:]
		recipientPadded := "000000000000000000000000" + safeAddress[2:]
		amount := "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
		return "0xe9b44a0c" + assetPadded + recipientPadded + amount
	}

	// Helper: unwrap(asset, recipient, amount)
	unwrapData := func(asset string) string {
		assetPadded := "000000000000000000000000" + asset[2:]
		recipientPadded := "000000000000000000000000" + safeAddress[2:]
		amount := "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
		return "0x095b3356" + assetPadded + recipientPadded + amount
	}

	tests := []struct {
		name         string
		input        *RuleInput
		expectPass   bool
		expectReason string
	}{
		{
			name: "pUSD approve to ExchangeV2",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   pUSD,
					Data: approveData(exchangeV2),
				},
			},
			expectPass: true,
		},
		{
			name: "pUSD approve to NegRiskExchangeV2",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   pUSD,
					Data: approveData(negRiskExchangeV2),
				},
			},
			expectPass: true,
		},
		{
			name: "pUSD approve to NegRiskAdapter",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   pUSD,
					Data: approveData(negAdapter),
				},
			},
			expectPass: true,
		},
		{
			name: "pUSD approve to CtfCollateralAdapter",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   pUSD,
					Data: approveData(ctfAdapter),
				},
			},
			expectPass: true,
		},
		{
			name: "pUSD approve to NegRiskCtfCollateralAdapter",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   pUSD,
					Data: approveData(negCtfAdapter),
				},
			},
			expectPass: true,
		},
		{
			name: "pUSD approve to CollateralOfframp",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   pUSD,
					Data: approveData(offramp),
				},
			},
			expectPass: true,
		},
		{
			name: "pUSD approve to disallowed spender",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   pUSD,
					Data: approveData(dead),
				},
			},
			expectPass:   false,
			expectReason: "spender must be allowed V2 protocol contract",
		},
		{
			name: "CTF setApprovalForAll to ExchangeV2",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   ctf,
					Data: setApprovalData(exchangeV2, true),
				},
			},
			expectPass: true,
		},
		{
			name: "CTF setApprovalForAll to NegRiskExchangeV2",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   ctf,
					Data: setApprovalData(negRiskExchangeV2, true),
				},
			},
			expectPass: true,
		},
		{
			name: "CTF setApprovalForAll to disallowed operator",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   ctf,
					Data: setApprovalData(dead, true),
				},
			},
			expectPass:   false,
			expectReason: "operator must be allowed V2 protocol contract",
		},
		{
			name: "CTF setApprovalForAll with approved=false",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   ctf,
					Data: setApprovalData(exchangeV2, false),
				},
			},
			expectPass:   false,
			expectReason: "approval must be true",
		},
		{
			name: "CollateralOnramp wrap with USDC",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   onramp,
					Data: wrapData(usdc),
				},
			},
			expectPass: true,
		},
		{
			name: "CollateralOnramp wrap with USDC.e",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   onramp,
					Data: wrapData(usdce),
				},
			},
			expectPass: true,
		},
		{
			name: "CollateralOnramp wrap with disallowed asset",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   onramp,
					Data: wrapData(pUSD),
				},
			},
			expectPass:   false,
			expectReason: "wrap asset must be USDC or USDC.e",
		},
		{
			name: "CollateralOfframp unwrap with USDC",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   offramp,
					Data: unwrapData(usdc),
				},
			},
			expectPass: true,
		},
		{
			name: "CollateralOfframp unwrap with USDC.e",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   offramp,
					Data: unwrapData(usdce),
				},
			},
			expectPass: true,
		},
		{
			name: "CollateralOfframp unwrap with disallowed asset",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   offramp,
					Data: unwrapData(pUSD),
				},
			},
			expectPass:   false,
			expectReason: "unwrap asset must be USDC or USDC.e",
		},
		{
			name: "USDC.e approve to CollateralOnramp",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   usdce,
					Data: approveData(onramp),
				},
			},
			expectPass: true,
		},
		{
			name: "USDC.e approve to wrong spender",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   usdce,
					Data: approveData(dead),
				},
			},
			expectPass:   false,
			expectReason: "approve spender must be CollateralOnramp",
		},
		{
			name: "USDC approve to CollateralOnramp",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   usdc,
					Data: approveData(onramp),
				},
			},
			expectPass: true,
		},
		{
			name: "USDC approve to wrong spender",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   usdc,
					Data: approveData(dead),
				},
			},
			expectPass:   false,
			expectReason: "approve spender must be CollateralOnramp",
		},
		{
			name: "unsupported target contract",
			input: &RuleInput{
				SignType: "transaction",
				ChainID:  137,
				Signer:   safeAddress,
				Transaction: &RuleInputTransaction{
					From: safeAddress,
					To:   dead,
					Data: approveData(dead),
				},
			},
			expectPass:   false,
			expectReason: "unsupported target contract",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := e.ValidateWithInput(script, tc.input, config)
			if tc.expectPass {
				assert.True(t, res.Valid, "expected pass, got reason=%s", res.Reason)
			} else {
				assert.False(t, res.Valid, "expected fail, got valid=true")
				if tc.expectReason != "" {
					assert.Contains(t, res.Reason, tc.expectReason)
				}
			}
		})
	}
}


func TestJSRuleEvaluator_Evaluate_WhitelistReject(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	script := `function validate(input){return{valid:false,reason:"value too high"};}`
	config := mustMarshalJSON(map[string]string{"script": script})
	rule := &types.Rule{
		ID:     "test-js-2",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeWhitelist,
		Config: config,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"2000000000000000000","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	parsed := &types.ParsedPayload{Value: strPtrForRuleInput("2000000000000000000")}

	matched, _, err := e.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.False(t, matched)
}

func TestJSRuleEvaluator_Evaluate_BlocklistViolation(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	script := `function validate(input){return{valid:false,reason:"blocked"};}`
	config := mustMarshalJSON(map[string]string{"script": script})
	rule := &types.Rule{
		ID:     "test-js-block",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeBlocklist,
		Config: config,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}

	matched, reason, err := e.Evaluate(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.True(t, matched, "blocklist should fire (violation)")
	assert.Contains(t, reason, "blocked")
}

func TestJSRuleEvaluator_Evaluate_BlocklistNoViolation(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	script := `function validate(input){return ok();}`
	config := mustMarshalJSON(map[string]string{"script": script})
	rule := &types.Rule{
		ID:     "test-js-block",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeBlocklist,
		Config: config,
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}

	matched, _, err := e.Evaluate(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.False(t, matched, "blocklist should not fire when script passes (no violation)")
}

// TestJSRuleEvaluator_AbiEncodeDecode verifies abi.encode/decode (go-ethereum/abi) and injected fail/ok.
func TestJSRuleEvaluator_AbiEncodeDecode(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	// Solidity-aligned: abi.encode(types[], values[]), abi.decode(data, types[])
	script := `function validate(i) {
		var enc = abi.encode(["address", "uint256"], ["0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "100"]);
		if (!enc || enc === "0x") return fail("encode failed");
		var dec = abi.decode(enc, ["address", "uint256"]);
		if (!dec || dec.length !== 2) return fail("decode failed");
		if (!eq(toChecksum(dec[0]), toChecksum("0x742d35Cc6634C0532925a3b844Bc454e4438f44e"))) return fail("address mismatch");
		if (!eq(dec[1], "100")) return fail("uint256 mismatch");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, nil)
	assert.True(t, res.Valid, "abi roundtrip should pass: %s", res.Reason)
}

// TestJSRuleEvaluator_AbiDecodeTransferFromPayload verifies abi.decode with exact transferFrom(address,address,uint256) payload (96 bytes).
func TestJSRuleEvaluator_AbiDecodeTransferFromPayload(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)
	// Same 96-byte payload as TestAbiDecodeTransferFromPayload (from+to+amount, each 32 bytes).
	from := "000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
	to := "0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc4"
	amount := "0000000000000000000000000000000000000000000000000000000000000000"
	payloadHex := "0x" + from + to + amount
	script := `function validate(i) {
		var dec = abi.decode("` + payloadHex + `", ["address", "address", "uint256"]);
		if (!dec || dec.length !== 3) return fail("decode failed");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, nil)
	assert.True(t, res.Valid, "transferFrom payload decode should pass: %s", res.Reason)
}

// TestJSRuleEvaluator_AbiTuple verifies abi.encode/decode with tuple (struct) type.
func TestJSRuleEvaluator_AbiTuple(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	// Tuple type: (uint256 a, uint256 b) — encode then decode and check fields
	script := `function validate(i) {
		var types = [
			{ type: "tuple", components: [ { name: "a", type: "uint256" }, { name: "b", type: "uint256" } ] }
		];
		var values = [ { a: "1", b: "2" } ];
		var enc = abi.encode(types, values);
		if (!enc || enc === "0x") return fail("tuple encode failed");
		var dec = abi.decode(enc, types);
		if (!dec || dec.length !== 1) return fail("tuple decode failed");
		var t = dec[0];
		if (typeof t !== "object" || t === null) return fail("tuple must be object");
		if (!eq(t.a, "1") || !eq(t.b, "2")) return fail("tuple fields mismatch: " + JSON.stringify(t));
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, nil)
	assert.True(t, res.Valid, "abi tuple roundtrip should pass: %s", res.Reason)
}

// TestJSRuleEvaluator_AbiTupleMixed verifies encode/decode with tuple and scalar (e.g. address + (uint256,uint256)).
func TestJSRuleEvaluator_AbiTupleMixed(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	script := `function validate(i) {
		var types = [
			"address",
			{ type: "tuple", components: [ { name: "x", type: "uint256" }, { name: "y", type: "uint256" } ] }
		];
		var values = [ "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", { x: "10", y: "20" } ];
		var enc = abi.encode(types, values);
		if (!enc || enc === "0x") return fail("encode failed");
		var dec = abi.decode(enc, types);
		if (!dec || dec.length !== 2) return fail("decode failed");
		if (!eq(toChecksum(dec[0]), toChecksum("0x742d35Cc6634C0532925a3b844Bc454e4438f44e"))) return fail("address mismatch");
		if (!dec[1] || !eq(dec[1].x, "10") || !eq(dec[1].y, "20")) return fail("tuple mismatch: " + JSON.stringify(dec[1]));
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil, nil)
	assert.True(t, res.Valid, "abi mixed tuple roundtrip should pass: %s", res.Reason)
}

func TestJSRuleEvaluator_EvaluateBudgetWithInput_ReturnsAmount(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	script := `function validate(i){ return ok(); }
function validateBudget(i){ return 42n; }`
	cfg := JSRuleConfig{Script: script}
	rule := &types.Rule{
		ID:     "test-budget",
		Type:   types.RuleTypeEVMJS,
		Config: mustMarshalJSON(cfg),
	}
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}

	result, err := e.EvaluateBudgetWithInput(context.Background(), rule, input)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, int64(42), result.Amount.Int64())
	assert.Empty(t, result.Unit, "plain bigint return should have empty unit")
}

func TestJSRuleEvaluator_EvaluateBudgetWithInput_NoValidateBudget_ReturnsZero(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	script := `function validate(i){ return ok(); }`
	cfg := JSRuleConfig{Script: script}
	rule := &types.Rule{ID: "test", Type: types.RuleTypeEVMJS, Config: mustMarshalJSON(cfg)}
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}

	result, err := e.EvaluateBudgetWithInput(context.Background(), rule, input)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Amount.Sign() == 0, "expected 0 when validateBudget is missing, got %s", result.Amount.String())
}

func TestJSRuleEvaluator_EvaluateBudget_FromRequest(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	script := `function validate(i){ return ok(); }
function validateBudget(i){ return 100n; }`
	cfg := JSRuleConfig{Script: script}
	rule := &types.Rule{
		ID:     "test-eval-budget",
		Type:   types.RuleTypeEVMJS,
		Config: mustMarshalJSON(cfg),
	}
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`),
	}
	parsed := &types.ParsedPayload{}

	result, err := e.EvaluateBudget(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 0, result.Amount.Cmp(big.NewInt(100)))
}

func TestJSRuleEvaluator_EvaluateBudget_DynamicUnit(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	script := `function validate(i){ return ok(); }
function validateBudget(i){ return { amount: 500000n, unit: "0xUSDC" }; }`
	cfg := JSRuleConfig{Script: script}
	rule := &types.Rule{
		ID:     "test-dynamic-unit",
		Type:   types.RuleTypeEVMJS,
		Config: mustMarshalJSON(cfg),
	}
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}

	result, err := e.EvaluateBudgetWithInput(context.Background(), rule, input)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, int64(500000), result.Amount.Int64())
	assert.Equal(t, "0xUSDC", result.Unit)
}

func TestJSRuleEvaluator_EvaluateBudget_DynamicUnitNative(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	script := `function validate(i){ return ok(); }
function validateBudget(i){ return { amount: 1n, unit: "tx_count" }; }`
	cfg := JSRuleConfig{Script: script}
	rule := &types.Rule{
		ID:     "test-tx-count",
		Type:   types.RuleTypeEVMJS,
		Config: mustMarshalJSON(cfg),
	}
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}

	result, err := e.EvaluateBudgetWithInput(context.Background(), rule, input)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, int64(1), result.Amount.Int64())
	assert.Equal(t, "tx_count", result.Unit)
}

func TestJSRuleEvaluator_EvaluateBudget_DynamicUnitMissingAmount(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	script := `function validate(i){ return ok(); }
function validateBudget(i){ return { unit: "native" }; }`
	cfg := JSRuleConfig{Script: script}
	rule := &types.Rule{
		ID:     "test-no-amount",
		Type:   types.RuleTypeEVMJS,
		Config: mustMarshalJSON(cfg),
	}
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}

	_, err = e.EvaluateBudgetWithInput(context.Background(), rule, input)
	require.Error(t, err, "should error when amount is missing from object")
	assert.Contains(t, err.Error(), "amount")
}

// TestJSRuleEvaluator_GoPanicBypassesJSTryCatch reproduces the bug where Go functions
// (e.g. requireDomain, requireInList) call bare panic(reason), which Sobek does NOT convert
// to a JS exception — it propagates as a Go panic to wrappedValidate's defer/recover.
// JS try/catch silently fails, the result is Valid: false, and a blocklist rule fires incorrectly.
// This is the root cause of Safe DELEGATECALL blocklist blocking the Polymarket airdrop bot.
//
// The test emulates the exact safe.yaml "Safe block DELEGATECALL" blocklist pattern (lines 51-65):
//
//	function validate(input) {
//	  var m = rs.typedData.match(input, 'SafeTx');
//	  if (!m.matched) return ok();
//	  ...
//	  try {
//	    rs.typedData.requireDomain(domain, { chainId: ..., allowedContracts: config.allowed_safe_addresses });
//	  } catch (e) { return ok(); }
//	  rs.int.requireEq(msg.operation, 0, 'only CALL allowed');
//	  return ok();
//	}
//
// When requireDomain panics because verifyingContract is not in allowed_safe_addresses,
// the try/catch should catch it and return ok(). But bare Go panic() goes straight to
// wrappedValidate's Go recover(), bypassing JS catch entirely.
func TestJSRuleEvaluator_GoPanicBypassesJSTryCatch(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	// This is the exact safe.yaml blocklist structure (simplified).
	// The rule has allowed_safe_addresses=["0x1111..."]. The request uses
	// verifyingContract="0xdb44..." which is NOT in the allowed list.
	// JS try/catch is SUPPOSED to catch requireDomain's exception and return ok().
	// Due to the Go panic bypass bug, it doesn't.
	script := `function validate(input) {
		var m = rs.typedData.match(input, 'SafeTx');
		if (!m.matched) return ok();
		var domain = m.domain || {};
		try {
			rs.typedData.requireDomain(domain, {
				chainId: 137,
				allowedContracts: ['0x1111111111111111111111111111111111111111']
			});
		} catch (e) { return ok(); }
		rs.int.requireEq(m.message.operation, 0, 'only CALL allowed');
		return ok();
	}`

	cfg := JSRuleConfig{Script: script, SignTypeFilter: "typed_data"}
	rule := &types.Rule{
		ID:     "safe-block-delegatecall",
		Type:   types.RuleTypeEVMJS,
		Mode:   types.RuleModeBlocklist,
		Config: mustMarshalJSON(cfg),
	}

	typedDataPayload := mustMarshalJSON(map[string]interface{}{
		"typed_data": map[string]interface{}{
		"types": map[string]interface{}{
			"EIP712Domain": []map[string]string{
				{"name": "chainId", "type": "uint256"},
				{"name": "verifyingContract", "type": "address"},
			},
			"SafeTx": []map[string]string{
				{"name": "to", "type": "address"},
				{"name": "value", "type": "uint256"},
				{"name": "data", "type": "bytes"},
				{"name": "operation", "type": "uint8"},
				{"name": "safeTxGas", "type": "uint256"},
				{"name": "nonce", "type": "uint256"},
			},
		},
		"primaryType": "SafeTx",
		"domain": map[string]string{
			"chainId":           "137",
			"verifyingContract": "0xdb44cf4ce5e57193c2245901179f3c403b5cec30",
		},
		"message": map[string]interface{}{
			"to":        "0xAdA200001000ef00D07553cEE7006808F895c6F1",
			"value":     "0",
			"data":      "0x9e7212ad0000000000000000000000000000000000000000000000000000000000000000",
			"operation": "0",
			"safeTxGas": "1088718",
			"nonce":     "84",
			},
		},
	})

	req := &types.SignRequest{
		ChainID:       "137",
		SignerAddress: "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837",
		SignType:      SignTypeTypedData,
		Payload:       typedDataPayload,
	}

	matched, reason, err := e.Evaluate(context.Background(), rule, req, nil)
	require.NoError(t, err)

	// BUG: The verifyingContract is NOT in allowed_safe_addresses. The try/catch
	// should catch the exception and return ok() — meaning the blocklist should NOT fire.
	// But bare Go panic bypasses JS catch → wrappedValidate returns Valid: false →
	// blocklist fires (matched=true). This is the production bug.
	assert.False(t, matched,
		"BUG: blocklist should NOT fire — try/catch should catch requireDomain exception and return ok() for unknown Safe addresses.\n"+
			"Instead Go panic() bypasses JS try/catch, causing wrappedValidate to return Valid: false, and blocklist fires.\n"+
			"reason=%s", reason)
}

// TestJSRuleEvaluator_GoPanicBypassesJSTryCatch_RsHelpers verifies that each rs.*.require*
// function uses bare panic() which bypasses JS try/catch. When all helpers are fixed to use
// throw (panic(vm.ToValue(...))), the JS catch will work and this test will pass.
func TestJSRuleEvaluator_GoPanicBypassesJSTryCatch_RsHelpers_RequireDomain(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	// requireDomain is called with an unknown verifyingContract inside try/catch.
	// If requireDomain throws a catchable JS error, try/catch works → ok() → Valid: true.
	// If requireDomain panics (Go panic), try/catch fails → Valid: false (because recover catches it).
	script := `function validate(input) {
		var domain = { chainId: '1', verifyingContract: '0xdb44cf4ce5e57193c2245901179f3c403b5cec30' };
		try {
			rs.typedData.requireDomain(domain, {
				chainId: 1,
				allowedContracts: ['0x1111111111111111111111111111111111111111']
			});
		} catch (e) {
			if (String(e).indexOf('invalid verifying contract') >= 0) return ok();
			return fail('unexpected error: ' + e);
		}
		return fail('should have thrown');
	}`

	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"}

	res := e.wrappedValidate(script, input, nil, nil)
	assert.True(t, res.Valid,
		"BUG: Go panic() in requireDomain bypasses JS try/catch. "+
			"Expected Valid=true (catch → ok()), got Valid=false with reason=%q", res.Reason)
}

// TestJSRuleEvaluator_GoPanicBypassesJSTryCatch_RsHelpers_RequireInList verifies the same bug
// for rs.addr.requireInList.
func TestJSRuleEvaluator_GoPanicBypassesJSTryCatch_RsHelpers_RequireInList(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	script := `function validate(input) {
		try {
			rs.addr.requireInList('0xdb44cf4ce5e57193c2245901179f3c403b5cec30',
				['0x1111111111111111111111111111111111111111'],
				'not in list');
		} catch (e) {
			if (String(e).indexOf('not in list') >= 0) return ok();
			return fail('unexpected error: ' + e);
		}
		return fail('should have thrown');
	}`

	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"}
	res := e.wrappedValidate(script, input, nil, nil)
	assert.True(t, res.Valid,
		"BUG: Go panic() in requireInList bypasses JS try/catch. "+
			"Expected Valid=true (catch → ok()), got Valid=false with reason=%q", res.Reason)
}

func TestJSRuleEvaluator_EvaluateBudget_DynamicUnitEmptyUnit(t *testing.T) {
	e, err := NewJSRuleEvaluator(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)

	script := `function validate(i){ return ok(); }
function validateBudget(i){ return { amount: 1n, unit: "" }; }`
	cfg := JSRuleConfig{Script: script}
	rule := &types.Rule{
		ID:     "test-empty-unit",
		Type:   types.RuleTypeEVMJS,
		Config: mustMarshalJSON(cfg),
	}
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}

	_, err = e.EvaluateBudgetWithInput(context.Background(), rule, input)
	require.Error(t, err, "should error when unit is empty in object")
	assert.Contains(t, err.Error(), "unit")
}

