package evm

import (
	"context"
	"encoding/json"
	"log/slog"
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
	res := e.wrappedValidate(script, input, nil)
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
	res := e.wrappedValidate(script, ruleInput, nil)
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
	res := e.wrappedValidate(script, input, nil)
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
	res := e.wrappedValidate(script, input, nil)
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
	res := e.wrappedValidate(script, input, nil)
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
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "abi mixed tuple roundtrip should pass: %s", res.Reason)
}

