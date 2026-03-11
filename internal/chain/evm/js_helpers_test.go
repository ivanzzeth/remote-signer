package evm

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─────────────────────────────────────────────────────────────────────────────
// abiEncode / abiDecode
// ─────────────────────────────────────────────────────────────────────────────

func TestAbiEncode_Basic(t *testing.T) {
	out, err := abiEncode([]string{"uint256"}, []interface{}{big.NewInt(42)})
	require.NoError(t, err)
	assert.Len(t, out, 32)
}

func TestAbiEncode_Address(t *testing.T) {
	addr := common.HexToAddress("0x742d35cc6634c0532925a3b844bc454e4438f44e")
	out, err := abiEncode([]string{"address"}, []interface{}{addr})
	require.NoError(t, err)
	assert.Len(t, out, 32)
}

func TestAbiEncode_InvalidType(t *testing.T) {
	_, err := abiEncode([]string{"invalid_type"}, []interface{}{"value"})
	require.Error(t, err)
}

func TestAbiEncode_MultipleArgs(t *testing.T) {
	addr := common.HexToAddress("0x742d35cc6634c0532925a3b844bc454e4438f44e")
	out, err := abiEncode([]string{"address", "uint256"}, []interface{}{addr, big.NewInt(100)})
	require.NoError(t, err)
	assert.Len(t, out, 64) // 32 bytes per arg
}

func TestAbiDecode_Basic(t *testing.T) {
	// Encode then decode
	encoded, err := abiEncode([]string{"uint256"}, []interface{}{big.NewInt(42)})
	require.NoError(t, err)

	decoded, err := abiDecode([]string{"uint256"}, encoded)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	assert.Equal(t, "42", decoded[0])
}

func TestAbiDecode_InvalidType(t *testing.T) {
	_, err := abiDecode([]string{"invalid_type"}, []byte{0})
	require.Error(t, err)
}

func TestAbiDecode_InvalidData(t *testing.T) {
	_, err := abiDecode([]string{"uint256"}, []byte{0x01, 0x02})
	require.Error(t, err)
}

func TestAbiDecode_AddressRoundtrip(t *testing.T) {
	addr := common.HexToAddress("0x742d35cc6634c0532925a3b844bc454e4438f44e")
	encoded, _ := abiEncode([]string{"address"}, []interface{}{addr})
	decoded, err := abiDecode([]string{"address"}, encoded)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	assert.Equal(t, addr.Hex(), decoded[0])
}

// ─────────────────────────────────────────────────────────────────────────────
// jsValueToAbiArg
// ─────────────────────────────────────────────────────────────────────────────

func TestJsValueToAbiArg_Address_Valid(t *testing.T) {
	result, err := jsValueToAbiArg("address", "0x742d35cc6634c0532925a3b844bc454e4438f44e")
	require.NoError(t, err)
	assert.Equal(t, common.HexToAddress("0x742d35cc6634c0532925a3b844bc454e4438f44e"), result)
}

func TestJsValueToAbiArg_Address_Invalid(t *testing.T) {
	result, err := jsValueToAbiArg("address", "not_an_address")
	require.NoError(t, err)
	assert.Equal(t, common.Address{}, result)
}

func TestJsValueToAbiArg_Address_NotString(t *testing.T) {
	result, err := jsValueToAbiArg("address", 42)
	require.NoError(t, err)
	assert.Equal(t, common.Address{}, result)
}

func TestJsValueToAbiArg_Uint256_String(t *testing.T) {
	result, err := jsValueToAbiArg("uint256", "1000000000000000000")
	require.NoError(t, err)
	expected, _ := new(big.Int).SetString("1000000000000000000", 10)
	assert.Equal(t, expected, result)
}

func TestJsValueToAbiArg_Uint256_Float64(t *testing.T) {
	result, err := jsValueToAbiArg("uint256", float64(42))
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(42), result)
}

func TestJsValueToAbiArg_Uint256_InvalidString(t *testing.T) {
	result, err := jsValueToAbiArg("uint256", "not_a_number")
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(0), result)
}

func TestJsValueToAbiArg_Uint8(t *testing.T) {
	result, err := jsValueToAbiArg("uint8", "255")
	require.NoError(t, err)
	assert.Equal(t, byte(255), result)
}

func TestJsValueToAbiArg_Uint8_Overflow(t *testing.T) {
	result, err := jsValueToAbiArg("uint8", "256")
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(0), result)
}

func TestJsValueToAbiArg_Uint16(t *testing.T) {
	result, err := jsValueToAbiArg("uint16", "65535")
	require.NoError(t, err)
	assert.Equal(t, uint16(65535), result)
}

func TestJsValueToAbiArg_Uint16_Overflow(t *testing.T) {
	result, err := jsValueToAbiArg("uint16", "65536")
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(0), result)
}

func TestJsValueToAbiArg_Uint32(t *testing.T) {
	result, err := jsValueToAbiArg("uint32", "4294967295")
	require.NoError(t, err)
	assert.Equal(t, uint32(4294967295), result)
}

func TestJsValueToAbiArg_Uint32_Overflow(t *testing.T) {
	result, err := jsValueToAbiArg("uint32", "4294967296")
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(0), result)
}

func TestJsValueToAbiArg_Uint64(t *testing.T) {
	result, err := jsValueToAbiArg("uint64", "18446744073709551615")
	require.NoError(t, err)
	assert.Equal(t, uint64(18446744073709551615), result)
}

func TestJsValueToAbiArg_Uint_Default(t *testing.T) {
	result, err := jsValueToAbiArg("uint", "42")
	require.NoError(t, err)
	// "uint" defaults to big.Int
	assert.IsType(t, &big.Int{}, result)
}

func TestJsValueToAbiArg_Uint_UnsupportedType(t *testing.T) {
	result, err := jsValueToAbiArg("uint256", []string{"array"})
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(0), result)
}

func TestJsValueToAbiArg_Int256(t *testing.T) {
	result, err := jsValueToAbiArg("int256", "-100")
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(-100), result)
}

func TestJsValueToAbiArg_Int256_Float64(t *testing.T) {
	result, err := jsValueToAbiArg("int256", float64(-42))
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(-42), result)
}

func TestJsValueToAbiArg_Int8(t *testing.T) {
	result, err := jsValueToAbiArg("int8", "42")
	require.NoError(t, err)
	assert.Equal(t, int64(42), result)
}

func TestJsValueToAbiArg_Int16(t *testing.T) {
	result, err := jsValueToAbiArg("int16", "1000")
	require.NoError(t, err)
	assert.Equal(t, int64(1000), result)
}

func TestJsValueToAbiArg_Int32(t *testing.T) {
	result, err := jsValueToAbiArg("int32", "-1000")
	require.NoError(t, err)
	assert.Equal(t, int64(-1000), result)
}

func TestJsValueToAbiArg_Int64(t *testing.T) {
	result, err := jsValueToAbiArg("int64", "999999")
	require.NoError(t, err)
	assert.Equal(t, int64(999999), result)
}

func TestJsValueToAbiArg_Int_Default(t *testing.T) {
	result, err := jsValueToAbiArg("int", "-42")
	require.NoError(t, err)
	assert.IsType(t, &big.Int{}, result)
}

func TestJsValueToAbiArg_Int_InvalidString(t *testing.T) {
	result, err := jsValueToAbiArg("int256", "nope")
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(0), result)
}

func TestJsValueToAbiArg_Int_UnsupportedType(t *testing.T) {
	result, err := jsValueToAbiArg("int256", []string{"arr"})
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(0), result)
}

func TestJsValueToAbiArg_Bool_True(t *testing.T) {
	result, err := jsValueToAbiArg("bool", true)
	require.NoError(t, err)
	assert.Equal(t, true, result)
}

func TestJsValueToAbiArg_Bool_False(t *testing.T) {
	result, err := jsValueToAbiArg("bool", false)
	require.NoError(t, err)
	assert.Equal(t, false, result)
}

func TestJsValueToAbiArg_Bool_NotBool(t *testing.T) {
	result, err := jsValueToAbiArg("bool", "true")
	require.NoError(t, err)
	assert.Equal(t, false, result) // type assertion fails → zero value
}

func TestJsValueToAbiArg_Bytes32_Valid(t *testing.T) {
	hexVal := "0x" + "ab" + "00" + "cd" + "00" + "ef" + "00" + "12" + "00" + "34" + "00" + "56" + "00" + "78" + "00" + "9a" + "00" + "bc" + "00" + "de" + "00" + "f0" + "00" + "11" + "00" + "22" + "00" + "33" + "00" + "44" + "00" + "55" + "00"
	result, err := jsValueToAbiArg("bytes32", hexVal)
	require.NoError(t, err)
	assert.IsType(t, common.Hash{}, result)
}

func TestJsValueToAbiArg_Bytes32_Invalid_ShortHex(t *testing.T) {
	result, err := jsValueToAbiArg("bytes32", "0x1234")
	require.NoError(t, err)
	assert.Equal(t, common.Hash{}, result)
}

func TestJsValueToAbiArg_Bytes32_NotString(t *testing.T) {
	result, err := jsValueToAbiArg("bytes32", 42)
	require.NoError(t, err)
	assert.Equal(t, common.Hash{}, result)
}

func TestJsValueToAbiArg_Bytes_HexString(t *testing.T) {
	result, err := jsValueToAbiArg("bytes", "0xabcdef")
	require.NoError(t, err)
	assert.Equal(t, []byte{0xab, 0xcd, 0xef}, result)
}

func TestJsValueToAbiArg_String(t *testing.T) {
	result, err := jsValueToAbiArg("string", "hello world")
	require.NoError(t, err)
	assert.Equal(t, "hello world", result)
}

func TestJsValueToAbiArg_String_NotString(t *testing.T) {
	_, err := jsValueToAbiArg("string", 42)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported value for string")
}

func TestJsValueToAbiArg_Bytes_NotString(t *testing.T) {
	_, err := jsValueToAbiArg("bytes", 42)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported value for bytes")
}

func TestJsValueToAbiArg_UnsupportedType(t *testing.T) {
	_, err := jsValueToAbiArg("tuple[]", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported abi type")
}

// ─────────────────────────────────────────────────────────────────────────────
// abiValueToJS
// ─────────────────────────────────────────────────────────────────────────────

func TestAbiValueToJS_Nil(t *testing.T) {
	assert.Nil(t, abiValueToJS(nil))
}

func TestAbiValueToJS_Address(t *testing.T) {
	addr := common.HexToAddress("0x742d35cc6634c0532925a3b844bc454e4438f44e")
	result := abiValueToJS(addr)
	assert.Equal(t, addr.Hex(), result)
}

func TestAbiValueToJS_Hash(t *testing.T) {
	h := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	result := abiValueToJS(h)
	assert.Equal(t, h.Hex(), result)
}

func TestAbiValueToJS_BigInt(t *testing.T) {
	n := big.NewInt(42)
	result := abiValueToJS(n)
	assert.Equal(t, "42", result)
}

func TestAbiValueToJS_Byte(t *testing.T) {
	result := abiValueToJS(byte(255))
	assert.Equal(t, "255", result)
}

func TestAbiValueToJS_Uint16(t *testing.T) {
	result := abiValueToJS(uint16(1000))
	assert.Equal(t, "1000", result)
}

func TestAbiValueToJS_Uint32(t *testing.T) {
	result := abiValueToJS(uint32(100000))
	assert.Equal(t, "100000", result)
}

func TestAbiValueToJS_Uint64(t *testing.T) {
	result := abiValueToJS(uint64(999999))
	assert.Equal(t, "999999", result)
}

func TestAbiValueToJS_Int8(t *testing.T) {
	result := abiValueToJS(int8(-42))
	assert.Equal(t, "-42", result)
}

func TestAbiValueToJS_Int16(t *testing.T) {
	result := abiValueToJS(int16(-1000))
	assert.Equal(t, "-1000", result)
}

func TestAbiValueToJS_Int32(t *testing.T) {
	result := abiValueToJS(int32(-100000))
	assert.Equal(t, "-100000", result)
}

func TestAbiValueToJS_Int64(t *testing.T) {
	result := abiValueToJS(int64(-999999))
	assert.Equal(t, "-999999", result)
}

func TestAbiValueToJS_ByteSlice(t *testing.T) {
	result := abiValueToJS([]byte{0xab, 0xcd, 0xef})
	assert.Equal(t, "0xabcdef", result)
}

func TestAbiValueToJS_EmptyByteSlice(t *testing.T) {
	result := abiValueToJS([]byte{})
	assert.Equal(t, "0x", result)
}

func TestAbiValueToJS_Bool(t *testing.T) {
	assert.Equal(t, true, abiValueToJS(true))
	assert.Equal(t, false, abiValueToJS(false))
}

func TestAbiValueToJS_String(t *testing.T) {
	result := abiValueToJS("hello")
	assert.Equal(t, "hello", result)
}

// ─────────────────────────────────────────────────────────────────────────────
// typesToArguments
// ─────────────────────────────────────────────────────────────────────────────

func TestTypesToArguments_Valid(t *testing.T) {
	args, err := typesToArguments([]string{"address", "uint256", "bool"})
	require.NoError(t, err)
	assert.Len(t, args, 3)
}

func TestTypesToArguments_Invalid(t *testing.T) {
	_, err := typesToArguments([]string{"invalid_type"})
	require.Error(t, err)
}

func TestTypesToArguments_Empty(t *testing.T) {
	args, err := typesToArguments([]string{})
	require.NoError(t, err)
	assert.Len(t, args, 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// exportStringSlice (tested via JS context)
// ─────────────────────────────────────────────────────────────────────────────

// exportStringSlice is tested indirectly through JS helpers injection.
// Direct testing requires a sobek.Value; covered by js_evaluator abi tests.

// ─────────────────────────────────────────────────────────────────────────────
// Injected JS helpers: tested through wrappedValidate
// ─────────────────────────────────────────────────────────────────────────────

func TestJSHelper_Keccak256_Text(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var h = keccak256("hello");
		if (h === null || h === undefined) return fail("keccak256 returned null");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "keccak256 text should work: %s", res.Reason)
}

func TestJSHelper_Keccak256_Hex(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var h = keccak256("0xabcdef");
		if (h === null || h === undefined) return fail("keccak256 hex returned null");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "keccak256 hex should work: %s", res.Reason)
}

func TestJSHelper_Keccak256_InvalidHex(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var h = keccak256("0xGGGG");
		if (h !== null && h !== undefined) return fail("expected null for invalid hex");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "keccak256 invalid hex: %s", res.Reason)
}

func TestJSHelper_Selector(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var sel = selector("transfer(address,uint256)");
		if (sel !== "0xa9059cbb") return fail("selector mismatch: " + sel);
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "selector should match: %s", res.Reason)
}

func TestJSHelper_ToChecksum(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var checksummed = toChecksum("0x742d35cc6634c0532925a3b844bc454e4438f44e");
		if (checksummed !== "0x742d35Cc6634C0532925a3b844Bc454e4438f44e") return fail("checksum mismatch: " + checksummed);
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "toChecksum: %s", res.Reason)
}

func TestJSHelper_IsAddress(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		if (!isAddress("0x742d35cc6634c0532925a3b844bc454e4438f44e")) return fail("should be valid");
		if (isAddress("not_an_address")) return fail("should be invalid");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "isAddress: %s", res.Reason)
}

func TestJSHelper_ToWei(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var wei = toWei("1");
		if (wei !== "1000000000000000000") return fail("toWei mismatch: " + wei);
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "toWei: %s", res.Reason)
}

func TestJSHelper_ToWei_Invalid(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var wei = toWei("not_a_number");
		if (wei !== "0") return fail("toWei should return 0 for invalid: " + wei);
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "toWei invalid: %s", res.Reason)
}

func TestJSHelper_FromWei(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var eth = fromWei("1000000000000000000");
		if (eth !== "1") return fail("fromWei mismatch: " + eth);
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "fromWei: %s", res.Reason)
}

func TestJSHelper_FromWei_Invalid(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var eth = fromWei("not_valid");
		if (eth !== "0") return fail("fromWei should return 0 for invalid: " + eth);
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "fromWei invalid: %s", res.Reason)
}

func TestJSHelper_Eq(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		if (!eq("hello", "hello")) return fail("eq strings failed");
		if (eq("hello", "world")) return fail("eq should be false");
		if (!eq(42, 42)) return fail("eq numbers failed");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "eq: %s", res.Reason)
}

func TestJSHelper_AbiEncode_TooFewArgs(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var enc = abi.encode();
		if (enc !== "0x") return fail("should return 0x for no args: " + enc);
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "abi.encode no args: %s", res.Reason)
}

func TestJSHelper_AbiDecode_TooFewArgs(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var dec = abi.decode();
		if (dec.length !== 0) return fail("should return empty array for no args");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "abi.decode no args: %s", res.Reason)
}

func TestJSHelper_AbiDecode_InvalidHex(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var dec = abi.decode("not_hex", ["uint256"]);
		if (dec.length !== 0) return fail("should return empty for invalid hex");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "abi.decode invalid hex: %s", res.Reason)
}

func TestJSHelper_AbiEncode_TypeMismatch(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	// 3 types but 2 values → should return "0x"
	script := `function validate(i){
		var enc = abi.encode(["uint256", "address", "bool"], ["100", "0x742d35cc6634c0532925a3b844bc454e4438f44e"]);
		if (enc !== "0x") return fail("should return 0x for mismatched args: " + enc);
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "abi.encode mismatch: %s", res.Reason)
}

// ─────────────────────────────────────────────────────────────────────────────
// toCamelCase (from js_abi_tuple.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestToCamelCase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"hello", "Hello"},
		{"Hello", "Hello"},
		{"a", "A"},
		{"abc", "Abc"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.expected, toCamelCase(tc.input))
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// abiStructToMap
// ─────────────────────────────────────────────────────────────────────────────

func TestAbiStructToMap_NonStruct(t *testing.T) {
	result := abiStructToMap("not a struct")
	assert.Nil(t, result)
}

func TestAbiStructToMap_EmptyStruct(t *testing.T) {
	type empty struct{}
	result := abiStructToMap(empty{})
	assert.NotNil(t, result)
	assert.Len(t, result, 0)
}

func TestAbiStructToMap_Pointer(t *testing.T) {
	type sample struct {
		Name string
	}
	result := abiStructToMap(&sample{Name: "test"})
	assert.NotNil(t, result)
	// Without json tag, field name lowercase first letter: "name"
	assert.Equal(t, "test", result["name"])
}

func TestAbiStructToMap_WithJsonTag(t *testing.T) {
	type sample struct {
		Amount *big.Int `json:"amount"`
	}
	result := abiStructToMap(sample{Amount: big.NewInt(42)})
	assert.NotNil(t, result)
	assert.Equal(t, "42", result["amount"])
}

// ─────────────────────────────────────────────────────────────────────────────
// Removed globals (security)
// ─────────────────────────────────────────────────────────────────────────────

func TestRemovedGlobals_Eval(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		if (typeof eval !== "undefined" && eval !== undefined) return fail("eval should be removed");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "eval removal: %s", res.Reason)
}

func TestRemovedGlobals_MathRandom(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		if (typeof Math !== "undefined" && Math !== undefined && typeof Math.random === "function") return fail("Math.random should be removed");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "Math.random removal: %s", res.Reason)
}

// ─────────────────────────────────────────────────────────────────────────────
// rs module (injectRsHelpers)
// ─────────────────────────────────────────────────────────────────────────────

func TestRs_TxRequire_Success(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var ctx = rs.tx.require(i);
		if (!ctx.valid) return ctx;
		if (ctx.selector !== "0xa9059cbb") return fail("selector mismatch: " + ctx.selector);
		return ok();
	}`
	input := &RuleInput{
		SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Transaction: &RuleInputTransaction{
			From: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
			To:   "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			Data: "0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000001",
		},
	}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.tx.require success: %s", res.Reason)
}

func TestRs_TxRequire_WrongSignType(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var ctx = rs.tx.require(i);
		if (!ctx.valid) return ctx;
		return fail("should fail");
	}`
	input := &RuleInput{SignType: "typed_data", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "transaction only")
}

func TestRs_TxRequire_MissingTx(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var ctx = rs.tx.require(i);
		if (!ctx.valid) return ctx;
		return fail("should fail");
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "missing tx")
}

func TestRs_TxRequire_ShortCalldata(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var ctx = rs.tx.require(i);
		if (!ctx.valid) return ctx;
		return fail("should fail");
	}`
	input := &RuleInput{
		SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Transaction: &RuleInputTransaction{
			From: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
			To:   "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			Data: "0xa905",
		},
	}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "calldata too short")
}

func TestRs_BigIntParse_SuccessAndType(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var r = rs.bigint.parse("42");
		if (!r.valid) return r;
		if (typeof r.n !== "bigint") return fail("expected bigint");
		if (r.n + 1n !== 43n) return fail("math failed");
		var h = rs.bigint.parse("0x2a");
		if (!h.valid) return h;
		if (h.n !== 42n) return fail("hex parse failed");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.bigint.parse: %s", res.Reason)
}

func TestRs_BigIntParse_Invalid(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var r = rs.bigint.parse("not_a_number");
		if (r.valid) return fail("should fail");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.bigint.parse invalid: %s", res.Reason)
}

func TestRs_BigIntUint256_Range(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		// 2^256 - 1
		var max = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
		var r = rs.bigint.uint256(max);
		if (!r.valid) return r;
		if (typeof r.n !== "bigint") return fail("expected bigint");

		// 2^256 (should fail)
		var tooBig = "0x10000000000000000000000000000000000000000000000000000000000000000";
		r = rs.bigint.uint256(tooBig);
		if (r.valid) return fail("should fail");

		// negative should fail
		r = rs.bigint.uint256("-1");
		if (r.valid) return fail("should fail");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.bigint.uint256 range: %s", res.Reason)
}

func TestRs_IntRequire_Success(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var r = rs.int.requireLte("1000", 1000, "fee exceeds 10%");
		if (!r.valid) return r;
		r = rs.int.requireEq("0", 0, "signatureType must be EOA");
		if (!r.valid) return r;
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.int require: %s", res.Reason)
}

// NOTE: Addresses must be strict hex address strings. "0" is invalid (not a zero address).

func TestRs_AddrInList_Array(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var list = ["0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "0x1111111111111111111111111111111111111111"];
		if (!rs.addr.inList("0x742d35cc6634c0532925a3b844bc454e4438f44e", list)) return fail("should be in list");
		if (rs.addr.inList("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead", list)) return fail("should not be in list");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.addr.inList array: %s", res.Reason)
}

func TestRs_AddrInList_String(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var list = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e,0x1111111111111111111111111111111111111111";
		if (!rs.addr.inList("0x742d35cc6634c0532925a3b844bc454e4438f44e", list)) return fail("should be in list");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.addr.inList string: %s", res.Reason)
}

func TestRs_AddrNotInList(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var usdt = "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174";
		if (!rs.addr.notInList("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead", [usdt])) return fail("should be not in list");
		if (rs.addr.notInList(usdt, [usdt])) return fail("should be in list");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.addr.notInList: %s", res.Reason)
}

func TestRs_AddrRequireNotInList(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	// Test 1: address NOT in list → ok
	script1 := `function validate(i){
		var usdt = "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174";
		var r = rs.addr.requireNotInList("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead", [usdt], "must not be usdt");
		if (!r.valid) return r;
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script1, input, nil)
	assert.True(t, res.Valid, "rs.addr.requireNotInList (not in list): %s", res.Reason)

	// Test 2: address IN list → panic (caught by engine as fail)
	script2 := `function validate(i){
		var usdt = "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174";
		rs.addr.requireNotInList(usdt, [usdt], "must not be usdt");
		return ok();
	}`
	res = e.wrappedValidate(script2, input, nil)
	assert.False(t, res.Valid, "rs.addr.requireNotInList (in list) should fail")
	assert.Contains(t, res.Reason, "must not be usdt")
}

func TestRs_AddrRequireInList(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var r = rs.addr.requireInList("0x742d35cc6634c0532925a3b844bc454e4438f44e", ["0x742d35Cc6634C0532925a3b844Bc454e4438f44e"], "not allowed");
		if (!r.valid) return r;
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.addr.requireInList: %s", res.Reason)
}

func TestRs_AddrRequireInList_Fail(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var r = rs.addr.requireInList("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead", ["0x742d35Cc6634C0532925a3b844Bc454e4438f44e"], "spender not allowed");
		if (!r.valid) return r;
		return fail("should fail");
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "spender not allowed")
}

func TestRs_AddrIsZero(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		if (!rs.addr.isZero("0x0000000000000000000000000000000000000000")) return fail("zero should be true");
		if (rs.addr.isZero("0x742d35cc6634c0532925a3b844bc454e4438f44e")) return fail("non-zero should be false");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.addr.isZero: %s", res.Reason)
}

func TestRs_AddrRequireZero(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var r = rs.addr.requireZero("0x0000000000000000000000000000000000000000", "taker must be zero");
		if (!r.valid) return r;
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.addr.requireZero: %s", res.Reason)
}

func TestRs_BigIntRequireLte_NoLimit(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var r = rs.bigint.requireLte("50", "100", "cap");
		if (!r.valid) return r;
		r = rs.bigint.requireLte("100", "100", "cap");
		if (!r.valid) return r;
		r = rs.bigint.requireLte("50", "", "cap");
		if (!r.valid) return r;
		r = rs.bigint.requireLte("50", "0", "cap");
		if (!r.valid) return r;
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.bigint.requireLte: %s", res.Reason)
}

func TestRs_BigIntRequireLte_ExceedsCap(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var r = rs.bigint.requireLte("200", "100", "transfer exceeds cap");
		if (r.valid) return fail("should fail");
		return r;
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "transfer exceeds cap")
}

func TestRs_BigIntRequireZero(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var r = rs.bigint.requireZero("0", "must be zero");
		if (!r.valid) return r;
		r = rs.bigint.requireZero("1", "must be zero");
		if (r.valid) return fail("should fail");
		return r;
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "must be zero")
}

func TestRs_Revert_BecomesFail(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ revert("exceeds cap"); return ok(); }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Equal(t, "exceeds cap", res.Reason)
}

func TestRs_Require_BecomesFailWhenFalsy(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ require(false, "not allowed"); return ok(); }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Equal(t, "not allowed", res.Reason)
}

func TestRs_Require_PassesWhenTruthy(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ require(true, "ignored"); return ok(); }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid)
}

func TestRs_AnyThrow_BecomesFail(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){ throw new Error("custom error"); }`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "custom error")
}

func TestRs_AddrRequireInListIfNonEmpty(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var r = rs.addr.requireInListIfNonEmpty("0x742d35cc6634c0532925a3b844bc454e4438f44e", "", "not allowed");
		if (!r.valid) return r;
		r = rs.addr.requireInListIfNonEmpty("0x742d35cc6634c0532925a3b844bc454e4438f44e", ["0x742d35Cc6634C0532925a3b844Bc454e4438f44e"], "not allowed");
		if (!r.valid) return r;
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.addr.requireInListIfNonEmpty: %s", res.Reason)
}

func TestRs_AddrRequireInListIfNonEmpty_Fail(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var r = rs.addr.requireInListIfNonEmpty("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead", ["0x742d35Cc6634C0532925a3b844Bc454e4438f44e"], "spender not allowed");
		if (r.valid) return fail("should fail");
		return r;
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "spender not allowed")
}

func TestRs_TypedDataRequire_Success(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var ctx = rs.typedData.require(i, "Order");
		if (!ctx.valid) return ctx;
		if (!ctx.domain || !ctx.message) return fail("domain and message required");
		return ok();
	}`
	input := &RuleInput{
		SignType: "typed_data", ChainID: 56, Signer: "0x53c68c954f85a29d2098e90addaf41baf2ff0a50",
		TypedData: &RuleInputTypedData{
			PrimaryType: "Order",
			Domain:      TypedDataDomain{Name: "Test", Version: "1", ChainId: "56"},
			Message:     map[string]interface{}{"maker": "0x53c68c954f85a29d2098e90addaf41baf2ff0a50"},
		},
	}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.typedData.require: %s", res.Reason)
}

func TestRs_TypedDataMatch(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var m = rs.typedData.match(i, "Order");
		if (!m.matched) return fail("should match");
		if (!m.domain || !m.message) return fail("missing domain/message");
		var m2 = rs.typedData.match(i, "Other");
		if (m2.matched) return fail("should not match");
		return ok();
	}`
	input := &RuleInput{
		SignType: "typed_data", ChainID: 56, Signer: "0x53c68c954f85a29d2098e90addaf41baf2ff0a50",
		TypedData: &RuleInputTypedData{
			PrimaryType: "Order",
			Domain:      TypedDataDomain{ChainId: "56"},
			Message:     map[string]interface{}{"maker": "0x53c68c954f85a29d2098e90addaf41baf2ff0a50"},
		},
	}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.typedData.match: %s", res.Reason)
}

func TestRs_TypedDataRequire_WrongSignType(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var ctx = rs.typedData.require(i, "Order");
		if (!ctx.valid) return ctx;
		return fail("should fail");
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "typed_data")
}

func TestRs_TypedDataRequireDomain(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var ctx = rs.typedData.require(i, "Order");
		if (!ctx.valid) return ctx;
		var r = rs.typedData.requireDomain(ctx.domain, { name: "Test", version: "1", chainId: "56", allowedContracts: ["0x8BC070BEdAB741406F4B1Eb65A72bee27894B689"] });
		if (!r.valid) return r;
		return ok();
	}`
	input := &RuleInput{
		SignType: "typed_data", ChainID: 56, Signer: "0x53c68c954f85a29d2098e90addaf41baf2ff0a50",
		TypedData: &RuleInputTypedData{
			PrimaryType: "Order",
			Domain: TypedDataDomain{
				Name:              "Test",
				Version:           "1",
				ChainId:           "56",
				VerifyingContract: "0x8BC070BEdAB741406F4B1Eb65A72bee27894B689",
			},
			Message: map[string]interface{}{},
		},
	}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.typedData.requireDomain: %s", res.Reason)
}

func TestRs_TypedDataRequireSignerMatch(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var r = rs.typedData.requireSignerMatch("0x53c68c954f85a29d2098e90addaf41baf2ff0a50", "0x53c68c954f85a29d2098e90addaf41baf2ff0a50", "signer mismatch");
		if (!r.valid) return r;
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.typedData.requireSignerMatch: %s", res.Reason)
}

// ─────────────────────────────────────────────────────────────────────────────
// ABI encode/decode roundtrip for bytes and string types
// ─────────────────────────────────────────────────────────────────────────────

func TestAbiEncodeDecode_Bytes(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	encoded, err := abiEncode([]string{"bytes"}, []interface{}{data})
	require.NoError(t, err)

	decoded, err := abiDecode([]string{"bytes"}, encoded)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	assert.Equal(t, "0x"+hex.EncodeToString(data), decoded[0])
}

func TestAbiEncodeDecode_String(t *testing.T) {
	encoded, err := abiEncode([]string{"string"}, []interface{}{"hello world"})
	require.NoError(t, err)

	decoded, err := abiDecode([]string{"string"}, encoded)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	assert.Equal(t, "hello world", decoded[0])
}

func TestAbiEncodeDecode_Bool(t *testing.T) {
	encoded, err := abiEncode([]string{"bool"}, []interface{}{true})
	require.NoError(t, err)

	decoded, err := abiDecode([]string{"bool"}, encoded)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	assert.Equal(t, true, decoded[0])
}

// ─────────────────────────────────────────────────────────────────────────────
// rs.gnosis.safe.parseExecTransactionData
// ─────────────────────────────────────────────────────────────────────────────

func buildExecTransactionCalldata(to common.Address, value *big.Int, data []byte, operation uint8) string {
	// execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)
	// selector = 0x6a761202
	sel := "6a761202"

	// Encode head: to(32) + value(32) + dataOffset(32) + operation(32) + safeTxGas(32) + baseGas(32) + gasPrice(32) + gasToken(32) + refundReceiver(32) + signaturesOffset(32)
	toSlot := hex.EncodeToString(common.LeftPadBytes(to.Bytes(), 32))
	valueSlot := hex.EncodeToString(common.LeftPadBytes(value.Bytes(), 32))
	// data offset = 10 * 32 = 320 = 0x140
	dataOffsetSlot := hex.EncodeToString(common.LeftPadBytes(big.NewInt(320).Bytes(), 32))
	opSlot := hex.EncodeToString(common.LeftPadBytes([]byte{operation}, 32))
	zeroSlot := hex.EncodeToString(common.LeftPadBytes([]byte{}, 32))

	// data length + data (padded to 32)
	dataLenSlot := hex.EncodeToString(common.LeftPadBytes(big.NewInt(int64(len(data))).Bytes(), 32))
	dataHex := hex.EncodeToString(data)
	padLen := (32 - len(data)%32) % 32
	dataPadded := dataHex + hex.EncodeToString(make([]byte, padLen))

	// signatures offset = data offset + 32 + padded data length
	sigOffset := 320 + 32 + len(data) + padLen
	sigOffsetSlot := hex.EncodeToString(common.LeftPadBytes(big.NewInt(int64(sigOffset)).Bytes(), 32))

	// empty signatures
	sigLenSlot := hex.EncodeToString(common.LeftPadBytes([]byte{}, 32))

	return "0x" + sel + toSlot + valueSlot + dataOffsetSlot + opSlot +
		zeroSlot + zeroSlot + zeroSlot + zeroSlot + zeroSlot + sigOffsetSlot +
		dataLenSlot + dataPadded + sigLenSlot
}

func TestRs_SafeParseExecTransactionData_Valid(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	innerTo := common.HexToAddress("0x742d35cc6634c0532925a3b844bc454e4438f44e")
	innerData := common.Hex2Bytes("a9059cbb000000000000000000000000dead000000000000000000000000000000000000")
	calldata := buildExecTransactionCalldata(innerTo, big.NewInt(0), innerData, 0)

	script := `function validate(i){
		var r = rs.gnosis.safe.parseExecTransactionData("` + calldata + `");
		if (!r.valid) return fail("parse failed: " + r.reason);
		if (!r.valueZero) return fail("value should be zero");
		if (!r.operationCALL) return fail("operation should be CALL");
		if (r.innerTo.toLowerCase() !== "0x742d35cc6634c0532925a3b844bc454e4438f44e") return fail("wrong innerTo: " + r.innerTo);
		if (!r.innerHex || r.innerHex.length < 10) return fail("innerHex too short");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "safe.parseExecTransactionData valid: %s", res.Reason)
}

func TestRs_SafeParseExecTransactionData_NonZeroValue(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	innerTo := common.HexToAddress("0x742d35cc6634c0532925a3b844bc454e4438f44e")
	calldata := buildExecTransactionCalldata(innerTo, big.NewInt(1000), []byte{0xab, 0xcd, 0xef, 0x12}, 0)

	script := `function validate(i){
		var r = rs.gnosis.safe.parseExecTransactionData("` + calldata + `");
		if (!r.valid) return fail("parse failed: " + r.reason);
		if (r.valueZero) return fail("value should NOT be zero");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "safe nonzero value: %s", res.Reason)
}

func TestRs_SafeParseExecTransactionData_DelegateCall(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	innerTo := common.HexToAddress("0x742d35cc6634c0532925a3b844bc454e4438f44e")
	calldata := buildExecTransactionCalldata(innerTo, big.NewInt(0), []byte{0xab, 0xcd, 0xef, 0x12}, 1)

	script := `function validate(i){
		var r = rs.gnosis.safe.parseExecTransactionData("` + calldata + `");
		if (!r.valid) return fail("parse failed: " + r.reason);
		if (r.operationCALL) return fail("should be DELEGATECALL");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "safe delegatecall: %s", res.Reason)
}

func TestRs_SafeParseExecTransactionData_TooShort(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var r = rs.gnosis.safe.parseExecTransactionData("0x6a761202abcd");
		if (r.valid) return fail("should fail");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "safe too short: %s", res.Reason)
}

func TestRs_SafeParseExecTransactionData_Empty(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var r = rs.gnosis.safe.parseExecTransactionData("");
		if (r.valid) return fail("should fail");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "safe empty: %s", res.Reason)
}

// ─────────────────────────────────────────────────────────────────────────────
// rs.config.requireNonEmpty
// ─────────────────────────────────────────────────────────────────────────────

func TestRs_ConfigRequireNonEmpty_Valid(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		rs.config.requireNonEmpty("token", "missing token");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	config := map[string]interface{}{"token": "0xdead"}
	res := e.wrappedValidate(script, input, config)
	assert.True(t, res.Valid, "config requireNonEmpty valid: %s", res.Reason)
}

func TestRs_ConfigRequireNonEmpty_Missing(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		rs.config.requireNonEmpty("token", "missing token");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, map[string]interface{}{})
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "missing token")
}

func TestRs_ConfigRequireNonEmpty_WhitespaceOnly(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		rs.config.requireNonEmpty("token", "missing token");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	config := map[string]interface{}{"token": "   "}
	res := e.wrappedValidate(script, input, config)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "missing token")
}

// ─────────────────────────────────────────────────────────────────────────────
// trimConfigStrings
// ─────────────────────────────────────────────────────────────────────────────

func TestTrimConfigStrings(t *testing.T) {
	input := map[string]interface{}{
		"name":   "  hello  ",
		"count":  42,
		"nested": map[string]interface{}{"key": " value "},
		"list":   []interface{}{" a ", " b "},
	}
	out := trimConfigStrings(input)
	assert.Equal(t, "hello", out["name"])
	assert.Equal(t, 42, out["count"])
	nested := out["nested"].(map[string]interface{})
	assert.Equal(t, "value", nested["key"])
	list := out["list"].([]interface{})
	assert.Equal(t, "a", list[0])
	assert.Equal(t, "b", list[1])
}

func TestTrimConfigStrings_Nil(t *testing.T) {
	assert.Nil(t, trimConfigStrings(nil))
}

// ─────────────────────────────────────────────────────────────────────────────
// rs.bigint.int256
// ─────────────────────────────────────────────────────────────────────────────

func TestRs_BigIntInt256_Range(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		// Negative value
		var r = rs.bigint.int256("-1");
		if (!r.valid) return fail("int256 -1 should be valid");
		if (typeof r.n !== "bigint") return fail("expected bigint");
		if (r.n !== -1n) return fail("value should be -1");

		// Max int256: 2^255 - 1
		r = rs.bigint.int256("57896044618658097711785492504343953926634992332820282019728792003956564819967");
		if (!r.valid) return fail("max int256 should be valid");

		// Min int256: -2^255
		r = rs.bigint.int256("-57896044618658097711785492504343953926634992332820282019728792003956564819968");
		if (!r.valid) return fail("min int256 should be valid");

		// Out of range (2^255)
		r = rs.bigint.int256("57896044618658097711785492504343953926634992332820282019728792003956564819968");
		if (r.valid) return fail("2^255 should fail");

		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.bigint.int256 range: %s", res.Reason)
}

// ─────────────────────────────────────────────────────────────────────────────
// rs.bigint.requireEq
// ─────────────────────────────────────────────────────────────────────────────

func TestRs_BigIntRequireEq_Success(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		var r = rs.bigint.requireEq("42", "42", "not equal");
		if (!r.valid) return r;
		r = rs.bigint.requireEq("0xff", "255", "hex vs dec");
		if (!r.valid) return r;
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.True(t, res.Valid, "rs.bigint.requireEq: %s", res.Reason)
}

func TestRs_BigIntRequireEq_Failure(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		rs.bigint.requireEq("42", "43", "values differ");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "values differ")
}

// ─────────────────────────────────────────────────────────────────────────────
// extractJSExceptionMessage
// ─────────────────────────────────────────────────────────────────────────────

func TestExtractJSExceptionMessage(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Error: exceeds cap at revert (native)", "exceeds cap"},
		{"Error: simple message", "simple message"},
		{"not an error prefix", "not an error prefix"},
		{"Error: ", ""},
		{"Error: multi word reason at someFunc (file:1:2)", "multi word reason"},
	}
	for _, tt := range tests {
		got := extractJSExceptionMessage(tt.input)
		assert.Equal(t, tt.want, got, "input: %q", tt.input)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// rs.addr.requireNotInList — invalid address must fail (not bypass)
// ─────────────────────────────────────────────────────────────────────────────

func TestRs_AddrRequireNotInList_InvalidAddr(t *testing.T) {
	e, _ := NewJSRuleEvaluator(testLogger())
	script := `function validate(i){
		rs.addr.requireNotInList("not_an_address", ["0x742d35cc6634c0532925a3b844bc454e4438f44e"], "blocked");
		return ok();
	}`
	input := &RuleInput{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	res := e.wrappedValidate(script, input, nil)
	assert.False(t, res.Valid, "invalid address should fail requireNotInList")
	assert.Contains(t, res.Reason, "blocked")
}
