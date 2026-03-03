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
