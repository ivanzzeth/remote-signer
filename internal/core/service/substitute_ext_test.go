package service

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ---------------------------------------------------------------------------
// jsonEncodeTyped
// ---------------------------------------------------------------------------

func TestJsonEncodeTyped_Bool(t *testing.T) {
	out, err := jsonEncodeTyped("flag", types.VarTypeBool, true)
	require.NoError(t, err)
	assert.Equal(t, "true", out)

	out, err = jsonEncodeTyped("flag", types.VarTypeBool, false)
	require.NoError(t, err)
	assert.Equal(t, "false", out)
}

func TestJsonEncodeTyped_AddressList(t *testing.T) {
	out, err := jsonEncodeTyped("addrs", types.VarTypeAddressList, []string{"0x1", "0x2"})
	require.NoError(t, err)
	assert.Equal(t, `["0x1","0x2"]`, out)
}

func TestJsonEncodeTyped_BigIntList(t *testing.T) {
	out, err := jsonEncodeTyped("vals", types.VarTypeBigIntList, []string{"100", "200"})
	require.NoError(t, err)
	assert.Equal(t, `["100","200"]`, out)
}

func TestJsonEncodeTyped_JSON(t *testing.T) {
	out, err := jsonEncodeTyped("cfg", types.VarTypeJSON, map[string]any{"x": 1})
	require.NoError(t, err)
	assert.JSONEq(t, `{"x":1}`, out)
}

func TestJsonEncodeTyped_BigInt(t *testing.T) {
	out, err := jsonEncodeTyped("cap", types.VarTypeBigInt, "5000000000000000000")
	require.NoError(t, err)
	assert.Equal(t, `"5000000000000000000"`, out)
}

func TestJsonEncodeTyped_BigIntSentinel(t *testing.T) {
	out, err := jsonEncodeTyped("cap", types.VarTypeBigInt, "-1")
	require.NoError(t, err)
	assert.Equal(t, `"-1"`, out)
}

func TestJsonEncodeTyped_BigIntError(t *testing.T) {
	_, err := jsonEncodeTyped("cap", types.VarTypeBigInt, "not-a-number")
	require.Error(t, err)
}

func TestJsonEncodeTyped_Duration(t *testing.T) {
	out, err := jsonEncodeTyped("ttl", types.VarTypeDuration, "30s")
	require.NoError(t, err)
	assert.Equal(t, `"30s"`, out)
}

func TestJsonEncodeTyped_DurationError(t *testing.T) {
	_, err := jsonEncodeTyped("ttl", types.VarTypeDuration, "forever")
	require.Error(t, err)
}

func TestJsonEncodeTyped_String(t *testing.T) {
	out, err := jsonEncodeTyped("name", types.VarTypeString, "hello")
	require.NoError(t, err)
	assert.Equal(t, `"hello"`, out)
}

func TestJsonEncodeTyped_Address(t *testing.T) {
	out, err := jsonEncodeTyped("addr", types.VarTypeAddress, "0xabc")
	require.NoError(t, err)
	assert.Equal(t, `"0xabc"`, out)
}

func TestJsonEncodeTyped_Bytes(t *testing.T) {
	out, err := jsonEncodeTyped("data", types.VarTypeBytes, "0xdead")
	require.NoError(t, err)
	assert.Equal(t, `"0xdead"`, out)
}

func TestJsonEncodeTyped_Bytes4(t *testing.T) {
	out, err := jsonEncodeTyped("sel", types.VarTypeBytes4, "0x01234567")
	require.NoError(t, err)
	assert.Equal(t, `"0x01234567"`, out)
}

func TestJsonEncodeTyped_Enum(t *testing.T) {
	out, err := jsonEncodeTyped("mode", types.VarTypeEnum, "strict")
	require.NoError(t, err)
	assert.Equal(t, `"strict"`, out)
}

func TestJsonEncodeTyped_UnknownType(t *testing.T) {
	_, err := jsonEncodeTyped("x", "unknown_type", "val")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown type")
}

// ---------------------------------------------------------------------------
// asString
// ---------------------------------------------------------------------------

func TestAsString(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		s, err := asString("x", "hello")
		require.NoError(t, err)
		assert.Equal(t, "hello", s)
	})

	t.Run("int_value", func(t *testing.T) {
		s, err := asString("x", 42)
		require.NoError(t, err)
		assert.Equal(t, "42", s)
	})

	t.Run("int64_value", func(t *testing.T) {
		s, err := asString("x", int64(99))
		require.NoError(t, err)
		assert.Equal(t, "99", s)
	})

	t.Run("float_value", func(t *testing.T) {
		s, err := asString("x", float64(3.14))
		require.NoError(t, err)
		assert.Equal(t, "3.14", s)
	})

	t.Run("bool_value", func(t *testing.T) {
		s, err := asString("x", true)
		require.NoError(t, err)
		assert.Equal(t, "true", s)
	})

	t.Run("nil_value", func(t *testing.T) {
		s, err := asString("x", nil)
		require.NoError(t, err)
		assert.Equal(t, "", s)
	})

	t.Run("stringer_value", func(t *testing.T) {
		v := big.NewInt(100)
		s, err := asString("x", v)
		require.NoError(t, err)
		assert.Equal(t, "100", s)
	})

	t.Run("unsupported_type", func(t *testing.T) {
		_, err := asString("x", []string{"a"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot coerce")
	})
}

// ---------------------------------------------------------------------------
// asBool
// ---------------------------------------------------------------------------

func TestAsBool(t *testing.T) {
	t.Run("bool_true", func(t *testing.T) {
		b, err := asBool("x", true)
		require.NoError(t, err)
		assert.True(t, b)
	})

	t.Run("bool_false", func(t *testing.T) {
		b, err := asBool("x", false)
		require.NoError(t, err)
		assert.False(t, b)
	})

	t.Run("string_true", func(t *testing.T) {
		b, err := asBool("x", "true")
		require.NoError(t, err)
		assert.True(t, b)
	})

	t.Run("string_false", func(t *testing.T) {
		b, err := asBool("x", "false")
		require.NoError(t, err)
		assert.False(t, b)
	})

	t.Run("string_1", func(t *testing.T) {
		b, err := asBool("x", "1")
		require.NoError(t, err)
		assert.True(t, b)
	})

	t.Run("string_0", func(t *testing.T) {
		b, err := asBool("x", "0")
		require.NoError(t, err)
		assert.False(t, b)
	})

	t.Run("string_not_bool", func(t *testing.T) {
		_, err := asBool("x", "notabool")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not a bool")
	})

	t.Run("unsupported_type", func(t *testing.T) {
		_, err := asBool("x", 42)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot coerce")
	})
}

// ---------------------------------------------------------------------------
// asStringSlice
// ---------------------------------------------------------------------------

func TestAsStringSlice(t *testing.T) {
	t.Run("string_slice", func(t *testing.T) {
		out, err := asStringSlice("x", []string{"a", "b"})
		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b"}, out)
	})

	t.Run("any_slice", func(t *testing.T) {
		out, err := asStringSlice("x", []any{"a", "b"})
		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b"}, out)
	})

	t.Run("comma_string", func(t *testing.T) {
		out, err := asStringSlice("x", "a,b,c")
		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b", "c"}, out)
	})

	t.Run("comma_string_with_spaces", func(t *testing.T) {
		out, err := asStringSlice("x", " a , b , c ")
		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b", "c"}, out)
	})

	t.Run("nil_value", func(t *testing.T) {
		out, err := asStringSlice("x", nil)
		require.NoError(t, err)
		assert.Nil(t, out)
	})

	t.Run("unsupported_type", func(t *testing.T) {
		_, err := asStringSlice("x", 42)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot coerce")
	})
}

// ---------------------------------------------------------------------------
// asBigIntString
// ---------------------------------------------------------------------------

func TestAsBigIntString(t *testing.T) {
	t.Run("valid_bigint", func(t *testing.T) {
		s, err := asBigIntString("cap", "123456789")
		require.NoError(t, err)
		assert.Equal(t, "123456789", s)
	})

	t.Run("sentinel_minus_one", func(t *testing.T) {
		s, err := asBigIntString("cap", "-1")
		require.NoError(t, err)
		assert.Equal(t, "-1", s)
	})

	t.Run("empty_string", func(t *testing.T) {
		_, err := asBigIntString("cap", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bigint cannot be empty")
	})

	t.Run("invalid_string", func(t *testing.T) {
		_, err := asBigIntString("cap", "not-a-number")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid bigint")
	})
}

// ---------------------------------------------------------------------------
// asDurationString
// ---------------------------------------------------------------------------

func TestAsDurationString(t *testing.T) {
	t.Run("valid_duration", func(t *testing.T) {
		s, err := asDurationString("ttl", "5m")
		require.NoError(t, err)
		assert.Equal(t, "5m", s)
	})

	t.Run("invalid_duration", func(t *testing.T) {
		_, err := asDurationString("ttl", "not-a-duration")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid duration")
	})
}

// ---------------------------------------------------------------------------
// findUnresolvedVars
// ---------------------------------------------------------------------------

func TestFindUnresolvedVars(t *testing.T) {
	t.Run("no_placeholders", func(t *testing.T) {
		rest := findUnresolvedVars(`{"a": 1}`)
		assert.Nil(t, rest)
	})

	t.Run("single_unresolved", func(t *testing.T) {
		rest := findUnresolvedVars(`${x}`)
		assert.Equal(t, []string{"x"}, rest)
	})

	t.Run("multiple_deduplicated", func(t *testing.T) {
		rest := findUnresolvedVars(`${x} ${y} ${x}`)
		assert.ElementsMatch(t, []string{"x", "y"}, rest)
	})

	t.Run("none_unresolved", func(t *testing.T) {
		rest := findUnresolvedVars(`{"a": "fixed"}`)
		assert.Nil(t, rest)
	})
}

// ---------------------------------------------------------------------------
// firstOfList
// ---------------------------------------------------------------------------

func TestFirstOfList(t *testing.T) {
	t.Run("empty_string", func(t *testing.T) {
		assert.Equal(t, "", firstOfList(""))
	})

	t.Run("single_item", func(t *testing.T) {
		assert.Equal(t, "abc", firstOfList("abc"))
	})

	t.Run("multiple_items", func(t *testing.T) {
		assert.Equal(t, "abc", firstOfList("abc,def"))
	})

	t.Run("leading_trailing_spaces", func(t *testing.T) {
		assert.Equal(t, "abc", firstOfList("  abc , def "))
	})

	t.Run("only_spaces", func(t *testing.T) {
		assert.Equal(t, "", firstOfList("  ,  "))
	})
}

// ---------------------------------------------------------------------------
// SubstituteVariables (deprecated but still tested for regression)
// ---------------------------------------------------------------------------

func TestSubstituteVariablesExt(t *testing.T) {
	t.Run("basic_substitution", func(t *testing.T) {
		out, err := SubstituteVariables([]byte(`{"key":"${val}"}`), map[string]string{"val": "hello"})
		require.NoError(t, err)
		assert.Equal(t, `{"key":"hello"}`, string(out))
	})

	t.Run("hex_prefix_stripped", func(t *testing.T) {
		out, err := SubstituteVariables([]byte(`{"key":"${hex:addr}"}`), map[string]string{"addr": "0xabc"})
		require.NoError(t, err)
		assert.Equal(t, `{"key":"abc"}`, string(out))
	})

	t.Run("paddedhex", func(t *testing.T) {
		out, err := SubstituteVariables([]byte(`{"key":"${paddedhex:val}"}`), map[string]string{"val": "0x1234"})
		require.NoError(t, err)
		assert.Equal(t, `{"key":"0000000000000000000000000000000000000000000000000000000000001234"}`, string(out))
	})

	t.Run("first_of_list", func(t *testing.T) {
		out, err := SubstituteVariables([]byte(`{"key":"${first:val}"}`), map[string]string{"val": "a,b,c"})
		require.NoError(t, err)
		assert.Equal(t, `{"key":"a"}`, string(out))
	})

	t.Run("hex_first_of_list", func(t *testing.T) {
		out, err := SubstituteVariables([]byte(`{"key":"${hex:first:val}"}`), map[string]string{"val": "0xabc,0xdef"})
		require.NoError(t, err)
		assert.Equal(t, `{"key":"abc"}`, string(out))
	})

	t.Run("multiple_vars", func(t *testing.T) {
		out, err := SubstituteVariables(
			[]byte(`{"a":"${x}","b":"${y}"}`),
			map[string]string{"x": "1", "y": "2"},
		)
		require.NoError(t, err)
		assert.Equal(t, `{"a":"1","b":"2"}`, string(out))
	})

	t.Run("unresolved_vars_error", func(t *testing.T) {
		_, err := SubstituteVariables([]byte(`{"a":"${x}"}`), map[string]string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unresolved variables")
	})

	t.Run("empty_config", func(t *testing.T) {
		out, err := SubstituteVariables([]byte{}, map[string]string{"x": "1"})
		require.NoError(t, err)
		assert.Equal(t, []byte{}, out)
	})
}

// ---------------------------------------------------------------------------
// SubstituteString
// ---------------------------------------------------------------------------

func TestSubstituteString(t *testing.T) {
	t.Run("substitutes_and_returns_string", func(t *testing.T) {
		out, err := SubstituteString("Hello ${name}!", map[string]string{"name": "World"})
		require.NoError(t, err)
		assert.Equal(t, "Hello World!", out)
	})

	t.Run("unresolved_returns_error", func(t *testing.T) {
		_, err := SubstituteString("Hello ${name}!", map[string]string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unresolved variables")
	})
}

// ---------------------------------------------------------------------------
// inlineCompatible
// ---------------------------------------------------------------------------

func TestInlineCompatible(t *testing.T) {
	assert.True(t, inlineCompatible(types.VarTypeAddress))
	assert.True(t, inlineCompatible(types.VarTypeBigInt))
	assert.True(t, inlineCompatible(types.VarTypeString))
	assert.True(t, inlineCompatible(types.VarTypeBytes))
	assert.True(t, inlineCompatible(types.VarTypeBytes4))
	assert.True(t, inlineCompatible(types.VarTypeDuration))
	assert.True(t, inlineCompatible(types.VarTypeEnum))
	assert.False(t, inlineCompatible(types.VarTypeBool))
	assert.False(t, inlineCompatible(types.VarTypeAddressList))
	assert.False(t, inlineCompatible(types.VarTypeBigIntList))
	assert.False(t, inlineCompatible(types.VarTypeJSON))
	assert.False(t, inlineCompatible("unknown"))
}

// ---------------------------------------------------------------------------
// inlineStringForm
// ---------------------------------------------------------------------------

func TestInlineStringForm(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		out, err := inlineStringForm("name", types.VarTypeString, "hello")
		require.NoError(t, err)
		assert.Equal(t, "hello", out)
	})

	t.Run("string_with_embedded_quote", func(t *testing.T) {
		out, err := inlineStringForm("name", types.VarTypeString, `a"b`)
		require.NoError(t, err)
		assert.Equal(t, `a\"b`, out)
	})

	t.Run("bigint_value", func(t *testing.T) {
		out, err := inlineStringForm("cap", types.VarTypeBigInt, "123")
		require.NoError(t, err)
		assert.Equal(t, "123", out)
	})

	t.Run("duration_value", func(t *testing.T) {
		out, err := inlineStringForm("ttl", types.VarTypeDuration, "10s")
		require.NoError(t, err)
		assert.Equal(t, "10s", out)
	})

	t.Run("int_value_converted", func(t *testing.T) {
		out, err := inlineStringForm("num", types.VarTypeString, 42)
		require.NoError(t, err)
		assert.Equal(t, "42", out)
	})
}
