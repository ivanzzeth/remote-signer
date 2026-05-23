package admin

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveKeyType_Empty(t *testing.T) {
	kt, err := resolveKeyType("")
	require.NoError(t, err)
	assert.Equal(t, "ed25519", string(kt))
}

func TestResolveKeyType_Ed25519(t *testing.T) {
	kt, err := resolveKeyType("ed25519")
	require.NoError(t, err)
	assert.Equal(t, "ed25519", string(kt))
}

func TestResolveKeyType_Secp256k1(t *testing.T) {
	kt, err := resolveKeyType("secp256k1")
	require.NoError(t, err)
	assert.Equal(t, "secp256k1", string(kt))
}

func TestResolveKeyType_P256(t *testing.T) {
	kt, err := resolveKeyType("p256")
	require.NoError(t, err)
	assert.Equal(t, "p256", string(kt))
}

func TestResolveKeyType_Invalid(t *testing.T) {
	_, err := resolveKeyType("rsa")
	assert.ErrorContains(t, err, "unsupported key type")
}

func TestParseValue_JSONObject(t *testing.T) {
	v := parseValue(`{"key":"val"}`)
	m, ok := v.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "val", m["key"])
}

func TestParseValue_JSONArray(t *testing.T) {
	v := parseValue(`[1,2,3]`)
	a, ok := v.([]interface{})
	require.True(t, ok)
	assert.Equal(t, 3.0, a[2])
}

func TestParseValue_Bool(t *testing.T) {
	assert.Equal(t, true, parseValue("true"))
	assert.Equal(t, false, parseValue("false"))
}

func TestParseValue_Int(t *testing.T) {
	assert.Equal(t, float64(42), parseValue("42"))
	assert.Equal(t, float64(-1), parseValue("-1"))
}

func TestParseValue_String(t *testing.T) {
	assert.Equal(t, "hello", parseValue("hello"))
	assert.Equal(t, float64(42.5), parseValue("42.5"))
}

func TestSetNested_Simple(t *testing.T) {
	m := map[string]any{}
	err := setNested(m, []string{"key"}, "value")
	require.NoError(t, err)
	assert.Equal(t, "value", m["key"])
}

func TestSetNested_Nested(t *testing.T) {
	m := map[string]any{}
	err := setNested(m, []string{"a", "b", "c"}, "deep")
	require.NoError(t, err)
	assert.Equal(t, "deep", m["a"].(map[string]any)["b"].(map[string]any)["c"])
}

func TestSetNested_OverwriteNonMap(t *testing.T) {
	m := map[string]any{"key": "string"}
	err := setNested(m, []string{"key", "nested"}, "val")
	assert.ErrorContains(t, err, "cannot descend")
}

func TestApplyAssignment_Simple(t *testing.T) {
	m := map[string]any{}
	err := applyAssignment(m, "key=value")
	require.NoError(t, err)
	assert.Equal(t, "value", m["key"])
}

func TestApplyAssignment_Nested(t *testing.T) {
	m := map[string]any{}
	err := applyAssignment(m, "a.b.c=42")
	require.NoError(t, err)
	assert.Equal(t, float64(42), m["a"].(map[string]any)["b"].(map[string]any)["c"])
}

func TestApplyAssignment_Invalid(t *testing.T) {
	m := map[string]any{}
	err := applyAssignment(m, "noequalsign")
	assert.ErrorContains(t, err, "expected key=value")
}

func TestSetStringsToMap_Empty(t *testing.T) {
	assert.Empty(t, setStringsToMap(nil))
	assert.Empty(t, setStringsToMap([]string{}))
}

func TestSetStringsToMap_Single(t *testing.T) {
	m := setStringsToMap([]string{"key=val"})
	assert.Equal(t, "val", m["key"])
}

func TestSetStringsToMap_Multiple(t *testing.T) {
	m := setStringsToMap([]string{"a=1", "b=hello"})
	assert.Equal(t, "1", m["a"])
	assert.Equal(t, "hello", m["b"])
}

func TestSetStringsToMap_ValueWithEquals(t *testing.T) {
	m := setStringsToMap([]string{"key=val=ue"})
	assert.Equal(t, "val=ue", m["key"])
}

func TestEncodeEd25519PrivKeygen(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pem, err := encodeEd25519PrivKeygen(priv)
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(pem), "PRIVATE KEY"))
}

func TestEncodeEd25519PubKeygen(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pem, err := encodeEd25519PubKeygen(pub)
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(pem), "PUBLIC KEY"))
}

func TestQuoteColonStrings_Map(t *testing.T) {
	m := map[string]interface{}{
		"key": "val:ue",
	}
	quoteColonStrings(m)
	_, ok := m["key"].(quotedYAMLString)
	assert.True(t, ok, "value with colon should be quotedYAMLString")
}

func TestQuoteColonStrings_Nested(t *testing.T) {
	m := map[string]interface{}{
		"outer": map[string]interface{}{
			"inner": "http://example.com",
		},
	}
	quoteColonStrings(m)
	inner := m["outer"].(map[string]interface{})["inner"]
	_, ok := inner.(quotedYAMLString)
	assert.True(t, ok, "nested value with colon should be quotedYAMLString")
}

func TestQuoteColonStrings_NoColon(t *testing.T) {
	m := map[string]interface{}{
		"key": "plain",
	}
	quoteColonStrings(m)
	assert.Equal(t, "plain", m["key"])
}

func TestQuoteColonStrings_NilMap(t *testing.T) {
	quoteColonStrings(nil) // should not panic
}

func TestQuoteColonStrings_NonStringValue(t *testing.T) {
	m := map[string]interface{}{
		"num": 42,
	}
	quoteColonStrings(m)
	assert.Equal(t, 42, m["num"])
}
