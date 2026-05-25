package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ---------------------------------------------------------------------------
// Whole-value substitution (placeholder fills the entire string slot)
// ---------------------------------------------------------------------------

func TestSubstituteTyped_BoolBecomesJSONLiteral(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "flag", Type: types.VarTypeBool}}
	cfg := []byte(`{"enabled":"${flag}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{"flag": true})
	require.NoError(t, err)
	assert.JSONEq(t, `{"enabled":true}`, string(out))
}

func TestSubstituteTyped_BoolFalse(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "flag", Type: types.VarTypeBool}}
	cfg := []byte(`{"enabled":"${flag}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{"flag": false})
	require.NoError(t, err)
	assert.JSONEq(t, `{"enabled":false}`, string(out))
}

func TestSubstituteTyped_BoolFromString(t *testing.T) {
	// HTTP request bodies often send everything as strings; the
	// substituter must accept "true"/"false" for bool vars.
	defs := []types.TemplateVariable{{Name: "flag", Type: types.VarTypeBool}}
	cfg := []byte(`{"enabled":"${flag}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{"flag": "true"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"enabled":true}`, string(out))
}

func TestSubstituteTyped_AddressListBecomesArray(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "addrs", Type: types.VarTypeAddressList}}
	cfg := []byte(`{"recipients":"${addrs}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{
		"addrs": []string{"0xabc", "0xdef"},
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"recipients":["0xabc","0xdef"]}`, string(out))
}

func TestSubstituteTyped_AddressListFromAnySlice(t *testing.T) {
	// YAML unmarshalling produces []any, not []string. Cover that path
	// since real callers pass values straight out of yaml.Unmarshal.
	defs := []types.TemplateVariable{{Name: "addrs", Type: types.VarTypeAddressList}}
	cfg := []byte(`{"recipients":"${addrs}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{
		"addrs": []any{"0xabc", "0xdef"},
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"recipients":["0xabc","0xdef"]}`, string(out))
}

func TestSubstituteTyped_AddressListFromCommaString_LegacyFallback(t *testing.T) {
	// Pre-migration presets stored *_list values as comma-separated
	// strings. The substituter still accepts them so an unmigrated
	// preset doesn't break at apply time.
	defs := []types.TemplateVariable{{Name: "addrs", Type: types.VarTypeAddressList}}
	cfg := []byte(`{"recipients":"${addrs}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{"addrs": "0xabc, 0xdef, 0x123"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"recipients":["0xabc","0xdef","0x123"]}`, string(out))
}

func TestSubstituteTyped_AddressListEmpty(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "addrs", Type: types.VarTypeAddressList}}
	cfg := []byte(`{"recipients":"${addrs}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{"addrs": []string{}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"recipients":[]}`, string(out))
}

func TestSubstituteTyped_BigIntListBecomesArray(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "amounts", Type: types.VarTypeBigIntList}}
	cfg := []byte(`{"caps":"${amounts}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{
		"amounts": []string{"100", "200"},
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"caps":["100","200"]}`, string(out))
}

func TestSubstituteTyped_JSONLiteralPassesThrough(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "config", Type: types.VarTypeJSON}}
	cfg := []byte(`{"settings":"${config}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{
		"config": map[string]any{"x": 1, "y": []string{"a", "b"}},
	})
	require.NoError(t, err)
	// JSON equivalence – field order may differ.
	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	settings := got["settings"].(map[string]any)
	assert.EqualValues(t, 1, settings["x"])
	assert.Equal(t, []any{"a", "b"}, settings["y"])
}

// ---------------------------------------------------------------------------
// Inline substitution (placeholder inside a larger string)
// ---------------------------------------------------------------------------

func TestSubstituteTyped_InlineStringValue(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "host", Type: types.VarTypeString}}
	cfg := []byte(`{"url":"https://${host}/api"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{"host": "example.com"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"url":"https://example.com/api"}`, string(out))
}

func TestSubstituteTyped_InlineEscapesEmbeddedQuote(t *testing.T) {
	// JSON-escape correctness: a value containing a quote must not
	// break the surrounding string.
	defs := []types.TemplateVariable{{Name: "label", Type: types.VarTypeString}}
	cfg := []byte(`{"label":"name=${label}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{"label": `alice"bob`})
	require.NoError(t, err)
	// The resulting JSON must parse back.
	var parsed map[string]string
	require.NoError(t, json.Unmarshal(out, &parsed))
	assert.Equal(t, `name=alice"bob`, parsed["label"])
}

func TestSubstituteTyped_InlineBoolRejected(t *testing.T) {
	// You can't use a bool inline — the resulting JSON would be
	// malformed ("...true..." is not what the user wants and we'd
	// rather surface a clear error than silently produce nonsense.
	defs := []types.TemplateVariable{{Name: "flag", Type: types.VarTypeBool}}
	cfg := []byte(`{"note":"flag is ${flag} now"}`)
	_, err := SubstituteTyped(cfg, defs, map[string]any{"flag": true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be used inline")
}

func TestSubstituteTyped_InlineListRejected(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "addrs", Type: types.VarTypeAddressList}}
	cfg := []byte(`{"summary":"got ${addrs} addresses"}`)
	_, err := SubstituteTyped(cfg, defs, map[string]any{"addrs": []string{"0x1"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "address_list")
}

// ---------------------------------------------------------------------------
// Bigint / duration
// ---------------------------------------------------------------------------

func TestSubstituteTyped_BigIntValidates(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "cap", Type: types.VarTypeBigInt}}
	cfg := []byte(`{"max":"${cap}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{"cap": "1000000000000000000"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"max":"1000000000000000000"}`, string(out))
}

func TestSubstituteTyped_BigIntSentinelMinusOne(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "cap", Type: types.VarTypeBigInt}}
	cfg := []byte(`{"max":"${cap}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{"cap": "-1"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"max":"-1"}`, string(out))
}

func TestSubstituteTyped_BigIntRejectsGarbage(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "cap", Type: types.VarTypeBigInt}}
	cfg := []byte(`{"max":"${cap}"}`)
	_, err := SubstituteTyped(cfg, defs, map[string]any{"cap": "nope"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid bigint")
}

func TestSubstituteTyped_DurationValidates(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "ttl", Type: types.VarTypeDuration}}
	cfg := []byte(`{"timeout":"${ttl}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{"ttl": "30s"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"timeout":"30s"}`, string(out))
}

func TestSubstituteTyped_DurationRejectsBad(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "ttl", Type: types.VarTypeDuration}}
	cfg := []byte(`{"timeout":"${ttl}"}`)
	_, err := SubstituteTyped(cfg, defs, map[string]any{"ttl": "30 days"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid duration")
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

func TestSubstituteTyped_UnresolvedReported(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "x", Type: types.VarTypeString}}
	cfg := []byte(`{"a":"${x}","b":"${y}","c":"${y}"}`) // y appears twice — dedupe
	_, err := SubstituteTyped(cfg, defs, map[string]any{"x": "ok"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unresolved variables: y")
	assert.False(t, strings.Contains(err.Error(), "y, y"), "duplicate names deduped")
}

func TestSubstituteTyped_NilConfigPassesThrough(t *testing.T) {
	out, err := SubstituteTyped(nil, nil, nil)
	require.NoError(t, err)
	assert.Nil(t, out)
}

func TestSubstituteTyped_NoPlaceholdersIsIdentity(t *testing.T) {
	cfg := []byte(`{"static":"value"}`)
	out, err := SubstituteTyped(cfg, nil, nil)
	require.NoError(t, err)
	assert.JSONEq(t, string(cfg), string(out))
}

func TestSubstituteTyped_ReservedVarFallsBackToString(t *testing.T) {
	// chain_id is auto-injected from rule scope; not declared in defs
	// but must still substitute. Reserved vars get the string treatment.
	cfg := []byte(`{"chain":"${chain_id}"}`)
	out, err := SubstituteTyped(cfg, nil, map[string]any{"chain_id": "137"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"chain":"137"}`, string(out))
}

// ---------------------------------------------------------------------------
// Whole-value + inline mix
// ---------------------------------------------------------------------------

func TestSubstituteTyped_MixedSubstitutions(t *testing.T) {
	defs := []types.TemplateVariable{
		{Name: "to", Type: types.VarTypeAddress},
		{Name: "amounts", Type: types.VarTypeBigIntList},
		{Name: "enabled", Type: types.VarTypeBool},
		{Name: "label", Type: types.VarTypeString},
	}
	cfg := []byte(`{
		"to":"${to}",
		"caps":"${amounts}",
		"on":"${enabled}",
		"tag":"${label}-suffix"
	}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{
		"to":      "0xabc",
		"amounts": []string{"100", "200"},
		"enabled": true,
		"label":   "v2",
	})
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	assert.Equal(t, "0xabc", got["to"])
	assert.Equal(t, []any{"100", "200"}, got["caps"])
	assert.Equal(t, true, got["on"])
	assert.Equal(t, "v2-suffix", got["tag"])
}

// ---------------------------------------------------------------------------
// jsonEncodeTyped — remaining paths
// ---------------------------------------------------------------------------

func TestJsonEncodeTyped_BoolRejectsNonBoolString(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "flag", Type: types.VarTypeBool}}
	cfg := []byte(`{"enabled":"${flag}"}`)
	_, err := SubstituteTyped(cfg, defs, map[string]any{"flag": "notabool"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a bool")
}

func TestJsonEncodeTyped_BoolRejectsNonBoolInt(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "flag", Type: types.VarTypeBool}}
	cfg := []byte(`{"enabled":"${flag}"}`)
	_, err := SubstituteTyped(cfg, defs, map[string]any{"flag": 42})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot coerce int to bool")
}

func TestJsonEncodeTyped_UnknownTypeReturnsError(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "x", Type: types.VariableType("unknown_type")}}
	cfg := []byte(`{"val":"${x}"}`)
	_, err := SubstituteTyped(cfg, defs, map[string]any{"x": "hello"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown type")
}

func TestJsonEncodeTyped_VarTypeBytes(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "sig", Type: types.VarTypeBytes}}
	cfg := []byte(`{"signature":"${sig}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{"sig": "0xabcdef"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"signature":"0xabcdef"}`, string(out))
}

func TestJsonEncodeTyped_VarTypeBytes4(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "selector", Type: types.VarTypeBytes4}}
	cfg := []byte(`{"selector":"${selector}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{"selector": "0xa9059cbb"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"selector":"0xa9059cbb"}`, string(out))
}

func TestJsonEncodeTyped_VarTypeEnum(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "network", Type: types.VarTypeEnum}}
	cfg := []byte(`{"network":"${network}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{"network": "mainnet"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"network":"mainnet"}`, string(out))
}

// ---------------------------------------------------------------------------
// inlineStringForm — remaining paths
// ---------------------------------------------------------------------------

func TestSubstituteTyped_InlineBigIntValue(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "amount", Type: types.VarTypeBigInt}}
	cfg := []byte(`{"tag":"amount=${amount}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{"amount": "1000000000000000000"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"tag":"amount=1000000000000000000"}`, string(out))
}

func TestSubstituteTyped_InlineDurationValue(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "ttl", Type: types.VarTypeDuration}}
	cfg := []byte(`{"header":"Cache-Control: max-age=${ttl}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{"ttl": "3600s"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"header":"Cache-Control: max-age=3600s"}`, string(out))
}

func TestSubstituteTyped_InlineBigIntSentinel(t *testing.T) {
	defs := []types.TemplateVariable{{Name: "cap", Type: types.VarTypeBigInt}}
	cfg := []byte(`{"value":"max=${cap}"}`)
	out, err := SubstituteTyped(cfg, defs, map[string]any{"cap": "-1"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"value":"max=-1"}`, string(out))
}
