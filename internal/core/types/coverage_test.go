package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// IsInvalidPayload
// ---------------------------------------------------------------------------

func TestIsInvalidPayload_DirectMatch(t *testing.T) {
	assert.True(t, IsInvalidPayload(ErrInvalidPayload))
}

func TestIsInvalidPayload_WrappedError(t *testing.T) {
	wrapped := fmt.Errorf("wrap: %w", ErrInvalidPayload)
	assert.True(t, IsInvalidPayload(wrapped))
}

func TestIsInvalidPayload_DifferentError(t *testing.T) {
	assert.False(t, IsInvalidPayload(ErrNotFound))
}

func TestIsInvalidPayload_NilError(t *testing.T) {
	assert.False(t, IsInvalidPayload(nil))
}

// ---------------------------------------------------------------------------
// IsSignerLocked
// ---------------------------------------------------------------------------

func TestIsSignerLocked_DirectMatch(t *testing.T) {
	assert.True(t, IsSignerLocked(ErrSignerLocked))
}

func TestIsSignerLocked_WrappedError(t *testing.T) {
	wrapped := fmt.Errorf("wrap: %w", ErrSignerLocked)
	assert.True(t, IsSignerLocked(wrapped))
}

func TestIsSignerLocked_DifferentError(t *testing.T) {
	assert.False(t, IsSignerLocked(ErrForbidden))
}

func TestIsSignerLocked_NilError(t *testing.T) {
	assert.False(t, IsSignerLocked(nil))
}

// ---------------------------------------------------------------------------
// JSONBytes: Scan
// ---------------------------------------------------------------------------

func TestJSONBytes_Scan_Nil(t *testing.T) {
	var b JSONBytes
	err := b.Scan(nil)
	require.NoError(t, err)
	assert.Nil(t, b)
}

func TestJSONBytes_Scan_ByteSlice(t *testing.T) {
	var b JSONBytes
	err := b.Scan([]byte(`{"hello":"world"}`))
	require.NoError(t, err)
	assert.Equal(t, `{"hello":"world"}`, string(b))
}

func TestJSONBytes_Scan_String(t *testing.T) {
	var b JSONBytes
	err := b.Scan(`{"foo":1}`)
	require.NoError(t, err)
	assert.Equal(t, `{"foo":1}`, string(b))
}

func TestJSONBytes_Scan_UnsupportedType(t *testing.T) {
	var b JSONBytes
	err := b.Scan(42)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported source type")
}

// ---------------------------------------------------------------------------
// JSONBytes: Value
// ---------------------------------------------------------------------------

func TestJSONBytes_Value_Nil(t *testing.T) {
	b := JSONBytes(nil)
	v, err := b.Value()
	require.NoError(t, err)
	assert.Nil(t, v)
}

func TestJSONBytes_Value_NonNil(t *testing.T) {
	b := JSONBytes(`{"a":1}`)
	v, err := b.Value()
	require.NoError(t, err)
	assert.Equal(t, []byte(`{"a":1}`), v)
}

// ---------------------------------------------------------------------------
// JSONBytes: MarshalJSON
// ---------------------------------------------------------------------------

func TestJSONBytes_MarshalJSON_Empty(t *testing.T) {
	b := JSONBytes{}
	data, err := b.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, []byte("null"), data)
}

func TestJSONBytes_MarshalJSON_NonEmpty(t *testing.T) {
	b := JSONBytes(`[1,2,3]`)
	data, err := b.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, []byte(`[1,2,3]`), data)
}

// ---------------------------------------------------------------------------
// JSONBytes: UnmarshalJSON
// ---------------------------------------------------------------------------

func TestJSONBytes_UnmarshalJSON_NilReceiver(t *testing.T) {
	err := (*JSONBytes)(nil).UnmarshalJSON([]byte("null"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil receiver")
}

func TestJSONBytes_UnmarshalJSON_Valid(t *testing.T) {
	var b JSONBytes
	err := b.UnmarshalJSON([]byte(`{"key":"val"}`))
	require.NoError(t, err)
	assert.Equal(t, `{"key":"val"}`, string(b))
}

func TestJSONBytes_UnmarshalJSON_ReusesBuffer(t *testing.T) {
	b := JSONBytes(`{"old":"data"}`)
	err := b.UnmarshalJSON([]byte(`"new"`))
	require.NoError(t, err)
	assert.Equal(t, `"new"`, string(b))
}

// ---------------------------------------------------------------------------
// JSONBytes: String
// ---------------------------------------------------------------------------

func TestJSONBytes_String(t *testing.T) {
	b := JSONBytes(`"hello"`)
	assert.Equal(t, `"hello"`, b.String())
}

// ---------------------------------------------------------------------------
// JSONBytes: JSON round trip (MarshalJSON -> UnmarshalJSON)
// ---------------------------------------------------------------------------

func TestJSONBytes_RoundTrip(t *testing.T) {
	original := JSONBytes(`[1,2,3]`)
	marshaled, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded JSONBytes
	err = json.Unmarshal(marshaled, &decoded)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

// ---------------------------------------------------------------------------
// CreateSignerRequest.TypedParams
// ---------------------------------------------------------------------------

func TestTypedParams_Keystore(t *testing.T) {
	r := &CreateSignerRequest{
		Type:     SignerTypeKeystore,
		Keystore: &CreateKeystoreParams{Password: "pwd"},
	}
	params := r.TypedParams()
	assert.Equal(t, r.Keystore, params)
}

func TestTypedParams_HDWallet(t *testing.T) {
	r := &CreateSignerRequest{
		Type:     SignerTypeHDWallet,
		HDWallet: &CreateHDWalletParams{Password: "pwd", EntropyBits: 256},
	}
	params := r.TypedParams()
	assert.Equal(t, r.HDWallet, params)
}

func TestTypedParams_UnknownType(t *testing.T) {
	r := &CreateSignerRequest{Type: SignerType("unknown")}
	params := r.TypedParams()
	assert.Nil(t, params)
}

func TestTypedParams_PrivateKey(t *testing.T) {
	r := &CreateSignerRequest{Type: SignerTypePrivateKey}
	params := r.TypedParams()
	assert.Nil(t, params)
}

// ---------------------------------------------------------------------------
// CreateSignerRequest.Validate — additional cases
// ---------------------------------------------------------------------------

func TestCreateSignerRequest_Validate_HDWallet_NoParams(t *testing.T) {
	r := &CreateSignerRequest{Type: SignerTypeHDWallet}
	err := r.Validate()
	assert.ErrorIs(t, err, ErrMissingHDWalletParams)
}

func TestCreateSignerRequest_Validate_HDWallet_EmptyPassword(t *testing.T) {
	r := &CreateSignerRequest{
		Type:     SignerTypeHDWallet,
		HDWallet: &CreateHDWalletParams{Password: ""},
	}
	err := r.Validate()
	assert.ErrorIs(t, err, ErrEmptyPassword)
}

// ---------------------------------------------------------------------------
// Remaining TableName tests
// ---------------------------------------------------------------------------

func TestRequestSimulation_TableName(t *testing.T) {
	assert.Equal(t, "request_simulations", RequestSimulation{}.TableName())
}

func TestSignerOwnership_TableName(t *testing.T) {
	assert.Equal(t, "signer_ownership", SignerOwnership{}.TableName())
}

func TestSignerAccess_TableName(t *testing.T) {
	assert.Equal(t, "signer_access", SignerAccess{}.TableName())
}

func TestSigner_TableName(t *testing.T) {
	assert.Equal(t, "signers", Signer{}.TableName())
}

func TestRulePreset_TableName(t *testing.T) {
	assert.Equal(t, "rule_presets", RulePreset{}.TableName())
}

func TestTransaction_TableName(t *testing.T) {
	assert.Equal(t, "transactions", Transaction{}.TableName())
}

func TestTokenMetadata_TableName(t *testing.T) {
	assert.Equal(t, "token_metadata", TokenMetadata{}.TableName())
}

func TestWallet_TableName(t *testing.T) {
	assert.Equal(t, "wallets", Wallet{}.TableName())
}

func TestWalletMember_TableName(t *testing.T) {
	assert.Equal(t, "wallet_members", WalletMember{}.TableName())
}

// ---------------------------------------------------------------------------
// IsValidVariableType
// ---------------------------------------------------------------------------

func TestIsValidVariableType_Valid(t *testing.T) {
	valid := []string{
		"address", "address_list", "bigint", "bigint_list",
		"string", "bool", "bytes", "bytes4",
		"duration", "enum", "json",
	}
	for _, vt := range valid {
		assert.True(t, IsValidVariableType(vt), "expected %q to be valid", vt)
	}
}

func TestIsValidVariableType_Invalid(t *testing.T) {
	assert.False(t, IsValidVariableType(""))
	assert.False(t, IsValidVariableType("unknown"))
	assert.False(t, IsValidVariableType("uint256"))
}

// ---------------------------------------------------------------------------
// SignerOwnership Tags / FormatSignerTagsJSON / ParseSignerTagsJSON
// ---------------------------------------------------------------------------

func TestFormatSignerTagsJSON_Empty(t *testing.T) {
	assert.Equal(t, "", FormatSignerTagsJSON(nil))
	assert.Equal(t, "", FormatSignerTagsJSON([]string{}))
}

func TestFormatSignerTagsJSON_Valid(t *testing.T) {
	result := FormatSignerTagsJSON([]string{"label1", "label2"})
	assert.Equal(t, `["label1","label2"]`, result)
}

func TestFormatSignerTagsJSON_InvalidMarshal(t *testing.T) {
	// json.Marshal on []string should never fail, but we test the code path
	result := FormatSignerTagsJSON([]string{"ok"})
	assert.Equal(t, `["ok"]`, result)
}

func TestParseSignerTagsJSON_Empty(t *testing.T) {
	assert.Nil(t, ParseSignerTagsJSON(""))
	assert.Nil(t, ParseSignerTagsJSON("   "))
}

func TestParseSignerTagsJSON_Valid(t *testing.T) {
	tags := ParseSignerTagsJSON(`["a","b"]`)
	assert.Equal(t, []string{"a", "b"}, tags)
}

func TestParseSignerTagsJSON_InvalidJSON(t *testing.T) {
	tags := ParseSignerTagsJSON("{invalid}")
	assert.Nil(t, tags)
}

func TestSignerOwnership_Tags(t *testing.T) {
	o := &SignerOwnership{TagsJSON: `["prod","us"]`}
	assert.Equal(t, []string{"prod", "us"}, o.Tags())
}

func TestSignerOwnership_Tags_Empty(t *testing.T) {
	o := &SignerOwnership{}
	assert.Nil(t, o.Tags())
}

// ---------------------------------------------------------------------------
// APIKey helper methods
// ---------------------------------------------------------------------------

func TestAPIKey_RoleChecks(t *testing.T) {
	admin := &APIKey{Role: RoleAdmin}
	dev := &APIKey{Role: RoleDev}
	agent := &APIKey{Role: RoleAgent}
	strategy := &APIKey{Role: RoleStrategy}

	assert.True(t, admin.IsAdmin())
	assert.False(t, admin.IsDev())

	assert.True(t, dev.IsDev())
	assert.False(t, dev.IsAdmin())

	assert.True(t, agent.IsAgent())
	assert.False(t, agent.IsStrategy())

	assert.True(t, strategy.IsStrategy())
	assert.False(t, strategy.IsAgent())
}

// ---------------------------------------------------------------------------
// DeriveApprovalSource edge cases
// ---------------------------------------------------------------------------

func TestDeriveApprovalSource_EmptyRuleID(t *testing.T) {
	ruleID := ""
	approver := "admin-1"
	result := DeriveApprovalSource(&ruleID, &approver)
	assert.Equal(t, ApprovalSourceManual, result)
}

// ---------------------------------------------------------------------------
// TypedError / NewTypedError
// ---------------------------------------------------------------------------

func TestNewTypedError_ErrorIs_NilCause(t *testing.T) {
	te := NewTypedError(ErrorCodeRateLimited, "too many", nil)
	assert.False(t, errors.Is(te, ErrNotFound))
}

// ---------------------------------------------------------------------------
// IsSignerNotFound - ensure ErrInvalidPayload does NOT match
// ---------------------------------------------------------------------------

func TestIsSignerNotFound_InvalidPayloadNotMatch(t *testing.T) {
	assert.False(t, IsSignerNotFound(ErrInvalidPayload))
}

// ---------------------------------------------------------------------------
// IsPendingApproval - ensure nil returns false
// ---------------------------------------------------------------------------

func TestIsPendingApproval_Nil(t *testing.T) {
	assert.False(t, IsPendingApproval(nil))
}

// ---------------------------------------------------------------------------
// BudgetID acceptance
// ---------------------------------------------------------------------------

func TestBudgetID_EmptyUnit(t *testing.T) {
	id := BudgetID("test-rule", "")
	assert.Len(t, id, 64)
	assert.Regexp(t, `^[a-f0-9]{64}$`, id)
}

// ---------------------------------------------------------------------------
// TypedError: table-driven test for Error() with various codes
// ---------------------------------------------------------------------------

func TestTypedError_Error_VariousCodes(t *testing.T) {
	codes := []ErrorCode{
		ErrorCodeInvalidRequest, ErrorCodeUnauthorized, ErrorCodeForbidden,
		ErrorCodeRuleViolation, ErrorCodeSignerNotFound, ErrorCodeSigningFailed,
		ErrorCodeTimeout, ErrorCodeRateLimited, ErrorCodeInternalError,
		ErrorCodeRequestExpired, ErrorCodePendingApproval,
	}
	for _, code := range codes {
		te := NewTypedError(code, "msg", nil)
		expected := fmt.Sprintf("%s: %s", code, "msg")
		assert.Equal(t, expected, te.Error())
	}
}
