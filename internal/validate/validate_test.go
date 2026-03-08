package validate

import (
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/stretchr/testify/assert"
)

// ─────────────────────────────────────────────────────────────────────────────
// IsValidEthereumAddress
// ─────────────────────────────────────────────────────────────────────────────

func TestIsValidEthereumAddress(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Valid addresses
		{"valid lowercase", "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", true},
		{"valid uppercase", "0xF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266", true},
		{"valid mixed case (checksum)", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", true},
		{"valid zero address", "0x0000000000000000000000000000000000000000", true},
		{"valid all-F address", "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", true},

		// Invalid addresses
		{"empty string", "", false},
		{"no 0x prefix", "f39fd6e51aad88f6f4ce6ab8827279cfffb92266", false},
		{"too short", "0xf39fd6e51aad88f6f4ce6ab8827279cfffb9226", false},
		{"too long", "0xf39fd6e51aad88f6f4ce6ab8827279cfffb922660", false},
		{"invalid hex char g", "0xg39fd6e51aad88f6f4ce6ab8827279cfffb92266", false},
		{"invalid hex char z", "0xz00000000000000000000000000000000000000ff", false},
		{"only 0x", "0x", false},
		{"capital 0X prefix", "0XF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266", false},
		{"spaces", " 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266 ", false},
		{"newline", "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266\n", false},
		{"random string", "hello", false},
		{"0x only", "0x0", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsValidEthereumAddress(tc.input)
			assert.Equal(t, tc.want, got, "IsValidEthereumAddress(%q)", tc.input)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IsValidWeiDecimal
// ─────────────────────────────────────────────────────────────────────────────

func TestIsValidWeiDecimal(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Valid
		{"zero", "0", true},
		{"small number", "100", true},
		{"large number", "1000000000000000000", true},
		{"very large", "999999999999999999999999999999", true},
		{"single digit", "5", true},

		// Invalid
		{"empty string", "", false},
		{"whitespace only", "   ", false},
		{"hex prefix", "0x100", false},
		{"negative", "-100", false},
		{"decimal point", "1.5", false},
		{"scientific notation", "1e18", false},
		{"letters", "abc", false},
		{"mixed", "100abc", false},
		{"leading space trimmed valid", " 100", true},   // TrimSpace → "100" → valid
		{"trailing space trimmed valid", "100 ", true}, // TrimSpace → "100" → valid
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsValidWeiDecimal(tc.input)
			assert.Equal(t, tc.want, got, "IsValidWeiDecimal(%q)", tc.input)
		})
	}

	// Spaces around digits are trimmed, so these pass
	assert.True(t, IsValidWeiDecimal(" 100 "), "trimmed '100' should be valid")
	// Tab/mixed whitespace
	assert.True(t, IsValidWeiDecimal("\t42\t"), "trimmed tab-wrapped '42' should be valid")
}

// ─────────────────────────────────────────────────────────────────────────────
// NormalizeRuleType
// ─────────────────────────────────────────────────────────────────────────────

func TestNormalizeRuleType(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"legacy address whitelist", "evm_address_whitelist", "evm_address_list"},
		{"already canonical address list", "evm_address_list", "evm_address_list"},
		{"other types pass through", "evm_contract_method", "evm_contract_method"},
		{"evm_js passthrough", "evm_js", "evm_js"},
		{"evm_solidity_expression passthrough", "evm_solidity_expression", "evm_solidity_expression"},
		{"empty string", "", ""},
		{"unknown type", "some_unknown_type", "some_unknown_type"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeRuleType(tc.input)
			assert.Equal(t, tc.expect, got)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidateRuleMode
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateRuleMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		wantErr bool
		errMsg  string
	}{
		{"whitelist valid", "whitelist", false, ""},
		{"blocklist valid", "blocklist", false, ""},
		{"empty string", "", true, "mode is required"},
		{"invalid mode", "greylist", true, "mode must be whitelist or blocklist"},
		{"case sensitive - Whitelist", "Whitelist", true, "mode must be whitelist or blocklist"},
		{"random", "foo", true, "mode must be whitelist or blocklist"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRuleMode(tc.mode)
			if tc.wantErr {
				assert.Error(t, err)
				if tc.errMsg != "" {
					assert.Contains(t, err.Error(), tc.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IsValidChainType
// ─────────────────────────────────────────────────────────────────────────────

func TestIsValidChainType(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"evm", "evm", true},
		{"solana", "solana", true},
		{"cosmos", "cosmos", true},
		{"empty", "", false},
		{"uppercase EVM", "EVM", false},
		{"unknown", "bitcoin", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsValidChainType(tc.input))
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IsValidRuleType
// ─────────────────────────────────────────────────────────────────────────────

func TestIsValidRuleType(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"signer_restriction", "signer_restriction", true},
		{"chain_restriction", "chain_restriction", true},
		{"sign_type_restriction", "sign_type_restriction", true},
		{"message_pattern", "message_pattern", true},
		{"evm_address_list", "evm_address_list", true},
		{"evm_contract_method", "evm_contract_method", true},
		{"evm_value_limit", "evm_value_limit", true},
		{"evm_solidity_expression", "evm_solidity_expression", true},
		{"evm_js", "evm_js", true},
		// Legacy alias
		{"legacy evm_address_whitelist normalizes", "evm_address_whitelist", true},
		// Invalid
		{"empty", "", false},
		{"unknown", "bitcoin_rule", false},
		{"uppercase", "EVM_JS", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsValidRuleType(tc.input))
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IsValidRuleSource
// ─────────────────────────────────────────────────────────────────────────────

func TestIsValidRuleSource(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"config", "config", true},
		{"api", "api", true},
		{"auto_generated", "auto_generated", true},
		{"instance", "instance", true},
		{"empty", "", false},
		{"unknown", "manual", false},
		{"uppercase", "CONFIG", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsValidRuleSource(tc.input))
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IsValidAuditEventType
// ─────────────────────────────────────────────────────────────────────────────

func TestIsValidAuditEventType(t *testing.T) {
	validTypes := []string{
		"auth_success", "auth_failure", "sign_request", "sign_complete",
		"sign_failed", "sign_rejected", "rule_matched", "approval_request",
		"approval_granted", "approval_denied", "rule_created", "rule_updated",
		"rule_deleted", "rate_limit_hit",
	}

	for _, vt := range validTypes {
		t.Run("valid_"+vt, func(t *testing.T) {
			assert.True(t, IsValidAuditEventType(vt), "expected %q to be valid", vt)
		})
	}

	invalidTypes := []string{"", "unknown", "SIGN_REQUEST", "login"}
	for _, it := range invalidTypes {
		t.Run("invalid_"+it, func(t *testing.T) {
			assert.False(t, IsValidAuditEventType(it), "expected %q to be invalid", it)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IsValidSignerType
// ─────────────────────────────────────────────────────────────────────────────

func TestIsValidSignerType(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"private_key", "private_key", true},
		{"keystore", "keystore", true},
		{"empty", "", false},
		{"unknown", "hardware", false},
		{"uppercase", "PRIVATE_KEY", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsValidSignerType(tc.input))
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidSignTypes map coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestValidSignTypes(t *testing.T) {
	expected := []string{"personal", "typed_data", "transaction", "hash", "raw_message", "eip191"}
	for _, st := range expected {
		assert.True(t, ValidSignTypes[st], "expected %q in ValidSignTypes", st)
	}
	assert.False(t, ValidSignTypes["unknown"])
	assert.False(t, ValidSignTypes[""])
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidRuleModes map coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestValidRuleModes(t *testing.T) {
	assert.True(t, ValidRuleModes["whitelist"])
	assert.True(t, ValidRuleModes["blocklist"])
	assert.False(t, ValidRuleModes["greylist"])
	assert.False(t, ValidRuleModes[""])
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidChainTypes map coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestValidChainTypes(t *testing.T) {
	assert.True(t, ValidChainTypes["evm"])
	assert.True(t, ValidChainTypes["solana"])
	assert.True(t, ValidChainTypes["cosmos"])
	assert.False(t, ValidChainTypes["bitcoin"])
	assert.False(t, ValidChainTypes[""])
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidRuleTypes map coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestValidRuleTypes(t *testing.T) {
	expectedTypes := []string{
		"signer_restriction", "chain_restriction", "sign_type_restriction",
		"message_pattern", "evm_address_list", "evm_contract_method",
		"evm_value_limit", "evm_solidity_expression", "evm_js",
	}
	for _, rt := range expectedTypes {
		assert.True(t, ValidRuleTypes[types.RuleType(rt)], "expected %q in ValidRuleTypes", rt)
	}
	assert.False(t, ValidRuleTypes[types.RuleType("evm_address_whitelist")]) // legacy name NOT in canonical set
	assert.Equal(t, 9, len(ValidRuleTypes), "expected exactly 9 valid rule types")
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidRuleSources map coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestValidRuleSources(t *testing.T) {
	expected := []string{"config", "api", "auto_generated", "instance"}
	for _, rs := range expected {
		assert.True(t, ValidRuleSources[types.RuleSource(rs)], "expected %q in ValidRuleSources", rs)
	}
	assert.Equal(t, 4, len(ValidRuleSources))
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidAuditEventTypes map size check
// ─────────────────────────────────────────────────────────────────────────────

func TestValidAuditEventTypes_Count(t *testing.T) {
	assert.Equal(t, 15, len(ValidAuditEventTypes), "expected 15 audit event types")
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidSignerTypes map coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestValidSignerTypes_Map(t *testing.T) {
	assert.True(t, ValidSignerTypes["private_key"])
	assert.True(t, ValidSignerTypes["keystore"])
	assert.True(t, ValidSignerTypes["hd_wallet"])
	assert.Equal(t, 3, len(ValidSignerTypes))
}
