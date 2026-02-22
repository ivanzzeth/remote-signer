package evm

import (
	"strings"
	"testing"
)

// =============================================================================
// Solidity Template Injection Attack Tests
//
// These tests verify that attacker-controlled EIP-712 typed data fields
// cannot inject Solidity code into the generated evaluation scripts.
// Each test simulates a specific attack vector and verifies it is blocked.
// =============================================================================

// TestAttack_FieldNameInjection verifies that malicious field NAMES in EIP-712
// types cannot inject Solidity code. The attacker tries to close the current
// function and inject a new one via the field name.
func TestAttack_FieldNameInjection(t *testing.T) {
	attacks := []struct {
		name      string
		fieldName string
	}{
		{
			name:      "function injection via field name",
			fieldName: `x; } function evil() public { revert("pwned"); } function f() pure public { uint256 y`,
		},
		{
			name:      "semicolon breakout",
			fieldName: `x; uint256 injected = 1; uint256 y`,
		},
		{
			name:      "assembly injection",
			fieldName: `x; assembly { invalid() } uint256 y`,
		},
		{
			name:      "newline injection",
			fieldName: "x\nuint256 injected = 1;\nuint256 y",
		},
	}

	for _, tt := range attacks {
		t.Run(tt.name, func(t *testing.T) {
			decl := generateFieldDeclaration(tt.fieldName, "uint256", "42")

			// The declaration must NOT contain the raw attack payload as executable code.
			// It should either be empty (skipped) or be a safe comment.
			if strings.Contains(decl, "evil()") ||
				strings.Contains(decl, "injected") ||
				strings.Contains(decl, "assembly") ||
				strings.Contains(decl, "invalid()") {
				t.Errorf("VULNERABILITY: field name injection succeeded!\nInput name: %q\nGenerated: %s", tt.fieldName, decl)
			}

			// Must not contain raw semicolons from the attack (other than the trailing one)
			parts := strings.Split(decl, ";")
			if len(parts) > 2 { // one ; for statement end, one for trailing empty
				t.Errorf("VULNERABILITY: multiple statements generated from single field!\nInput name: %q\nGenerated: %s", tt.fieldName, decl)
			}
		})
	}
}

// TestAttack_FieldTypeInjection verifies that malicious field TYPES in EIP-712
// types cannot inject Solidity code. The attacker exploits the HasPrefix("uint")
// check by sending a type like "uint256; assembly { invalid() } uint256".
func TestAttack_FieldTypeInjection(t *testing.T) {
	attacks := []struct {
		name      string
		fieldType string
	}{
		{
			name:      "uint prefix with assembly injection",
			fieldType: "uint256; assembly { invalid() } uint256",
		},
		{
			name:      "int prefix with function injection",
			fieldType: `int256; } function evil() public { } function f() pure public { int256`,
		},
		{
			name:      "bytes prefix with code injection",
			fieldType: "bytes32; uint256 injected = 1; bytes32",
		},
		{
			name:      "uint with newline injection",
			fieldType: "uint256\nuint256 injected = 1;\nuint256",
		},
	}

	for _, tt := range attacks {
		t.Run(tt.name, func(t *testing.T) {
			decl := generateFieldDeclaration("safeField", tt.fieldType, "42")

			// Must not contain injected code
			if strings.Contains(decl, "assembly") ||
				strings.Contains(decl, "evil()") ||
				strings.Contains(decl, "injected") ||
				strings.Contains(decl, "invalid()") {
				t.Errorf("VULNERABILITY: field type injection succeeded!\nInput type: %q\nGenerated: %s", tt.fieldType, decl)
			}

			// Must not produce multiple statements
			parts := strings.Split(decl, ";")
			if len(parts) > 2 {
				t.Errorf("VULNERABILITY: multiple statements generated from single field!\nInput type: %q\nGenerated: %s", tt.fieldType, decl)
			}
		})
	}
}

// TestAttack_CommentBreakout verifies that the "// Skipped field" default branch
// cannot be exploited via newline injection in the type or name.
func TestAttack_CommentBreakout(t *testing.T) {
	attacks := []struct {
		name      string
		fieldName string
		fieldType string
	}{
		{
			name:      "newline in type breaks out of comment",
			fieldName: "x",
			fieldType: "CustomStruct\nuint256 public injected = 1;\n//",
		},
		{
			name:      "newline in name breaks out of comment",
			fieldName: "x\nuint256 public injected = 1;\n//",
			fieldType: "CustomStruct",
		},
		{
			name:      "carriage return in type",
			fieldName: "x",
			fieldType: "CustomStruct\r\nuint256 injected = 1;\r\n//",
		},
	}

	for _, tt := range attacks {
		t.Run(tt.name, func(t *testing.T) {
			decl := generateFieldDeclaration(tt.fieldName, tt.fieldType, "test")

			// Must not contain injected code outside of a comment
			lines := strings.Split(decl, "\n")
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" {
					continue
				}
				// Every line must be a comment or empty
				if !strings.HasPrefix(trimmed, "//") {
					t.Errorf("VULNERABILITY: comment breakout succeeded!\nInput name: %q\nInput type: %q\nGenerated:\n%s\nNon-comment line: %q",
						tt.fieldName, tt.fieldType, decl, line)
				}
			}
		})
	}
}

// TestAttack_GenerateMessageFieldDeclarations_MapKeyInjection verifies that
// when field names come from the message map keys (fallback path), they are
// also validated as proper identifiers.
func TestAttack_GenerateMessageFieldDeclarations_MapKeyInjection(t *testing.T) {
	typedData := &TypedDataPayload{
		PrimaryType: "Custom",
		Types:       map[string][]TypedDataField{}, // Empty — triggers fallback path
		Domain:      TypedDataDomain{Name: "Test", Version: "1"},
		Message: map[string]interface{}{
			"x; } function attack() public { revert(); } function f() pure public { uint256 y": "42",
		},
	}

	result := generateMessageFieldDeclarations(typedData)

	// The result must not contain the attack payload as executable code
	if strings.Contains(result, "attack()") ||
		strings.Contains(result, "revert()") {
		t.Errorf("VULNERABILITY: map key injection via fallback path!\nGenerated:\n%s", result)
	}
}

// TestAttack_GenerateMessageFieldDeclarations_TypeFromRequest verifies that
// field types from the request types array are validated.
func TestAttack_GenerateMessageFieldDeclarations_TypeFromRequest(t *testing.T) {
	typedData := &TypedDataPayload{
		PrimaryType: "Evil",
		Types: map[string][]TypedDataField{
			"Evil": {
				{Name: "x", Type: "uint256; assembly { invalid() } uint256"},
			},
		},
		Domain:  TypedDataDomain{Name: "Test", Version: "1"},
		Message: map[string]interface{}{"x": "1"},
	}

	result := generateMessageFieldDeclarations(typedData)

	if strings.Contains(result, "assembly") || strings.Contains(result, "invalid()") {
		t.Errorf("VULNERABILITY: type injection from request types array!\nGenerated:\n%s", result)
	}
}

// TestSafe_ValidFieldDeclarations verifies that legitimate field declarations
// still work correctly after hardening.
func TestSafe_ValidFieldDeclarations(t *testing.T) {
	tests := []struct {
		name       string
		fieldName  string
		fieldType  string
		value      interface{}
		expectSafe string // substring that must be present
	}{
		{"address field", "owner", "address", "0x0000000000000000000000000000000000000001", "address owner"},
		{"uint256 field", "amount", "uint256", "1000000", "uint256 amount = 1000000"},
		{"bool field", "active", "bool", true, "bool active = true"},
		{"string field", "name", "string", "hello", `string memory name = "hello"`},
		{"bytes32 field", "hash", "bytes32", "0x" + strings.Repeat("ab", 32), "bytes32 hash"},
		{"int256 field", "delta", "int256", "-100", "int256 delta = -100"},
		{"uint8 field", "decimals", "uint8", "18", "uint8 decimals = 18"},
		{"underscore name", "_internal", "uint256", "1", "uint256 _internal = 1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decl := generateFieldDeclaration(tt.fieldName, tt.fieldType, tt.value)
			if !strings.Contains(decl, tt.expectSafe) {
				t.Errorf("expected declaration to contain %q, got: %s", tt.expectSafe, decl)
			}
		})
	}
}

// TestSafe_FormatFunctions_RejectInjection verifies all format* functions
// reject injection payloads that were previously found vulnerable.
func TestSafe_FormatFunctions_RejectInjection(t *testing.T) {
	t.Run("formatDomainContract rejects injection", func(t *testing.T) {
		result := formatDomainContract(`0xDEAD); return; } function x() public { //`)
		if result != "address(0)" {
			t.Errorf("expected address(0), got: %s", result)
		}
	})

	t.Run("formatDomainChainId rejects injection", func(t *testing.T) {
		result := formatDomainChainId("1; return true; //")
		if result != "0" {
			t.Errorf("expected 0, got: %s", result)
		}
	})

	t.Run("formatWei rejects injection", func(t *testing.T) {
		val := "1e18"
		result := formatWei(&val)
		if result != "0" {
			t.Errorf("expected 0, got: %s", result)
		}
	})

	t.Run("formatChainID rejects injection", func(t *testing.T) {
		result := formatChainID("1; assembly { invalid() }")
		if result != "1" {
			t.Errorf("expected 1, got: %s", result)
		}
	})

	t.Run("formatSelector rejects injection", func(t *testing.T) {
		val := "0x12345678; revert();"
		result := formatSelector(&val)
		if result != "bytes4(0)" {
			t.Errorf("expected bytes4(0), got: %s", result)
		}
	})

	t.Run("formatInterfaceAsAddress rejects injection", func(t *testing.T) {
		result := formatInterfaceAsAddress(`0xDEAD"); revert(); address(0x`)
		if result != "address(0)" {
			t.Errorf("expected address(0), got: %s", result)
		}
	})

	t.Run("formatInterfaceAsUint rejects injection", func(t *testing.T) {
		result := formatInterfaceAsUint("1; revert();")
		if result != "0" {
			t.Errorf("expected 0, got: %s", result)
		}
	})

	t.Run("formatInterfaceAsInt rejects injection", func(t *testing.T) {
		result := formatInterfaceAsInt("-1; assembly { invalid() }")
		if result != "0" {
			t.Errorf("expected 0, got: %s", result)
		}
	})

	t.Run("formatInterfaceAsBytes32 rejects injection", func(t *testing.T) {
		result := formatInterfaceAsBytes32("0x" + strings.Repeat("ab", 32) + "; revert();")
		if result != "bytes32(0)" {
			t.Errorf("expected bytes32(0), got: %s", result)
		}
	})
}
