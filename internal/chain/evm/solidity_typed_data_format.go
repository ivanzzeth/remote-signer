// Package evm provides EVM-specific chain logic for the Remote Signer.
// solidity_typed_data_format.go contains formatting helper functions for
// EIP-712 typed data Solidity code generation.
package evm

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// solidityReservedKeywords contains only Solidity language reserved keywords
// Template context variables now use prefixes (eip712_*, ctx_*, tx_*) so they won't conflict with user field names
var solidityReservedKeywords = map[string]bool{
	// Solidity reserved keywords (types)
	"address": true, "bool": true, "string": true, "bytes": true,
	"uint": true, "int": true, "mapping": true, "struct": true, "enum": true,
	// Solidity reserved keywords (declarations)
	"function": true, "modifier": true, "event": true, "error": true,
	"contract": true, "interface": true, "library": true, "abstract": true,
	// Solidity reserved keywords (visibility/modifiers)
	"public": true, "private": true, "internal": true, "external": true,
	"view": true, "pure": true, "payable": true, "constant": true,
	"immutable": true, "virtual": true, "override": true,
	// Solidity reserved keywords (data location)
	"memory": true, "storage": true, "calldata": true,
	// Solidity reserved keywords (control flow)
	"if": true, "else": true, "for": true, "while": true, "do": true, "break": true, "continue": true, "return": true,
	"try": true, "catch": true, "revert": true, "require": true, "assert": true,
	// Solidity reserved keywords (special)
	"new": true, "delete": true, "this": true, "super": true,
	// Solidity reserved keywords (literals)
	"true": true, "false": true, "wei": true, "ether": true, "gwei": true,
	// Solidity reserved keywords (time units)
	"seconds": true, "minutes": true, "hours": true, "days": true, "weeks": true,
}

// escapeReservedKeyword prefixes reserved keywords with underscore
func escapeReservedKeyword(name string) string {
	if solidityReservedKeywords[name] {
		return "_" + name
	}
	return name
}

// validSolidityTypePattern matches only valid Solidity primitive types.
// This prevents Solidity template injection via attacker-controlled type strings.
var validSolidityTypePattern = regexp.MustCompile(`^(address|bool|string|bytes|bytes([1-9]|[12]\d|3[0-2])|u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?)$`)

// parseTypedDataFromPayload extracts TypedDataPayload from request payload
func parseTypedDataFromPayload(payload []byte) (*TypedDataPayload, error) {
	var evmPayload EVMSignPayload
	if err := json.Unmarshal(payload, &evmPayload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal EVM payload: %w", err)
	}

	if evmPayload.TypedData == nil {
		return nil, fmt.Errorf("typed_data field is required for EIP-712 validation")
	}

	return evmPayload.TypedData, nil
}

// generateMessageFieldDeclarations generates Solidity variable declarations from typed data message
func generateMessageFieldDeclarations(typedData *TypedDataPayload) string {
	if typedData == nil || typedData.Message == nil {
		return ""
	}

	var declarations []string

	// Get type definitions for the primary type
	fields := typedData.Types[typedData.PrimaryType]

	if len(fields) > 0 {
		// Use type definitions when available
		for _, field := range fields {
			value, exists := typedData.Message[field.Name]
			if !exists {
				continue
			}

			// Generate declaration based on field type
			decl := generateFieldDeclaration(field.Name, field.Type, value)
			if decl != "" {
				declarations = append(declarations, decl)
			}
		}
	} else {
		// Fallback: infer types from message values when Types is missing
		for name, value := range typedData.Message {
			inferredType := inferSolidityType(value)
			decl := generateFieldDeclaration(name, inferredType, value)
			if decl != "" {
				declarations = append(declarations, decl)
			}
		}
	}

	return strings.Join(declarations, "\n        ")
}

// generateFieldDeclaration generates a single Solidity variable declaration.
// Both name and solidityType may come from attacker-controlled request data
// (EIP-712 typed data types/message), so they MUST be validated before embedding
// in Solidity code to prevent template injection attacks.
func generateFieldDeclaration(name, solidityType string, value interface{}) string {
	// Security: validate field name as a valid Solidity identifier.
	// This prevents injection via field names like "x; } function evil() { uint256 y".
	if !isValidIdentifier(name) {
		return "// Skipped field with invalid name"
	}

	// Escape reserved keywords
	safeName := escapeReservedKeyword(name)

	// Security: validate type against strict whitelist of Solidity primitives.
	// This prevents injection via types like "uint256; assembly { invalid() } uint256".
	// IMPORTANT: Do NOT embed the raw attacker-controlled type string in the output,
	// not even inside a comment. While comments are not executable, defense-in-depth
	// means we never reflect untrusted input into generated Solidity code.
	if !validSolidityTypePattern.MatchString(solidityType) {
		return fmt.Sprintf("// Skipped field %s: unsupported type", safeName)
	}

	// Handle validated Solidity types
	switch {
	case solidityType == "address":
		return fmt.Sprintf("address %s = %s;", safeName, formatInterfaceAsAddress(value))
	case solidityType == "uint256" || solidityType == "uint":
		return fmt.Sprintf("uint256 %s = %s;", safeName, formatInterfaceAsUint(value))
	case solidityType == "int256" || solidityType == "int":
		return fmt.Sprintf("int256 %s = %s;", safeName, formatInterfaceAsInt(value))
	case solidityType == "bool":
		return fmt.Sprintf("bool %s = %s;", safeName, formatInterfaceAsBool(value))
	case solidityType == "bytes32":
		return fmt.Sprintf("bytes32 %s = %s;", safeName, formatInterfaceAsBytes32(value))
	case solidityType == "bytes":
		return fmt.Sprintf("bytes memory %s = %s;", safeName, formatInterfaceAsBytes(value))
	case solidityType == "string":
		return fmt.Sprintf("string memory %s = %s;", safeName, formatInterfaceAsString(value))
	case strings.HasPrefix(solidityType, "uint"):
		return fmt.Sprintf("%s %s = %s;", solidityType, safeName, formatInterfaceAsUint(value))
	case strings.HasPrefix(solidityType, "int"):
		return fmt.Sprintf("%s %s = %s;", solidityType, safeName, formatInterfaceAsInt(value))
	case strings.HasPrefix(solidityType, "bytes"):
		return fmt.Sprintf("%s %s = %s;", solidityType, safeName, formatInterfaceAsFixedBytes(value, solidityType))
	default:
		return fmt.Sprintf("// Skipped field %s of type %s", safeName, solidityType)
	}
}

// encodeMessageData encodes the message fields as ABI-encoded bytes
func encodeMessageData(typedData *TypedDataPayload) string {
	if typedData == nil || typedData.Message == nil {
		return `hex""`
	}

	// For simplicity, we encode message as JSON bytes
	// The user can decode it using abi.decode with their struct definition
	msgBytes, err := json.Marshal(typedData.Message)
	if err != nil {
		return `hex""`
	}

	return fmt.Sprintf(`hex"%s"`, hex.EncodeToString(msgBytes))
}

// Helper functions for formatting typed data values

func formatString(s string) string {
	if s == "" {
		return `""`
	}
	// Escape special characters for Solidity string literal
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return fmt.Sprintf(`"%s"`, escaped)
}

func formatDomainChainId(chainId string) string {
	if chainId == "" {
		return "0"
	}
	// Defense in depth: validate numeric to prevent Solidity template injection.
	// Embedded as: uint256 eip712_domainChainId = {{.DomainChainId}};
	if !isDecimalString(chainId) {
		return "0"
	}
	return chainId
}

func formatDomainContract(addr string) string {
	if addr == "" {
		return "address(0)"
	}
	// Defense in depth: validate hex address to prevent Solidity template injection.
	// Attacker-controlled verifyingContract is embedded in Solidity template as:
	//   address eip712_domainContract = {{.DomainContract}};
	if !common.IsHexAddress(addr) {
		return "address(0)"
	}
	return common.HexToAddress(addr).Hex()
}

func formatInterfaceAsAddress(v interface{}) string {
	switch val := v.(type) {
	case string:
		if val == "" {
			return "address(0)"
		}
		// Defense in depth: validate hex address to prevent Solidity template injection.
		if !common.IsHexAddress(val) {
			return "address(0)"
		}
		return common.HexToAddress(val).Hex()
	default:
		return "address(0)"
	}
}

func formatInterfaceAsUint(v interface{}) string {
	switch val := v.(type) {
	case string:
		if val == "" {
			return "0"
		}
		// Defense in depth: validate only decimal digits to prevent Solidity template injection.
		if !isDecimalString(val) {
			return "0"
		}
		return val
	case float64:
		return fmt.Sprintf("%.0f", val)
	case int:
		return fmt.Sprintf("%d", val)
	case int64:
		return fmt.Sprintf("%d", val)
	case uint64:
		return fmt.Sprintf("%d", val)
	default:
		return "0"
	}
}

func formatInterfaceAsInt(v interface{}) string {
	switch val := v.(type) {
	case string:
		if val == "" {
			return "0"
		}
		// Defense in depth: validate signed decimal to prevent Solidity template injection.
		// Allow optional leading '-' for negative int values.
		check := strings.TrimPrefix(val, "-")
		if check == "" || !isDecimalString(check) {
			return "0"
		}
		return val
	case float64:
		return fmt.Sprintf("%.0f", val)
	case int:
		return fmt.Sprintf("%d", val)
	case int64:
		return fmt.Sprintf("%d", val)
	default:
		return "0"
	}
}

func formatInterfaceAsBool(v interface{}) string {
	switch val := v.(type) {
	case bool:
		if val {
			return "true"
		}
		return "false"
	case string:
		if val == "true" {
			return "true"
		}
		return "false"
	default:
		return "false"
	}
}

func formatInterfaceAsBytes32(v interface{}) string {
	switch val := v.(type) {
	case string:
		if val == "" {
			return "bytes32(0)"
		}
		if strings.HasPrefix(val, "0x") {
			// Defense in depth: validate hex content to prevent Solidity template injection.
			hexPart := val[2:]
			if !isHexString(hexPart) || len(hexPart) != 64 {
				return "bytes32(0)"
			}
			return val
		}
		// Validate hex before embedding in template
		if !isHexString(val) {
			return "bytes32(0)"
		}
		return fmt.Sprintf(`hex"%s"`, val)
	default:
		return "bytes32(0)"
	}
}

func formatInterfaceAsBytes(v interface{}) string {
	switch val := v.(type) {
	case string:
		if val == "" {
			return `hex""`
		}
		if strings.HasPrefix(val, "0x") {
			hexPart := val[2:]
			// Defense in depth: validate hex content to prevent Solidity template injection.
			if !isHexString(hexPart) {
				return `hex""`
			}
			return fmt.Sprintf(`hex"%s"`, hexPart)
		}
		// Non-0x string: encode as hex bytes (safe -- hex.EncodeToString always produces valid hex)
		return fmt.Sprintf(`hex"%s"`, hex.EncodeToString([]byte(val)))
	case []byte:
		return fmt.Sprintf(`hex"%s"`, hex.EncodeToString(val))
	default:
		return `hex""`
	}
}

func formatInterfaceAsString(v interface{}) string {
	switch val := v.(type) {
	case string:
		escaped := strings.ReplaceAll(val, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `"`, `\"`)
		return fmt.Sprintf(`"%s"`, escaped)
	default:
		return `""`
	}
}

func formatInterfaceAsFixedBytes(v interface{}, solidityType string) string {
	switch val := v.(type) {
	case string:
		if val == "" {
			return fmt.Sprintf("%s(0)", solidityType)
		}
		if strings.HasPrefix(val, "0x") {
			// Defense in depth: validate hex content to prevent Solidity template injection.
			hexPart := val[2:]
			if !isHexString(hexPart) {
				return fmt.Sprintf("%s(0)", solidityType)
			}
			return val
		}
		// Validate hex before embedding in template
		if !isHexString(val) {
			return fmt.Sprintf("%s(0)", solidityType)
		}
		return fmt.Sprintf(`hex"%s"`, val)
	default:
		return fmt.Sprintf("%s(0)", solidityType)
	}
}
