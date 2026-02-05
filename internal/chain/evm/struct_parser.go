package evm

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// StructDefinition represents a parsed Solidity struct
type StructDefinition struct {
	Name   string            // struct name (e.g., "Order")
	Fields []TypedDataField  // ordered list of fields
}

// parseStructDefinition extracts struct name and fields from Solidity struct syntax
// Example input:
//
//	struct Order {
//	    uint256 salt;
//	    address maker;
//	    address taker;
//	}
func parseStructDefinition(structCode string) (*StructDefinition, error) {
	// Remove comments
	structCode = removeComments(structCode)

	// Match struct definition: struct Name { ... }
	structRegex := regexp.MustCompile(`(?s)struct\s+(\w+)\s*\{([^}]*)\}`)
	matches := structRegex.FindStringSubmatch(structCode)
	if len(matches) < 3 {
		return nil, fmt.Errorf("invalid struct definition: no struct found")
	}

	structName := strings.TrimSpace(matches[1])
	fieldsBody := matches[2]

	// Parse fields
	fields, err := parseStructFields(fieldsBody)
	if err != nil {
		return nil, fmt.Errorf("failed to parse struct fields: %w", err)
	}

	if len(fields) == 0 {
		return nil, fmt.Errorf("struct %s has no fields", structName)
	}

	return &StructDefinition{
		Name:   structName,
		Fields: fields,
	}, nil
}

// parseStructFields parses field declarations from struct body
// Handles: type name; or type name; // comment
func parseStructFields(body string) ([]TypedDataField, error) {
	var fields []TypedDataField

	// Split by semicolons and newlines
	lines := strings.Split(body, ";")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Remove inline comments
		if idx := strings.Index(line, "//"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		// Parse field: type name
		// Handle array types like uint256[] and fixed arrays like bytes32[2]
		field, err := parseFieldDeclaration(line)
		if err != nil {
			return nil, fmt.Errorf("failed to parse field '%s': %w", line, err)
		}

		fields = append(fields, *field)
	}

	return fields, nil
}

// parseFieldDeclaration parses a single field declaration
// Examples:
//   - "uint256 salt"
//   - "address maker"
//   - "bytes32[] hashes"
//   - "string memory message" (memory/storage/calldata modifiers are stripped)
func parseFieldDeclaration(decl string) (*TypedDataField, error) {
	decl = strings.TrimSpace(decl)

	// Remove memory/storage/calldata modifiers
	decl = strings.ReplaceAll(decl, " memory ", " ")
	decl = strings.ReplaceAll(decl, " storage ", " ")
	decl = strings.ReplaceAll(decl, " calldata ", " ")

	// Split into parts
	parts := strings.Fields(decl)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid field declaration: expected 'type name', got '%s'", decl)
	}

	// Last part is the name, everything before is the type
	name := parts[len(parts)-1]
	fieldType := strings.Join(parts[:len(parts)-1], " ")

	// Validate name (must be valid identifier)
	if !isValidIdentifier(name) {
		return nil, fmt.Errorf("invalid field name: %s", name)
	}

	// Normalize type
	fieldType = normalizeType(fieldType)

	return &TypedDataField{
		Name: name,
		Type: fieldType,
	}, nil
}

// removeComments removes single-line and multi-line comments
func removeComments(code string) string {
	// Remove multi-line comments /* ... */
	multiLineRegex := regexp.MustCompile(`/\*[\s\S]*?\*/`)
	code = multiLineRegex.ReplaceAllString(code, "")

	// Remove single-line comments // ...
	lines := strings.Split(code, "\n")
	var cleanLines []string
	for _, line := range lines {
		if idx := strings.Index(line, "//"); idx != -1 {
			line = line[:idx]
		}
		cleanLines = append(cleanLines, line)
	}

	return strings.Join(cleanLines, "\n")
}

// isValidIdentifier checks if a string is a valid Solidity identifier
func isValidIdentifier(s string) bool {
	if len(s) == 0 {
		return false
	}
	// Must start with letter or underscore
	first := s[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_') {
		return false
	}
	// Rest can be alphanumeric or underscore
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// normalizeType normalizes Solidity type names
func normalizeType(t string) string {
	t = strings.TrimSpace(t)

	// Normalize uint/int to uint256/int256
	if t == "uint" {
		return "uint256"
	}
	if t == "int" {
		return "int256"
	}

	return t
}

// generateStructDefinition generates a Solidity struct definition from StructDefinition
// This creates the struct type that can be used in the contract
func generateStructDefinition(structDef *StructDefinition) string {
	if structDef == nil || len(structDef.Fields) == 0 {
		return ""
	}

	var fields []string
	for _, field := range structDef.Fields {
		fields = append(fields, fmt.Sprintf("        %s %s;", field.Type, field.Name))
	}

	return fmt.Sprintf(`struct %s {
%s
    }`, structDef.Name, strings.Join(fields, "\n"))
}

// generateStructInstance generates a Solidity struct instance with values from the message
// The instance variable name is the lowercase version of the struct name (e.g., Order -> order)
func generateStructInstance(structDef *StructDefinition, message map[string]interface{}) string {
	if structDef == nil || len(structDef.Fields) == 0 {
		return ""
	}

	// Generate lowercase instance name
	instanceName := strings.ToLower(structDef.Name[:1]) + structDef.Name[1:]

	// Generate field initializers
	var fieldValues []string
	for _, field := range structDef.Fields {
		// Determine the message key to look up
		// Field names ending with underscore (e.g., "address_") map to message keys without underscore (e.g., "address")
		// This allows using Solidity reserved keywords as struct field names by escaping them with underscore
		messageKey := field.Name
		if strings.HasSuffix(field.Name, "_") {
			messageKey = strings.TrimSuffix(field.Name, "_")
		}

		value, exists := message[messageKey]
		if !exists {
			value = nil
		}

		// Format the value for Solidity
		formattedValue := formatFieldValue(field.Type, value)
		fieldValues = append(fieldValues, fmt.Sprintf("            %s: %s", field.Name, formattedValue))
	}

	return fmt.Sprintf(`%s memory %s = %s({
%s
        });`, structDef.Name, instanceName, structDef.Name, strings.Join(fieldValues, ",\n"))
}

// formatFieldValue formats a value for Solidity struct initialization based on type
func formatFieldValue(solidityType string, value interface{}) string {
	if value == nil {
		return getDefaultValue(solidityType)
	}

	switch solidityType {
	case "address":
		if str, ok := value.(string); ok {
			if len(str) == 42 && strings.HasPrefix(str, "0x") {
				return str
			}
		}
		return "address(0)"

	case "string":
		if str, ok := value.(string); ok {
			// Escape quotes in string
			escaped := strings.ReplaceAll(str, "\\", "\\\\")
			escaped = strings.ReplaceAll(escaped, "\"", "\\\"")
			return fmt.Sprintf(`"%s"`, escaped)
		}
		return `""`

	case "bytes":
		if str, ok := value.(string); ok {
			if strings.HasPrefix(str, "0x") {
				return fmt.Sprintf(`hex"%s"`, str[2:])
			}
			return fmt.Sprintf(`hex"%x"`, []byte(str))
		}
		if bytes, ok := value.([]byte); ok {
			return fmt.Sprintf(`hex"%x"`, bytes)
		}
		return `""`

	case "bytes32":
		if str, ok := value.(string); ok {
			if len(str) == 66 && strings.HasPrefix(str, "0x") {
				return str
			}
		}
		return "bytes32(0)"

	case "bool":
		if b, ok := value.(bool); ok {
			if b {
				return "true"
			}
			return "false"
		}
		return "false"

	default:
		// Numeric types (uint256, uint8, int256, etc.)
		if strings.HasPrefix(solidityType, "uint") || strings.HasPrefix(solidityType, "int") {
			switch v := value.(type) {
			case string:
				// Numeric string
				return v
			case float64:
				return fmt.Sprintf("%.0f", v)
			case int, int64, uint64:
				return fmt.Sprintf("%d", v)
			case json.Number:
				return string(v)
			}
			return "0"
		}
		// Fallback
		if str, ok := value.(string); ok {
			return str
		}
		return getDefaultValue(solidityType)
	}
}

// getDefaultValue returns the default Solidity value for a type
func getDefaultValue(solidityType string) string {
	switch solidityType {
	case "address":
		return "address(0)"
	case "string":
		return `""`
	case "bytes":
		return `""`
	case "bytes32":
		return "bytes32(0)"
	case "bool":
		return "false"
	default:
		if strings.HasPrefix(solidityType, "uint") || strings.HasPrefix(solidityType, "int") {
			return "0"
		}
		if strings.HasPrefix(solidityType, "bytes") {
			return `""`
		}
		return "0"
	}
}
