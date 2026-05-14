package evm

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
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

// evaluateTypedDataExpression evaluates a Solidity expression with EIP-712 typed data context
// If structDef is provided, it's used for field declarations instead of inferring from request
func (e *SolidityRuleEvaluator) evaluateTypedDataExpression(
	ctx context.Context,
	expression string,
	req *types.SignRequest,
	typedData *TypedDataPayload,
	structDef *StructDefinition,
	inMappingArrays map[string][]string,
) (bool, string, error) {
	// Generate script with typed data context
	script, err := e.generateTypedDataExpressionScript(expression, req, typedData, structDef, inMappingArrays)
	if err != nil {
		return false, "", fmt.Errorf("failed to generate typed data expression script: %w", err)
	}

	passed, reason, err := e.executeScript(ctx, script, nil)
	if err != nil {
		return false, "", fmt.Errorf("script execution failed: %w", err)
	}
	return passed, reason, nil
}

// evaluateTypedDataFunctions evaluates user-defined functions with EIP-712 typed data context
func (e *SolidityRuleEvaluator) evaluateTypedDataFunctions(
	ctx context.Context,
	functions string,
	req *types.SignRequest,
	typedData *TypedDataPayload,
	inMappingArrays map[string][]string,
) (bool, string, error) {
	// Generate script with typed data context and user functions
	script, err := e.generateTypedDataFunctionsScript(functions, req, typedData, inMappingArrays)
	if err != nil {
		return false, "", fmt.Errorf("failed to generate typed data functions script: %w", err)
	}

	passed, reason, err := e.executeScript(ctx, script, nil)
	if err != nil {
		return false, "", fmt.Errorf("script execution failed: %w", err)
	}
	return passed, reason, nil
}

// generateTypedDataExpressionScript generates a Solidity script for TypedDataExpression mode
// If structDef is provided, it generates a struct definition and instance variable
// accessible via structName.field syntax (e.g., order.taker)
func (e *SolidityRuleEvaluator) generateTypedDataExpressionScript(
	expression string,
	req *types.SignRequest,
	typedData *TypedDataPayload,
	structDef *StructDefinition,
	inMappingArrays map[string][]string,
) (string, error) {
	ir := processInOperatorToMappings(expression, inMappingArrays)
	expression = preprocessInOperator(ir.Modified)
	var structDefinition string
	var structInstance string

	if structDef != nil {
		// Generate struct definition and instance
		structDefinition = generateStructDefinition(structDef)
		structInstance = generateStructInstance(structDef, typedData.Message)
	} else {
		// Fall back to generating individual field declarations (legacy behavior)
		// No struct definition needed
		structDefinition = ""
		structInstance = generateMessageFieldDeclarations(typedData)
	}

	data := struct {
		PrimaryType               string
		DomainName                string
		DomainVersion             string
		DomainChainId             string
		DomainContract            string
		Signer                    string
		ChainID                   string
		StructDefinition          string
		StructInstance            string
		Expression                string
		InMappingDeclarations     string
		InMappingConstructorInit string
	}{
		PrimaryType:               formatString(typedData.PrimaryType),
		DomainName:                formatString(typedData.Domain.Name),
		DomainVersion:             formatString(typedData.Domain.Version),
		DomainChainId:             formatDomainChainId(typedData.Domain.ChainId),
		DomainContract:            formatDomainContract(typedData.Domain.VerifyingContract),
		Signer:                    formatAddress(&req.SignerAddress),
		ChainID:                   formatChainID(req.ChainID),
		StructDefinition:          structDefinition,
		StructInstance:            structInstance,
		Expression:                expression,
		InMappingDeclarations:     ir.Declarations,
		InMappingConstructorInit:  ir.ConstructorInit,
	}

	tmpl, err := template.New("typedDataExpression").Parse(solidityTypedDataExpressionTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// generateTypedDataFunctionsScript generates a Solidity script for TypedDataFunctions mode
func (e *SolidityRuleEvaluator) generateTypedDataFunctionsScript(
	functions string,
	req *types.SignRequest,
	typedData *TypedDataPayload,
	inMappingArrays map[string][]string,
) (string, error) {
	ir := processInOperatorToMappings(functions, inMappingArrays)
	functions = preprocessInOperator(ir.Modified)
	// Encode message data as bytes for struct decoding
	messageData := encodeMessageData(typedData)

	data := struct {
		PrimaryType               string
		DomainName                string
		DomainVersion             string
		DomainChainId             string
		DomainContract            string
		Signer                    string
		ChainID                   string
		MessageData               string
		Functions                 string
		InMappingDeclarations     string
		InMappingConstructorInit  string
	}{
		PrimaryType:              formatString(typedData.PrimaryType),
		DomainName:               formatString(typedData.Domain.Name),
		DomainVersion:            formatString(typedData.Domain.Version),
		DomainChainId:            formatDomainChainId(typedData.Domain.ChainId),
		DomainContract:           formatDomainContract(typedData.Domain.VerifyingContract),
		Signer:                   formatAddress(&req.SignerAddress),
		ChainID:                  formatChainID(req.ChainID),
		MessageData:              messageData,
		Functions:                functions,
		InMappingDeclarations:    ir.Declarations,
		InMappingConstructorInit: ir.ConstructorInit,
	}

	tmpl, err := template.New("typedDataFunctions").Parse(solidityTypedDataFunctionsTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// GenerateTypedDataExpressionSyntaxCheckScript generates a syntax check script for TypedDataExpression mode.
// Callers must pass the rule's typed_data_struct via GenerateTypedDataExpressionSyntaxCheckScriptWithStruct; rules are the single source of truth.
func (e *SolidityRuleEvaluator) GenerateTypedDataExpressionSyntaxCheckScript(expression string, inMappingArrays ...map[string][]string) string {
	return e.GenerateTypedDataExpressionSyntaxCheckScriptWithStruct(expression, nil, inMappingArrays...)
}

// GenerateTypedDataExpressionSyntaxCheckScriptWithStruct generates a syntax check script from the rule's struct definition only.
// structDef must come from the rule config (typed_data_struct); no hardcoded structs. When structDef is nil, generates only EIP-712/ctx vars so expressions that reference structs fail at compile (caller should require typed_data_struct for typed_data_expression rules).
func (e *SolidityRuleEvaluator) GenerateTypedDataExpressionSyntaxCheckScriptWithStruct(expression string, structDef *StructDefinition, inMappingArrays ...map[string][]string) string {
	// Preprocess custom in() operator: first try mapping replacement,
	// then expand literal in(expr, a, b, c) to OR chains. This must happen before embedding into
	// Solidity source; otherwise forge will fail on the non-standard in() syntax.
	var arrays map[string][]string
	if len(inMappingArrays) > 0 {
		arrays = inMappingArrays[0]
	}
	ir := processInOperatorToMappings(expression, arrays)
	expression = preprocessInOperator(ir.Modified)

	if structDef == nil {
		// No struct: only standard EIP-712 and ctx variables. Expression that references any struct will fail at compile (undefined identifier).
		return fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SyntaxCheck {
    %s

    constructor() {
        %s
    }

    function run() public view returns (bool) {
        string memory eip712_primaryType = "";
        string memory eip712_domainName = "";
        string memory eip712_domainVersion = "";
        uint256 eip712_domainChainId = 1;
        address eip712_domainContract = address(0);
        address ctx_signer = address(0);
        uint256 ctx_chainId = 1;
        eip712_domainChainId; eip712_domainContract; ctx_signer; ctx_chainId;

        // User expression (must not reference structs unless typed_data_struct is set in rule config)
        %s

        return true;
    }
}
`, ir.Declarations, ir.ConstructorInit, expression)
	}

	// Generate from rule's struct only
	structDefStr := generateStructDefinition(structDef)
	instanceName := strings.ToLower(structDef.Name[:1]) + structDef.Name[1:]

	var fieldDefaults []string
	for _, field := range structDef.Fields {
		fieldDefaults = append(fieldDefaults, fmt.Sprintf("            %s: %s", field.Name, getDefaultValue(field.Type)))
	}

	return fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SyntaxCheck {
    %s
    %s

    constructor() {
        %s
    }

    function run() public view returns (bool) {
        string memory eip712_primaryType = "";
        string memory eip712_domainName = "";
        string memory eip712_domainVersion = "";
        uint256 eip712_domainChainId = 1;
        address eip712_domainContract = address(0);
        address ctx_signer = address(0);
        uint256 ctx_chainId = 1;
        eip712_domainChainId; eip712_domainContract; ctx_signer; ctx_chainId;

        %s memory %s = %s({
%s
        });

        %s

        return true;
    }
}
`, structDefStr, ir.Declarations, ir.ConstructorInit, structDef.Name, instanceName, structDef.Name, strings.Join(fieldDefaults, ",\n"), expression)
}

// GenerateTypedDataFunctionsSyntaxCheckScript generates a syntax check script for TypedDataFunctions mode
func (e *SolidityRuleEvaluator) GenerateTypedDataFunctionsSyntaxCheckScript(functions string, inMappingArrays ...map[string][]string) string {
	var arrays map[string][]string
	if len(inMappingArrays) > 0 {
		arrays = inMappingArrays[0]
	}
	ir := processInOperatorToMappings(functions, arrays)
	functions = preprocessInOperator(ir.Modified)
	return fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SyntaxCheck {
    %s

    // EIP-712 Domain context (eip712_* prefix)
    string public eip712_primaryType;
    string public eip712_domainName;
    string public eip712_domainVersion;
    uint256 public eip712_domainChainId;
    address public eip712_domainContract;

    // Signing context (ctx_* prefix)
    address public ctx_signer;
    uint256 public ctx_chainId;

    // EIP-712 Message encoded as bytes for struct decoding
    bytes public messageData;

    constructor() {
        eip712_primaryType = "";
        eip712_domainName = "";
        eip712_domainVersion = "";
        eip712_domainChainId = 1;
        eip712_domainContract = address(0);
        ctx_signer = address(0);
        ctx_chainId = 1;
        messageData = "";
        %s
    }

    // User-defined structs and validation functions
    %s

    function run() public returns (bool) {
        return true;
    }

    function _validateMessage() internal virtual {
        // Override in user functions if needed
    }
}
`, ir.Declarations, ir.ConstructorInit, functions)
}
