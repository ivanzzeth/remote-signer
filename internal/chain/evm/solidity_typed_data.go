// Package evm provides EVM-specific chain logic for the Remote Signer.
// solidity_typed_data.go contains evaluation and script generation methods for
// EIP-712 typed data Solidity rules.
//
// Formatting helpers for typed data values have been moved to solidity_typed_data_format.go.
package evm

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"text/template"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

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
		PrimaryType              string
		DomainName               string
		DomainVersion            string
		DomainChainId            string
		DomainContract           string
		Signer                   string
		ChainID                  string
		StructDefinition         string
		StructInstance           string
		Expression               string
		InMappingDeclarations    string
		InMappingConstructorInit string
	}{
		PrimaryType:              formatString(typedData.PrimaryType),
		DomainName:               formatString(typedData.Domain.Name),
		DomainVersion:            formatString(typedData.Domain.Version),
		DomainChainId:            formatDomainChainId(typedData.Domain.ChainId),
		DomainContract:           formatDomainContract(typedData.Domain.VerifyingContract),
		Signer:                   formatAddress(&req.SignerAddress),
		ChainID:                  formatChainID(req.ChainID),
		StructDefinition:         structDefinition,
		StructInstance:           structInstance,
		Expression:               expression,
		InMappingDeclarations:    ir.Declarations,
		InMappingConstructorInit: ir.ConstructorInit,
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
		PrimaryType              string
		DomainName               string
		DomainVersion            string
		DomainChainId            string
		DomainContract           string
		Signer                   string
		ChainID                  string
		MessageData              string
		Functions                string
		InMappingDeclarations    string
		InMappingConstructorInit string
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
