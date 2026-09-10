// Package evm provides EVM-specific chain logic for the Remote Signer.
// solidity_typed_data.go contains evaluation and script generation methods for
// EIP-712 typed data Solidity rules.
//
// Formatting helpers for typed data values have been moved to solidity_typed_data_format.go.
package evm

import (
	"fmt"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// generateTypedDataExpressionScript generates a Solidity script for TypedDataExpression mode
// If structDef is provided, it generates a struct definition and instance variable
// accessible via structName.field syntax (e.g., order.taker)
// typedDataExpressionScript builds the script for an expression checked against
// EIP-712 typed data.
func (e *SolidityRuleEvaluator) typedDataExpressionScript(
	expression string,
	req *types.SignRequest,
	typedData *TypedDataPayload,
	structDef *StructDefinition,
	inMappingArrays map[string][]string,
) (solidityScript, error) {
	bind := typedDataBindings(req, typedData)
	if structDef != nil {
		// A declared struct gives the operator `order.taker` field access.
		bind["StructDefinition"] = generateStructDefinition(structDef)
		bind["StructInstance"] = generateStructInstance(structDef, typedData.Message)
	} else {
		// Legacy shape: no struct, each message field declared on its own.
		bind["StructDefinition"] = ""
		bind["StructInstance"] = generateMessageFieldDeclarations(typedData)
	}
	return solidityScript{
		mode:     "typedDataExpression",
		template: solidityTypedDataExpressionTemplate,
		body:     expression,
		inMaps:   inMappingArrays,
		bind:     bind,
	}, nil
}

// generateTypedDataFunctionsScript generates a Solidity script for TypedDataFunctions mode
// typedDataFunctionsScript builds the script for functions checked against
// EIP-712 typed data.
func (e *SolidityRuleEvaluator) typedDataFunctionsScript(
	functions string,
	req *types.SignRequest,
	typedData *TypedDataPayload,
	inMappingArrays map[string][]string,
) (solidityScript, error) {
	bind := typedDataBindings(req, typedData)
	// Functions decode the message themselves, so it is passed as bytes.
	bind["MessageData"] = encodeMessageData(typedData)
	return solidityScript{
		mode:     "typedDataFunctions",
		template: solidityTypedDataFunctionsTemplate,
		body:     functions,
		inMaps:   inMappingArrays,
		bind:     bind,
	}, nil
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
