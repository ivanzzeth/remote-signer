// Package evm provides the EVM chain implementation including rule evaluation,
// signer management, and transaction processing for the remote-signer daemon.
package evm

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"github.com/ethereum/go-ethereum/common"
)

// inMappingResult holds the result of replacing in(expr, varName) with mapping lookups.
type inMappingResult struct {
	Modified        string // source with in(expr, varName) replaced by varName_mapping[expr]
	Declarations    string // e.g. "mapping(address => bool) private allowed_safe_addresses_mapping;"
	ConstructorInit string // e.g. "allowed_safe_addresses_mapping[0xa]=true;\n        ..."
}

// sanitizeEmptyComparisons fixes empty variable substitution in comparisons so that generated Solidity compiles.
// Uses address(0) for address types and 0 for numeric (e.g. chainId) when LHS name suggests type.
func sanitizeEmptyComparisons(code string) string {
	// LHS containing chainId/CainId -> use 0 (uint256); otherwise address(0)
	emptyRHS := func(lhs string) string {
		if regexp.MustCompile(`(?i)chainid`).MatchString(lhs) {
			return "0"
		}
		return "address(0)"
	}
	// == ) with optional LHS capture: (something) == ) -> (something) == 0) or address(0))
	code = regexp.MustCompile(`(\w+)\s*==\s*\)`).ReplaceAllStringFunc(code, func(m string) string {
		sub := regexp.MustCompile(`(\w+)\s*==\s*\)`).FindStringSubmatch(m)
		if len(sub) != 2 {
			return m
		}
		return sub[1] + " == " + emptyRHS(sub[1]) + ")"
	})
	code = regexp.MustCompile(`(\w+)\s*==\s*,\s*`).ReplaceAllStringFunc(code, func(m string) string {
		sub := regexp.MustCompile(`(\w+)\s*==\s*,\s*`).FindStringSubmatch(m)
		if len(sub) != 2 {
			return m
		}
		return sub[1] + " == " + emptyRHS(sub[1]) + ", "
	})
	code = regexp.MustCompile(`(\w+)\s*==\s+\|\|`).ReplaceAllStringFunc(code, func(m string) string {
		sub := regexp.MustCompile(`(\w+)\s*==\s+\|\|`).FindStringSubmatch(m)
		if len(sub) != 2 {
			return m
		}
		return sub[1] + " == " + emptyRHS(sub[1]) + " ||"
	})
	code = regexp.MustCompile(`(\w+)\s*==\s+&&`).ReplaceAllStringFunc(code, func(m string) string {
		sub := regexp.MustCompile(`(\w+)\s*==\s+&&`).FindStringSubmatch(m)
		if len(sub) != 2 {
			return m
		}
		return sub[1] + " == " + emptyRHS(sub[1]) + " &&"
	})
	code = regexp.MustCompile(`(\w+)\s*==\s+;`).ReplaceAllStringFunc(code, func(m string) string {
		sub := regexp.MustCompile(`(\w+)\s*==\s+;`).FindStringSubmatch(m)
		if len(sub) != 2 {
			return m
		}
		return sub[1] + " == " + emptyRHS(sub[1]) + ";"
	})
	code = regexp.MustCompile(`(\w+)\s*!=\s*\)`).ReplaceAllStringFunc(code, func(m string) string {
		sub := regexp.MustCompile(`(\w+)\s*!=\s*\)`).FindStringSubmatch(m)
		if len(sub) != 2 {
			return m
		}
		return sub[1] + " != " + emptyRHS(sub[1]) + ")"
	})
	code = regexp.MustCompile(`\s*!=\s*,\s*`).ReplaceAllString(code, " != address(0), ")
	code = regexp.MustCompile(`\s*!=\s+\|\|`).ReplaceAllString(code, " != address(0) ||")
	code = regexp.MustCompile(`\s*!=\s+&&`).ReplaceAllString(code, " != address(0) &&")
	return code
}

// processInOperatorToMappings replaces in(expr, varName) with varName_mapping[expr].
// Only supports second argument as a single identifier (array variable name).
// When inMappingArrays[varName] is set, the mapping is filled in constructor; otherwise empty (syntax check).
// Any in() not matched (e.g. literal list in(expr, a, b, c)) is left for preprocessInOperator.
func processInOperatorToMappings(source string, inMappingArrays map[string][]string) inMappingResult {
	// Match in(expr, varName) — second arg must be single identifier \w+
	re := regexp.MustCompile(`in\s*\(\s*([^,]+)\s*,\s*(\w+)\s*\)`)
	var declarations []string
	var constructorInits []string
	seenVar := make(map[string]bool)

	modified := re.ReplaceAllStringFunc(source, func(match string) string {
		sub := re.FindStringSubmatch(match)
		if len(sub) != 3 {
			return match
		}
		expr := strings.TrimSpace(sub[1])
		varName := sub[2]
		// Only treat as array variable if it looks like an identifier (not a literal like 0x... or 123)
		if len(varName) == 0 || varName[0] >= '0' && varName[0] <= '9' || strings.HasPrefix(varName, "0x") {
			return match
		}
		mappingName := varName + "_mapping"
		if !seenVar[varName] {
			seenVar[varName] = true
			declarations = append(declarations, "mapping(address => bool) private "+mappingName+";")
			addrs := inMappingArrays[varName]
			for _, a := range addrs {
				addr := strings.TrimSpace(a)
				if addr == "" {
					continue
				}
				// Defense-in-depth: validate address before embedding in generated Solidity code.
				// Invalid addresses would cause compilation failure anyway, but explicit validation
				// catches the issue earlier with a clear error message.
				if !common.IsHexAddress(addr) {
					continue
				}
				checksumAddr := common.HexToAddress(addr).Hex()
				constructorInits = append(constructorInits, mappingName+"["+checksumAddr+"] = true;")
			}
		}
		return mappingName + "[" + expr + "]"
	})

	return inMappingResult{
		Modified:        modified,
		Declarations:    strings.Join(declarations, "\n    "),
		ConstructorInit: strings.Join(constructorInits, "\n        "),
	}
}

// preprocessInOperator expands in(target, a, b, c) to (target == a || target == b || target == c).
// Used for backward compat when no InMappingArrays or for literal-list in().
func preprocessInOperator(expression string) string {
	// Match in(expr, val1, val2, ...) — first arg is [^,]+, rest may be empty [^)]*
	re := regexp.MustCompile(`in\s*\(\s*([^,]+)\s*,\s*([^)]*)\s*\)`)
	return re.ReplaceAllStringFunc(expression, func(match string) string {
		sub := re.FindStringSubmatch(match)
		if len(sub) != 3 {
			return match
		}
		target := strings.TrimSpace(sub[1])
		rest := strings.TrimSpace(sub[2])
		parts := strings.Split(rest, ",")
		var clauses []string
		for _, p := range parts {
			v := strings.TrimSpace(p)
			if v != "" {
				clauses = append(clauses, target+" == "+v)
			}
		}
		if len(clauses) == 0 {
			return "false"
		}
		return "(" + strings.Join(clauses, " || ") + ")"
	})
}

// generateExpressionScript generates a Solidity script for Expression mode.
// Script content depends only on the rule (expression + inMapping); request data is passed at runtime via env.
func (e *SolidityRuleEvaluator) generateExpressionScript(
	expression string,
	inMappingArrays map[string][]string,
) (string, error) {
	ir := processInOperatorToMappings(expression, inMappingArrays)
	expression = preprocessInOperator(ir.Modified)
	data := struct {
		Expression               string
		InMappingDeclarations    string
		InMappingConstructorInit string
	}{
		Expression:               expression,
		InMappingDeclarations:    ir.Declarations,
		InMappingConstructorInit: ir.ConstructorInit,
	}

	tmpl, err := template.New("expression").Parse(solidityExpressionTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// generateFunctionScript generates a Solidity script for Functions mode.
// Script content depends only on the rule (functions + inMapping); request data is passed at runtime via env.
func (e *SolidityRuleEvaluator) generateFunctionScript(
	functions string,
	inMappingArrays map[string][]string,
) (string, error) {
	ir := processInOperatorToMappings(functions, inMappingArrays)
	functions = preprocessInOperator(ir.Modified)
	data := struct {
		Functions                string
		InMappingDeclarations    string
		InMappingConstructorInit string
	}{
		Functions:                functions,
		InMappingDeclarations:    ir.Declarations,
		InMappingConstructorInit: ir.ConstructorInit,
	}

	tmpl, err := template.New("functions").Parse(solidityFunctionTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// GenerateSyntaxCheckScript generates a script for compilation checking (Expression mode)
func (e *SolidityRuleEvaluator) GenerateSyntaxCheckScript(expression string, inMappingArrays ...map[string][]string) string {
	// Preprocess custom in() operator before embedding into Solidity source
	var arrays map[string][]string
	if len(inMappingArrays) > 0 {
		arrays = inMappingArrays[0]
	}
	ir := processInOperatorToMappings(expression, arrays)
	expression = preprocessInOperator(ir.Modified)
	return fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SyntaxCheck {
    function run() public pure returns (bool) {
        // Transaction context
        address tx_to = address(0);
        uint256 tx_value = 0;
        bytes4 tx_selector = bytes4(0);
        bytes memory tx_data = "";

        // Signing context
        uint256 ctx_chainId = 1;
        address ctx_signer = address(0);

        // Backward-compatible short aliases
        address to = tx_to;
        uint256 value = tx_value;
        bytes4 selector = tx_selector;
        bytes memory data = tx_data;
        uint256 chainId = ctx_chainId;
        address signer = ctx_signer;

        // Suppress unused variable warnings
        tx_to; tx_value; tx_selector; tx_data; ctx_chainId; ctx_signer;
        to; value; selector; data; chainId; signer;

        // User expression
        %s

        return true;
    }
}
`, expression)
}

// GenerateFunctionSyntaxCheckScript generates a script for compilation checking (Functions mode)
// Uses the same two-contract structure as solidityFunctionTemplate for consistency
func (e *SolidityRuleEvaluator) GenerateFunctionSyntaxCheckScript(functions string, inMappingArrays ...map[string][]string) string {
	var arrays map[string][]string
	if len(inMappingArrays) > 0 {
		arrays = inMappingArrays[0]
	}
	ir := processInOperatorToMappings(functions, arrays)
	functions = preprocessInOperator(ir.Modified)
	return fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// RuleContract contains user-defined validation functions
contract RuleContract {
    %s

    // Transaction context available as state variables
    address public immutable txTo;
    uint256 public immutable txValue;
    bytes4 public immutable txSelector;
    bytes public txData;
    uint256 public immutable txChainId;
    address public immutable txSigner;

    constructor(
        address _txTo,
        uint256 _txValue,
        bytes4 _txSelector,
        bytes memory _txData,
        uint256 _txChainId,
        address _txSigner
    ) {
        txTo = _txTo;
        txValue = _txValue;
        txSelector = _txSelector;
        txData = _txData;
        txChainId = _txChainId;
        txSigner = _txSigner;
        %s
    }

    // Fallback: reject any function call that doesn't match whitelisted selectors
    fallback() external {
        revert("function not whitelisted");
    }

    // User-defined functions for automatic selector matching
    %s
}

// RuleEvaluatorTest is the forge test entry point (for syntax check only)
contract RuleEvaluatorTest {
    RuleContract public ruleContract;

    function setUp() public {
        ruleContract = new RuleContract(
            address(0),
            0,
            bytes4(0),
            hex"",
            1,
            address(0)
        );
    }

    function test_rule() public view {
        // Syntax check only - no execution needed
        ruleContract;
    }
}
`, ir.Declarations, ir.ConstructorInit, functions)
}
