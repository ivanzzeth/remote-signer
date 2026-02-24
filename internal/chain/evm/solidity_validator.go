package evm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// dangerousPatterns contains regex patterns for dangerous Foundry cheatcodes
// These patterns are checked before rule execution to prevent code injection attacks.
// This is a defense-in-depth layer; FOUNDRY_FFI=false and FOUNDRY_FS_PERMISSIONS=[]
// are also set at runtime. The blocklist catches issues at rule creation time.
var dangerousPatterns = []*regexp.Regexp{
	// Command execution
	regexp.MustCompile(`(?i)vm\s*\.\s*ffi\s*\(`), // vm.ffi() - arbitrary command execution

	// File system access
	regexp.MustCompile(`(?i)vm\s*\.\s*readFile\s*\(`),   // vm.readFile() - file read
	regexp.MustCompile(`(?i)vm\s*\.\s*writeFile\s*\(`),  // vm.writeFile() - file write
	regexp.MustCompile(`(?i)vm\s*\.\s*removeFile\s*\(`), // vm.removeFile() - file delete
	regexp.MustCompile(`(?i)vm\s*\.\s*readDir\s*\(`),    // vm.readDir() - directory read
	regexp.MustCompile(`(?i)vm\s*\.\s*closeFile\s*\(`),  // vm.closeFile() - file close
	regexp.MustCompile(`(?i)vm\s*\.\s*writeLine\s*\(`),  // vm.writeLine() - file write
	regexp.MustCompile(`(?i)vm\s*\.\s*readLine\s*\(`),   // vm.readLine() - file read
	regexp.MustCompile(`(?i)vm\s*\.\s*fsMetadata\s*\(`), // vm.fsMetadata() - file metadata

	// Environment variable access (all vm.env* variants)
	regexp.MustCompile(`(?i)vm\s*\.\s*env[A-Za-z]*\s*\(`), // vm.envOr, vm.envString, vm.envUint, vm.envBool, vm.envAddress, vm.envBytes, vm.envBytes32, vm.envInt
	regexp.MustCompile(`(?i)vm\s*\.\s*setEnv\s*\(`),       // vm.setEnv() - environment variable write

	// Path disclosure
	regexp.MustCompile(`(?i)vm\s*\.\s*projectRoot\s*\(`), // vm.projectRoot() - path disclosure

	// Network access
	regexp.MustCompile(`(?i)vm\s*\.\s*rpc\s*\(`),        // vm.rpc() - external RPC calls
	regexp.MustCompile(`(?i)vm\s*\.\s*createFork\s*\(`),  // vm.createFork() - network access
	regexp.MustCompile(`(?i)vm\s*\.\s*selectFork\s*\(`),  // vm.selectFork() - network access

	// Transaction broadcasting (could initiate real on-chain transactions)
	regexp.MustCompile(`(?i)vm\s*\.\s*broadcast\s*\(`),      // vm.broadcast() - broadcast next tx
	regexp.MustCompile(`(?i)vm\s*\.\s*startBroadcast\s*\(`), // vm.startBroadcast() - broadcast mode

	// Signing (could sign arbitrary data with Foundry test keys)
	regexp.MustCompile(`(?i)vm\s*\.\s*sign\s*\(`), // vm.sign() - sign with test key
}

// SecurityError represents a security validation error
type SecurityError struct {
	Pattern string `json:"pattern"`
	Message string `json:"message"`
}

// ValidateSolidityCodeSecurity checks code for dangerous patterns
// Returns nil if code is safe, or SecurityError if dangerous patterns are found
func ValidateSolidityCodeSecurity(code string) *SecurityError {
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(code) {
			return &SecurityError{
				Pattern: pattern.String(),
				Message: fmt.Sprintf("dangerous pattern detected: %s - this cheatcode is not allowed for security reasons", pattern.String()),
			}
		}
	}
	return nil
}

// SolidityRuleValidator validates Solidity expression rules before storage
type SolidityRuleValidator struct {
	evaluator      *SolidityRuleEvaluator
	logger         *slog.Logger
	syntaxCache    map[string]bool // script hash -> syntax valid
	syntaxCacheMu  sync.RWMutex
}

// BatchValidationResult contains results for batch validation
type BatchValidationResult struct {
	Results []ValidationResult
	Valid   bool
}

// NewSolidityRuleValidator creates a new validator
func NewSolidityRuleValidator(evaluator *SolidityRuleEvaluator, logger *slog.Logger) (*SolidityRuleValidator, error) {
	if evaluator == nil {
		return nil, fmt.Errorf("evaluator is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &SolidityRuleValidator{
		evaluator:   evaluator,
		logger:      logger,
		syntaxCache: make(map[string]bool),
	}, nil
}

// ValidationResult contains the result of rule validation
type ValidationResult struct {
	Valid           bool             `json:"valid"`
	SyntaxError     *SyntaxError     `json:"syntax_error,omitempty"`
	TestCaseResults []TestCaseResult `json:"test_case_results,omitempty"`
	FailedTestCases int              `json:"failed_test_cases"`
}

// SyntaxError contains details about a Solidity compilation error
type SyntaxError struct {
	Message  string `json:"message"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
	Severity string `json:"severity"` // "error" or "warning"
}

// TestCaseResult contains the result of a single test case execution
type TestCaseResult struct {
	Name           string `json:"name"`
	Passed         bool   `json:"passed"`
	ExpectedPass   bool   `json:"expected_pass"`
	ActualPass     bool   `json:"actual_pass"`
	ExpectedReason string `json:"expected_reason,omitempty"`
	ActualReason   string `json:"actual_reason,omitempty"`
	Error          string `json:"error,omitempty"`
}

// ValidationMode represents the validation mode for a Solidity rule
type ValidationMode int

const (
	ValidationModeExpression ValidationMode = iota
	ValidationModeFunctions
	ValidationModeTypedDataExpression
	ValidationModeTypedDataFunctions
)

// ValidateRule performs full validation of a Solidity expression rule
func (v *SolidityRuleValidator) ValidateRule(ctx context.Context, rule *types.Rule) (*ValidationResult, error) {
	// Delegate to batch validation with a single rule.
	// This ensures there is only ONE validation code path to maintain.
	batchResult, err := v.ValidateRulesBatch(ctx, []*types.Rule{rule})
	if err != nil {
		return nil, err
	}
	if len(batchResult.Results) != 1 {
		return nil, fmt.Errorf("unexpected number of results: got %d, want 1", len(batchResult.Results))
	}
	return &batchResult.Results[0], nil
}

// cleanGeneratedScripts removes validator/evaluator-generated .sol files from tempDir
// so forge only compiles this run's scripts. Shared workspace (e.g. ./data/forge-workspace)
// otherwise accumulates thousands of syntax_check_*.sol and batch_rule_*.t.sol and forge hangs.
func cleanGeneratedScripts(tempDir string, log *slog.Logger) {
	for _, glob := range []string{
		"syntax_check_*.sol",
		"batch_rule_*.t.sol",
		"batch_*.t.sol",
		"rule_*.sol",
		"rule_*.t.sol",
	} {
		matches, err := filepath.Glob(filepath.Join(tempDir, glob))
		if err != nil {
			continue
		}
		for _, p := range matches {
			if err := os.Remove(p); err != nil {
				log.Debug("cleanGeneratedScripts: remove failed", "path", p, "error", err)
			}
		}
	}
}

// ValidateRulesBatch validates multiple rules in a single compilation
// This significantly improves performance by reducing the number of forge compilations.
// Rules are automatically grouped by validation mode and each group is batched separately.
func (v *SolidityRuleValidator) ValidateRulesBatch(ctx context.Context, rules []*types.Rule) (*BatchValidationResult, error) {
	if len(rules) == 0 {
		return &BatchValidationResult{Results: []ValidationResult{}, Valid: true}, nil
	}

	// Clean generated scripts from workspace so forge only compiles this run's files.
	// Otherwise accumulated syntax_check_*.sol / batch_rule_*.t.sol (e.g. in shared ./data/forge-workspace)
	// cause forge to compile thousands of files and hang; default /tmp stays fast because it has fewer leftovers.
	cleanGeneratedScripts(v.evaluator.GetTempDir(), v.logger)

	// Pre-validate: all rules must have at least 2 test cases (1 positive + 1 negative)
	for _, rule := range rules {
		var config SolidityExpressionConfig
		if err := json.Unmarshal(rule.Config, &config); err != nil {
			return nil, fmt.Errorf("invalid solidity expression config for rule %s: %w", rule.ID, err)
		}
		_, code := v.determineValidationMode(&config)
		if code == "" {
			return nil, fmt.Errorf("rule %s: either expression, functions, typed_data_expression, or typed_data_functions must be specified", rule.ID)
		}
		if len(config.TestCases) < 2 {
			return nil, fmt.Errorf("rule %s: at least 2 test cases required (got %d): need at least one positive and one negative", rule.ID, len(config.TestCases))
		}
		var positiveCount, negativeCount int
		for _, tc := range config.TestCases {
			if tc.ExpectPass {
				positiveCount++
			} else {
				negativeCount++
			}
		}
		if positiveCount == 0 {
			return nil, fmt.Errorf("rule %s: at least one positive test case (expect_pass: true) is required", rule.ID)
		}
		if negativeCount == 0 {
			return nil, fmt.Errorf("rule %s: at least one negative test case (expect_pass: false) is required", rule.ID)
		}
	}

	// Group rules by validation mode — different modes require different contract structures
	type ruleWithOrigIndex struct {
		rule      *types.Rule
		origIndex int // index in the original `rules` slice
	}
	modeGroups := make(map[ValidationMode][]ruleWithOrigIndex)
	for i, rule := range rules {
		var config SolidityExpressionConfig
		if err := json.Unmarshal(rule.Config, &config); err != nil {
			return nil, fmt.Errorf("invalid solidity expression config for rule %s: %w", rule.ID, err)
		}
		mode, _ := v.determineValidationMode(&config)
		modeGroups[mode] = append(modeGroups[mode], ruleWithOrigIndex{rule: rule, origIndex: i})
	}

	// Initialize results
	results := make([]ValidationResult, len(rules))
	allValid := true

	// Batch validate each mode group separately
	for mode, groupItems := range modeGroups {
		// Extract rules for this group
		groupRules := make([]*types.Rule, len(groupItems))
		for j, item := range groupItems {
			groupRules[j] = item.rule
		}

		v.logger.Info("Batch validating rules",
			"mode", v.modeString(mode),
			"count", len(groupRules),
		)

		// Batch validate this mode group
		groupResult, err := v.validateRulesBatchForMode(ctx, groupRules, mode)
		if err != nil {
			return nil, fmt.Errorf("batch validation failed for mode %s: %w", v.modeString(mode), err)
		}

		// Map group results back to original indices
		for j, item := range groupItems {
			results[item.origIndex] = groupResult.Results[j]
			if !groupResult.Results[j].Valid {
				allValid = false
			}
		}
	}

	return &BatchValidationResult{
		Results: results,
		Valid:   allValid,
	}, nil
}

// validateRulesBatchForMode validates multiple rules with the same validation mode
func (v *SolidityRuleValidator) validateRulesBatchForMode(ctx context.Context, rules []*types.Rule, mode ValidationMode) (*BatchValidationResult, error) {
	results := make([]ValidationResult, len(rules))
	allValid := true

	// Collect all test cases with their rule indices
	var allTestCases []testCaseWithRule

	// Parse all rules and collect test cases
	for i, rule := range rules {
		var config SolidityExpressionConfig
		if err := json.Unmarshal(rule.Config, &config); err != nil {
			results[i] = ValidationResult{
				Valid: false,
				SyntaxError: &SyntaxError{
					Message:  fmt.Sprintf("invalid config: %v", err),
					Severity: "error",
				},
			}
			allValid = false
			continue
		}

		_, code := v.determineValidationMode(&config)

		// Security validation
		if secErr := ValidateSolidityCodeSecurity(code); secErr != nil {
			results[i] = ValidationResult{
				Valid: false,
				SyntaxError: &SyntaxError{
					Message:  secErr.Message,
					Severity: "error",
				},
			}
			allValid = false
			continue
		}

		// Collect test cases
		for _, tc := range config.TestCases {
			allTestCases = append(allTestCases, testCaseWithRule{
				ruleIndex: i,
				ruleID:    rule.ID,
				ruleName:  rule.Name,
				tc:        tc,
			})
		}
	}

	// Validate syntax for all rules first (can be cached). Use rule config as single source of truth.
	for i, rule := range rules {
		var config SolidityExpressionConfig
		if err := json.Unmarshal(rule.Config, &config); err != nil {
			results[i] = ValidationResult{Valid: false}
			allValid = false
			continue
		}
		_, code := v.determineValidationMode(&config)

		// TypedData modes require explicit typed_data_struct; no type inference from message values.
		var structDef *StructDefinition
		if mode == ValidationModeTypedDataExpression || mode == ValidationModeTypedDataFunctions {
			if config.TypedDataStruct == "" {
				msg := "typed_data_expression requires typed_data_struct in rule config (rules are the single source of truth)"
				if mode == ValidationModeTypedDataFunctions {
					msg = "typed_data_functions requires typed_data_struct in rule config (rules are the single source of truth)"
				}
				results[i] = ValidationResult{
					Valid: false,
					SyntaxError: &SyntaxError{
						Message:  msg,
						Severity: "error",
					},
				}
				allValid = false
				continue
			}
			var parseErr error
			structDef, parseErr = parseStructDefinition(config.TypedDataStruct)
			if parseErr != nil {
				results[i] = ValidationResult{
					Valid: false,
					SyntaxError: &SyntaxError{
						Message:  fmt.Sprintf("invalid typed_data_struct: %v", parseErr),
						Severity: "error",
					},
				}
				allValid = false
				continue
			}
		}

		syntaxErr, err := v.validateSyntaxForModeWithStruct(ctx, code, mode, structDef)
		if err != nil {
			results[i] = ValidationResult{Valid: false}
			allValid = false
			continue
		}
		if syntaxErr != nil {
			results[i] = ValidationResult{
				Valid:       false,
				SyntaxError: syntaxErr,
			}
			allValid = false
			continue
		}
	}

	// Generate batch test contract with all test cases
	// This allows us to compile once and run all tests
	batchScript, err := v.generateBatchTestScript(rules, mode, allTestCases)
	if err != nil {
		return nil, fmt.Errorf("failed to generate batch test script: %w", err)
	}

	// Execute batch test contract (compile once, run all tests)
	batchResults, err := v.executeBatchTestScript(ctx, batchScript, len(rules), allTestCases)
	if err != nil {
		return nil, fmt.Errorf("failed to execute batch test: %w", err)
	}

	// Map batch results back to individual rule results
	// batchResults are ordered the same as allTestCases
	for i, rule := range rules {
		var config SolidityExpressionConfig
		json.Unmarshal(rule.Config, &config)

		result := ValidationResult{Valid: true}
		result.TestCaseResults = make([]TestCaseResult, len(config.TestCases))

		// Find test cases for this rule and map batch results
		testCaseIndex := 0
		for batchIdx, tcwr := range allTestCases {
			if tcwr.ruleIndex == i {
				if batchIdx < len(batchResults) && testCaseIndex < len(result.TestCaseResults) {
					result.TestCaseResults[testCaseIndex] = batchResults[batchIdx]
					if !batchResults[batchIdx].Passed {
						result.FailedTestCases++
						result.Valid = false
						allValid = false
					}
					testCaseIndex++
				}
			}
		}

		results[i] = result
	}

	return &BatchValidationResult{
		Results: results,
		Valid:   allValid,
	}, nil
}

// testCaseWithRule represents a test case with its associated rule information
type testCaseWithRule struct {
	ruleIndex int
	ruleID    types.RuleID
	ruleName  string
	tc        SolidityTestCase
}

// generateBatchTestScript generates a single test contract with all test cases
// This significantly reduces compilation time by compiling once instead of N times
func (v *SolidityRuleValidator) generateBatchTestScript(rules []*types.Rule, mode ValidationMode, allTestCases []testCaseWithRule) (string, error) {
	var testFunctions []string      // test functions placed INSIDE BatchRuleEvaluatorTest
	var topLevelContracts []string  // helper contracts placed OUTSIDE BatchRuleEvaluatorTest

	switch mode {
	case ValidationModeExpression:
		// Expression mode: simple require() statements
		for i, tcwr := range allTestCases {
			rule := rules[tcwr.ruleIndex]
			var config SolidityExpressionConfig
			if err := json.Unmarshal(rule.Config, &config); err != nil {
				return "", fmt.Errorf("failed to parse config for rule %s: %w", rule.ID, err)
			}

			// Convert test input to SignRequest and ParsedPayload
			req, parsed, err := v.testInputToRequest(tcwr.tc.Input)
			if err != nil {
				return "", fmt.Errorf("failed to convert test input for rule %s test case %d: %w", rule.ID, i, err)
			}

			// Generate test function
			testFunc := fmt.Sprintf(`    function test_%s_%d() public pure returns (bool) {
        // Transaction context
        address tx_to = %s;
        uint256 tx_value = %s;
        bytes4 tx_selector = %s;
        bytes memory tx_data = %s;

        // Signing context
        uint256 ctx_chainId = %s;
        address ctx_signer = %s;

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

        // User-defined validation logic
        %s

        return true;
    }`,
				sanitizeFunctionName(tcwr.ruleName),
				i,
				formatAddress(parsed.Recipient),
				formatWei(parsed.Value),
				formatSelector(parsed.MethodSig),
				formatBytes(parsed.RawData),
				formatChainID(req.ChainID),
				formatAddress(&req.SignerAddress),
				sanitizeEmptyComparisons(preprocessInOperator(config.Expression)),
			)
			testFunctions = append(testFunctions, testFunc)
		}

	case ValidationModeFunctions:
		// Functions mode: each rule needs its OWN RuleContract with its specific functions.
		// Different rules define different validation functions (e.g., rule A has transfer(),
		// rule B has redeemPositions()). Using a shared RuleContract would cause test cases
		// to execute the wrong rule's functions, leading to false passes/failures.

		// Parse each rule's functions and in()-mapping state (declarations + constructor init)
		type ruleFuncState struct {
			funcs           string
			mappingDecls    string
			constructorInit string
		}
		ruleFuncMap := make(map[int]ruleFuncState)
		for i, rule := range rules {
			var config SolidityExpressionConfig
			if err := json.Unmarshal(rule.Config, &config); err != nil {
				return "", fmt.Errorf("failed to parse config for rule %s: %w", rule.ID, err)
			}
			ir := processInOperatorToMappings(config.Functions, config.InMappingArrays)
			funcs := sanitizeEmptyComparisons(preprocessInOperator(ir.Modified))
			mappingDecls := strings.TrimSpace(ir.Declarations)
			if mappingDecls != "" {
				mappingDecls = "\n    " + strings.ReplaceAll(mappingDecls, "\n", "\n    ")
			}
			constructorInit := strings.TrimSpace(ir.ConstructorInit)
			if constructorInit != "" {
				constructorInit = "\n        " + strings.ReplaceAll(constructorInit, "\n", "\n        ")
			}
			ruleFuncMap[i] = ruleFuncState{funcs: funcs, mappingDecls: mappingDecls, constructorInit: constructorInit}
		}

		// Generate a separate RuleContract for each rule
		var ruleContracts []string
		for ruleIdx := range rules {
			state := ruleFuncMap[ruleIdx]
			ruleContractCode := fmt.Sprintf(`contract RuleContract_%d {
    // Transaction context available as state variables
    address public immutable txTo;
    uint256 public immutable txValue;
    bytes4 public immutable txSelector;
    bytes public txData;
    uint256 public immutable txChainId;
    address public immutable txSigner;
    %s

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
}`, ruleIdx, state.mappingDecls, state.constructorInit, state.funcs)
			ruleContracts = append(ruleContracts, ruleContractCode)
		}
		// RuleContracts go OUTSIDE BatchRuleEvaluatorTest (top-level)
		topLevelContracts = append(topLevelContracts, ruleContracts...)

		// Generate test functions for each test case, referencing the correct RuleContract
		for i, tcwr := range allTestCases {
			req, parsed, err := v.testInputToRequest(tcwr.tc.Input)
			if err != nil {
				return "", fmt.Errorf("failed to convert test input for test case %d: %w", i, err)
			}

			// Each test case uses the RuleContract for its specific rule
			testFunc := fmt.Sprintf(`    function test_%s_%d() public returns (bool) {
        // Create RuleContract for this rule's functions
        RuleContract_%d ruleContract = new RuleContract_%d(
            %s,
            %s,
            %s,
            %s,
            %s,
            %s
        );

        // Get txData from the rule contract
        bytes memory txData = ruleContract.txData();

        if (txData.length >= 4) {
            // Forward calldata to RuleContract - this is an external call
            (bool success, bytes memory returnData) = address(ruleContract).call(txData);
            if (!success) {
                // Propagate revert reason
                if (returnData.length > 0) {
                    assembly {
                        revert(add(returnData, 32), mload(returnData))
                    }
                }
                revert("no matching function or validation failed");
            }
        }

        return true;
    }`,
				sanitizeFunctionName(tcwr.ruleName),
				i,
				tcwr.ruleIndex,
				tcwr.ruleIndex,
				formatAddress(parsed.Recipient),
				formatWei(parsed.Value),
				formatSelector(parsed.MethodSig),
				formatBytes(parsed.RawData),
				formatChainID(req.ChainID),
				formatAddress(&req.SignerAddress),
			)
			testFunctions = append(testFunctions, testFunc)
		}

	case ValidationModeTypedDataExpression:
		// TypedDataExpression mode: EIP-712 with require() statements
		// Collect struct definitions from rules for generating contract-level structs
		structDefs := make(map[string]*StructDefinition)
		for _, rule := range rules {
			var config SolidityExpressionConfig
			if err := json.Unmarshal(rule.Config, &config); err != nil {
				continue
			}
			if config.TypedDataStruct != "" {
				if sd, err := parseStructDefinition(config.TypedDataStruct); err == nil {
					structDefs[sd.Name] = sd
				}
			}
		}

		// Generate struct definitions at contract level
		var structDefinitions []string
		for _, sd := range structDefs {
			structDefinitions = append(structDefinitions, generateStructDefinition(sd))
		}

		// Collect all in()-mapping declarations from rules for contract-level declarations
		allDeclarations := make(map[string]bool)
		for _, rule := range rules {
			var config SolidityExpressionConfig
			if err := json.Unmarshal(rule.Config, &config); err != nil {
				continue
			}
			ir := processInOperatorToMappings(config.TypedDataExpression, config.InMappingArrays)
			for _, line := range strings.Split(ir.Declarations, "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					allDeclarations[line] = true
				}
			}
		}
		var inMappingDecls []string
		for d := range allDeclarations {
			inMappingDecls = append(inMappingDecls, "    "+d)
		}
		sort.Strings(inMappingDecls)
		inMappingDeclarationsStr := strings.Join(inMappingDecls, "\n")

		for i, tcwr := range allTestCases {
			rule := rules[tcwr.ruleIndex]
			var config SolidityExpressionConfig
			if err := json.Unmarshal(rule.Config, &config); err != nil {
				return "", fmt.Errorf("failed to parse config for rule %s: %w", rule.ID, err)
			}

			// Build typed data from test input
			typedData, err := v.buildTypedDataFromInput(tcwr.tc.Input)
			if err != nil {
				return "", fmt.Errorf("failed to build typed data for test case %d: %w", i, err)
			}

			// Convert test input to SignRequest
			req := v.testInputToTypedDataRequest(tcwr.tc.Input, typedData)

			// TypedDataExpression requires typed_data_struct (enforced above); no type inference.
			structDef, parseErr := parseStructDefinition(config.TypedDataStruct)
			if parseErr != nil {
				return "", fmt.Errorf("failed to parse typed data struct: %w", parseErr)
			}
			if structDef == nil {
				return "", fmt.Errorf("rule %s: typed_data_expression requires typed_data_struct in config", rule.Name)
			}
			structInstance := generateStructInstance(structDef, typedData.Message)

			ir := processInOperatorToMappings(config.TypedDataExpression, config.InMappingArrays)
			expression := sanitizeEmptyComparisons(preprocessInOperator(ir.Modified))
			mappingInit := strings.TrimSpace(ir.ConstructorInit)
			if mappingInit != "" {
				mappingInit = mappingInit + "\n\n        "
			}
			// If we have mapping init, function cannot be pure (writes to state)
			// If expression reads block/msg/tx (e.g. block.timestamp), use view
			funcModifier := " pure"
			if mappingInit != "" {
				funcModifier = ""
			}
			if funcModifier == " pure" && (strings.Contains(expression, "block.") || strings.Contains(expression, "msg.") || strings.Contains(expression, " tx.")) {
				funcModifier = " view"
			}

			// Generate test function
			testFunc := fmt.Sprintf(`    function test_%s_%d() public%s returns (bool) {
        // EIP-712 Domain context
        string memory eip712_primaryType = %s;
        string memory eip712_domainName = %s;
        string memory eip712_domainVersion = %s;
        uint256 eip712_domainChainId = %s;
        address eip712_domainContract = %s;

        // Signing context
        address ctx_signer = %s;
        uint256 ctx_chainId = %s;

        // Suppress unused variable warnings
        bytes memory _eip712_primaryType = bytes(eip712_primaryType);
        bytes memory _eip712_domainName = bytes(eip712_domainName);
        bytes memory _eip712_domainVersion = bytes(eip712_domainVersion);
        eip712_domainChainId; eip712_domainContract; ctx_signer; ctx_chainId;
        _eip712_primaryType; _eip712_domainName; _eip712_domainVersion;

        // EIP-712 Message struct instance
        %s

        // In-mapping init (for in(expr, varName))
        %s
        // User-defined validation logic
        %s

        return true;
    }`,
				sanitizeFunctionName(tcwr.ruleName),
				i,
				funcModifier,
				formatString(typedData.PrimaryType),
				formatString(typedData.Domain.Name),
				formatString(typedData.Domain.Version),
				formatDomainChainId(typedData.Domain.ChainId),
				formatDomainContract(typedData.Domain.VerifyingContract),
				formatAddress(&req.SignerAddress),
				formatChainID(req.ChainID),
				structInstance,
				mappingInit,
				expression,
			)
			testFunctions = append(testFunctions, testFunc)
		}

		// Prepend contract-level in-mapping declarations and struct definitions
		if inMappingDeclarationsStr != "" {
			testFunctions = append([]string{inMappingDeclarationsStr}, testFunctions...)
		}
		// Add struct definitions at the beginning of the test functions
		if len(structDefinitions) > 0 {
			testFunctions = append(structDefinitions, testFunctions...)
		}

	case ValidationModeTypedDataFunctions:
		// TypedDataFunctions mode: EIP-712 with user-defined functions
		// Collect all unique function sets
		ruleFuncMap := make(map[int]string)
		for i, rule := range rules {
			var config SolidityExpressionConfig
			if err := json.Unmarshal(rule.Config, &config); err != nil {
				return "", fmt.Errorf("failed to parse config for rule %s: %w", rule.ID, err)
			}
			ruleFuncMap[i] = sanitizeEmptyComparisons(preprocessInOperator(config.TypedDataFunctions))
		}

		// Generate test functions for each test case
		for i, tcwr := range allTestCases {
			typedData, err := v.buildTypedDataFromInput(tcwr.tc.Input)
			if err != nil {
				return "", fmt.Errorf("failed to build typed data for test case %d: %w", i, err)
			}

			req := v.testInputToTypedDataRequest(tcwr.tc.Input, typedData)
			messageData := encodeMessageData(typedData)

			// Generate test function
			testFunc := fmt.Sprintf(`    function test_%s_%d() public returns (bool) {
        // Create RuleContract with typed data context
        RuleContract ruleContract = new RuleContract(
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s
        );

        // Call the validate function
        ruleContract.run();
        return true;
    }`,
				sanitizeFunctionName(tcwr.ruleName),
				i,
				formatString(typedData.PrimaryType),
				formatString(typedData.Domain.Name),
				formatString(typedData.Domain.Version),
				formatDomainChainId(typedData.Domain.ChainId),
				formatDomainContract(typedData.Domain.VerifyingContract),
				formatAddress(&req.SignerAddress),
				formatChainID(req.ChainID),
				messageData,
			)
			testFunctions = append(testFunctions, testFunc)
		}

		// Add RuleContract with all user functions
		if len(rules) > 0 {
			var config SolidityExpressionConfig
			if err := json.Unmarshal(rules[0].Config, &config); err == nil {
				ruleContractCode := fmt.Sprintf(`contract RuleContract {
    // EIP-712 Domain context
    string public immutable eip712_primaryType;
    string public immutable eip712_domainName;
    string public immutable eip712_domainVersion;
    uint256 public immutable eip712_domainChainId;
    address public immutable eip712_domainContract;

    // Signing context
    address public immutable ctx_signer;
    uint256 public immutable ctx_chainId;

    // EIP-712 Message encoded as bytes for struct decoding
    bytes public messageData;

    constructor(
        string memory _primaryType,
        string memory _domainName,
        string memory _domainVersion,
        uint256 _domainChainId,
        address _domainContract,
        address _signer,
        uint256 _chainId,
        bytes memory _messageData
    ) {
        eip712_primaryType = _primaryType;
        eip712_domainName = _domainName;
        eip712_domainVersion = _domainVersion;
        eip712_domainChainId = _domainChainId;
        eip712_domainContract = _domainContract;
        ctx_signer = _signer;
        ctx_chainId = _chainId;
        messageData = _messageData;
    }

    // User-defined structs and validation functions
    %s

    function run() public returns (bool) {
        // Call the validate function with decoded message
        _validateMessage();
        return true;
    }

    function _validateMessage() internal virtual {
        // Override in user functions if needed
    }
}`,
					sanitizeEmptyComparisons(preprocessInOperator(config.TypedDataFunctions)),
				)
				// RuleContract goes OUTSIDE BatchRuleEvaluatorTest (top-level)
				topLevelContracts = append(topLevelContracts, ruleContractCode)
			}
		}

	default:
		return "", fmt.Errorf("unsupported validation mode: %d", mode)
	}

	// Combine: top-level contracts go BEFORE the test contract, test functions go INSIDE
	var sb strings.Builder
	sb.WriteString("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n\n")

	// Write top-level helper contracts (e.g., RuleContract_0, RuleContract_1, ...)
	for _, c := range topLevelContracts {
		sb.WriteString(c)
		sb.WriteString("\n\n")
	}

	// Write the main test contract containing all test functions
	sb.WriteString("contract BatchRuleEvaluatorTest {\n")
	sb.WriteString(strings.Join(testFunctions, "\n\n"))
	sb.WriteString("\n}\n")

	return sb.String(), nil
}

// sanitizeFunctionName sanitizes a rule name to be a valid Solidity function name
func sanitizeFunctionName(name string) string {
	// Replace invalid characters with underscores
	re := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	sanitized := re.ReplaceAllString(name, "_")
	// Ensure it starts with a letter or underscore
	if len(sanitized) > 0 && (sanitized[0] >= '0' && sanitized[0] <= '9') {
		sanitized = "_" + sanitized
	}
	// Limit length to avoid issues
	if len(sanitized) > 50 {
		sanitized = sanitized[:50]
	}
	return sanitized
}

// executeBatchTestScript executes the batch test script and returns results for all test cases
func (v *SolidityRuleValidator) executeBatchTestScript(ctx context.Context, script string, ruleCount int, allTestCases []testCaseWithRule) ([]TestCaseResult, error) {
	// Calculate script hash for caching/naming
	hash := sha256.Sum256([]byte(script))
	hashStr := hex.EncodeToString(hash[:8])

	tempDir := v.evaluator.GetTempDir()
	scriptPath := filepath.Join(tempDir, fmt.Sprintf("batch_rule_%s.t.sol", hashStr))

	// Remove other batch_rule_*.t.sol so forge only compiles this script (avoids stale files with different syntax)
	matches, err := filepath.Glob(filepath.Join(tempDir, "batch_rule_*.t.sol"))
	if err != nil {
		return nil, fmt.Errorf("glob batch scripts: %w", err)
	}
	for _, p := range matches {
		if p != scriptPath {
			if removeErr := os.Remove(p); removeErr != nil {
				slog.Debug("remove stale batch script", "path", p, "error", removeErr)
			}
		}
	}

	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		return nil, fmt.Errorf("failed to write batch script: %w", err)
	}

	// Create timeout context if not already set (use evaluator timeout so config applies; cold cache can be slow)
	execCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		t := v.evaluator.GetTimeout()
		if t < 60*time.Second {
			t = 60 * time.Second
		}
		execCtx, cancel = context.WithTimeout(ctx, t)
		defer cancel()
	}

	// Execute forge test
	cmd := exec.CommandContext(execCtx,
		v.evaluator.GetFoundryPath(), "test",
		"--match-path", scriptPath,
		"--match-contract", "BatchRuleEvaluatorTest",
		"--cache-path", filepath.Join(v.evaluator.GetCacheDir(), "forge-cache"),
		"-vvv", // verbose for revert reasons
	)

	// Set working directory to temp dir where foundry.toml exists
	cmd.Dir = v.evaluator.GetTempDir()

	// Security: Use minimal environment to prevent leaking secrets to user-controlled Solidity code
	cmd.Env = safeForgeEnv()

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	// Parse test results from forge output
	results := make([]TestCaseResult, len(allTestCases))

	// Initialize all results with default values
	for i, tcwr := range allTestCases {
		results[i] = TestCaseResult{
			Name:         tcwr.tc.Name,
			ExpectedPass: tcwr.tc.ExpectPass,
			ExpectedReason: tcwr.tc.ExpectReason,
		}
	}

	if err != nil {
		// Check if this is a compilation error (no tests ran at all)
		// Compilation errors contain "Compiler run failed" or "Error (" patterns
		// but NOT "[FAIL" or "[PASS" patterns (which indicate tests ran)
		isCompilationError := (strings.Contains(outputStr, "Compiler run failed") ||
			strings.Contains(outputStr, "Error (")) &&
			!strings.Contains(outputStr, "[FAIL") &&
			!strings.Contains(outputStr, "[PASS")
		if isCompilationError {
			return nil, fmt.Errorf("batch test compilation failed: %s", outputStr)
		}

		// Parse individual test failures from forge output
		// Forge output formats vary by version:
		//   [FAIL: <reason>] test_<ruleName>_<index>()           (forge >= 0.2.0)
		//   [FAIL. Reason: <reason>] test_<ruleName>_<index>()   (older forge)
		failPattern := regexp.MustCompile(`\[FAIL[.:]\s*(?:Reason:\s*)?([^\]]+)\]\s*test_(\w+)_(\d+)\(\)`)
		matches := failPattern.FindAllStringSubmatch(outputStr, -1)

		// Track which tests passed (default to true, set to false if found in failures)
		testPassed := make(map[int]bool)
		for i := range allTestCases {
			testPassed[i] = true // Default to passed
		}

		// Process failures
		for _, match := range matches {
			if len(match) >= 4 {
				reason := strings.TrimSpace(match[1])
				testIndexStr := match[3]
				testIndex := 0
				if idx, err := strconv.Atoi(testIndexStr); err == nil {
					testIndex = idx
					if testIndex < len(results) {
						testPassed[testIndex] = false
						results[testIndex].Passed = false
						results[testIndex].ActualPass = false
						results[testIndex].ActualReason = reason
						results[testIndex].Error = reason
					}
				}
			}
		}

		// Check for tests that passed (not in failure list)
		for i := range results {
			if testPassed[i] {
				results[i].Passed = true
				results[i].ActualPass = true
			}
		}

		// Compare with expectations
		for i := range results {
			if v.compareTestResult(allTestCases[i].tc.ExpectPass, results[i].ActualPass, allTestCases[i].tc.ExpectReason, results[i].ActualReason) {
				// Test result matches expectation — this is a validation pass
				results[i].Passed = true
				results[i].Error = ""
			} else {
				results[i].Passed = false
				if allTestCases[i].tc.ExpectPass && !results[i].ActualPass {
					results[i].Error = fmt.Sprintf("expected pass but got revert: %s", results[i].ActualReason)
				} else if !allTestCases[i].tc.ExpectPass && results[i].ActualPass {
					results[i].Error = "expected revert but passed"
				} else if allTestCases[i].tc.ExpectReason != "" && !strings.Contains(results[i].ActualReason, allTestCases[i].tc.ExpectReason) {
					results[i].Error = fmt.Sprintf("expected reason containing '%s' but got '%s'", allTestCases[i].tc.ExpectReason, results[i].ActualReason)
				}
			}
		}

		// If context was cancelled, return error
		if execCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("batch test execution timed out")
		}

		// Return results even if some tests failed (this is expected)
		return results, nil
	}

	// All tests passed
	for i := range results {
		results[i].Passed = true
		results[i].ActualPass = true
	}

	return results, nil
}

// determineValidationMode determines the validation mode based on config fields
func (v *SolidityRuleValidator) determineValidationMode(config *SolidityExpressionConfig) (ValidationMode, string) {
	// Priority: TypedDataExpression > TypedDataFunctions > Functions > Expression
	if config.TypedDataExpression != "" {
		return ValidationModeTypedDataExpression, config.TypedDataExpression
	}
	if config.TypedDataFunctions != "" {
		return ValidationModeTypedDataFunctions, config.TypedDataFunctions
	}
	if config.Functions != "" {
		return ValidationModeFunctions, config.Functions
	}
	return ValidationModeExpression, config.Expression
}

// modeString returns a human-readable string for the validation mode
func (v *SolidityRuleValidator) modeString(mode ValidationMode) string {
	switch mode {
	case ValidationModeExpression:
		return "expression"
	case ValidationModeFunctions:
		return "functions"
	case ValidationModeTypedDataExpression:
		return "typed_data_expression"
	case ValidationModeTypedDataFunctions:
		return "typed_data_functions"
	default:
		return "unknown"
	}
}

// validateSyntaxForMode compiles the Solidity code to check for syntax errors based on mode
func (v *SolidityRuleValidator) validateSyntaxForMode(ctx context.Context, code string, mode ValidationMode) (*SyntaxError, error) {
	return v.validateSyntaxForModeWithStruct(ctx, code, mode, nil)
}

// validateSyntaxForModeWithStruct compiles the Solidity code to check for syntax errors based on mode
// If structDef is provided, it will be used for struct-based syntax checking in TypedDataExpression mode
func (v *SolidityRuleValidator) validateSyntaxForModeWithStruct(ctx context.Context, code string, mode ValidationMode, structDef *StructDefinition) (*SyntaxError, error) {
	var script string
	switch mode {
	case ValidationModeExpression:
		script = v.evaluator.GenerateSyntaxCheckScript(code)
	case ValidationModeFunctions:
		script = v.evaluator.GenerateFunctionSyntaxCheckScript(code)
	case ValidationModeTypedDataExpression:
		script = v.evaluator.GenerateTypedDataExpressionSyntaxCheckScriptWithStruct(code, structDef)
	case ValidationModeTypedDataFunctions:
		script = v.evaluator.GenerateTypedDataFunctionsSyntaxCheckScript(code)
	default:
		return nil, fmt.Errorf("unknown validation mode: %d", mode)
	}
	return v.compileSyntaxCheckScript(ctx, script)
}

// buildTypedDataFromInput constructs a TypedDataPayload from test input
func (v *SolidityRuleValidator) buildTypedDataFromInput(input SolidityTestInput) (*TypedDataPayload, error) {
	if input.TypedData == nil {
		return nil, fmt.Errorf("typed_data field is required for EIP-712 test cases")
	}

	typedData := &TypedDataPayload{
		PrimaryType: input.TypedData.PrimaryType,
		Message:     input.TypedData.Message,
		Types:       make(map[string][]TypedDataField),
	}

	// Set default primary type if not specified
	if typedData.PrimaryType == "" {
		typedData.PrimaryType = "Permit" // Common default for EIP-2612
	}

	// Build domain from input
	if input.TypedData.Domain != nil {
		typedData.Domain = TypedDataDomain{
			Name:              input.TypedData.Domain.Name,
			Version:           input.TypedData.Domain.Version,
			ChainId:           input.TypedData.Domain.ChainID,
			VerifyingContract: input.TypedData.Domain.VerifyingContract,
			Salt:              input.TypedData.Domain.Salt,
		}
	}

	// Infer types from message fields if not explicitly provided
	// This allows test cases to work without explicit type definitions
	if typedData.Message != nil {
		fields := make([]TypedDataField, 0, len(typedData.Message))
		for name, value := range typedData.Message {
			fieldType := inferSolidityType(value)
			fields = append(fields, TypedDataField{
				Name: name,
				Type: fieldType,
			})
		}
		typedData.Types[typedData.PrimaryType] = fields
	}

	return typedData, nil
}

// testInputToTypedDataRequest converts test input to a SignRequest with typed data payload
func (v *SolidityRuleValidator) testInputToTypedDataRequest(input SolidityTestInput, typedData *TypedDataPayload) *types.SignRequest {
	req := &types.SignRequest{
		ChainID:       input.ChainID,
		SignerAddress: input.Signer,
		SignType:      SignTypeTypedData,
	}
	if req.ChainID == "" {
		req.ChainID = "1"
	}
	if req.SignerAddress == "" {
		req.SignerAddress = "0x0000000000000000000000000000000000000000"
	}

	// Encode typed data as payload
	evmPayload := EVMSignPayload{
		TypedData: typedData,
	}
	payload, _ := json.Marshal(evmPayload)
	req.Payload = payload

	return req
}

// inferSolidityType infers the Solidity type from a Go value
func inferSolidityType(value interface{}) string {
	switch v := value.(type) {
	case string:
		// Check if it's an address (0x + 40 hex chars)
		if len(v) == 42 && strings.HasPrefix(v, "0x") {
			return "address"
		}
		// Check if it's bytes32 (0x + 64 hex chars)
		if len(v) == 66 && strings.HasPrefix(v, "0x") {
			return "bytes32"
		}
		// Numeric string (including values > Int64, e.g. "100000000000000000000")
		if isDecimalString(v) {
			return "uint256"
		}
		if strings.HasPrefix(v, "-") && isDecimalString(strings.TrimPrefix(v, "-")) {
			return "int256"
		}
		return "string"
	case float64:
		return "uint256"
	case int, int64, uint64:
		return "uint256"
	case bool:
		return "bool"
	case []byte:
		return "bytes"
	default:
		return "bytes"
	}
}

// compileSyntaxCheckScript compiles a syntax check script and returns any errors
func (v *SolidityRuleValidator) compileSyntaxCheckScript(ctx context.Context, script string) (*SyntaxError, error) {
	// Calculate script hash for caching
	hash := sha256.Sum256([]byte(script))
	hashStr := hex.EncodeToString(hash[:])

	// Check cache first
	v.syntaxCacheMu.RLock()
	cached, found := v.syntaxCache[hashStr]
	v.syntaxCacheMu.RUnlock()
	if found && cached {
		return nil, nil // Syntax is valid (cached)
	}
	// If not found, or cached as invalid, we need to (re)compile to get the actual error message

	// Use unique filename based on hash to enable forge incremental compilation
	scriptPath := filepath.Join(v.evaluator.GetTempDir(), fmt.Sprintf("syntax_check_%s.sol", hashStr[:16]))

	// Check if file already exists (from previous compilation)
	if _, err := os.Stat(scriptPath); err == nil {
		// File exists, check if compilation output exists
		outDir := filepath.Join(v.evaluator.GetTempDir(), "out")
		if _, err := os.Stat(outDir); err == nil {
			// Output exists, syntax is valid (cached by forge)
			v.syntaxCacheMu.Lock()
			v.syntaxCache[hashStr] = true
			v.syntaxCacheMu.Unlock()
			return nil, nil
		}
	}

	// Write script file
	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		return nil, fmt.Errorf("failed to write script: %w", err)
	}
	// Don't delete script file - keep it for forge incremental compilation

	// Create timeout context (use evaluator timeout: cold cache compile can exceed 30s)
	t := v.evaluator.GetTimeout()
	if t < 60*time.Second {
		t = 60 * time.Second
	}
	execCtx, cancel := context.WithTimeout(ctx, t)
	defer cancel()

	// Run forge build with cache path for incremental compilation
	cachePath := filepath.Join(v.evaluator.GetCacheDir(), "forge-cache")
	cmd := exec.CommandContext(execCtx,
		v.evaluator.GetFoundryPath(), "build",
		"--root", v.evaluator.GetTempDir(),
		"--cache-path", cachePath,
	)

	// Security: Use minimal environment to prevent leaking secrets to user-controlled Solidity code
	cmd.Env = safeForgeEnv()

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Parse compilation error
		syntaxErr := parseSolidityError(string(output))
		// CRITICAL: Remove the failing syntax check file so it doesn't poison
		// subsequent forge builds (forge compiles ALL .sol files in the directory)
		os.Remove(scriptPath)
		// Cache as invalid
		v.syntaxCacheMu.Lock()
		v.syntaxCache[hashStr] = false
		v.syntaxCacheMu.Unlock()
		return syntaxErr, nil
	}

	// Cache as valid
	v.syntaxCacheMu.Lock()
	v.syntaxCache[hashStr] = true
	v.syntaxCacheMu.Unlock()

	// Don't delete output directory - keep it for forge incremental compilation
	return nil, nil
}

// compareTestResult compares expected and actual test results
func (v *SolidityRuleValidator) compareTestResult(expectPass, actualPass bool, expectReason, actualReason string) bool {
	if expectPass {
		// Expected to pass - actual must also pass
		return actualPass
	}

	// Expected to fail
	if actualPass {
		// But it passed - failure
		return false
	}

	// Both expected and actual are failures
	// If expect_reason is specified, check if actual reason contains it
	if expectReason != "" {
		return strings.Contains(actualReason, expectReason)
	}

	// No specific reason expected, any failure is ok
	return true
}

// testInputToRequest converts test input to request structures
func (v *SolidityRuleValidator) testInputToRequest(input SolidityTestInput) (*types.SignRequest, *types.ParsedPayload, error) {
	req := &types.SignRequest{
		ChainID:       input.ChainID,
		SignerAddress: input.Signer,
	}
	if req.ChainID == "" {
		req.ChainID = "1"
	}
	if req.SignerAddress == "" {
		req.SignerAddress = "0x0000000000000000000000000000000000000000"
	}

	parsed := &types.ParsedPayload{}
	if input.To != "" {
		parsed.Recipient = &input.To
	}
	if input.Value != "" {
		parsed.Value = &input.Value
	}
	if input.Selector != "" {
		parsed.MethodSig = &input.Selector
	}
	if input.Data != "" {
		data, err := hex.DecodeString(strings.TrimPrefix(input.Data, "0x"))
		if err != nil {
			return nil, nil, fmt.Errorf("invalid hex data in test input: %w (data length %d chars, must be even)", err, len(strings.TrimPrefix(input.Data, "0x")))
		}
		parsed.RawData = data
	}

	return req, parsed, nil
}

// parseSolidityError extracts error details from forge output
func parseSolidityError(output string) *SyntaxError {
	// Parse forge's error format to extract line/column info
	// Example formats:
	// "Error (1234): <message>"
	// "ParserError: <message>"
	// "TypeError: <message>"

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Check for error patterns
		if strings.Contains(line, "Error") || strings.Contains(line, "error") {
			return &SyntaxError{
				Message:  line,
				Severity: "error",
			}
		}
		if strings.Contains(line, "ParserError") || strings.Contains(line, "TypeError") {
			return &SyntaxError{
				Message:  line,
				Severity: "error",
			}
		}
	}

	// If we couldn't parse a specific error, return the whole output
	if strings.TrimSpace(output) != "" {
		return &SyntaxError{
			Message:  strings.TrimSpace(output),
			Severity: "error",
		}
	}

	return &SyntaxError{
		Message:  "unknown compilation error",
		Severity: "error",
	}
}
