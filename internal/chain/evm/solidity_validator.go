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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// dangerousPatterns contains regex patterns for dangerous Foundry cheatcodes
// These patterns are checked before rule execution to prevent code injection attacks
var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)vm\s*\.\s*ffi\s*\(`),           // vm.ffi() - arbitrary command execution
	regexp.MustCompile(`(?i)vm\s*\.\s*readFile\s*\(`),      // vm.readFile() - file read
	regexp.MustCompile(`(?i)vm\s*\.\s*writeFile\s*\(`),     // vm.writeFile() - file write
	regexp.MustCompile(`(?i)vm\s*\.\s*removeFile\s*\(`),    // vm.removeFile() - file delete
	regexp.MustCompile(`(?i)vm\s*\.\s*readDir\s*\(`),       // vm.readDir() - directory read
	regexp.MustCompile(`(?i)vm\s*\.\s*fsMetadata\s*\(`),    // vm.fsMetadata() - file metadata
	regexp.MustCompile(`(?i)vm\s*\.\s*envOr\s*\(`),         // vm.envOr() - environment variable read
	regexp.MustCompile(`(?i)vm\s*\.\s*setEnv\s*\(`),        // vm.setEnv() - environment variable write
	regexp.MustCompile(`(?i)vm\s*\.\s*projectRoot\s*\(`),   // vm.projectRoot() - path disclosure
	regexp.MustCompile(`(?i)vm\s*\.\s*rpc\s*\(`),           // vm.rpc() - external RPC calls
	regexp.MustCompile(`(?i)vm\s*\.\s*createFork\s*\(`),    // vm.createFork() - network access
	regexp.MustCompile(`(?i)vm\s*\.\s*selectFork\s*\(`),    // vm.selectFork() - network access
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
	var config SolidityExpressionConfig
	if err := json.Unmarshal(rule.Config, &config); err != nil {
		return nil, fmt.Errorf("invalid solidity expression config: %w", err)
	}

	// Determine validation mode and code
	mode, code := v.determineValidationMode(&config)

	// Validate that at least one mode is specified
	if code == "" {
		return nil, fmt.Errorf("either expression, functions, typed_data_expression, or typed_data_functions must be specified")
	}

	// Step 0: Security validation - check for dangerous patterns
	if secErr := ValidateSolidityCodeSecurity(code); secErr != nil {
		v.logger.Warn("security validation failed",
			"rule_id", rule.ID,
			"pattern", secErr.Pattern,
		)
		return nil, fmt.Errorf("security validation failed: %s", secErr.Message)
	}

	// Parse struct definition early if provided (for TypedData modes)
	// This is needed for both syntax validation and test case execution
	var structDef *StructDefinition
	if config.TypedDataStruct != "" {
		var structErr error
		structDef, structErr = parseStructDefinition(config.TypedDataStruct)
		if structErr != nil {
			return nil, fmt.Errorf("failed to parse typed_data_struct: %w", structErr)
		}
	}

	result := &ValidationResult{Valid: true}

	// Step 1: Syntax validation via forge build
	v.logger.Debug("validating Solidity syntax",
		"rule_id", rule.ID,
		"mode", v.modeString(mode),
	)
	syntaxErr, err := v.validateSyntaxForModeWithStruct(ctx, code, mode, structDef)
	if err != nil {
		return nil, fmt.Errorf("syntax validation failed: %w", err)
	}
	if syntaxErr != nil {
		v.logger.Warn("syntax validation failed",
			"rule_id", rule.ID,
			"error", syntaxErr.Message,
		)
		result.Valid = false
		result.SyntaxError = syntaxErr
		return result, nil
	}
	v.logger.Debug("syntax validation passed", "rule_id", rule.ID)

	// Step 2: Validate test cases requirement
	// Rules MUST have at least 2 test cases: one positive (expect_pass: true) and one negative (expect_pass: false)
	if len(config.TestCases) < 2 {
		return nil, fmt.Errorf("at least 2 test cases required for Solidity expression rules (got %d): need at least one positive (expect_pass: true) and one negative (expect_pass: false)", len(config.TestCases))
	}

	// Count positive and negative test cases
	var positiveCount, negativeCount int
	for _, tc := range config.TestCases {
		if tc.ExpectPass {
			positiveCount++
		} else {
			negativeCount++
		}
	}
	if positiveCount == 0 {
		return nil, fmt.Errorf("at least one positive test case (expect_pass: true) is required")
	}
	if negativeCount == 0 {
		return nil, fmt.Errorf("at least one negative test case (expect_pass: false) is required")
	}

	result.TestCaseResults = make([]TestCaseResult, len(config.TestCases))

	// Execute test cases in parallel for better performance
	type testCaseJob struct {
		index int
		tc    SolidityTestCase
	}
	jobs := make(chan testCaseJob, len(config.TestCases))
	resultsChan := make(chan struct {
		index int
		result TestCaseResult
	}, len(config.TestCases))

	// Start worker goroutines (limit concurrency to avoid overwhelming the system)
	maxWorkers := 4
	if len(config.TestCases) < maxWorkers {
		maxWorkers = len(config.TestCases)
	}

	// Start workers
	for w := 0; w < maxWorkers; w++ {
		go func() {
			for job := range jobs {
				v.logger.Debug("executing test case",
					"rule_id", rule.ID,
					"test_case", job.tc.Name,
					"index", job.index,
				)
				tcResult := v.executeTestCaseForMode(ctx, code, job.tc, mode, structDef)
				resultsChan <- struct {
					index  int
					result TestCaseResult
				}{job.index, tcResult}
			}
		}()
	}

	// Send jobs
	for i, tc := range config.TestCases {
		jobs <- testCaseJob{index: i, tc: tc}
	}
	close(jobs)

	// Collect results
	for i := 0; i < len(config.TestCases); i++ {
		res := <-resultsChan
		result.TestCaseResults[res.index] = res.result

		if !res.result.Passed {
			result.FailedTestCases++
			result.Valid = false
			v.logger.Warn("test case failed",
				"rule_id", rule.ID,
				"test_case", res.result.Name,
				"error", res.result.Error,
			)
		} else {
			v.logger.Debug("test case passed",
				"rule_id", rule.ID,
				"test_case", res.result.Name,
			)
		}
	}

	return result, nil
}

// ValidateRulesBatch validates multiple rules in a single compilation
// This significantly improves performance by reducing the number of forge compilations
func (v *SolidityRuleValidator) ValidateRulesBatch(ctx context.Context, rules []*types.Rule) (*BatchValidationResult, error) {
	if len(rules) == 0 {
		return &BatchValidationResult{Results: []ValidationResult{}, Valid: true}, nil
	}

	// Group rules by validation mode (they must use the same mode to be batched)
	// For now, we'll only batch rules with the same mode
	// Different modes require different contract structures
	modeGroups := make(map[ValidationMode][]*types.Rule)
	for _, rule := range rules {
		var config SolidityExpressionConfig
		if err := json.Unmarshal(rule.Config, &config); err != nil {
			return nil, fmt.Errorf("invalid solidity expression config for rule %s: %w", rule.ID, err)
		}
		mode, _ := v.determineValidationMode(&config)
		modeGroups[mode] = append(modeGroups[mode], rule)
	}

	// For simplicity, if rules have different modes, fall back to individual validation
	// In the future, we could batch each mode separately
	if len(modeGroups) > 1 {
		return nil, fmt.Errorf("cannot batch rules with different validation modes")
	}

	// Get the single mode
	var mode ValidationMode
	var modeRules []*types.Rule
	for m, rs := range modeGroups {
		mode = m
		modeRules = rs
		break
	}

	// Batch validate all rules with the same mode
	return v.validateRulesBatchForMode(ctx, modeRules, mode)
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

	// Validate syntax for all rules first (can be cached)
	for i, rule := range rules {
		var config SolidityExpressionConfig
		json.Unmarshal(rule.Config, &config)
		_, code := v.determineValidationMode(&config)

		syntaxErr, err := v.validateSyntaxForMode(ctx, code, mode)
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
		// Fall back to individual validation if batch generation fails
		v.logger.Warn("batch test generation failed, using individual validation", "error", err)
		return v.validateRulesIndividually(ctx, rules, results, allValid)
	}

	// Execute batch test contract (compile once, run all tests)
	batchResults, err := v.executeBatchTestScript(ctx, batchScript, len(rules), allTestCases)
	if err != nil {
		// Fall back to individual validation
		v.logger.Warn("batch test execution failed, using individual validation", "error", err)
		return v.validateRulesIndividually(ctx, rules, results, allValid)
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

// validateRulesIndividually is a fallback that validates rules individually
func (v *SolidityRuleValidator) validateRulesIndividually(ctx context.Context, rules []*types.Rule, results []ValidationResult, allValid bool) (*BatchValidationResult, error) {
	type ruleJob struct {
		index int
		rule  *types.Rule
	}
	jobs := make(chan ruleJob, len(rules))
	resultsChan := make(chan struct {
		index  int
		result ValidationResult
	}, len(rules))

	// Start workers
	maxWorkers := 4
	if len(rules) < maxWorkers {
		maxWorkers = len(rules)
	}

	for w := 0; w < maxWorkers; w++ {
		go func() {
			for job := range jobs {
				validationResult, err := v.ValidateRule(ctx, job.rule)
				if err != nil {
					resultsChan <- struct {
						index  int
						result ValidationResult
					}{
						index: job.index,
						result: ValidationResult{
							Valid: false,
							SyntaxError: &SyntaxError{
								Message:  err.Error(),
								Severity: "error",
							},
						},
					}
				} else {
					resultsChan <- struct {
						index  int
						result ValidationResult
					}{job.index, *validationResult}
				}
			}
		}()
	}

	// Send jobs
	for i, rule := range rules {
		jobs <- ruleJob{index: i, rule: rule}
	}
	close(jobs)

	// Collect results
	for i := 0; i < len(rules); i++ {
		res := <-resultsChan
		results[res.index] = res.result
		if !res.result.Valid {
			allValid = false
		}
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
	var testFunctions []string

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
			req, parsed := v.testInputToRequest(tcwr.tc.Input)

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
				config.Expression,
			)
			testFunctions = append(testFunctions, testFunc)
		}

	case ValidationModeFunctions:
		// Functions mode: need RuleContract with user functions
		// Collect all unique function sets (rules may share functions)
		ruleFuncMap := make(map[int]string) // rule index -> functions code
		for i, rule := range rules {
			var config SolidityExpressionConfig
			if err := json.Unmarshal(rule.Config, &config); err != nil {
				return "", fmt.Errorf("failed to parse config for rule %s: %w", rule.ID, err)
			}
			ruleFuncMap[i] = config.Functions
		}

		// Generate test functions for each test case
		for i, tcwr := range allTestCases {
			req, parsed := v.testInputToRequest(tcwr.tc.Input)

			// Generate test function that creates RuleContract and calls it
			testFunc := fmt.Sprintf(`    function test_%s_%d() public returns (bool) {
        // Create RuleContract with transaction context
        RuleContract ruleContract = new RuleContract(
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
				formatAddress(parsed.Recipient),
				formatWei(parsed.Value),
				formatSelector(parsed.MethodSig),
				formatBytes(parsed.RawData),
				formatChainID(req.ChainID),
				formatAddress(&req.SignerAddress),
			)
			testFunctions = append(testFunctions, testFunc)
		}

		// Add RuleContract with all user functions (deduplicated)
		// Use the first rule's functions as the contract definition
		// Note: In batch mode, we assume all rules in the batch use compatible function sets
		if len(rules) > 0 {
			var config SolidityExpressionConfig
			if err := json.Unmarshal(rules[0].Config, &config); err == nil {
				ruleContractCode := fmt.Sprintf(`contract RuleContract {
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
    }

    // Fallback: reject any function call that doesn't match whitelisted selectors
    fallback() external {
        revert("function not whitelisted");
    }

    // User-defined functions for automatic selector matching
    %s
}`,
					config.Functions,
				)
				// Insert RuleContract before test functions
				testFunctions = append([]string{ruleContractCode}, testFunctions...)
			}
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

			// Parse struct definition if provided
			var structDef *StructDefinition
			if config.TypedDataStruct != "" {
				var parseErr error
				structDef, parseErr = parseStructDefinition(config.TypedDataStruct)
				if parseErr != nil {
					return "", fmt.Errorf("failed to parse typed data struct: %w", parseErr)
				}
			}

			// Generate struct instance or message field declarations
			var structInstance string
			if structDef != nil {
				// Use struct instance syntax (e.g., Order memory order = Order({...}))
				structInstance = generateStructInstance(structDef, typedData.Message)
			} else {
				// Fall back to individual field declarations
				structInstance = generateMessageFieldDeclarations(typedData)
			}

			// Generate test function
			testFunc := fmt.Sprintf(`    function test_%s_%d() public pure returns (bool) {
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

        // User-defined validation logic
        %s

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
				structInstance,
				config.TypedDataExpression,
			)
			testFunctions = append(testFunctions, testFunc)
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
			ruleFuncMap[i] = config.TypedDataFunctions
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
					config.TypedDataFunctions,
				)
				// Insert RuleContract before test functions
				testFunctions = append([]string{ruleContractCode}, testFunctions...)
			}
		}

	default:
		return "", fmt.Errorf("unsupported validation mode: %d", mode)
	}

	// Combine all test functions into a single contract
	script := fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BatchRuleEvaluatorTest {
%s
}
`, strings.Join(testFunctions, "\n\n"))

	return script, nil
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

	// Create script file
	scriptPath := filepath.Join(v.evaluator.GetTempDir(), fmt.Sprintf("batch_rule_%s.t.sol", hashStr))
	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		return nil, fmt.Errorf("failed to write batch script: %w", err)
	}

	// Create timeout context if not already set
	execCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, 60*time.Second) // Longer timeout for batch tests
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

	// Security: Disable dangerous Foundry cheatcodes
	cmd.Env = append(os.Environ(),
		"FOUNDRY_FFI=false",
		"FOUNDRY_FS_PERMISSIONS=[]",
	)

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
		// Parse individual test failures from forge output
		// Format: [FAIL. Reason: <reason>] test_<ruleName>_<index>()
		failPattern := regexp.MustCompile(`\[FAIL\.\s*Reason:\s*([^\]]+)\]\s*test_(\w+)_(\d+)\(\)`)
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
			if !v.compareTestResult(allTestCases[i].tc.ExpectPass, results[i].ActualPass, allTestCases[i].tc.ExpectReason, results[i].ActualReason) {
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

// executeTestCaseForMode runs a single test case based on the validation mode
func (v *SolidityRuleValidator) executeTestCaseForMode(ctx context.Context, code string, tc SolidityTestCase, mode ValidationMode, structDef *StructDefinition) TestCaseResult {
	switch mode {
	case ValidationModeExpression, ValidationModeFunctions:
		return v.executeTestCaseWithMode(ctx, code, tc, mode == ValidationModeFunctions)
	case ValidationModeTypedDataExpression, ValidationModeTypedDataFunctions:
		return v.executeTypedDataTestCase(ctx, code, tc, mode, structDef)
	default:
		return TestCaseResult{
			Name:   tc.Name,
			Passed: false,
			Error:  fmt.Sprintf("unknown validation mode: %d", mode),
		}
	}
}

// executeTypedDataTestCase runs a test case for EIP-712 typed data validation
func (v *SolidityRuleValidator) executeTypedDataTestCase(ctx context.Context, code string, tc SolidityTestCase, mode ValidationMode, structDef *StructDefinition) TestCaseResult {
	result := TestCaseResult{
		Name:           tc.Name,
		ExpectedPass:   tc.ExpectPass,
		ExpectedReason: tc.ExpectReason,
	}

	// Build typed data from test input
	typedData, err := v.buildTypedDataFromInput(tc.Input)
	if err != nil {
		result.Passed = false
		result.Error = fmt.Sprintf("failed to build typed data from input: %v", err)
		return result
	}

	// Convert test input to SignRequest with typed data payload
	req := v.testInputToTypedDataRequest(tc.Input, typedData)

	// Execute the rule based on mode
	// Pass structDef to ensure field name mappings (e.g., message_ -> message) are applied
	var passed bool
	var reason string
	if mode == ValidationModeTypedDataExpression {
		passed, reason, err = v.evaluator.evaluateTypedDataExpression(ctx, code, req, typedData, structDef)
	} else {
		passed, reason, err = v.evaluator.evaluateTypedDataFunctions(ctx, code, req, typedData)
	}

	if err != nil {
		result.Passed = false
		result.Error = err.Error()
		return result
	}

	result.ActualPass = passed
	result.ActualReason = reason

	// Compare with expectation
	result.Passed = v.compareTestResult(tc.ExpectPass, passed, tc.ExpectReason, reason)
	if !result.Passed {
		if tc.ExpectPass && !passed {
			result.Error = fmt.Sprintf("expected pass but got revert: %s", reason)
		} else if !tc.ExpectPass && passed {
			result.Error = "expected revert but passed"
		} else if tc.ExpectReason != "" && !strings.Contains(reason, tc.ExpectReason) {
			result.Error = fmt.Sprintf("expected reason containing '%s' but got '%s'", tc.ExpectReason, reason)
		}
	}

	return result
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
		// Check if it's a numeric string
		if _, err := json.Number(v).Int64(); err == nil {
			return "uint256"
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

// validateSyntaxWithMode compiles the Solidity code to check for syntax errors
func (v *SolidityRuleValidator) validateSyntaxWithMode(ctx context.Context, code string, isFunctionMode bool) (*SyntaxError, error) {
	var script string
	if isFunctionMode {
		script = v.evaluator.GenerateFunctionSyntaxCheckScript(code)
	} else {
		script = v.evaluator.GenerateSyntaxCheckScript(code)
	}
	return v.compileSyntaxCheckScript(ctx, script)
}

// validateSyntax compiles the Solidity expression to check for syntax errors (legacy, expression mode only)
func (v *SolidityRuleValidator) validateSyntax(ctx context.Context, expression string) (*SyntaxError, error) {
	script := v.evaluator.GenerateSyntaxCheckScript(expression)
	return v.compileSyntaxCheckScript(ctx, script)
}

// compileSyntaxCheckScript compiles a syntax check script and returns any errors
func (v *SolidityRuleValidator) compileSyntaxCheckScript(ctx context.Context, script string) (*SyntaxError, error) {
	// Calculate script hash for caching
	hash := sha256.Sum256([]byte(script))
	hashStr := hex.EncodeToString(hash[:])

	// Check cache first
	v.syntaxCacheMu.RLock()
	if cached, found := v.syntaxCache[hashStr]; found {
		v.syntaxCacheMu.RUnlock()
		if cached {
			return nil, nil // Syntax is valid (cached)
		}
		// If cached as invalid, we still need to return the error, but we can skip compilation
		// For now, let's recompile to get the actual error message
	}
	v.syntaxCacheMu.RUnlock()

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

	// Create timeout context
	execCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Run forge build with cache path for incremental compilation
	cachePath := filepath.Join(v.evaluator.GetCacheDir(), "forge-cache")
	cmd := exec.CommandContext(execCtx,
		v.evaluator.GetFoundryPath(), "build",
		"--root", v.evaluator.GetTempDir(),
		"--cache-path", cachePath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Parse compilation error
		syntaxErr := parseSolidityError(string(output))
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

// executeTestCaseWithMode runs a single test case with the specified mode
func (v *SolidityRuleValidator) executeTestCaseWithMode(ctx context.Context, code string, tc SolidityTestCase, isFunctionMode bool) TestCaseResult {
	result := TestCaseResult{
		Name:           tc.Name,
		ExpectedPass:   tc.ExpectPass,
		ExpectedReason: tc.ExpectReason,
	}

	// Convert test input to SignRequest and ParsedPayload
	req, parsed := v.testInputToRequest(tc.Input)

	// Execute the rule based on mode
	var passed bool
	var reason string
	var err error
	if isFunctionMode {
		passed, reason, err = v.evaluator.evaluateFunctions(ctx, code, req, parsed)
	} else {
		passed, reason, err = v.evaluator.evaluateExpression(ctx, code, req, parsed)
	}

	if err != nil {
		result.Passed = false
		result.Error = err.Error()
		return result
	}

	result.ActualPass = passed
	result.ActualReason = reason

	// Compare with expectation
	result.Passed = v.compareTestResult(tc.ExpectPass, passed, tc.ExpectReason, reason)
	if !result.Passed {
		if tc.ExpectPass && !passed {
			result.Error = fmt.Sprintf("expected pass but got revert: %s", reason)
		} else if !tc.ExpectPass && passed {
			result.Error = "expected revert but passed"
		} else if tc.ExpectReason != "" && !strings.Contains(reason, tc.ExpectReason) {
			result.Error = fmt.Sprintf("expected reason containing '%s' but got '%s'", tc.ExpectReason, reason)
		}
	}

	return result
}

// executeTestCase runs a single test case and compares result with expectation (legacy, expression mode only)
func (v *SolidityRuleValidator) executeTestCase(ctx context.Context, expression string, tc SolidityTestCase) TestCaseResult {
	return v.executeTestCaseWithMode(ctx, expression, tc, false)
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
func (v *SolidityRuleValidator) testInputToRequest(input SolidityTestInput) (*types.SignRequest, *types.ParsedPayload) {
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
		if err == nil {
			parsed.RawData = data
		}
	}

	return req, parsed
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
