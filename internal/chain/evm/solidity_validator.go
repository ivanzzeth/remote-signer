package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
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
	evaluator *SolidityRuleEvaluator
	logger    *slog.Logger
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
		evaluator: evaluator,
		logger:    logger,
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

	result := &ValidationResult{Valid: true}

	// Step 1: Syntax validation via forge build
	v.logger.Debug("validating Solidity syntax",
		"rule_id", rule.ID,
		"mode", v.modeString(mode),
	)
	syntaxErr, err := v.validateSyntaxForMode(ctx, code, mode)
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

	// Step 2: Execute test cases
	if len(config.TestCases) == 0 {
		return nil, fmt.Errorf("at least one test case is required for Solidity expression rules")
	}

	result.TestCaseResults = make([]TestCaseResult, 0, len(config.TestCases))

	for i, tc := range config.TestCases {
		v.logger.Debug("executing test case",
			"rule_id", rule.ID,
			"test_case", tc.Name,
			"index", i,
		)
		tcResult := v.executeTestCaseForMode(ctx, code, tc, mode)
		result.TestCaseResults = append(result.TestCaseResults, tcResult)

		if !tcResult.Passed {
			result.FailedTestCases++
			result.Valid = false
			v.logger.Warn("test case failed",
				"rule_id", rule.ID,
				"test_case", tc.Name,
				"error", tcResult.Error,
			)
		} else {
			v.logger.Debug("test case passed",
				"rule_id", rule.ID,
				"test_case", tc.Name,
			)
		}
	}

	return result, nil
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
	var script string
	switch mode {
	case ValidationModeExpression:
		script = v.evaluator.GenerateSyntaxCheckScript(code)
	case ValidationModeFunctions:
		script = v.evaluator.GenerateFunctionSyntaxCheckScript(code)
	case ValidationModeTypedDataExpression:
		script = v.evaluator.GenerateTypedDataExpressionSyntaxCheckScript(code)
	case ValidationModeTypedDataFunctions:
		script = v.evaluator.GenerateTypedDataFunctionsSyntaxCheckScript(code)
	default:
		return nil, fmt.Errorf("unknown validation mode: %d", mode)
	}
	return v.compileSyntaxCheckScript(ctx, script)
}

// executeTestCaseForMode runs a single test case based on the validation mode
func (v *SolidityRuleValidator) executeTestCaseForMode(ctx context.Context, code string, tc SolidityTestCase, mode ValidationMode) TestCaseResult {
	switch mode {
	case ValidationModeExpression, ValidationModeFunctions:
		return v.executeTestCaseWithMode(ctx, code, tc, mode == ValidationModeFunctions)
	case ValidationModeTypedDataExpression, ValidationModeTypedDataFunctions:
		return v.executeTypedDataTestCase(ctx, code, tc, mode)
	default:
		return TestCaseResult{
			Name:   tc.Name,
			Passed: false,
			Error:  fmt.Sprintf("unknown validation mode: %d", mode),
		}
	}
}

// executeTypedDataTestCase runs a test case for EIP-712 typed data validation
func (v *SolidityRuleValidator) executeTypedDataTestCase(ctx context.Context, code string, tc SolidityTestCase, mode ValidationMode) TestCaseResult {
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
	var passed bool
	var reason string
	if mode == ValidationModeTypedDataExpression {
		passed, reason, err = v.evaluator.evaluateTypedDataExpression(ctx, code, req, typedData)
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

	// Write to temp file
	scriptPath := filepath.Join(v.evaluator.GetTempDir(), "syntax_check.sol")
	if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {
		return nil, fmt.Errorf("failed to write script: %w", err)
	}
	defer os.Remove(scriptPath)

	// Create timeout context
	execCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Run forge build (compile only, no execution)
	// We use a simple solc compile check via forge
	cmd := exec.CommandContext(execCtx,
		v.evaluator.GetFoundryPath(), "build",
		"--root", v.evaluator.GetTempDir(),
	)

	// First, we need a foundry.toml in the temp dir
	foundryToml := `[profile.default]
src = "."
out = "out"
libs = []
`
	foundryTomlPath := filepath.Join(v.evaluator.GetTempDir(), "foundry.toml")
	if err := os.WriteFile(foundryTomlPath, []byte(foundryToml), 0644); err != nil {
		return nil, fmt.Errorf("failed to write foundry.toml: %w", err)
	}
	defer os.Remove(foundryTomlPath)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Parse compilation error
		syntaxErr := parseSolidityError(string(output))
		return syntaxErr, nil
	}

	// Clean up output directory
	outDir := filepath.Join(v.evaluator.GetTempDir(), "out")
	os.RemoveAll(outDir)

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
