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
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

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

// ValidateRule performs full validation of a Solidity expression rule
func (v *SolidityRuleValidator) ValidateRule(ctx context.Context, rule *types.Rule) (*ValidationResult, error) {
	var config SolidityExpressionConfig
	if err := json.Unmarshal(rule.Config, &config); err != nil {
		return nil, fmt.Errorf("invalid solidity expression config: %w", err)
	}

	result := &ValidationResult{Valid: true}

	// Step 1: Syntax validation via forge build
	v.logger.Debug("validating Solidity syntax", "rule_id", rule.ID)
	syntaxErr, err := v.validateSyntax(ctx, config.Expression)
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
		tcResult := v.executeTestCase(ctx, config.Expression, tc)
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

// validateSyntax compiles the Solidity expression to check for syntax errors
func (v *SolidityRuleValidator) validateSyntax(ctx context.Context, expression string) (*SyntaxError, error) {
	// Generate a test script with dummy values
	script := v.evaluator.GenerateSyntaxCheckScript(expression)

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

// executeTestCase runs a single test case and compares result with expectation
func (v *SolidityRuleValidator) executeTestCase(ctx context.Context, expression string, tc SolidityTestCase) TestCaseResult {
	result := TestCaseResult{
		Name:           tc.Name,
		ExpectedPass:   tc.ExpectPass,
		ExpectedReason: tc.ExpectReason,
	}

	// Convert test input to SignRequest and ParsedPayload
	req, parsed := v.testInputToRequest(tc.Input)

	// Execute the rule
	passed, reason, err := v.evaluator.evaluateExpression(ctx, expression, req, parsed)
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
