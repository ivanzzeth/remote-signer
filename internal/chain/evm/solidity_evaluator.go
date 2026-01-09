package evm

import (
	"bytes"
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
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

const solidityTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RuleEvaluator {
    function run() public pure returns (bool) {
        // Transaction context
        address to = {{.To}};
        uint256 value = {{.Value}};
        bytes4 selector = {{.Selector}};
        bytes memory data = {{.Data}};
        uint256 chainId = {{.ChainID}};
        address signer = {{.Signer}};

        // Suppress unused variable warnings
        to; value; selector; data; chainId; signer;

        // User-defined validation logic
        {{.Expression}}

        // If we reach here, all require() passed
        return true;
    }
}
`

// SolidityRuleEvaluator evaluates rules using Foundry's forge script
type SolidityRuleEvaluator struct {
	tempDir     string
	cacheDir    string
	mu          sync.RWMutex
	scriptCache map[string]string // hash -> compiled script path
	foundryPath string            // path to forge binary
	timeout     time.Duration
	logger      *slog.Logger
}

// SolidityEvaluatorConfig holds configuration for the evaluator
type SolidityEvaluatorConfig struct {
	ForgePath string        // path to forge binary, empty = auto-detect from PATH
	CacheDir  string        // cache directory for compiled scripts
	Timeout   time.Duration // max execution time per rule
}

// NewSolidityRuleEvaluator creates a new evaluator
func NewSolidityRuleEvaluator(cfg SolidityEvaluatorConfig, logger *slog.Logger) (*SolidityRuleEvaluator, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	foundryPath := cfg.ForgePath
	if foundryPath == "" {
		// Try to find forge in PATH
		path, err := exec.LookPath("forge")
		if err != nil {
			return nil, fmt.Errorf("forge not found in PATH and ForgePath not specified: %w", err)
		}
		foundryPath = path
	}

	// Verify forge is executable
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := exec.CommandContext(ctx, foundryPath, "--version").Output(); err != nil {
		return nil, fmt.Errorf("forge not executable at %s: %w", foundryPath, err)
	}

	tempDir := filepath.Join(os.TempDir(), "remote-signer-rules")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	cacheDir := cfg.CacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(tempDir, "cache")
	}
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache dir: %w", err)
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	logger.Info("SolidityRuleEvaluator initialized",
		"forge_path", foundryPath,
		"temp_dir", tempDir,
		"cache_dir", cacheDir,
		"timeout", timeout,
	)

	return &SolidityRuleEvaluator{
		tempDir:     tempDir,
		cacheDir:    cacheDir,
		scriptCache: make(map[string]string),
		foundryPath: foundryPath,
		timeout:     timeout,
		logger:      logger,
	}, nil
}

// Type returns the rule type this evaluator handles
func (e *SolidityRuleEvaluator) Type() types.RuleType {
	return types.RuleTypeEVMSolidityExpression
}

// Evaluate evaluates the rule against the request
func (e *SolidityRuleEvaluator) Evaluate(
	ctx context.Context,
	rule *types.Rule,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
) (bool, string, error) {
	var config SolidityExpressionConfig
	if err := json.Unmarshal(rule.Config, &config); err != nil {
		return false, "", fmt.Errorf("invalid solidity expression config: %w", err)
	}

	return e.evaluateExpression(ctx, config.Expression, req, parsed)
}

// evaluateExpression evaluates a Solidity expression with the given context
func (e *SolidityRuleEvaluator) evaluateExpression(
	ctx context.Context,
	expression string,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
) (bool, string, error) {
	// Generate script with transaction context
	script, err := e.generateScript(expression, req, parsed)
	if err != nil {
		return false, "", fmt.Errorf("failed to generate script: %w", err)
	}

	// Execute via forge script
	passed, reason, err := e.executeScript(ctx, script)
	if err != nil {
		return false, "", fmt.Errorf("script execution failed: %w", err)
	}

	return passed, reason, nil
}

// generateScript generates a Solidity script from the expression and context
func (e *SolidityRuleEvaluator) generateScript(
	expression string,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
) (string, error) {
	// Prepare template data
	data := struct {
		To         string
		Value      string
		Selector   string
		Data       string
		ChainID    string
		Signer     string
		Expression string
	}{
		To:         formatAddress(parsed.Recipient),
		Value:      formatWei(parsed.Value),
		Selector:   formatSelector(parsed.MethodSig),
		Data:       formatBytes(parsed.RawData),
		ChainID:    formatChainID(req.ChainID),
		Signer:     formatAddress(&req.SignerAddress),
		Expression: expression,
	}

	tmpl, err := template.New("rule").Parse(solidityTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// executeScript executes the Solidity script and returns pass/fail with reason
func (e *SolidityRuleEvaluator) executeScript(ctx context.Context, script string) (bool, string, error) {
	// Calculate script hash for caching/naming
	hash := sha256.Sum256([]byte(script))
	hashStr := hex.EncodeToString(hash[:8]) // Use first 8 bytes for shorter filename

	// Create script file
	scriptPath := filepath.Join(e.tempDir, fmt.Sprintf("rule_%s.sol", hashStr))
	if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {
		return false, "", fmt.Errorf("failed to write script: %w", err)
	}
	defer os.Remove(scriptPath)

	// Create timeout context if not already set
	execCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}

	// Execute forge script
	cmd := exec.CommandContext(execCtx,
		e.foundryPath, "script",
		scriptPath,
		"--json",
		"-vvv", // verbose for revert reasons
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Parse revert reason from output if available
		reason := parseRevertReason(output)
		if reason != "" {
			e.logger.Debug("rule evaluation failed with revert",
				"reason", reason,
				"script_hash", hashStr,
			)
			return false, reason, nil // Rule failed with reason
		}

		// Check if it's a context timeout
		if execCtx.Err() == context.DeadlineExceeded {
			return false, "", fmt.Errorf("script execution timed out after %v", e.timeout)
		}

		e.logger.Error("forge script failed",
			"error", err,
			"output", string(output),
			"script_hash", hashStr,
		)
		return false, "", fmt.Errorf("forge script failed: %w, output: %s", err, string(output))
	}

	e.logger.Debug("rule evaluation passed", "script_hash", hashStr)
	return true, "", nil
}

// GenerateSyntaxCheckScript generates a script for compilation checking
func (e *SolidityRuleEvaluator) GenerateSyntaxCheckScript(expression string) string {
	return fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SyntaxCheck {
    function run() public pure returns (bool) {
        // Dummy values for syntax check
        address to = address(0);
        uint256 value = 0;
        bytes4 selector = bytes4(0);
        bytes memory data = "";
        uint256 chainId = 1;
        address signer = address(0);

        // Suppress unused variable warnings
        to; value; selector; data; chainId; signer;

        // User expression
        %s

        return true;
    }
}
`, expression)
}

// GetTempDir returns the temp directory path
func (e *SolidityRuleEvaluator) GetTempDir() string {
	return e.tempDir
}

// GetFoundryPath returns the forge binary path
func (e *SolidityRuleEvaluator) GetFoundryPath() string {
	return e.foundryPath
}

// Helper functions

func formatAddress(addr *string) string {
	if addr == nil || *addr == "" {
		return "address(0)"
	}
	return *addr
}

func formatWei(value *string) string {
	if value == nil || *value == "" {
		return "0"
	}
	return *value
}

func formatSelector(sig *string) string {
	if sig == nil || *sig == "" {
		return "bytes4(0)"
	}
	// Ensure proper format: bytes4(0xXXXXXXXX)
	s := *sig
	if strings.HasPrefix(s, "0x") {
		return fmt.Sprintf("bytes4(%s)", s)
	}
	return fmt.Sprintf("bytes4(0x%s)", s)
}

func formatBytes(data []byte) string {
	if len(data) == 0 {
		return "hex\"\""
	}
	return fmt.Sprintf("hex\"%s\"", hex.EncodeToString(data))
}

func formatChainID(chainID string) string {
	if chainID == "" {
		return "1"
	}
	return chainID
}

// forgeScriptResult represents the relevant parts of forge script JSON output
type forgeScriptResult struct {
	Success bool `json:"success"`
	Traces  [][]interface{}
}

// parseRevertReason extracts the revert reason from forge output
func parseRevertReason(output []byte) string {
	outputStr := string(output)

	// Pattern 1: Parse from JSON - look for "return_data" in decoded traces
	// The JSON format is: {"traces":[...["Execution",{"arena":[{..."decoded":{"return_data":"..."}}]}]...]}
	if idx := strings.Index(outputStr, `"return_data":`); idx != -1 {
		// Find the value after "return_data":
		start := idx + len(`"return_data":`)
		// Skip whitespace
		for start < len(outputStr) && (outputStr[start] == ' ' || outputStr[start] == '\t') {
			start++
		}
		if start < len(outputStr) && outputStr[start] == '"' {
			start++ // skip opening quote
			end := strings.Index(outputStr[start:], `"`)
			if end != -1 {
				reason := outputStr[start : start+end]
				if reason != "" && reason != "null" {
					return reason
				}
			}
		}
	}

	// Pattern 2: Look for "Error: script failed: <reason>" in stderr
	if idx := strings.Index(outputStr, "Error: script failed: "); idx != -1 {
		start := idx + len("Error: script failed: ")
		end := strings.IndexAny(outputStr[start:], "\n\r")
		if end == -1 {
			return strings.TrimSpace(outputStr[start:])
		}
		return strings.TrimSpace(outputStr[start : start+end])
	}

	// Pattern 3: Look for "revert: <reason>"
	if idx := strings.Index(outputStr, "revert: "); idx != -1 {
		start := idx + len("revert: ")
		end := strings.IndexAny(outputStr[start:], "\n\r")
		if end == -1 {
			return strings.TrimSpace(outputStr[start:])
		}
		return strings.TrimSpace(outputStr[start : start+end])
	}

	// Pattern 4: General "Error:" pattern
	revertPattern := regexp.MustCompile(`Error:\s*([^\n\r]+)`)
	matches := revertPattern.FindStringSubmatch(outputStr)
	if len(matches) > 1 {
		reason := strings.TrimSpace(matches[1])
		// Skip generic errors that aren't actual revert reasons
		if reason != "" && !strings.HasPrefix(reason, "Compiler run failed") {
			return reason
		}
	}

	// Pattern 5: Look for panic codes
	if strings.Contains(outputStr, "Panic") {
		panicPattern := regexp.MustCompile(`Panic\(([^)]+)\)`)
		matches := panicPattern.FindStringSubmatch(outputStr)
		if len(matches) > 1 {
			return fmt.Sprintf("panic: %s", matches[1])
		}
	}

	return ""
}
