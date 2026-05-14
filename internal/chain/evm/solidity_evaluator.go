package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// executionResult holds the cached result of a script execution
type executionResult struct {
	passed    bool
	reason    string
	err       error
	timestamp time.Time // when the result was cached
}

// SolidityRuleEvaluator evaluates rules using Foundry's forge script
type SolidityRuleEvaluator struct {
	tempDir        string
	cacheDir       string
	mu             sync.RWMutex
	scriptCache    map[string]string           // hash -> compiled script path
	executionCache map[string]*executionResult // hash -> execution result (cached for identical scripts)
	foundryPath    string                      // path to forge binary
	timeout        time.Duration
	cacheTTL       time.Duration // TTL for execution result cache entries
	logger         *slog.Logger
}

// SolidityEvaluatorConfig holds configuration for the evaluator
type SolidityEvaluatorConfig struct {
	ForgePath string        // path to forge binary, empty = auto-detect from PATH
	CacheDir  string        // cache directory for compiled scripts
	TempDir   string        // workspace dir (foundry.toml + lib/forge-std + rule scripts); empty = os.TempDir()/remote-signer-rules. When set to a dir with pre-installed lib/forge-std (e.g. Docker mount), ensureForgeStd is skipped.
	Timeout   time.Duration // max execution time per rule
	CacheTTL  time.Duration // TTL for execution result cache entries, 0 = no expiration
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
	if _, err := exec.CommandContext(ctx, foundryPath, "--version").Output(); err != nil { // #nosec G204 -- foundryPath is admin-configured
		return nil, fmt.Errorf("forge not executable at %s: %w", foundryPath, err)
	}

	// Workspace directory: use configured TempDir (e.g. mounted data/forge-workspace in Docker) or default
	tempDir := cfg.TempDir
	if tempDir == "" {
		tempDir = filepath.Join(os.TempDir(), "remote-signer-rules")
	}
	if err := os.MkdirAll(tempDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create temp dir %s: %w", tempDir, err)
	}

	// Create foundry.toml for forge test to work properly
	// Note: Don't specify solc version to let forge auto-detect from pragma
	// Enable via_ir to avoid "Stack too deep" errors with many local variables
	// Enable incremental compilation for better performance (supported in foundry >= 1.5.1)
	// forge-std is required for vm env/parse cheatcodes when using request-as-input (no recompile per request)
	foundryConfig := `[profile.default]
src = "."
test = "."
out = "out"
libs = ["lib"]
remappings = ["forge-std/=lib/forge-std/src/"]
via_ir = true
optimizer = false
incremental = true
`
	foundryConfigPath := filepath.Join(tempDir, "foundry.toml")
	if err := os.WriteFile(foundryConfigPath, []byte(foundryConfig), 0600); err != nil {
		return nil, fmt.Errorf("failed to create foundry.toml: %w", err)
	}
	// Ensure forge-std is available so scripts can use vm.env* / vm.parseBytes (request-as-input mode)
	if err := ensureForgeStd(tempDir, foundryPath); err != nil {
		return nil, fmt.Errorf("forge-std setup: %w", err)
	}

	cacheDir := cfg.CacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(tempDir, "cache")
	}
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cache dir: %w", err)
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute // default 5 minutes TTL
	}

	logger.Info("SolidityRuleEvaluator initialized",
		"forge_path", foundryPath,
		"temp_dir", tempDir,
		"cache_dir", cacheDir,
		"timeout", timeout,
		"cache_ttl", cacheTTL,
	)

	return &SolidityRuleEvaluator{
		tempDir:        tempDir,
		cacheDir:       cacheDir,
		scriptCache:    make(map[string]string),
		executionCache: make(map[string]*executionResult),
		foundryPath:    foundryPath,
		timeout:        timeout,
		cacheTTL:       cacheTTL,
		logger:         logger,
	}, nil
}

// Type returns the rule type this evaluator handles
func (e *SolidityRuleEvaluator) Type() types.RuleType {
	return types.RuleTypeEVMSolidityExpression
}

// AppliesToSignType implements rule.SignTypeApplicable: returns false if the rule's sign_type_filter does not match.
func (e *SolidityRuleEvaluator) AppliesToSignType(rule *types.Rule, signType string) bool {
	var config SolidityExpressionConfig
	if err := json.Unmarshal(rule.Config, &config); err != nil {
		return true // invalid config: keep rule, let Evaluate fail or skip
	}
	if config.SignTypeFilter == "" {
		return true
	}
	return config.SignTypeFilter == signType
}

var _ rule.SignTypeApplicable = (*SolidityRuleEvaluator)(nil)

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

	// Check SignTypeFilter if specified
	if config.SignTypeFilter != "" && config.SignTypeFilter != req.SignType {
		// Rule doesn't apply to this sign type, skip evaluation (pass through)
		return false, "", nil
	}

	// Whitelist transaction rules: selector or decode must be valid; missing/short calldata = fail (do not allow)
	if rule.Mode == types.RuleModeWhitelist && (config.Functions != "" || config.Expression != "") {
		if config.TypedDataExpression == "" && config.TypedDataFunctions == "" {
			if parsed == nil || len(parsed.RawData) < 4 {
				return false, "transaction calldata missing or too short: no selector", nil
			}
		}
	}

	var passed bool
	var reason string
	var err error

	// Determine mode based on which field is populated
	// Priority: TypedDataExpression/Functions > Functions > Expression

	// EIP-712 Typed Data validation modes
	if config.TypedDataExpression != "" || config.TypedDataFunctions != "" {
		// Parse typed data from request payload
		typedData, parseErr := parseTypedDataFromPayload(req.Payload)
		if parseErr != nil {
			return false, "", fmt.Errorf("failed to parse typed data: %w", parseErr)
		}

		// If typed_data_struct is defined, parse it and check primaryType match
		var structDef *StructDefinition
		if config.TypedDataStruct != "" {
			var structErr error
			structDef, structErr = parseStructDefinition(config.TypedDataStruct)
			if structErr != nil {
				return false, "", fmt.Errorf("failed to parse typed_data_struct: %w", structErr)
			}

			// Check if request's primaryType matches the struct name
			if typedData.PrimaryType != structDef.Name {
				// Rule doesn't apply to this primaryType, skip evaluation
				e.logger.Debug("typed_data_struct primaryType mismatch, skipping rule",
					"rule_struct", structDef.Name,
					"request_primaryType", typedData.PrimaryType,
				)
				return false, "", nil
			}
		}

		if config.TypedDataExpression != "" {
			passed, reason, err = e.evaluateTypedDataExpression(ctx, config.TypedDataExpression, req, typedData, structDef, config.InMappingArrays)
		} else {
			passed, reason, err = e.evaluateTypedDataFunctions(ctx, config.TypedDataFunctions, req, typedData, config.InMappingArrays)
		}
	} else if config.Functions != "" {
		// Transaction validation with function mode
		passed, reason, err = e.evaluateFunctions(ctx, config.Functions, req, parsed, config.InMappingArrays)
	} else {
		// Transaction validation with expression mode
		passed, reason, err = e.evaluateExpression(ctx, config.Expression, req, parsed, config.InMappingArrays)
	}

	if err != nil {
		return false, "", err
	}

	// For blocklist mode, invert the result:
	// - require() passes (no violation) -> return false (don't block)
	// - require() reverts (violation) -> return true (block) with revert reason
	//
	// For whitelist mode (default):
	// - require() passes (matches whitelist) -> return true (allow)
	// - require() reverts (no match) -> return false (need manual approval)
	if rule.Mode == types.RuleModeBlocklist {
		return !passed, reason, nil
	}

	return passed, reason, nil
}

// evaluateExpression evaluates a Solidity expression with the given context (Expression mode).
// Script is generated from rule only (expression + inMapping); request data is passed at runtime via env (compile once per rule).
func (e *SolidityRuleEvaluator) evaluateExpression(
	ctx context.Context,
	expression string,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
	inMappingArrays map[string][]string,
) (bool, string, error) {
	script, err := e.generateExpressionScript(expression, inMappingArrays)
	if err != nil {
		return false, "", fmt.Errorf("failed to generate script: %w", err)
	}
	passed, reason, err := e.executeScript(ctx, script, buildRequestEnv(req, parsed))
	if err != nil {
		return false, "", fmt.Errorf("script execution failed: %w", err)
	}
	return passed, reason, nil
}

// evaluateFunctions evaluates user-defined functions (Functions mode).
// Script is generated from rule only; request data is passed at runtime via env (compile once per rule).
func (e *SolidityRuleEvaluator) evaluateFunctions(
	ctx context.Context,
	functions string,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
	inMappingArrays map[string][]string,
) (bool, string, error) {
	script, err := e.generateFunctionScript(functions, inMappingArrays)
	if err != nil {
		return false, "", fmt.Errorf("failed to generate function script: %w", err)
	}
	passed, reason, err := e.executeScript(ctx, script, buildRequestEnv(req, parsed))
	if err != nil {
		return false, "", fmt.Errorf("script execution failed: %w", err)
	}
	return passed, reason, nil
}
