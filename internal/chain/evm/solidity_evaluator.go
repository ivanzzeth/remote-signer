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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// solidityExpressionTemplate is for require-based rules (Expression mode)
// Context variables are available with both short names and tx_*/ctx_* prefixed names:
// - Short: to, value, selector, data, chainId, signer (backward-compatible)
// - Prefixed: tx_to, tx_value, tx_selector, tx_data, ctx_chainId, ctx_signer
const solidityExpressionTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RuleEvaluator {
    function run() public pure returns (bool) {
        // Transaction context
        address tx_to = {{.To}};
        uint256 tx_value = {{.Value}};
        bytes4 tx_selector = {{.Selector}};
        bytes memory tx_data = {{.Data}};

        // Signing context
        uint256 ctx_chainId = {{.ChainID}};
        address ctx_signer = {{.Signer}};

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
        {{.Expression}}

        // If we reach here, all require() passed
        return true;
    }
}
`

// solidityFunctionTemplate is for function-based rules (Functions mode)
// Uses two contracts: RuleContract (contains user functions) and RuleEvaluatorTest (forge test)
// This avoids Foundry's address(this) check by calling an external contract via forge test
const solidityFunctionTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// RuleContract contains user-defined validation functions
contract RuleContract {
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
    {{.Functions}}
}

// RuleEvaluatorTest is the forge test entry point
contract RuleEvaluatorTest {
    RuleContract public ruleContract;

    function setUp() public {
        // Create RuleContract with transaction context
        ruleContract = new RuleContract(
            {{.To}},
            {{.Value}},
            {{.Selector}},
            {{.Data}},
            {{.ChainID}},
            {{.Signer}}
        );
    }

    function test_rule() public {
        // Get txData from the rule contract
        bytes memory txData = ruleContract.txData();

        if (txData.length >= 4) {
            // Forward calldata to RuleContract - this is an external call, not address(this)
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
    }
}
`

// solidityTypedDataExpressionTemplate is for EIP-712 typed data validation using require() statements
// Context variables use prefixes to avoid conflicts with user-defined field names:
// - eip712_* : EIP-712 domain context (eip712_primaryType, eip712_domainName, etc.)
// - ctx_* : Signing context (ctx_chainId, ctx_signer)
// Message fields are accessible via struct instance (e.g., order.taker, permit.value)
const solidityTypedDataExpressionTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RuleEvaluator {
    {{.StructDefinition}}

    function run() public pure returns (bool) {
        // EIP-712 Domain context (eip712_* prefix)
        string memory eip712_primaryType = {{.PrimaryType}};
        string memory eip712_domainName = {{.DomainName}};
        string memory eip712_domainVersion = {{.DomainVersion}};
        uint256 eip712_domainChainId = {{.DomainChainId}};
        address eip712_domainContract = {{.DomainContract}};

        // Signing context (ctx_* prefix)
        address ctx_signer = {{.Signer}};
        uint256 ctx_chainId = {{.ChainID}};

        // EIP-712 Message struct instance (access fields via structName.field)
        {{.StructInstance}}

        // Suppress unused variable warnings
        bytes memory _eip712_primaryType = bytes(eip712_primaryType);
        bytes memory _eip712_domainName = bytes(eip712_domainName);
        bytes memory _eip712_domainVersion = bytes(eip712_domainVersion);
        eip712_domainChainId; eip712_domainContract; ctx_signer; ctx_chainId;
        _eip712_primaryType; _eip712_domainName; _eip712_domainVersion;

        // User-defined validation logic
        {{.Expression}}

        // If we reach here, all require() passed
        return true;
    }
}
`

// solidityBatchTypedDataTestTemplate is for batch testing multiple typed data rules in a single contract
// This significantly reduces compilation time by compiling once instead of N times
const solidityBatchTypedDataTestTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BatchRuleEvaluatorTest {
    {{.TestFunctions}}
}
`

// solidityTypedDataFunctionsTemplate is for EIP-712 typed data validation using struct-based functions
// Context variables use prefixes to avoid conflicts with user-defined field names:
// - eip712_* : EIP-712 domain context
// - ctx_* : Signing context
const solidityTypedDataFunctionsTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RuleEvaluator {
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
        eip712_primaryType = {{.PrimaryType}};
        eip712_domainName = {{.DomainName}};
        eip712_domainVersion = {{.DomainVersion}};
        eip712_domainChainId = {{.DomainChainId}};
        eip712_domainContract = {{.DomainContract}};
        ctx_signer = {{.Signer}};
        ctx_chainId = {{.ChainID}};
        messageData = {{.MessageData}};
    }

    // User-defined structs and validation functions
    {{.Functions}}

    function run() public returns (bool) {
        // Call the validate function with decoded message
        _validateMessage();
        return true;
    }

    function _validateMessage() internal virtual {
        // Override in user functions if needed
    }
}
`

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
	if _, err := exec.CommandContext(ctx, foundryPath, "--version").Output(); err != nil {
		return nil, fmt.Errorf("forge not executable at %s: %w", foundryPath, err)
	}

	// Create temp directory with restricted permissions (owner-only)
	tempDir := filepath.Join(os.TempDir(), "remote-signer-rules")
	if err := os.MkdirAll(tempDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	// Create foundry.toml for forge test to work properly
	// Note: Don't specify solc version to let forge auto-detect from pragma
	// Enable via_ir to avoid "Stack too deep" errors with many local variables
	// Enable incremental compilation for better performance (supported in foundry >= 1.5.1)
	foundryConfig := `[profile.default]
src = "."
test = "."
out = "out"
libs = []
via_ir = true
optimizer = false
incremental = true
`
	foundryConfigPath := filepath.Join(tempDir, "foundry.toml")
	if err := os.WriteFile(foundryConfigPath, []byte(foundryConfig), 0600); err != nil {
		return nil, fmt.Errorf("failed to create foundry.toml: %w", err)
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
			passed, reason, err = e.evaluateTypedDataExpression(ctx, config.TypedDataExpression, req, typedData, structDef)
		} else {
			passed, reason, err = e.evaluateTypedDataFunctions(ctx, config.TypedDataFunctions, req, typedData)
		}
	} else if config.Functions != "" {
		// Transaction validation with function mode
		passed, reason, err = e.evaluateFunctions(ctx, config.Functions, req, parsed)
	} else {
		// Transaction validation with expression mode
		passed, reason, err = e.evaluateExpression(ctx, config.Expression, req, parsed)
	}

	if err != nil {
		return false, "", err
	}

	// For blocklist mode, invert the result:
	// - require() passes (no violation) → return false (don't block)
	// - require() reverts (violation) → return true (block) with revert reason
	//
	// For whitelist mode (default):
	// - require() passes (matches whitelist) → return true (allow)
	// - require() reverts (no match) → return false (need manual approval)
	if rule.Mode == types.RuleModeBlocklist {
		return !passed, reason, nil
	}

	return passed, reason, nil
}

// evaluateExpression evaluates a Solidity expression with the given context (Expression mode)
func (e *SolidityRuleEvaluator) evaluateExpression(
	ctx context.Context,
	expression string,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
) (bool, string, error) {
	// Generate script with transaction context
	script, err := e.generateExpressionScript(expression, req, parsed)
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

// evaluateFunctions evaluates user-defined functions with the given context (Functions mode)
func (e *SolidityRuleEvaluator) evaluateFunctions(
	ctx context.Context,
	functions string,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
) (bool, string, error) {
	// Generate script with transaction context and user functions
	script, err := e.generateFunctionScript(functions, req, parsed)
	if err != nil {
		return false, "", fmt.Errorf("failed to generate function script: %w", err)
	}

	// Execute via forge script
	passed, reason, err := e.executeScript(ctx, script)
	if err != nil {
		return false, "", fmt.Errorf("script execution failed: %w", err)
	}

	return passed, reason, nil
}

// generateExpressionScript generates a Solidity script for Expression mode
func (e *SolidityRuleEvaluator) generateExpressionScript(
	expression string,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
) (string, error) {
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

// generateFunctionScript generates a Solidity script for Functions mode
func (e *SolidityRuleEvaluator) generateFunctionScript(
	functions string,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
) (string, error) {
	data := struct {
		To        string
		Value     string
		Selector  string
		Data      string
		ChainID   string
		Signer    string
		Functions string
	}{
		To:        formatAddress(parsed.Recipient),
		Value:     formatWei(parsed.Value),
		Selector:  formatSelector(parsed.MethodSig),
		Data:      formatBytes(parsed.RawData),
		ChainID:   formatChainID(req.ChainID),
		Signer:    formatAddress(&req.SignerAddress),
		Functions: functions,
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

// executeScript executes the Solidity script/test and returns pass/fail with reason
// filePathHint is an optional hint for grouping scripts from the same file (for better caching)
// This method implements two levels of caching:
// 1. Script file caching: avoids rewriting the same script content to disk
// 2. Execution result caching: avoids re-executing forge for identical scripts
func (e *SolidityRuleEvaluator) executeScript(ctx context.Context, script string, filePathHint ...string) (bool, string, error) {
	// Calculate script hash for caching/naming
	hash := sha256.Sum256([]byte(script))
	hashStr := hex.EncodeToString(hash[:8]) // Use first 8 bytes for shorter filename
	fullHashStr := hex.EncodeToString(hash[:]) // Full hash for cache key

	// Check execution result cache first (fastest path)
	// Since Solidity scripts are deterministic, identical scripts always produce identical results
	e.mu.RLock()
	cachedResult, resultFound := e.executionCache[fullHashStr]
	e.mu.RUnlock()

	if resultFound {
		// Check if cache entry has expired
		if time.Since(cachedResult.timestamp) < e.cacheTTL {
			e.logger.Debug("using cached execution result", "script_hash", hashStr)
			return cachedResult.passed, cachedResult.reason, cachedResult.err
		}
		// Cache entry expired, remove it
		e.mu.Lock()
		delete(e.executionCache, fullHashStr)
		e.mu.Unlock()
		e.logger.Debug("cached execution result expired", "script_hash", hashStr)
	}

	// If filePathHint is provided, use it to create a file-grouped prefix
	// This helps forge's incremental compilation by grouping related files
	var filePrefix string
	if len(filePathHint) > 0 && filePathHint[0] != "" {
		fileHash := sha256.Sum256([]byte(filePathHint[0]))
		filePrefix = hex.EncodeToString(fileHash[:8]) + "_"
	}

	// Determine if this is a test (contains RuleEvaluatorTest) or a script (contains RuleEvaluator)
	isTest := strings.Contains(script, "contract RuleEvaluatorTest")

	// Check script file cache
	e.mu.RLock()
	cachedPath, found := e.scriptCache[fullHashStr]
	e.mu.RUnlock()

	var scriptPath string
	if found {
		// Use cached script path if it still exists
		if _, err := os.Stat(cachedPath); err == nil {
			scriptPath = cachedPath
			e.logger.Debug("using cached script file", "script_hash", hashStr)
		} else {
			// Cache entry is stale, remove it
			e.mu.Lock()
			delete(e.scriptCache, fullHashStr)
			e.mu.Unlock()
			found = false
		}
	}

	// Create script file if not cached
	if !found {
		var err error
		if isTest {
			scriptPath = filepath.Join(e.tempDir, fmt.Sprintf("%srule_%s.t.sol", filePrefix, hashStr))
		} else {
			scriptPath = filepath.Join(e.tempDir, fmt.Sprintf("%srule_%s.sol", filePrefix, hashStr))
		}
		if err = os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
			return false, "", fmt.Errorf("failed to write script: %w", err)
		}
		// Update script cache
		e.mu.Lock()
		e.scriptCache[fullHashStr] = scriptPath
		e.mu.Unlock()
	}

	// Create timeout context if not already set
	execCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}

	// Execute forge test or forge script based on contract type
	var cmd *exec.Cmd
	if isTest {
		// Use forge test for RuleEvaluatorTest contracts
		// Use cache path to speed up compilation
		cmd = exec.CommandContext(execCtx,
			e.foundryPath, "test",
			"--match-path", scriptPath,
			"--match-contract", "RuleEvaluatorTest",
			"--cache-path", filepath.Join(e.cacheDir, "forge-cache"),
			"-vvv", // verbose for revert reasons
		)
	} else {
		// Use forge script for RuleEvaluator contracts
		// Use cache path to speed up compilation
		cmd = exec.CommandContext(execCtx,
			e.foundryPath, "script",
			scriptPath,
			"--json",
			"--cache-path", filepath.Join(e.cacheDir, "forge-cache"),
			"-vvv", // verbose for revert reasons
		)
	}

	// Set working directory to temp dir where foundry.toml exists
	cmd.Dir = e.tempDir

	// Security: Use minimal environment to prevent leaking secrets to user-controlled Solidity code
	cmd.Env = safeForgeEnv()

	output, err := cmd.CombinedOutput()

	// Prepare result for caching
	var result *executionResult

	if err != nil {
		// Parse revert reason from output if available
		reason := parseRevertReason(output)
		if reason != "" {
			e.logger.Debug("rule evaluation failed with revert",
				"reason", reason,
				"script_hash", hashStr,
			)
			result = &executionResult{passed: false, reason: reason, err: nil, timestamp: time.Now()}
		} else if execCtx.Err() == context.DeadlineExceeded {
			// Don't cache timeout errors as they may be transient
			return false, "", fmt.Errorf("script execution timed out after %v", e.timeout)
		} else {
			e.logger.Error("forge execution failed",
				"error", err,
				"output", string(output),
				"script_hash", hashStr,
				"is_test", isTest,
			)
			// Don't cache execution errors as they may be transient (e.g., resource issues)
			return false, "", fmt.Errorf("forge execution failed: %w, output: %s", err, string(output))
		}
	} else {
		e.logger.Debug("rule evaluation passed", "script_hash", hashStr, "is_test", isTest)
		result = &executionResult{passed: true, reason: "", err: nil, timestamp: time.Now()}
	}

	// Cache the execution result (only for successful executions or deterministic failures)
	if result != nil {
		e.mu.Lock()
		e.executionCache[fullHashStr] = result
		e.mu.Unlock()
	}

	return result.passed, result.reason, result.err
}

// GenerateSyntaxCheckScript generates a script for compilation checking (Expression mode)
func (e *SolidityRuleEvaluator) GenerateSyntaxCheckScript(expression string) string {
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
func (e *SolidityRuleEvaluator) GenerateFunctionSyntaxCheckScript(functions string) string {
	return fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// RuleContract contains user-defined validation functions
contract RuleContract {
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
`, functions)
}

// GetTempDir returns the temp directory path
func (e *SolidityRuleEvaluator) GetTempDir() string {
	return e.tempDir
}

// GetFoundryPath returns the forge binary path
func (e *SolidityRuleEvaluator) GetFoundryPath() string {
	return e.foundryPath
}

// GetCacheDir returns the cache directory path
func (e *SolidityRuleEvaluator) GetCacheDir() string {
	return e.cacheDir
}

// Helper functions

func formatAddress(addr *string) string {
	if addr == nil || *addr == "" {
		return "address(0)"
	}
	// Defense in depth: validate hex format before embedding in Solidity.
	// Invalid addresses would cause forge compilation errors and could
	// poison the shared compilation directory (forge compiles all .sol files).
	if !common.IsHexAddress(*addr) {
		return "address(0)"
	}
	// Solidity requires EIP-55 checksummed addresses.
	// common.HexToAddress().Hex() returns the properly checksummed form.
	return common.HexToAddress(*addr).Hex()
}

func formatWei(value *string) string {
	if value == nil || *value == "" {
		return "0"
	}
	// Defense in depth: validate only decimal digits to prevent Solidity template injection.
	// Embedded as: uint256 value = {{.Value}};
	if !isDecimalString(*value) {
		return "0"
	}
	return *value
}

func formatSelector(sig *string) string {
	if sig == nil || *sig == "" {
		return "bytes4(0)"
	}
	// Defense in depth: validate hex to prevent Solidity template injection.
	// Embedded as: bytes4 selector = {{.Selector}};
	s := strings.TrimPrefix(*sig, "0x")
	if !isHexString(s) || len(s) != 8 {
		return "bytes4(0)"
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
	// Defense in depth: validate only decimal digits to prevent Solidity template injection.
	// Embedded as: uint256 chainId = {{.ChainID}};
	if !isDecimalString(chainID) {
		return "1"
	}
	return chainID
}

// forgeScriptResult represents the relevant parts of forge script JSON output
type forgeScriptResult struct {
	Success bool `json:"success"`
	Traces  [][]interface{}
}

// evaluateTypedDataExpression evaluates a Solidity expression with EIP-712 typed data context
// If structDef is provided, it's used for field declarations instead of inferring from request
func (e *SolidityRuleEvaluator) evaluateTypedDataExpression(
	ctx context.Context,
	expression string,
	req *types.SignRequest,
	typedData *TypedDataPayload,
	structDef *StructDefinition,
) (bool, string, error) {
	// Generate script with typed data context
	script, err := e.generateTypedDataExpressionScript(expression, req, typedData, structDef)
	if err != nil {
		return false, "", fmt.Errorf("failed to generate typed data expression script: %w", err)
	}

	// Execute via forge script
	passed, reason, err := e.executeScript(ctx, script)
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
) (bool, string, error) {
	// Generate script with typed data context and user functions
	script, err := e.generateTypedDataFunctionsScript(functions, req, typedData)
	if err != nil {
		return false, "", fmt.Errorf("failed to generate typed data functions script: %w", err)
	}

	// Execute via forge script
	passed, reason, err := e.executeScript(ctx, script)
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
) (string, error) {
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
		PrimaryType      string
		DomainName       string
		DomainVersion    string
		DomainChainId    string
		DomainContract   string
		Signer           string
		ChainID          string
		StructDefinition string
		StructInstance   string
		Expression       string
	}{
		PrimaryType:      formatString(typedData.PrimaryType),
		DomainName:       formatString(typedData.Domain.Name),
		DomainVersion:    formatString(typedData.Domain.Version),
		DomainChainId:    formatDomainChainId(typedData.Domain.ChainId),
		DomainContract:   formatDomainContract(typedData.Domain.VerifyingContract),
		Signer:           formatAddress(&req.SignerAddress),
		ChainID:          formatChainID(req.ChainID),
		StructDefinition: structDefinition,
		StructInstance:   structInstance,
		Expression:       expression,
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
) (string, error) {
	// Encode message data as bytes for struct decoding
	messageData := encodeMessageData(typedData)

	data := struct {
		PrimaryType    string
		DomainName     string
		DomainVersion  string
		DomainChainId  string
		DomainContract string
		Signer         string
		ChainID        string
		MessageData    string
		Functions      string
	}{
		PrimaryType:    formatString(typedData.PrimaryType),
		DomainName:     formatString(typedData.Domain.Name),
		DomainVersion:  formatString(typedData.Domain.Version),
		DomainChainId:  formatDomainChainId(typedData.Domain.ChainId),
		DomainContract: formatDomainContract(typedData.Domain.VerifyingContract),
		Signer:         formatAddress(&req.SignerAddress),
		ChainID:        formatChainID(req.ChainID),
		MessageData:    messageData,
		Functions:      functions,
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

// GenerateTypedDataExpressionSyntaxCheckScript generates a syntax check script for TypedDataExpression mode
// This version supports struct instance syntax when structDef is provided
func (e *SolidityRuleEvaluator) GenerateTypedDataExpressionSyntaxCheckScript(expression string) string {
	// For syntax checking without struct definition, use legacy individual field declarations
	return e.GenerateTypedDataExpressionSyntaxCheckScriptWithStruct(expression, nil)
}

// GenerateTypedDataExpressionSyntaxCheckScriptWithStruct generates a syntax check script with struct support
func (e *SolidityRuleEvaluator) GenerateTypedDataExpressionSyntaxCheckScriptWithStruct(expression string, structDef *StructDefinition) string {
	if structDef != nil {
		// Generate struct-based syntax check
		structDefStr := generateStructDefinition(structDef)
		instanceName := strings.ToLower(structDef.Name[:1]) + structDef.Name[1:]

		// Generate default struct instance
		var fieldDefaults []string
		for _, field := range structDef.Fields {
			fieldDefaults = append(fieldDefaults, fmt.Sprintf("            %s: %s", field.Name, getDefaultValue(field.Type)))
		}

		return fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SyntaxCheck {
    %s

    function run() public pure returns (bool) {
        // EIP-712 Domain context (eip712_* prefix)
        string memory eip712_primaryType = "";
        string memory eip712_domainName = "";
        string memory eip712_domainVersion = "";
        uint256 eip712_domainChainId = 1;
        address eip712_domainContract = address(0);

        // Signing context (ctx_* prefix)
        address ctx_signer = address(0);
        uint256 ctx_chainId = 1;

        // Suppress unused variable warnings
        bytes memory _eip712_primaryType = bytes(eip712_primaryType);
        bytes memory _eip712_domainName = bytes(eip712_domainName);
        bytes memory _eip712_domainVersion = bytes(eip712_domainVersion);
        eip712_domainChainId; eip712_domainContract; ctx_signer; ctx_chainId;
        _eip712_primaryType; _eip712_domainName; _eip712_domainVersion;

        // EIP-712 Message struct instance
        %s memory %s = %s({
%s
        });

        // User expression
        %s

        return true;
    }
}
`, structDefStr, structDef.Name, instanceName, structDef.Name, strings.Join(fieldDefaults, ",\n"), expression)
	}

	// Legacy: Generate with common predefined fields for backward compatibility
	return fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SyntaxCheck {
    // Common struct definitions for syntax checking
    struct Order {
        uint256 salt;
        address maker;
        address signer;
        address taker;
        uint256 tokenId;
        uint256 makerAmount;
        uint256 takerAmount;
        uint256 expiration;
        uint256 nonce;
        uint256 feeRateBps;
        uint8 side;
        uint8 signatureType;
    }

    struct ClobAuth {
        address address_;
        string timestamp;
        uint256 nonce;
        string message_;
    }

    struct CreateProxy {
        address paymentToken;
        uint256 payment;
        address paymentReceiver;
    }

    struct SafeTx {
        address to;
        uint256 value;
        bytes data;
        uint8 operation;
        uint256 safeTxGas;
        uint256 baseGas;
        uint256 gasPrice;
        address gasToken;
        address refundReceiver;
        uint256 nonce;
    }

    struct Permit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }

    function run() public pure returns (bool) {
        // EIP-712 Domain context (eip712_* prefix)
        string memory eip712_primaryType = "";
        string memory eip712_domainName = "";
        string memory eip712_domainVersion = "";
        uint256 eip712_domainChainId = 1;
        address eip712_domainContract = address(0);

        // Signing context (ctx_* prefix)
        address ctx_signer = address(0);
        uint256 ctx_chainId = 1;

        // Suppress unused variable warnings
        bytes memory _eip712_primaryType = bytes(eip712_primaryType);
        bytes memory _eip712_domainName = bytes(eip712_domainName);
        bytes memory _eip712_domainVersion = bytes(eip712_domainVersion);
        eip712_domainChainId; eip712_domainContract; ctx_signer; ctx_chainId;
        _eip712_primaryType; _eip712_domainName; _eip712_domainVersion;

        // Common struct instances for syntax checking
        Order memory order = Order({
            salt: 0, maker: address(0), signer: address(0), taker: address(0),
            tokenId: 0, makerAmount: 0, takerAmount: 0, expiration: 0,
            nonce: 0, feeRateBps: 0, side: 0, signatureType: 0
        });

        ClobAuth memory clobAuth = ClobAuth({
            address_: address(0), timestamp: "", nonce: 0, message_: ""
        });

        CreateProxy memory createProxy = CreateProxy({
            paymentToken: address(0), payment: 0, paymentReceiver: address(0)
        });

        SafeTx memory safeTx = SafeTx({
            to: address(0), value: 0, data: "", operation: 0, safeTxGas: 0,
            baseGas: 0, gasPrice: 0, gasToken: address(0), refundReceiver: address(0), nonce: 0
        });

        Permit memory permit = Permit({
            owner: address(0), spender: address(0), value: 0, nonce: 0, deadline: 0
        });

        // Suppress unused struct warnings
        order; clobAuth; createProxy; safeTx; permit;

        // User expression
        %s

        return true;
    }
}
`, expression)
}

// GenerateTypedDataFunctionsSyntaxCheckScript generates a syntax check script for TypedDataFunctions mode
func (e *SolidityRuleEvaluator) GenerateTypedDataFunctionsSyntaxCheckScript(functions string) string {
	return fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SyntaxCheck {
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
`, functions)
}

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
		// Non-0x string: encode as hex bytes (safe — hex.EncodeToString always produces valid hex)
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

// safeForgeEnv returns a minimal environment for Forge subprocesses.
// Only passes essential system variables (PATH, HOME, TMPDIR) and
// explicitly disables dangerous Foundry features.
// This prevents leaking secrets (e.g., SIGNER_PRIVATE_KEY) to user-controlled
// Solidity code even if the cheatcode blocklist is bypassed.
func safeForgeEnv() []string {
	env := []string{
		"FOUNDRY_FFI=false",
		"FOUNDRY_FS_PERMISSIONS=[]",
	}
	// Only forward essential system variables
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "TEMP", "TMP", "XDG_CACHE_HOME"} {
		if val := os.Getenv(key); val != "" {
			env = append(env, key+"="+val)
		}
	}
	return env
}

// isDecimalString checks if a string contains only decimal digits (0-9).
// Used to validate numeric values before embedding in Solidity templates.
func isDecimalString(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isHexString checks if a string contains only hex characters (0-9, a-f, A-F).
// Used to validate hex values before embedding in Solidity templates.
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// parseRevertReason extracts the revert reason from forge output
func parseRevertReason(output []byte) string {
	outputStr := string(output)

	// Pattern 0: forge test output format - [FAIL: <reason>] test_name()
	// This is the primary format for forge test failures
	failPattern := regexp.MustCompile(`\[FAIL:\s*([^\]]+)\]`)
	if matches := failPattern.FindStringSubmatch(outputStr); len(matches) > 1 {
		reason := strings.TrimSpace(matches[1])
		if reason != "" {
			return reason
		}
	}

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

// ============================================================================
// Batch Evaluation Support
// ============================================================================

// ValidationMode represents the type of Solidity validation
type evaluationMode int

const (
	evalModeExpression evaluationMode = iota
	evalModeFunctions
	evalModeTypedDataExpression
	evalModeTypedDataFunctions
)

// ruleEvalContext holds preprocessed rule context for batch evaluation
type ruleEvalContext struct {
	rule      *types.Rule
	config    SolidityExpressionConfig
	mode      evaluationMode
	structDef *StructDefinition
	typedData *TypedDataPayload
	skipped   bool // true if rule doesn't apply (primaryType mismatch, etc.)
}

// CanBatchEvaluate returns true if the given rules can be evaluated together
// Rules can be batched if they all use compatible validation modes
func (e *SolidityRuleEvaluator) CanBatchEvaluate(rules []*types.Rule) bool {
	if len(rules) == 0 {
		return false
	}
	if len(rules) == 1 {
		return true // Single rule is always "batchable"
	}

	// Check if all rules use the same mode family
	var hasExpression, hasFunctions, hasTypedDataExpression, hasTypedDataFunctions bool
	for _, rule := range rules {
		var config SolidityExpressionConfig
		if err := json.Unmarshal(rule.Config, &config); err != nil {
			return false
		}

		if config.TypedDataExpression != "" {
			hasTypedDataExpression = true
		} else if config.TypedDataFunctions != "" {
			hasTypedDataFunctions = true
		} else if config.Functions != "" {
			hasFunctions = true
		} else {
			hasExpression = true
		}
	}

	// Count how many different modes are present
	modeCount := 0
	if hasExpression {
		modeCount++
	}
	if hasFunctions {
		modeCount++
	}
	if hasTypedDataExpression {
		modeCount++
	}
	if hasTypedDataFunctions {
		modeCount++
	}

	// Can batch if all rules use the same mode
	// For now, we support batching TypedDataExpression rules together
	// as they are the most common and benefit most from batching
	return modeCount == 1 && hasTypedDataExpression
}

// EvaluateBatch evaluates multiple rules against the same request in a single forge execution
func (e *SolidityRuleEvaluator) EvaluateBatch(
	ctx context.Context,
	rules []*types.Rule,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
) ([]rule.BatchEvaluationResult, error) {
	if len(rules) == 0 {
		return nil, nil
	}

	// For single rule, just use regular Evaluate
	if len(rules) == 1 {
		passed, reason, err := e.Evaluate(ctx, rules[0], req, parsed)
		return []rule.BatchEvaluationResult{{
			RuleID: rules[0].ID,
			Passed: passed,
			Reason: reason,
			Err:    err,
		}}, nil
	}

	// Preprocess all rules
	contexts, err := e.preprocessRulesForBatch(rules, req)
	if err != nil {
		return nil, fmt.Errorf("failed to preprocess rules: %w", err)
	}

	// Check if any rules are applicable (not skipped)
	applicableCount := 0
	for _, ctx := range contexts {
		if !ctx.skipped {
			applicableCount++
		}
	}

	if applicableCount == 0 {
		// All rules skipped, return results immediately
		results := make([]rule.BatchEvaluationResult, len(rules))
		for i, c := range contexts {
			results[i] = rule.BatchEvaluationResult{
				RuleID:  c.rule.ID,
				Skipped: true,
			}
		}
		return results, nil
	}

	// Generate batch test script
	script, ruleIndices, err := e.generateBatchEvaluationScript(contexts, req, parsed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate batch script: %w", err)
	}

	// Execute batch test
	testResults, err := e.executeBatchScript(ctx, script, ruleIndices)
	if err != nil {
		return nil, fmt.Errorf("batch script execution failed: %w", err)
	}

	// Map results back to rules
	results := make([]rule.BatchEvaluationResult, len(rules))
	for i, c := range contexts {
		if c.skipped {
			results[i] = rule.BatchEvaluationResult{
				RuleID:  c.rule.ID,
				Skipped: true,
			}
			continue
		}

		if tr, ok := testResults[i]; ok {
			// Apply blocklist mode inversion
			passed := tr.passed
			if c.rule.Mode == types.RuleModeBlocklist {
				passed = !passed
			}
			results[i] = rule.BatchEvaluationResult{
				RuleID: c.rule.ID,
				Passed: passed,
				Reason: tr.reason,
				Err:    tr.err,
			}
		} else {
			results[i] = rule.BatchEvaluationResult{
				RuleID: c.rule.ID,
				Err:    fmt.Errorf("no result for rule"),
			}
		}
	}

	return results, nil
}

// preprocessRulesForBatch prepares rule contexts for batch evaluation
func (e *SolidityRuleEvaluator) preprocessRulesForBatch(
	rules []*types.Rule,
	req *types.SignRequest,
) ([]*ruleEvalContext, error) {
	contexts := make([]*ruleEvalContext, len(rules))

	// Parse typed data once if needed
	var typedData *TypedDataPayload
	var typedDataErr error
	typedDataParsed := false

	for i, r := range rules {
		var config SolidityExpressionConfig
		if err := json.Unmarshal(r.Config, &config); err != nil {
			return nil, fmt.Errorf("invalid config for rule %s: %w", r.ID, err)
		}

		ctx := &ruleEvalContext{
			rule:   r,
			config: config,
		}

		// Check SignTypeFilter
		if config.SignTypeFilter != "" && config.SignTypeFilter != req.SignType {
			ctx.skipped = true
			contexts[i] = ctx
			continue
		}

		// Determine mode
		if config.TypedDataExpression != "" {
			ctx.mode = evalModeTypedDataExpression

			// Parse typed data lazily
			if !typedDataParsed {
				typedData, typedDataErr = parseTypedDataFromPayload(req.Payload)
				typedDataParsed = true
			}
			if typedDataErr != nil {
				return nil, fmt.Errorf("failed to parse typed data: %w", typedDataErr)
			}
			ctx.typedData = typedData

			// Parse struct definition if provided
			if config.TypedDataStruct != "" {
				structDef, err := parseStructDefinition(config.TypedDataStruct)
				if err != nil {
					return nil, fmt.Errorf("failed to parse typed_data_struct for rule %s: %w", r.ID, err)
				}
				ctx.structDef = structDef

				// Check primaryType match
				if typedData.PrimaryType != structDef.Name {
					ctx.skipped = true
					e.logger.Debug("typed_data_struct primaryType mismatch, skipping rule in batch",
						"rule_id", r.ID,
						"rule_struct", structDef.Name,
						"request_primaryType", typedData.PrimaryType,
					)
				}
			}
		} else if config.TypedDataFunctions != "" {
			ctx.mode = evalModeTypedDataFunctions
			// For now, we don't batch TypedDataFunctions
			ctx.skipped = true
		} else if config.Functions != "" {
			ctx.mode = evalModeFunctions
			// For now, we don't batch Functions mode
			ctx.skipped = true
		} else {
			ctx.mode = evalModeExpression
			// For now, we don't batch Expression mode
			ctx.skipped = true
		}

		contexts[i] = ctx
	}

	return contexts, nil
}

// generateBatchEvaluationScript generates a single Solidity contract with multiple test functions
func (e *SolidityRuleEvaluator) generateBatchEvaluationScript(
	contexts []*ruleEvalContext,
	req *types.SignRequest,
	parsed *types.ParsedPayload,
) (string, map[int]int, error) {
	// Collect struct definitions for TypedDataExpression mode
	structDefs := make(map[string]*StructDefinition)
	var testFunctions []string
	ruleIndices := make(map[int]int) // testIndex -> contextIndex

	testIndex := 0
	for i, ctx := range contexts {
		if ctx.skipped {
			continue
		}

		if ctx.mode == evalModeTypedDataExpression {
			// Collect struct definition
			if ctx.structDef != nil {
				structDefs[ctx.structDef.Name] = ctx.structDef
			}

			// Generate struct instance
			var structInstance string
			if ctx.structDef != nil {
				structInstance = generateStructInstance(ctx.structDef, ctx.typedData.Message)
			} else {
				structInstance = generateMessageFieldDeclarations(ctx.typedData)
			}

			// Generate test function for this rule
			testFunc := fmt.Sprintf(`    function test_rule_%d() public pure returns (bool) {
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
				testIndex,
				formatString(ctx.typedData.PrimaryType),
				formatString(ctx.typedData.Domain.Name),
				formatString(ctx.typedData.Domain.Version),
				formatDomainChainId(ctx.typedData.Domain.ChainId),
				formatDomainContract(ctx.typedData.Domain.VerifyingContract),
				formatAddress(&req.SignerAddress),
				formatChainID(req.ChainID),
				structInstance,
				ctx.config.TypedDataExpression,
			)
			testFunctions = append(testFunctions, testFunc)
			ruleIndices[testIndex] = i
			testIndex++
		}
	}

	if len(testFunctions) == 0 {
		return "", nil, fmt.Errorf("no applicable rules for batch evaluation")
	}

	// Generate struct definitions
	var structDefinitions []string
	for _, sd := range structDefs {
		structDefinitions = append(structDefinitions, generateStructDefinition(sd))
	}

	// Build the batch test contract
	var sb strings.Builder
	sb.WriteString(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BatchRuleEvaluatorTest {
`)

	// Add struct definitions
	for _, sd := range structDefinitions {
		sb.WriteString("    ")
		sb.WriteString(sd)
		sb.WriteString("\n\n")
	}

	// Add test functions
	for _, tf := range testFunctions {
		sb.WriteString(tf)
		sb.WriteString("\n\n")
	}

	sb.WriteString("}\n")

	return sb.String(), ruleIndices, nil
}

// batchTestResult holds the result of a single test in a batch
type batchTestResult struct {
	passed bool
	reason string
	err    error
}

// executeBatchScript executes the batch test script and parses results
func (e *SolidityRuleEvaluator) executeBatchScript(
	ctx context.Context,
	script string,
	ruleIndices map[int]int,
) (map[int]*batchTestResult, error) {
	// Calculate script hash
	hash := sha256.Sum256([]byte(script))
	hashStr := hex.EncodeToString(hash[:8])
	fullHashStr := hex.EncodeToString(hash[:])

	// Check execution cache
	e.mu.RLock()
	cachedResult, found := e.executionCache[fullHashStr]
	e.mu.RUnlock()

	if found && time.Since(cachedResult.timestamp) < e.cacheTTL {
		e.logger.Debug("using cached batch execution result", "script_hash", hashStr)
		// For cached results, we assume all tests passed or all failed together
		// This is a simplification - in practice, batch results need per-test caching
		results := make(map[int]*batchTestResult)
		for testIdx, ctxIdx := range ruleIndices {
			results[ctxIdx] = &batchTestResult{
				passed: cachedResult.passed,
				reason: cachedResult.reason,
			}
			_ = testIdx // suppress unused warning
		}
		return results, nil
	}

	// Write script to temp file
	scriptPath := filepath.Join(e.tempDir, fmt.Sprintf("batch_%s.t.sol", hashStr))
	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		return nil, fmt.Errorf("failed to write batch script: %w", err)
	}

	// Create timeout context
	execCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}

	// Execute forge test with verbose output for parsing individual test results
	// Note: We use human-readable output (not --json) because parseBatchTestOutput
	// uses regex to match [PASS] and [FAIL: reason] patterns
	cmd := exec.CommandContext(execCtx,
		e.foundryPath, "test",
		"--match-path", scriptPath,
		"--match-contract", "BatchRuleEvaluatorTest",
		"--cache-path", filepath.Join(e.cacheDir, "forge-cache"),
		"-vvv",
	)
	cmd.Dir = e.tempDir
	cmd.Env = safeForgeEnv()

	output, err := cmd.CombinedOutput()

	results := make(map[int]*batchTestResult)

	if err != nil {
		// Parse individual test failures from output
		outputStr := string(output)
		e.logger.Debug("batch test execution failed, parsing results",
			"script_hash", hashStr,
			"output_length", len(outputStr),
		)

		// Try to parse JSON output for individual test results
		testResults := e.parseBatchTestOutput(outputStr, ruleIndices)
		if len(testResults) > 0 {
			return testResults, nil
		}

		// Fallback: if we can't parse individual results, mark all as failed
		reason := parseRevertReason(output)
		for _, ctxIdx := range ruleIndices {
			results[ctxIdx] = &batchTestResult{
				passed: false,
				reason: reason,
			}
		}
		return results, nil
	}

	// All tests passed
	e.logger.Debug("batch test execution passed", "script_hash", hashStr, "test_count", len(ruleIndices))
	for _, ctxIdx := range ruleIndices {
		results[ctxIdx] = &batchTestResult{
			passed: true,
		}
	}

	// Cache the successful result
	e.mu.Lock()
	e.executionCache[fullHashStr] = &executionResult{
		passed:    true,
		timestamp: time.Now(),
	}
	e.mu.Unlock()

	return results, nil
}

// parseBatchTestOutput parses forge test human-readable output to extract individual test results
func (e *SolidityRuleEvaluator) parseBatchTestOutput(
	output string,
	ruleIndices map[int]int,
) map[int]*batchTestResult {
	results := make(map[int]*batchTestResult)

	// Parse test results from forge output
	// Format: [PASS] test_rule_0() or [FAIL: reason] test_rule_0()
	passPattern := regexp.MustCompile(`\[PASS\]\s+test_rule_(\d+)\(\)`)
	failPattern := regexp.MustCompile(`\[FAIL:\s*([^\]]*)\]\s+test_rule_(\d+)\(\)`)

	// Find passed tests
	passMatches := passPattern.FindAllStringSubmatch(output, -1)
	for _, match := range passMatches {
		if len(match) >= 2 {
			var testIdx int
			if _, err := fmt.Sscanf(match[1], "%d", &testIdx); err == nil {
				if ctxIdx, ok := ruleIndices[testIdx]; ok {
					results[ctxIdx] = &batchTestResult{passed: true}
				}
			}
		}
	}

	// Find failed tests
	failMatches := failPattern.FindAllStringSubmatch(output, -1)
	for _, match := range failMatches {
		if len(match) >= 3 {
			reason := strings.TrimSpace(match[1])
			var testIdx int
			if _, err := fmt.Sscanf(match[2], "%d", &testIdx); err == nil {
				if ctxIdx, ok := ruleIndices[testIdx]; ok {
					results[ctxIdx] = &batchTestResult{
						passed: false,
						reason: reason,
					}
				}
			}
		}
	}

	return results
}
