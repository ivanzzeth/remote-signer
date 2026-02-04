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

// solidityExpressionTemplate is for require-based rules (Expression mode)
// Context variables use prefixes to avoid conflicts with user-defined field names:
// - tx_* : Transaction context (tx_to, tx_value, tx_selector, tx_data)
// - ctx_* : Signing context (ctx_chainId, ctx_signer)
const solidityExpressionTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RuleEvaluator {
    function run() public pure returns (bool) {
        // Transaction context (tx_* prefix)
        address tx_to = {{.To}};
        uint256 tx_value = {{.Value}};
        bytes4 tx_selector = {{.Selector}};
        bytes memory tx_data = {{.Data}};

        // Signing context (ctx_* prefix)
        uint256 ctx_chainId = {{.ChainID}};
        address ctx_signer = {{.Signer}};

        // Suppress unused variable warnings
        tx_to; tx_value; tx_selector; tx_data; ctx_chainId; ctx_signer;

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
// Message fields are generated directly from typed data without prefixes (e.g., value, to, data)
const solidityTypedDataExpressionTemplate = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RuleEvaluator {
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

        // EIP-712 Message fields (dynamically generated based on message content)
        // These use the original field names from the typed data message (e.g., value, to, data)
        {{.MessageFields}}

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

	// Create temp directory with restricted permissions (owner-only)
	tempDir := filepath.Join(os.TempDir(), "remote-signer-rules")
	if err := os.MkdirAll(tempDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	// Create foundry.toml for forge test to work properly
	// Note: Don't specify solc version to let forge auto-detect from pragma
	// Enable via_ir to avoid "Stack too deep" errors with many local variables
	foundryConfig := `[profile.default]
src = "."
test = "."
out = "out"
libs = []
via_ir = true
optimizer = false
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

		if config.TypedDataExpression != "" {
			passed, reason, err = e.evaluateTypedDataExpression(ctx, config.TypedDataExpression, req, typedData)
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
func (e *SolidityRuleEvaluator) executeScript(ctx context.Context, script string) (bool, string, error) {
	// Calculate script hash for caching/naming
	hash := sha256.Sum256([]byte(script))
	hashStr := hex.EncodeToString(hash[:8]) // Use first 8 bytes for shorter filename

	// Determine if this is a test (contains RuleEvaluatorTest) or a script (contains RuleEvaluator)
	isTest := strings.Contains(script, "contract RuleEvaluatorTest")

	// Create script file with restricted permissions (owner-only)
	var scriptPath string
	if isTest {
		scriptPath = filepath.Join(e.tempDir, fmt.Sprintf("rule_%s.t.sol", hashStr))
	} else {
		scriptPath = filepath.Join(e.tempDir, fmt.Sprintf("rule_%s.sol", hashStr))
	}
	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		return false, "", fmt.Errorf("failed to write script: %w", err)
	}
	// DEBUG: Comment out to keep files for debugging
	// defer os.Remove(scriptPath)

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
		cmd = exec.CommandContext(execCtx,
			e.foundryPath, "test",
			"--match-path", scriptPath,
			"--match-contract", "RuleEvaluatorTest",
			"-vvv", // verbose for revert reasons
		)
	} else {
		// Use forge script for RuleEvaluator contracts
		cmd = exec.CommandContext(execCtx,
			e.foundryPath, "script",
			scriptPath,
			"--json",
			"-vvv", // verbose for revert reasons
		)
	}

	// Set working directory to temp dir where foundry.toml exists
	cmd.Dir = e.tempDir

	// Security: Disable dangerous Foundry cheatcodes
	// - FOUNDRY_FFI=false: Prevent arbitrary command execution via vm.ffi()
	// - FOUNDRY_FS_PERMISSIONS=[]: Prevent file system access via vm.readFile(), vm.writeFile(), etc.
	cmd.Env = append(os.Environ(),
		"FOUNDRY_FFI=false",
		"FOUNDRY_FS_PERMISSIONS=[]",
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

		e.logger.Error("forge execution failed",
			"error", err,
			"output", string(output),
			"script_hash", hashStr,
			"is_test", isTest,
		)
		return false, "", fmt.Errorf("forge execution failed: %w, output: %s", err, string(output))
	}

	e.logger.Debug("rule evaluation passed", "script_hash", hashStr, "is_test", isTest)
	return true, "", nil
}

// GenerateSyntaxCheckScript generates a script for compilation checking (Expression mode)
func (e *SolidityRuleEvaluator) GenerateSyntaxCheckScript(expression string) string {
	return fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SyntaxCheck {
    function run() public pure returns (bool) {
        // Transaction context (tx_* prefix)
        address tx_to = address(0);
        uint256 tx_value = 0;
        bytes4 tx_selector = bytes4(0);
        bytes memory tx_data = "";

        // Signing context (ctx_* prefix)
        uint256 ctx_chainId = 1;
        address ctx_signer = address(0);

        // Suppress unused variable warnings
        tx_to; tx_value; tx_selector; tx_data; ctx_chainId; ctx_signer;

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

// evaluateTypedDataExpression evaluates a Solidity expression with EIP-712 typed data context
func (e *SolidityRuleEvaluator) evaluateTypedDataExpression(
	ctx context.Context,
	expression string,
	req *types.SignRequest,
	typedData *TypedDataPayload,
) (bool, string, error) {
	// Generate script with typed data context
	script, err := e.generateTypedDataExpressionScript(expression, req, typedData)
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
func (e *SolidityRuleEvaluator) generateTypedDataExpressionScript(
	expression string,
	req *types.SignRequest,
	typedData *TypedDataPayload,
) (string, error) {
	// Generate message field declarations from the typed data message
	messageFields := generateMessageFieldDeclarations(typedData)

	data := struct {
		PrimaryType    string
		DomainName     string
		DomainVersion  string
		DomainChainId  string
		DomainContract string
		Signer         string
		ChainID        string
		MessageFields  string
		Expression     string
	}{
		PrimaryType:    formatString(typedData.PrimaryType),
		DomainName:     formatString(typedData.Domain.Name),
		DomainVersion:  formatString(typedData.Domain.Version),
		DomainChainId:  formatDomainChainId(typedData.Domain.ChainId),
		DomainContract: formatDomainContract(typedData.Domain.VerifyingContract),
		Signer:         formatAddress(&req.SignerAddress),
		ChainID:        formatChainID(req.ChainID),
		MessageFields:  messageFields,
		Expression:     expression,
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
func (e *SolidityRuleEvaluator) GenerateTypedDataExpressionSyntaxCheckScript(expression string) string {
	return fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SyntaxCheck {
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

        // Common EIP-712 message fields for syntax check
        // These use original field names from typed data (no prefix needed)

        // Permit fields
        address owner = address(0);
        address spender = address(0);
        uint256 value = 0;
        uint256 nonce = 0;
        uint256 deadline = 0;

        // ClobAuth fields
        string memory message = "";

        // Order fields (Polymarket/Opinion CTF Exchange)
        uint256 salt = 0;
        address maker = address(0);
        address signer = address(0);
        address taker = address(0);
        uint256 tokenId = 0;
        uint256 makerAmount = 0;
        uint256 takerAmount = 0;
        uint256 expiration = 0;
        uint256 feeRateBps = 0;
        uint256 side = 0;
        uint256 signatureType = 0;

        // CreateProxy fields (Polymarket Safe Factory)
        address paymentToken = address(0);
        uint256 payment = 0;
        address paymentReceiver = address(0);

        // SafeTx fields
        address to = address(0);
        bytes memory data = "";
        uint256 operation = 0;
        uint256 safeTxGas = 0;
        uint256 baseGas = 0;
        uint256 gasPrice = 0;
        address gasToken = address(0);
        address refundReceiver = address(0);

        // Suppress unused variable warnings
        owner; spender; value; nonce; deadline;
        bytes memory _message = bytes(message); _message;
        salt; maker; signer; taker; tokenId; makerAmount; takerAmount; expiration; feeRateBps; side; signatureType;
        paymentToken; payment; paymentReceiver;
        to; data; operation; safeTxGas; baseGas; gasPrice; gasToken; refundReceiver;

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

// generateFieldDeclaration generates a single Solidity variable declaration
func generateFieldDeclaration(name, solidityType string, value interface{}) string {
	// Escape reserved keywords
	safeName := escapeReservedKeyword(name)

	// Handle common Solidity types
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
		// uint8, uint16, ..., uint248
		return fmt.Sprintf("%s %s = %s;", solidityType, safeName, formatInterfaceAsUint(value))
	case strings.HasPrefix(solidityType, "int"):
		// int8, int16, ..., int248
		return fmt.Sprintf("%s %s = %s;", solidityType, safeName, formatInterfaceAsInt(value))
	case strings.HasPrefix(solidityType, "bytes") && len(solidityType) <= 8:
		// bytes1, bytes2, ..., bytes32
		return fmt.Sprintf("%s %s = %s;", solidityType, safeName, formatInterfaceAsFixedBytes(value, solidityType))
	default:
		// For custom types or arrays, skip for now (can be extended)
		return fmt.Sprintf("// Skipped field %s of type %s", name, solidityType)
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
	return chainId
}

func formatDomainContract(addr string) string {
	if addr == "" {
		return "address(0)"
	}
	return addr
}

func formatInterfaceAsAddress(v interface{}) string {
	switch val := v.(type) {
	case string:
		if val == "" {
			return "address(0)"
		}
		return val
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
			return val
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
			return fmt.Sprintf(`hex"%s"`, strings.TrimPrefix(val, "0x"))
		}
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
			return val
		}
		return fmt.Sprintf(`hex"%s"`, val)
	default:
		return fmt.Sprintf("%s(0)", solidityType)
	}
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
