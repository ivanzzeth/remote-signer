// Package evm provides the EVM chain implementation including rule evaluation,
// signer management, and transaction processing for the remote-signer daemon.
package evm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// executeScript executes the Solidity script/test and returns pass/fail with reason.
// When requestEnv is non-nil, those vars are merged into the process env (request-as-input mode:
// same script is reused, no execution result cache). When requestEnv is nil, behavior is unchanged.
// filePathHint is an optional hint for grouping scripts from the same file (for better caching).
func (e *SolidityRuleEvaluator) executeScript(ctx context.Context, script string, requestEnv []string, filePathHint ...string) (bool, string, error) {
	// Calculate script hash for caching/naming
	hash := sha256.Sum256([]byte(script))
	hashStr := hex.EncodeToString(hash[:8]) // Use first 8 bytes for shorter filename
	fullHashStr := hex.EncodeToString(hash[:]) // Full hash for cache key

	// When request data is passed via env, same script can produce different results -> do not use execution cache
	useExecutionCache := len(requestEnv) == 0

	if useExecutionCache {
		// Check execution result cache first (fastest path)
		e.mu.RLock()
		cachedResult, resultFound := e.executionCache[fullHashStr]
		e.mu.RUnlock()

		if resultFound {
			if time.Since(cachedResult.timestamp) < e.cacheTTL {
				e.logger.Debug("using cached execution result", "script_hash", hashStr)
				return cachedResult.passed, cachedResult.reason, cachedResult.err
			}
			e.mu.Lock()
			delete(e.executionCache, fullHashStr)
			e.mu.Unlock()
			e.logger.Debug("cached execution result expired", "script_hash", hashStr)
		}
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
		cmd = exec.CommandContext(execCtx, // #nosec G204 -- foundryPath is admin-configured
			e.foundryPath, "test",
			"--match-path", scriptPath,
			"--match-contract", "RuleEvaluatorTest",
			"--cache-path", filepath.Join(e.cacheDir, "forge-cache"),
			"-vvv", // verbose for revert reasons
		)
	} else {
		// Use forge script for RuleEvaluator contracts.
		// Foundry expects "path:ContractName" or "ContractName"; pass path:RuleEvaluator.
		scriptTarget := scriptPath + ":RuleEvaluator"
		cmd = exec.CommandContext(execCtx, // #nosec G204 -- foundryPath is admin-configured
			e.foundryPath, "script",
			scriptTarget,
			"--json",
			"--cache-path", filepath.Join(e.cacheDir, "forge-cache"),
			"-vvv", // verbose for revert reasons
		)
	}

	// Set working directory to temp dir where foundry.toml exists
	cmd.Dir = e.tempDir

	// Security: Use minimal environment; merge request-as-input vars when provided
	cmd.Env = safeForgeEnv()
	if len(requestEnv) > 0 {
		cmd.Env = append(cmd.Env, requestEnv...)
	}

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

	// Cache the execution result only when script is deterministic (no requestEnv)
	if result != nil && useExecutionCache {
		e.mu.Lock()
		e.executionCache[fullHashStr] = result
		e.mu.Unlock()
	}

	return result.passed, result.reason, result.err
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

// GetTimeout returns the configured execution timeout (for validator to align forge build/test timeouts)
func (e *SolidityRuleEvaluator) GetTimeout() time.Duration {
	return e.timeout
}

// ensureForgeStd installs forge-std in the given directory if lib/forge-std does not exist.
// Required for request-as-input scripts that use vm.env* and vm.parseBytes.
//
// To avoid re-downloading forge-std for every test's isolated temp directory (which
// caused the pre-commit hook to timeout), this function uses a global cache at
// $HOME/.cache/remote-signer/forge-std. The first call installs forge-std to the
// cache, and subsequent calls symlink from it.
func ensureForgeStd(dir, foundryPath string) error {
	libForgeStd := filepath.Join(dir, "lib", "forge-std")
	if _, err := os.Stat(filepath.Join(libForgeStd, "src")); err == nil {
		return nil
	}

	// Check global cache to avoid repeated downloads.
	homeDir, _ := os.UserHomeDir()
	cacheDir := filepath.Join(homeDir, ".cache", "remote-signer")
	cachedForgeStd := filepath.Join(cacheDir, "forge-std")
	if _, err := os.Stat(filepath.Join(cachedForgeStd, "lib", "forge-std", "src")); err != nil {
		// Install to global cache.
		if err := os.MkdirAll(filepath.Join(cachedForgeStd, "lib"), 0700); err != nil {
			return fmt.Errorf("create cache lib dir: %w", err)
		}
		cacheFoundryConfig := `[profile.default]
src = "."
libs = ["lib"]
`
		if err := os.WriteFile(filepath.Join(cachedForgeStd, "foundry.toml"), []byte(cacheFoundryConfig), 0600); err != nil {
			return fmt.Errorf("create cache foundry.toml: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, foundryPath, "install", "foundry-rs/forge-std", "--no-git")
		cmd.Dir = cachedForgeStd
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("forge install forge-std (cache): %w, output: %s", err, string(out))
		}
	}

	// Symlink from cache.
	if err := os.MkdirAll(filepath.Join(dir, "lib"), 0700); err != nil {
		return fmt.Errorf("create lib dir: %w", err)
	}
	if err := os.Symlink(filepath.Join(cachedForgeStd, "lib", "forge-std"), libForgeStd); err != nil {
		return fmt.Errorf("symlink forge-std: %w", err)
	}
	return nil
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
