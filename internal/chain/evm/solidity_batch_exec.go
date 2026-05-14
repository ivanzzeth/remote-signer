// Package evm provides EVM-specific chain logic for the Remote Signer.
// solidity_batch_exec.go executes Solidity batch verification scripts (entrypoint
// generation, output parsing, result aggregation across multiple rules/routes).
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

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// batchTestResult holds the result of a single test in a batch
type batchTestResult struct {
	passed bool
	reason string
	err    error
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
				preprocessInOperator(ctx.config.TypedDataExpression),
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
		for _, ctxIdx := range ruleIndices {
			results[ctxIdx] = &batchTestResult{
				passed: cachedResult.passed,
				reason: cachedResult.reason,
			}
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
	cmd := exec.CommandContext(execCtx, // #nosec G204 -- foundryPath is admin-configured
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
