package evm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// evaluationMode represents the type of Solidity validation
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
