package evm

import (
	"context"
	"encoding/json"
	"fmt"

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
