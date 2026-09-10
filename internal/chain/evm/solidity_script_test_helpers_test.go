package evm

import (
	"context"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// renderTypedDataExpression and renderTypedDataFunctions render a typed-data
// script in one step.
//
// ⚠️ Production builds the script and runs it in two steps, because the
// evaluator needs the script value to decide it passes no env — a typed-data
// script bakes the signed payload into its source and must not read request
// data at run time. Tests only want the source, so they collapse the two.
func renderTypedDataExpression(e *SolidityRuleEvaluator, expression string, req *types.SignRequest, td *TypedDataPayload, sd *StructDefinition, inMaps map[string][]string) (string, error) {
	s, err := e.typedDataExpressionScript(expression, req, td, sd, inMaps)
	if err != nil {
		return "", err
	}
	return s.render()
}

func renderTypedDataFunctions(e *SolidityRuleEvaluator, functions string, req *types.SignRequest, td *TypedDataPayload, inMaps map[string][]string) (string, error) {
	s, err := e.typedDataFunctionsScript(functions, req, td, inMaps)
	if err != nil {
		return "", err
	}
	return s.render()
}

// runTypedDataExpression and runTypedDataFunctions build a typed-data script and
// run it, which is what the evaluator's dispatch does in two steps.
//
// ⛔ env is nil, and must stay nil: a typed-data script bakes the domain and
// message it checks into its own source. Feeding it request data at run time
// would let it verify a payload other than the one it was compiled against.
func runTypedDataExpression(e *SolidityRuleEvaluator, ctx context.Context, expression string, req *types.SignRequest, td *TypedDataPayload, sd *StructDefinition, inMaps map[string][]string) (bool, string, error) {
	s, err := e.typedDataExpressionScript(expression, req, td, sd, inMaps)
	if err != nil {
		return false, "", err
	}
	return e.run(ctx, s, nil)
}

func runTypedDataFunctions(e *SolidityRuleEvaluator, ctx context.Context, functions string, req *types.SignRequest, td *TypedDataPayload, inMaps map[string][]string) (bool, string, error) {
	s, err := e.typedDataFunctionsScript(functions, req, td, inMaps)
	if err != nil {
		return false, "", err
	}
	return e.run(ctx, s, nil)
}
