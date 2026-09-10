package evm

import (
	"bytes"
	"context"
	"fmt"
	"text/template"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ---------- one way to build and run a Solidity rule script ----------
//
// A Solidity rule comes in four shapes: the operator writes an expression or a
// block of functions, against transaction context or EIP-712 typed data. Each
// combination had its own generator and its own evaluator — eight functions
// that differed in a template name and a struct field name, and agreed on
// everything else:
//
//	ir := processInOperatorToMappings(body, arrays)   // rewrite in(...)
//	body = preprocessInOperator(ir.Modified)
//	... bind ...                                       // the two typed-data
//	                                                   // modes bound the same
//	                                                   // seven EIP-712 fields
//	tmpl, err := template.New(name).Parse(text)        // render
//	... execute ...
//	passed, reason, err := e.executeScript(ctx, script, env)   // run
//
// ⚠️ The templates themselves are not duplicates — measured pairwise they share
// 22–50% of their lines, because a contract holding typed-data really does look
// different from one holding a transaction. It is the machinery around them
// that was written four times.
//
// ⛔ Adding a fifth shape means adding a template and a spec, not another copy
// of this pipeline.

// solidityScript is a Solidity rule script waiting to be rendered: the
// operator's own code, plus whatever bindings its template needs beyond the
// in()-rewrite every shape shares.
type solidityScript struct {
	// mode names the template and is the noun in error messages, so a
	// generation failure says which shape failed.
	mode     string
	template string

	// body is the operator's expression or function block, before in() is
	// rewritten into mappings. Every template binds it as {{.Body}}.
	//
	// ⚠️ The templates used to call this slot {{.Expression}} or {{.Functions}}
	// depending on the shape, which is the whole reason two identical render
	// functions could not be one.
	body   string
	inMaps map[string][]string

	// bind carries the mode-specific placeholders. Empty for the transaction
	// shapes; the typed-data shapes fill it from typedDataBindings.
	bind map[string]string
}

// render turns the script into Solidity source.
func (s solidityScript) render() (string, error) {
	ir := processInOperatorToMappings(s.body, s.inMaps)

	data := make(map[string]string, len(s.bind)+4)
	for k, v := range s.bind {
		data[k] = v
	}
	data["Body"] = preprocessInOperator(ir.Modified)
	data["InMappingDeclarations"] = ir.Declarations
	data["InMappingConstructorInit"] = ir.ConstructorInit

	tmpl, err := template.New(s.mode).Parse(s.template)
	if err != nil {
		return "", fmt.Errorf("failed to parse %s template: %w", s.mode, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute %s template: %w", s.mode, err)
	}
	return buf.String(), nil
}

// run renders the script and executes it under forge.
//
// env carries request data the contract reads at runtime, which is how the
// transaction shapes stay compilable once per rule rather than once per
// request. The typed-data shapes bake their context into the source instead and
// pass nil.
func (e *SolidityRuleEvaluator) run(ctx context.Context, s solidityScript, env []string) (bool, string, error) {
	script, err := s.render()
	if err != nil {
		return false, "", fmt.Errorf("failed to generate %s script: %w", s.mode, err)
	}
	passed, reason, err := e.executeScript(ctx, script, env)
	if err != nil {
		return false, "", fmt.Errorf("script execution failed: %w", err)
	}
	return passed, reason, nil
}

// typedDataBindings is the EIP-712 context both typed-data shapes bind.
//
// ⚠️ These seven were spelled out twice, in two struct literals that had to
// agree field for field. They describe what the signer is being asked to sign;
// a mismatch between the two would let one shape check a domain the other did
// not.
func typedDataBindings(req *types.SignRequest, typedData *TypedDataPayload) map[string]string {
	return map[string]string{
		"PrimaryType":    formatString(typedData.PrimaryType),
		"DomainName":     formatString(typedData.Domain.Name),
		"DomainVersion":  formatString(typedData.Domain.Version),
		"DomainChainId":  formatDomainChainId(typedData.Domain.ChainId),
		"DomainContract": formatDomainContract(typedData.Domain.VerifyingContract),
		"Signer":         formatAddress(&req.SignerAddress),
		"ChainID":        formatChainID(req.ChainID),
	}
}

// expressionScript and functionsScript build the two transaction-context shapes.
//
// Both take no request: the script compiles from the rule alone and reads the
// request from env at run time, so a rule compiles once instead of once per
// signing request. The two typed-data shapes cannot do that — an EIP-712
// domain has to be baked in — and so take a request and live beside the typed
// data code.
func expressionScript(expression string, inMaps map[string][]string) solidityScript {
	return solidityScript{mode: "expression", template: solidityExpressionTemplate, body: expression, inMaps: inMaps}
}

func functionsScript(functions string, inMaps map[string][]string) solidityScript {
	return solidityScript{mode: "functions", template: solidityFunctionTemplate, body: functions, inMaps: inMaps}
}
