# in() Operator → Mapping Design

## Goal
Replace the current "expand in(expr, a, b, c) to (expr == a || expr == b || ...)" with O(1) lookup via a generated mapping. Rule authors keep writing `in(expr, arrayVarName)`; the second argument is the **name** of an array variable whose values are supplied in config.

## Syntax (unchanged for authors)
- `in(expr, arrayVarName)` — two arguments: expression to check (e.g. `txTo`, `eip712_domainContract`) and the **identifier** of an array variable.
- Generated code: `arrayVarName_mapping[expr]` with a `mapping(address => bool)` filled in constructor.

## Config
- **SolidityExpressionConfig** gains `InMappingArrays map[string][]string` (`in_mapping_arrays` in JSON). Keys are array variable names; values are address lists (e.g. from template variables).

## Template expansion
- In rule body, keep the identifier in `in()`: `in(txTo, allowed_safe_addresses)` (no `${}` inside the call).
- Substitution: replace `in(expr, ${var})` → `in(expr, var)` so the body keeps the var name; then set `InMappingArrays[var] = parseAddressList(variables[var])` when building the rule config.
- Template YAML can keep writing `in(txTo, ${allowed_safe_addresses})`; the expand step will turn it into `in(txTo, allowed_safe_addresses)` and fill `InMappingArrays["allowed_safe_addresses"]` from the template variable value.

## Code generation
1. Parse body for `in(expr, varName)` (second arg = single identifier). Only replace when `InMappingArrays[varName]` is present.
2. For each such varName: emit `mapping(address => bool) private varName_mapping;` and in constructor `varName_mapping[addr] = true;` for each address.
3. Replace `in(expr, varName)` with `varName_mapping[expr]`.
4. Inject declarations and constructor init into existing contract templates (placeholders `InMappingDeclarations`, `InMappingConstructorInit`).
5. Backward compat: any remaining `in(expr, a, b, c)` (literal list) after the above is still expanded by the existing `preprocessInOperator` so old configs keep working.

## Files to change
- `internal/chain/evm/types.go`: add `InMappingArrays`
- `internal/chain/evm/solidity_evaluator.go`: add `processInOperatorToMappings`, use it + inject into templates; keep `preprocessInOperator` for remaining in()
- `internal/config/template_init.go`: substitute `in(..., ${var})` → `in(..., var)` and fill `InMappingArrays` per rule
- Template YAML: can keep `in(txTo, ${allowed_safe_addresses})` (expand step rewrites and fills arrays)
