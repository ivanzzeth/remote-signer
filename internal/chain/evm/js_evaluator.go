package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/grafana/sobek"

	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

const (
	jsRuleTimeout       = 20 * time.Millisecond
	jsRuleMaxReasonLen  = 120
	jsRuleMaxAllocBytes = 32 * 1024 * 1024 // 32MB max allocation growth per evaluation
)

// trimConfigStrings returns a copy of config with all string values trimmed so rules can use config.xxx directly.
func trimConfigStrings(config map[string]interface{}) map[string]interface{} {
	if config == nil {
		return nil
	}
	out := make(map[string]interface{}, len(config))
	for k, v := range config {
		out[k] = trimConfigValue(v)
	}
	return out
}

func trimConfigValue(v interface{}) interface{} {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case map[string]interface{}:
		return trimConfigStrings(x)
	case []interface{}:
		a := make([]interface{}, len(x))
		for i, e := range x {
			a[i] = trimConfigValue(e)
		}
		return a
	default:
		return v
	}
}

// JSRuleEvaluator evaluates evm_js rules in-process via Sobek.
type JSRuleEvaluator struct {
	logger        *slog.Logger
	rpcProvider   *RPCProvider
	metadataCache *TokenMetadataCache
}

// NewJSRuleEvaluator creates a new JS rule evaluator.
func NewJSRuleEvaluator(logger *slog.Logger) (*JSRuleEvaluator, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &JSRuleEvaluator{logger: logger}, nil
}

// SetRPCProvider configures the RPC provider and token metadata cache for read-only
// on-chain queries from JS rules (web3.call, erc20.decimals, etc.).
func (e *JSRuleEvaluator) SetRPCProvider(provider *RPCProvider, cache *TokenMetadataCache) {
	e.rpcProvider = provider
	e.metadataCache = cache
}

// buildRPCContext creates an RPCInjectionContext for a given chain ID, or nil if RPC is not configured.
// SECURITY: chainID is validated as a positive numeric integer to prevent SSRF via path injection.
func (e *JSRuleEvaluator) buildRPCContext(ctx context.Context, chainID string) *RPCInjectionContext {
	if e.rpcProvider == nil {
		return nil
	}
	if err := ValidateChainID(chainID); err != nil {
		e.logger.Warn("invalid chain_id for RPC context, disabling RPC for this evaluation", "chain_id", chainID, "error", err)
		return nil
	}
	return &RPCInjectionContext{
		ChainID:  chainID,
		Provider: e.rpcProvider,
		Cache:    e.metadataCache,
		Counter:  NewRPCCallCounter(rpcMaxCallsPerEval),
		Ctx:      ctx,
	}
}

// Type returns the rule type this evaluator handles.
func (e *JSRuleEvaluator) Type() types.RuleType {
	return types.RuleTypeEVMJS
}

// AppliesToSignType returns true if the rule applies to the given sign type.
// Uses optional sign_type_filter from config; if empty, applies to all.
//
// Only evm_js rules support comma-separated sign_type_filter (e.g. "typed_data,transaction").
// Other rule types (evm_solidity_expression, message_pattern, etc.) use a single value only.
func (e *JSRuleEvaluator) AppliesToSignType(r *types.Rule, signType string) bool {
	var cfg JSRuleConfig
	if err := json.Unmarshal(r.Config, &cfg); err != nil {
		return true
	}
	raw := strings.TrimSpace(strings.ToLower(cfg.SignTypeFilter))
	if raw == "" {
		return true
	}
	st := strings.ToLower(signType)
	// evm_js only: support comma-separated list (e.g. "typed_data,transaction")
	for _, part := range strings.Split(raw, ",") {
		filter := strings.TrimSpace(part)
		if filter == "" {
			continue
		}
		switch filter {
		case "transaction":
			if st == "transaction" {
				return true
			}
		case "typed_data":
			if st == "typed_data" {
				return true
			}
		case "personal", "personal_sign", "eip191":
			if st == "personal" || st == "eip191" {
				return true
			}
		default:
			if st == filter {
				return true
			}
		}
	}
	return false
}

// Evaluate runs the rule's JS validate(input) and maps result to (matched, reason, error).
// Supports both whitelist and blocklist modes: whitelist returns (true, reason, nil) when script
// passes (allow); blocklist returns (true, reason, nil) when script fails (violation → block).
func (e *JSRuleEvaluator) Evaluate(ctx context.Context, r *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
	ruleInput, err := BuildRuleInput(req, parsed)
	if err != nil {
		if err == ErrFromNotDerivable {
			e.logger.Warn("from address not derivable for evm_js rule", "rule_id", r.ID, "request_id", req.ID)
			return false, "", fmt.Errorf("from address not derivable")
		}
		return false, "", err
	}

	var cfg JSRuleConfig
	if err := json.Unmarshal(r.Config, &cfg); err != nil {
		return false, "", fmt.Errorf("invalid evm_js config: %w", err)
	}
	if cfg.Script == "" {
		return false, "", fmt.Errorf("evm_js rule script is empty")
	}

	configObj := make(map[string]interface{})
	if r.Variables != nil {
		if err := json.Unmarshal(r.Variables, &configObj); err != nil {
			return false, "", fmt.Errorf("invalid rule variables JSON: %w", err)
		}
	}

	rpcCtx := e.buildRPCContext(ctx, req.ChainID)
	result := e.wrappedValidate(cfg.Script, ruleInput, configObj, rpcCtx)

	if !result.Valid {
		if r.Mode == types.RuleModeBlocklist {
			return true, result.Reason, nil
		}
		return false, result.Reason, nil
	}

	// valid=true
	if r.Mode == types.RuleModeBlocklist {
		return false, "", nil
	}
	return true, result.Reason, nil
}

// EvaluateWithDelegation implements EvaluatorWithDelegation. Runs the script once; when valid and
// delegate_to is set and payload is present, returns a DelegationRequest for the engine to resolve.
func (e *JSRuleEvaluator) EvaluateWithDelegation(ctx context.Context, r *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, *rule.DelegationRequest, error) {
	ruleInput, err := BuildRuleInput(req, parsed)
	if err != nil {
		if err == ErrFromNotDerivable {
			e.logger.Warn("from address not derivable for evm_js rule", "rule_id", r.ID, "request_id", req.ID)
			return false, "", nil, fmt.Errorf("from address not derivable")
		}
		return false, "", nil, err
	}

	var cfg JSRuleConfig
	if err := json.Unmarshal(r.Config, &cfg); err != nil {
		return false, "", nil, fmt.Errorf("invalid evm_js config: %w", err)
	}
	if cfg.Script == "" {
		return false, "", nil, fmt.Errorf("evm_js rule script is empty")
	}

	configObj := make(map[string]interface{})
	if r.Variables != nil {
		if err := json.Unmarshal(r.Variables, &configObj); err != nil {
			return false, "", nil, fmt.Errorf("invalid rule variables JSON: %w", err)
		}
	}

	rpcCtx := e.buildRPCContext(ctx, req.ChainID)
	result := e.wrappedValidate(cfg.Script, ruleInput, configObj, rpcCtx)

	if !result.Valid {
		if r.Mode == types.RuleModeBlocklist {
			return true, result.Reason, nil, nil
		}
		return false, result.Reason, nil, nil
	}
	if r.Mode == types.RuleModeBlocklist {
		return false, "", nil, nil
	}

	// Whitelist matched (valid=true). Optionally delegate.
	targetRuleID := result.DelegateTo
	if targetRuleID == "" {
		targetRuleID = strings.TrimSpace(cfg.DelegateTo)
	}
	// Treat unsubstituted template placeholders as no delegation
	if targetRuleID != "" && strings.HasPrefix(targetRuleID, "${") {
		targetRuleID = ""
	}
	if targetRuleID == "" || result.Payload == nil {
		return true, result.Reason, nil, nil
	}

	// Support multiple targets: comma-separated rule IDs; engine tries each until one allows
	targetRuleIDs := parseDelegateToIDs(targetRuleID)
	if len(targetRuleIDs) == 0 {
		return true, result.Reason, nil, nil
	}

	mode := strings.TrimSpace(cfg.DelegateMode)
	if mode == "" || strings.HasPrefix(mode, "${") {
		mode = "single"
	}
	itemsKey := strings.TrimSpace(cfg.ItemsKey)
	if mode == "per_item" && itemsKey == "" {
		itemsKey = "items"
	}
	if mode == "per_item" {
		sl, ok := result.Payload.(map[string]interface{})
		if !ok {
			return true, result.Reason, nil, nil
		}
		raw, ok := sl[itemsKey]
		if !ok {
			return true, result.Reason, nil, nil
		}
		arr, ok := raw.([]interface{})
		if !ok || len(arr) > rule.DelegationMaxItems {
			return true, result.Reason, nil, nil
		}
	}

	return true, result.Reason, &rule.DelegationRequest{
		TargetRuleIDs: targetRuleIDs,
		Mode:          mode,
		Payload:       result.Payload,
		ItemsKey:      itemsKey,
		PayloadKey:    strings.TrimSpace(cfg.PayloadKey),
	}, nil
}

// parseDelegateToIDs splits delegate_to by comma and returns non-empty trimmed rule IDs.
func parseDelegateToIDs(delegateTo string) []types.RuleID {
	var ids []types.RuleID
	for _, s := range strings.Split(delegateTo, ",") {
		t := strings.TrimSpace(s)
		if t != "" && !strings.HasPrefix(t, "${") {
			ids = append(ids, types.RuleID(t))
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return ids
}

// ValidateWithInput runs the rule script with the given input and config, returns the sanitized result.
// Used by JSRuleValidator to run test cases.
func (e *JSRuleEvaluator) ValidateWithInput(script string, input *RuleInput, config map[string]interface{}) JSRuleValidateResult {
	return e.wrappedValidate(script, input, config, nil)
}

// EvaluateBudget runs the rule script's validateBudget(input) and returns the spend amount for budget metering.
// Used when template budget_metering.method is "js". Returns (nil, error) on any failure (fail-closed).
// Supports both plain BigInt return (backward compat) and {amount, unit} object for dynamic budget.
func (e *JSRuleEvaluator) EvaluateBudget(ctx context.Context, r *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (*types.BudgetResult, error) {
	ruleInput, err := BuildRuleInput(req, parsed)
	if err != nil {
		return nil, fmt.Errorf("build rule input: %w", err)
	}
	var cfg JSRuleConfig
	if err := json.Unmarshal(r.Config, &cfg); err != nil {
		return nil, fmt.Errorf("invalid evm_js config: %w", err)
	}
	if cfg.Script == "" {
		return nil, fmt.Errorf("evm_js rule script is empty")
	}
	configObj := make(map[string]interface{})
	if r.Variables != nil {
		if err := json.Unmarshal(r.Variables, &configObj); err != nil {
			return nil, fmt.Errorf("invalid rule variables JSON: %w", err)
		}
	}
	rpcCtx := e.buildRPCContext(ctx, req.ChainID)
	return e.wrappedValidateBudget(cfg.Script, ruleInput, configObj, rpcCtx)
}

// EvaluateBudgetWithInput runs validateBudget(input) with the given input and rule config.
// Used by JSRuleValidator to assert expect_budget_amount in test cases.
func (e *JSRuleEvaluator) EvaluateBudgetWithInput(ctx context.Context, r *types.Rule, input *RuleInput) (*types.BudgetResult, error) {
	var cfg JSRuleConfig
	if err := json.Unmarshal(r.Config, &cfg); err != nil {
		return nil, fmt.Errorf("invalid evm_js config: %w", err)
	}
	if cfg.Script == "" {
		return nil, fmt.Errorf("evm_js rule script is empty")
	}
	configObj := make(map[string]interface{})
	if r.Variables != nil {
		if err := json.Unmarshal(r.Variables, &configObj); err != nil {
			return nil, fmt.Errorf("invalid rule variables JSON: %w", err)
		}
	}
	return e.wrappedValidateBudget(cfg.Script, input, configObj, nil)
}

// wrappedValidateBudget runs script in a sandbox, calls validateBudget(input), and returns BudgetResult.
// Supports both plain BigInt return (backward compat, Unit="") and {amount, unit} object (dynamic budget).
// Missing validateBudget or return 0n → amount=0. Error or invalid return type → fail-closed (error).
func (e *JSRuleEvaluator) wrappedValidateBudget(script string, input *RuleInput, config map[string]interface{}, rpcCtx *RPCInjectionContext) (*types.BudgetResult, error) {
	vm := sobek.New()
	defer vm.ClearInterrupt()

	inputMap, mapErr := ruleInputToMap(input)
	if mapErr != nil {
		return nil, fmt.Errorf("rule input: %w", mapErr)
	}
	inputVal := vm.ToValue(inputMap)
	if err := vm.Set("input", inputVal); err != nil {
		return nil, fmt.Errorf("set input: %w", err)
	}
	configVal := vm.ToValue(trimConfigStrings(config))
	if err := vm.Set("config", configVal); err != nil {
		return nil, fmt.Errorf("set config: %w", err)
	}
	if err := injectHelpers(vm); err != nil {
		return nil, fmt.Errorf("inject helpers: %w", err)
	}
	if err := injectRPCHelpers(vm, rpcCtx); err != nil {
		return nil, fmt.Errorf("inject rpc helpers: %w", err)
	}
	if err := removeGlobals(vm); err != nil {
		return nil, fmt.Errorf("remove globals: %w", err)
	}

	// Timeout and memory guard (same as wrappedValidate — pausable timer for pure JS execution).
	// Note: Memory monitoring uses process-wide runtime.ReadMemStats, not per-VM tracking.
	// Under concurrent JS evaluations, allocation growth may be attributed to the wrong VM.
	// This provides defense-in-depth rather than precise per-evaluation enforcement.
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)
	done := make(chan struct{})
	defer close(done)
	jsTimer := newPausableTimer(vm, jsRuleTimeout)
	defer jsTimer.Stop()
	if rpcCtx != nil {
		rpcCtx.Timer = jsTimer
	}
	go func() {
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				if m.TotalAlloc-memBefore.TotalAlloc > jsRuleMaxAllocBytes {
					vm.Interrupt("memory_limit_exceeded")
					return
				}
			}
		}
	}()

	if _, err := vm.RunString(script); err != nil {
		return nil, fmt.Errorf("script run: %w", err)
	}

	validateBudgetVal := vm.Get("validateBudget")
	if validateBudgetVal == nil || isUndefined(validateBudgetVal) {
		return &types.BudgetResult{Amount: big.NewInt(0)}, nil
	}
	fn, ok := sobek.AssertFunction(validateBudgetVal)
	if !ok {
		return nil, fmt.Errorf("validateBudget is not a function")
	}

	var res sobek.Value
	var callErr error
	func() {
		defer func() {
			if v := recover(); v != nil {
				callErr = fmt.Errorf("%v", v)
			}
		}()
		res, callErr = fn(sobek.Undefined(), inputVal)
	}()
	if callErr != nil {
		return nil, fmt.Errorf("validateBudget: %w", callErr)
	}
	if res == nil || isUndefined(res) {
		return &types.BudgetResult{Amount: big.NewInt(0)}, nil
	}

	exported := res.Export()

	// Check for {amount, unit} object (dynamic budget)
	if obj, ok := exported.(map[string]interface{}); ok {
		return parseBudgetResultObject(obj)
	}

	// Plain BigInt / number / string (backward compatible, no dynamic unit)
	amount, err := exportedToBigInt(exported)
	if err != nil {
		return nil, fmt.Errorf("validateBudget: %w", err)
	}
	return &types.BudgetResult{Amount: amount}, nil
}

// parseBudgetResultObject parses a {amount, unit} JS object into BudgetResult.
func parseBudgetResultObject(obj map[string]interface{}) (*types.BudgetResult, error) {
	amountRaw, ok := obj["amount"]
	if !ok {
		return nil, fmt.Errorf("validateBudget returned object without 'amount' field")
	}
	amount, err := exportedToBigInt(amountRaw)
	if err != nil {
		return nil, fmt.Errorf("validateBudget amount: %w", err)
	}

	unit, _ := obj["unit"].(string)
	if unit == "" {
		return nil, fmt.Errorf("validateBudget returned object with empty 'unit' field")
	}

	return &types.BudgetResult{Amount: amount, Unit: unit}, nil
}

// exportedToBigInt converts a Sobek-exported value (int64, uint64, string, *big.Int) to *big.Int.
func exportedToBigInt(exported interface{}) (*big.Int, error) {
	switch v := exported.(type) {
	case int64:
		if v < 0 {
			return nil, fmt.Errorf("negative amount: %d", v)
		}
		return big.NewInt(v), nil
	case int:
		if v < 0 {
			return nil, fmt.Errorf("negative amount: %d", v)
		}
		return big.NewInt(int64(v)), nil
	case uint64:
		return new(big.Int).SetUint64(v), nil
	case string:
		z := new(big.Int)
		if _, ok := z.SetString(strings.TrimSpace(v), 10); !ok {
			return nil, fmt.Errorf("invalid decimal string: %q", v)
		}
		if z.Sign() < 0 {
			return nil, fmt.Errorf("negative amount")
		}
		return z, nil
	default:
		if bi, ok := exported.(*big.Int); ok {
			if bi.Sign() < 0 {
				return nil, fmt.Errorf("negative amount")
			}
			return new(big.Int).Set(bi), nil
		}
		return nil, fmt.Errorf("unsupported type %T (use bigint or decimal string)", exported)
	}
}

// wrappedValidate runs script in a sandbox, calls validate(input), and returns sanitized result.
func (e *JSRuleEvaluator) wrappedValidate(script string, input *RuleInput, config map[string]interface{}, rpcCtx *RPCInjectionContext) JSRuleValidateResult {
	vm := sobek.New()
	defer vm.ClearInterrupt()

	// Allow-list globals: input, config, helpers. Inject then remove dangerous ones.
	inputMap, mapErr := ruleInputToMap(input)
	if mapErr != nil {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("script_error", mapErr.Error(), false)}
	}
	inputVal := vm.ToValue(inputMap)
	if err := vm.Set("input", inputVal); err != nil {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("script_error", err.Error(), false)}
	}
	configVal := vm.ToValue(trimConfigStrings(config))
	if err := vm.Set("config", configVal); err != nil {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("script_error", err.Error(), false)}
	}
	if err := injectHelpers(vm); err != nil {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("script_error", err.Error(), false)}
	}
	if err := injectRPCHelpers(vm, rpcCtx); err != nil {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("script_error", err.Error(), false)}
	}

	// Remove dangerous globals (§11.7)
	if err := removeGlobals(vm); err != nil {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("script_error", err.Error(), false)}
	}

	// Timeout and memory guard. The pausable timer interrupts the VM after jsRuleTimeout
	// of pure JS execution time. The timer pauses during Go-side RPC callbacks so that
	// network I/O does not consume the JS execution budget.
	// The memory monitor polls allocations and interrupts if growth exceeds jsRuleMaxAllocBytes.
	// Note: Memory monitoring uses process-wide runtime.ReadMemStats, not per-VM tracking.
	// Under concurrent JS evaluations, allocation growth may be attributed to the wrong VM.
	// This provides defense-in-depth rather than precise per-evaluation enforcement.
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)
	done := make(chan struct{})
	defer close(done)
	jsTimer := newPausableTimer(vm, jsRuleTimeout)
	defer jsTimer.Stop()
	if rpcCtx != nil {
		rpcCtx.Timer = jsTimer
	}
	go func() {
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				if m.TotalAlloc-memBefore.TotalAlloc > jsRuleMaxAllocBytes {
					vm.Interrupt("memory_limit_exceeded")
					return
				}
			}
		}
	}()
	_, err := vm.RunString(script)
	if err != nil {
		reason := "script_error"
		errMsg := err.Error()
		if strings.Contains(errMsg, "memory_limit_exceeded") {
			reason = "memory_limit_exceeded"
		} else if strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "Interrupt") {
			reason = "timeout"
		}
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason(reason, errMsg, false)}
	}

	validateVal := vm.Get("validate")
	if validateVal == nil || isUndefined(validateVal) {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("script_error", "validate is not defined", false)}
	}
	fn, ok := sobek.AssertFunction(validateVal)
	if !ok {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("script_error", "validate is not a function", false)}
	}

	var res sobek.Value
	var callErr error
	var panicErr error
	func() {
		defer func() {
			if v := recover(); v != nil {
				panicErr = fmt.Errorf("%v", v)
			}
		}()
		res, callErr = fn(sobek.Undefined(), inputVal)
	}()
	if err := panicErr; err != nil {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("", extractJSExceptionMessage(err.Error()), true)}
	}
	if err := callErr; err != nil {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("", extractJSExceptionMessage(err.Error()), true)}
	}

	if res == nil || isUndefined(res) {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("invalid_shape", "invalid return shape", false)}
	}

	obj, ok := res.Export().(map[string]interface{})
	if !ok {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("invalid_shape", "invalid return shape", false)}
	}

	valid, _ := obj["valid"].(bool)
	reason, _ := obj["reason"].(string)
	// Script may return reason as non-string (e.g. number/undefined); type assertion then gives "".
	// Ensure we always have a loggable reason when valid=false so we can locate the issue.
	if !valid && strings.TrimSpace(reason) == "" {
		reason = "script returned valid=false with empty reason"
	}
	payload := obj["payload"]
	delegateTo := ""
	if s, ok := obj["delegate_to"].(string); ok && strings.TrimSpace(s) != "" {
		delegateTo = strings.TrimSpace(s)
	}
	return JSRuleValidateResult{
		Valid:      valid,
		Reason:     sanitizeReason("", reason, true),
		Payload:    payload,
		DelegateTo: delegateTo,
	}
}

// extractJSExceptionMessage extracts the message from a Sobek/Goja error string like "Error: message at revert (...)".
// Returns the original string if it doesn't match that pattern.
func extractJSExceptionMessage(s string) string {
	const prefix = "Error: "
	if !strings.HasPrefix(s, prefix) {
		return s
	}
	rest := s[len(prefix):]
	if idx := strings.Index(rest, " at "); idx >= 0 {
		return strings.TrimSpace(rest[:idx])
	}
	return rest
}

func removeGlobals(vm *sobek.Runtime) error {
	// SECURITY: Remove dangerous globals to prevent code execution, data exfiltration,
	// and DoS attacks within the JS sandbox. Per spec §11.7: allow-list only.
	for _, name := range []string{
		"eval", "Function", "Date", "console", "global", "globalThis",
		// require: our rule primitive require(cond, reason), do not remove
		// Network APIs — prevent data exfiltration of rule logic / signing inputs
		"fetch", "XMLHttpRequest", "WebSocket",
		// Timer APIs — prevent queued callback abuse
		"setTimeout", "setInterval", "clearTimeout", "clearInterval",
		// Reflection/proxy — prevent introspection of VM internals
		"Reflect", "Proxy",
	} {
		if err := vm.Set(name, sobek.Undefined()); err != nil {
			return err
		}
	}

	// SECURITY: Poison Function.prototype.constructor to prevent sandbox escape via
	// (function(){}).constructor("return malicious_code")() — merely setting Function
	// to undefined is NOT enough since the constructor is still on the prototype chain.
	// Also freeze GeneratorFunction constructor via the same pattern.
	if _, err := vm.RunString(`
		(function(){
			var noop = function(){throw new Error("Function constructor is disabled");};
			var FP = (function(){}).constructor.prototype;
			Object.defineProperty(FP, "constructor", {value: noop, writable: false, configurable: false});
			try {
				var GP = (function*(){}).constructor.prototype;
				Object.defineProperty(GP, "constructor", {value: noop, writable: false, configurable: false});
			} catch(e) {}
		})();
	`); err != nil {
		return err
	}

	// Sobek doesn't expose Delete on runtime; Set(name, Undefined()) effectively hides
	return trySetUndefined(vm, "Math", "random")
}

func trySetUndefined(vm *sobek.Runtime, top, key string) error {
	mathVal := vm.Get(top)
	if mathVal == nil {
		return nil
	}
	if o := mathVal.ToObject(vm); o != nil {
		return o.Set(key, sobek.Undefined())
	}
	return nil
}

// sanitizeReason: when code is set (e.g. script_error), include detail so logs can identify the actual error
// (e.g. "script_error: fail() requires a non-empty reason" vs "script_error: TypeError: ...").
// Truncates to jsRuleMaxReasonLen, strips control chars, escapes newlines.
func sanitizeReason(code, detail string, isReason bool) string {
	if detail == "" {
		if code != "" {
			return code
		}
		if isReason {
			return ""
		}
		return "script_error"
	}
	// Sanitize detail for safe logging
	s := detail
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' {
			continue
		}
		if r == '\n' {
			b.WriteString("\\n")
			continue
		}
		b.WriteRune(r)
	}
	s = b.String()
	if len(s) > jsRuleMaxReasonLen {
		s = s[:jsRuleMaxReasonLen]
	}
	if code != "" && !isReason {
		return code + ": " + s
	}
	return s
}

// isUndefined returns true if v is nil or the undefined value.
func isUndefined(v sobek.Value) bool {
	if v == nil {
		return true
	}
	return v.Equals(sobek.Undefined())
}

var _ rule.RuleEvaluator = (*JSRuleEvaluator)(nil)
var _ rule.SignTypeApplicable = (*JSRuleEvaluator)(nil)
var _ rule.EvaluatorWithDelegation = (*JSRuleEvaluator)(nil)
