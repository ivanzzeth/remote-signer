package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"

	"github.com/grafana/sobek"

	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

const (
	jsRuleTimeout      = 20 * time.Millisecond
	jsRuleMaxReasonLen = 120
)

// JSRuleEvaluator evaluates evm_js rules in-process via Sobek.
type JSRuleEvaluator struct {
	logger *slog.Logger
}

// NewJSRuleEvaluator creates a new JS rule evaluator.
func NewJSRuleEvaluator(logger *slog.Logger) (*JSRuleEvaluator, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &JSRuleEvaluator{logger: logger}, nil
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
			configObj = nil
		}
	}

	result := e.wrappedValidate(cfg.Script, ruleInput, configObj)

	if !result.Valid {
		// For blocklist: "violated" when valid=false. For whitelist: "matched" when valid=true.
		// So we return matched = result.Valid (whitelist matches when valid; blocklist "violated" when !valid).
		// Engine interprets: blocklist wants (true = block), whitelist wants (true = allow).
		// So for blocklist we need to return (true, reason) when valid=false → block.
		// For whitelist we need to return (true, reason) when valid=true → allow.
		// So matched = result.Valid is correct: when valid, we return (true, ...) = allow/match; when invalid, (false, ...) = no match / blocklist will not "fire" from this rule's perspective... Wait, for blocklist the engine does: if matched then block. So "matched" for blocklist means "rule fires = block". So when valid=false we want to BLOCK, so we want "matched"=true for blocklist. So for blocklist: matched = !result.Valid. For whitelist: matched = result.Valid. So we need to return different things based on mode!
		// Re-read engine: for blocklist, evaluator.Evaluate returns (violated, reason, err). If violated true → block. So our "matched" for blocklist is "violated". So we return (true, reason) when we want to block = when valid=false. So matched = !result.Valid for blocklist, matched = result.Valid for whitelist.
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
			configObj = nil
		}
	}

	result := e.wrappedValidate(cfg.Script, ruleInput, configObj)

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
	return e.wrappedValidate(script, input, config)
}

// wrappedValidate runs script in a sandbox, calls validate(input), and returns sanitized result.
func (e *JSRuleEvaluator) wrappedValidate(script string, input *RuleInput, config map[string]interface{}) JSRuleValidateResult {
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
	configVal := vm.ToValue(config)
	if err := vm.Set("config", configVal); err != nil {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("script_error", err.Error(), false)}
	}
	if err := injectHelpers(vm); err != nil {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("script_error", err.Error(), false)}
	}

	// Remove dangerous globals (§11.7)
	if err := removeGlobals(vm); err != nil {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("script_error", err.Error(), false)}
	}

	// Timeout (must be after script run for first run; interrupt only affects next RunString/call)
	time.AfterFunc(jsRuleTimeout, func() { vm.Interrupt("timeout") })
	_, err := vm.RunString(script)
	if err != nil {
		reason := "script_error"
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "Interrupt") {
			reason = "timeout"
		}
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason(reason, err.Error(), false)}
	}

	validateVal := vm.Get("validate")
	if validateVal == nil || isUndefined(validateVal) {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("script_error", "validate is not defined", false)}
	}
	fn, ok := sobek.AssertFunction(validateVal)
	if !ok {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("script_error", "validate is not a function", false)}
	}

	res, err := fn(sobek.Undefined(), inputVal)
	if err != nil {
		return JSRuleValidateResult{Valid: false, Reason: sanitizeReason("script_error", err.Error(), false)}
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

func removeGlobals(vm *sobek.Runtime) error {
	for _, name := range []string{"eval", "Function", "Date", "console", "require", "global", "globalThis"} {
		if err := vm.Set(name, sobek.Undefined()); err != nil {
			return err
		}
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

// sanitizeReason: production uses fixed codes; debug truncates 120 chars, strips control chars, escapes \n.
func sanitizeReason(code, detail string, isReason bool) string {
	if code != "" && !isReason {
		return code
	}
	if detail == "" {
		if code != "" {
			return code
		}
		if isReason {
			return ""
		}
		return "script_error"
	}
	// Debug-style: truncate, strip control, escape newlines
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
