package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// TemplateHandler handles template management and instance creation endpoints
type TemplateHandler struct {
	templateRepo      storage.TemplateRepository
	templateService   *service.TemplateService
	jsEvaluator       *evm.JSRuleEvaluator
	solidityValidator *evm.SolidityRuleValidator
	readOnly          bool // when true, block all template mutations via API
	logger            *slog.Logger
	requireApproval   bool
	apiKeyRepo        storage.APIKeyRepository
}

// TemplateHandlerOption is a functional option for TemplateHandler.
type TemplateHandlerOption func(*TemplateHandler)

// WithTemplateRequireApproval enables admin approval for agent whitelist rules created via template instantiation.
func WithTemplateRequireApproval(v bool) TemplateHandlerOption {
	return func(h *TemplateHandler) {
		h.requireApproval = v
	}
}

// WithTemplateAPIKeyRepo sets the API key repository for applied_to validation.
func WithTemplateAPIKeyRepo(repo storage.APIKeyRepository) TemplateHandlerOption {
	return func(h *TemplateHandler) {
		h.apiKeyRepo = repo
	}
}

// WithTemplateJSEvaluator sets the JS rule evaluator for template test case validation.
func WithTemplateJSEvaluator(eval *evm.JSRuleEvaluator) TemplateHandlerOption {
	return func(h *TemplateHandler) {
		h.jsEvaluator = eval
	}
}

// WithTemplateSolidityValidator sets the Solidity rule validator for template instantiation gating.
func WithTemplateSolidityValidator(v *evm.SolidityRuleValidator) TemplateHandlerOption {
	return func(h *TemplateHandler) {
		h.solidityValidator = v
	}
}

// NewTemplateHandler creates a new template handler
func NewTemplateHandler(
	templateRepo storage.TemplateRepository,
	templateService *service.TemplateService,
	logger *slog.Logger,
	readOnly bool,
	opts ...TemplateHandlerOption,
) (*TemplateHandler, error) {
	if templateRepo == nil {
		return nil, fmt.Errorf("template repository is required")
	}
	if templateService == nil {
		return nil, fmt.Errorf("template service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	h := &TemplateHandler{
		templateRepo:    templateRepo,
		templateService: templateService,
		readOnly:        readOnly,
		logger:          logger,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h, nil
}

// ServeHTTP handles /api/v1/templates and /api/v1/templates/{id}
func (h *TemplateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get API key from context (for audit)
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Path: /api/v1/templates or /api/v1/templates/{id} or /api/v1/templates/{id}/instantiate.
	// EscapedPath instead of Path so file-stem IDs containing '/'
	// (v0.3 Registry: "evm/erc20") round-trip through the SDK's
	// encodeURIComponent unchanged.
	rawPath := strings.TrimPrefix(r.URL.EscapedPath(), "/api/v1/templates")
	rawPath = strings.TrimPrefix(rawPath, "/")

	if rawPath == "" {
		switch r.Method {
		case http.MethodGet:
			h.listTemplates(w, r)
		case http.MethodPost:
			h.createTemplate(w, r)
		default:
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	encodedID := rawPath
	sub := ""
	if strings.HasSuffix(rawPath, "/instantiate") {
		encodedID = strings.TrimSuffix(rawPath, "/instantiate")
		sub = "instantiate"
	}
	if strings.HasSuffix(rawPath, "/validate") {
		encodedID = strings.TrimSuffix(rawPath, "/validate")
		sub = "validate"
	}
	templateID, err := url.PathUnescape(encodedID)
	if err != nil {
		h.writeError(w, "invalid template id", http.StatusBadRequest)
		return
	}

	if sub == "instantiate" {
		if r.Method == http.MethodPost {
			h.instantiateTemplate(w, r, templateID)
		} else {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	if sub == "validate" {
		if r.Method != http.MethodPost {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Validate is admin-only (RBAC via role check)
		if !apiKey.IsAdmin() {
			h.writeError(w, "forbidden: admin role required", http.StatusForbidden)
			return
		}
		h.validateTemplate(w, r, templateID)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getTemplate(w, r, templateID)
	case http.MethodDelete:
		h.deleteTemplate(w, r, templateID)
	case http.MethodPatch:
		h.updateTemplate(w, r, templateID)
	default:
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ServeInstanceHTTP handles /api/v1/templates/instances/{ruleID}/revoke
func (h *TemplateHandler) ServeInstanceHTTP(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Path: /api/v1/templates/instances/{ruleID}/revoke
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/templates/instances/")

	if strings.HasSuffix(path, "/revoke") {
		ruleID := strings.TrimSuffix(path, "/revoke")
		if r.Method == http.MethodPost {
			h.revokeInstance(w, r, ruleID)
		} else {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	h.writeError(w, "not found", http.StatusNotFound)
}

// validateTemplateResponse is the response for POST /api/v1/templates/{id}/validate.
type validateTemplateResponse struct {
	TemplateID   string                    `json:"template_id"`
	TemplateName string                    `json:"template_name"`
	Results      []*validateRuleResultItem `json:"results,omitempty"`
	Total        int                       `json:"total"`
	Passed       int                       `json:"passed"`
	Failed       int                       `json:"failed"`
}

// validateRuleResultItem is a single rule's validation result.
type validateRuleResultItem struct {
	RuleID   string `json:"rule_id,omitempty"`
	RuleName string `json:"rule_name"`
	Type     string `json:"type"`
	Mode     string `json:"mode"`
	Valid    bool   `json:"valid"`
	Error    string `json:"error,omitempty"`
}

// validateTemplate handles POST /api/v1/templates/{id}/validate.
// Loads the template, resolves test_variables, substitutes them into
// the template config, then runs each rule's test cases through the JS evaluator.
func (h *TemplateHandler) validateTemplate(w http.ResponseWriter, r *http.Request, templateID string) {
	tmpl, err := h.templateRepo.Get(r.Context(), templateID)
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "template not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to get template", "error", err, "template_id", templateID)
		h.writeError(w, "failed to get template", http.StatusInternalServerError)
		return
	}

	if h.jsEvaluator == nil {
		h.writeError(w, "JS evaluator not available", http.StatusServiceUnavailable)
		return
	}

	// Parse test_variables
	var testVars map[string]string
	if len(tmpl.TestVariables) > 0 {
		if err := json.Unmarshal(tmpl.TestVariables, &testVars); err != nil {
			h.logger.Error("failed to parse template test_variables", "error", err, "template_id", templateID)
			testVars = make(map[string]string)
		}
	}
	if testVars == nil {
		testVars = make(map[string]string)
	}

	// Resolve template variables with defaults + test_variables
	var varDefs []types.TemplateVariable
	if len(tmpl.Variables) > 0 {
		if err := json.Unmarshal(tmpl.Variables, &varDefs); err != nil {
			h.writeError(w, "failed to parse template variables", http.StatusInternalServerError)
			return
		}
	}
	resolvedVars := resolveTemplateDefaults(varDefs, testVars)

	// If the template has a chain_id in its type-level scope, inject it as a reserved variable
	// (test_variables should already include it, but be safe)
	if tmpl.ChainType == types.ChainTypeEVM && testVars["chain_id"] != "" {
		resolvedVars["chain_id"] = testVars["chain_id"]
	}

	if err := validateRequiredTemplateVars(varDefs, resolvedVars); err != nil {
		h.writeError(w, fmt.Sprintf("variable substitution failed: %s", err.Error()), http.StatusBadRequest)
		return
	}
	// Dry-run: ensure all ${var} placeholders in config resolve (without mutating config;
	// test case inputs are substituted per chain_id inside RunJSTestCases).
	//lint:ignore SA1019 R8 迁移未完成:SubstituteTyped 需要变量定义,语义也不同(带类型转换),
	// 而这里只要一次「占位符是否都能解析」的 dry-run。换过去要先确认 typed 版对
	// 未解析占位符的报错行为一致 —— 那是 R8 的范围,不是本次重构的。
	if _, err := service.SubstituteVariables(tmpl.Config, resolvedVars); err != nil {
		h.writeError(w, fmt.Sprintf("variable substitution failed: %s", err.Error()), http.StatusBadRequest)
		return
	}

	configForValidate := normalizeTemplateConfigForValidation(tmpl, tmpl.Config)
	if isUnrecognizedTemplateConfig(tmpl.Config) {
		h.writeJSON(w, validateTemplateResponse{
			TemplateID:   templateID,
			TemplateName: tmpl.Name,
			Results: []*validateRuleResultItem{{
				RuleName: tmpl.Name,
				Type:     string(tmpl.Type),
				Mode:     string(tmpl.Mode),
				Valid:    true,
				Error:    "non-evm_js template (config format not recognized)",
			}},
			Total:  1,
			Passed: 1,
			Failed: 0,
		}, http.StatusOK)
		return
	}

	results, allPassed := ValidateTemplateConfig(h.jsEvaluator, tmpl.Name, configForValidate, resolvedVars)
	totalPassed := 0
	totalFailed := 0
	for _, r := range results {
		if r.Valid {
			totalPassed++
		} else {
			totalFailed++
		}
	}
	_ = allPassed

	resp := validateTemplateResponse{
		TemplateID:   tmpl.ID,
		TemplateName: tmpl.Name,
		Results:      results,
		Total:        len(results),
		Passed:       totalPassed,
		Failed:       totalFailed,
	}
	h.writeJSON(w, resp, http.StatusOK)
}

// evmhandlerJSRuleTestCase mirrors evm.JSRuleTestCase for template validation.
type evmhandlerJSRuleTestCase struct {
	Name       string                 `json:"name"`
	Input      map[string]interface{} `json:"input"`
	Variables  map[string]string      `json:"variables,omitempty"`
	ExpectPass bool                   `json:"expect_pass"`
}

// runJSTestCase runs a single test case via the shared evm.RunJSTestCases path.
func runJSTestCase(eval *evm.JSRuleEvaluator, script string, cfgMap map[string]interface{}, tc evmhandlerJSRuleTestCase, mode types.RuleMode) struct {
	Name   string
	Passed bool
	Reason string
} {
	vars := cfgMapToStringVars(cfgMap)
	jsTC := evm.JSTestCase{
		Name:       tc.Name,
		Input:      tc.Input,
		Variables:  tc.Variables,
		ExpectPass: tc.ExpectPass,
	}
	results, _ := eval.RunJSTestCases(script, []evm.JSTestCase{jsTC}, evm.VarsEvalContext(vars))
	if len(results) == 0 {
		return struct {
			Name   string
			Passed bool
			Reason string
		}{Name: tc.Name, Passed: false, Reason: "no result"}
	}
	r := results[0]
	return struct {
		Name   string
		Passed bool
		Reason string
	}{Name: r.Name, Passed: r.Passed, Reason: r.Reason}
}

func cfgMapToStringVars(cfg map[string]interface{}) map[string]string {
	if cfg == nil {
		return nil
	}
	out := make(map[string]string, len(cfg))
	for k, v := range cfg {
		out[k] = fmt.Sprint(v)
	}
	return out
}

func handlerTestCasesToEVM(cases []evmhandlerJSRuleTestCase) []evm.JSTestCase {
	out := make([]evm.JSTestCase, len(cases))
	for i, tc := range cases {
		out[i] = evm.JSTestCase{
			Name:       tc.Name,
			Input:      tc.Input,
			Variables:  tc.Variables,
			ExpectPass: tc.ExpectPass,
		}
	}
	return out
}

// normalizeTemplateConfigForValidation wraps flat template configs as a rules bundle.
func normalizeTemplateConfigForValidation(tmpl *types.RuleTemplate, rawConfig []byte) []byte {
	var configDoc struct {
		Rules []json.RawMessage `json:"rules"`
	}
	if json.Unmarshal(rawConfig, &configDoc) == nil && len(configDoc.Rules) > 0 {
		return rawConfig
	}
	// ⚠️ 「**没有** rules 键」才是 flat 模板;「rules 键在、但是空数组」已经是
	// bundle 形态,只是没有规则 —— 不许包装。
	// 包装它的后果:`{"rules":[]}` 被裹成一条以整个 config 为 config 的合成规则,
	// 于是「这个模板是空的」这个信号被抹掉,ValidateTemplateConfig 再也走不到
	// 「no rules array in config (skipped)」那条分支,改而去校验一条根本不存在的
	// 规则 —— 校验结果绿,而模板其实一条规则都没有。
	var probe map[string]json.RawMessage
	if json.Unmarshal(rawConfig, &probe) == nil {
		if _, hasRules := probe["rules"]; hasRules {
			return rawConfig
		}
	}
	var flat map[string]interface{}
	if json.Unmarshal(rawConfig, &flat) != nil {
		return rawConfig
	}
	bundle, err := json.Marshal(map[string]interface{}{
		"rules": []map[string]interface{}{{
			"name":   tmpl.Name,
			"type":   tmpl.Type,
			"mode":   tmpl.Mode,
			"config": flat,
		}},
	})
	if err != nil {
		return rawConfig
	}
	return bundle
}

// ValidateTemplateConfig runs test cases from template-form config against the JS evaluator.
// resolvedVars supplies variable values; test case inputs are substituted per test chain_id.
func ValidateTemplateConfig(jsEvaluator *evm.JSRuleEvaluator, tmplName string, templateConfig []byte, resolvedVars map[string]string) ([]*validateRuleResultItem, bool) {
	var configDoc struct {
		Rules []struct {
			ID     string                 `json:"id"`
			Name   string                 `json:"name"`
			Type   string                 `json:"type"`
			Mode   string                 `json:"mode"`
			Config map[string]interface{} `json:"config"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(templateConfig, &configDoc); err != nil || len(configDoc.Rules) == 0 {
		return []*validateRuleResultItem{{
			RuleName: tmplName,
			Type:     "",
			Mode:     "",
			Valid:    true,
			Error:    "no rules array in config (skipped)",
		}}, true
	}

	var results []*validateRuleResultItem
	allPassed := true
	for _, rule := range configDoc.Rules {
		item := &validateRuleResultItem{
			RuleName: rule.Name,
			Type:     rule.Type,
			Mode:     rule.Mode,
		}
		if rule.Type != string(types.RuleTypeEVMJS) || rule.Config == nil {
			item.Valid = true
			results = append(results, item)
			continue
		}
		testCasesRaw, hasTC := rule.Config["test_cases"]
		if !hasTC || testCasesRaw == nil {
			item.Valid = true
			results = append(results, item)
			continue
		}
		tcJSON, _ := json.Marshal(testCasesRaw)
		var testCases []evmhandlerJSRuleTestCase
		if json.Unmarshal(tcJSON, &testCases) != nil || len(testCases) == 0 {
			item.Valid = true
			results = append(results, item)
			continue
		}
		scriptRaw, ok := rule.Config["script"]
		if !ok {
			item.Error = "no script in rule config"
			allPassed = false
			results = append(results, item)
			continue
		}
		script, ok := scriptRaw.(string)
		if !ok {
			item.Error = "script is not a string"
			allPassed = false
			results = append(results, item)
			continue
		}
		runResults, rulePassed := jsEvaluator.RunJSTestCases(script, handlerTestCasesToEVM(testCases), evm.VarsEvalContext(resolvedVars))
		var failedCases []string
		if !rulePassed {
			for _, result := range runResults {
				if !result.Passed {
					failedCases = append(failedCases, fmt.Sprintf("%s: %s", result.Name, result.Reason))
				}
			}
		}
		if len(failedCases) > 0 {
			item.Valid = false
			item.Error = fmt.Sprintf("%d test case(s) failed", len(failedCases))
			allPassed = false
		} else {
			item.Valid = true
		}
		results = append(results, item)
	}
	return results, allPassed
}

// ValidateConfigTestCases runs test cases for a single resolved rule config (non-bundle templates).
// Returns per-test-case validation results and whether all passed.
func ValidateConfigTestCases(jsEvaluator *evm.JSRuleEvaluator, ruleType types.RuleType, ruleMode types.RuleMode, ruleName string, config map[string]interface{}) ([]*validateRuleResultItem, bool) {
	if ruleType != types.RuleTypeEVMJS || config == nil {
		return []*validateRuleResultItem{{
			RuleName: ruleName,
			Type:     string(ruleType),
			Mode:     string(ruleMode),
			Valid:    true,
		}}, true
	}
	testCasesRaw, hasTC := config["test_cases"]
	if !hasTC || testCasesRaw == nil {
		return []*validateRuleResultItem{{
			RuleName: ruleName,
			Type:     string(ruleType),
			Mode:     string(ruleMode),
			Valid:    true,
		}}, true
	}
	tcJSON, _ := json.Marshal(testCasesRaw)
	var testCases []evmhandlerJSRuleTestCase
	if json.Unmarshal(tcJSON, &testCases) != nil || len(testCases) == 0 {
		return []*validateRuleResultItem{{
			RuleName: ruleName,
			Type:     string(ruleType),
			Mode:     string(ruleMode),
			Valid:    true,
		}}, true
	}
	scriptRaw, ok := config["script"]
	if !ok {
		return []*validateRuleResultItem{{
			RuleName: ruleName,
			Type:     string(ruleType),
			Mode:     string(ruleMode),
			Valid:    false,
			Error:    "no script in rule config",
		}}, false
	}
	script, ok := scriptRaw.(string)
	if !ok {
		return []*validateRuleResultItem{{
			RuleName: ruleName,
			Type:     string(ruleType),
			Mode:     string(ruleMode),
			Valid:    false,
			Error:    "script is not a string",
		}}, false
	}
	cfgMap := make(map[string]interface{})
	for k, v := range config {
		if k != "script" && k != "test_cases" && k != "description" {
			cfgMap[k] = v
		}
	}
	var results []*validateRuleResultItem
	allPassed := true
	for _, tc := range testCases {
		result := runJSTestCase(jsEvaluator, script, cfgMap, tc, ruleMode)
		item := &validateRuleResultItem{
			RuleName: fmt.Sprintf("%s / %s", ruleName, tc.Name),
			Type:     string(ruleType),
			Mode:     string(ruleMode),
			Valid:    result.Passed,
		}
		if !result.Passed {
			item.Error = result.Reason
			allPassed = false
		}
		results = append(results, item)
	}
	return results, allPassed
}

// resolveTemplateDefaults fills in default values from template variable definitions,
// preferring the provided vars (test_variables) over defaults.
func validateRequiredTemplateVars(defs []types.TemplateVariable, vars map[string]string) error {
	for _, def := range defs {
		if !def.Required {
			continue
		}
		if v, ok := vars[def.Name]; !ok || strings.TrimSpace(v) == "" {
			return fmt.Errorf("required variable %q is missing", def.Name)
		}
	}
	return nil
}

func isUnrecognizedTemplateConfig(raw []byte) bool {
	var rules struct {
		Rules []json.RawMessage `json:"rules"`
	}
	if json.Unmarshal(raw, &rules) == nil && len(rules.Rules) > 0 {
		return false
	}
	var flat map[string]interface{}
	return json.Unmarshal(raw, &flat) != nil
}

func resolveTemplateDefaults(defs []types.TemplateVariable, vars map[string]string) map[string]string {
	result := make(map[string]string, len(vars))
	for k, v := range vars {
		result[k] = v
	}
	for _, def := range defs {
		if _, provided := result[def.Name]; provided {
			continue
		}
		if def.Default == nil {
			continue
		}
		if s, ok := def.Default.(string); ok {
			result[def.Name] = s
			continue
		}
		result[def.Name] = fmt.Sprint(def.Default)
	}
	return result
}

// resolvedVarsToConfig creates a config map from resolved config JSON.
func resolvedVarsToConfig(resolvedConfig []byte) map[string]interface{} {
	var cfg map[string]interface{}
	_ = json.Unmarshal(resolvedConfig, &cfg)
	return cfg
}
