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
	templateRepo    storage.TemplateRepository
	templateService *service.TemplateService
	jsEvaluator     *evm.JSRuleEvaluator
	readOnly        bool // when true, block all template mutations via API
	logger          *slog.Logger
	requireApproval bool
	apiKeyRepo      storage.APIKeyRepository
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
	TemplateID   string                     `json:"template_id"`
	TemplateName string                     `json:"template_name"`
	Results      []*validateRuleResultItem  `json:"results,omitempty"`
	Total        int                        `json:"total"`
	Passed       int                        `json:"passed"`
	Failed       int                        `json:"failed"`
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

	// Substitute variables into config
	resolvedConfig, err := service.SubstituteVariables(tmpl.Config, resolvedVars) //nolint:staticcheck
	if err != nil {
		h.writeError(w, fmt.Sprintf("variable substitution failed: %s", err.Error()), http.StatusBadRequest)
		return
	}

	// Parse the resolved config as a rules array
	var results []*validateRuleResultItem
	totalPassed := 0
	totalFailed := 0
	var configDoc struct {
		Rules []struct {
			ID     string                 `json:"id"`
			Name   string                 `json:"name"`
			Type   string                 `json:"type"`
			Mode   string                 `json:"mode"`
			Config map[string]interface{} `json:"config"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(resolvedConfig, &configDoc); err != nil {
		// Try flat config directly (non-bundle templates)
		var flatConfig struct {
			Script    string                 `json:"script"`
			TestCases []map[string]interface{} `json:"test_cases"`
		}
		if flatErr := json.Unmarshal(resolvedConfig, &flatConfig); flatErr != nil {
			// Third fallback: non-evm_js template (e.g. sign_type_restriction).
			results = append(results, &validateRuleResultItem{
				RuleName: tmpl.Name,
				Type:     string(tmpl.Type),
				Mode:     string(tmpl.Mode),
				Valid:    true,
				Error:    "non-evm_js template (config format not recognized)",
			})
			totalPassed++
			resp := validateTemplateResponse{
				TemplateID:   templateID,
				TemplateName: tmpl.Name,
				Results:      results,
				Total:        len(results),
				Passed:       totalPassed,
				Failed:       totalFailed,
			}
			h.writeJSON(w, resp, http.StatusOK)
			return
		}
		configDoc.Rules = []struct {
			ID     string                 `json:"id"`
			Name   string                 `json:"name"`
			Type   string                 `json:"type"`
			Mode   string                 `json:"mode"`
			Config map[string]interface{} `json:"config"`
		}{
			{Name: tmpl.Name, Type: string(tmpl.Type), Mode: string(tmpl.Mode), Config: resolvedVarsToConfig(resolvedConfig)},
		}
	}

	// Parse types from the template's top-level if rules don't override

	for _, rule := range configDoc.Rules {
		item := &validateRuleResultItem{
			RuleName: rule.Name,
			Type:     rule.Type,
			Mode:     rule.Mode,
		}

		if rule.Type != string(types.RuleTypeEVMJS) {
			item.Valid = true
			item.Error = "non-evm_js rules are not validated"
			results = append(results, item)
			totalPassed++
			continue
		}

		// Extract test_cases from the rule's config
		testCasesRaw, hasTC := rule.Config["test_cases"]
		if !hasTC || testCasesRaw == nil {
			item.Valid = true
			results = append(results, item)
			totalPassed++
			continue
		}
		tcJSON, err := json.Marshal(testCasesRaw)
		if err != nil {
			item.Error = fmt.Sprintf("invalid test_cases: %v", err)
			results = append(results, item)
			totalFailed++
			continue
		}
		var testCases []evmhandlerJSRuleTestCase
		if err := json.Unmarshal(tcJSON, &testCases); err != nil {
			item.Error = fmt.Sprintf("invalid test_cases: %v", err)
			results = append(results, item)
			totalFailed++
			continue
		}

		if len(testCases) == 0 {
			item.Valid = true
			results = append(results, item)
			totalPassed++
			continue
		}

		// Extract script from config
		scriptRaw, ok := rule.Config["script"]
		if !ok {
			item.Error = "no script in rule config"
			results = append(results, item)
			totalFailed++
			continue
		}
		script, ok := scriptRaw.(string)
		if !ok {
			item.Error = "script is not a string"
			results = append(results, item)
			totalFailed++
			continue
		}

		// Build config map excluding script and test_cases
		cfgMap := make(map[string]interface{})
		for k, v := range rule.Config {
			if k != "script" && k != "test_cases" && k != "description" {
				cfgMap[k] = v
			}
		}
		// Merge template-level variables into cfgMap so JS scripts can
		// reference them via config.xxx (e.g. config.exchange_v2_address).
		for k, v := range resolvedVars {
			if _, exists := cfgMap[k]; !exists {
				cfgMap[k] = v
			}
		}

		// Run each test case
		var failedCases []string
		for _, tc := range testCases {
			result := runJSTestCase(h.jsEvaluator, script, cfgMap, tc, types.RuleMode(rule.Mode))
			if !result.Passed {
				failedCases = append(failedCases, fmt.Sprintf("%s: %s", result.Name, result.Reason))
			}
		}

		if len(failedCases) > 0 {
			item.Valid = false
			item.Error = fmt.Sprintf("%d test case(s) failed", len(failedCases))
			totalFailed++
		} else {
			item.Valid = true
			totalPassed++
		}
		results = append(results, item)
	}

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
	ExpectPass bool                   `json:"expect_pass"`
}

// runJSTestCase runs a single test case against the JS evaluator.
func runJSTestCase(eval *evm.JSRuleEvaluator, script string, cfgMap map[string]interface{}, tc evmhandlerJSRuleTestCase, mode types.RuleMode) struct {
	Name   string
	Passed bool
	Reason string
} {
	req, parsed, err := evm.TestCaseInputToSignRequest(tc.Input)
	if err != nil {
		return struct {
			Name   string
			Passed bool
			Reason string
		}{Name: tc.Name, Passed: false, Reason: fmt.Sprintf("invalid input: %v", err)}
	}
	ruleInput, err := evm.BuildRuleInput(req, parsed)
	if err != nil {
		return struct {
			Name   string
			Passed bool
			Reason string
		}{Name: tc.Name, Passed: false, Reason: fmt.Sprintf("build input: %v", err)}
	}
	result := eval.ValidateWithInput(script, ruleInput, cfgMap)
	actualPass := result.Valid
	if actualPass != tc.ExpectPass {
		if tc.ExpectPass {
			return struct {
				Name   string
				Passed bool
				Reason string
			}{Name: tc.Name, Passed: false, Reason: fmt.Sprintf("expected pass but got: %s", result.Reason)}
		}
		return struct {
			Name   string
			Passed bool
			Reason string
		}{Name: tc.Name, Passed: false, Reason: "expected fail but passed"}
	}
	return struct {
		Name   string
		Passed bool
		Reason string
	}{Name: tc.Name, Passed: true}
}

// ValidateTemplateConfig runs test cases from a resolved template config against the JS evaluator.
// Returns validation results for each rule in the config. Handles both bundle (rules array) and
// flat config formats. Used by both template instantiation and preset apply.
func ValidateTemplateConfig(jsEvaluator *evm.JSRuleEvaluator, tmplName string, resolvedConfig []byte, resolvedVars map[string]string) ([]*validateRuleResultItem, bool) {
	var configDoc struct {
		Rules []struct {
			ID     string                 `json:"id"`
			Name   string                 `json:"name"`
			Type   string                 `json:"type"`
			Mode   string                 `json:"mode"`
			Config map[string]interface{} `json:"config"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(resolvedConfig, &configDoc); err != nil || len(configDoc.Rules) == 0 {
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
		cfgMap := make(map[string]interface{})
		for k, v := range rule.Config {
			if k != "script" && k != "test_cases" && k != "description" {
				cfgMap[k] = v
			}
		}
		// Merge template-level variables into cfgMap
		for k, v := range resolvedVars {
			if _, exists := cfgMap[k]; !exists {
				cfgMap[k] = v
			}
		}
		var failedCases []string
		for _, tc := range testCases {
			result := runJSTestCase(jsEvaluator, script, cfgMap, tc, types.RuleMode(rule.Mode))
			if !result.Passed {
				failedCases = append(failedCases, fmt.Sprintf("%s: %s", result.Name, result.Reason))
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
			if s != "" {
				result[def.Name] = s
			}
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
