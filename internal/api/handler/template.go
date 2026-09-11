package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

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
	readOnly          func() bool // when true, block all template mutations via API
	logger            *slog.Logger
	requireApproval   func() bool
	apiKeyRepo        storage.APIKeyRepository
}

// TemplateHandlerOption is a functional option for TemplateHandler.
type TemplateHandlerOption func(*TemplateHandler)

// WithTemplateRequireApproval enables admin approval for agent whitelist rules created via template instantiation.
func WithTemplateRequireApproval(v func() bool) TemplateHandlerOption {
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
	readOnly func() bool,
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

// ---------------------------------------------------------------------------
// The seven named template endpoints (proposal S6)
// ---------------------------------------------------------------------------
//
// # What these replaced
//
// TemplateHandler.ServeHTTP: one function behind two method-less patterns
// ("/api/v1/templates" and "/api/v1/templates/") that cut r.URL.EscapedPath()
// apart, stripped a known sub-action suffix ("/instantiate", "/validate"),
// PathUnescape'd the remainder into an id and then dispatched on r.Method with a
// 405 default in each of its three branches. It was the last entry in
// scripts/lib/arch-baseline/ast/handler-path-dispatch.txt for this package, and
// its validate branch held the last hand-written method comparison that
// api-layer-counts.txt attributes to a path-dispatching closure (that count goes
// 7 → 6 here).
//
// ⚠️ Do not write that comparison out literally anywhere in this tree, comment
// or not: scripts/arch/70-api-layer-duplication.sh counts it with a plain grep
// over production files, so a mention in prose is indistinguishable from the
// thing itself and silently holds the ratchet at its old value.
//
// ⛔ WHY THIS COULD NOT BE DONE UNTIL THE CLIENTS CHANGED. A template id is a
// file stem under the registry's templates directory
// (internal/core/registry/file_source.go relPathIdentity), so shipped ids are
// "evm/erc20", "evm/polymarket_v2" — the '/' is part of the id. While half the
// clients sent it unencoded, "/api/v1/templates/a/b" was equally "template a/b"
// and "template a, sub-action b", and only the suffix ladder above could tell
// them apart. `GET /api/v1/templates/{id}` does not truncate such an id, it
// stops matching it. Measured on the old handler: GET
// /api/v1/templates/evm/erc20 answered 200 with the template. That path is
// unmatched now and lands on the /api/v1/ JSON 404.
//
// The decision recorded on templatesModule was option (a): every client
// percent-encodes. pkg/client (url.PathEscape) and pkg/rs-client
// (urlencoding::encode) always did; pkg/js-client, the extension bundle and the
// two e2e call sites were changed to encodeURIComponent / url.PathEscape in the
// commit before this one, against the *unchanged* server — which accepted both
// forms — so that no window exists in which a client sends a raw slash to a
// daemon that no longer takes it.
//
// ⚠️ The cost, stated rather than buried: a published remote-signer-client
// (npm 0.0.5, vendored under pkg/mcp-server/node_modules) and any extension
// bundle deployed from before that commit still send the raw form and will get
// a 404 from a daemon built from this commit. That is the accepted price of (a).
//
// ⚠️ The nil-API-key guard is repeated verbatim in each endpoint rather than
// hoisted. In a daemon it is unreachable — AuthMiddleware runs first — but it is
// what the "unauthorized" tests assert, and dropping a 401 on the way past
// would be a behaviour change smuggled inside a routing change. Same reasoning
// as RevokeInstance below.
//
// ⚠️ No endpoint checks a method any more: the pattern carries it, so a verb no
// route declares matches no pattern. ⛔ And there was no verb hole here to
// close — unlike presets (GET applied a preset), signers (GET unlocked) and
// hd-wallets (GET derived), every one of ServeHTTP's three branches did check
// the method before mutating. Measured against the real registrations: POST on
// an item answered 405, GET on instantiate answered 405, GET on validate
// answered 405. What this step closes is the *ambiguity* and the deep-path
// swallow, not a reachability defect.

// ListTemplates serves GET /api/v1/templates.
func (h *TemplateHandler) ListTemplates(w http.ResponseWriter, r *http.Request) {
	if middleware.GetAPIKey(r.Context()) == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}
	h.listTemplates(w, r)
}

// CreateTemplate serves POST /api/v1/templates.
func (h *TemplateHandler) CreateTemplate(w http.ResponseWriter, r *http.Request) {
	if middleware.GetAPIKey(r.Context()) == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}
	h.createTemplate(w, r)
}

// GetTemplate serves GET /api/v1/templates/{id}.
func (h *TemplateHandler) GetTemplate(w http.ResponseWriter, r *http.Request) {
	if middleware.GetAPIKey(r.Context()) == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}
	h.getTemplate(w, r, r.PathValue("id"))
}

// UpdateTemplate serves PATCH /api/v1/templates/{id}.
func (h *TemplateHandler) UpdateTemplate(w http.ResponseWriter, r *http.Request) {
	if middleware.GetAPIKey(r.Context()) == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}
	h.updateTemplate(w, r, r.PathValue("id"))
}

// DeleteTemplate serves DELETE /api/v1/templates/{id}.
func (h *TemplateHandler) DeleteTemplate(w http.ResponseWriter, r *http.Request) {
	if middleware.GetAPIKey(r.Context()) == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}
	h.deleteTemplate(w, r, r.PathValue("id"))
}

// InstantiateTemplate serves POST /api/v1/templates/{id}/instantiate.
func (h *TemplateHandler) InstantiateTemplate(w http.ResponseWriter, r *http.Request) {
	if middleware.GetAPIKey(r.Context()) == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}
	h.instantiateTemplate(w, r, r.PathValue("id"))
}

// ValidateTemplate serves POST /api/v1/templates/{id}/validate.
//
// ⚠️ The admin check stays in the handler and is copied verbatim. It is a *role*
// test (apiKey.IsAdmin()), not a permission, so the route layer cannot express
// it: RouteAuth carries one permission and the route's is PermReadTemplates,
// exactly as the prefix declared. ⛔ Moving it would be a security change, and
// deleting it would widen the endpoint to every key holding read_templates.
func (h *TemplateHandler) ValidateTemplate(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}
	// Validate is admin-only (RBAC via role check)
	if !apiKey.IsAdmin() {
		respond.Error(w, "forbidden: admin role required", http.StatusForbidden, h.logger)
		return
	}
	h.validateTemplate(w, r, r.PathValue("id"))
}

// RevokeInstance serves POST /api/v1/templates/instances/{ruleID}/revoke.
//
// # What this replaced (proposal S6)
//
// ServeInstanceHTTP, reached through a closure registered inline in
// setupRoutes that tested strings.HasPrefix(path, "/api/v1/templates/instances/")
// and forwarded to it — one of the two closures
// scripts/lib/arch-baseline/api-layer-counts.txt names as the reason
// manual_method_checks cannot reach zero.
//
// ⚠️ The ruleID comes from PathValue and is therefore exactly one segment.
// That is not a narrowing that matters: instance rule IDs are minted as
// "inst_" + 16 hex chars (internal/core/service/template.go:757,910) and cannot
// contain a slash, and every client builds this path from such an id. The old
// TrimPrefix/TrimSuffix pair accepted any depth, so
// POST /api/v1/templates/instances/a/b/revoke reached the service with ruleID
// "a/b" — measured, and it is the same swallow S4 found on the signer access
// sub-tree.
//
// ⚠️ The nil-API-key guard is kept verbatim. In a daemon it is unreachable —
// AuthMiddleware runs first — but it is what the two "without_api_key" tests
// assert, and dropping a 401 on the way past would be a behaviour change
// smuggled inside a routing change.
func (h *TemplateHandler) RevokeInstance(w http.ResponseWriter, r *http.Request) {
	if middleware.GetAPIKey(r.Context()) == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}
	h.revokeInstance(w, r, r.PathValue("ruleID"))
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
			respond.Error(w, "template not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("failed to get template", "error", err, "template_id", templateID)
		respond.Error(w, "failed to get template", http.StatusInternalServerError, h.logger)
		return
	}

	if h.jsEvaluator == nil {
		respond.Error(w, "JS evaluator not available", http.StatusServiceUnavailable, h.logger)
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
			respond.Error(w, "failed to parse template variables", http.StatusInternalServerError, h.logger)
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
		respond.Error(w, fmt.Sprintf("variable substitution failed: %s", err.Error()), http.StatusBadRequest, h.logger)
		return
	}
	// Dry-run: ensure all ${var} placeholders in config resolve (without mutating config;
	// test case inputs are substituted per chain_id inside RunJSTestCases).
	//lint:ignore SA1019 R8 迁移未完成:SubstituteTyped 需要变量定义,语义也不同(带类型转换),
	// 而这里只要一次「占位符是否都能解析」的 dry-run。换过去要先确认 typed 版对
	// 未解析占位符的报错行为一致 —— 那是 R8 的范围,不是本次重构的。
	if _, err := service.SubstituteVariables(tmpl.Config, resolvedVars); err != nil {
		respond.Error(w, fmt.Sprintf("variable substitution failed: %s", err.Error()), http.StatusBadRequest, h.logger)
		return
	}

	configForValidate := normalizeTemplateConfigForValidation(tmpl, tmpl.Config)
	if isUnrecognizedTemplateConfig(tmpl.Config) {
		respond.JSON(w, validateTemplateResponse{
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
		}, http.StatusOK, h.logger)

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
	respond.JSON(w, resp, http.StatusOK, h.logger)
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

// isReadOnly reports whether write operations are blocked right now. See the
// note on Router.liveReadOnly: the setting behind it is runtime mutable, so a
// bool captured at construction freezes at boot.
func (h *TemplateHandler) isReadOnly() bool {
	if h.readOnly == nil {
		return false
	}
	return h.readOnly()
}

// requireApprovalValue reads the setting at request time — see
// Router.liveReadOnly for why it must not be a captured bool.
func (h *TemplateHandler) requireApprovalValue() bool {
	if h.requireApproval == nil {
		return false
	}
	return h.requireApproval()
}
