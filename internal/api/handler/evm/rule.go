package evm

import (
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ruleIDPattern validates rule ID format. Accepts:
// - rule_<uuid>: API-created rules
// - cfg_<16hex> or cfg_<digits>: config rules (auto-generated or legacy)
// - <custom>: config custom IDs (alphanumeric, hyphen, underscore, 1-64 chars).
var ruleIDPattern = regexp.MustCompile(`^(rule_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|cfg_[0-9a-f]{16}|cfg_\d+|[a-zA-Z0-9][0-9A-Za-z_\-]{0,63})$`)

// blockedAgentRuleTypes are rule types that agents cannot create or modify to.
var blockedAgentRuleTypes = map[types.RuleType]bool{
	types.RuleTypeEVMJS:                 true,
	types.RuleTypeSignerRestriction:     true,
	types.RuleTypeEVMSolidityExpression: true,
}

// blockedDevRuleTypes are rule types that dev role cannot create.
var blockedDevRuleTypes = map[types.RuleType]bool{
	types.RuleTypeSignerRestriction: true,
}

// RuleHandler handles rule management endpoints
type RuleHandler struct {
	ruleRepo          storage.RuleRepository
	budgetRepo        storage.BudgetRepository
	templateRepo      storage.TemplateRepository
	apiKeyRepo        storage.APIKeyRepository
	solidityValidator *evmchain.SolidityRuleValidator
	jsEvaluator       *evmchain.JSRuleEvaluator
	auditLogger       *audit.AuditLogger
	readOnly          bool // when true, block all rule mutations via API
	logger            *slog.Logger
	maxRulesPerKey    int  // per-key rule count limit (0 = no limit)
	requireApproval   bool // require admin approval for agent whitelist rules
	onRuleActivated   func(callerName string) // optional callback when rule becomes active
}

// RuleHandlerOption is a functional option for RuleHandler
type RuleHandlerOption func(*RuleHandler)

// WithSolidityValidator sets the Solidity rule validator for the handler
func WithSolidityValidator(validator *evmchain.SolidityRuleValidator) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.solidityValidator = validator
	}
}

// WithJSEvaluator sets the JS rule evaluator for test-case validation on API-created evm_js rules.
func WithJSEvaluator(eval *evmchain.JSRuleEvaluator) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.jsEvaluator = eval
	}
}

// WithAuditLogger sets the audit logger for rule CRUD audit events.
func WithAuditLogger(al *audit.AuditLogger) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.auditLogger = al
	}
}

// WithBudgetRepo sets the budget repository for GET /api/v1/evm/rules/{id}/budgets
// and budget auto-migration during rule updates.
func WithBudgetRepo(repo storage.BudgetRepository) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.budgetRepo = repo
	}
}

// WithTemplateRepo sets the template repository for budget auto-migration
// when Variables affecting the budget unit are changed during rule updates.
func WithTemplateRepo(repo storage.TemplateRepository) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.templateRepo = repo
	}
}

// WithReadOnly disables all rule mutation endpoints (create/update/delete).
func WithReadOnly() RuleHandlerOption {
	return func(h *RuleHandler) {
		h.readOnly = true
	}
}

// WithAPIKeyRepo sets the API key repository for validating applied_to key IDs.
func WithAPIKeyRepo(repo storage.APIKeyRepository) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.apiKeyRepo = repo
	}
}

// WithMaxRulesPerKey sets the per-key rule count limit.
func WithMaxRulesPerKey(max int) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.maxRulesPerKey = max
	}
}

// WithRequireApproval enables admin approval for agent whitelist rules.
func WithRequireApproval(require bool) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.requireApproval = require
	}
}

// WithRuleActivatedCallback sets a callback invoked (asynchronously) when a
// rule transitions to active. It re-evaluates pending approval requests
// against the updated rule set so a newly-active whitelist rule can
// auto-approve requests that were waiting.
func WithRuleActivatedCallback(cb func(callerName string)) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.onRuleActivated = cb
	}
}

// NewRuleHandler creates a new rule handler
func NewRuleHandler(ruleRepo storage.RuleRepository, logger *slog.Logger, opts ...RuleHandlerOption) (*RuleHandler, error) {
	if ruleRepo == nil {
		return nil, fmt.Errorf("rule repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	h := &RuleHandler{
		ruleRepo: ruleRepo,
		logger:   logger,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h, nil
}

// ServeHTTP handles /api/v1/evm/rules and /api/v1/evm/rules/{id}
func (h *RuleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get API key from context (for audit)
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Determine if this is a list request or a specific rule request
	// Path: /api/v1/evm/rules or /api/v1/evm/rules/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/evm/rules")
	path = strings.TrimPrefix(path, "/")

	if path == "" {
		// Wallet operations: GET /api/v1/evm/rules or POST /api/v1/evm/rules
		switch r.Method {
		case http.MethodGet:
			h.listRules(w, r)
		case http.MethodPost:
			h.createRule(w, r)
		default:
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	// Sub-resource: /api/v1/evm/rules/validate (batch validate — no rule ID, admin only)
	if path == "validate" && r.Method == http.MethodPost {
		if !apiKey.IsAdmin() {
			h.writeError(w, "forbidden: admin role required", http.StatusForbidden)
			return
		}
		h.validateRules(w, r)
		return
	}

	// Sub-resource: /api/v1/evm/rules/{id}/validate (admin only)
	if strings.HasSuffix(path, "/validate") {
		ruleID := strings.TrimSuffix(path, "/validate")
		ruleID = strings.Trim(ruleID, "/")
		if ruleID != "" && !strings.Contains(ruleID, "/") && r.Method == http.MethodPost {
			if !apiKey.IsAdmin() {
				h.writeError(w, "forbidden: admin role required", http.StatusForbidden)
				return
			}
			h.validateRule(w, r, ruleID)
			return
		}
	}

	// Sub-resource: /api/v1/evm/rules/{id}/budgets
	// Accept any rule ID that is a single path segment (config-expanded IDs like erc20-schedule_erc20-transfer-limit).
	if strings.HasSuffix(path, "/budgets") {
		ruleID := strings.TrimSuffix(path, "/budgets")
		ruleID = strings.Trim(ruleID, "/")
		if ruleID != "" && !strings.Contains(ruleID, "/") && len(ruleID) <= 128 && r.Method == http.MethodGet && h.budgetRepo != nil {
			h.listBudgets(w, r, ruleID)
			return
		}
	}

	// Sub-resource: /api/v1/evm/rules/{id}/approve or /api/v1/evm/rules/{id}/reject
	if strings.HasSuffix(path, "/approve") {
		ruleID := strings.TrimSuffix(path, "/approve")
		ruleID = strings.Trim(ruleID, "/")
		if ruleID != "" && !strings.Contains(ruleID, "/") && r.Method == http.MethodPost {
			h.approveRule(w, r, ruleID)
			return
		}
	}
	if strings.HasSuffix(path, "/reject") {
		ruleID := strings.TrimSuffix(path, "/reject")
		ruleID = strings.Trim(ruleID, "/")
		if ruleID != "" && !strings.Contains(ruleID, "/") && r.Method == http.MethodPost {
			h.rejectRule(w, r, ruleID)
			return
		}
	}

	// Specific rule operations: /api/v1/evm/rules/{id}
	ruleID := strings.Trim(path, "/")
	if !ruleIDPattern.MatchString(ruleID) {
		h.writeError(w, "invalid rule_id format", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.getRule(w, r, ruleID)
	case http.MethodDelete:
		h.deleteRule(w, r, ruleID)
	case http.MethodPatch:
		h.updateRule(w, r, ruleID)
	default:
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
