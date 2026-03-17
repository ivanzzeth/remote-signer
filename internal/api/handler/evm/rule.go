package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/ruleconfig"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

// ruleIDPattern validates rule ID format. Accepts:
// - rule_<uuid>: API-created rules
// - cfg_<16hex> or cfg_<digits>: config rules (auto-generated or legacy)
// - <custom>: config custom IDs (alphanumeric, hyphen, underscore, 1-64 chars).
var ruleIDPattern = regexp.MustCompile(`^(rule_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|cfg_[0-9a-f]{16}|cfg_\d+|[a-zA-Z0-9][0-9A-Za-z_\-]{0,63})$`)

// apiKeyIDPattern validates API key ID format (SA-6).
var apiKeyIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// blockedAgentRuleTypes are rule types that agents cannot create or modify to.
var blockedAgentRuleTypes = map[types.RuleType]bool{
	types.RuleTypeEVMJS:                  true,
	types.RuleTypeSignerRestriction:      true,
	types.RuleTypeEVMSolidityExpression:  true,
}

// blockedDevRuleTypes are rule types that dev role cannot create.
var blockedDevRuleTypes = map[types.RuleType]bool{
	types.RuleTypeSignerRestriction: true,
}

// RuleHandler handles rule management endpoints
type RuleHandler struct {
	ruleRepo          storage.RuleRepository
	budgetRepo        storage.BudgetRepository
	apiKeyRepo        storage.APIKeyRepository
	solidityValidator *evmchain.SolidityRuleValidator
	jsEvaluator       *evmchain.JSRuleEvaluator
	auditLogger       *audit.AuditLogger
	readOnly          bool // when true, block all rule mutations via API
	logger            *slog.Logger
	maxRulesPerKey    int  // per-key rule count limit (0 = no limit)
	requireApproval   bool // require admin approval for agent whitelist rules
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

// WithBudgetRepo sets the budget repository for GET /api/v1/evm/rules/{id}/budgets.
func WithBudgetRepo(repo storage.BudgetRepository) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.budgetRepo = repo
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

// RuleResponse represents a rule in API responses
type RuleResponse struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Description       string          `json:"description,omitempty"`
	Type              string          `json:"type"`
	Mode              string          `json:"mode"`
	Source            string          `json:"source"`
	ChainType         *string         `json:"chain_type,omitempty"`
	ChainID           *string         `json:"chain_id,omitempty"`
	Owner             *string         `json:"owner,omitempty"`
	AppliedTo         []string        `json:"applied_to,omitempty"`
	Status            string          `json:"status,omitempty"`
	ApprovedBy        *string         `json:"approved_by,omitempty"`
	Immutable         bool            `json:"immutable,omitempty"`
	SignerAddress     *string         `json:"signer_address,omitempty"`
	Config            json.RawMessage `json:"config,omitempty"`
	Enabled           bool            `json:"enabled"`
	CreatedAt         string          `json:"created_at"`
	UpdatedAt         string          `json:"updated_at"`
	ExpiresAt         *string         `json:"expires_at,omitempty"`
	MatchCount        uint64          `json:"match_count"`
	LastMatchedAt     *string         `json:"last_matched_at,omitempty"`
	BudgetPeriod      string          `json:"budget_period,omitempty"`       // e.g. "24h0m0s"; set when schedule.period is configured
	BudgetPeriodStart *string         `json:"budget_period_start,omitempty"` // RFC3339; when first period began
}

// ListRulesResponse represents the response for listing rules
type ListRulesResponse struct {
	Rules []RuleResponse `json:"rules"`
	Total int            `json:"total"`
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
		// Collection operations: GET /api/v1/evm/rules or POST /api/v1/evm/rules
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

// JSRuleTestCase is a test case for evm_js rules submitted via API.
type JSRuleTestCase struct {
	Name         string                 `json:"name"`
	Input        map[string]interface{} `json:"input"`
	ExpectPass   bool                   `json:"expect_pass"`
	ExpectReason string                 `json:"expect_reason,omitempty"`
}

// CreateRuleRequest represents a request to create a new rule
type CreateRuleRequest struct {
	Name          string                 `json:"name"`
	Description   string                 `json:"description,omitempty"`
	Type          string                 `json:"type"`
	Mode          string                 `json:"mode"`
	ChainType     *string                `json:"chain_type,omitempty"`
	ChainID       *string                `json:"chain_id,omitempty"`
	SignerAddress *string                `json:"signer_address,omitempty"`
	Config        map[string]interface{} `json:"config"`
	Enabled       bool                   `json:"enabled"`
	Immutable     bool                   `json:"immutable,omitempty"`
	AppliedTo     []string               `json:"applied_to,omitempty"`
	TestCases     []JSRuleTestCase       `json:"test_cases,omitempty"` // required for evm_js rules
}

// UpdateRuleRequest represents a request to update an existing rule
type UpdateRuleRequest struct {
	Name          string                 `json:"name,omitempty"`
	Description   string                 `json:"description,omitempty"`
	Type          string                 `json:"type,omitempty"`
	Config        map[string]interface{} `json:"config,omitempty"`
	ChainType     *string                `json:"chain_type,omitempty"`
	ChainID       *string                `json:"chain_id,omitempty"`
	SignerAddress *string                `json:"signer_address,omitempty"`
	Enabled       *bool                  `json:"enabled,omitempty"`
	AppliedTo     []string               `json:"applied_to,omitempty"`
	TestCases     []JSRuleTestCase       `json:"test_cases,omitempty"` // required for evm_js when updating config
}

// RejectRuleRequest represents a request body for POST /evm/rules/:id/reject
type RejectRuleRequest struct {
	Reason string `json:"reason"`
}

func (h *RuleHandler) createRule(w http.ResponseWriter, r *http.Request) {
	if h.readOnly {
		h.writeError(w, "rule creation via API is disabled (security.rules_api_readonly)", http.StatusForbidden)
		return
	}

	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req CreateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Name == "" {
		h.writeError(w, "name is required", http.StatusBadRequest)
		return
	}
	if req.Type == "" {
		h.writeError(w, "type is required", http.StatusBadRequest)
		return
	}
	if req.Mode == "" {
		h.writeError(w, "mode is required", http.StatusBadRequest)
		return
	}

	// Validate mode is a known value
	if req.Mode != "whitelist" && req.Mode != "blocklist" {
		h.writeError(w, "mode must be 'whitelist' or 'blocklist'", http.StatusBadRequest)
		return
	}

	ruleType := types.RuleType(req.Type)

	// Agent: block restricted rule types
	if apiKey.IsAgent() && blockedAgentRuleTypes[ruleType] {
		h.writeError(w, fmt.Sprintf("agent role cannot create rules of type %q", req.Type), http.StatusForbidden)
		return
	}

	// Dev: block signer_restriction
	if apiKey.IsDev() && blockedDevRuleTypes[ruleType] {
		h.writeError(w, fmt.Sprintf("dev role cannot create rules of type %q", req.Type), http.StatusForbidden)
		return
	}

	// Per-key rule count limit (admin exempt)
	if !apiKey.IsAdmin() && h.maxRulesPerKey > 0 {
		ownerID := apiKey.ID
		count, err := h.ruleRepo.Count(r.Context(), storage.RuleFilter{Owner: &ownerID})
		if err != nil {
			h.logger.Error("failed to count rules for owner", "error", err, "owner", ownerID)
			h.writeError(w, "failed to check rule count", http.StatusInternalServerError)
			return
		}
		if count >= h.maxRulesPerKey {
			h.writeError(w, fmt.Sprintf("rule limit exceeded: maximum %d rules per API key", h.maxRulesPerKey), http.StatusForbidden)
			return
		}
	}

	// Determine applied_to based on role
	var appliedTo pq.StringArray
	if apiKey.IsAdmin() {
		if len(req.AppliedTo) > 0 {
			appliedTo = pq.StringArray(req.AppliedTo)
		} else {
			appliedTo = pq.StringArray{"*"}
		}
		// Validate non-wildcard key IDs exist (SA-6)
		if h.apiKeyRepo != nil {
			for _, keyID := range appliedTo {
				if keyID == "*" || keyID == "self" {
					continue
				}
				if !apiKeyIDPattern.MatchString(keyID) {
					h.writeError(w, fmt.Sprintf("invalid applied_to key ID format: %q", keyID), http.StatusBadRequest)
					return
				}
				if _, err := h.apiKeyRepo.Get(r.Context(), keyID); err != nil {
					if types.IsNotFound(err) {
						h.writeError(w, fmt.Sprintf("applied_to key ID not found: %q", keyID), http.StatusBadRequest)
						return
					}
					h.logger.Error("failed to validate applied_to key ID", "error", err, "key_id", keyID)
					h.writeError(w, "failed to validate applied_to", http.StatusInternalServerError)
					return
				}
			}
		}
	} else {
		// Non-admin: force applied_to = ["self"]
		appliedTo = pq.StringArray{"self"}
	}

	// Determine status based on role and config
	status := types.RuleStatusActive
	if apiKey.IsAgent() && h.requireApproval && req.Mode == "whitelist" {
		status = types.RuleStatusPendingApproval
	}
	// Agent blocklist rules are always active immediately (self-restriction is safe)

	// Validate rule config format (shared with config load and validate-rules)
	if err := ruleconfig.ValidateRuleConfig(req.Type, req.Config); err != nil {
		h.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate optional scope fields to prevent storing invalid data
	if req.ChainType != nil {
		if !validate.IsValidChainType(*req.ChainType) {
			h.writeError(w, "invalid chain_type: must be one of evm, solana, cosmos", http.StatusBadRequest)
			return
		}
	}
	if req.SignerAddress != nil {
		if !validate.IsValidEthereumAddress(*req.SignerAddress) {
			h.writeError(w, "invalid signer_address: must be 0x followed by 40 hex characters", http.StatusBadRequest)
			return
		}
	}

	// Generate rule ID
	ruleID := types.RuleID(fmt.Sprintf("rule_%s", uuid.New().String()))

	// Marshal config to JSON
	configJSON, err := json.Marshal(req.Config)
	if err != nil {
		h.writeError(w, "invalid config", http.StatusBadRequest)
		return
	}

	// Only admin can set immutable
	immutable := false
	if apiKey.IsAdmin() {
		immutable = req.Immutable
	}

	// Build rule
	rule := &types.Rule{
		ID:          ruleID,
		Name:        req.Name,
		Description: req.Description,
		Type:        ruleType,
		Mode:        types.RuleMode(req.Mode),
		Source:      types.RuleSourceAPI,
		Config:      configJSON,
		Enabled:     req.Enabled,
		Owner:       apiKey.ID, // auto-set from caller
		AppliedTo:   appliedTo,
		Status:      status,
		Immutable:   immutable,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Set optional fields
	if req.ChainType != nil {
		ct := types.ChainType(*req.ChainType)
		rule.ChainType = &ct
	} else {
		// Default to EVM for /api/v1/evm/rules
		ct := types.ChainTypeEVM
		rule.ChainType = &ct
	}
	if req.ChainID != nil {
		rule.ChainID = req.ChainID
	}
	if req.SignerAddress != nil {
		rule.SignerAddress = req.SignerAddress
	}

	// Validate Solidity expression rules if validator is available
	if rule.Type == types.RuleTypeEVMSolidityExpression && h.solidityValidator != nil {
		if err := h.validateSolidityRule(r.Context(), rule); err != nil {
			h.logger.Error("rule validation failed", "error", err, "rule_type", rule.Type)
			h.writeError(w, "rule validation failed", http.StatusBadRequest)
			return
		}
	}

	// Validate evm_js rules: require test_cases with 1+ positive and 1+ negative, then run them
	if rule.Type == types.RuleTypeEVMJS {
		if err := h.validateJSRule(rule, req.TestCases); err != nil {
			h.logger.Error("evm_js rule validation failed", "error", err, "rule_name", rule.Name)
			h.writeError(w, fmt.Sprintf("evm_js rule validation failed: %v", err), http.StatusBadRequest)
			return
		}
	}

	// Create rule
	if err := h.ruleRepo.Create(r.Context(), rule); err != nil {
		h.logger.Error("failed to create rule", "error", err)
		h.writeError(w, "failed to create rule", http.StatusInternalServerError)
		return
	}

	h.logger.Info("rule created", "rule_id", rule.ID, "name", rule.Name, "owner", rule.Owner, "applied_to", rule.AppliedTo, "status", rule.Status)
	if h.auditLogger != nil {
		clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
		h.auditLogger.LogRuleCreated(r.Context(), apiKey.ID, clientIP, rule.ID, rule.Name)
	}

	responseStatus := http.StatusCreated
	if rule.Status == types.RuleStatusPendingApproval {
		responseStatus = http.StatusAccepted
	}
	h.writeJSON(w, h.toRuleResponse(rule), responseStatus)
}

func (h *RuleHandler) updateRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	var req UpdateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Get existing rule
	rule, err := h.ruleRepo.Get(r.Context(), types.RuleID(ruleID))
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "rule not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to get rule", "error", err, "rule_id", ruleID)
		h.writeError(w, "failed to get rule", http.StatusInternalServerError)
		return
	}

	if h.readOnly {
		h.writeError(w, "rule updates via API are disabled (security.rules_api_readonly)", http.StatusForbidden)
		return
	}
	if rule.Source == types.RuleSourceConfig {
		h.writeError(w, "cannot update config-sourced rules via API", http.StatusForbidden)
		return
	}

	// Immutable check
	if rule.Immutable {
		h.writeError(w, "cannot modify immutable rule", http.StatusForbidden)
		return
	}

	// Ownership check: only owner or admin can modify
	if !apiKey.IsAdmin() && rule.Owner != apiKey.ID {
		h.writeError(w, "permission denied: can only modify own rules", http.StatusForbidden)
		return
	}

	// Agent: block changing to restricted rule types
	if req.Type != "" && apiKey.IsAgent() && blockedAgentRuleTypes[types.RuleType(req.Type)] {
		h.writeError(w, fmt.Sprintf("agent role cannot change rule type to %q", req.Type), http.StatusForbidden)
		return
	}

	// Agent: cannot change applied_to
	if len(req.AppliedTo) > 0 && !apiKey.IsAdmin() {
		// Non-admin cannot change applied_to (forced to ["self"])
		h.writeError(w, "only admin can change applied_to", http.StatusForbidden)
		return
	}

	// Save old config for audit diff
	oldConfig := make([]byte, len(rule.Config))
	copy(oldConfig, rule.Config)

	// Update fields if provided
	if req.Name != "" {
		rule.Name = req.Name
	}
	if req.Description != "" {
		rule.Description = req.Description
	}
	if req.Config != nil {
		if err := ruleconfig.ValidateRuleConfig(string(rule.Type), req.Config); err != nil {
			h.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		configJSON, err := json.Marshal(req.Config)
		if err != nil {
			h.writeError(w, "invalid config", http.StatusBadRequest)
			return
		}
		rule.Config = configJSON
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	if req.ChainType != nil {
		if !validate.IsValidChainType(*req.ChainType) {
			h.writeError(w, "invalid chain_type: must be one of evm, solana, cosmos", http.StatusBadRequest)
			return
		}
		ct := types.ChainType(*req.ChainType)
		rule.ChainType = &ct
	}
	if req.ChainID != nil {
		rule.ChainID = req.ChainID
	}
	if req.SignerAddress != nil {
		if !validate.IsValidEthereumAddress(*req.SignerAddress) {
			h.writeError(w, "invalid signer_address: must be 0x followed by 40 hex characters", http.StatusBadRequest)
			return
		}
		rule.SignerAddress = req.SignerAddress
	}
	// Admin can change applied_to
	if len(req.AppliedTo) > 0 && apiKey.IsAdmin() {
		rule.AppliedTo = pq.StringArray(req.AppliedTo)
	}
	rule.UpdatedAt = time.Now()

	// Validate Solidity expression rules if config was updated and validator is available
	if req.Config != nil && rule.Type == types.RuleTypeEVMSolidityExpression && h.solidityValidator != nil {
		if err := h.validateSolidityRule(r.Context(), rule); err != nil {
			h.logger.Error("rule validation failed", "error", err, "rule_id", ruleID)
			h.writeError(w, "rule validation failed", http.StatusBadRequest)
			return
		}
	}

	// Validate evm_js rules when config is updated
	if req.Config != nil && rule.Type == types.RuleTypeEVMJS {
		if err := h.validateJSRule(rule, req.TestCases); err != nil {
			h.logger.Error("evm_js rule validation failed", "error", err, "rule_id", ruleID)
			h.writeError(w, fmt.Sprintf("evm_js rule validation failed: %v", err), http.StatusBadRequest)
			return
		}
	}

	// Update rule
	if err := h.ruleRepo.Update(r.Context(), rule); err != nil {
		h.logger.Error("failed to update rule", "error", err, "rule_id", ruleID)
		h.writeError(w, "failed to update rule", http.StatusInternalServerError)
		return
	}

	h.logger.Info("rule updated", "rule_id", ruleID)
	if h.auditLogger != nil {
		clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
		h.auditLogger.LogRuleUpdated(r.Context(), apiKey.ID, clientIP, rule.ID, rule.Name, oldConfig, rule.Config)
	}
	h.writeJSON(w, h.toRuleResponse(rule), http.StatusOK)
}

func (h *RuleHandler) listRules(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// Build filter
	filter := storage.RuleFilter{
		Limit: 100,
	}

	// Parse query parameters (strict: unknown enum values return 400)
	if chainType := query.Get("chain_type"); chainType != "" {
		if !validate.IsValidChainType(chainType) {
			h.writeError(w, "invalid chain_type filter", http.StatusBadRequest)
			return
		}
		ct := types.ChainType(chainType)
		filter.ChainType = &ct
	} else {
		// Default to EVM for /api/v1/evm/rules
		ct := types.ChainTypeEVM
		filter.ChainType = &ct
	}

	if signerAddress := query.Get("signer_address"); signerAddress != "" {
		if !validate.IsValidEthereumAddress(signerAddress) {
			h.writeError(w, "invalid signer_address: must be 0x followed by 40 hex characters", http.StatusBadRequest)
			return
		}
		filter.SignerAddress = &signerAddress
	}
	if owner := query.Get("owner"); owner != "" {
		filter.Owner = &owner
	}
	if ruleType := query.Get("type"); ruleType != "" {
		if !validate.IsValidRuleType(ruleType) {
			h.writeError(w, "invalid type filter", http.StatusBadRequest)
			return
		}
		rt := types.RuleType(validate.NormalizeRuleType(ruleType))
		filter.Type = &rt
	}
	if source := query.Get("source"); source != "" {
		if !validate.IsValidRuleSource(source) {
			h.writeError(w, "invalid source filter", http.StatusBadRequest)
			return
		}
		rs := types.RuleSource(source)
		filter.Source = &rs
	}
	if enabled := query.Get("enabled"); enabled != "" {
		if enabled == "true" {
			filter.EnabledOnly = true
		}
	}
	if limitStr := query.Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			if limit > 1000 {
				limit = 1000
			}
			filter.Limit = limit
		}
	}
	if offsetStr := query.Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}

	rules, err := h.ruleRepo.List(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list rules", "error", err)
		h.writeError(w, "failed to list rules", http.StatusInternalServerError)
		return
	}

	// Get total count (without limit/offset)
	countFilter := filter
	countFilter.Limit = 0
	countFilter.Offset = 0
	total, err := h.ruleRepo.Count(r.Context(), countFilter)
	if err != nil {
		h.logger.Error("failed to count rules", "error", err)
		h.writeError(w, "failed to count rules", http.StatusInternalServerError)
		return
	}

	// Scope rules for non-admin, non-dev callers (agent, strategy).
	// Agents/strategies only see rules that apply to them.
	// Admins and devs see all rules.
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey != nil && !apiKey.IsAdmin() && !apiKey.IsDev() {
		rules = rule.FilterRulesForCaller(rules, apiKey.ID)
		total = len(rules)
	}

	// Agent keys get redacted responses (no script source in config)
	redact := apiKey != nil && apiKey.IsAgent()

	resp := ListRulesResponse{
		Rules: make([]RuleResponse, 0, len(rules)),
		Total: total,
	}
	for _, r := range rules {
		rr := h.toRuleResponse(r)
		if redact {
			rr.Config = nil
		}
		resp.Rules = append(resp.Rules, rr)
	}

	h.writeJSON(w, resp, http.StatusOK)
}

func (h *RuleHandler) getRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	gotRule, err := h.ruleRepo.Get(r.Context(), types.RuleID(ruleID))
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "rule not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to get rule", "error", err, "rule_id", ruleID)
		h.writeError(w, "failed to get rule", http.StatusInternalServerError)
		return
	}

	// Scope check: non-admin, non-dev callers can only see rules that apply to them
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey != nil && !apiKey.IsAdmin() && !apiKey.IsDev() {
		filtered := rule.FilterRulesForCaller([]*types.Rule{gotRule}, apiKey.ID)
		if len(filtered) == 0 {
			h.writeError(w, "rule not found", http.StatusNotFound)
			return
		}
	}

	rr := h.toRuleResponse(gotRule)
	// Agent keys get redacted responses (no script source in config)
	if apiKey != nil && apiKey.IsAgent() {
		rr.Config = nil
	}
	h.writeJSON(w, rr, http.StatusOK)
}

func (h *RuleHandler) listBudgets(w http.ResponseWriter, r *http.Request, ruleID string) {
	budgets, err := h.budgetRepo.ListByRuleID(r.Context(), types.RuleID(ruleID))
	if err != nil {
		h.logger.Error("failed to list budgets", "error", err, "rule_id", ruleID)
		h.writeError(w, "failed to list budgets", http.StatusInternalServerError)
		return
	}
	if budgets == nil {
		budgets = []*types.RuleBudget{}
	}
	h.writeJSON(w, budgets, http.StatusOK)
}

func (h *RuleHandler) deleteRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Fetch rule first for readOnly and source guards
	rule, err := h.ruleRepo.Get(r.Context(), types.RuleID(ruleID))
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "rule not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to get rule", "error", err, "rule_id", ruleID)
		h.writeError(w, "failed to get rule", http.StatusInternalServerError)
		return
	}

	if h.readOnly {
		h.writeError(w, "rule deletion via API is disabled (security.rules_api_readonly)", http.StatusForbidden)
		return
	}
	if rule.Source == types.RuleSourceConfig {
		h.writeError(w, "cannot delete config-sourced rules via API", http.StatusForbidden)
		return
	}

	// Immutable check
	if rule.Immutable {
		h.writeError(w, "cannot delete immutable rule", http.StatusForbidden)
		return
	}

	// Ownership check: only owner or admin can delete
	if !apiKey.IsAdmin() && rule.Owner != apiKey.ID {
		h.writeError(w, "permission denied: can only delete own rules", http.StatusForbidden)
		return
	}

	if err := h.ruleRepo.Delete(r.Context(), rule.ID); err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "rule not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to delete rule", "error", err, "rule_id", ruleID)
		h.writeError(w, "failed to delete rule", http.StatusInternalServerError)
		return
	}

	h.logger.Info("rule deleted", "rule_id", ruleID)
	if h.auditLogger != nil {
		clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
		h.auditLogger.LogRuleDeleted(r.Context(), apiKey.ID, clientIP, rule.ID)
	}
	w.WriteHeader(http.StatusNoContent)
}

// approveRule handles POST /api/v1/evm/rules/{id}/approve (admin only via RBAC)
func (h *RuleHandler) approveRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Only admin can approve (enforced by RBAC middleware PermApproveRule,
	// but double-check here for defense in depth)
	if !apiKey.IsAdmin() {
		h.writeError(w, "permission denied: only admin can approve rules", http.StatusForbidden)
		return
	}

	rule, err := h.ruleRepo.Get(r.Context(), types.RuleID(ruleID))
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "rule not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to get rule", "error", err, "rule_id", ruleID)
		h.writeError(w, "failed to get rule", http.StatusInternalServerError)
		return
	}

	if rule.Status != types.RuleStatusPendingApproval {
		h.writeError(w, fmt.Sprintf("rule is not pending approval (current status: %s)", rule.Status), http.StatusBadRequest)
		return
	}

	rule.Status = types.RuleStatusActive
	approvedBy := apiKey.ID
	rule.ApprovedBy = &approvedBy
	rule.UpdatedAt = time.Now()

	if err := h.ruleRepo.Update(r.Context(), rule); err != nil {
		h.logger.Error("failed to approve rule", "error", err, "rule_id", ruleID)
		h.writeError(w, "failed to approve rule", http.StatusInternalServerError)
		return
	}

	h.logger.Info("rule approved", "rule_id", ruleID, "approved_by", apiKey.ID)
	if h.auditLogger != nil {
		clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
		h.auditLogger.LogRuleApproved(r.Context(), apiKey.ID, clientIP, rule.ID, rule.Owner)
	}
	h.writeJSON(w, h.toRuleResponse(rule), http.StatusOK)
}

// rejectRule handles POST /api/v1/evm/rules/{id}/reject (admin only via RBAC)
func (h *RuleHandler) rejectRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !apiKey.IsAdmin() {
		h.writeError(w, "permission denied: only admin can reject rules", http.StatusForbidden)
		return
	}

	var req RejectRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Allow empty body (reason is optional)
		req.Reason = ""
	}

	rule, err := h.ruleRepo.Get(r.Context(), types.RuleID(ruleID))
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "rule not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to get rule", "error", err, "rule_id", ruleID)
		h.writeError(w, "failed to get rule", http.StatusInternalServerError)
		return
	}

	if rule.Status != types.RuleStatusPendingApproval {
		h.writeError(w, fmt.Sprintf("rule is not pending approval (current status: %s)", rule.Status), http.StatusBadRequest)
		return
	}

	rule.Status = types.RuleStatusRejected
	rule.UpdatedAt = time.Now()

	if err := h.ruleRepo.Update(r.Context(), rule); err != nil {
		h.logger.Error("failed to reject rule", "error", err, "rule_id", ruleID)
		h.writeError(w, "failed to reject rule", http.StatusInternalServerError)
		return
	}

	h.logger.Info("rule rejected", "rule_id", ruleID, "rejected_by", apiKey.ID, "reason", req.Reason)
	if h.auditLogger != nil {
		clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
		h.auditLogger.LogRuleRejected(r.Context(), apiKey.ID, clientIP, rule.ID, rule.Owner, req.Reason)
	}
	h.writeJSON(w, h.toRuleResponse(rule), http.StatusOK)
}

func (h *RuleHandler) toRuleResponse(rule *types.Rule) RuleResponse {
	resp := RuleResponse{
		ID:          string(rule.ID),
		Name:        rule.Name,
		Description: rule.Description,
		Type:        string(rule.Type),
		Mode:        string(rule.Mode),
		Source:      string(rule.Source),
		Config:      rule.Config,
		Enabled:     rule.Enabled,
		CreatedAt:   rule.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   rule.UpdatedAt.Format(time.RFC3339),
		MatchCount:  rule.MatchCount,
		Immutable:   rule.Immutable,
	}

	if rule.ChainType != nil {
		ct := string(*rule.ChainType)
		resp.ChainType = &ct
	}
	if rule.ChainID != nil {
		resp.ChainID = rule.ChainID
	}
	if rule.Owner != "" {
		owner := rule.Owner
		resp.Owner = &owner
	}
	if len(rule.AppliedTo) > 0 {
		resp.AppliedTo = []string(rule.AppliedTo)
	}
	if rule.Status != "" {
		resp.Status = string(rule.Status)
	}
	if rule.ApprovedBy != nil {
		resp.ApprovedBy = rule.ApprovedBy
	}
	if rule.SignerAddress != nil {
		resp.SignerAddress = rule.SignerAddress
	}
	if rule.ExpiresAt != nil {
		expiresAt := rule.ExpiresAt.Format(time.RFC3339)
		resp.ExpiresAt = &expiresAt
	}
	if rule.LastMatchedAt != nil {
		lastMatchedAt := rule.LastMatchedAt.Format(time.RFC3339)
		resp.LastMatchedAt = &lastMatchedAt
	}
	if rule.BudgetPeriod != nil && *rule.BudgetPeriod > 0 {
		resp.BudgetPeriod = rule.BudgetPeriod.String()
	}
	if rule.BudgetPeriodStart != nil {
		s := rule.BudgetPeriodStart.Format(time.RFC3339)
		resp.BudgetPeriodStart = &s
	}

	return resp
}

func (h *RuleHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

func (h *RuleHandler) writeError(w http.ResponseWriter, message string, status int) {
	h.writeJSON(w, ErrorResponse{Error: message}, status)
}

// validateSolidityRule validates a Solidity expression rule using the validator
func (h *RuleHandler) validateSolidityRule(ctx context.Context, rule *types.Rule) error {
	result, err := h.solidityValidator.ValidateRule(ctx, rule)
	if err != nil {
		return err
	}
	if !result.Valid {
		if result.SyntaxError != nil {
			return fmt.Errorf("syntax error: %s", result.SyntaxError.Message)
		}
		if result.FailedTestCases > 0 {
			return fmt.Errorf("%d test case(s) failed", result.FailedTestCases)
		}
		return fmt.Errorf("validation failed")
	}
	return nil
}

// validateJSRule validates an evm_js rule by running its test cases through the JS evaluator.
// Requires at least 1 positive and 1 negative test case. Runs each test case in isolated mode.
func (h *RuleHandler) validateJSRule(rule *types.Rule, testCases []JSRuleTestCase) error {
	if h.jsEvaluator == nil {
		return fmt.Errorf("JS evaluator not available")
	}

	// Enforce test case requirement
	var pos, neg int
	for _, tc := range testCases {
		if tc.ExpectPass {
			pos++
		} else {
			neg++
		}
	}
	if err := ruleconfig.ValidateJSRuleTestCasesRequirement(pos, neg); err != nil {
		return err
	}

	// Parse the rule config
	var cfg evmchain.JSRuleConfig
	if err := json.Unmarshal(rule.Config, &cfg); err != nil {
		return fmt.Errorf("invalid evm_js config: %w", err)
	}

	// Run each test case
	var failed []string
	for _, tc := range testCases {
		if tc.Name == "" {
			return fmt.Errorf("test case name is required")
		}
		req, parsed, err := evmchain.TestCaseInputToSignRequest(tc.Input)
		if err != nil {
			failed = append(failed, fmt.Sprintf("test %q: invalid input: %v", tc.Name, err))
			continue
		}
		ruleInput, err := evmchain.BuildRuleInput(req, parsed)
		if err != nil {
			failed = append(failed, fmt.Sprintf("test %q: build input: %v", tc.Name, err))
			continue
		}
		// Build config map from the rule's raw JSON config so user-defined keys (e.g. max_message_length)
		// are available to the JS script via the global `config` object.
		var cfgMap map[string]interface{}
		if len(rule.Config) > 0 {
			if err := json.Unmarshal(rule.Config, &cfgMap); err != nil {
				return fmt.Errorf("failed to unmarshal rule config for JS validation: %w", err)
			}
		}
		result := h.jsEvaluator.ValidateWithInput(cfg.Script, ruleInput, cfgMap)

		// For isolated validation: valid=true means pass, valid=false means fail
		actualPass := result.Valid
		if rule.Mode == types.RuleModeBlocklist {
			// Blocklist: script returns valid=false when "violation detected" (should block).
			// A blocklist test case with expect_pass=true means "should NOT be blocked" → valid=true.
			// expect_pass=false means "should be blocked" → valid=false.
			// So actualPass matches result.Valid directly.
		}

		if actualPass != tc.ExpectPass {
			if tc.ExpectPass {
				failed = append(failed, fmt.Sprintf("test %q: expected pass but got: %s", tc.Name, result.Reason))
			} else {
				failed = append(failed, fmt.Sprintf("test %q: expected fail but passed", tc.Name))
			}
			continue
		}

		// Optionally check expect_reason
		if tc.ExpectReason != "" && !tc.ExpectPass {
			if !strings.Contains(result.Reason, tc.ExpectReason) {
				failed = append(failed, fmt.Sprintf("test %q: expected reason containing %q but got %q", tc.Name, tc.ExpectReason, result.Reason))
			}
		}
	}

	if len(failed) > 0 {
		return fmt.Errorf("%d test case(s) failed:\n  - %s", len(failed), strings.Join(failed, "\n  - "))
	}
	return nil
}
