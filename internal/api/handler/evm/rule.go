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
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/ruleconfig"
	"github.com/ivanzzeth/remote-signer/internal/validate"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ruleIDPattern validates rule ID format: "rule_" prefix followed by UUID or "cfg_" prefix followed by index.
var ruleIDPattern = regexp.MustCompile(`^(rule_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|cfg_\d+)$`)

// RuleHandler handles rule management endpoints
type RuleHandler struct {
	ruleRepo          storage.RuleRepository
	solidityValidator *evmchain.SolidityRuleValidator
	jsEvaluator       *evmchain.JSRuleEvaluator
	logger            *slog.Logger
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
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Description   string          `json:"description,omitempty"`
	Type          string          `json:"type"`
	Mode          string          `json:"mode"`
	Source        string          `json:"source"`
	ChainType     *string         `json:"chain_type,omitempty"`
	ChainID       *string         `json:"chain_id,omitempty"`
	APIKeyID      *string         `json:"api_key_id,omitempty"`
	SignerAddress *string         `json:"signer_address,omitempty"`
	Config        json.RawMessage `json:"config,omitempty"`
	Enabled       bool            `json:"enabled"`
	CreatedAt     string          `json:"created_at"`
	UpdatedAt     string          `json:"updated_at"`
	ExpiresAt     *string         `json:"expires_at,omitempty"`
	MatchCount    uint64          `json:"match_count"`
	LastMatchedAt *string         `json:"last_matched_at,omitempty"`
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

	// Specific rule operations: /api/v1/evm/rules/{id}
	ruleID := path
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
	APIKeyID      *string                `json:"api_key_id,omitempty"`
	SignerAddress *string                `json:"signer_address,omitempty"`
	Config        map[string]interface{} `json:"config"`
	Enabled       bool                   `json:"enabled"`
	TestCases     []JSRuleTestCase       `json:"test_cases,omitempty"` // required for evm_js rules
}

// UpdateRuleRequest represents a request to update an existing rule
type UpdateRuleRequest struct {
	Name          string                 `json:"name,omitempty"`
	Description   string                 `json:"description,omitempty"`
	Config        map[string]interface{} `json:"config,omitempty"`
	ChainType     *string                `json:"chain_type,omitempty"`
	ChainID       *string                `json:"chain_id,omitempty"`
	APIKeyID      *string                `json:"api_key_id,omitempty"`
	SignerAddress *string                `json:"signer_address,omitempty"`
	Enabled       *bool                  `json:"enabled,omitempty"`
	TestCases     []JSRuleTestCase       `json:"test_cases,omitempty"` // required for evm_js when updating config
}

func (h *RuleHandler) createRule(w http.ResponseWriter, r *http.Request) {
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

	// Build rule
	rule := &types.Rule{
		ID:          ruleID,
		Name:        req.Name,
		Description: req.Description,
		Type:        types.RuleType(req.Type),
		Mode:        types.RuleMode(req.Mode),
		Source:      types.RuleSourceAPI,
		Config:      configJSON,
		Enabled:     req.Enabled,
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
	if req.APIKeyID != nil {
		rule.APIKeyID = req.APIKeyID
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

	h.logger.Info("rule created", "rule_id", rule.ID, "name", rule.Name)
	h.writeJSON(w, h.toRuleResponse(rule), http.StatusCreated)
}

func (h *RuleHandler) updateRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	var req UpdateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
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
	if req.APIKeyID != nil {
		rule.APIKeyID = req.APIKeyID
	}
	if req.SignerAddress != nil {
		if !validate.IsValidEthereumAddress(*req.SignerAddress) {
			h.writeError(w, "invalid signer_address: must be 0x followed by 40 hex characters", http.StatusBadRequest)
			return
		}
		rule.SignerAddress = req.SignerAddress
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
	if apiKeyID := query.Get("api_key_id"); apiKeyID != "" {
		filter.APIKeyID = &apiKeyID
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

	resp := ListRulesResponse{
		Rules: make([]RuleResponse, 0, len(rules)),
		Total: total,
	}
	for _, rule := range rules {
		resp.Rules = append(resp.Rules, h.toRuleResponse(rule))
	}

	h.writeJSON(w, resp, http.StatusOK)
}

func (h *RuleHandler) getRule(w http.ResponseWriter, r *http.Request, ruleID string) {
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

	h.writeJSON(w, h.toRuleResponse(rule), http.StatusOK)
}

func (h *RuleHandler) deleteRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	err := h.ruleRepo.Delete(r.Context(), types.RuleID(ruleID))
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "rule not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to delete rule", "error", err, "rule_id", ruleID)
		h.writeError(w, "failed to delete rule", http.StatusInternalServerError)
		return
	}

	h.logger.Info("rule deleted", "rule_id", ruleID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *RuleHandler) toRuleResponse(rule *types.Rule) RuleResponse {
	resp := RuleResponse{
		ID:            string(rule.ID),
		Name:          rule.Name,
		Description:   rule.Description,
		Type:          string(rule.Type),
		Mode:          string(rule.Mode),
		Source:        string(rule.Source),
		Config:        rule.Config,
		Enabled:       rule.Enabled,
		CreatedAt:     rule.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     rule.UpdatedAt.Format(time.RFC3339),
		MatchCount:    rule.MatchCount,
	}

	if rule.ChainType != nil {
		ct := string(*rule.ChainType)
		resp.ChainType = &ct
	}
	if rule.ChainID != nil {
		resp.ChainID = rule.ChainID
	}
	if rule.APIKeyID != nil {
		resp.APIKeyID = rule.APIKeyID
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
		result := h.jsEvaluator.ValidateWithInput(cfg.Script, ruleInput, nil)

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
