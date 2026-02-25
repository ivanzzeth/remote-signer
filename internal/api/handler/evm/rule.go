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
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// RuleHandler handles rule management endpoints
type RuleHandler struct {
	ruleRepo          storage.RuleRepository
	solidityValidator *evm.SolidityRuleValidator
	logger            *slog.Logger
}

// RuleHandlerOption is a functional option for RuleHandler
type RuleHandlerOption func(*RuleHandler)

// WithSolidityValidator sets the Solidity rule validator for the handler
func WithSolidityValidator(validator *evm.SolidityRuleValidator) RuleHandlerOption {
	return func(h *RuleHandler) {
		h.solidityValidator = validator
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
}

// UpdateRuleRequest represents a request to update an existing rule
type UpdateRuleRequest struct {
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Enabled     *bool                  `json:"enabled,omitempty"`
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

	// Validate rule config based on type
	if err := h.validateRuleConfig(req.Type, req.Config); err != nil {
		h.writeError(w, err.Error(), http.StatusBadRequest)
		return
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
	rule.UpdatedAt = time.Now()

	// Validate Solidity expression rules if config was updated and validator is available
	if req.Config != nil && rule.Type == types.RuleTypeEVMSolidityExpression && h.solidityValidator != nil {
		if err := h.validateSolidityRule(r.Context(), rule); err != nil {
			h.logger.Error("rule validation failed", "error", err, "rule_id", ruleID)
			h.writeError(w, "rule validation failed", http.StatusBadRequest)
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

	// Parse query parameters
	if chainType := query.Get("chain_type"); chainType != "" {
		ct := types.ChainType(chainType)
		filter.ChainType = &ct
	} else {
		// Default to EVM for /api/v1/evm/rules
		ct := types.ChainTypeEVM
		filter.ChainType = &ct
	}

	if signerAddress := query.Get("signer_address"); signerAddress != "" {
		filter.SignerAddress = &signerAddress
	}
	if apiKeyID := query.Get("api_key_id"); apiKeyID != "" {
		filter.APIKeyID = &apiKeyID
	}
	if ruleType := query.Get("type"); ruleType != "" {
		rt := types.RuleType(ruleType)
		filter.Type = &rt
	}
	if source := query.Get("source"); source != "" {
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

// ethAddressRegex matches a valid Ethereum address (0x followed by 40 hex chars)
var ethAddressRegex = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

// validSignTypes defines the known sign types
var validSignTypes = map[string]bool{
	"personal":    true,
	"typed_data":  true,
	"transaction": true,
	"hash":        true,
	"raw_message": true,
	"eip191":      true,
}

// maxExpressionLength is the maximum allowed length for Solidity expressions (10 KB)
const maxExpressionLength = 10 * 1024

// dangerousSolidityPatterns are patterns that should be rejected in expression mode
var dangerousSolidityPatterns = regexp.MustCompile(`(?i)\b(selfdestruct|delegatecall|create2|suicide)\b`)

// validateRuleConfig validates the config for a given rule type.
// This ensures that the server rejects malformed or dangerous configurations.
func (h *RuleHandler) validateRuleConfig(ruleType string, config map[string]interface{}) error {
	switch types.RuleType(ruleType) {
	case types.RuleTypeEVMAddressList:
		return h.validateAddressListConfig(config)
	case types.RuleTypeEVMValueLimit:
		return h.validateValueLimitConfig(config)
	case types.RuleTypeSignerRestriction:
		return h.validateSignerRestrictionConfig(config)
	case types.RuleTypeSignTypeRestriction:
		return h.validateSignTypeRestrictionConfig(config)
	case types.RuleTypeEVMSolidityExpression:
		return h.validateSolidityExpressionConfig(config)
	case types.RuleTypeEVMContractMethod:
		// Contract method rules have their own validation elsewhere
		return nil
	case types.RuleTypeEVMJS:
		return h.validateJSRuleConfig(config)
	case types.RuleTypeChainRestriction, types.RuleTypeMessagePattern:
		// These rule types have simpler validation
		return nil
	default:
		return fmt.Errorf("unknown rule type: %s", ruleType)
	}
}

func (h *RuleHandler) validateAddressListConfig(config map[string]interface{}) error {
	addressesRaw, ok := config["addresses"]
	if !ok {
		return fmt.Errorf("config.addresses is required for evm_address_list rules")
	}

	addresses, ok := addressesRaw.([]interface{})
	if !ok {
		return fmt.Errorf("config.addresses must be an array")
	}

	if len(addresses) == 0 {
		return fmt.Errorf("config.addresses must not be empty")
	}

	for i, addr := range addresses {
		addrStr, ok := addr.(string)
		if !ok {
			return fmt.Errorf("config.addresses[%d] must be a string", i)
		}
		if !ethAddressRegex.MatchString(addrStr) {
			return fmt.Errorf("config.addresses[%d] is not a valid Ethereum address: %s", i, addrStr)
		}
	}

	return nil
}

func (h *RuleHandler) validateValueLimitConfig(config map[string]interface{}) error {
	maxValueRaw, ok := config["max_value"]
	if !ok {
		return fmt.Errorf("config.max_value is required for evm_value_limit rules")
	}

	maxValueStr, ok := maxValueRaw.(string)
	if !ok {
		return fmt.Errorf("config.max_value must be a string (wei value)")
	}

	if maxValueStr == "" {
		return fmt.Errorf("config.max_value must not be empty")
	}

	// Validate it's a valid numeric string (positive integer)
	if _, err := strconv.ParseUint(maxValueStr, 10, 64); err != nil {
		// Could be a very large number — try to validate it's all digits
		for _, c := range maxValueStr {
			if c < '0' || c > '9' {
				return fmt.Errorf("config.max_value must be a positive numeric string, got: %s", maxValueStr)
			}
		}
	}

	return nil
}

func (h *RuleHandler) validateSignerRestrictionConfig(config map[string]interface{}) error {
	signersRaw, ok := config["allowed_signers"]
	if !ok {
		return fmt.Errorf("config.allowed_signers is required for signer_restriction rules")
	}

	signers, ok := signersRaw.([]interface{})
	if !ok {
		return fmt.Errorf("config.allowed_signers must be an array")
	}

	if len(signers) == 0 {
		return fmt.Errorf("config.allowed_signers must not be empty")
	}

	for i, signer := range signers {
		signerStr, ok := signer.(string)
		if !ok {
			return fmt.Errorf("config.allowed_signers[%d] must be a string", i)
		}
		if !ethAddressRegex.MatchString(signerStr) {
			return fmt.Errorf("config.allowed_signers[%d] is not a valid Ethereum address: %s", i, signerStr)
		}
	}

	return nil
}

func (h *RuleHandler) validateJSRuleConfig(config map[string]interface{}) error {
	scriptRaw, ok := config["script"]
	if !ok {
		return fmt.Errorf("config.script is required for evm_js rules")
	}
	script, ok := scriptRaw.(string)
	if !ok {
		return fmt.Errorf("config.script must be a string")
	}
	if strings.TrimSpace(script) == "" {
		return fmt.Errorf("config.script must not be empty")
	}
	if mode, ok := config["delegate_mode"].(string); ok && mode == "per_item" {
		itemsKey, ok := config["items_key"].(string)
		if !ok || strings.TrimSpace(itemsKey) == "" {
			itemsKey = "items"
		}
		// items_key is required for per_item; validated at evaluation time
	}
	return nil
}

func (h *RuleHandler) validateSignTypeRestrictionConfig(config map[string]interface{}) error {
	typesRaw, ok := config["allowed_sign_types"]
	if !ok {
		return fmt.Errorf("config.allowed_sign_types is required for sign_type_restriction rules")
	}

	signTypes, ok := typesRaw.([]interface{})
	if !ok {
		return fmt.Errorf("config.allowed_sign_types must be an array")
	}

	if len(signTypes) == 0 {
		return fmt.Errorf("config.allowed_sign_types must not be empty")
	}

	for i, st := range signTypes {
		stStr, ok := st.(string)
		if !ok {
			return fmt.Errorf("config.allowed_sign_types[%d] must be a string", i)
		}
		if !validSignTypes[stStr] {
			return fmt.Errorf("config.allowed_sign_types[%d] is not a valid sign type: %s", i, stStr)
		}
	}

	return nil
}

func (h *RuleHandler) validateSolidityExpressionConfig(config map[string]interface{}) error {
	// Check expression length
	if expr, ok := config["expression"].(string); ok {
		if len(expr) > maxExpressionLength {
			return fmt.Errorf("expression is too long (%d bytes, max %d)", len(expr), maxExpressionLength)
		}
		// Check for dangerous patterns
		if dangerousSolidityPatterns.MatchString(expr) {
			return fmt.Errorf("expression contains dangerous patterns (selfdestruct, delegatecall, create2 are not allowed)")
		}
	}

	// Check typed_data_expression length
	if expr, ok := config["typed_data_expression"].(string); ok {
		if len(expr) > maxExpressionLength {
			return fmt.Errorf("typed_data_expression is too long (%d bytes, max %d)", len(expr), maxExpressionLength)
		}
		if dangerousSolidityPatterns.MatchString(expr) {
			return fmt.Errorf("typed_data_expression contains dangerous patterns")
		}
	}

	// Check functions length
	if funcs, ok := config["functions"].(string); ok {
		if len(funcs) > maxExpressionLength {
			return fmt.Errorf("functions is too long (%d bytes, max %d)", len(funcs), maxExpressionLength)
		}
		if dangerousSolidityPatterns.MatchString(funcs) {
			return fmt.Errorf("functions contains dangerous patterns")
		}
	}

	// Check typed_data_functions length
	if funcs, ok := config["typed_data_functions"].(string); ok {
		if len(funcs) > maxExpressionLength {
			return fmt.Errorf("typed_data_functions is too long (%d bytes, max %d)", len(funcs), maxExpressionLength)
		}
		if dangerousSolidityPatterns.MatchString(funcs) {
			return fmt.Errorf("typed_data_functions contains dangerous patterns")
		}
	}

	return nil
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
