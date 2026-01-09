package evm

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// RuleHandler handles rule management endpoints
type RuleHandler struct {
	ruleRepo storage.RuleRepository
	logger   *slog.Logger
}

// NewRuleHandler creates a new rule handler
func NewRuleHandler(ruleRepo storage.RuleRepository, logger *slog.Logger) (*RuleHandler, error) {
	if ruleRepo == nil {
		return nil, fmt.Errorf("rule repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &RuleHandler{
		ruleRepo: ruleRepo,
		logger:   logger,
	}, nil
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

	// Generate rule ID
	ruleID := types.RuleID(fmt.Sprintf("rule_%d", time.Now().UnixNano()))

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
