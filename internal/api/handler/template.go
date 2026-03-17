package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/validate"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// TemplateHandler handles template management and instance creation endpoints
type TemplateHandler struct {
	templateRepo    storage.TemplateRepository
	templateService *service.TemplateService
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

// TemplateResponse represents a template in API responses
type TemplateResponse struct {
	ID             string              `json:"id"`
	Name           string              `json:"name"`
	Description    string              `json:"description,omitempty"`
	Type           string              `json:"type"`
	Mode           string              `json:"mode"`
	Source         string              `json:"source"`
	Variables      []TemplateVarResponse `json:"variables,omitempty"`
	Config         json.RawMessage     `json:"config,omitempty"`
	BudgetMetering json.RawMessage     `json:"budget_metering,omitempty"`
	Enabled        bool                `json:"enabled"`
	CreatedAt      string              `json:"created_at"`
	UpdatedAt      string              `json:"updated_at"`
}

// TemplateVarResponse represents a template variable in API responses
type TemplateVarResponse struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
}

// ListTemplatesResponse represents the response for listing templates
type ListTemplatesResponse struct {
	Templates []TemplateResponse `json:"templates"`
	Total     int                `json:"total"`
}

// CreateTemplateRequest represents a request to create a new template via API
type CreateTemplateRequest struct {
	Name           string                 `json:"name"`
	Description    string                 `json:"description,omitempty"`
	Type           string                 `json:"type"`
	Mode           string                 `json:"mode"`
	Variables      []TemplateVarRequest   `json:"variables,omitempty"`
	Config         map[string]interface{} `json:"config"`
	// BudgetMetering (optional) configures how a template instance measures "spend amount"
	// for budget enforcement.
	//
	// Expected keys:
	// - method: "none" | "count_only" | "tx_value" | "calldata_param" | "typed_data_field" | "js"
	// - unit:   budget identity string (recommended: include chain+asset identity, e.g. "${chain_id}:${token_address}")
	//
	// Notes:
	// - For method "js" (evm_js rules), the script may implement validateBudget(input) and return bigint/decimal-string.
	BudgetMetering map[string]interface{} `json:"budget_metering,omitempty"`
	TestVariables  map[string]string      `json:"test_variables,omitempty"`
	Enabled        bool                   `json:"enabled"`
}

// TemplateVarRequest represents a template variable in a create/update request
type TemplateVarRequest struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
}

// UpdateTemplateRequest represents a request to update an existing template
type UpdateTemplateRequest struct {
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Enabled     *bool                  `json:"enabled,omitempty"`
}

// InstantiateTemplateRequest represents a request to create a rule instance from a template
type InstantiateTemplateRequest struct {
	TemplateName  string            `json:"template_name,omitempty"`
	Name          string            `json:"name,omitempty"`
	Variables     map[string]string `json:"variables"`
	ChainType     *string           `json:"chain_type,omitempty"`
	ChainID       *string           `json:"chain_id,omitempty"`
	APIKeyID      *string           `json:"api_key_id,omitempty"`
	SignerAddress *string           `json:"signer_address,omitempty"`
	ExpiresAt     *time.Time        `json:"expires_at,omitempty"`
	ExpiresIn     *string           `json:"expires_in,omitempty"` // duration string e.g. "24h", "168h"
	Budget        *BudgetRequest    `json:"budget,omitempty"`
	Schedule      *ScheduleRequest  `json:"schedule,omitempty"`
}

// BudgetRequest represents budget config in an instantiate request
type BudgetRequest struct {
	MaxTotal   string `json:"max_total"`
	MaxPerTx   string `json:"max_per_tx"`
	MaxTxCount int    `json:"max_tx_count,omitempty"`
	AlertPct   int    `json:"alert_pct,omitempty"`
}

// ScheduleRequest represents schedule config in an instantiate request
type ScheduleRequest struct {
	Period  string     `json:"period"` // duration string e.g. "24h"
	StartAt *time.Time `json:"start_at,omitempty"`
}

// InstantiateTemplateResponse represents the response for creating a rule instance
type InstantiateTemplateResponse struct {
	Rule   json.RawMessage `json:"rule"`
	Budget json.RawMessage `json:"budget,omitempty"`
}

// ServeHTTP handles /api/v1/templates and /api/v1/templates/{id}
func (h *TemplateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get API key from context (for audit)
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Determine if this is a list request or a specific template request
	// Path: /api/v1/templates or /api/v1/templates/{id} or /api/v1/templates/{id}/instantiate
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/templates")
	path = strings.TrimPrefix(path, "/")

	if path == "" {
		// Collection operations: GET /api/v1/templates or POST /api/v1/templates
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

	// Check for /instantiate sub-path
	if strings.HasSuffix(path, "/instantiate") {
		templateID := strings.TrimSuffix(path, "/instantiate")
		if r.Method == http.MethodPost {
			h.instantiateTemplate(w, r, templateID)
		} else {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	// Check for /revoke sub-path (on instance rule, not template)
	// This is handled separately: POST /api/v1/templates/instances/{ruleID}/revoke
	// But for simplicity, we handle it under the template handler

	// Specific template operations: /api/v1/templates/{id}
	templateID := path
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

func (h *TemplateHandler) listTemplates(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// Build filter
	filter := storage.TemplateFilter{
		Limit: 100,
	}

	if ruleType := query.Get("type"); ruleType != "" {
		rt := types.RuleType(ruleType)
		filter.Type = &rt
	}
	if source := query.Get("source"); source != "" {
		rs := types.RuleSource(source)
		filter.Source = &rs
	}
	if enabled := query.Get("enabled"); enabled == "true" {
		filter.EnabledOnly = true
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

	templates, err := h.templateRepo.List(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list templates", "error", err)
		h.writeError(w, "failed to list templates", http.StatusInternalServerError)
		return
	}

	// Get total count
	countFilter := filter
	countFilter.Limit = 0
	countFilter.Offset = 0
	total, err := h.templateRepo.Count(r.Context(), countFilter)
	if err != nil {
		h.logger.Error("failed to count templates", "error", err)
		h.writeError(w, "failed to count templates", http.StatusInternalServerError)
		return
	}

	resp := ListTemplatesResponse{
		Templates: make([]TemplateResponse, 0, len(templates)),
		Total:     total,
	}
	for _, tmpl := range templates {
		resp.Templates = append(resp.Templates, h.toTemplateResponse(tmpl))
	}

	h.writeJSON(w, resp, http.StatusOK)
}

func (h *TemplateHandler) getTemplate(w http.ResponseWriter, r *http.Request, templateID string) {
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

	h.writeJSON(w, h.toTemplateResponse(tmpl), http.StatusOK)
}

func (h *TemplateHandler) createTemplate(w http.ResponseWriter, r *http.Request) {
	if h.readOnly {
		h.writeError(w, "template creation via API is disabled (security.rules_api_readonly)", http.StatusForbidden)
		return
	}

	var req CreateTemplateRequest
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
	if !validate.IsValidRuleType(req.Type) {
		h.writeError(w, "invalid rule type", http.StatusBadRequest)
		return
	}
	if req.Mode == "" {
		h.writeError(w, "mode is required", http.StatusBadRequest)
		return
	}
	if err := validate.ValidateRuleMode(req.Mode); err != nil {
		h.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Template config may contain variable placeholders (e.g. ${target}); validated at instantiation time.

	// Marshal config
	configJSON, err := json.Marshal(req.Config)
	if err != nil {
		h.writeError(w, "invalid config", http.StatusBadRequest)
		return
	}

	// Marshal variables
	var variablesJSON []byte
	if len(req.Variables) > 0 {
		vars := make([]types.TemplateVariable, len(req.Variables))
		for i, v := range req.Variables {
			vars[i] = types.TemplateVariable{
				Name:        v.Name,
				Type:        v.Type,
				Description: v.Description,
				Required:    v.Required,
				Default:     v.Default,
			}
		}
		variablesJSON, err = json.Marshal(vars)
		if err != nil {
			h.writeError(w, "invalid variables", http.StatusBadRequest)
			return
		}
	}

	// Marshal budget metering
	var budgetMeteringJSON []byte
	if req.BudgetMetering != nil {
		budgetMeteringJSON, err = json.Marshal(req.BudgetMetering)
		if err != nil {
			h.writeError(w, "invalid budget_metering", http.StatusBadRequest)
			return
		}
	}

	// Marshal test variables
	var testVariablesJSON []byte
	if req.TestVariables != nil {
		testVariablesJSON, err = json.Marshal(req.TestVariables)
		if err != nil {
			h.writeError(w, "invalid test_variables", http.StatusBadRequest)
			return
		}
	}

	// Generate template ID
	tmplID := fmt.Sprintf("tmpl_api_%d", time.Now().UnixNano())

	tmpl := &types.RuleTemplate{
		ID:             tmplID,
		Name:           req.Name,
		Description:    req.Description,
		Type:           types.RuleType(req.Type),
		Mode:           types.RuleMode(req.Mode),
		Variables:      variablesJSON,
		Config:         configJSON,
		BudgetMetering: budgetMeteringJSON,
		TestVariables:  testVariablesJSON,
		Source:         types.RuleSourceAPI,
		Enabled:        req.Enabled,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	if err := h.templateRepo.Create(r.Context(), tmpl); err != nil {
		h.logger.Error("failed to create template", "error", err)
		h.writeError(w, "failed to create template", http.StatusInternalServerError)
		return
	}

	h.logger.Info("template created", "template_id", tmpl.ID, "name", tmpl.Name)
	h.writeJSON(w, h.toTemplateResponse(tmpl), http.StatusCreated)
}

func (h *TemplateHandler) updateTemplate(w http.ResponseWriter, r *http.Request, templateID string) {
	var req UpdateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Get existing template
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

	if h.readOnly {
		h.writeError(w, "template updates via API are disabled (security.rules_api_readonly)", http.StatusForbidden)
		return
	}

	// Protect config-sourced templates from API updates
	if tmpl.Source == types.RuleSourceConfig {
		h.writeError(w, "cannot update config-sourced templates via API", http.StatusForbidden)
		return
	}

	// Update fields if provided
	if req.Name != "" {
		tmpl.Name = req.Name
	}
	if req.Description != "" {
		tmpl.Description = req.Description
	}
	if req.Config != nil {
		// Template config may contain placeholders; structure validated at instantiation.
		configJSON, err := json.Marshal(req.Config)
		if err != nil {
			h.writeError(w, "invalid config", http.StatusBadRequest)
			return
		}
		tmpl.Config = configJSON
	}
	if req.Enabled != nil {
		tmpl.Enabled = *req.Enabled
	}
	tmpl.UpdatedAt = time.Now()

	if err := h.templateRepo.Update(r.Context(), tmpl); err != nil {
		h.logger.Error("failed to update template", "error", err, "template_id", templateID)
		h.writeError(w, "failed to update template", http.StatusInternalServerError)
		return
	}

	h.logger.Info("template updated", "template_id", templateID)
	h.writeJSON(w, h.toTemplateResponse(tmpl), http.StatusOK)
}

func (h *TemplateHandler) deleteTemplate(w http.ResponseWriter, r *http.Request, templateID string) {
	// Check if template exists and is API-sourced
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

	if h.readOnly {
		h.writeError(w, "template deletion via API is disabled (security.rules_api_readonly)", http.StatusForbidden)
		return
	}

	// Protect config-sourced templates
	if tmpl.Source == types.RuleSourceConfig {
		h.writeError(w, "cannot delete config-sourced templates via API", http.StatusForbidden)
		return
	}

	if err := h.templateRepo.Delete(r.Context(), templateID); err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "template not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to delete template", "error", err, "template_id", templateID)
		h.writeError(w, "failed to delete template", http.StatusInternalServerError)
		return
	}

	h.logger.Info("template deleted", "template_id", templateID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *TemplateHandler) instantiateTemplate(w http.ResponseWriter, r *http.Request, templateID string) {
	if h.readOnly {
		h.writeError(w, "template instantiation via API is disabled (security.rules_api_readonly)", http.StatusForbidden)
		return
	}

	var req InstantiateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Build CreateInstanceRequest
	instanceReq := &service.CreateInstanceRequest{
		TemplateID:   templateID,
		TemplateName: req.TemplateName,
		Name:         req.Name,
		Variables:    req.Variables,
		ChainType:    req.ChainType,
		ChainID:      req.ChainID,
		APIKeyID:     req.APIKeyID,
		SignerAddress: req.SignerAddress,
		ExpiresAt:    req.ExpiresAt,
	}

	// Parse expires_in duration string
	if req.ExpiresIn != nil {
		d, err := time.ParseDuration(*req.ExpiresIn)
		if err != nil {
			h.writeError(w, fmt.Sprintf("invalid expires_in duration: %s", *req.ExpiresIn), http.StatusBadRequest)
			return
		}
		instanceReq.ExpiresIn = &d
	}

	// Convert budget
	if req.Budget != nil {
		instanceReq.Budget = &service.BudgetConfig{
			MaxTotal:   req.Budget.MaxTotal,
			MaxPerTx:   req.Budget.MaxPerTx,
			MaxTxCount: req.Budget.MaxTxCount,
			AlertPct:   req.Budget.AlertPct,
		}
	}

	// Convert schedule
	if req.Schedule != nil {
		d, err := time.ParseDuration(req.Schedule.Period)
		if err != nil {
			h.writeError(w, fmt.Sprintf("invalid schedule period: %s", req.Schedule.Period), http.StatusBadRequest)
			return
		}
		instanceReq.Schedule = &service.ScheduleConfig{
			Period:  d,
			StartAt: req.Schedule.StartAt,
		}
	}

	// Apply RBAC ownership
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey != nil {
		// Resolve template to get mode for RBAC determination
		tmpl, err := h.templateService.ResolveTemplate(r.Context(), instanceReq)
		if err != nil {
			h.writeError(w, fmt.Sprintf("failed to resolve template: %s", err.Error()), http.StatusBadRequest)
			return
		}
		ownership, err := DetermineRuleOwnership(
			r.Context(), apiKey, nil,
			tmpl.Mode, h.requireApproval, h.apiKeyRepo,
		)
		if err != nil {
			h.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		instanceReq.Owner = ownership.Owner
		instanceReq.AppliedTo = []string(ownership.AppliedTo)
		instanceReq.Status = ownership.Status
	}

	// Create instance
	result, err := h.templateService.CreateInstance(r.Context(), instanceReq)
	if err != nil {
		h.logger.Error("failed to create instance", "error", err, "template_id", templateID)
		h.writeError(w, fmt.Sprintf("failed to create instance: %s", err.Error()), http.StatusBadRequest)
		return
	}

	// Build response
	resp := make(map[string]interface{})

	ruleJSON, err := json.Marshal(result.Rule)
	if err != nil {
		h.logger.Error("failed to marshal rule", "error", err)
		h.writeError(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}
	resp["rule"] = json.RawMessage(ruleJSON)

	if result.Budget != nil {
		budgetJSON, err := json.Marshal(result.Budget)
		if err != nil {
			h.logger.Error("failed to marshal budget", "error", err)
		} else {
			resp["budget"] = json.RawMessage(budgetJSON)
		}
	}

	// Include expanded sub-rules for template_bundle responses
	if len(result.SubRules) > 0 {
		subRulesJSON, err := json.Marshal(result.SubRules)
		if err != nil {
			h.logger.Error("failed to marshal sub-rules", "error", err)
		} else {
			resp["sub_rules"] = json.RawMessage(subRulesJSON)
		}
		if len(result.SubBudgets) > 0 {
			subBudgetsJSON, err := json.Marshal(result.SubBudgets)
			if err != nil {
				h.logger.Error("failed to marshal sub-budgets", "error", err)
			} else {
				resp["sub_budgets"] = json.RawMessage(subBudgetsJSON)
			}
		}
	}

	h.logger.Info("instance created from template",
		"template_id", templateID,
		"rule_id", result.Rule.ID,
	)
	h.writeJSON(w, resp, http.StatusCreated)
}

func (h *TemplateHandler) revokeInstance(w http.ResponseWriter, r *http.Request, ruleID string) {
	if h.readOnly {
		h.writeError(w, "instance revocation via API is disabled (security.rules_api_readonly)", http.StatusForbidden)
		return
	}

	if err := h.templateService.RevokeInstance(r.Context(), types.RuleID(ruleID)); err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "instance not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to revoke instance", "error", err, "rule_id", ruleID)
		h.writeError(w, fmt.Sprintf("failed to revoke instance: %s", err.Error()), http.StatusBadRequest)
		return
	}

	h.logger.Info("instance revoked", "rule_id", ruleID)
	h.writeJSON(w, map[string]string{"status": "revoked", "rule_id": ruleID}, http.StatusOK)
}

func (h *TemplateHandler) toTemplateResponse(tmpl *types.RuleTemplate) TemplateResponse {
	resp := TemplateResponse{
		ID:          tmpl.ID,
		Name:        tmpl.Name,
		Description: tmpl.Description,
		Type:        string(tmpl.Type),
		Mode:        string(tmpl.Mode),
		Source:      string(tmpl.Source),
		Config:      tmpl.Config,
		Enabled:     tmpl.Enabled,
		CreatedAt:   tmpl.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   tmpl.UpdatedAt.Format(time.RFC3339),
	}

	// Parse variables
	if len(tmpl.Variables) > 0 {
		var vars []types.TemplateVariable
		if err := json.Unmarshal(tmpl.Variables, &vars); err == nil {
			resp.Variables = make([]TemplateVarResponse, len(vars))
			for i, v := range vars {
				resp.Variables[i] = TemplateVarResponse{
					Name:        v.Name,
					Type:        v.Type,
					Description: v.Description,
					Required:    v.Required,
					Default:     v.Default,
				}
			}
		}
	}

	if len(tmpl.BudgetMetering) > 0 {
		resp.BudgetMetering = tmpl.BudgetMetering
	}

	return resp
}

func (h *TemplateHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

func (h *TemplateHandler) writeError(w http.ResponseWriter, message string, status int) {
	h.writeJSON(w, ErrorResponse{Error: message}, status)
}
