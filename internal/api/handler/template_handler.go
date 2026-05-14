package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/validate"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

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
				Type:        types.VariableType(v.Type),
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
		TemplateID:    templateID,
		TemplateName:  req.TemplateName,
		Name:          req.Name,
		Variables:     req.Variables,
		ChainType:     req.ChainType,
		ChainID:       req.ChainID,
		APIKeyID:      req.APIKeyID,
		SignerAddress: req.SignerAddress,
		ExpiresAt:     req.ExpiresAt,
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
