// Package handler provides HTTP handlers for the RemoteSigner API,
// including template management endpoints (list, get, create, update).
package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

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
	// Allow both rule evaluator types AND the meta "template_bundle"
	// type — the latter expands into multiple sub-rules at instance
	// time. The file-based registry already accepts this; the API
	// path was rejecting it, which left bundle templates only
	// creatable from YAML files and silently broke API-driven CRUD
	// for the bundle case.
	if !validate.IsValidRuleType(req.Type) && req.Type != "template_bundle" {
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
