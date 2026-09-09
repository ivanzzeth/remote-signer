// Package handler provides HTTP handlers for the RemoteSigner API,
// including template action endpoints (delete, instantiate, revoke).
package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func (h *TemplateHandler) deleteTemplate(w http.ResponseWriter, r *http.Request, templateID string) {
	// Check if template exists and is API-sourced
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

	if h.isReadOnly() {
		respond.Error(w, "template deletion via API is disabled (security.rules_api_readonly)", http.StatusForbidden, h.logger)
		return
	}

	// Protect config-sourced templates
	if tmpl.Source == types.RuleSourceConfig {
		respond.Error(w, "cannot delete config-sourced templates via API", http.StatusForbidden, h.logger)
		return
	}

	if err := h.templateRepo.Delete(r.Context(), templateID); err != nil {
		if types.IsNotFound(err) {
			respond.Error(w, "template not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("failed to delete template", "error", err, "template_id", templateID)
		respond.Error(w, "failed to delete template", http.StatusInternalServerError, h.logger)
		return
	}

	h.logger.Info("template deleted", "template_id", templateID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *TemplateHandler) instantiateTemplate(w http.ResponseWriter, r *http.Request, templateID string) {
	if h.isReadOnly() {
		respond.Error(w, "template instantiation via API is disabled (security.rules_api_readonly)", http.StatusForbidden, h.logger)
		return
	}

	var req InstantiateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.Error(w, "invalid request body", http.StatusBadRequest, h.logger)
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
			respond.Error(w, fmt.Sprintf("invalid expires_in duration: %s", *req.ExpiresIn), http.StatusBadRequest, h.logger)
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
			respond.Error(w, fmt.Sprintf("invalid schedule period: %s", req.Schedule.Period), http.StatusBadRequest, h.logger)
			return
		}
		instanceReq.Schedule = &service.ScheduleConfig{
			Period:  d,
			StartAt: req.Schedule.StartAt,
		}
	}

	// Resolve template for RBAC ownership and validation
	tmpl, err := h.templateService.ResolveTemplate(r.Context(), instanceReq)
	if err != nil {
		respond.Error(w, fmt.Sprintf("failed to resolve template: %s", err.Error()), http.StatusBadRequest, h.logger)
		return
	}

	// Reject solidity templates when forge is unavailable
	if h.solidityValidator == nil && templateContainsSolidity(tmpl) {
		respond.Error(w, "solidity expression rules require forge; forge not available", http.StatusServiceUnavailable, h.logger)
		return
	}

	// Apply RBAC ownership
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey != nil {
		ownership, err := DetermineRuleOwnership(
			r.Context(), apiKey, nil,
			tmpl.Mode, h.requireApprovalValue(), h.apiKeyRepo,
		)
		if err != nil {
			respond.Error(w, err.Error(), http.StatusBadRequest, h.logger)
			return
		}
		instanceReq.Owner = ownership.Owner
		instanceReq.AppliedTo = []string(ownership.AppliedTo)
		instanceReq.Status = ownership.Status
	}

	// FORCED VALIDATION — see validation_mandatory.go. Do not restore optional skip.
	if req.SkipValidation {
		respond.Error(w, errSkipValidationForbidden, http.StatusBadRequest, h.logger)
		return
	}
	if h.jsEvaluator == nil {
		respond.Error(w, "test case validation required for template instantiate but JS evaluator is unavailable", http.StatusServiceUnavailable, h.logger)
		return
	}
	// Previously (REMOVED — fund-loss risk):
	//   if !req.SkipValidation && h.jsEvaluator != nil { ... }
	var varDefs []types.TemplateVariable
	if len(tmpl.Variables) > 0 {
		_ = json.Unmarshal(tmpl.Variables, &varDefs)
	}
	resolvedVars := resolveTemplateDefaults(varDefs, req.Variables)
	if instanceReq.ChainID != nil {
		resolvedVars["chain_id"] = *instanceReq.ChainID
	}
	results, allPassed := ValidateTemplateConfig(h.jsEvaluator, tmpl.Name, tmpl.Config, resolvedVars)
	if !allPassed {
		var failures []string
		for _, r := range results {
			if !r.Valid && r.Error != "" {
				failures = append(failures, fmt.Sprintf("%s: %s", r.RuleName, r.Error))
			}
		}
		respond.Error(w, fmt.Sprintf("test case validation failed: %s", strings.Join(failures, "; ")), http.StatusBadRequest, h.logger)
		return
	}
	h.logger.Debug("template test case validation passed",
		"template_id", templateID,
		"results", len(results),
	)

	// Create instance
	result, err := h.templateService.CreateInstance(r.Context(), instanceReq)
	if err != nil {
		h.logger.Error("failed to create instance", "error", err, "template_id", templateID)
		respond.Error(w, fmt.Sprintf("failed to create instance: %s", err.Error()), http.StatusBadRequest, h.logger)
		return
	}

	// Build response
	resp := make(map[string]interface{})

	ruleJSON, err := json.Marshal(result.Rule)
	if err != nil {
		h.logger.Error("failed to marshal rule", "error", err)
		respond.Error(w, "failed to marshal response", http.StatusInternalServerError, h.logger)
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
	respond.JSON(w, resp, http.StatusCreated, h.logger)
}

func (h *TemplateHandler) revokeInstance(w http.ResponseWriter, r *http.Request, ruleID string) {
	if h.isReadOnly() {
		respond.Error(w, "instance revocation via API is disabled (security.rules_api_readonly)", http.StatusForbidden, h.logger)
		return
	}

	if err := h.templateService.RevokeInstance(r.Context(), types.RuleID(ruleID)); err != nil {
		if types.IsNotFound(err) {
			respond.Error(w, "instance not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("failed to revoke instance", "error", err, "rule_id", ruleID)
		respond.Error(w, fmt.Sprintf("failed to revoke instance: %s", err.Error()), http.StatusBadRequest, h.logger)
		return
	}

	h.logger.Info("instance revoked", "rule_id", ruleID)
	respond.JSON(w, map[string]string{"status": "revoked", "rule_id": ruleID}, http.StatusOK, h.logger)
}
