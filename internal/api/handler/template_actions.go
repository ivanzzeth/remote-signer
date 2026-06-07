// Package handler provides HTTP handlers for the RemoteSigner API,
// including template action endpoints (delete, instantiate, revoke).
package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

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

	// Resolve template for RBAC ownership and validation
	tmpl, err := h.templateService.ResolveTemplate(r.Context(), instanceReq)
	if err != nil {
		h.writeError(w, fmt.Sprintf("failed to resolve template: %s", err.Error()), http.StatusBadRequest)
		return
	}

	// Reject solidity templates when forge is unavailable
	if h.solidityValidator == nil && templateContainsSolidity(tmpl) {
		h.writeError(w, "solidity expression rules require forge; forge not available", http.StatusServiceUnavailable)
		return
	}

	// Apply RBAC ownership
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey != nil {
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

	// FORCED VALIDATION — see validation_mandatory.go. Do not restore optional skip.
	if req.SkipValidation {
		h.writeError(w, errSkipValidationForbidden, http.StatusBadRequest)
		return
	}
	if h.jsEvaluator == nil {
		h.writeError(w, "test case validation required for template instantiate but JS evaluator is unavailable", http.StatusServiceUnavailable)
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
	resolvedConfig, subErr := service.SubstituteVariables(tmpl.Config, resolvedVars) //nolint:staticcheck
	if subErr != nil {
		h.writeError(w, fmt.Sprintf("variable substitution for validation failed: %s", subErr.Error()), http.StatusBadRequest)
		return
	}
	results, allPassed := ValidateTemplateConfig(h.jsEvaluator, tmpl.Name, resolvedConfig, resolvedVars)
	if !allPassed {
		var failures []string
		for _, r := range results {
			if !r.Valid && r.Error != "" {
				failures = append(failures, fmt.Sprintf("%s: %s", r.RuleName, r.Error))
			}
		}
		h.writeError(w, fmt.Sprintf("test case validation failed: %s", strings.Join(failures, "; ")), http.StatusBadRequest)
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
