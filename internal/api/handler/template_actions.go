// Package handler provides HTTP handlers for the RemoteSigner API,
// including template action endpoints (delete, instantiate, revoke).
package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
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
