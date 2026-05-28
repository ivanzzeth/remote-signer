// Package evm provides EVM-specific HTTP handlers for the Remote Signer API.
// rule_query.go contains query and approval handler methods for rules.
package evm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

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
		if !redact {
			h.enrichVariableDefs(&rr, r)
		}
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
	} else {
		h.enrichVariableDefs(&rr, gotRule)
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

	// Idempotent: already active rules can be "approved" again without error.
	if rule.Status != types.RuleStatusPendingApproval && rule.Status != types.RuleStatusActive {
		h.writeError(w, fmt.Sprintf("rule is not pending approval (current status: %s)", rule.Status), http.StatusBadRequest)
		return
	}

	if rule.Status == types.RuleStatusPendingApproval {
		rule.Status = types.RuleStatusActive
	}
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

	// Allow rejecting pending_approval or active rules (idempotent for rejected).
	if rule.Status != types.RuleStatusPendingApproval && rule.Status != types.RuleStatusActive {
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
