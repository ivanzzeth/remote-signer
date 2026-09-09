package evm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

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
			respond.Error(w, "invalid chain_type filter", http.StatusBadRequest, h.logger)
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
			respond.Error(w, "invalid signer_address: must be 0x followed by 40 hex characters", http.StatusBadRequest, h.logger)
			return
		}
		filter.SignerAddress = &signerAddress
	}
	if owner := query.Get("owner"); owner != "" {
		filter.Owner = &owner
	}
	if ruleType := query.Get("type"); ruleType != "" {
		if !validate.IsValidRuleType(ruleType) {
			respond.Error(w, "invalid type filter", http.StatusBadRequest, h.logger)
			return
		}
		rt := types.RuleType(validate.NormalizeRuleType(ruleType))
		filter.Type = &rt
	}
	if source := query.Get("source"); source != "" {
		if !validate.IsValidRuleSource(source) {
			respond.Error(w, "invalid source filter", http.StatusBadRequest, h.logger)
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
		respond.Error(w, "failed to list rules", http.StatusInternalServerError, h.logger)
		return
	}

	// Get total count (without limit/offset)
	countFilter := filter
	countFilter.Limit = 0
	countFilter.Offset = 0
	total, err := h.ruleRepo.Count(r.Context(), countFilter)
	if err != nil {
		h.logger.Error("failed to count rules", "error", err)
		respond.Error(w, "failed to count rules", http.StatusInternalServerError, h.logger)
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

	respond.JSON(w, resp, http.StatusOK, h.logger)
}

func (h *RuleHandler) getRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	gotRule, err := h.ruleRepo.Get(r.Context(), types.RuleID(ruleID))
	if err != nil {
		if types.IsNotFound(err) {
			respond.Error(w, "rule not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("failed to get rule", "error", err, "rule_id", ruleID)
		respond.Error(w, "failed to get rule", http.StatusInternalServerError, h.logger)
		return
	}

	// Scope check: non-admin, non-dev callers can only see rules that apply to them
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey != nil && !apiKey.IsAdmin() && !apiKey.IsDev() {
		filtered := rule.FilterRulesForCaller([]*types.Rule{gotRule}, apiKey.ID)
		if len(filtered) == 0 {
			respond.Error(w, "rule not found", http.StatusNotFound, h.logger)
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
	respond.JSON(w, rr, http.StatusOK, h.logger)
}

func (h *RuleHandler) listBudgets(w http.ResponseWriter, r *http.Request, ruleID string) {
	budgets, err := h.budgetRepo.ListByRuleID(r.Context(), types.RuleID(ruleID))
	if err != nil {
		h.logger.Error("failed to list budgets", "error", err, "rule_id", ruleID)
		respond.Error(w, "failed to list budgets", http.StatusInternalServerError, h.logger)
		return
	}
	if budgets == nil {
		budgets = []*types.RuleBudget{}
	}
	gotRule, ruleErr := h.ruleRepo.Get(r.Context(), types.RuleID(ruleID))
	siblingUnits := make([]string, 0, len(budgets))
	for _, b := range budgets {
		if b != nil {
			siblingUnits = append(siblingUnits, b.Unit)
		}
	}
	items := make([]RuleBudgetListItem, 0, len(budgets))
	for i, b := range budgets {
		if b == nil {
			continue
		}
		if ruleErr == nil {
			needs, periodStart := rule.NeedsPeriodReset(gotRule, b, time.Now())
			if needs {
				if err := h.budgetRepo.ResetBudget(r.Context(), b.RuleID, b.Unit, periodStart); err == nil {
					if fresh, err := h.budgetRepo.Get(r.Context(), b.ID); err == nil && fresh != nil {
						budgets[i] = fresh
						b = fresh
					}
				}
			}
		}
		if ruleErr != nil {
			items = append(items, ruleBudgetListItem(nil, b, siblingUnits))
			continue
		}
		items = append(items, ruleBudgetListItem(gotRule, b, siblingUnits))
	}
	respond.JSON(w, items, http.StatusOK, h.logger)
}

// resetAllBudgets handles POST /api/v1/evm/rules/{id}/budgets/reset — clears
// spent counters on every enforcing, non-stale budget row for the rule.
func (h *RuleHandler) resetAllBudgets(w http.ResponseWriter, r *http.Request, ruleID string) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}
	if h.budgetRepo == nil {
		respond.Error(w, "budget repository not configured", http.StatusInternalServerError, h.logger)
		return
	}

	gotRule, err := h.ruleRepo.Get(r.Context(), types.RuleID(ruleID))
	if err != nil {
		if types.IsNotFound(err) {
			respond.Error(w, "rule not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("failed to get rule for budget reset", "error", err, "rule_id", ruleID)
		respond.Error(w, "failed to get rule", http.StatusInternalServerError, h.logger)
		return
	}

	budgets, err := h.budgetRepo.ListByRuleID(r.Context(), types.RuleID(ruleID))
	if err != nil {
		h.logger.Error("failed to list budgets", "error", err, "rule_id", ruleID)
		respond.Error(w, "failed to list budgets", http.StatusInternalServerError, h.logger)
		return
	}
	siblingUnits := make([]string, 0, len(budgets))
	for _, b := range budgets {
		if b != nil {
			siblingUnits = append(siblingUnits, b.Unit)
		}
	}

	reset := 0
	for _, b := range budgets {
		if b == nil {
			continue
		}
		meta := buildBudgetUXMeta(gotRule, b, siblingUnits)
		if meta.IsStalePlaceholder || !meta.EnforcesLimit {
			continue
		}
		if err := h.budgetRepo.ResetBudget(r.Context(), b.RuleID, b.Unit, time.Time{}); err != nil {
			if types.IsNotFound(err) {
				continue
			}
			h.logger.Error("failed to reset budget", "error", err, "rule_id", ruleID, "unit", b.Unit)
			respond.Error(w, "failed to reset budgets", http.StatusInternalServerError, h.logger)
			return
		}
		reset++
	}
	respond.JSON(w, map[string]int{"reset": reset}, http.StatusOK, h.logger)
}

// approveRule handles POST /api/v1/evm/rules/{id}/approve (admin only via RBAC)
func (h *RuleHandler) approveRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}

	// Only admin can approve (enforced by RBAC middleware PermApproveRule,
	// but double-check here for defense in depth)
	if !apiKey.IsAdmin() {
		respond.Error(w, "permission denied: only admin can approve rules", http.StatusForbidden, h.logger)
		return
	}

	rule, err := h.ruleRepo.Get(r.Context(), types.RuleID(ruleID))
	if err != nil {
		if types.IsNotFound(err) {
			respond.Error(w, "rule not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("failed to get rule", "error", err, "rule_id", ruleID)
		respond.Error(w, "failed to get rule", http.StatusInternalServerError, h.logger)
		return
	}

	// If this is a proposal, apply changes to the target rule
	if rule.ProposalFor != nil {
		h.approveProposal(w, r, rule)
		return
	}

	// Idempotent: already active rules can be "approved" again without error.
	if rule.Status != types.RuleStatusPendingApproval && rule.Status != types.RuleStatusActive {
		respond.Error(w, fmt.Sprintf("rule is not pending approval (current status: %s)", rule.Status), http.StatusBadRequest, h.logger)
		return
	}

	if rule.Status == types.RuleStatusPendingApproval {
		rule.Status = types.RuleStatusActive
	}
	approvedBy := apiKey.ID
	rule.ApprovedBy = &approvedBy
	rule.UpdatedAt = time.Now()

	// ⛔ No validation: approving sets ApprovedBy/UpdatedAt and nothing else.
	// A rule that fails validation should be rejectable and disableable, not
	// stuck. See rule.Writer.UpdateMetadata.
	if err := h.ruleRepo.Update(r.Context(), rule); err != nil {
		h.logger.Error("failed to approve rule", "error", err, "rule_id", ruleID)
		respond.Error(w, "failed to approve rule", http.StatusInternalServerError, h.logger)
		return
	}

	h.logger.Info("rule approved", "rule_id", ruleID, "approved_by", apiKey.ID)
	if h.auditLogger != nil {
		clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
		h.auditLogger.LogRuleApproved(r.Context(), apiKey.ID, clientIP, rule.ID, rule.Owner)
	}

	// Re-evaluate pending requests against the newly-active rule.
	if h.onRuleActivated != nil {
		go h.onRuleActivated("rule-approved:" + ruleID)
	}

	respond.JSON(w, h.toRuleResponse(rule), http.StatusOK, h.logger)
}

// rejectRule handles POST /api/v1/evm/rules/{id}/reject (admin only via RBAC)
func (h *RuleHandler) rejectRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}

	if !apiKey.IsAdmin() {
		respond.Error(w, "permission denied: only admin can reject rules", http.StatusForbidden, h.logger)
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
			respond.Error(w, "rule not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("failed to get rule", "error", err, "rule_id", ruleID)
		respond.Error(w, "failed to get rule", http.StatusInternalServerError, h.logger)
		return
	}

	// Allow rejecting pending_approval or active rules (idempotent for rejected).
	if rule.Status != types.RuleStatusPendingApproval && rule.Status != types.RuleStatusActive {
		respond.Error(w, fmt.Sprintf("rule is not pending approval (current status: %s)", rule.Status), http.StatusBadRequest, h.logger)
		return
	}

	rule.Status = types.RuleStatusRejected
	if req.Reason != "" {
		rule.RejectionReason = &req.Reason
	}
	rule.UpdatedAt = time.Now()

	if err := h.ruleRepo.Update(r.Context(), rule); err != nil {
		h.logger.Error("failed to reject rule", "error", err, "rule_id", ruleID)
		respond.Error(w, "failed to reject rule", http.StatusInternalServerError, h.logger)
		return
	}

	h.logger.Info("rule rejected", "rule_id", ruleID, "rejected_by", apiKey.ID, "reason", req.Reason)
	if h.auditLogger != nil {
		clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
		h.auditLogger.LogRuleRejected(r.Context(), apiKey.ID, clientIP, rule.ID, rule.Owner, req.Reason)
	}
	respond.JSON(w, h.toRuleResponse(rule), http.StatusOK, h.logger)
}

// approveProposal applies a proposal's changes to its target rule.
// The proposal is marked rejected (preserved for audit trail).
// Other pending proposals on the same target are auto-superseded.
func (h *RuleHandler) approveProposal(w http.ResponseWriter, r *http.Request, proposal *types.Rule) {
	apiKey := middleware.GetAPIKey(r.Context())
	targetRuleID := string(*proposal.ProposalFor)

	target, err := h.ruleRepo.Get(r.Context(), types.RuleID(targetRuleID))
	if err != nil {
		if types.IsNotFound(err) {
			// Target rule was deleted — reject the proposal
			reason := "target rule no longer exists"
			proposal.Status = types.RuleStatusRejected
			proposal.RejectionReason = &reason
			proposal.UpdatedAt = time.Now()
			_ = h.ruleRepo.Update(r.Context(), proposal)
			respond.Error(w, "target rule no longer exists: proposal rejected", http.StatusConflict, h.logger)
			return
		}
		h.logger.Error("failed to get target rule", "error", err, "rule_id", targetRuleID)
		respond.Error(w, "failed to get target rule", http.StatusInternalServerError, h.logger)
		return
	}

	if target.Immutable {
		respond.Error(w, "target rule has been marked immutable", http.StatusForbidden, h.logger)
		return
	}

	// Save old config for audit
	oldConfig := make([]byte, len(target.Config))
	copy(oldConfig, target.Config)
	oldVariables := make([]byte, len(target.Variables))
	copy(oldVariables, target.Variables)

	// Apply proposal fields to target
	if proposal.Name != target.Name {
		target.Name = proposal.Name
	}
	if proposal.Description != target.Description {
		target.Description = proposal.Description
	}
	if proposal.Type != target.Type {
		target.Type = proposal.Type
	}
	if !bytes.Equal(proposal.Config, target.Config) {
		target.Config = proposal.Config
	}
	if !bytes.Equal(proposal.Variables, target.Variables) {
		target.Variables = proposal.Variables
	}
	if !bytes.Equal(proposal.Matrix, target.Matrix) {
		target.Matrix = proposal.Matrix
	}
	if proposal.ChainType != nil && target.ChainType != nil && *proposal.ChainType != *target.ChainType {
		target.ChainType = proposal.ChainType
	} else if proposal.ChainType != nil && target.ChainType == nil {
		target.ChainType = proposal.ChainType
	}
	if proposal.ChainID != nil && target.ChainID != nil && *proposal.ChainID != *target.ChainID {
		target.ChainID = proposal.ChainID
	} else if proposal.ChainID != nil && target.ChainID == nil {
		target.ChainID = proposal.ChainID
	}
	if proposal.SignerAddress != nil && target.SignerAddress != nil && *proposal.SignerAddress != *target.SignerAddress {
		target.SignerAddress = proposal.SignerAddress
	} else if proposal.SignerAddress != nil && target.SignerAddress == nil {
		target.SignerAddress = proposal.SignerAddress
	}
	if proposal.Priority != target.Priority {
		target.Priority = proposal.Priority
	}
	if proposal.BudgetPeriod != nil {
		if target.BudgetPeriod == nil || *proposal.BudgetPeriod != *target.BudgetPeriod {
			target.BudgetPeriod = proposal.BudgetPeriod
		}
	}
	if proposal.ExpiresAt != nil {
		if target.ExpiresAt == nil || !proposal.ExpiresAt.Equal(*target.ExpiresAt) {
			target.ExpiresAt = proposal.ExpiresAt
		}
	}

	target.Status = types.RuleStatusActive
	approvedBy := apiKey.ID
	target.ApprovedBy = &approvedBy
	target.UpdatedAt = time.Now()

	// Budget sync if Variables changed and rule has a TemplateID
	if !bytes.Equal(oldVariables, target.Variables) && target.TemplateID != nil && h.budgetRepo != nil && h.templateRepo != nil {
		budgetRequests := h.prepareBudgetSync(r.Context(), target)
		txRepo, ok := h.ruleRepo.(storage.RuleBudgetTransactional)
		if ok {
			err = txRepo.RunInRuleBudgetTransaction(r.Context(), func(txRule storage.RuleRepository, txBudget storage.BudgetRepository) error {
				if err := txRule.Update(r.Context(), target); err != nil {
					return fmt.Errorf("update rule: %w", err)
				}
				if len(budgetRequests) > 0 {
					return txBudget.UpsertLimits(r.Context(), target.ID, budgetRequests)
				}
				return nil
			})
			if err != nil {
				h.logger.Error("failed to update target rule with budget sync from proposal", "error", err)
				respond.Error(w, "failed to apply proposal changes", http.StatusInternalServerError, h.logger)
				return
			}
		} else {
			if vErr := rule.ValidateRuleForWrite(target); vErr != nil {
				respond.Error(w, "rule failed validation: "+vErr.Error(), http.StatusBadRequest, h.logger)
				return
			}
			if err := h.ruleRepo.Update(r.Context(), target); err != nil {
				h.logger.Error("failed to update target rule from proposal", "error", err)
				respond.Error(w, "failed to apply proposal changes", http.StatusInternalServerError, h.logger)
				return
			}
			if len(budgetRequests) > 0 {
				_ = h.budgetRepo.UpsertLimits(r.Context(), target.ID, budgetRequests)
			}
		}
	} else {
		if err := h.ruleRepo.Update(r.Context(), target); err != nil {
			h.logger.Error("failed to update target rule from proposal", "error", err)
			respond.Error(w, "failed to apply proposal changes", http.StatusInternalServerError, h.logger)
			return
		}
	}

	// Mark proposal as superseded (preserved for audit trail),
	// then delete it so it no longer appears in the rule list.
	reason := "applied: changes merged into target rule"
	proposal.Status = types.RuleStatusSuperseded
	proposal.RejectionReason = &reason
	proposal.UpdatedAt = time.Now()
	_ = h.ruleRepo.Update(r.Context(), proposal)
	if err := h.ruleRepo.Delete(r.Context(), proposal.ID); err != nil {
		h.logger.Warn("failed to delete proposal row after approval", "proposal_id", proposal.ID, "error", err)
	}

	// Auto-supersede other pending proposals on the same target.
	// RuleFilter does not expose ProposalFor or Status columns, so we list
	// by Owner and filter in memory (same pattern as proposeRule).
	ownerID := apiKey.ID
	allRules, err := h.ruleRepo.List(r.Context(), storage.RuleFilter{
		Owner: &ownerID,
		Limit: 1000,
	})
	if err == nil {
		for _, rl := range allRules {
			if rl.ProposalFor != nil && string(*rl.ProposalFor) == targetRuleID &&
				rl.Status == types.RuleStatusPendingApproval && rl.ID != proposal.ID {
				supersededReason := "superseded: another proposal was approved"
				rl.Status = types.RuleStatusSuperseded
				rl.RejectionReason = &supersededReason
				rl.UpdatedAt = time.Now()
				_ = h.ruleRepo.Update(r.Context(), rl)
			}
		}
	}
	// Also check all rules regardless of owner for proposals from other keys.
	moreRules, err := h.ruleRepo.List(r.Context(), storage.RuleFilter{Limit: 1000})
	if err == nil {
		for _, rl := range moreRules {
			if rl.ProposalFor != nil && string(*rl.ProposalFor) == targetRuleID &&
				rl.Status == types.RuleStatusPendingApproval && rl.ID != proposal.ID &&
				rl.Owner != ownerID {
				supersededReason := "superseded: another proposal was approved"
				rl.Status = types.RuleStatusSuperseded
				rl.RejectionReason = &supersededReason
				rl.UpdatedAt = time.Now()
				_ = h.ruleRepo.Update(r.Context(), rl)
			}
		}
	}

	h.logger.Info("proposal approved and applied", "proposal_id", proposal.ID, "target_id", targetRuleID, "approved_by", apiKey.ID)
	if h.auditLogger != nil {
		clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
		h.auditLogger.LogRuleUpdated(r.Context(), apiKey.ID, clientIP, target.ID, target.Name, oldConfig, target.Config)
	}

	// Re-evaluate pending sign requests
	if h.onRuleActivated != nil {
		go h.onRuleActivated("proposal-approved:" + string(proposal.ID))
	}

	respond.JSON(w, h.toRuleResponse(target), http.StatusOK, h.logger)
}
