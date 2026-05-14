package evm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/ruleconfig"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

func (h *RuleHandler) createRule(w http.ResponseWriter, r *http.Request) {
	if h.readOnly {
		h.writeError(w, "rule creation via API is disabled (security.rules_api_readonly)", http.StatusForbidden)
		return
	}

	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

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

	ruleType := types.RuleType(req.Type)

	// Agent: block restricted rule types
	if apiKey.IsAgent() && blockedAgentRuleTypes[ruleType] {
		h.writeError(w, fmt.Sprintf("agent role cannot create rules of type %q", req.Type), http.StatusForbidden)
		return
	}

	// Dev: block signer_restriction
	if apiKey.IsDev() && blockedDevRuleTypes[ruleType] {
		h.writeError(w, fmt.Sprintf("dev role cannot create rules of type %q", req.Type), http.StatusForbidden)
		return
	}

	// Per-key rule count limit (admin exempt)
	if !apiKey.IsAdmin() && h.maxRulesPerKey > 0 {
		ownerID := apiKey.ID
		count, err := h.ruleRepo.Count(r.Context(), storage.RuleFilter{Owner: &ownerID})
		if err != nil {
			h.logger.Error("failed to count rules for owner", "error", err, "owner", ownerID)
			h.writeError(w, "failed to check rule count", http.StatusInternalServerError)
			return
		}
		if count >= h.maxRulesPerKey {
			h.writeError(w, fmt.Sprintf("rule limit exceeded: maximum %d rules per API key", h.maxRulesPerKey), http.StatusForbidden)
			return
		}
	}

	// Determine owner, applied_to, and status via shared RBAC logic
	ownership, err := handler.DetermineRuleOwnership(
		r.Context(), apiKey, req.AppliedTo,
		types.RuleMode(req.Mode), h.requireApproval, h.apiKeyRepo,
	)
	if err != nil {
		h.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	appliedTo := ownership.AppliedTo
	status := ownership.Status

	// Validate rule config format (shared with config load and validate-rules)
	if err := ruleconfig.ValidateRuleConfig(req.Type, req.Config); err != nil {
		h.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate optional scope fields to prevent storing invalid data
	if req.ChainType != nil {
		if !validate.IsValidChainType(*req.ChainType) {
			h.writeError(w, "invalid chain_type: must be one of evm, solana, cosmos", http.StatusBadRequest)
			return
		}
	}
	if req.SignerAddress != nil {
		if !validate.IsValidEthereumAddress(*req.SignerAddress) {
			h.writeError(w, "invalid signer_address: must be 0x followed by 40 hex characters", http.StatusBadRequest)
			return
		}
	}

	// Generate rule ID
	ruleID := types.RuleID(fmt.Sprintf("rule_%s", uuid.New().String()))

	// Marshal config to JSON
	configJSON, err := json.Marshal(req.Config)
	if err != nil {
		h.writeError(w, "invalid config", http.StatusBadRequest)
		return
	}

	// Only admin can set immutable
	immutable := false
	if apiKey.IsAdmin() {
		immutable = req.Immutable
	}

	// Build rule
	rule := &types.Rule{
		ID:          ruleID,
		Name:        req.Name,
		Description: req.Description,
		Type:        ruleType,
		Mode:        types.RuleMode(req.Mode),
		Source:      types.RuleSourceAPI,
		Config:      configJSON,
		Enabled:     req.Enabled,
		Owner:       apiKey.ID, // auto-set from caller
		AppliedTo:   appliedTo,
		Status:      status,
		Immutable:   immutable,
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

	// Validate evm_js rules: require test_cases with 1+ positive and 1+ negative, then run them
	if rule.Type == types.RuleTypeEVMJS {
		if err := h.validateJSRule(rule, req.TestCases); err != nil {
			h.logger.Error("evm_js rule validation failed", "error", err, "rule_name", rule.Name)
			h.writeError(w, fmt.Sprintf("evm_js rule validation failed: %v", err), http.StatusBadRequest)
			return
		}
	}

	// Create rule
	if err := h.ruleRepo.Create(r.Context(), rule); err != nil {
		h.logger.Error("failed to create rule", "error", err)
		h.writeError(w, "failed to create rule", http.StatusInternalServerError)
		return
	}

	h.logger.Info("rule created", "rule_id", rule.ID, "name", rule.Name, "owner", rule.Owner, "applied_to", rule.AppliedTo, "status", rule.Status)
	if h.auditLogger != nil {
		clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
		h.auditLogger.LogRuleCreated(r.Context(), apiKey.ID, clientIP, rule.ID, rule.Name)
	}

	responseStatus := http.StatusCreated
	if rule.Status == types.RuleStatusPendingApproval {
		responseStatus = http.StatusAccepted
	}
	h.writeJSON(w, h.toRuleResponse(rule), responseStatus)
}

func (h *RuleHandler) updateRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	var req UpdateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
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

	if h.readOnly {
		h.writeError(w, "rule updates via API are disabled (security.rules_api_readonly)", http.StatusForbidden)
		return
	}
	if rule.Source == types.RuleSourceConfig {
		h.writeError(w, "cannot update config-sourced rules via API", http.StatusForbidden)
		return
	}

	// Immutable check
	if rule.Immutable {
		h.writeError(w, "cannot modify immutable rule", http.StatusForbidden)
		return
	}

	// Ownership check: only owner or admin can modify
	if !apiKey.IsAdmin() && rule.Owner != apiKey.ID {
		h.writeError(w, "permission denied: can only modify own rules", http.StatusForbidden)
		return
	}

	// Agent: block changing to restricted rule types
	if req.Type != "" && apiKey.IsAgent() && blockedAgentRuleTypes[types.RuleType(req.Type)] {
		h.writeError(w, fmt.Sprintf("agent role cannot change rule type to %q", req.Type), http.StatusForbidden)
		return
	}

	// Agent: cannot change applied_to
	if len(req.AppliedTo) > 0 && !apiKey.IsAdmin() {
		// Non-admin cannot change applied_to (forced to ["self"])
		h.writeError(w, "only admin can change applied_to", http.StatusForbidden)
		return
	}

	// Save old config for audit diff
	oldConfig := make([]byte, len(rule.Config))
	copy(oldConfig, rule.Config)

	// Update fields if provided
	if req.Name != "" {
		rule.Name = req.Name
	}
	if req.Description != "" {
		rule.Description = req.Description
	}
	if req.Config != nil {
		if err := ruleconfig.ValidateRuleConfig(string(rule.Type), req.Config); err != nil {
			h.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
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
	if req.ChainType != nil {
		if !validate.IsValidChainType(*req.ChainType) {
			h.writeError(w, "invalid chain_type: must be one of evm, solana, cosmos", http.StatusBadRequest)
			return
		}
		ct := types.ChainType(*req.ChainType)
		rule.ChainType = &ct
	}
	if req.ChainID != nil {
		rule.ChainID = req.ChainID
	}
	if req.SignerAddress != nil {
		if !validate.IsValidEthereumAddress(*req.SignerAddress) {
			h.writeError(w, "invalid signer_address: must be 0x followed by 40 hex characters", http.StatusBadRequest)
			return
		}
		rule.SignerAddress = req.SignerAddress
	}
	// Admin can change applied_to
	if len(req.AppliedTo) > 0 && apiKey.IsAdmin() {
		rule.AppliedTo = pq.StringArray(req.AppliedTo)
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

	// Validate evm_js rules when config is updated
	if req.Config != nil && rule.Type == types.RuleTypeEVMJS {
		if err := h.validateJSRule(rule, req.TestCases); err != nil {
			h.logger.Error("evm_js rule validation failed", "error", err, "rule_id", ruleID)
			h.writeError(w, fmt.Sprintf("evm_js rule validation failed: %v", err), http.StatusBadRequest)
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
	if h.auditLogger != nil {
		clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
		h.auditLogger.LogRuleUpdated(r.Context(), apiKey.ID, clientIP, rule.ID, rule.Name, oldConfig, rule.Config)
	}
	h.writeJSON(w, h.toRuleResponse(rule), http.StatusOK)
}

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

func (h *RuleHandler) deleteRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Fetch rule first for readOnly and source guards
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

	if h.readOnly {
		h.writeError(w, "rule deletion via API is disabled (security.rules_api_readonly)", http.StatusForbidden)
		return
	}
	if rule.Source == types.RuleSourceConfig {
		h.writeError(w, "cannot delete config-sourced rules via API", http.StatusForbidden)
		return
	}

	// Immutable check
	if rule.Immutable {
		h.writeError(w, "cannot delete immutable rule", http.StatusForbidden)
		return
	}

	// Ownership check: only owner or admin can delete
	if !apiKey.IsAdmin() && rule.Owner != apiKey.ID {
		h.writeError(w, "permission denied: can only delete own rules", http.StatusForbidden)
		return
	}

	if err := h.ruleRepo.Delete(r.Context(), rule.ID); err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "rule not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to delete rule", "error", err, "rule_id", ruleID)
		h.writeError(w, "failed to delete rule", http.StatusInternalServerError)
		return
	}

	h.logger.Info("rule deleted", "rule_id", ruleID)
	if h.auditLogger != nil {
		clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
		h.auditLogger.LogRuleDeleted(r.Context(), apiKey.ID, clientIP, rule.ID)
	}
	w.WriteHeader(http.StatusNoContent)
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

	if rule.Status != types.RuleStatusPendingApproval {
		h.writeError(w, fmt.Sprintf("rule is not pending approval (current status: %s)", rule.Status), http.StatusBadRequest)
		return
	}

	rule.Status = types.RuleStatusActive
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

	if rule.Status != types.RuleStatusPendingApproval {
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
