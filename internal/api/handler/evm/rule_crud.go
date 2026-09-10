// Package evm provides EVM-specific HTTP handlers for the Remote Signer API.
// rule_crud.go contains create and update handler methods (delete lives in rule_delete.go).
package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	rulepkg "github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/ruleconfig"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

func (h *RuleHandler) createRule(w http.ResponseWriter, r *http.Request) {
	if h.isReadOnly() {
		respond.Error(w, "rule creation via API is disabled (security.rules_api_readonly)", http.StatusForbidden, h.logger)
		return
	}

	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}

	var req CreateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.Error(w, "invalid request body", http.StatusBadRequest, h.logger)
		return
	}

	// Validate required fields
	if req.Name == "" {
		respond.Error(w, "name is required", http.StatusBadRequest, h.logger)
		return
	}
	if req.Type == "" {
		respond.Error(w, "type is required", http.StatusBadRequest, h.logger)
		return
	}
	if req.Mode == "" {
		respond.Error(w, "mode is required", http.StatusBadRequest, h.logger)
		return
	}

	// Validate mode is a known value
	if req.Mode != "whitelist" && req.Mode != "blocklist" {
		respond.Error(w, "mode must be 'whitelist' or 'blocklist'", http.StatusBadRequest, h.logger)
		return
	}

	ruleType := types.RuleType(req.Type)

	// Agent: block restricted rule types
	if apiKey.IsAgent() && blockedAgentRuleTypes[ruleType] {
		respond.Error(w, fmt.Sprintf("agent role cannot create rules of type %q", req.Type), http.StatusForbidden, h.logger)
		return
	}

	// Dev: block signer_restriction
	if apiKey.IsDev() && blockedDevRuleTypes[ruleType] {
		respond.Error(w, fmt.Sprintf("dev role cannot create rules of type %q", req.Type), http.StatusForbidden, h.logger)
		return
	}

	// Per-key rule count limit (admin exempt)
	if !apiKey.IsAdmin() && h.maxRulesPerKeyValue() > 0 {
		ownerID := apiKey.ID
		count, err := h.ruleRepo.Count(r.Context(), storage.RuleFilter{Owner: &ownerID})
		if err != nil {
			h.logger.Error("failed to count rules for owner", "error", err, "owner", ownerID)
			respond.Error(w, "failed to check rule count", http.StatusInternalServerError, h.logger)
			return
		}
		if count >= h.maxRulesPerKeyValue() {
			respond.Error(w, fmt.Sprintf("rule limit exceeded: maximum %d rules per API key", h.maxRulesPerKeyValue()), http.StatusForbidden, h.logger)
			return
		}
	}

	// Determine owner, applied_to, and status via shared RBAC logic
	ownership, err := handler.DetermineRuleOwnership(
		r.Context(), apiKey, req.AppliedTo,
		types.RuleMode(req.Mode), h.requireApprovalValue(), h.apiKeyRepo,
	)
	if err != nil {
		respond.Error(w, err.Error(), http.StatusBadRequest, h.logger)
		return
	}
	appliedTo := ownership.AppliedTo
	status := ownership.Status

	// Validate rule config format (shared with config load and validate-rules)
	if err := ruleconfig.ValidateRuleConfig(req.Type, req.Config); err != nil {
		respond.Error(w, err.Error(), http.StatusBadRequest, h.logger)
		return
	}

	// Validate optional scope fields to prevent storing invalid data
	if req.ChainType != nil {
		if !validate.IsValidChainType(*req.ChainType) {
			respond.Error(w, "invalid chain_type: must be one of evm, solana, cosmos", http.StatusBadRequest, h.logger)
			return
		}
	}
	if req.SignerAddress != nil {
		if !validate.IsValidEthereumAddress(*req.SignerAddress) {
			respond.Error(w, "invalid signer_address: must be 0x followed by 40 hex characters", http.StatusBadRequest, h.logger)
			return
		}
	}

	// Generate rule ID
	ruleID := types.RuleID(fmt.Sprintf("rule_%s", uuid.New().String()))

	// Marshal config to JSON
	configMap := req.Config
	if configMap == nil {
		configMap = make(map[string]interface{})
	}
	// Store test_cases for engines that run them.
	//
	// ⚠️ Asks the descriptor rather than naming evm_js: a second engine that
	// takes test cases would otherwise silently drop them here, with the rule
	// created and its cases gone.
	if d, ok := types.LookupRuleType(ruleType); ok && d.TakesTestCases && len(req.TestCases) > 0 {
		configMap["test_cases"] = req.TestCases
	}
	configJSON, err := json.Marshal(configMap)
	if err != nil {
		respond.Error(w, "invalid config", http.StatusBadRequest, h.logger)
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
		Priority:    coalescePriority(req.Priority),
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

	// Reject rules whose engine shells out to a toolchain this deployment has
	// not configured. Asks the descriptor rather than naming the engine.
	if d, ok := types.LookupRuleType(rule.Type); ok && d.RequiresToolchain != "" {
		if h.solidityValidator == nil {
			respond.Error(w, fmt.Sprintf("%s rules require %s; %s not available", rule.Type, d.RequiresToolchain, d.RequiresToolchain), http.StatusServiceUnavailable, h.logger)
			return
		}
		if err := h.validateSolidityRule(r.Context(), rule); err != nil {
			h.logger.Error("rule validation failed", "error", err, "rule_type", rule.Type)
			respond.Error(w, "rule validation failed", http.StatusBadRequest, h.logger)
			return
		}
	}

	// Create rule
	if err := h.ruleRepo.Create(r.Context(), rule); err != nil {
		h.logger.Error("failed to create rule", "error", err)
		respond.Error(w, "failed to create rule", http.StatusInternalServerError, h.logger)
		return
	}

	h.logger.Info("rule created", "rule_id", rule.ID, "name", rule.Name, "owner", rule.Owner, "applied_to", rule.AppliedTo, "status", rule.Status)
	if h.auditLogger != nil {
		clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
		h.auditLogger.LogRuleCreated(r.Context(), apiKey.ID, clientIP, rule.ID, rule.Name)
	}

	// When a rule is created directly as active, re-evaluate pending
	// requests so they can be auto-approved by the new rule.
	if rule.Status == types.RuleStatusActive && h.onRuleActivated != nil {
		go h.onRuleActivated("rule-created:" + string(rule.ID))
	}

	responseStatus := http.StatusCreated
	if rule.Status == types.RuleStatusPendingApproval {
		responseStatus = http.StatusAccepted
	}
	respond.JSON(w, h.toRuleResponse(rule), responseStatus, h.logger)
}

func (h *RuleHandler) updateRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	var req UpdateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.Error(w, "invalid request body", http.StatusBadRequest, h.logger)
		return
	}

	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}

	// Get existing rule
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

	if h.isReadOnly() {
		respond.Error(w, "rule updates via API are disabled (security.rules_api_readonly)", http.StatusForbidden, h.logger)
		return
	}
	if rule.Source == types.RuleSourceConfig {
		respond.Error(w, "cannot update config-sourced rules via API", http.StatusForbidden, h.logger)
		return
	}

	// Immutable check
	if rule.Immutable {
		respond.Error(w, "cannot modify immutable rule", http.StatusForbidden, h.logger)
		return
	}

	// Ownership check: only owner or admin can modify
	if !apiKey.IsAdmin() && rule.Owner != apiKey.ID {
		respond.Error(w, "permission denied: can only modify own rules", http.StatusForbidden, h.logger)
		return
	}

	// Agent: block changing to restricted rule types
	if req.Type != "" && apiKey.IsAgent() && blockedAgentRuleTypes[types.RuleType(req.Type)] {
		respond.Error(w, fmt.Sprintf("agent role cannot change rule type to %q", req.Type), http.StatusForbidden, h.logger)
		return
	}

	// Agent: cannot change applied_to
	if len(req.AppliedTo) > 0 && !apiKey.IsAdmin() {
		// Non-admin cannot change applied_to (forced to ["self"])
		respond.Error(w, "only admin can change applied_to", http.StatusForbidden, h.logger)
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
			respond.Error(w, err.Error(), http.StatusBadRequest, h.logger)
			return
		}
		// Preserve test_cases from request if provided
		configMap := req.Config
		if d, ok := types.LookupRuleType(rule.Type); ok && d.TakesTestCases && len(req.TestCases) > 0 {
			configMap["test_cases"] = req.TestCases
		}
		configJSON, err := json.Marshal(configMap)
		if err != nil {
			respond.Error(w, "invalid config", http.StatusBadRequest, h.logger)
			return
		}
		rule.Config = configJSON
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	if req.Priority != nil {
		rule.Priority = *req.Priority
	}
	if req.BudgetPeriod != nil {
		if *req.BudgetPeriod == "" {
			rule.BudgetPeriod = nil
			rule.BudgetPeriodStart = nil
		} else {
			d, err := time.ParseDuration(*req.BudgetPeriod)
			if err != nil || d <= 0 {
				respond.Error(w, "invalid budget_period: must be a valid duration like 24h, 7d (7*24h)", http.StatusBadRequest, h.logger)
				return
			}
			rule.BudgetPeriod = &d
			now := time.Now()
			rule.BudgetPeriodStart = &now
		}
	}
	if req.ChainType != nil {
		if !validate.IsValidChainType(*req.ChainType) {
			respond.Error(w, "invalid chain_type: must be one of evm, solana, cosmos", http.StatusBadRequest, h.logger)
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
			respond.Error(w, "invalid signer_address: must be 0x followed by 40 hex characters", http.StatusBadRequest, h.logger)
			return
		}
		rule.SignerAddress = req.SignerAddress
	}
	// Admin can change applied_to
	if len(req.AppliedTo) > 0 && apiKey.IsAdmin() {
		rule.AppliedTo = pq.StringArray(req.AppliedTo)
	}

	// Save old variables for budget auto-migration
	oldVariables := make([]byte, len(rule.Variables))
	copy(oldVariables, rule.Variables)

	// Variables: merge patch into existing set (partial --set-var must not drop other keys)
	if req.Variables != nil {
		patchJSON, err := json.Marshal(req.Variables)
		if err != nil {
			respond.Error(w, "invalid variables: failed to marshal JSON", http.StatusBadRequest, h.logger)
			return
		}
		merged, err := rulepkg.MergeVariablesJSON(rule.Variables, patchJSON)
		if err != nil {
			respond.Error(w, "invalid variables: failed to merge JSON", http.StatusBadRequest, h.logger)
			return
		}
		rule.Variables = merged
	}

	// Matrix: replace entire per-chain override table
	if req.Matrix != nil {
		// Empty array clears the matrix
		matrixJSON, err := json.Marshal(req.Matrix)
		if err != nil {
			respond.Error(w, "invalid matrix: failed to marshal JSON", http.StatusBadRequest, h.logger)
			return
		}
		rule.Matrix = matrixJSON
	}

	// NOTE: instance rules store their Config in template form (${var}
	// placeholders) and the rule engine substitutes Variables live at
	// evaluation, so updating Variables here takes effect immediately with no
	// Config re-render required.

	rule.UpdatedAt = time.Now()

	if d, ok := types.LookupRuleType(rule.Type); ok && d.RequiresToolchain != "" {
		if h.solidityValidator == nil {
			respond.Error(w, fmt.Sprintf("%s rules require %s; %s not available", rule.Type, d.RequiresToolchain, d.RequiresToolchain), http.StatusServiceUnavailable, h.logger)
			return
		}
		if req.Config != nil {
			if err := h.validateSolidityRule(r.Context(), rule); err != nil {
				h.logger.Error("rule validation failed", "error", err, "rule_id", ruleID)
				respond.Error(w, "rule validation failed", http.StatusBadRequest, h.logger)
				return
			}
		}
	}

	// Update rule and sync budget limits atomically when variables changed.
	if req.Variables != nil && rule.TemplateID != nil && *rule.TemplateID != "" &&
		h.budgetRepo != nil && h.templateRepo != nil {

		// Pre-resolve budget sync requests outside the transaction.
		// templateRepo.Get() opens its own DB connection - calling it inside
		// a GORM transaction serializes on SQLite and causes deadlocks.
		budgetRequests := h.prepareBudgetSync(r.Context(), rule)

		txRepo, ok := h.ruleRepo.(storage.RuleBudgetTransactional)
		if ok {
			err = txRepo.RunInRuleBudgetTransaction(r.Context(), func(txRule storage.RuleRepository, txBudget storage.BudgetRepository) error {
				if err := txRule.Update(r.Context(), rule); err != nil {
					return fmt.Errorf("update rule: %w", err)
				}
				if len(budgetRequests) > 0 {
					return txBudget.UpsertLimits(r.Context(), rule.ID, budgetRequests)
				}
				return nil
			})
			if err != nil {
				h.logger.Error("failed to update rule with budget sync", "error", err, "rule_id", ruleID)
				respond.Error(w, "failed to update rule", http.StatusInternalServerError, h.logger)
				return
			}
		} else {
			// Non-transactional fallback (in-memory repos)
			if err := h.ruleRepo.Update(r.Context(), rule); err != nil {
				h.logger.Error("failed to update rule", "error", err, "rule_id", ruleID)
				respond.Error(w, "failed to update rule", http.StatusInternalServerError, h.logger)
				return
			}
			if len(budgetRequests) > 0 {
				h.budgetRepo.UpsertLimits(r.Context(), rule.ID, budgetRequests)
			}
		}
	} else {
		if err := h.ruleRepo.Update(r.Context(), rule); err != nil {
			h.logger.Error("failed to update rule", "error", err, "rule_id", ruleID)
			respond.Error(w, "failed to update rule", http.StatusInternalServerError, h.logger)
			return
		}
	}

	h.logger.Info("rule updated", "rule_id", ruleID)
	if h.auditLogger != nil {
		clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
		h.auditLogger.LogRuleUpdated(r.Context(), apiKey.ID, clientIP, rule.ID, rule.Name, oldConfig, rule.Config)
	}

	// Active rule updates (e.g. agent self-service trusted_contracts) take
	// effect immediately — re-evaluate authorizing requests so matching
	// ones can auto-approve under the new policy.
	if rule.Status == types.RuleStatusActive && h.onRuleActivated != nil {
		go h.onRuleActivated("rule-updated:" + ruleID)
	}

	respond.JSON(w, h.toRuleResponse(rule), http.StatusOK, h.logger)
}

// proposeRule handles POST /api/v1/evm/rules/{id}/propose
// Creates a shadow-copy proposal for modifying a rule the caller doesn't own.
// Agent-created proposals require admin approval before taking effect.
func (h *RuleHandler) proposeRule(w http.ResponseWriter, r *http.Request, targetRuleID string) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}

	// Only agent and admin can propose (dev uses direct PATCH on own rules)
	if !apiKey.IsAgent() && !apiKey.IsAdmin() {
		respond.Error(w, "permission denied: only agents and admins can propose rule changes", http.StatusForbidden, h.logger)
		return
	}

	// Read-only check
	if h.isReadOnly() {
		respond.Error(w, "rule mutations are disabled in read-only mode", http.StatusForbidden, h.logger)
		return
	}

	var req ProposeRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest, h.logger)
		return
	}

	// Validate at least one field is being changed
	if req.Name == "" && req.Description == "" && req.Config == nil && req.Variables == nil &&
		req.Matrix == nil && req.ChainType == nil && req.ChainID == nil &&
		req.SignerAddress == nil && req.Priority == nil && req.BudgetPeriod == nil &&
		req.Type == "" {
		respond.Error(w, "at least one field must be changed in a proposal", http.StatusBadRequest, h.logger)
		return
	}

	// Validate type if specified
	if req.Type != "" {
		if !validate.IsValidRuleType(req.Type) {
			respond.Error(w, "invalid rule type: "+req.Type, http.StatusBadRequest, h.logger)
			return
		}
		if apiKey.IsAgent() && blockedAgentRuleTypes[types.RuleType(req.Type)] {
			respond.Error(w, fmt.Sprintf("agent role cannot change rule type to %q", req.Type), http.StatusForbidden, h.logger)
			return
		}
	}

	// Load target rule
	targetRule, err := h.ruleRepo.Get(r.Context(), types.RuleID(targetRuleID))
	if err != nil {
		if types.IsNotFound(err) {
			respond.Error(w, "target rule not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("failed to get target rule", "error", err, "rule_id", targetRuleID)
		respond.Error(w, "failed to get target rule", http.StatusInternalServerError, h.logger)
		return
	}

	// Validate target rule
	if targetRule.Source == types.RuleSourceConfig {
		respond.Error(w, "cannot propose changes to config-sourced rules", http.StatusForbidden, h.logger)
		return
	}
	if targetRule.Immutable {
		respond.Error(w, "cannot modify immutable rule", http.StatusForbidden, h.logger)
		return
	}
	if targetRule.ProposalFor != nil {
		respond.Error(w, "cannot propose changes to a rule that is itself a proposal", http.StatusBadRequest, h.logger)
		return
	}
	if targetRule.Status != types.RuleStatusActive && targetRule.Status != types.RuleStatusPendingApproval {
		respond.Error(w, fmt.Sprintf("target rule is not active (current status: %s)", targetRule.Status), http.StatusBadRequest, h.logger)
		return
	}

	// Check for existing pending proposal from this API key on the same target.
	// RuleFilter does not expose ProposalFor or Status columns directly, so we
	// list by Owner and filter in memory.
	existing, err := h.ruleRepo.List(r.Context(), storage.RuleFilter{
		Owner: &apiKey.ID,
		Limit: 100,
	})
	if err == nil {
		for _, rl := range existing {
			if rl.ProposalFor != nil && string(*rl.ProposalFor) == targetRuleID &&
				rl.Status == types.RuleStatusPendingApproval {
				respond.Error(w, "a pending proposal from you already exists for this rule", http.StatusConflict, h.logger)
				return
			}
		}
	}

	// Check per-key rule count limit
	if h.maxRulesPerKeyValue() > 0 {
		ownerID := apiKey.ID
		count, err := h.ruleRepo.Count(r.Context(), storage.RuleFilter{Owner: &ownerID})
		if err != nil {
			h.logger.Error("failed to count rules for owner", "error", err, "owner", ownerID)
			respond.Error(w, "failed to check rule count", http.StatusInternalServerError, h.logger)
			return
		}
		if count >= h.maxRulesPerKeyValue() {
			respond.Error(w, fmt.Sprintf("rule limit exceeded: maximum %d rules per API key", h.maxRulesPerKeyValue()), http.StatusForbidden, h.logger)
			return
		}
	}

	// Determine the effective type for config validation
	effectiveType := targetRule.Type
	if req.Type != "" {
		effectiveType = types.RuleType(req.Type)
	}

	// Validate config if provided
	if req.Config != nil {
		if err := ruleconfig.ValidateRuleConfig(string(effectiveType), req.Config); err != nil {
			respond.Error(w, "invalid config: "+err.Error(), http.StatusBadRequest, h.logger)
			return
		}
	}

	// Validate optional scope fields
	if req.ChainType != nil {
		if !validate.IsValidChainType(*req.ChainType) {
			respond.Error(w, "invalid chain_type: must be one of evm, solana, cosmos", http.StatusBadRequest, h.logger)
			return
		}
	}
	if req.SignerAddress != nil {
		if !validate.IsValidEthereumAddress(*req.SignerAddress) {
			respond.Error(w, "invalid signer_address: must be 0x followed by 40 hex characters", http.StatusBadRequest, h.logger)
			return
		}
	}

	// Build proposal rule by deep-copying the target and overlaying requested changes
	now := time.Now()
	proposal := &types.Rule{
		ID:            types.RuleID(fmt.Sprintf("rule_%s", uuid.New().String())),
		Name:          targetRule.Name,
		Description:   targetRule.Description,
		Type:          targetRule.Type,
		Mode:          targetRule.Mode,
		Source:        types.RuleSourceAPI,
		ChainType:     targetRule.ChainType,
		ChainID:       targetRule.ChainID,
		SignerAddress: targetRule.SignerAddress,
		Owner:         apiKey.ID,
		AppliedTo:     targetRule.AppliedTo,
		Status:        types.RuleStatusPendingApproval,
		Immutable:     false,
		TemplateID:    targetRule.TemplateID,
		Priority:      targetRule.Priority,
		Enabled:       false, // proposals are never active
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	// Deep-copy byte slices from target
	if len(targetRule.Config) > 0 {
		proposal.Config = make([]byte, len(targetRule.Config))
		copy(proposal.Config, targetRule.Config)
	}
	if len(targetRule.Variables) > 0 {
		proposal.Variables = make([]byte, len(targetRule.Variables))
		copy(proposal.Variables, targetRule.Variables)
	}
	if len(targetRule.Matrix) > 0 {
		proposal.Matrix = make([]byte, len(targetRule.Matrix))
		copy(proposal.Matrix, targetRule.Matrix)
	}
	if targetRule.BudgetPeriod != nil {
		bp := *targetRule.BudgetPeriod
		proposal.BudgetPeriod = &bp
	}
	if targetRule.ExpiresAt != nil {
		et := *targetRule.ExpiresAt
		proposal.ExpiresAt = &et
	}
	// Set proposal linkage
	pf := types.RuleID(targetRuleID)
	proposal.ProposalFor = &pf

	// Overlay proposed changes
	if req.Name != "" {
		proposal.Name = req.Name
	}
	if req.Description != "" {
		proposal.Description = req.Description
	}
	if req.Type != "" {
		proposal.Type = types.RuleType(req.Type)
	}
	if req.Config != nil {
		configJSON, err := json.Marshal(req.Config)
		if err != nil {
			respond.Error(w, "failed to marshal config", http.StatusInternalServerError, h.logger)
			return
		}
		proposal.Config = configJSON
	}
	if req.Variables != nil {
		patchJSON, err := json.Marshal(req.Variables)
		if err != nil {
			respond.Error(w, "failed to marshal variables", http.StatusInternalServerError, h.logger)
			return
		}
		merged, err := rulepkg.MergeVariablesJSON(proposal.Variables, patchJSON)
		if err != nil {
			respond.Error(w, "failed to merge variables", http.StatusInternalServerError, h.logger)
			return
		}
		proposal.Variables = merged
	}
	if req.Matrix != nil {
		matrixJSON, err := json.Marshal(req.Matrix)
		if err != nil {
			respond.Error(w, "failed to marshal matrix", http.StatusInternalServerError, h.logger)
			return
		}
		proposal.Matrix = matrixJSON
	}
	if req.ChainType != nil {
		ct := types.ChainType(*req.ChainType)
		proposal.ChainType = &ct
	}
	if req.ChainID != nil {
		proposal.ChainID = req.ChainID
	}
	if req.SignerAddress != nil {
		proposal.SignerAddress = req.SignerAddress
	}
	if req.Priority != nil {
		proposal.Priority = *req.Priority
	}
	if req.BudgetPeriod != nil {
		if *req.BudgetPeriod == "" {
			proposal.BudgetPeriod = nil
		} else {
			d, err := time.ParseDuration(*req.BudgetPeriod)
			if err != nil {
				respond.Error(w, "invalid budget_period: "+err.Error(), http.StatusBadRequest, h.logger)
				return
			}
			proposal.BudgetPeriod = &d
		}
	}

	// Persist proposal
	if err := h.ruleRepo.Create(r.Context(), proposal); err != nil {
		h.logger.Error("failed to create proposal", "error", err)
		respond.Error(w, "failed to create proposal", http.StatusInternalServerError, h.logger)
		return
	}

	h.logger.Info("rule proposal created", "proposal_id", proposal.ID, "target_id", targetRuleID, "proposed_by", apiKey.ID)
	if h.auditLogger != nil {
		clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
		h.auditLogger.LogRuleCreated(r.Context(), apiKey.ID, clientIP, proposal.ID, proposal.Name)
	}

	respond.JSON(w, h.toRuleResponse(proposal), http.StatusAccepted, h.logger)
}

// prepareBudgetSync resolves template BudgetMetering against current rule
// variables and returns BudgetSyncRequests ready for upsert. Template fetching
// happens outside any DB transaction to avoid SQLite serialization deadlocks.
func (h *RuleHandler) prepareBudgetSync(ctx context.Context, rule *types.Rule) []storage.BudgetSyncRequest {
	tmpl, err := h.templateRepo.Get(ctx, *rule.TemplateID)
	if err != nil {
		h.logger.Warn("budget sync: failed to get template, skipping", "rule_id", rule.ID, "template_id", *rule.TemplateID, "error", err)
		return nil
	}

	if len(tmpl.BudgetMetering) == 0 {
		return nil
	}

	resolvedJSON := rulepkg.SubstituteMeteringJSON(tmpl.BudgetMetering, rule.Variables)
	var metering types.BudgetMetering
	if err := json.Unmarshal(resolvedJSON, &metering); err != nil {
		h.logger.Warn("budget sync: failed to unmarshal budget metering", "rule_id", rule.ID, "error", err)
		return nil
	}

	if metering.Dynamic {
		return buildDynamicBudgetRequests(&metering)
	}
	return buildStaticBudgetRequests(rule.Variables, &metering)
}

func buildDynamicBudgetRequests(metering *types.BudgetMetering) []storage.BudgetSyncRequest {
	var requests []storage.BudgetSyncRequest
	for unitName, conf := range metering.KnownUnits {
		unit := rulepkg.NormalizeBudgetUnit(unitName)
		maxTotal := conf.MaxTotal
		if maxTotal == "" {
			maxTotal = "-1"
		}
		maxPerTx := conf.MaxPerTx
		if maxPerTx == "" {
			maxPerTx = "-1"
		}
		alertPct := conf.AlertPct
		if alertPct <= 0 {
			alertPct = 80
		}
		requests = append(requests, storage.BudgetSyncRequest{
			Unit:       unit,
			MaxTotal:   maxTotal,
			MaxPerTx:   maxPerTx,
			MaxTxCount: conf.MaxTxCount,
			AlertPct:   alertPct,
		})
	}
	return requests
}

func buildStaticBudgetRequests(variables []byte, metering *types.BudgetMetering) []storage.BudgetSyncRequest {
	unit := resolveBudgetUnit(variables, metering.Unit)
	return []storage.BudgetSyncRequest{{
		Unit:     unit,
		MaxTotal: "-1",
		MaxPerTx: "-1",
		AlertPct: 80,
	}}
}

// resolveBudgetUnit substitutes rule variables into a budget unit template string.
func resolveBudgetUnit(variables []byte, unitTemplate string) string {
	if unitTemplate == "" {
		return "count"
	}
	if !strings.Contains(unitTemplate, "${") || len(variables) == 0 {
		return unitTemplate
	}
	var vars map[string]string
	if err := json.Unmarshal(variables, &vars); err != nil {
		return unitTemplate
	}
	result := unitTemplate
	// Same expansion the engine performs — see rule/substitution.go. Rolling a
	// bare-${k} loop here would resolve fewer forms than evaluation does.
	result = rulepkg.ExpandPlaceholders(result, vars)
	return result
}

func coalescePriority(p *int) int {
	if p == nil {
		return 100 // default
	}
	if *p < 1 {
		return 1 // minimum
	}
	return *p
}
