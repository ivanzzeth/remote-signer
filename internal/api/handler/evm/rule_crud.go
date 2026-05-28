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

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	rulepkg "github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/ruleconfig"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/ivanzzeth/remote-signer/internal/validate"

	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
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
	configMap := req.Config
	if configMap == nil {
		configMap = make(map[string]interface{})
	}
	// Store test_cases in config for evm_js rules
	if ruleType == types.RuleTypeEVMJS && len(req.TestCases) > 0 {
		configMap["test_cases"] = req.TestCases
	}
	configJSON, err := json.Marshal(configMap)
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

	// Reject solidity rules when forge is unavailable
	if rule.Type == types.RuleTypeEVMSolidityExpression {
		if h.solidityValidator == nil {
			h.writeError(w, "solidity expression rules require forge; forge not available", http.StatusServiceUnavailable)
			return
		}
		if err := h.validateSolidityRule(r.Context(), rule); err != nil {
			h.logger.Error("rule validation failed", "error", err, "rule_type", rule.Type)
			h.writeError(w, "rule validation failed", http.StatusBadRequest)
			return
		}
	}

	// Validate evm_js rules: ensure config is parseable
	if rule.Type == types.RuleTypeEVMJS {
		var jsCfg evmchain.JSRuleConfig
		if err := json.Unmarshal(rule.Config, &jsCfg); err != nil {
			h.logger.Error("evm_js rule has invalid config", "error", err, "rule_name", rule.Name)
			h.writeError(w, "invalid evm_js rule config", http.StatusBadRequest)
			return
		}
		if jsCfg.Script == "" {
			h.writeError(w, "evm_js rule must have a script", http.StatusBadRequest)
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
		// Preserve test_cases from request if provided
		configMap := req.Config
		if rule.Type == types.RuleTypeEVMJS && len(req.TestCases) > 0 {
			configMap["test_cases"] = req.TestCases
		}
		configJSON, err := json.Marshal(configMap)
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

	// Save old variables for budget auto-migration
	oldVariables := make([]byte, len(rule.Variables))
	copy(oldVariables, rule.Variables)

	// Variables: replace entire set with the given map
	if req.Variables != nil {
		varsJSON, err := json.Marshal(req.Variables)
		if err != nil {
			h.writeError(w, "invalid variables: failed to marshal JSON", http.StatusBadRequest)
			return
		}
		rule.Variables = varsJSON
	}

	// Matrix: replace entire per-chain override table
	if req.Matrix != nil {
		// Empty array clears the matrix
		matrixJSON, err := json.Marshal(req.Matrix)
		if err != nil {
			h.writeError(w, "invalid matrix: failed to marshal JSON", http.StatusBadRequest)
			return
		}
		rule.Matrix = matrixJSON
	}

	rule.UpdatedAt = time.Now()

	// Reject solidity rules when forge is unavailable
	if rule.Type == types.RuleTypeEVMSolidityExpression {
		if h.solidityValidator == nil {
			h.writeError(w, "solidity expression rules require forge; forge not available", http.StatusServiceUnavailable)
			return
		}
		if req.Config != nil {
			if err := h.validateSolidityRule(r.Context(), rule); err != nil {
				h.logger.Error("rule validation failed", "error", err, "rule_id", ruleID)
				h.writeError(w, "rule validation failed", http.StatusBadRequest)
				return
			}
		}
	}

	// Validate evm_js rules when config is updated
	if req.Config != nil && rule.Type == types.RuleTypeEVMJS {
		var jsCfg evmchain.JSRuleConfig
		if err := json.Unmarshal(rule.Config, &jsCfg); err != nil {
			h.logger.Error("evm_js update has invalid config", "error", err, "rule_id", ruleID)
			h.writeError(w, "invalid evm_js rule config", http.StatusBadRequest)
			return
		}
		if jsCfg.Script == "" {
			h.writeError(w, "evm_js rule must have a script", http.StatusBadRequest)
			return
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
				h.writeError(w, "failed to update rule", http.StatusInternalServerError)
				return
			}
		} else {
			// Non-transactional fallback (in-memory repos)
			if err := h.ruleRepo.Update(r.Context(), rule); err != nil {
				h.logger.Error("failed to update rule", "error", err, "rule_id", ruleID)
				h.writeError(w, "failed to update rule", http.StatusInternalServerError)
				return
			}
			if len(budgetRequests) > 0 {
				h.budgetRepo.UpsertLimits(r.Context(), rule.ID, budgetRequests)
			}
		}
	} else {
		if err := h.ruleRepo.Update(r.Context(), rule); err != nil {
			h.logger.Error("failed to update rule", "error", err, "rule_id", ruleID)
			h.writeError(w, "failed to update rule", http.StatusInternalServerError)
			return
		}
	}

	h.logger.Info("rule updated", "rule_id", ruleID)
	if h.auditLogger != nil {
		clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
		h.auditLogger.LogRuleUpdated(r.Context(), apiKey.ID, clientIP, rule.ID, rule.Name, oldConfig, rule.Config)
	}
	h.writeJSON(w, h.toRuleResponse(rule), http.StatusOK)
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
	for k, v := range vars {
		result = strings.ReplaceAll(result, "${"+k+"}", v)
	}
	return result
}
