// Package evm — rule_delete.go handles rule deletion via the API.
// Guards: read-only mode, config-sourced rules, immutable rules, and ownership.
package evm

import (
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

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
