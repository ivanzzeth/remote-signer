package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// BudgetListHandler serves GET /api/v1/evm/budgets — every budget row in
// the system, annotated with whether it belongs to a real rule
// (kind=rule, populated rule_name/rule_type) or to the simulation fallback
// (kind=simulation, populated signer_address from the synthetic
// "sim:<address>" rule_id).
//
// Per-rule listing under /rules/{id}/budgets remains and still drives the
// rule-detail view; this endpoint exists because synthetic simulation
// budgets have no entry in the rules table, so a UI that fans out over
// rules.list() can never see them.
type BudgetListHandler struct {
	budgetRepo storage.BudgetRepository
	ruleRepo   storage.RuleRepository
	logger     *slog.Logger
}

// NewBudgetListHandler creates a list-all budgets handler.
func NewBudgetListHandler(budgetRepo storage.BudgetRepository, ruleRepo storage.RuleRepository, logger *slog.Logger) (*BudgetListHandler, error) {
	if budgetRepo == nil {
		return nil, fmt.Errorf("budget repository is required")
	}
	if ruleRepo == nil {
		return nil, fmt.Errorf("rule repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &BudgetListHandler{budgetRepo: budgetRepo, ruleRepo: ruleRepo, logger: logger}, nil
}

// BudgetKind discriminates real-rule budgets from synthetic ones so the UI
// can group them. New synthetic sources should add a new constant.
type BudgetKind string

const (
	BudgetKindRule       BudgetKind = "rule"
	BudgetKindSimulation BudgetKind = "simulation"
)

// BudgetEntry is the wire shape returned by the list endpoint. It mirrors
// the storage RuleBudget plus annotations resolved server-side so clients
// don't need a second roundtrip.
type BudgetEntry struct {
	ID         string     `json:"id"`
	Kind       BudgetKind `json:"kind"`
	RuleID     string     `json:"rule_id"`
	RuleName   string     `json:"rule_name,omitempty"`
	RuleType   string     `json:"rule_type,omitempty"`
	RuleMode   string     `json:"rule_mode,omitempty"`
	RuleOwner  string     `json:"rule_owner,omitempty"`
	// SignerAddress is set for kind=simulation budgets, decoded from the
	// "sim:<address>" rule_id used by the simulation fallback. Real-rule
	// budgets keep this empty (the signer is implicit from the rule's
	// own scope).
	SignerAddress string `json:"signer_address,omitempty"`
	Unit          string `json:"unit"`
	MaxTotal      string `json:"max_total"`
	MaxPerTx      string `json:"max_per_tx"`
	Spent         string `json:"spent"`
	TxCount       int    `json:"tx_count"`
	MaxTxCount    int    `json:"max_tx_count"`
	AlertPct      int    `json:"alert_pct"`
	AlertSent     bool   `json:"alert_sent"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// ListBudgetsResponse wraps the list so future pagination metadata has a
// place to land without a breaking shape change.
type ListBudgetsResponse struct {
	Budgets []BudgetEntry `json:"budgets"`
	Total   int           `json:"total"`
}

// ServeHTTP handles GET /api/v1/evm/budgets.
func (h *BudgetListHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	budgets, err := h.budgetRepo.ListAll(r.Context())
	if err != nil {
		h.logger.Error("failed to list budgets", "error", err)
		h.writeError(w, "failed to list budgets", http.StatusInternalServerError)
		return
	}

	entries := make([]BudgetEntry, 0, len(budgets))
	for _, b := range budgets {
		entry, ok := h.annotate(r.Context(), apiKey, b)
		if !ok {
			continue
		}
		entries = append(entries, entry)
	}

	h.writeJSON(w, ListBudgetsResponse{Budgets: entries, Total: len(entries)}, http.StatusOK)
}

// annotate enriches a budget row with rule/simulation metadata and
// performs per-key authorization. Returns (entry, true) when the caller
// is allowed to see the row, (zero, false) otherwise.
func (h *BudgetListHandler) annotate(ctx context.Context, apiKey *types.APIKey, b *types.RuleBudget) (BudgetEntry, bool) {
	entry := BudgetEntry{
		ID:         b.ID,
		RuleID:     string(b.RuleID),
		Unit:       b.Unit,
		MaxTotal:   b.MaxTotal,
		MaxPerTx:   b.MaxPerTx,
		Spent:      b.Spent,
		TxCount:    b.TxCount,
		MaxTxCount: b.MaxTxCount,
		AlertPct:   b.AlertPct,
		AlertSent:  b.AlertSent,
		CreatedAt:  b.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:  b.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	// Synthetic simulation budget. The rule_id has the form
	// "sim:0x<addr>" set by the simulation fallback rule.
	if strings.HasPrefix(string(b.RuleID), "sim:") {
		entry.Kind = BudgetKindSimulation
		entry.SignerAddress = strings.TrimPrefix(string(b.RuleID), "sim:")
		// Non-admin/dev callers don't see simulation budgets in v1 —
		// they're an operator-level view; agents shouldn't infer
		// signer-level spend from peers' traffic.
		if !apiKey.IsAdmin() && !apiKey.IsDev() {
			return BudgetEntry{}, false
		}
		return entry, true
	}

	// Real rule. Look up so we can show the human name + enforce
	// ownership for agents.
	entry.Kind = BudgetKindRule
	rule, err := h.ruleRepo.Get(ctx, b.RuleID)
	if err != nil {
		// Orphaned budget (rule deleted, row left behind) — still show
		// to admin/dev so they can clean it up; hide from others.
		if !apiKey.IsAdmin() && !apiKey.IsDev() {
			return BudgetEntry{}, false
		}
		return entry, true
	}
	entry.RuleName = rule.Name
	entry.RuleType = string(rule.Type)
	entry.RuleMode = string(rule.Mode)
	entry.RuleOwner = rule.Owner

	if apiKey.IsAdmin() || apiKey.IsDev() {
		return entry, true
	}
	// Agent: must own the rule.
	if rule.Owner == apiKey.ID {
		return entry, true
	}
	return BudgetEntry{}, false
}

func (h *BudgetListHandler) writeJSON(w http.ResponseWriter, v any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

func (h *BudgetListHandler) writeError(w http.ResponseWriter, message string, status int) {
	h.writeJSON(w, handler.ErrorResponse{Error: message}, status)
}
