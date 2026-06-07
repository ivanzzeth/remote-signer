package evm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ErrCannotCreateSimulationBudget is returned when an operator tries to
// POST a row whose rule_id starts with "sim:". Those are owned by the
// simulation fallback's auto-create path and have a security envelope
// (MaxDynamicUnits, decimals lookup, post-create TOCTOU re-check) that
// a manual POST would bypass.
var ErrCannotCreateSimulationBudget = errors.New("simulation budgets are created by the simulation engine, not via POST")

// BudgetListHandler serves the /api/v1/evm/budgets collection:
//
//   GET  /api/v1/evm/budgets   — every budget row (PermReadBudgets)
//   POST /api/v1/evm/budgets   — create a budget for an existing rule
//                                (PermManageBudgets, refuses sim:* IDs)
//
// Per-rule listing under /rules/{id}/budgets remains and still drives
// the rule-detail view; this endpoint exists because synthetic
// simulation budgets have no entry in the rules table, so a UI that
// fans out over rules.list() can never see them.
type BudgetListHandler struct {
	budgetRepo  storage.BudgetRepository
	ruleRepo    storage.RuleRepository
	auditLogger *audit.AuditLogger
	logger      *slog.Logger
}

// NewBudgetListHandler creates the collection-level handler.
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

// SetAuditLogger wires audit-event emission for create. Optional.
func (h *BudgetListHandler) SetAuditLogger(al *audit.AuditLogger) {
	h.auditLogger = al
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
	UnitDisplay        string `json:"unit_display,omitempty"`
	BudgetPeriod       string `json:"budget_period,omitempty"`
	PeriodStart        string `json:"period_start,omitempty"`
	PeriodEndsAt       string `json:"period_ends_at,omitempty"`
	EnforcesLimit      bool   `json:"enforces_limit"`
	IsStalePlaceholder bool   `json:"is_stale_placeholder,omitempty"`
}

// ListBudgetsResponse wraps the list so future pagination metadata has a
// place to land without a breaking shape change.
type ListBudgetsResponse struct {
	Budgets []BudgetEntry `json:"budgets"`
	Total   int           `json:"total"`
}

// CreateBudgetRequest is the POST body. RuleID + Unit form the row's
// identity (the budget ID is a deterministic hash of the two). The
// daemon refuses RuleID values that start with "sim:" — those belong
// to the simulation fallback's owned namespace.
type CreateBudgetRequest struct {
	RuleID     string `json:"rule_id"`
	Unit       string `json:"unit"`
	MaxTotal   string `json:"max_total"`
	MaxPerTx   string `json:"max_per_tx,omitempty"`
	MaxTxCount int    `json:"max_tx_count,omitempty"`
	AlertPct   int    `json:"alert_pct,omitempty"`
}

// UpdateBudgetRequest patches mutable fields on an existing budget.
// All fields are pointers so the JSON omitted-vs-zero distinction
// survives the round-trip — sending {"alert_pct":0} explicitly clears
// the threshold while omitting the field leaves it untouched. RuleID,
// Unit, and ID can never be changed via this endpoint; identity
// transitions require delete+create.
type UpdateBudgetRequest struct {
	MaxTotal   *string `json:"max_total,omitempty"`
	MaxPerTx   *string `json:"max_per_tx,omitempty"`
	MaxTxCount *int    `json:"max_tx_count,omitempty"`
	AlertPct   *int    `json:"alert_pct,omitempty"`
	AlertSent  *bool   `json:"alert_sent,omitempty"`
	Spent      *string `json:"spent,omitempty"`
	TxCount    *int    `json:"tx_count,omitempty"`
}

// ServeHTTP handles /api/v1/evm/budgets (collection).
func (h *BudgetListHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.handleList(w, r, apiKey)
	case http.MethodPost:
		if !middleware.HasPermission(apiKey.Role, middleware.PermManageBudgets) {
			h.writeError(w, "forbidden", http.StatusForbidden)
			return
		}
		h.handleCreate(w, r, apiKey)
	default:
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *BudgetListHandler) handleList(w http.ResponseWriter, r *http.Request, apiKey *types.APIKey) {
	budgets, err := h.budgetRepo.ListAll(r.Context())
	if err != nil {
		h.logger.Error("failed to list budgets", "error", err)
		h.writeError(w, "failed to list budgets", http.StatusInternalServerError)
		return
	}

	entries := make([]BudgetEntry, 0, len(budgets))
	unitsByRule := make(map[types.RuleID][]string, len(budgets))
	for _, b := range budgets {
		unitsByRule[b.RuleID] = append(unitsByRule[b.RuleID], b.Unit)
	}
	for _, b := range budgets {
		b = h.maybeRenewBudget(r, b)
		entry, ok := h.annotate(r.Context(), apiKey, b, unitsByRule[b.RuleID])
		if !ok {
			continue
		}
		entries = append(entries, entry)
	}

	h.writeJSON(w, ListBudgetsResponse{Budgets: entries, Total: len(entries)}, http.StatusOK)
}

func (h *BudgetListHandler) handleCreate(w http.ResponseWriter, r *http.Request, apiKey *types.APIKey) {
	var req CreateBudgetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.RuleID = strings.TrimSpace(req.RuleID)
	req.Unit = strings.TrimSpace(req.Unit)
	if req.RuleID == "" {
		h.writeError(w, "rule_id is required", http.StatusBadRequest)
		return
	}
	if req.Unit == "" {
		h.writeError(w, "unit is required", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(req.RuleID, "sim:") {
		h.writeError(w, ErrCannotCreateSimulationBudget.Error(), http.StatusForbidden)
		return
	}
	if !isValidBudgetLimit(req.MaxTotal) {
		h.writeError(w, "max_total must be a non-negative decimal or \"-1\"", http.StatusBadRequest)
		return
	}
	if req.MaxPerTx != "" && !isValidBudgetLimit(req.MaxPerTx) {
		h.writeError(w, "max_per_tx must be a non-negative decimal or \"-1\"", http.StatusBadRequest)
		return
	}
	if req.MaxTxCount < 0 {
		h.writeError(w, "max_tx_count must be >= 0", http.StatusBadRequest)
		return
	}
	if req.AlertPct < 0 || req.AlertPct > 100 {
		h.writeError(w, "alert_pct must be between 0 and 100", http.StatusBadRequest)
		return
	}

	// Ensure the referenced rule actually exists; orphan budgets that
	// debit a non-existent rule would never get hit and confuse the UI.
	rule, err := h.ruleRepo.Get(r.Context(), types.RuleID(req.RuleID))
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "rule not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to load rule for budget create", "error", err, "rule_id", req.RuleID)
		h.writeError(w, "failed to load rule", http.StatusInternalServerError)
		return
	}

	maxPerTx := req.MaxPerTx
	if maxPerTx == "" {
		maxPerTx = "-1"
	}
	alertPct := req.AlertPct
	if alertPct == 0 {
		alertPct = 80
	}
	budget := &types.RuleBudget{
		ID:         types.BudgetID(types.RuleID(req.RuleID), req.Unit),
		RuleID:     types.RuleID(req.RuleID),
		Unit:       req.Unit,
		MaxTotal:   req.MaxTotal,
		MaxPerTx:   maxPerTx,
		MaxTxCount: req.MaxTxCount,
		Spent:      "0",
		TxCount:    0,
		AlertPct:   alertPct,
		AlertSent:  false,
	}

	created, wasCreated, err := h.budgetRepo.CreateOrGet(r.Context(), budget)
	if err != nil {
		h.logger.Error("failed to create budget", "error", err, "rule_id", req.RuleID, "unit", req.Unit)
		h.writeError(w, "failed to create budget", http.StatusInternalServerError)
		return
	}
	if !wasCreated {
		h.writeError(w, "budget already exists for this rule+unit", http.StatusConflict)
		return
	}

	if h.auditLogger != nil {
		h.auditLogger.LogBudgetMutation(r.Context(), apiKey.ID, "create", created.ID,
			fmt.Sprintf("rule=%s unit=%s max_total=%s", req.RuleID, req.Unit, req.MaxTotal))
	}

	entry, _ := h.annotateFromRule(rule, created)
	h.writeJSON(w, entry, http.StatusCreated)
}

// annotate enriches a budget row with rule/simulation metadata and
// performs per-key authorization. Returns (entry, true) when the caller
// is allowed to see the row, (zero, false) otherwise.
func (h *BudgetListHandler) annotate(ctx context.Context, apiKey *types.APIKey, b *types.RuleBudget, siblingUnits []string) (BudgetEntry, bool) {
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
		applyBudgetUX(&entry, nil, b, siblingUnits)
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
		applyBudgetUX(&entry, nil, b, siblingUnits)
		return entry, true
	}
	entry.RuleName = rule.Name
	entry.RuleType = string(rule.Type)
	entry.RuleMode = string(rule.Mode)
	entry.RuleOwner = rule.Owner
	applyBudgetUX(&entry, rule, b, siblingUnits)

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

// annotateFromRule is a fast-path used by handleCreate where we already
// have the rule in hand and don't need to refetch from the repo.
func (h *BudgetListHandler) annotateFromRule(rule *types.Rule, b *types.RuleBudget) (BudgetEntry, bool) {
	entry := BudgetEntry{
		ID:         b.ID,
		Kind:       BudgetKindRule,
		RuleID:     string(b.RuleID),
		RuleName:   rule.Name,
		RuleType:   string(rule.Type),
		RuleMode:   string(rule.Mode),
		RuleOwner:  rule.Owner,
		Unit:       b.Unit,
		MaxTotal:   b.MaxTotal,
		MaxPerTx:   b.MaxPerTx,
		Spent:      b.Spent,
		TxCount:    b.TxCount,
		MaxTxCount: b.MaxTxCount,
		AlertPct:   b.AlertPct,
		AlertSent:  b.AlertSent,
		CreatedAt:  b.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  b.UpdatedAt.Format(time.RFC3339),
	}
	applyBudgetUX(&entry, rule, b, []string{b.Unit})
	return entry, true
}

// BudgetItemHandler serves the per-budget routes:
//
//   GET    /api/v1/evm/budgets/{id}          — detail   (PermReadBudgets)
//   PATCH  /api/v1/evm/budgets/{id}          — update   (PermManageBudgets)
//   DELETE /api/v1/evm/budgets/{id}          — delete   (PermManageBudgets)
//   POST   /api/v1/evm/budgets/{id}/reset    — reset    (PermManageBudgets)
//
// {id} is the budget primary key — either the SHA256 hash returned by
// BudgetID(rule_id, unit) for real-rule budgets, or the literal
// "sim:<address>" base id of simulation budgets (which the daemon
// stores as the hash too, but the UI also accepts the human form for
// links from the request detail page). The handler accepts both forms.
type BudgetItemHandler struct {
	budgetRepo  storage.BudgetRepository
	ruleRepo    storage.RuleRepository
	auditLogger *audit.AuditLogger
	logger      *slog.Logger
}

// NewBudgetItemHandler creates the per-item handler.
func NewBudgetItemHandler(budgetRepo storage.BudgetRepository, ruleRepo storage.RuleRepository, logger *slog.Logger) (*BudgetItemHandler, error) {
	if budgetRepo == nil {
		return nil, fmt.Errorf("budget repository is required")
	}
	if ruleRepo == nil {
		return nil, fmt.Errorf("rule repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &BudgetItemHandler{budgetRepo: budgetRepo, ruleRepo: ruleRepo, logger: logger}, nil
}

// SetAuditLogger wires audit-event emission for mutations.
func (h *BudgetItemHandler) SetAuditLogger(al *audit.AuditLogger) {
	h.auditLogger = al
}

// ServeHTTP routes a path of the form /api/v1/evm/budgets/{id}[/reset]
// to the right method-specific handler. {id} is the budget primary key
// (BudgetID(rule_id, unit) — a SHA256 hex); callers find it via the
// list endpoint, never construct it client-side.
func (h *BudgetItemHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	const prefix = "/api/v1/evm/budgets/"
	tail := strings.TrimPrefix(r.URL.Path, prefix)
	if tail == "" || tail == "/" {
		h.writeError(w, "budget id is required", http.StatusBadRequest)
		return
	}

	if strings.HasPrefix(tail, "by-rule/") {
		ruleID := strings.TrimPrefix(tail, "by-rule/")
		ruleID = strings.Trim(ruleID, "/")
		if ruleID == "" {
			h.writeError(w, "rule_id is required", http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodDelete {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !middleware.HasPermission(apiKey.Role, middleware.PermManageBudgets) {
			h.writeError(w, "forbidden", http.StatusForbidden)
			return
		}
		h.handleDeleteByRuleID(w, r, apiKey, ruleID)
		return
	}

	if strings.HasSuffix(tail, "/reset") {
		id := strings.TrimSuffix(tail, "/reset")
		if r.Method != http.MethodPost {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !middleware.HasPermission(apiKey.Role, middleware.PermManageBudgets) {
			h.writeError(w, "forbidden", http.StatusForbidden)
			return
		}
		h.handleReset(w, r, apiKey, id)
		return
	}

	id := tail
	switch r.Method {
	case http.MethodGet:
		h.handleGet(w, r, apiKey, id)
	case http.MethodPatch:
		if !middleware.HasPermission(apiKey.Role, middleware.PermManageBudgets) {
			h.writeError(w, "forbidden", http.StatusForbidden)
			return
		}
		h.handleUpdate(w, r, apiKey, id)
	case http.MethodDelete:
		if !middleware.HasPermission(apiKey.Role, middleware.PermManageBudgets) {
			h.writeError(w, "forbidden", http.StatusForbidden)
			return
		}
		h.handleDelete(w, r, apiKey, id)
	default:
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *BudgetItemHandler) handleGet(w http.ResponseWriter, r *http.Request, apiKey *types.APIKey, id string) {
	b, ok := h.loadBudget(w, r, id)
	if !ok {
		return
	}
	b = h.maybeRenewBudget(r, b)
	entry, allowed := h.annotate(r.Context(), apiKey, b)
	if !allowed {
		h.writeError(w, "not found", http.StatusNotFound)
		return
	}
	h.writeJSON(w, entry, http.StatusOK)
}

func (h *BudgetItemHandler) handleUpdate(w http.ResponseWriter, r *http.Request, apiKey *types.APIKey, id string) {
	var req UpdateBudgetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	b, ok := h.loadBudget(w, r, id)
	if !ok {
		return
	}

	if req.MaxTotal != nil {
		if !isValidBudgetLimit(*req.MaxTotal) {
			h.writeError(w, "max_total must be a non-negative decimal or \"-1\"", http.StatusBadRequest)
			return
		}
		b.MaxTotal = *req.MaxTotal
	}
	if req.MaxPerTx != nil {
		if !isValidBudgetLimit(*req.MaxPerTx) {
			h.writeError(w, "max_per_tx must be a non-negative decimal or \"-1\"", http.StatusBadRequest)
			return
		}
		b.MaxPerTx = *req.MaxPerTx
	}
	if req.MaxTxCount != nil {
		if *req.MaxTxCount < 0 {
			h.writeError(w, "max_tx_count must be >= 0", http.StatusBadRequest)
			return
		}
		b.MaxTxCount = *req.MaxTxCount
	}
	if req.AlertPct != nil {
		if *req.AlertPct < 0 || *req.AlertPct > 100 {
			h.writeError(w, "alert_pct must be between 0 and 100", http.StatusBadRequest)
			return
		}
		b.AlertPct = *req.AlertPct
	}
	if req.AlertSent != nil {
		b.AlertSent = *req.AlertSent
	}
	if req.Spent != nil {
		if !isValidBudgetAmount(*req.Spent) {
			h.writeError(w, "spent must be a non-negative decimal", http.StatusBadRequest)
			return
		}
		b.Spent = *req.Spent
	}
	if req.TxCount != nil {
		if *req.TxCount < 0 {
			h.writeError(w, "tx_count must be >= 0", http.StatusBadRequest)
			return
		}
		b.TxCount = *req.TxCount
	}

	if err := h.budgetRepo.Update(r.Context(), b); err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "budget not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to update budget", "error", err, "id", id)
		h.writeError(w, "failed to update budget", http.StatusInternalServerError)
		return
	}

	if h.auditLogger != nil {
		h.auditLogger.LogBudgetMutation(r.Context(), apiKey.ID, "update", b.ID,
			fmt.Sprintf("max_total=%s max_per_tx=%s spent=%s", b.MaxTotal, b.MaxPerTx, b.Spent))
	}

	updated, _ := h.budgetRepo.Get(r.Context(), b.ID)
	if updated == nil {
		updated = b
	}
	entry, _ := h.annotate(r.Context(), apiKey, updated)
	h.writeJSON(w, entry, http.StatusOK)
}

func (h *BudgetItemHandler) handleReset(w http.ResponseWriter, r *http.Request, apiKey *types.APIKey, id string) {
	b, ok := h.loadBudget(w, r, id)
	if !ok {
		return
	}
	if err := h.budgetRepo.ResetBudget(r.Context(), b.RuleID, b.Unit, time.Time{}); err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "budget not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to reset budget", "error", err, "id", id)
		h.writeError(w, "failed to reset budget", http.StatusInternalServerError)
		return
	}
	if h.auditLogger != nil {
		h.auditLogger.LogBudgetMutation(r.Context(), apiKey.ID, "reset", b.ID, "spent=0 tx_count=0")
	}
	updated, _ := h.budgetRepo.Get(r.Context(), b.ID)
	if updated == nil {
		updated = b
	}
	entry, _ := h.annotate(r.Context(), apiKey, updated)
	h.writeJSON(w, entry, http.StatusOK)
}

func (h *BudgetItemHandler) handleDeleteByRuleID(w http.ResponseWriter, r *http.Request, apiKey *types.APIKey, ruleID string) {
	if !isBudgetCleanupRuleID(ruleID) {
		h.writeError(w, "invalid rule_id format for budget cleanup", http.StatusBadRequest)
		return
	}
	budgets, err := h.budgetRepo.ListByRuleID(r.Context(), types.RuleID(ruleID))
	if err != nil {
		h.logger.Error("failed to list budgets for rule", "error", err, "rule_id", ruleID)
		h.writeError(w, "failed to list budgets", http.StatusInternalServerError)
		return
	}
	deletedBudgets := 0
	if len(budgets) > 0 {
		if err := h.budgetRepo.DeleteByRuleID(r.Context(), types.RuleID(ruleID)); err != nil {
			h.logger.Error("failed to delete budgets by rule", "error", err, "rule_id", ruleID)
			h.writeError(w, "failed to delete budgets", http.StatusInternalServerError)
			return
		}
		deletedBudgets = len(budgets)
	}

	// Orphan synthetic placeholder: budgets already gone but sim:0x... rule row remains.
	deletedPlaceholder := false
	if isSyntheticBudgetRuleID(ruleID) {
		if err := h.ruleRepo.Delete(r.Context(), types.RuleID(ruleID)); err == nil {
			deletedPlaceholder = true
		} else if !types.IsNotFound(err) {
			h.logger.Error("failed to delete synthetic rule placeholder", "error", err, "rule_id", ruleID)
			h.writeError(w, "failed to delete synthetic rule placeholder", http.StatusInternalServerError)
			return
		}
	}

	if deletedBudgets == 0 && !deletedPlaceholder {
		h.writeError(w, "no budgets or synthetic rule placeholder found for rule", http.StatusNotFound)
		return
	}
	if h.auditLogger != nil {
		h.auditLogger.LogBudgetMutation(r.Context(), apiKey.ID, "delete_by_rule", ruleID,
			fmt.Sprintf("deleted %d budget row(s), placeholder_removed=%v", deletedBudgets, deletedPlaceholder))
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *BudgetItemHandler) handleDelete(w http.ResponseWriter, r *http.Request, apiKey *types.APIKey, id string) {
	b, ok := h.loadBudget(w, r, id)
	if !ok {
		return
	}
	if err := h.budgetRepo.Delete(r.Context(), b.ID); err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "budget not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to delete budget", "error", err, "id", id)
		h.writeError(w, "failed to delete budget", http.StatusInternalServerError)
		return
	}
	h.maybeDeleteOrphanSyntheticRule(r.Context(), b.RuleID)
	if h.auditLogger != nil {
		h.auditLogger.LogBudgetMutation(r.Context(), apiKey.ID, "delete", b.ID,
			fmt.Sprintf("rule=%s unit=%s", b.RuleID, b.Unit))
	}
	w.WriteHeader(http.StatusNoContent)
}

// maybeDeleteOrphanSyntheticRule removes the sim:0x... placeholder rule when
// the last budget row for that signer has been deleted.
func (h *BudgetItemHandler) maybeDeleteOrphanSyntheticRule(ctx context.Context, ruleID types.RuleID) {
	if !isSyntheticBudgetRuleID(string(ruleID)) {
		return
	}
	remaining, err := h.budgetRepo.ListByRuleID(ctx, ruleID)
	if err != nil || len(remaining) > 0 {
		return
	}
	if err := h.ruleRepo.Delete(ctx, ruleID); err != nil && !types.IsNotFound(err) {
		h.logger.Warn("failed to delete orphan synthetic rule after budget delete", "error", err, "rule_id", ruleID)
	}
}

// loadBudget fetches by ID. Writes the appropriate error response and
// returns ok=false on miss.
func (h *BudgetItemHandler) loadBudget(w http.ResponseWriter, r *http.Request, id string) (*types.RuleBudget, bool) {
	b, err := h.budgetRepo.Get(r.Context(), id)
	if err == nil {
		return b, true
	}
	if !types.IsNotFound(err) {
		h.logger.Error("failed to load budget", "error", err, "id", id)
		h.writeError(w, "failed to load budget", http.StatusInternalServerError)
		return nil, false
	}
	h.writeError(w, "budget not found", http.StatusNotFound)
	return nil, false
}

// annotate is BudgetListHandler.annotate's twin — kept on this handler
// so it can be unit-tested without spinning up the list. The
// authorization logic is identical so callers see consistent visibility
// across list and detail.
func (h *BudgetItemHandler) annotate(ctx context.Context, apiKey *types.APIKey, b *types.RuleBudget) (BudgetEntry, bool) {
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
		CreatedAt:  b.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  b.UpdatedAt.Format(time.RFC3339),
	}
	siblingUnits := h.siblingUnits(ctx, b.RuleID)
	if strings.HasPrefix(string(b.RuleID), "sim:") {
		entry.Kind = BudgetKindSimulation
		entry.SignerAddress = strings.TrimPrefix(string(b.RuleID), "sim:")
		if !apiKey.IsAdmin() && !apiKey.IsDev() {
			return BudgetEntry{}, false
		}
		applyBudgetUX(&entry, nil, b, siblingUnits)
		return entry, true
	}
	entry.Kind = BudgetKindRule
	rule, err := h.ruleRepo.Get(ctx, b.RuleID)
	if err != nil {
		if !apiKey.IsAdmin() && !apiKey.IsDev() {
			return BudgetEntry{}, false
		}
		applyBudgetUX(&entry, nil, b, siblingUnits)
		return entry, true
	}
	entry.RuleName = rule.Name
	entry.RuleType = string(rule.Type)
	entry.RuleMode = string(rule.Mode)
	entry.RuleOwner = rule.Owner
	applyBudgetUX(&entry, rule, b, siblingUnits)
	if apiKey.IsAdmin() || apiKey.IsDev() {
		return entry, true
	}
	if rule.Owner == apiKey.ID {
		return entry, true
	}
	return BudgetEntry{}, false
}

func (h *BudgetItemHandler) siblingUnits(ctx context.Context, ruleID types.RuleID) []string {
	list, err := h.budgetRepo.ListByRuleID(ctx, ruleID)
	if err != nil {
		return nil
	}
	units := make([]string, 0, len(list))
	for _, row := range list {
		if row != nil {
			units = append(units, row.Unit)
		}
	}
	return units
}

func (h *BudgetItemHandler) writeJSON(w http.ResponseWriter, v any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

func (h *BudgetItemHandler) writeError(w http.ResponseWriter, message string, status int) {
	h.writeJSON(w, handler.ErrorResponse{Error: message}, status)
}

func (h *BudgetListHandler) maybeRenewBudget(r *http.Request, b *types.RuleBudget) *types.RuleBudget {
	return maybeRenewBudget(r.Context(), h.budgetRepo, h.ruleRepo, b)
}

func (h *BudgetItemHandler) maybeRenewBudget(r *http.Request, b *types.RuleBudget) *types.RuleBudget {
	return maybeRenewBudget(r.Context(), h.budgetRepo, h.ruleRepo, b)
}

// maybeRenewBudget applies periodic budget renewal on read so the UI reflects
// the current period without requiring a sign attempt first.
func maybeRenewBudget(ctx context.Context, budgetRepo storage.BudgetRepository, ruleRepo storage.RuleRepository, b *types.RuleBudget) *types.RuleBudget {
	if b == nil || strings.HasPrefix(string(b.RuleID), "sim:") {
		return b
	}
	gotRule, err := ruleRepo.Get(ctx, b.RuleID)
	if err != nil {
		return b
	}
	needs, periodStart := rule.NeedsPeriodReset(gotRule, b, time.Now())
	if !needs {
		return b
	}
	if err := budgetRepo.ResetBudget(ctx, b.RuleID, b.Unit, periodStart); err != nil {
		return b
	}
	fresh, err := budgetRepo.Get(ctx, b.ID)
	if err != nil || fresh == nil {
		return b
	}
	return fresh
}

// --- shared validators ---

// isValidBudgetLimit accepts a non-negative integer literal or "-1"
// (meaning "unlimited"). The daemon stores these as varchar to handle
// uint256-scale values.
func isValidBudgetLimit(s string) bool {
	s = strings.TrimSpace(s)
	if s == "-1" {
		return true
	}
	return isValidBudgetAmount(s)
}

// isValidBudgetAmount accepts a non-negative integer literal. Used for
// limits-other-than-min-sentinel and for the spent field.
func isValidBudgetAmount(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	n := new(big.Int)
	if _, ok := n.SetString(s, 10); !ok {
		return false
	}
	return n.Sign() >= 0
}

