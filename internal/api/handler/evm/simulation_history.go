// Package evm — simulation_history.go lists persisted simulation snapshots
// for operator debugging (GET /api/v1/evm/simulations).

package evm

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// SimulationHistoryHandler implements GET /api/v1/evm/simulations.
type SimulationHistoryHandler struct {
	simRepo storage.RequestSimulationRepository
	logger  *slog.Logger
}

// NewSimulationHistoryHandler validates deps and returns the handler.
func NewSimulationHistoryHandler(
	simRepo storage.RequestSimulationRepository,
	logger *slog.Logger,
) (*SimulationHistoryHandler, error) {
	if simRepo == nil {
		return nil, errors.New("simulation repository is required")
	}
	if logger == nil {
		return nil, errors.New("logger is required")
	}
	return &SimulationHistoryHandler{simRepo: simRepo, logger: logger}, nil
}

// ListSimulationsResponse is the JSON envelope for simulation history.
type ListSimulationsResponse struct {
	Simulations []*SimulationHistoryItem `json:"simulations"`
	HasMore     bool                     `json:"has_more"`
	NextCursor  string                   `json:"next_cursor,omitempty"`
	NextCursorID string                  `json:"next_cursor_id,omitempty"`
}

// SimulationHistoryItem is a list-row view of a persisted simulation snapshot.
type SimulationHistoryItem struct {
	SignRequestID string    `json:"sign_request_id"`
	ChainID       string    `json:"chain_id"`
	Decision      string    `json:"decision"`
	Reason        string    `json:"reason,omitempty"`
	Success       bool      `json:"success"`
	GasUsed       uint64    `json:"gas_used"`
	RevertReason  string    `json:"revert_reason,omitempty"`
	SimulatedAt   time.Time `json:"simulated_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ServeHTTP handles GET /api/v1/evm/simulations.
func (h *SimulationHistoryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	q := r.URL.Query()
	filter := storage.ListRequestSimulationsFilter{
		Decision: q.Get("decision"),
		ChainID:  q.Get("chain_id"),
		Limit:    parseIntDefault(q.Get("limit"), 0),
		CursorID: q.Get("cursor_id"),
	}
	if !apiKey.IsAdmin() {
		filter.APIKeyID = apiKey.ID
	}
	if s := q.Get("success"); s != "" {
		v := s == "true" || s == "1"
		filter.Success = &v
	}
	if c := q.Get("cursor"); c != "" {
		if ts, err := time.Parse(time.RFC3339Nano, c); err == nil {
			filter.CursorUpdatedAt = &ts
		}
	}

	rows, hasMore, err := h.simRepo.List(r.Context(), filter)
	if err != nil {
		h.logger.Error("list simulations failed", slog.String("error", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "list failed")
		return
	}

	items := make([]*SimulationHistoryItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, &SimulationHistoryItem{
			SignRequestID: row.SignRequestID,
			ChainID:       row.ChainID,
			Decision:      row.Decision,
			Reason:        row.Reason,
			Success:       row.Success,
			GasUsed:       row.GasUsed,
			RevertReason:  row.RevertReason,
			SimulatedAt:   row.SimulatedAt,
			UpdatedAt:     row.UpdatedAt,
		})
	}

	resp := ListSimulationsResponse{
		Simulations: items,
		HasMore:     hasMore,
	}
	if hasMore && len(rows) > 0 {
		last := rows[len(rows)-1]
		resp.NextCursor = last.UpdatedAt.Format(time.RFC3339Nano)
		resp.NextCursorID = last.SignRequestID
	}

	h.writeJSON(w, http.StatusOK, resp)
}

func parseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func (h *SimulationHistoryHandler) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (h *SimulationHistoryHandler) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
