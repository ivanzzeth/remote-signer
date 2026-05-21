// Package evm — transactions.go is the read-only HTTP surface over
// the daemon's on-chain Transaction records. The wallet RPC proxy
// writes; this handler reads.
//
// Visibility model:
//   - Admin sees every row.
//   - Non-admin sees only rows whose linked sign_request was created
//     by their api_key_id. The scoping is enforced server-side via
//     TransactionFilter.APIKeyID — a client that passes a different
//     api_key_id gets 403, mirroring the existing /api/v1/evm/signers
//     filter behaviour.

package evm

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// TransactionsHandler implements GET /api/v1/evm/transactions[/{id}].
type TransactionsHandler struct {
	repo   storage.TransactionRepository
	logger *slog.Logger
}

// NewTransactionsHandler validates deps and returns a ready handler.
func NewTransactionsHandler(repo storage.TransactionRepository, logger *slog.Logger) (*TransactionsHandler, error) {
	if repo == nil {
		return nil, errors.New("transaction repository is required")
	}
	if logger == nil {
		return nil, errors.New("logger is required")
	}
	return &TransactionsHandler{repo: repo, logger: logger}, nil
}

// ServeHTTP routes /api/v1/evm/transactions (list) and
// /api/v1/evm/transactions/{id} (item).
func (h *TransactionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/evm/transactions")
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		h.list(w, r, apiKey)
		return
	}
	if strings.Contains(path, "/") {
		h.writeError(w, http.StatusNotFound, "not found")
		return
	}
	h.get(w, r, apiKey, path)
}

// TransactionsListResponse is the envelope for the index route.
type TransactionsListResponse struct {
	Transactions []*types.Transaction `json:"transactions"`
	Total        int                  `json:"total"`
	HasMore      bool                 `json:"has_more"`
}

func (h *TransactionsHandler) list(w http.ResponseWriter, r *http.Request, apiKey *types.APIKey) {
	q := r.URL.Query()
	filter := types.TransactionFilter{
		SignRequestID: q.Get("sign_request_id"),
		ChainID:       q.Get("chain_id"),
		FromAddress:   q.Get("from"),
		APIKeyID:      q.Get("api_key_id"),
	}
	if s := q.Get("status"); s != "" {
		st := types.TransactionStatus(s)
		filter.Status = &st
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			h.writeError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		filter.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			h.writeError(w, http.StatusBadRequest, "invalid offset")
			return
		}
		filter.Offset = n
	}

	// Visibility gate. Non-admin callers may NOT see rows belonging
	// to another api key — pin server-side so a bad client can't
	// bypass via a hand-rolled query string. Mirrors the
	// /signers?api_key_id behavior (signer_crud.go).
	if !apiKey.IsAdmin() {
		if filter.APIKeyID != "" && filter.APIKeyID != apiKey.ID {
			h.writeError(w, http.StatusForbidden,
				"forbidden: only admins can filter by another api key")
			return
		}
		filter.APIKeyID = apiKey.ID
	}

	total, err := h.repo.Count(r.Context(), filter)
	if err != nil {
		h.logger.Error("transactions: count failed", slog.String("error", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "failed to count")
		return
	}
	items, err := h.repo.List(r.Context(), filter)
	if err != nil {
		h.logger.Error("transactions: list failed", slog.String("error", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "failed to list")
		return
	}
	h.writeJSON(w, http.StatusOK, TransactionsListResponse{
		Transactions: items,
		Total:        total,
		HasMore:      filter.Offset+len(items) < total,
	})
}

func (h *TransactionsHandler) get(w http.ResponseWriter, r *http.Request, apiKey *types.APIKey, id string) {
	tx, err := h.repo.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, types.ErrNotFound) {
			h.writeError(w, http.StatusNotFound, "transaction not found")
			return
		}
		h.logger.Error("transactions: get failed", slog.String("error", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "failed to get")
		return
	}
	// Visibility check for non-admin: a non-admin can only fetch a
	// transaction whose linked sign_request belongs to them.
	// Implementing via the filter saves a separate lookup — request
	// the row by ID + APIKeyID; a mismatch comes back as not-found,
	// matching the standard 404-on-no-permission posture.
	if !apiKey.IsAdmin() {
		owned, ownErr := h.repo.List(r.Context(), types.TransactionFilter{APIKeyID: apiKey.ID, Limit: 1, Offset: 0, SignRequestID: tx.SignRequestID})
		if ownErr != nil || len(owned) == 0 || owned[0].ID != tx.ID {
			h.writeError(w, http.StatusNotFound, "transaction not found")
			return
		}
	}
	h.writeJSON(w, http.StatusOK, tx)
}

func (h *TransactionsHandler) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (h *TransactionsHandler) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
