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
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/ivanzzeth/remote-signer/internal/validate"
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
	// ⛔ No method check: the route is method-scoped (see setupRoutes) and Go's
	// ServeMux answers 405 for anything else before this runs.
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/evm/transactions")
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		h.list(w, r, apiKey)
		return
	}
	if strings.Contains(path, "/") {
		respond.Error(w, "not found", http.StatusNotFound, h.logger)
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
	from := q.Get("from")
	if from == "" {
		from = q.Get("signer_address")
	}
	filter := types.TransactionFilter{
		SignRequestID: q.Get("sign_request_id"),
		ChainID:       q.Get("chain_id"),
		FromAddress:   from,
		APIKeyID:      q.Get("api_key_id"),
		SignType:      q.Get("sign_type"),
	}
	if s := q.Get("status"); s != "" {
		st := types.TransactionStatus(s)
		filter.Status = &st
	}
	if roleStr := q.Get("role"); roleStr != "" {
		if !types.IsValidAPIKeyRole(roleStr) {
			respond.Error(w, "invalid role", http.StatusBadRequest, h.logger)
			return
		}
		filter.APIKeyRole = types.APIKeyRole(roleStr)
	}
	if filter.SignType != "" && !validate.ValidSignTypes[filter.SignType] {
		respond.Error(w, "invalid sign_type", http.StatusBadRequest, h.logger)
		return
	}
	if filter.FromAddress != "" && !validate.IsValidEthereumAddress(filter.FromAddress) {
		respond.Error(w, "invalid from address", http.StatusBadRequest, h.logger)
		return
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			respond.Error(w, "invalid limit", http.StatusBadRequest, h.logger)
			return
		}
		filter.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			respond.Error(w, "invalid offset", http.StatusBadRequest, h.logger)
			return
		}
		filter.Offset = n
	}

	// Visibility gate. Non-admin/dev callers may NOT see rows belonging
	// to another api key — pin server-side so a bad client can't
	// bypass via a hand-rolled query string. Mirrors the
	// /signers?api_key_id behavior (signer_crud.go).
	if !apiKey.IsAdmin() && !apiKey.IsDev() {
		if filter.APIKeyID != "" && filter.APIKeyID != apiKey.ID {
			respond.Error(w, "forbidden: only admins can filter by another api key", http.StatusForbidden, h.logger)

			return
		}
		filter.APIKeyID = apiKey.ID
		filter.APIKeyRole = ""
	}

	total, err := h.repo.Count(r.Context(), filter)
	if err != nil {
		h.logger.Error("transactions: count failed", slog.String("error", err.Error()))
		respond.Error(w, "failed to count", http.StatusInternalServerError, h.logger)
		return
	}
	items, err := h.repo.List(r.Context(), filter)
	if err != nil {
		h.logger.Error("transactions: list failed", slog.String("error", err.Error()))
		respond.Error(w, "failed to list", http.StatusInternalServerError, h.logger)
		return
	}
	respond.JSON(w, TransactionsListResponse{
		Transactions: items,
		Total:        total,
		HasMore:      filter.Offset+len(items) < total,
	}, http.StatusOK, h.logger)

}

func (h *TransactionsHandler) get(w http.ResponseWriter, r *http.Request, apiKey *types.APIKey, id string) {
	tx, err := h.repo.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, types.ErrNotFound) {
			respond.Error(w, "transaction not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("transactions: get failed", slog.String("error", err.Error()))
		respond.Error(w, "failed to get", http.StatusInternalServerError, h.logger)
		return
	}
	// Visibility check for non-admin: a non-admin can only fetch a
	// transaction whose linked sign_request belongs to them.
	// Implementing via the filter saves a separate lookup — request
	// the row by ID + APIKeyID; a mismatch comes back as not-found,
	// matching the standard 404-on-no-permission posture.
	if !apiKey.IsAdmin() && !apiKey.IsDev() {
		owned, ownErr := h.repo.List(r.Context(), types.TransactionFilter{APIKeyID: apiKey.ID, Limit: 1, Offset: 0, SignRequestID: tx.SignRequestID})
		if ownErr != nil || len(owned) == 0 || owned[0].ID != tx.ID {
			respond.Error(w, "transaction not found", http.StatusNotFound, h.logger)
			return
		}
	}
	respond.JSON(w, tx, http.StatusOK, h.logger)
}
