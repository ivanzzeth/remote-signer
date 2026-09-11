// Package evm — request_simulation.go is the read-only HTTP surface
// over the daemon's simulation pipeline output. The web UI's
// request-detail page polls it while a request is pending so the
// operator sees what the tx would do — balance changes + events +
// decision — before deciding to manually approve.
//
// Visibility piggybacks on the sign-request visibility model: a
// non-admin caller can only fetch the simulation row for a sign
// request they own. The handler joins via the linked sign_request
// row's api_key_id.

package evm

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/respond"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// RequestSimulationHandler implements
// GET /api/v1/evm/requests/{id}/simulation.
type RequestSimulationHandler struct {
	simRepo storage.RequestSimulationRepository
	reqRepo storage.RequestRepository
	logger  *slog.Logger
}

// NewRequestSimulationHandler validates deps and returns the handler.
func NewRequestSimulationHandler(
	simRepo storage.RequestSimulationRepository,
	reqRepo storage.RequestRepository,
	logger *slog.Logger,
) (*RequestSimulationHandler, error) {
	if simRepo == nil {
		return nil, errors.New("simulation repository is required")
	}
	if reqRepo == nil {
		return nil, errors.New("request repository is required")
	}
	if logger == nil {
		return nil, errors.New("logger is required")
	}
	return &RequestSimulationHandler{simRepo: simRepo, reqRepo: reqRepo, logger: logger}, nil
}

// ServeHTTP serves GET /api/v1/evm/requests/{id}/simulation — one endpoint, one
// route (internal/api/module_requests.go).
//
// ⚠️ The method guard, the suffix check and the "invalid path" 400 that used to
// stand here are gone, and they are gone rather than moved: this function was
// reached through the method-less "/api/v1/evm/requests/" prefix and a closure
// that picked it by strings.HasSuffix(path, "/simulation"), so nothing but the
// handler itself could say which verb and which shape it served. The route says
// both now, and a shape it does not describe reaches no handler at all — which is
// why the checks are not merely redundant but unreachable.
func (h *RequestSimulationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		respond.Error(w, "unauthorized", http.StatusUnauthorized, h.logger)
		return
	}

	requestID := r.PathValue("id")

	// Visibility gate: re-fetch the parent sign_request so we can
	// enforce the same "caller must own this id" rule the rest of
	// /requests/* uses. 404 (not 403) on a foreign id so a probing
	// caller can't enumerate other operators' request IDs by
	// pattern-watching response codes.
	parent, err := h.reqRepo.Get(r.Context(), types.SignRequestID(requestID))
	if err != nil {
		if errors.Is(err, types.ErrNotFound) {
			respond.Error(w, "request not found", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("simulation: parent request lookup failed", slog.String("error", err.Error()))
		respond.Error(w, "lookup failed", http.StatusInternalServerError, h.logger)
		return
	}
	if !apiKey.IsAdmin() && parent.APIKeyID != apiKey.ID {
		respond.Error(w, "request not found", http.StatusNotFound, h.logger)
		return
	}

	sim, err := h.simRepo.GetByRequestID(r.Context(), requestID)
	if err != nil {
		if errors.Is(err, types.ErrNotFound) {
			// 404 → the UI renders "evaluating, please wait" + spinner
			// instead of a hard error while the simulation pipeline
			// is still in flight on a fresh request.
			respond.Error(w, "simulation not yet available", http.StatusNotFound, h.logger)
			return
		}
		h.logger.Error("simulation: row lookup failed", slog.String("error", err.Error()))
		respond.Error(w, "lookup failed", http.StatusInternalServerError, h.logger)
		return
	}
	respond.JSON(w, sim, http.StatusOK, h.logger)
}
