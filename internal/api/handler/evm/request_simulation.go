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
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

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

// ServeHTTP only honors GET. The path must end in "/simulation"; the
// id is the path segment immediately before. Anything else is a 404
// shape mismatch — the router only sends us URLs that match the
// expected pattern, but defence-in-depth means we still validate.
func (h *RequestSimulationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Path: /api/v1/evm/requests/{id}/simulation
	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	// expected ["", "api", "v1", "evm", "requests", "{id}", "simulation"]
	if len(parts) < 7 || parts[len(parts)-1] != "simulation" {
		h.writeError(w, http.StatusBadRequest, "invalid path: expected /api/v1/evm/requests/{id}/simulation")
		return
	}
	requestID := parts[len(parts)-2]
	if requestID == "" {
		h.writeError(w, http.StatusBadRequest, "request id is required")
		return
	}

	// Visibility gate: re-fetch the parent sign_request so we can
	// enforce the same "caller must own this id" rule the rest of
	// /requests/* uses. 404 (not 403) on a foreign id so a probing
	// caller can't enumerate other operators' request IDs by
	// pattern-watching response codes.
	parent, err := h.reqRepo.Get(r.Context(), types.SignRequestID(requestID))
	if err != nil {
		if errors.Is(err, types.ErrNotFound) {
			h.writeError(w, http.StatusNotFound, "request not found")
			return
		}
		h.logger.Error("simulation: parent request lookup failed", slog.String("error", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if !apiKey.IsAdmin() && parent.APIKeyID != apiKey.ID {
		h.writeError(w, http.StatusNotFound, "request not found")
		return
	}

	sim, err := h.simRepo.GetByRequestID(r.Context(), requestID)
	if err != nil {
		if errors.Is(err, types.ErrNotFound) {
			// 404 → the UI renders "evaluating, please wait" + spinner
			// instead of a hard error while the simulation pipeline
			// is still in flight on a fresh request.
			h.writeError(w, http.StatusNotFound, "simulation not yet available")
			return
		}
		h.logger.Error("simulation: row lookup failed", slog.String("error", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	h.writeJSON(w, http.StatusOK, sim)
}

func (h *RequestSimulationHandler) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (h *RequestSimulationHandler) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
