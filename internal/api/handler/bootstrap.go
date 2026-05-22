package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/bootstrap"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// BootstrapHandler serves the two unauthenticated routes that complete a
// soft-started daemon's admin setup:
//
//   - GET  /api/v1/bootstrap/status   reports whether bootstrap is still
//                                     needed. Always reachable; idempotent.
//   - POST /api/v1/bootstrap/admin    accepts {"password": "..."}, creates
//                                     the admin keystore + api_keys row,
//                                     and returns the keystore paths.
//                                     Succeeds exactly once; subsequent
//                                     calls return 410 Gone.
//
// Both routes deliberately skip the auth middleware. Authentication
// requires the api_keys table to already contain a verifying public key —
// which by definition it doesn't during bootstrap, so requiring auth here
// would be a chicken-and-egg deadlock.
//
// Safety properties:
//
//   - The POST handler re-checks `api_keys is empty` atomically inside
//     bootstrap.AdminCreator (the underlying CreateAdminKeystore). Two
//     concurrent POSTs race fairly; one wins with 200, the other gets the
//     410 Gone path.
//   - The status handler is a strict read; no side effects, idempotent.
//   - No path here ever returns the password back to the caller, and the
//     handler zeroises the in-memory copy before responding.
//
// See SECURITY.md "Bootstrap state machine" for the full threat model.
type BootstrapHandler struct {
	repo   storage.APIKeyRepository
	create bootstrap.AdminCreator
	log    *slog.Logger
}

// NewBootstrapHandler wires the bootstrap handler with the api_keys
// repository (for status checks) and an AdminCreator closure (the actual
// keystore-writing function — supplied by run.go so this package doesn't
// need to depend on internal/cli/server).
func NewBootstrapHandler(repo storage.APIKeyRepository, create bootstrap.AdminCreator, log *slog.Logger) *BootstrapHandler {
	if log == nil {
		log = slog.Default()
	}
	return &BootstrapHandler{repo: repo, create: create, log: log}
}

// statusResponse is the GET /api/v1/bootstrap/status payload. Kept as a
// named type so the SDK can regenerate from this shape without guessing.
type statusResponse struct {
	NeedsBootstrap bool `json:"needs_bootstrap"`
}

// ServeStatus answers GET /api/v1/bootstrap/status.
//
// The response shape is intentionally minimal — the front-end only needs
// "is bootstrap still required?". Anything richer would invite tying UI
// behaviour to mutable backend state and complicate the unauth contract.
func (h *BootstrapHandler) ServeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	// "Needs bootstrap" specifically means "no admin api key yet". The
	// agent api_keys row is provisioned independently at every first
	// start (bootstrapAgentKeyIfNeeded), so any count-based check would
	// flip to false after the agent lands and never show the bootstrap
	// form. The id="admin" lookup is the only signal the front-end
	// cares about — it's the credential the operator needs to drive the
	// UI's management surfaces.
	existing, err := h.repo.Get(r.Context(), "admin")
	if err != nil && !types.IsNotFound(err) {
		h.log.Error("bootstrap status: get admin api key failed", "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	h.writeJSON(w, http.StatusOK, statusResponse{NeedsBootstrap: existing == nil})
}

// adminRequest is the POST /api/v1/bootstrap/admin payload.
//
// We accept only the password — paths and rate limit come from daemon
// config, baked into the AdminCreator closure at construction time. That
// keeps the wire format small and makes it impossible for a malicious
// caller to redirect the keystore output to an attacker-controlled path.
type adminRequest struct {
	Password string `json:"password"`
}

// ServeAdmin answers POST /api/v1/bootstrap/admin.
//
// Error mapping:
//
//   - bad JSON / empty password    → 400
//   - bootstrap.ErrAdminAlreadyExists → 410 (window closed)
//   - any other error              → 500 (logged with detail; response generic)
//
// The 410 distinction matters: a 500 invites retries that will never
// succeed; the 410 tells the UI to drop the bootstrap flow and route the
// user to the regular login page instead.
func (h *BootstrapHandler) ServeAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req adminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Password == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password is required"})
		return
	}
	// Materialise the password as a mutable byte slice so we can zero it
	// once CreateAdminKeystore is done. Strings in Go are immutable; the
	// underlying memory is reachable through the GC's intern pool, so we
	// cannot wipe req.Password directly. The encrypted keystore is the
	// only persistent record of the secret on this path.
	password := []byte(req.Password)
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()
	req.Password = ""

	res, err := h.create(r.Context(), password)
	if err != nil {
		if errors.Is(err, bootstrap.ErrAdminAlreadyExists) {
			h.writeJSON(w, http.StatusGone, map[string]string{
				"error": "admin already configured; the bootstrap window has closed",
				"code":  "admin_already_exists",
			})
			return
		}
		h.log.Error("bootstrap admin: create failed", "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "bootstrap failed"})
		return
	}

	h.log.Info("admin api key created via HTTP bootstrap",
		"keystore_path", res.KeystorePath,
		"public_key_hex", res.PubKeyHex,
		"client_ip", clientIP(r),
	)
	h.writeJSON(w, http.StatusOK, struct {
		Status string `json:"status"`
		bootstrap.AdminResult
	}{
		Status:      "ok",
		AdminResult: *res,
	})
}

// writeJSON is a tiny helper to keep the response paths free of repeated
// boilerplate. We don't lean on http.Error for the error responses because
// the front-end parses JSON unconditionally and a text/plain "method not
// allowed" would break the error display path.
func (h *BootstrapHandler) writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// clientIP extracts the apparent caller IP from the request. Used only
// for the success-path log line so an operator triaging "who configured
// admin?" has somewhere to start. Strips proxy headers — they're not
// trustworthy enough to claim authoritative source IP from.
func clientIP(r *http.Request) string {
	// Strip ":port" suffix.
	for i := len(r.RemoteAddr) - 1; i >= 0; i-- {
		if r.RemoteAddr[i] == ':' {
			return r.RemoteAddr[:i]
		}
	}
	return r.RemoteAddr
}

// Compile-time guard: NewBootstrapHandler accepts a closure that matches
// bootstrap.AdminCreator. Confirms the field type is the canonical one.
var _ = func() {
	var _ bootstrap.AdminCreator = func(_ context.Context, _ []byte) (*bootstrap.AdminResult, error) {
		return nil, nil
	}
}
