package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/registry"
)

// RegistryRefreshHandler serves POST /api/v1/registry/refresh. The
// endpoint re-runs the template + preset Registry sync without a
// daemon restart, so an operator who edited YAML on disk can pick up
// changes immediately.
//
// Permission gate: same as preset apply — admin-tier keys only — since
// a refresh can prune templates whose files were removed.
type RegistryRefreshHandler struct {
	templateRegistry *registry.TemplateRegistry
	presetRegistry   *registry.PresetRegistry
	logger           *slog.Logger
}

// NewRegistryRefreshHandler constructs the handler. Both registries are
// required; the constructor returns an error rather than degrading to
// a partial refresh so the operator sees the misconfiguration loudly
// at boot.
func NewRegistryRefreshHandler(
	tmplReg *registry.TemplateRegistry,
	presetReg *registry.PresetRegistry,
	logger *slog.Logger,
) (*RegistryRefreshHandler, error) {
	if tmplReg == nil || presetReg == nil {
		return nil, fmt.Errorf("template and preset registries are required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &RegistryRefreshHandler{
		templateRegistry: tmplReg,
		presetRegistry:   presetReg,
		logger:           logger,
	}, nil
}

// RefreshResponse is the JSON shape returned to clients. One report
// per registry kind so the UI / CLI can render a single "x changed,
// y skipped, z deleted" summary line without joining structures.
type RefreshResponse struct {
	Templates RefreshReport `json:"templates"`
	Presets   RefreshReport `json:"presets"`
}

// RefreshReport is a serialisable view of registry.SyncReport. The
// internal SyncReport carries error objects that don't JSON-encode
// cleanly; this wrapper flattens those to strings.
type RefreshReport struct {
	Source  string         `json:"source"`
	Changed int            `json:"changed"`
	Skipped int            `json:"skipped"`
	Deleted int            `json:"deleted"`
	Errors  []RefreshError `json:"errors,omitempty"`
}

type RefreshError struct {
	ID    string `json:"id,omitempty"`
	Path  string `json:"path,omitempty"`
	Error string `json:"error"`
}

func (h *RegistryRefreshHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRegistryError(w, h.logger, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil || !middleware.HasPermission(apiKey.Role, middleware.PermApplyPreset) {
		// Refresh shares the apply_preset permission gate — both touch
		// the catalogue, both want admin-only.
		writeRegistryError(w, h.logger, "forbidden: apply_preset permission required", http.StatusForbidden)
		return
	}

	tmplReport, tmplErr := h.templateRegistry.Sync(r.Context())
	if tmplErr != nil {
		h.logger.Error("registry refresh: template sync failed", "error", tmplErr)
		writeRegistryError(w, h.logger, fmt.Sprintf("template sync: %s", tmplErr.Error()), http.StatusInternalServerError)
		return
	}
	presetReport, presetErr := h.presetRegistry.Sync(r.Context())
	if presetErr != nil {
		h.logger.Error("registry refresh: preset sync failed", "error", presetErr)
		writeRegistryError(w, h.logger, fmt.Sprintf("preset sync: %s", presetErr.Error()), http.StatusInternalServerError)
		return
	}

	resp := RefreshResponse{
		Templates: toRefreshReport(tmplReport),
		Presets:   toRefreshReport(presetReport),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error("registry refresh: write response failed", "error", err)
	}
}

func toRefreshReport(r registry.SyncReport) RefreshReport {
	out := RefreshReport{
		Source:  string(r.Source),
		Changed: r.Changed,
		Skipped: r.Skipped,
		Deleted: r.Deleted,
	}
	for _, e := range r.Errors {
		msg := ""
		if e.Err != nil {
			msg = e.Err.Error()
		}
		out.Errors = append(out.Errors, RefreshError{ID: e.ID, Path: e.Path, Error: msg})
	}
	return out
}

func writeRegistryError(w http.ResponseWriter, log *slog.Logger, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write([]byte(fmt.Sprintf(`{"error":%q}`, message))); err != nil {
		log.Error("write error response failed", "error", err)
	}
}
