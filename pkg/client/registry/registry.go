// Package registry provides the v0.3 Registry refresh client (admin only).
//
// The daemon syncs templates + presets from disk into the DB at startup.
// When an operator edits a YAML on disk and wants the change visible
// without restarting, they call this endpoint and the daemon re-runs
// both Registry syncs.
package registry

import (
	"context"
	"net/http"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// Service handles registry refresh. Requires apply_preset permission
// (admin tier) — refresh can prune rows whose source file was removed.
type Service struct {
	transport *transport.Transport
}

// NewService creates a new registry service.
func NewService(t *transport.Transport) *Service {
	if t == nil {
		panic("registry.NewService: transport is required")
	}
	return &Service{transport: t}
}

// RefreshError is one per-file parse failure. The rest of the sync still
// went through; the operator can fix the one file and call refresh again.
type RefreshError struct {
	ID    string `json:"id,omitempty"`
	Path  string `json:"path,omitempty"`
	Error string `json:"error"`
}

// RefreshReport is a serialisable view of one Registry's Sync result.
type RefreshReport struct {
	Source  string         `json:"source"`
	Changed int            `json:"changed"`
	Skipped int            `json:"skipped"`
	Deleted int            `json:"deleted"`
	Errors  []RefreshError `json:"errors,omitempty"`
}

// RefreshResponse is the JSON body for POST /api/v1/registry/refresh.
type RefreshResponse struct {
	Templates RefreshReport `json:"templates"`
	Presets   RefreshReport `json:"presets"`
}

// Refresh re-runs Template + Preset Registry sync against the configured
// source roots. Returns one report per kind, with per-file errors
// surfaced as Errors entries.
func (s *Service) Refresh(ctx context.Context) (*RefreshResponse, error) {
	var out RefreshResponse
	err := s.transport.Request(ctx, http.MethodPost, "/api/v1/registry/refresh", nil, &out, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &out, nil
}
