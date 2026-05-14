// Package clientsettings is the SDK accessor for /api/v1/admin/settings/:group.
// Schemas live in internal/settings.* and are not redefined here; the service
// exchanges raw JSON so callers (CLI, tests, downstream SDKs) deserialize into
// whatever local mirror they keep.
package clientsettings

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// Service provides admin-only access to the runtime settings store.
type Service struct {
	transport *transport.Transport
}

// NewService binds a Service to an authenticated transport.
func NewService(t *transport.Transport) *Service { return &Service{transport: t} }

// Get fetches the current snapshot for group as JSON. Caller decodes into a
// typed struct matching internal/settings.<Group>Snapshot.
func (s *Service) Get(ctx context.Context, group string) (json.RawMessage, error) {
	out, err := s.transport.RequestRaw(ctx, http.MethodGet, "/api/v1/admin/settings/"+group, nil, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Put replaces the snapshot for group with body (must be valid JSON for the
// corresponding type). Returns the server's view of the new state.
func (s *Service) Put(ctx context.Context, group string, body json.RawMessage) (json.RawMessage, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("body required")
	}
	out, err := s.transport.RequestRaw(ctx, http.MethodPut, "/api/v1/admin/settings/"+group, body, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return out, nil
}
