package evm

import (
	"context"
	"net/http"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// GuardService handles the approval guard.
type GuardService struct {
	transport *transport.Transport
}

// Resume resumes the approval guard after it has paused sign requests (admin only).
func (s *GuardService) Resume(ctx context.Context) error {
	return s.transport.Request(ctx, http.MethodPost, "/api/v1/evm/guard/resume", nil, nil,
		http.StatusOK)
}
