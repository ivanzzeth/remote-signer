package acls

import (
	"context"
	"net/http"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// IPWhitelistResponse is the read-only IP whitelist config (admin only).
type IPWhitelistResponse struct {
	Enabled         bool     `json:"enabled"`
	AllowedIPs      []string `json:"allowed_ips"`
	TrustProxy      bool     `json:"trust_proxy"`
	TrustedProxies  []string `json:"trusted_proxies"`
}

// Service provides read-only ACL operations (admin only).
type Service struct {
	transport *transport.Transport
}

// NewService creates a new ACLs service.
func NewService(t *transport.Transport) *Service {
	return &Service{transport: t}
}

// GetIPWhitelist returns the IP whitelist configuration (admin only).
func (s *Service) GetIPWhitelist(ctx context.Context) (*IPWhitelistResponse, error) {
	var resp IPWhitelistResponse
	err := s.transport.Request(ctx, http.MethodGet, "/api/v1/acls/ip-whitelist", nil, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
