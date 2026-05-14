package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/config"
)

// IPWhitelistResponse is the read-only response for GET /api/v1/acls/ip-whitelist.
type IPWhitelistResponse struct {
	Enabled         bool     `json:"enabled"`
	AllowedIPs     []string `json:"allowed_ips"`
	TrustProxy     bool     `json:"trust_proxy"`
	TrustedProxies []string `json:"trusted_proxies"`
}

// ACLHandler handles admin-only, read-only ACL endpoints (e.g. IP whitelist).
type ACLHandler struct {
	ipWhitelist *config.IPWhitelistConfig
}

// NewACLHandler creates an ACL handler. ipWhitelist may be nil (returns empty/disabled).
func NewACLHandler(ipWhitelist *config.IPWhitelistConfig) *ACLHandler {
	return &ACLHandler{ipWhitelist: ipWhitelist}
}

// ServeHTTP handles GET /api/v1/acls/ip-whitelist only.
func (h *ACLHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/api/v1/acls/ip-whitelist" {
		http.NotFound(w, r)
		return
	}

	resp := IPWhitelistResponse{
		Enabled:         false,
		AllowedIPs:      nil,
		TrustProxy:      false,
		TrustedProxies:  nil,
	}
	if h.ipWhitelist != nil {
		resp.Enabled = h.ipWhitelist.Enabled
		resp.AllowedIPs = append([]string(nil), h.ipWhitelist.AllowedIPs...)
		resp.TrustProxy = h.ipWhitelist.TrustProxy
		resp.TrustedProxies = append([]string(nil), h.ipWhitelist.TrustedProxies...)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// Headers already sent (200 OK); cannot change status code, so log the error.
		slog.Error("failed to encode IP whitelist response", "error", err)
	}
}
