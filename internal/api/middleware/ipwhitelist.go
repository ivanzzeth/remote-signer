package middleware

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/config"
)

// IPWhitelist holds the parsed IP whitelist configuration
type IPWhitelist struct {
	enabled    bool
	allowedIPs map[string]struct{} // exact IP matches
	allowedCIDRs []*net.IPNet       // CIDR ranges
	trustProxy bool
	logger     *slog.Logger
}

// NewIPWhitelist creates a new IP whitelist from configuration
func NewIPWhitelist(cfg config.IPWhitelistConfig, logger *slog.Logger) (*IPWhitelist, error) {
	w := &IPWhitelist{
		enabled:      cfg.Enabled,
		allowedIPs:   make(map[string]struct{}),
		allowedCIDRs: make([]*net.IPNet, 0),
		trustProxy:   cfg.TrustProxy,
		logger:       logger,
	}

	if !cfg.Enabled {
		return w, nil
	}

	if len(cfg.AllowedIPs) == 0 {
		return nil, fmt.Errorf("ip_whitelist enabled but no allowed_ips configured")
	}

	for _, entry := range cfg.AllowedIPs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		// Check if it's a CIDR range
		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR range '%s': %w", entry, err)
			}
			w.allowedCIDRs = append(w.allowedCIDRs, ipNet)
			logger.Info("IP whitelist: added CIDR range", "cidr", entry)
		} else {
			// Parse as single IP
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address '%s'", entry)
			}
			// Normalize IP to string (handles IPv4-mapped IPv6)
			w.allowedIPs[ip.String()] = struct{}{}
			logger.Info("IP whitelist: added IP", "ip", ip.String())
		}
	}

	logger.Info("IP whitelist initialized",
		"enabled", cfg.Enabled,
		"allowed_ips_count", len(w.allowedIPs),
		"allowed_cidrs_count", len(w.allowedCIDRs),
		"trust_proxy", cfg.TrustProxy,
	)

	return w, nil
}

// IsAllowed checks if an IP address is in the whitelist
func (w *IPWhitelist) IsAllowed(ipStr string) bool {
	if !w.enabled {
		return true
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		w.logger.Warn("failed to parse IP address", "ip", ipStr)
		return false
	}

	// Normalize IP string
	normalizedIP := ip.String()

	// Check exact match
	if _, ok := w.allowedIPs[normalizedIP]; ok {
		return true
	}

	// Check CIDR ranges
	for _, cidr := range w.allowedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// GetClientIP extracts the client IP from the request
// If trustProxy is enabled, it checks X-Forwarded-For and X-Real-IP headers
func (w *IPWhitelist) GetClientIP(r *http.Request) string {
	if w.trustProxy {
		// Check X-Forwarded-For header (can contain multiple IPs)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the first IP (original client)
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				clientIP := strings.TrimSpace(ips[0])
				if ip := net.ParseIP(clientIP); ip != nil {
					return ip.String()
				}
			}
		}

		// Check X-Real-IP header
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			if ip := net.ParseIP(xri); ip != nil {
				return ip.String()
			}
		}
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr might not have a port
		if ip := net.ParseIP(r.RemoteAddr); ip != nil {
			return ip.String()
		}
		return r.RemoteAddr
	}

	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

// IPWhitelistMiddleware creates an IP whitelist middleware
// This should be applied as the outermost middleware (before auth)
func IPWhitelistMiddleware(whitelist *IPWhitelist) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !whitelist.enabled {
				next.ServeHTTP(w, r)
				return
			}

			clientIP := whitelist.GetClientIP(r)

			if !whitelist.IsAllowed(clientIP) {
				whitelist.logger.Warn("IP not in whitelist",
					"client_ip", clientIP,
					"remote_addr", r.RemoteAddr,
					"path", r.URL.Path,
					"method", r.Method,
				)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			whitelist.logger.Debug("IP allowed",
				"client_ip", clientIP,
				"path", r.URL.Path,
			)

			next.ServeHTTP(w, r)
		})
	}
}
