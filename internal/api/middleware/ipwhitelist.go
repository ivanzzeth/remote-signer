package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/config"
)

// IPWhitelist holds the parsed IP whitelist configuration
type IPWhitelist struct {
	enabled        bool
	allowedIPs     map[string]struct{} // exact IP matches
	allowedCIDRs   []*net.IPNet        // CIDR ranges
	trustProxy     bool
	trustedProxies map[string]struct{} // exact trusted proxy IP matches
	trustedProxyCIDRs []*net.IPNet     // trusted proxy CIDR ranges
	logger         *slog.Logger
	alertService   *SecurityAlertService
}

// NewIPWhitelist creates a new IP whitelist from configuration
func NewIPWhitelist(cfg config.IPWhitelistConfig, logger *slog.Logger) (*IPWhitelist, error) {
	w := &IPWhitelist{
		enabled:           cfg.Enabled,
		allowedIPs:        make(map[string]struct{}),
		allowedCIDRs:      make([]*net.IPNet, 0),
		trustProxy:        cfg.TrustProxy,
		trustedProxies:    make(map[string]struct{}),
		trustedProxyCIDRs: make([]*net.IPNet, 0),
		logger:            logger,
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

	// Parse trusted proxy IPs/CIDRs
	if cfg.TrustProxy {
		if len(cfg.TrustedProxies) == 0 {
			logger.Warn("trust_proxy is enabled but no trusted_proxies configured; proxy headers will be ignored (fail-closed)")
		}
		for _, entry := range cfg.TrustedProxies {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			if strings.Contains(entry, "/") {
				_, ipNet, err := net.ParseCIDR(entry)
				if err != nil {
					return nil, fmt.Errorf("invalid trusted_proxies CIDR range '%s': %w", entry, err)
				}
				w.trustedProxyCIDRs = append(w.trustedProxyCIDRs, ipNet)
				logger.Info("IP whitelist: added trusted proxy CIDR", "cidr", entry)
			} else {
				ip := net.ParseIP(entry)
				if ip == nil {
					return nil, fmt.Errorf("invalid trusted_proxies IP address '%s'", entry)
				}
				w.trustedProxies[ip.String()] = struct{}{}
				logger.Info("IP whitelist: added trusted proxy IP", "ip", ip.String())
			}
		}
	}

	logger.Info("IP whitelist initialized",
		"enabled", cfg.Enabled,
		"allowed_ips_count", len(w.allowedIPs),
		"allowed_cidrs_count", len(w.allowedCIDRs),
		"trust_proxy", cfg.TrustProxy,
		"trusted_proxies_count", len(w.trustedProxies)+len(w.trustedProxyCIDRs),
	)

	return w, nil
}

// SetAlertService sets the security alert service for real-time notifications.
func (w *IPWhitelist) SetAlertService(alertService *SecurityAlertService) {
	w.alertService = alertService
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

// isTrustedProxy checks if an IP is in the trusted proxy list
func (w *IPWhitelist) isTrustedProxy(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	normalized := ip.String()
	if _, ok := w.trustedProxies[normalized]; ok {
		return true
	}
	for _, cidr := range w.trustedProxyCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// extractRemoteIP extracts the direct remote IP from r.RemoteAddr (without port)
func (w *IPWhitelist) extractRemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
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

// GetClientIP extracts the client IP from the request.
// If trustProxy is enabled AND the direct connection comes from a trusted proxy,
// it checks X-Forwarded-For and X-Real-IP headers.
// Otherwise, it uses RemoteAddr directly (fail-closed).
func (w *IPWhitelist) GetClientIP(r *http.Request) string {
	remoteIP := w.extractRemoteIP(r)

	if w.trustProxy && w.isTrustedProxy(remoteIP) {
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

	return remoteIP
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
				if whitelist.alertService != nil {
					whitelist.alertService.Alert(AlertIPBlocked, clientIP,
						fmt.Sprintf("[Remote Signer] IP BLOCKED\n\nIP: %s\nRemote: %s\nPath: %s %s\nTime: %s",
							clientIP, r.RemoteAddr, r.Method, r.URL.Path, time.Now().UTC().Format(time.RFC3339)))
				}
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

// ResolveClientIP returns the client IP for the request. If whitelist is non-nil, uses
// whitelist.GetClientIP (trust_proxy + X-Forwarded-For aware); otherwise uses host from RemoteAddr.
// Use this (or context from ClientIPMiddleware) so logging, rate limit, audit and request detail all use the same value.
func ResolveClientIP(r *http.Request, whitelist *IPWhitelist) string {
	if whitelist != nil {
		return whitelist.GetClientIP(r)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
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

// ClientIPMiddleware sets the resolved client IP in request context (key ClientIPContextKey).
// Place before Logging and IPRateLimit so they can read from context.
func ClientIPMiddleware(whitelist *IPWhitelist) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := ResolveClientIP(r, whitelist)
			ctx := context.WithValue(r.Context(), ClientIPContextKey, clientIP)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
