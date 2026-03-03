package middleware

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/config"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestNewIPWhitelist(t *testing.T) {
	logger := newTestLogger()

	tests := []struct {
		name    string
		cfg     config.IPWhitelistConfig
		wantErr bool
	}{
		{
			name: "disabled whitelist",
			cfg: config.IPWhitelistConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "enabled with valid IPs",
			cfg: config.IPWhitelistConfig{
				Enabled:    true,
				AllowedIPs: []string{"127.0.0.1", "192.168.1.1", "::1"},
			},
			wantErr: false,
		},
		{
			name: "enabled with valid CIDRs",
			cfg: config.IPWhitelistConfig{
				Enabled:    true,
				AllowedIPs: []string{"10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"},
			},
			wantErr: false,
		},
		{
			name: "enabled with mixed IPs and CIDRs",
			cfg: config.IPWhitelistConfig{
				Enabled:    true,
				AllowedIPs: []string{"127.0.0.1", "10.0.0.0/8", "::1"},
			},
			wantErr: false,
		},
		{
			name: "enabled but no allowed IPs",
			cfg: config.IPWhitelistConfig{
				Enabled:    true,
				AllowedIPs: []string{},
			},
			wantErr: true,
		},
		{
			name: "invalid IP address",
			cfg: config.IPWhitelistConfig{
				Enabled:    true,
				AllowedIPs: []string{"invalid-ip"},
			},
			wantErr: true,
		},
		{
			name: "invalid CIDR range",
			cfg: config.IPWhitelistConfig{
				Enabled:    true,
				AllowedIPs: []string{"192.168.1.0/99"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewIPWhitelist(tt.cfg, logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewIPWhitelist() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIPWhitelist_IsAllowed(t *testing.T) {
	logger := newTestLogger()

	// Create whitelist with various entries
	cfg := config.IPWhitelistConfig{
		Enabled: true,
		AllowedIPs: []string{
			"127.0.0.1",
			"192.168.1.100",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"::1",
			"2001:db8::/32",
		},
	}

	whitelist, err := NewIPWhitelist(cfg, logger)
	if err != nil {
		t.Fatalf("NewIPWhitelist() error = %v", err)
	}

	tests := []struct {
		name    string
		ip      string
		allowed bool
	}{
		// Exact matches
		{"localhost IPv4", "127.0.0.1", true},
		{"specific IP", "192.168.1.100", true},
		{"localhost IPv6", "::1", true},

		// CIDR matches
		{"10.x.x.x in 10.0.0.0/8", "10.255.255.255", true},
		{"10.1.2.3 in 10.0.0.0/8", "10.1.2.3", true},
		{"172.16.x.x in 172.16.0.0/12", "172.16.0.1", true},
		{"172.31.x.x in 172.16.0.0/12", "172.31.255.255", true},
		{"IPv6 in 2001:db8::/32", "2001:db8::1", true},
		{"IPv6 in 2001:db8::/32 full", "2001:db8:abcd:1234::1", true},

		// Not allowed
		{"different IP", "192.168.1.101", false},
		{"outside 10.0.0.0/8", "11.0.0.1", false},
		{"outside 172.16.0.0/12", "172.32.0.1", false},
		{"public IP", "8.8.8.8", false},
		{"different IPv6", "2001:db9::1", false},

		// Invalid IPs
		{"invalid IP", "not-an-ip", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := whitelist.IsAllowed(tt.ip); got != tt.allowed {
				t.Errorf("IsAllowed(%q) = %v, want %v", tt.ip, got, tt.allowed)
			}
		})
	}
}

func TestIPWhitelist_IsAllowed_Disabled(t *testing.T) {
	logger := newTestLogger()

	cfg := config.IPWhitelistConfig{
		Enabled: false,
	}

	whitelist, err := NewIPWhitelist(cfg, logger)
	if err != nil {
		t.Fatalf("NewIPWhitelist() error = %v", err)
	}

	// When disabled, all IPs should be allowed
	tests := []string{"127.0.0.1", "8.8.8.8", "192.168.1.1", "::1"}
	for _, ip := range tests {
		if !whitelist.IsAllowed(ip) {
			t.Errorf("disabled whitelist should allow %q", ip)
		}
	}
}

func TestIPWhitelist_GetClientIP(t *testing.T) {
	logger := newTestLogger()

	tests := []struct {
		name           string
		trustProxy     bool
		trustedProxies []string
		remoteAddr     string
		xForwarded     string
		xRealIP        string
		expectedIP     string
	}{
		{
			name:       "direct connection without proxy",
			trustProxy: false,
			remoteAddr: "192.168.1.100:12345",
			expectedIP: "192.168.1.100",
		},
		{
			name:        "with X-Forwarded-For but trust_proxy disabled",
			trustProxy:  false,
			remoteAddr:  "192.168.1.1:12345",
			xForwarded:  "203.0.113.50",
			expectedIP:  "192.168.1.1", // Should ignore X-Forwarded-For
		},
		{
			name:           "with X-Forwarded-For from trusted proxy",
			trustProxy:     true,
			trustedProxies: []string{"192.168.1.1"},
			remoteAddr:     "192.168.1.1:12345",
			xForwarded:     "203.0.113.50",
			expectedIP:     "203.0.113.50",
		},
		{
			name:           "with X-Forwarded-For from untrusted proxy",
			trustProxy:     true,
			trustedProxies: []string{"10.0.0.1"},
			remoteAddr:     "192.168.1.1:12345",
			xForwarded:     "203.0.113.50",
			expectedIP:     "192.168.1.1", // Should ignore, not a trusted proxy
		},
		{
			name:           "trust_proxy enabled but no trusted_proxies configured",
			trustProxy:     true,
			trustedProxies: nil,
			remoteAddr:     "192.168.1.1:12345",
			xForwarded:     "203.0.113.50",
			expectedIP:     "192.168.1.1", // Fail-closed: no trusted proxies
		},
		{
			name:           "multiple IPs in X-Forwarded-For from trusted proxy",
			trustProxy:     true,
			trustedProxies: []string{"192.168.1.1"},
			remoteAddr:     "192.168.1.1:12345",
			xForwarded:     "203.0.113.50, 192.168.1.254, 10.0.0.1",
			expectedIP:     "203.0.113.50", // Should take first IP
		},
		{
			name:           "with X-Real-IP from trusted proxy",
			trustProxy:     true,
			trustedProxies: []string{"192.168.1.1"},
			remoteAddr:     "192.168.1.1:12345",
			xRealIP:        "203.0.113.100",
			expectedIP:     "203.0.113.100",
		},
		{
			name:           "X-Forwarded-For takes precedence over X-Real-IP",
			trustProxy:     true,
			trustedProxies: []string{"192.168.1.1"},
			remoteAddr:     "192.168.1.1:12345",
			xForwarded:     "203.0.113.50",
			xRealIP:        "203.0.113.100",
			expectedIP:     "203.0.113.50",
		},
		{
			name:       "IPv6 address",
			trustProxy: false,
			remoteAddr: "[2001:db8::1]:12345",
			expectedIP: "2001:db8::1",
		},
		{
			name:           "IPv6 in X-Forwarded-For from trusted proxy",
			trustProxy:     true,
			trustedProxies: []string{"192.168.1.1"},
			remoteAddr:     "192.168.1.1:12345",
			xForwarded:     "2001:db8::1",
			expectedIP:     "2001:db8::1",
		},
		{
			name:           "trusted proxy via CIDR range",
			trustProxy:     true,
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.1.2.3:12345",
			xForwarded:     "203.0.113.50",
			expectedIP:     "203.0.113.50",
		},
		{
			name:           "outside trusted proxy CIDR range",
			trustProxy:     true,
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "11.0.0.1:12345",
			xForwarded:     "203.0.113.50",
			expectedIP:     "11.0.0.1", // Not in trusted CIDR
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.IPWhitelistConfig{
				Enabled:        true,
				AllowedIPs:     []string{"0.0.0.0/0"}, // Allow all for this test
				TrustProxy:     tt.trustProxy,
				TrustedProxies: tt.trustedProxies,
			}

			whitelist, err := NewIPWhitelist(cfg, logger)
			if err != nil {
				t.Fatalf("NewIPWhitelist() error = %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xForwarded != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwarded)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			got := whitelist.GetClientIP(req)
			if got != tt.expectedIP {
				t.Errorf("GetClientIP() = %q, want %q", got, tt.expectedIP)
			}
		})
	}
}

func TestIPWhitelistMiddleware(t *testing.T) {
	logger := newTestLogger()

	cfg := config.IPWhitelistConfig{
		Enabled:    true,
		AllowedIPs: []string{"127.0.0.1", "192.168.1.0/24"},
	}

	whitelist, err := NewIPWhitelist(cfg, logger)
	if err != nil {
		t.Fatalf("NewIPWhitelist() error = %v", err)
	}

	// Create a simple handler that returns 200
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	handler := IPWhitelistMiddleware(whitelist)(nextHandler)

	tests := []struct {
		name           string
		remoteAddr     string
		expectedStatus int
	}{
		{"allowed IP localhost", "127.0.0.1:12345", http.StatusOK},
		{"allowed IP in CIDR", "192.168.1.50:12345", http.StatusOK},
		{"blocked IP", "8.8.8.8:12345", http.StatusForbidden},
		{"blocked IP outside CIDR", "192.168.2.1:12345", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %d, want %d", rr.Code, tt.expectedStatus)
			}
		})
	}
}

func TestIPWhitelistMiddleware_Disabled(t *testing.T) {
	logger := newTestLogger()

	cfg := config.IPWhitelistConfig{
		Enabled: false,
	}

	whitelist, err := NewIPWhitelist(cfg, logger)
	if err != nil {
		t.Fatalf("NewIPWhitelist() error = %v", err)
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := IPWhitelistMiddleware(whitelist)(nextHandler)

	// Any IP should be allowed when disabled
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "8.8.8.8:12345"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("disabled middleware should allow all IPs, got status %d", rr.Code)
	}
}
