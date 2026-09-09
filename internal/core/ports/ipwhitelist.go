package ports

// IPWhitelistConfig contains IP whitelist settings
type IPWhitelist struct {
	// Enabled controls whether IP whitelist is enforced
	Enabled bool `yaml:"enabled"`
	// AllowedIPs is a list of allowed IP addresses or CIDR ranges
	// Examples: "192.168.1.1", "10.0.0.0/8", "::1"
	AllowedIPs []string `yaml:"allowed_ips"`
	// TrustProxy enables parsing X-Forwarded-For and X-Real-IP headers
	// WARNING: Only enable this if running behind a trusted reverse proxy
	TrustProxy bool `yaml:"trust_proxy"`
	// TrustedProxies is a list of IP addresses or CIDR ranges of trusted reverse proxies
	// When TrustProxy is true, X-Forwarded-For/X-Real-IP headers are only honored
	// if the request's direct RemoteAddr matches one of these entries.
	// If TrustProxy is true but TrustedProxies is empty, proxy headers are ignored
	// (fail-closed: no trusted proxies means no header trust).
	TrustedProxies []string `yaml:"trusted_proxies"`
}
