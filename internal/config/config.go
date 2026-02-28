package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/notify"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// Config is the root configuration structure
type Config struct {
	Server        ServerConfig        `yaml:"server"`
	Database      storage.Config      `yaml:"database"`
	Chains        ChainsConfig        `yaml:"chains"`
	Notify        notify.Config       `yaml:"notify"`
	NotifyChannel notify.Channel      `yaml:"notify_channels"`
	AuditMonitor  audit.MonitorConfig `yaml:"audit_monitor"`
	Security      SecurityConfig      `yaml:"security"`
	Logger        LoggerConfig        `yaml:"logger"`
	APIKeys       []APIKeyConfig      `yaml:"api_keys"`
	Templates     []TemplateConfig    `yaml:"templates"`
	Rules         []RuleConfig        `yaml:"rules"`
}

// TemplateConfig defines a rule template in configuration
type TemplateConfig struct {
	Name           string                 `yaml:"name" json:"name"`
	Description    string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Type           string                 `yaml:"type" json:"type"` // actual rule type or "file" for external file
	Mode           string                 `yaml:"mode,omitempty" json:"mode,omitempty"`
	Variables      []TemplateVarConfig    `yaml:"variables,omitempty" json:"variables,omitempty"`
	Config         map[string]interface{} `yaml:"config,omitempty" json:"config,omitempty"`
	BudgetMetering map[string]interface{} `yaml:"budget_metering,omitempty" json:"budget_metering,omitempty"`
	TestVariables  map[string]string      `yaml:"test_variables,omitempty" json:"test_variables,omitempty"` // default variable values for validation
	Enabled        bool                   `yaml:"enabled" json:"enabled"`
}

// TemplateVarConfig defines a template variable in configuration
type TemplateVarConfig struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	Description string `yaml:"description,omitempty"`
	Required    bool   `yaml:"required"`
	Default     string `yaml:"default,omitempty"`
}

// TestCaseConfig defines a single test case for rule validation (evm_js, solidity, etc.)
type TestCaseConfig struct {
	Name         string                 `yaml:"name" json:"name"`
	Input        map[string]interface{} `yaml:"input" json:"input"`
	ExpectPass   bool                   `yaml:"expect_pass" json:"expect_pass"`
	ExpectReason string                 `yaml:"expect_reason,omitempty" json:"expect_reason,omitempty"`
}

// RuleConfig defines a rule in configuration. JSON tags must match YAML/validator expectations
// so that substituted rules_json unmarshals correctly (e.g. "config" not "Config").
type RuleConfig struct {
	// Id is an optional stable rule ID. If set, it is used as the rule's ID (for delegate_to etc.);
	// must be unique across all rules. If empty, a deterministic ID is generated from config order.
	Id            string                 `yaml:"id,omitempty" json:"id,omitempty"`
	Name          string                 `yaml:"name" json:"name"`
	Description   string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Type          string                 `yaml:"type" json:"type"`
	Mode          string                 `yaml:"mode" json:"mode"`
	ChainType     string                 `yaml:"chain_type,omitempty" json:"chain_type,omitempty"`
	ChainID       string                 `yaml:"chain_id,omitempty" json:"chain_id,omitempty"`
	APIKeyID      string                 `yaml:"api_key_id,omitempty" json:"api_key_id,omitempty"`
	SignerAddress string                 `yaml:"signer_address,omitempty" json:"signer_address,omitempty"`
	Config        map[string]interface{} `yaml:"config" json:"config"`
	Variables     map[string]interface{} `yaml:"variables,omitempty" json:"variables,omitempty"`   // instance/template variable values (e.g. for evm_js config)
	TestCases     []TestCaseConfig       `yaml:"test_cases,omitempty" json:"test_cases,omitempty"` // test cases for validation (evm_js, solidity, etc.)
	Enabled       bool                   `yaml:"enabled" json:"enabled"`
}

// APIKeyConfig defines an API key in configuration
type APIKeyConfig struct {
	ID                string   `yaml:"id"`                   // Unique identifier for the API key
	Name              string   `yaml:"name"`                 // Human-readable name
	PublicKey         string   `yaml:"public_key"`           // Ed25519 public key (hex or base64, auto-detected)
	PublicKeyEnv      string   `yaml:"public_key_env"`       // Environment variable containing public key
	AllowedChainTypes []string `yaml:"allowed_chain_types"`  // Empty = all chains allowed
	AllowedSigners    []string `yaml:"allowed_signers"`      // Empty = all signers allowed
	RateLimit         int      `yaml:"rate_limit"`           // Requests per minute (default: 100)
	Enabled           bool     `yaml:"enabled"`              // Whether the key is active
	Admin             bool     `yaml:"admin"`                // Admin keys can approve requests and manage rules
}

// ResolvePublicKey returns the public key hex, resolving from env var and auto-detecting format (hex or base64)
func (c *APIKeyConfig) ResolvePublicKey() (string, error) {
	var rawKey string

	if c.PublicKey != "" {
		rawKey = c.PublicKey
	} else if c.PublicKeyEnv != "" {
		rawKey = os.Getenv(c.PublicKeyEnv)
		if rawKey == "" {
			return "", fmt.Errorf("environment variable %s is empty for API key %s", c.PublicKeyEnv, c.ID)
		}
	} else {
		return "", fmt.Errorf("API key %s has no public_key or public_key_env configured", c.ID)
	}

	// Auto-detect format: hex (64 chars) or base64
	if isHexPublicKey(rawKey) {
		return rawKey, nil
	}

	// Try to decode as base64 DER format
	derBytes, err := base64.StdEncoding.DecodeString(rawKey)
	if err != nil {
		return "", fmt.Errorf("invalid public key for API key %s: not valid hex or base64: %w", c.ID, err)
	}

	// Ed25519 DER public key is 44 bytes: 12-byte header + 32-byte key
	if len(derBytes) < 32 {
		return "", fmt.Errorf("invalid public key length for API key %s: got %d bytes, need at least 32", c.ID, len(derBytes))
	}

	// Extract the last 32 bytes (the actual public key)
	pubKey := derBytes[len(derBytes)-32:]
	return hex.EncodeToString(pubKey), nil
}

// isHexPublicKey checks if a string is a valid hex-encoded Ed25519 public key (64 hex chars = 32 bytes)
func isHexPublicKey(key string) bool {
	if len(key) != 64 {
		return false
	}
	for _, c := range key {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Host string    `yaml:"host"`
	Port int       `yaml:"port"`
	TLS  TLSConfig `yaml:"tls"`
}

// TLSConfig contains TLS/mTLS configuration for the server
type TLSConfig struct {
	// Enabled enables TLS (HTTPS) for the server
	Enabled bool `yaml:"enabled"`
	// CertFile is the path to the server TLS certificate
	CertFile string `yaml:"cert_file"`
	// KeyFile is the path to the server TLS private key
	KeyFile string `yaml:"key_file"`
	// CAFile is the path to the CA certificate for verifying client certificates (mTLS)
	CAFile string `yaml:"ca_file"`
	// ClientAuth enables mutual TLS (mTLS) — requires clients to present a valid certificate
	ClientAuth bool `yaml:"client_auth"`
}

// ChainsConfig contains chain-specific configurations
type ChainsConfig struct {
	EVM *EVMConfig `yaml:"evm,omitempty"`
}

// EVMConfig contains EVM chain configuration
type EVMConfig struct {
	Enabled     bool             `yaml:"enabled"`
	Signers     evm.SignerConfig `yaml:"signers"`
	KeystoreDir string           `yaml:"keystore_dir"` // Directory for storing dynamically created keystores
	Foundry     FoundryConfig    `yaml:"foundry"`
}

// FoundryConfig contains Foundry (forge) configuration for Solidity rules
type FoundryConfig struct {
	Enabled   bool          `yaml:"enabled"`
	ForgePath string        `yaml:"forge_path"` // path to forge binary, empty = auto-detect from PATH
	CacheDir  string        `yaml:"cache_dir"`  // cache directory for compiled scripts
	TempDir   string        `yaml:"temp_dir"`   // workspace dir for rule scripts and lib/forge-std; empty = os.TempDir()/remote-signer-rules. For Docker, set to /app/data/forge-workspace and mount repo data/forge-workspace.
	Timeout   time.Duration `yaml:"timeout"`    // max execution time per rule (default: 30s)
}

// SecurityConfig contains security-related settings
type SecurityConfig struct {
	MaxRequestAge    time.Duration     `yaml:"max_request_age"`
	RateLimitDefault int               `yaml:"rate_limit_default"`
	// IPRateLimit is the maximum requests per minute from a single IP address (pre-auth).
	// Protects against unauthenticated flood attacks. Default: 200.
	IPRateLimit int `yaml:"ip_rate_limit"`
	IPWhitelist      IPWhitelistConfig `yaml:"ip_whitelist"`
	// ManualApprovalEnabled: when true, requests with no whitelist match go to manual approval;
	// when false (default), they are rejected immediately. Default false for stricter security.
	ManualApprovalEnabled bool `yaml:"manual_approval_enabled"`
	// ApprovalGuard pauses all sign requests when too many consecutive manual-approval outcomes occur
	ApprovalGuard ApprovalGuardConfig `yaml:"approval_guard"`
	// NonceRequired enforces nonce for all requests (recommended for production)
	// When true, requests without X-Nonce header will be rejected
	NonceRequired *bool `yaml:"nonce_required"`
}

// ApprovalGuardConfig configures the request-rejection burst guard.
// When within Window there are Threshold consecutive outcomes that are either: (a) blocked by a rule,
// or (b) require manual approval (no whitelist match), the guard pauses all sign requests and alerts.
// Use case: detect API key abuse — attacker with valid API key repeatedly hits rule rejections or pending approval.
// After ResumeAfter the guard auto-resumes so the team has time to respond.
type ApprovalGuardConfig struct {
	Enabled     bool          `yaml:"enabled"`
	Window      time.Duration `yaml:"window"`       // time window for counting (e.g. 5m); 0 = no window check
	Threshold   int           `yaml:"threshold"`    // consecutive rejections (blocked or manual-approval) that trigger pause (e.g. 10)
	ResumeAfter time.Duration `yaml:"resume_after"` // pause duration after which to auto-resume (e.g. 2h)
}

// IPWhitelistConfig contains IP whitelist settings
type IPWhitelistConfig struct {
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

// LoggerConfig contains logging configuration
type LoggerConfig struct {
	Level  string `yaml:"level"` // debug, info, warn, error
	Pretty bool   `yaml:"pretty"`
}

// Load loads configuration from a YAML file
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("config path is required")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables in the config (supports ${VAR:-default} syntax)
	expandedData := ExpandEnvWithDefaults(string(data))

	cfg := &Config{}
	if err := yaml.Unmarshal([]byte(expandedData), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Set defaults
	setDefaults(cfg)

	return cfg, nil
}

// ExpandEnvWithDefaults expands environment variables with support for default values.
// Supports: ${VAR}, ${VAR:-default}, $VAR
func ExpandEnvWithDefaults(s string) string {
	// Pattern matches ${VAR:-default} or ${VAR}
	re := regexp.MustCompile(`\$\{([^}:]+)(:-([^}]*))?\}`)

	result := re.ReplaceAllStringFunc(s, func(match string) string {
		submatch := re.FindStringSubmatch(match)
		if len(submatch) < 2 {
			return match
		}

		varName := submatch[1]
		defaultValue := ""
		if len(submatch) >= 4 {
			defaultValue = submatch[3]
		}

		if value := os.Getenv(varName); value != "" {
			return value
		}
		return defaultValue
	})

	// Also handle simple $VAR format (without braces)
	result = os.Expand(result, func(key string) string {
		// Skip if it contains special characters (already handled above)
		if strings.Contains(key, ":") || strings.Contains(key, "-") {
			return ""
		}
		return os.Getenv(key)
	})

	return result
}

// validate validates the configuration
func validate(cfg *Config) error {
	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", cfg.Server.Port)
	}

	if cfg.Database.DSN == "" {
		return fmt.Errorf("database DSN is required")
	}

	// Validate at least one chain is enabled
	if cfg.Chains.EVM == nil || !cfg.Chains.EVM.Enabled {
		return fmt.Errorf("at least one chain must be enabled")
	}

	// Validate TLS configuration
	if cfg.Server.TLS.Enabled {
		if cfg.Server.TLS.CertFile == "" {
			return fmt.Errorf("TLS is enabled but cert_file is not set")
		}
		if cfg.Server.TLS.KeyFile == "" {
			return fmt.Errorf("TLS is enabled but key_file is not set")
		}
		if _, err := os.Stat(cfg.Server.TLS.CertFile); err != nil {
			return fmt.Errorf("TLS cert_file not found: %s", cfg.Server.TLS.CertFile)
		}
		if _, err := os.Stat(cfg.Server.TLS.KeyFile); err != nil {
			return fmt.Errorf("TLS key_file not found: %s", cfg.Server.TLS.KeyFile)
		}
		if cfg.Server.TLS.ClientAuth {
			if cfg.Server.TLS.CAFile == "" {
				return fmt.Errorf("TLS client_auth (mTLS) is enabled but ca_file is not set")
			}
			if _, err := os.Stat(cfg.Server.TLS.CAFile); err != nil {
				return fmt.Errorf("TLS ca_file not found: %s", cfg.Server.TLS.CAFile)
			}
		}
	}

	// Validate API keys
	seenIDs := make(map[string]bool)
	for i, key := range cfg.APIKeys {
		if key.ID == "" {
			return fmt.Errorf("api_keys[%d]: id is required", i)
		}
		if seenIDs[key.ID] {
			return fmt.Errorf("api_keys[%d]: duplicate id '%s'", i, key.ID)
		}
		seenIDs[key.ID] = true

		// Skip public key validation for disabled keys
		if !key.Enabled {
			continue
		}

		if key.PublicKey == "" && key.PublicKeyEnv == "" {
			return fmt.Errorf("api_keys[%d] (%s): public_key or public_key_env is required", i, key.ID)
		}
	}

	return nil
}

// setDefaults sets default values for configuration
func setDefaults(cfg *Config) {
	if cfg.Server.Host == "" {
		cfg.Server.Host = "127.0.0.1"
	}

	if cfg.Security.MaxRequestAge == 0 {
		cfg.Security.MaxRequestAge = 60 * time.Second // Reduced from 5min for security
	}

	if cfg.Security.RateLimitDefault <= 0 {
		cfg.Security.RateLimitDefault = 100
	}

	if cfg.Security.IPRateLimit <= 0 {
		cfg.Security.IPRateLimit = 200
	}

	// Default to requiring nonce for security
	if cfg.Security.NonceRequired == nil {
		nonceRequired := true
		cfg.Security.NonceRequired = &nonceRequired
	}

	if cfg.Logger.Level == "" {
		cfg.Logger.Level = "info"
	}

	// ApprovalGuard defaults
	if cfg.Security.ApprovalGuard.Enabled && cfg.Security.ApprovalGuard.Threshold <= 0 {
		cfg.Security.ApprovalGuard.Threshold = 10
	}
	if cfg.Security.ApprovalGuard.Enabled && cfg.Security.ApprovalGuard.Window <= 0 {
		cfg.Security.ApprovalGuard.Window = 5 * time.Minute
	}
	if cfg.Security.ApprovalGuard.Enabled && cfg.Security.ApprovalGuard.ResumeAfter <= 0 {
		cfg.Security.ApprovalGuard.ResumeAfter = 2 * time.Hour
	}
}
