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
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/notify"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// Config is the root configuration structure
type Config struct {
	Server           ServerConfig            `yaml:"server"`
	Database         storage.Config          `yaml:"database"`
	Chains           ChainsConfig            `yaml:"chains"`
	Notify           notify.Config           `yaml:"notify"`
	NotifyChannel    notify.Channel          `yaml:"notify_channels"`
	AuditMonitor     audit.MonitorConfig     `yaml:"audit_monitor"`
	Security         SecurityConfig          `yaml:"security"`
	Logger           LoggerConfig            `yaml:"logger"`
	APIKeys          []APIKeyConfig          `yaml:"api_keys"`
	Templates        []TemplateConfig        `yaml:"templates"`
	Rules            []RuleConfig            `yaml:"rules"`
	Presets          *PresetsConfig          `yaml:"presets,omitempty"`
	DynamicBlocklist *DynamicBlocklistConfig `yaml:"dynamic_blocklist,omitempty"`
}

// DynamicBlocklistConfig configures the runtime address blocklist synced from external URLs.
type DynamicBlocklistConfig struct {
	Enabled      bool                     `yaml:"enabled"`
	SyncInterval string                   `yaml:"sync_interval"` // e.g. "1h", "30m"
	FailMode     string                   `yaml:"fail_mode"`     // "open" (default) or "close"
	CacheFile    string                   `yaml:"cache_file"`    // local file for persisting fetched addresses
	Sources      []DynamicBlocklistSource `yaml:"sources"`
}

// DynamicBlocklistSource defines an address list source.
type DynamicBlocklistSource struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"` // "url_text" or "url_json"
	URL      string `yaml:"url"`
	JSONPath string `yaml:"json_path"` // for url_json: dot-path to address array
}

// PresetsConfig configures the server preset API. When Dir is set, preset list/vars/apply endpoints are registered (admin-only).
type PresetsConfig struct {
	Dir string `yaml:"dir"` // required: directory containing preset YAML files (e.g. rules/presets)
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

// TemplateVarConfig defines a template variable in configuration.
// Optional variables (Required: false) must declare Default; validate-rules enforces this.
type TemplateVarConfig struct {
	Name        string  `yaml:"name"`
	Type        string  `yaml:"type"`
	Description string  `yaml:"description,omitempty"`
	Required    bool    `yaml:"required"`
	Default     *string `yaml:"default,omitempty"` // nil = not declared; optional vars must declare default
}

// TestCaseConfig defines a single test case for rule validation (evm_js, solidity, etc.)
type TestCaseConfig struct {
	Name               string                 `yaml:"name" json:"name"`
	Input              map[string]interface{} `yaml:"input" json:"input"`
	ExpectPass         bool                   `yaml:"expect_pass" json:"expect_pass"`
	ExpectReason       string                 `yaml:"expect_reason,omitempty" json:"expect_reason,omitempty"`
	ExpectBudgetAmount string                 `yaml:"expect_budget_amount,omitempty" json:"expect_budget_amount,omitempty"`
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
	Variables     map[string]interface{} `yaml:"variables,omitempty" json:"variables,omitempty"`           // instance/template variable values (e.g. for evm_js config)
	TestVariables map[string]string      `yaml:"test_variables,omitempty" json:"test_variables,omitempty"` // from template; used for running test cases at startup so expectations match
	TestCases     []TestCaseConfig       `yaml:"test_cases,omitempty" json:"test_cases,omitempty"`         // test cases for validation (evm_js, solidity, etc.)
	Enabled       bool                   `yaml:"enabled" json:"enabled"`
}

// APIKeyConfig defines an API key in configuration
type APIKeyConfig struct {
	ID           string `yaml:"id"`             // Unique identifier for the API key
	Name         string `yaml:"name"`           // Human-readable name
	PublicKey    string `yaml:"public_key"`     // Ed25519 public key (hex or base64, auto-detected)
	PublicKeyEnv string `yaml:"public_key_env"` // Environment variable containing public key
	RateLimit    int    `yaml:"rate_limit"`     // Requests per minute (default: 100)
	Enabled      bool   `yaml:"enabled"`        // Whether the key is active
	Role         string `yaml:"role"`           // API key role: admin, dev, agent, strategy
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
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	TLS          TLSConfig     `yaml:"tls"`
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
	Enabled     bool                 `yaml:"enabled"`
	Signers     evm.SignerConfig     `yaml:"signers"`
	KeystoreDir string               `yaml:"keystore_dir"`  // Directory for storing dynamically created keystores
	HDWalletDir string               `yaml:"hd_wallet_dir"` // Directory for storing HD wallets
	Foundry     FoundryConfig        `yaml:"foundry"`
	RPCGateway  evm.RPCGatewayConfig `yaml:"rpc_gateway"`   // RPC gateway for JS rule sandbox (read-only)
	Simulation  SimulationConfig     `yaml:"simulation"`    // Transaction simulation engine (anvil fork)
}

// FoundryConfig contains Foundry (forge) configuration for Solidity rules
type FoundryConfig struct {
	Enabled   bool          `yaml:"enabled"`
	ForgePath string        `yaml:"forge_path"` // path to forge binary, empty = auto-detect from PATH
	CacheDir  string        `yaml:"cache_dir"`  // cache directory for compiled scripts
	TempDir   string        `yaml:"temp_dir"`   // workspace dir for rule scripts and lib/forge-std; empty = os.TempDir()/remote-signer-rules. For Docker, set to /app/data/forge-workspace and mount repo data/forge-workspace.
	Timeout   time.Duration `yaml:"timeout"`    // max execution time per rule (default: 30s)
}

// SimulationConfig contains transaction simulation engine configuration.
type SimulationConfig struct {
	Enabled      bool          `yaml:"enabled"`
	Backend      string        `yaml:"backend"`         // "rpc" (eth_simulateV1 via gateway) or "anvil" (local fork). Default: "rpc"
	AnvilPath    string        `yaml:"anvil_path"`      // [anvil] path to anvil binary
	SyncInterval time.Duration `yaml:"sync_interval"`   // [anvil] periodic health check interval (default: 60s)
	Timeout      time.Duration `yaml:"timeout"`         // per-simulation timeout (default: 60s)
	MaxChains    int           `yaml:"max_chains"`      // [anvil] max concurrent anvil forks (default: 10)
	BatchWindow  time.Duration `yaml:"batch_window"`    // accumulation window for single sign fallback (default: 1s)
	BatchMaxSize int           `yaml:"batch_max_size"`  // max txs per batch (default: 20)
	PruneHistory int           `yaml:"prune_history"`   // [anvil] --prune-history: max states in memory (default: 0 = minimal)
	CacheDir     string        `yaml:"cache_dir"`       // [anvil] fork RPC cache directory (default: data/anvil-cache)
	// Budget defaults for auto-created simulation budget records (human-readable units).
	// Decimals are auto-queried from chain. "-1" = unlimited.
	BudgetNativeMaxTotal string `yaml:"budget_native_max_total"`  // native token max total per period (default: "0.01")
	BudgetNativeMaxPerTx string `yaml:"budget_native_max_per_tx"` // native token max per tx (default: "0.02")
	BudgetERC20MaxTotal  string `yaml:"budget_erc20_max_total"`   // ERC20 max total per period per token (default: "100")
	BudgetERC20MaxPerTx  string `yaml:"budget_erc20_max_per_tx"`  // ERC20 max per tx per token (default: "50")
}

// SecurityConfig contains security-related settings
type SecurityConfig struct {
	MaxRequestAge    time.Duration `yaml:"max_request_age"`
	RateLimitDefault int           `yaml:"rate_limit_default"`
	// IPRateLimit is the maximum requests per minute from a single IP address (pre-auth).
	// Protects against unauthenticated flood attacks. Default: 200.
	IPRateLimit int               `yaml:"ip_rate_limit"`
	IPWhitelist IPWhitelistConfig `yaml:"ip_whitelist"`
	// ManualApprovalEnabled: when true, requests with no whitelist match go to manual approval;
	// when false (default), they are rejected immediately. Default false for stricter security.
	ManualApprovalEnabled bool `yaml:"manual_approval_enabled"`
	// ApprovalGuard pauses all sign requests when too many consecutive manual-approval outcomes occur
	ApprovalGuard ApprovalGuardConfig `yaml:"approval_guard"`
	// NonceRequired enforces nonce for all requests (recommended for production)
	// When true, requests without X-Nonce header will be rejected
	NonceRequired *bool `yaml:"nonce_required"`

	// RulesAPIReadonly disables rule/template mutations via API.
	// Default (nil) = true. Covers: rule CRUD, template CRUD/instantiate/revoke,
	// approval auto-rule creation. Rules managed through config files only.
	RulesAPIReadonly *bool `yaml:"rules_api_readonly"`

	// SignersAPIReadonly disables signer/HD-wallet creation via API.
	// Default (nil) = false. Covers: signer creation, HD wallet create/import/derive.
	// Unlock/lock remain allowed. Signers managed through config or TUI.
	SignersAPIReadonly *bool `yaml:"signers_api_readonly"`

	// APIKeysAPIReadonly disables API key management via API.
	// Default (nil) = true (secure by default). API keys managed through config files only.
	APIKeysAPIReadonly *bool `yaml:"api_keys_api_readonly"`

	// AllowSIGHUPRulesReload enables reloading rules from config when receiving SIGHUP.
	// Default (nil) = false (secure by default). When disabled, SIGHUP is ignored (process stays alive).
	AllowSIGHUPRulesReload *bool `yaml:"allow_sighup_rules_reload"`

	// MaxRulesPerAPIKey limits how many rules a single non-admin API key can own.
	// Admin keys are exempt. Default: 50.
	MaxRulesPerAPIKey int `yaml:"max_rules_per_api_key"`

	// RequireApprovalForAgentRules: when true, agent-created whitelist rules start as "pending_approval"
	// and require admin approval before becoming active. Blocklist rules are always active immediately.
	// Default (nil) = true (secure by default). When false, agent-created whitelist rules
	// (including template instantiation with custom variables like allowed_spenders) become
	// active immediately without admin review, which is a security risk.
	RequireApprovalForAgentRules *bool `yaml:"require_approval_for_agent_rules"`

	// AutoLockTimeout: automatically lock signers after this duration since unlock.
	// Default: 0 (disabled). Example: "1h", "30m".
	AutoLockTimeout time.Duration `yaml:"auto_lock_timeout"`

	// SignTimeout: context timeout for sign operations. Default: 30s.
	SignTimeout time.Duration `yaml:"sign_timeout"`

	// MaxKeystoresPerKey limits how many keystores a single API key can own.
	// 0 = no limit. Default: 5.
	MaxKeystoresPerKey int `yaml:"max_keystores_per_key"`

	// MaxHDWalletsPerKey limits how many HD wallets a single API key can own.
	// 0 = no limit. Default: 3.
	MaxHDWalletsPerKey int `yaml:"max_hd_wallets_per_key"`
}

// IsRulesAPIReadonly returns whether rule/template mutations via API are disabled.
// Defaults to true (secure by default) when not explicitly configured.
func (s SecurityConfig) IsRulesAPIReadonly() bool {
	if s.RulesAPIReadonly == nil {
		return true
	}
	return *s.RulesAPIReadonly
}

// IsSignersAPIReadonly returns whether signer/HD-wallet creation via API is disabled.
// Defaults to false when not explicitly configured (low risk: API never exposes private keys).
func (s SecurityConfig) IsSignersAPIReadonly() bool {
	if s.SignersAPIReadonly == nil {
		return false
	}
	return *s.SignersAPIReadonly
}

// IsAPIKeysAPIReadonly returns whether API key management via API is disabled.
// Defaults to true (secure by default) when not explicitly configured.
func (s SecurityConfig) IsAPIKeysAPIReadonly() bool {
	if s.APIKeysAPIReadonly == nil {
		return true
	}
	return *s.APIKeysAPIReadonly
}

// IsRequireApprovalForAgentRules returns whether agent-created whitelist rules require admin approval.
// Defaults to true (secure by default) when not explicitly configured.
func (s SecurityConfig) IsRequireApprovalForAgentRules() bool {
	if s.RequireApprovalForAgentRules == nil {
		return true
	}
	return *s.RequireApprovalForAgentRules
}

// IsSIGHUPRulesReloadEnabled returns whether SIGHUP-triggered rules reload is enabled.
// Defaults to false (secure by default) when not explicitly configured.
func (s SecurityConfig) IsSIGHUPRulesReloadEnabled() bool {
	if s.AllowSIGHUPRulesReload == nil {
		return false
	}
	return *s.AllowSIGHUPRulesReload
}

// ApprovalGuardConfig configures the request-rejection burst guard.
// When within Window there are Threshold consecutive outcomes that are either: (a) blocked by a rule,
// or (b) require manual approval (no whitelist match), the guard pauses all sign requests and alerts.
// Use case: detect API key abuse — attacker with valid API key repeatedly hits rule rejections or pending approval.
// After ResumeAfter the guard auto-resumes so the team has time to respond.
type ApprovalGuardConfig struct {
	Enabled               bool          `yaml:"enabled"`
	Window                time.Duration `yaml:"window"`                  // sliding time window for rate calculation (default: 1h)
	RejectionThresholdPct float64       `yaml:"rejection_threshold_pct"` // rejection rate % that triggers pause (default: 50)
	MinSamples            int           `yaml:"min_samples"`             // minimum events in window before rate check applies (default: 10)
	ResumeAfter           time.Duration `yaml:"resume_after"`            // pause duration after which to auto-resume (e.g. 2h)
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

	data, err := os.ReadFile(path) // #nosec G304 -- path is admin-provided config file
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables in the config (supports ${VAR:-default} syntax)
	expandedData := ExpandEnvWithDefaults(string(data))

	cfg := &Config{}
	if err := yaml.Unmarshal([]byte(expandedData), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Prefer DATABASE_DSN env over config (required for Docker host network: config may have "postgres" hostname)
	if dsn := os.Getenv("DATABASE_DSN"); dsn != "" {
		cfg.Database.DSN = dsn
	}

	// Set defaults before validation so that default budget values are populated
	setDefaults(cfg)

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

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

	// Validate simulation requires budget defaults
	if cfg.Chains.EVM != nil && cfg.Chains.EVM.Simulation.Enabled {
		sim := cfg.Chains.EVM.Simulation
		if sim.BudgetNativeMaxTotal == "" && sim.BudgetNativeMaxPerTx == "" &&
			sim.BudgetERC20MaxTotal == "" && sim.BudgetERC20MaxPerTx == "" {
			return fmt.Errorf("simulation is enabled but no budget defaults configured (budget_native_max_total, budget_native_max_per_tx, budget_erc20_max_total, budget_erc20_max_per_tx are all empty); this allows unlimited spending — configure budget limits or disable simulation")
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

		if key.Role == "" {
			return fmt.Errorf("api_keys[%d] (%s): role is required (admin, dev, agent, strategy)", i, key.ID)
		}
		if !types.IsValidAPIKeyRole(key.Role) {
			return fmt.Errorf("api_keys[%d] (%s): invalid role %q (must be admin, dev, agent, or strategy)", i, key.ID, key.Role)
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

	// EVM directory defaults
	if cfg.Chains.EVM != nil && cfg.Chains.EVM.Enabled {
		if cfg.Chains.EVM.KeystoreDir == "" {
			cfg.Chains.EVM.KeystoreDir = "./data/keystores"
		}
		if cfg.Chains.EVM.HDWalletDir == "" {
			cfg.Chains.EVM.HDWalletDir = "./data/hd-wallets"
		}
	}

	// Simulation engine defaults
	if cfg.Chains.EVM != nil && cfg.Chains.EVM.Simulation.Enabled {
		sim := &cfg.Chains.EVM.Simulation
		if sim.AnvilPath == "" {
			sim.AnvilPath = "data/foundry/anvil"
		}
		if sim.SyncInterval <= 0 {
			sim.SyncInterval = 60 * time.Second
		}
		if sim.Timeout <= 0 {
			sim.Timeout = 60 * time.Second
		}
		if sim.MaxChains <= 0 {
			sim.MaxChains = 10
		}
		if sim.BatchWindow <= 0 {
			sim.BatchWindow = 1 * time.Second
		}
		if sim.BatchMaxSize <= 0 {
			sim.BatchMaxSize = 20
		}
		if sim.CacheDir == "" {
			sim.CacheDir = "data/anvil-cache"
		}
		if sim.BudgetNativeMaxTotal == "" {
			sim.BudgetNativeMaxTotal = "0.01"
		}
		if sim.BudgetNativeMaxPerTx == "" {
			sim.BudgetNativeMaxPerTx = "0.1"
		}
		if sim.BudgetERC20MaxTotal == "" {
			sim.BudgetERC20MaxTotal = "100"
		}
		if sim.BudgetERC20MaxPerTx == "" {
			sim.BudgetERC20MaxPerTx = "50"
		}
	}

	// Rule limits defaults
	if cfg.Security.MaxRulesPerAPIKey <= 0 {
		cfg.Security.MaxRulesPerAPIKey = 50
	}

	// Resource limit defaults
	if cfg.Security.MaxKeystoresPerKey <= 0 {
		cfg.Security.MaxKeystoresPerKey = 5
	}
	if cfg.Security.MaxHDWalletsPerKey <= 0 {
		cfg.Security.MaxHDWalletsPerKey = 3
	}

	// ApprovalGuard defaults
	if cfg.Security.ApprovalGuard.Enabled && cfg.Security.ApprovalGuard.RejectionThresholdPct <= 0 {
		cfg.Security.ApprovalGuard.RejectionThresholdPct = 50
	}
	if cfg.Security.ApprovalGuard.Enabled && cfg.Security.ApprovalGuard.MinSamples <= 0 {
		cfg.Security.ApprovalGuard.MinSamples = 10
	}
	if cfg.Security.ApprovalGuard.Enabled && cfg.Security.ApprovalGuard.Window <= 0 {
		cfg.Security.ApprovalGuard.Window = 1 * time.Hour
	}
	if cfg.Security.ApprovalGuard.Enabled && cfg.Security.ApprovalGuard.ResumeAfter <= 0 {
		cfg.Security.ApprovalGuard.ResumeAfter = 2 * time.Hour
	}
}
