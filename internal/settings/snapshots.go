package settings

import "time"

// Snapshot types mirror the YAML config groups that move into system_settings.
// Each is small, JSON-tagged, and cheap to copy — Manager hands callers a
// pointer to the current immutable snapshot, and writes go through Manager
// (never via mutating the snapshot).
//
// PR7a defines the SecuritySnapshot in full so subsequent PRs (7b) can switch
// consumers over without further plumbing churn. The remaining groups live as
// placeholder types now and will gain fields as each PR7c/d migration lands.

// SecuritySnapshot holds every knob currently under SecurityConfig in YAML.
// Field names are derived from the existing YAML/JSON keys so that PUT
// requests against /api/v1/admin/settings/security accept the same shape an
// operator already understands from config.example.yaml.
type SecuritySnapshot struct {
	MaxRequestAge                time.Duration `json:"max_request_age"`
	RateLimitDefault             int           `json:"rate_limit_default"`
	IPRateLimit                  int           `json:"ip_rate_limit"`
	IPWhitelist                  IPWhitelist   `json:"ip_whitelist"`
	ManualApprovalEnabled        bool          `json:"manual_approval_enabled"`
	ApprovalGuard                ApprovalGuard `json:"approval_guard"`
	NonceRequired                bool          `json:"nonce_required"`
	RulesAPIReadonly             bool          `json:"rules_api_readonly"`
	SignersAPIReadonly           bool          `json:"signers_api_readonly"`
	APIKeysAPIReadonly           bool          `json:"api_keys_api_readonly"`
	AllowSIGHUPRulesReload       bool          `json:"allow_sighup_rules_reload"`
	MaxRulesPerAPIKey            int           `json:"max_rules_per_api_key"`
	RequireApprovalForAgentRules bool          `json:"require_approval_for_agent_rules"`
	AutoLockTimeout              time.Duration `json:"auto_lock_timeout"`
	SignTimeout                  time.Duration `json:"sign_timeout"`
	MaxKeystoresPerKey           int           `json:"max_keystores_per_key"`
	MaxHDWalletsPerKey           int           `json:"max_hd_wallets_per_key"`
}

// IPWhitelist matches the YAML shape.
type IPWhitelist struct {
	Enabled        bool     `json:"enabled"`
	AllowedIPs     []string `json:"allowed_ips"`
	TrustProxy     bool     `json:"trust_proxy"`
	TrustedProxies []string `json:"trusted_proxies"`
}

// ApprovalGuard matches the YAML shape.
type ApprovalGuard struct {
	Enabled               bool          `json:"enabled"`
	Window                time.Duration `json:"window"`
	RejectionThresholdPct float64       `json:"rejection_threshold_pct"`
	MinSamples            int           `json:"min_samples"`
	ResumeAfter           time.Duration `json:"resume_after"`
}

// DefaultSecurity returns the secure-by-default snapshot Manager seeds when
// no system_settings row exists for the security group. Values match the
// current config.setDefaults() behaviour so PR7b can be a pure migration.
func DefaultSecurity() *SecuritySnapshot {
	return &SecuritySnapshot{
		MaxRequestAge:                60 * time.Second,
		RateLimitDefault:             100,
		IPRateLimit:                  200,
		NonceRequired:                true,
		RulesAPIReadonly:             true,
		SignersAPIReadonly:           false,
		APIKeysAPIReadonly:           true,
		AllowSIGHUPRulesReload:       false,
		MaxRulesPerAPIKey:            50,
		RequireApprovalForAgentRules: true,
		SignTimeout:                  30 * time.Second,
		MaxKeystoresPerKey:           5,
		MaxHDWalletsPerKey:           3,
	}
}

// FoundrySnapshot — placeholder for PR7d. Fields land when consumers switch.
type FoundrySnapshot struct {
	Enabled   bool          `json:"enabled"`
	ForgePath string        `json:"forge_path"`
	CacheDir  string        `json:"cache_dir"`
	TempDir   string        `json:"temp_dir"`
	Timeout   time.Duration `json:"timeout"`
}

// SimulationSnapshot — placeholder for PR7d.
type SimulationSnapshot struct {
	Enabled              bool          `json:"enabled"`
	Timeout              time.Duration `json:"timeout"`
	BatchWindow          time.Duration `json:"batch_window"`
	BatchMaxSize         int           `json:"batch_max_size"`
	BudgetNativeMaxTotal string        `json:"budget_native_max_total"`
	BudgetNativeMaxPerTx string        `json:"budget_native_max_per_tx"`
	BudgetERC20MaxTotal  string        `json:"budget_erc20_max_total"`
	BudgetERC20MaxPerTx  string        `json:"budget_erc20_max_per_tx"`
}

// BlocklistSnapshot — placeholder for PR7d (replaces config.DynamicBlocklistConfig).
type BlocklistSnapshot struct {
	Enabled      bool             `json:"enabled"`
	SyncInterval time.Duration    `json:"sync_interval"`
	FailMode     string           `json:"fail_mode"`
	CacheFile    string           `json:"cache_file"`
	Sources      []BlocklistEntry `json:"sources"`
}

// BlocklistEntry — placeholder for PR7d.
type BlocklistEntry struct {
	Type     string `json:"type"`
	URL      string `json:"url"`
	JSONPath string `json:"json_path"`
}

// AuditMonitorSnapshot — placeholder for PR7d.
type AuditMonitorSnapshot struct {
	Enabled bool `json:"enabled"`
}

// RPCGatewaySnapshot — placeholder for PR7d.
type RPCGatewaySnapshot struct {
	Enabled bool `json:"enabled"`
}

// MaterialCheckSnapshot — placeholder for PR7d.
type MaterialCheckSnapshot struct {
	Enabled      bool          `json:"enabled"`
	StartupCheck bool          `json:"startup_check"`
	Interval     time.Duration `json:"interval"`
}
