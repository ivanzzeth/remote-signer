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

// DefaultSecurity returns the snapshot Manager seeds when no
// system_settings row exists for the security group.
//
// The *_api_readonly flags default to FALSE so a freshly-bootstrapped
// daemon is usable through the API/UI out of the box — they're a
// post-setup hardening switch, not a "secure on first run" stance. The
// real security guard is RBAC (admin-only writes) + the
// require_approval_for_agent_rules flag on non-admin keys, both of
// which stay on. Operators who want to freeze a hand-curated config
// against further API edits flip these to true via the Settings UI or
// config.yaml — and that's the load-bearing knob, not the default.
func DefaultSecurity() *SecuritySnapshot {
	return &SecuritySnapshot{
		MaxRequestAge:                60 * time.Second,
		RateLimitDefault:             100,
		IPRateLimit:                  200,
		NonceRequired:                true,
		ManualApprovalEnabled:        true,
		RulesAPIReadonly:             false,
		SignersAPIReadonly:           false,
		APIKeysAPIReadonly:           false,
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

// SimulationSnapshot is the runtime view of the simulation engine knobs.
//
// AutoCreateBudget gates the lazy "first-outflow" budget creation in
// SimulationBudgetRule. When false the rule still evaluates simulation
// results (deny on excess) but no new sim:<signer> rows are written —
// existing rows continue to be debited so admins can disable the
// system globally without losing in-flight spend tracking.
//
// MaxDynamicUnits caps how many distinct (signer, token) units a
// single signer can accumulate, defending against budget-amplification
// attacks where a hostile caller targets many tokens.
type SimulationSnapshot struct {
	Enabled              bool          `json:"enabled"`
	Timeout              time.Duration `json:"timeout"`
	BatchWindow          time.Duration `json:"batch_window"`
	BatchMaxSize         int           `json:"batch_max_size"`
	AutoCreateBudget     bool          `json:"auto_create_budget"`
	MaxDynamicUnits      int           `json:"max_dynamic_units"`
	BudgetNativeMaxTotal string        `json:"budget_native_max_total"`
	BudgetNativeMaxPerTx string        `json:"budget_native_max_per_tx"`
	BudgetERC20MaxTotal  string        `json:"budget_erc20_max_total"`
	BudgetERC20MaxPerTx  string        `json:"budget_erc20_max_per_tx"`
}

// BlocklistSnapshot mirrors config.DynamicBlocklistConfig. SyncInterval is
// kept as the human-readable string ("1h", "30m") that YAML uses; the
// overlay layer parses it into time.Duration when assigning to the runtime
// config so cfg consumers see no behaviour change.
type BlocklistSnapshot struct {
	Enabled      bool             `json:"enabled"`
	SyncInterval string           `json:"sync_interval"`
	FailMode     string           `json:"fail_mode"`
	CacheFile    string           `json:"cache_file"`
	Sources      []BlocklistEntry `json:"sources"`
}

// BlocklistEntry mirrors config.DynamicBlocklistSource (one address-list source).
type BlocklistEntry struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	URL      string `json:"url"`
	JSONPath string `json:"json_path,omitempty"`
}

// AuditMonitorSnapshot mirrors audit.MonitorConfig.
type AuditMonitorSnapshot struct {
	Enabled                  bool          `json:"enabled"`
	Interval                 time.Duration `json:"interval"`
	LookbackHours            int           `json:"lookback_hours"`
	AuthFailureThreshold     int           `json:"auth_failure_threshold"`
	BlocklistRejectThreshold int           `json:"blocklist_reject_threshold"`
	HighFreqThreshold        int           `json:"high_freq_threshold"`
	RetentionDays            int           `json:"retention_days"`
	CleanupInterval          time.Duration `json:"cleanup_interval"`
}

// NotifySnapshot mirrors what used to live under the YAML `notify` and
// `notify_channels` blocks. The two are bundled into a single snapshot so
// admins can update provider credentials and recipient routing atomically;
// the API exposes this as a single group "notify".
type NotifySnapshot struct {
	Providers NotifyProviders `json:"providers"`
	Channels  NotifyChannels  `json:"channels"`
}

// NotifyProviders holds per-provider service config (tokens, timeouts).
// Field names align with notify.Config in the notify package.
type NotifyProviders struct {
	Slack    *NotifySlackProvider    `json:"slack,omitempty"`
	Pushover *NotifyPushoverProvider `json:"pushover,omitempty"`
	Webhook  *NotifyWebhookProvider  `json:"webhook,omitempty"`
	Telegram *NotifyTelegramProvider `json:"telegram,omitempty"`
}

// NotifySlackProvider holds Slack service config (bot token).
type NotifySlackProvider struct {
	Enabled  bool   `json:"enabled"`
	BotToken string `json:"bot_token"`
}

// NotifyPushoverProvider holds Pushover service config (app token, retry).
type NotifyPushoverProvider struct {
	Enabled    bool `json:"enabled"`
	AppToken   string `json:"app_token"`
	Retry      int  `json:"retry"`
	Expire     int  `json:"expire"`
	MaxRetries int  `json:"max_retries"`
	RetryDelay int  `json:"retry_delay"`
}

// NotifyWebhookProvider holds webhook service config (headers, timeout).
type NotifyWebhookProvider struct {
	Enabled bool              `json:"enabled"`
	Headers map[string]string `json:"headers,omitempty"`
	Timeout time.Duration     `json:"timeout,omitempty"`
}

// NotifyTelegramProvider holds Telegram service config (bot token).
type NotifyTelegramProvider struct {
	Enabled  bool   `json:"enabled"`
	BotToken string `json:"bot_token"`
}

// NotifyChannels holds the recipient lists used to fan a single notification
// out to multiple destinations within each provider. Mirrors notify.Channel.
type NotifyChannels struct {
	Slack    []string `json:"slack,omitempty"`
	Pushover []string `json:"pushover,omitempty"`
	Webhook  []string `json:"webhook,omitempty"`
	Telegram []string `json:"telegram,omitempty"`
}

// RPCGatewaySnapshot mirrors evm.RPCGatewayConfig (read-only EVM RPC proxy
// used by the JS rule sandbox).
type RPCGatewaySnapshot struct {
	BaseURL  string        `json:"base_url"`
	APIKey   string        `json:"api_key,omitempty"`
	CacheTTL time.Duration `json:"cache_ttl"`
}

// MaterialCheckSnapshot mirrors config.SignerMaterialCheckConfig.
type MaterialCheckSnapshot struct {
	Enabled      bool          `json:"enabled"`
	StartupCheck bool          `json:"startup_check"`
	Interval     time.Duration `json:"interval"`
}

// WebSnapshot controls the embedded web UI. Enabled gates whether the
// catch-all "/" handler is registered at all; DevProxy, when non-empty,
// switches the handler from embed.FS to a reverse proxy pointed at a
// running Vite dev server (the front-end developer's workflow).
type WebSnapshot struct {
	Enabled  bool   `json:"enabled"`
	DevProxy string `json:"dev_proxy,omitempty"`
}

// DefaultWeb returns the secure-by-default snapshot. Enabled=true is the
// "easy install" choice — operators who want a headless deployment can
// flip it off via `remote-signer settings set web enabled=false` without
// losing any other configuration.
func DefaultWeb() *WebSnapshot {
	return &WebSnapshot{Enabled: true}
}
