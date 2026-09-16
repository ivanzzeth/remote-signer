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
// ⛔ 为什么每一个字段都是指针 —— 动它之前先读这一段
//
// nil 表示**「这次请求没有提到它」**,而不是「把它设成零值」。这两件事在裸值上
// 不可区分,而它们的后果相反。
//
// 2026-09-15 实测的真实形状:`PUT /api/v1/admin/settings/security` 把 body 解进一个
// **全零值**的结构体,再把那个结构体整份存下去。于是一个只想调限流的调用方发
// `{"rate_limit_default":500}`,会顺带:
//
//	nonce_required                → false   (默认 true,**防重放关掉**)
//	manual_approval_enabled       → false   (默认 true,**人工审批关掉**)
//	require_approval_for_agent_rules → false (默认 true,agent 建规则不再需批准)
//	max_rules_per_api_key         → 0       (默认 50)
//	max_keystores_per_key         → 0       (默认 5,而 **0 = 无限制**,config.go:341)
//	max_hd_wallets_per_key        → 0       (默认 3,同上,config.go:345)
//
// ⭐ 规律是单向的:**少写一个字段,后果一律是更松**。而 PRD §6 写着 ——
//
//	N3「『没设置』被当成『不限制』:空着不填的后果必须是**更严**,不是更松」
//	N1「配置写错,结果比写对**更宽松**」
//
// 这个形状正面撞上那两条,而 N1 本身正是从 incidents.md 里「一个拼写错误让额度
// 上限变成无限」那次事故学来的 —— 同一个形状,换个地方又长了一遍。
//
// ⚠️ 三层里**只有这一层**是裸值:config.SecurityConfig 与 SecurityYAMLView 早就用
// `*bool` 表达「没写」,而 seed.go 的 `if v.X != nil { s.X = *v.X }` 就是信息在这一层
// 被丢掉的那一行。所以指针化不是发明新语义,是把 API 层补齐到 YAML 层早有的表达力。
//
// ⛔ **不变式:Manager 手上的快照永远不含 nil。** NewManager 用 DefaultSecurity()
// 播种,UpdateSecurity 只把非 nil 的字段合并进当前值 —— 所以读取路径拿到的字段
// 一定非 nil。⚠️ 即便如此也请走下面的访问器(Guard/Whitelist/…)或 Deref:
// 一次 nil 解引用在一个持有私钥的守护进程里是**停摆**,而停摆和被攻击在主人眼里
// 长得一样(incidents.md N6)。
type SecuritySnapshot struct {
	MaxRequestAge                *time.Duration `json:"max_request_age,omitempty"`
	RateLimitDefault             *int           `json:"rate_limit_default,omitempty"`
	IPRateLimit                  *int           `json:"ip_rate_limit,omitempty"`
	IPWhitelist                  *IPWhitelist   `json:"ip_whitelist,omitempty"`
	ManualApprovalEnabled        *bool          `json:"manual_approval_enabled,omitempty"`
	ApprovalGuard                *ApprovalGuard `json:"approval_guard,omitempty"`
	NonceRequired                *bool          `json:"nonce_required,omitempty"`
	RulesAPIReadonly             *bool          `json:"rules_api_readonly,omitempty"`
	SignersAPIReadonly           *bool          `json:"signers_api_readonly,omitempty"`
	APIKeysAPIReadonly           *bool          `json:"api_keys_api_readonly,omitempty"`
	AllowSIGHUPRulesReload       *bool          `json:"allow_sighup_rules_reload,omitempty"`
	MaxRulesPerAPIKey            *int           `json:"max_rules_per_api_key,omitempty"`
	RequireApprovalForAgentRules *bool          `json:"require_approval_for_agent_rules,omitempty"`
	AutoLockTimeout              *time.Duration `json:"auto_lock_timeout,omitempty"`
	SignTimeout                  *time.Duration `json:"sign_timeout,omitempty"`
	MaxKeystoresPerKey           *int           `json:"max_keystores_per_key,omitempty"`
	MaxHDWalletsPerKey           *int           `json:"max_hd_wallets_per_key,omitempty"`
}

// Ptr returns a pointer to v. Exists so callers can write field: Ptr(true)
// instead of hoisting a variable for every field.
func Ptr[T any](v T) *T { return &v }

// Deref returns *p, or def when p is nil.
//
// ⚠️ def is what "the caller never said" means for that field — it is not a
// safety net for a snapshot that should have been complete. On a snapshot from
// Manager every field is non-nil (see the invariant above), so a def that gets
// used there is a bug somewhere else, not a value to rely on.
func Deref[T any](p *T, def T) T {
	if p == nil {
		return def
	}
	return *p
}

// Guard returns the approval-guard block, zero-valued when unset.
// ⭐ The zero ApprovalGuard has Enabled=false, which is the safe reading of
// "nobody configured a guard": no guard, rather than a guard that never trips.
func (s *SecuritySnapshot) Guard() ApprovalGuard {
	if s == nil || s.ApprovalGuard == nil {
		return ApprovalGuard{}
	}
	return *s.ApprovalGuard
}

// Whitelist returns the IP-whitelist block, zero-valued when unset.
// ⚠️ The zero IPWhitelist has Enabled=false — i.e. no IP restriction. That is
// the existing meaning of an absent ip_whitelist block, not a new decision.
func (s *SecuritySnapshot) Whitelist() IPWhitelist {
	if s == nil || s.IPWhitelist == nil {
		return IPWhitelist{}
	}
	return *s.IPWhitelist
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
// ⛔ 每一个字段都必须显式给值,一个都不能省 —— 这是「Manager 手上的快照永不含
// nil」那条不变式的**唯一**来源。
//
// ⚠️ 三个字段以前靠零值、这里改成显式写出来,值与行为**一字不差**:
//
//	AutoLockTimeout: 0     以前不写(零值 0),0 的含义是**不自动锁定**(config.go:333)
//	IPWhitelist:     {}     以前不写,零值的 Enabled=false 意为不做 IP 限制
//	ApprovalGuard:   {}     以前不写,零值的 Enabled=false 意为没有守卫
//
// ⛔ 别把它们删回去「反正是零值」:指针化之后不写就是 nil,而 nil 会让读取路径
// 拿到 Deref 的兜底值,那是另一条语义。
func DefaultSecurity() *SecuritySnapshot {
	return &SecuritySnapshot{
		MaxRequestAge:                Ptr(60 * time.Second),
		RateLimitDefault:             Ptr(100),
		IPRateLimit:                  Ptr(200),
		IPWhitelist:                  &IPWhitelist{},
		NonceRequired:                Ptr(true),
		ManualApprovalEnabled:        Ptr(true),
		ApprovalGuard:                &ApprovalGuard{},
		RulesAPIReadonly:             Ptr(false),
		SignersAPIReadonly:           Ptr(false),
		APIKeysAPIReadonly:           Ptr(false),
		AllowSIGHUPRulesReload:       Ptr(false),
		MaxRulesPerAPIKey:            Ptr(50),
		RequireApprovalForAgentRules: Ptr(true),
		AutoLockTimeout:              Ptr(time.Duration(0)),
		SignTimeout:                  Ptr(30 * time.Second),
		MaxKeystoresPerKey:           Ptr(5),
		MaxHDWalletsPerKey:           Ptr(3),
	}
}

// FoundrySnapshot — placeholder for PR7d. Fields land when consumers switch.
// ⛔ 指针的含义与 SecuritySnapshot 一致(见那边的长注释):nil = 这次请求没有提到
// 这个字段,而不是「把它设成零值」。
//
// ⚠️ 与 security 的**一处不同**:这一组没有 DefaultFoundry(),NewManager 播种的是
// `&FoundrySnapshot{}`(全 nil)。那不是疏漏 —— 它的出厂默认**本来就是零值**,
// 所以「没配过」与「配成零值」在结果上相同,用 nil 表达「没配过」更诚实。
// 读取侧一律走 Deref 兜到零值。
type FoundrySnapshot struct {
	Enabled   *bool          `json:"enabled,omitempty"`
	ForgePath *string        `json:"forge_path,omitempty"`
	CacheDir  *string        `json:"cache_dir,omitempty"`
	TempDir   *string        `json:"temp_dir,omitempty"`
	Timeout   *time.Duration `json:"timeout,omitempty"`
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
	Enabled              *bool          `json:"enabled,omitempty"`
	Timeout              *time.Duration `json:"timeout,omitempty"`
	BatchWindow          *time.Duration `json:"batch_window,omitempty"`
	BatchMaxSize         *int           `json:"batch_max_size,omitempty"`
	AutoCreateBudget     *bool          `json:"auto_create_budget,omitempty"`
	MaxDynamicUnits      *int           `json:"max_dynamic_units,omitempty"`
	BudgetNativeMaxTotal *string        `json:"budget_native_max_total,omitempty"`
	BudgetNativeMaxPerTx *string        `json:"budget_native_max_per_tx,omitempty"`
	BudgetERC20MaxTotal  *string        `json:"budget_erc20_max_total,omitempty"`
	BudgetERC20MaxPerTx  *string        `json:"budget_erc20_max_per_tx,omitempty"`
}

// BlocklistSnapshot mirrors config.DynamicBlocklistConfig. SyncInterval is
// kept as the human-readable string ("1h", "30m") that YAML uses; the
// overlay layer parses it into time.Duration when assigning to the runtime
// config so cfg consumers see no behaviour change.
// ⚠️ Sources 保持 slice,**不**加指针:slice 自己就有 nil 语义 —— JSON 里不提供
// 解成 nil(= 没提到),`[]` 解成非 nil 的空切片(= 明确要求清空)。再包一层指针
// 只会多出一个无意义的「指向 nil 切片的非 nil 指针」状态。
type BlocklistSnapshot struct {
	Enabled      *bool            `json:"enabled,omitempty"`
	SyncInterval *string          `json:"sync_interval,omitempty"`
	FailMode     *string          `json:"fail_mode,omitempty"`
	CacheFile    *string          `json:"cache_file,omitempty"`
	Sources      []BlocklistEntry `json:"sources,omitempty"`
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
	Enabled                  *bool          `json:"enabled,omitempty"`
	Interval                 *time.Duration `json:"interval,omitempty"`
	LookbackHours            *int           `json:"lookback_hours,omitempty"`
	AuthFailureThreshold     *int           `json:"auth_failure_threshold,omitempty"`
	BlocklistRejectThreshold *int           `json:"blocklist_reject_threshold,omitempty"`
	HighFreqThreshold        *int           `json:"high_freq_threshold,omitempty"`
	RetentionDays            *int           `json:"retention_days,omitempty"`
	CleanupInterval          *time.Duration `json:"cleanup_interval,omitempty"`
}

// NotifySnapshot mirrors what used to live under the YAML `notify` and
// `notify_channels` blocks. The two are bundled into a single snapshot so
// admins can update provider credentials and recipient routing atomically;
// the API exposes this as a single group "notify".
// ⚠️ 合并粒度到 **provider 为止**,不再往下拆。
//
// Providers / Channels 指针化(nil = 没提到整块),而 NotifyProviders 里那四个
// provider 本来就是指针,mergeNotify 逐个判 nil —— 所以「只改 Slack」不会丢掉
// Pushover/Webhook/Telegram。
//
// ⛔ 但 provider **内部**字段(enabled / bot_token …)仍是裸值:改一个 provider
// 要把它那一块整体发上来。那是有意的取舍 —— 一个 provider 的 enabled 与凭据
// 本来就是一件事,而再往下拆是 16 个字段加 4 个嵌套 merge。
type NotifySnapshot struct {
	Providers *NotifyProviders `json:"providers,omitempty"`
	Channels  *NotifyChannels  `json:"channels,omitempty"`
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
	Enabled    bool   `json:"enabled"`
	AppToken   string `json:"app_token"`
	Retry      int    `json:"retry"`
	Expire     int    `json:"expire"`
	MaxRetries int    `json:"max_retries"`
	RetryDelay int    `json:"retry_delay"`
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
	BaseURL  *string        `json:"base_url,omitempty"`
	APIKey   *string        `json:"api_key,omitempty"`
	CacheTTL *time.Duration `json:"cache_ttl,omitempty"`
}

// MaterialCheckSnapshot mirrors config.SignerMaterialCheckConfig.
type MaterialCheckSnapshot struct {
	Enabled      *bool          `json:"enabled,omitempty"`
	StartupCheck *bool          `json:"startup_check,omitempty"`
	Interval     *time.Duration `json:"interval,omitempty"`
}

// WebSnapshot controls the embedded web UI. Enabled gates whether the
// catch-all "/" handler is registered at all; DevProxy, when non-empty,
// switches the handler from embed.FS to a reverse proxy pointed at a
// running Vite dev server (the front-end developer's workflow).
// ⚠️ Web 与其余七组不同,它**有**实质默认值(Enabled=true),所以像 security 一样
// 由 DefaultWeb() 播种出完整快照 —— 对它而言 nil 不等于零值:漏掉 enabled 会
// 关掉整个 Web UI,而默认是开着的。
type WebSnapshot struct {
	Enabled  *bool   `json:"enabled,omitempty"`
	DevProxy *string `json:"dev_proxy,omitempty"`
}

// DefaultWeb returns the secure-by-default snapshot. Enabled=true is the
// "easy install" choice — operators who want a headless deployment can
// flip it off via `remote-signer settings set web enabled=false` without
// losing any other configuration.
func DefaultWeb() *WebSnapshot {
	return &WebSnapshot{Enabled: Ptr(true), DevProxy: Ptr("")}
}
