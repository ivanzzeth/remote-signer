package settings

import (
	"context"
	"errors"
	"time"
)

// SeedSecurity writes the given snapshot to the store unless a security row
// already exists. This is the one-shot bootstrap that moves an existing YAML
// configuration into system_settings on first launch of a Phase-3 build;
// subsequent launches use the persisted row (which the admin API can edit).
//
// The function reads through the Store directly rather than the Manager so
// callers can run it before any Reload — the seed value will be picked up by
// the next Reload.
func SeedSecurity(ctx context.Context, store Store, snapshot *SecuritySnapshot) error {
	return seedIfMissing(ctx, store, GroupSecurity, snapshot)
}

// SeedNotify writes the given notify snapshot to the store unless a notify
// row already exists. Same one-shot semantics as SeedSecurity.
func SeedNotify(ctx context.Context, store Store, snapshot *NotifySnapshot) error {
	return seedIfMissing(ctx, store, GroupNotify, snapshot)
}

// SeedAuditMonitor seeds the audit-monitor group.
func SeedAuditMonitor(ctx context.Context, store Store, s *AuditMonitorSnapshot) error {
	return seedIfMissing(ctx, store, GroupAuditMonitor, s)
}

// SeedBlocklist seeds the dynamic blocklist group.
func SeedBlocklist(ctx context.Context, store Store, s *BlocklistSnapshot) error {
	return seedIfMissing(ctx, store, GroupBlocklist, s)
}

// SeedSimulation seeds the EVM simulation group.
func SeedSimulation(ctx context.Context, store Store, s *SimulationSnapshot) error {
	return seedIfMissing(ctx, store, GroupSimulation, s)
}

// SeedFoundry seeds the EVM foundry group.
func SeedFoundry(ctx context.Context, store Store, s *FoundrySnapshot) error {
	return seedIfMissing(ctx, store, GroupFoundry, s)
}

// SeedRPCGateway seeds the EVM RPC gateway group.
func SeedRPCGateway(ctx context.Context, store Store, s *RPCGatewaySnapshot) error {
	return seedIfMissing(ctx, store, GroupRPCGateway, s)
}

// SeedMaterialCheck seeds the EVM signer-material-check group.
func SeedMaterialCheck(ctx context.Context, store Store, s *MaterialCheckSnapshot) error {
	return seedIfMissing(ctx, store, GroupMaterialCheck, s)
}

// SeedWeb seeds the web-UI group (defaults to enabled on a fresh install).
func SeedWeb(ctx context.Context, store Store, s *WebSnapshot) error {
	return seedIfMissing(ctx, store, GroupWeb, s)
}

func seedIfMissing(ctx context.Context, store Store, key Group, value any) error {
	row, err := store.Get(ctx, key)
	if err == nil {
		// Overwrite rows that a previous version's bootstrap wrote so
		// code-default changes propagate on upgrade without clobbering
		// values set by an admin through the API/UI.
		if row.UpdatedBy == UpdatedByBootstrap {
			mgr := &Manager{store: store, interval: DefaultRefreshInterval}
			return mgr.put(ctx, key, value, UpdatedByBootstrap)
		}
		return nil
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	mgr := &Manager{store: store, interval: DefaultRefreshInterval}
	return mgr.put(ctx, key, value, UpdatedByBootstrap)
}

// SecurityFromConfigValues constructs a snapshot from the loose-typed values
// that the YAML config layer hands the daemon. It exists so seed callers
// avoid importing the internal/config package (avoids an import cycle); the
// helper applies the same defaults config.setDefaults() would.
func SecurityFromConfigValues(v SecurityYAMLView) *SecuritySnapshot {
	// ⭐ 这个函数因为指针化**变短也变直白了**:`SecurityYAMLView` 的五个 *bool
	// 以前要「解引用再存进裸值」(`s.X = *v.X`),那一行正是「没写」这个信息在这一层
	// 被丢掉的地方 —— 现在指针直接传下去,信息不再损失。
	//
	// ⚠️ 数值字段仍然是 `> 0 才覆盖`,语义没变:YAMLView 那几个是裸值,分不出
	// 「没写」和「写了 0」。⛔ 那是 YAML 层自己的限制,不是这里能修的 ——
	// 要修得先把 config.SecurityConfig 的数值字段也指针化,那是另一步。
	s := DefaultSecurity()
	if v.MaxRequestAge > 0 {
		s.MaxRequestAge = Ptr(v.MaxRequestAge)
	}
	if v.RateLimitDefault > 0 {
		s.RateLimitDefault = Ptr(v.RateLimitDefault)
	}
	if v.IPRateLimit > 0 {
		s.IPRateLimit = Ptr(v.IPRateLimit)
	}
	s.IPWhitelist = &IPWhitelist{
		Enabled:        v.IPWhitelistEnabled,
		AllowedIPs:     v.IPWhitelistAllowedIPs,
		TrustProxy:     v.IPWhitelistTrustProxy,
		TrustedProxies: v.IPWhitelistTrustedProxies,
	}
	s.ManualApprovalEnabled = Ptr(v.ManualApprovalEnabled)
	if v.ApprovalGuardEnabled {
		s.ApprovalGuard = &ApprovalGuard{
			Enabled:               true,
			Window:                fallbackDuration(v.ApprovalGuardWindow, time.Hour),
			RejectionThresholdPct: fallbackFloat(v.ApprovalGuardRejectionPct, 50),
			MinSamples:            fallbackInt(v.ApprovalGuardMinSamples, 10),
			ResumeAfter:           fallbackDuration(v.ApprovalGuardResumeAfter, 2*time.Hour),
		}
	}
	// 五个 *bool:直接传指针,nil 时保留 DefaultSecurity 给的值。
	if v.NonceRequired != nil {
		s.NonceRequired = v.NonceRequired
	}
	if v.RulesAPIReadonly != nil {
		s.RulesAPIReadonly = v.RulesAPIReadonly
	}
	if v.SignersAPIReadonly != nil {
		s.SignersAPIReadonly = v.SignersAPIReadonly
	}
	if v.APIKeysAPIReadonly != nil {
		s.APIKeysAPIReadonly = v.APIKeysAPIReadonly
	}
	if v.AllowSIGHUPRulesReload != nil {
		s.AllowSIGHUPRulesReload = v.AllowSIGHUPRulesReload
	}
	if v.MaxRulesPerAPIKey > 0 {
		s.MaxRulesPerAPIKey = Ptr(v.MaxRulesPerAPIKey)
	}
	if v.RequireApprovalForAgentRules != nil {
		s.RequireApprovalForAgentRules = v.RequireApprovalForAgentRules
	}
	if v.AutoLockTimeout > 0 {
		s.AutoLockTimeout = Ptr(v.AutoLockTimeout)
	}
	if v.SignTimeout > 0 {
		s.SignTimeout = Ptr(v.SignTimeout)
	}
	if v.MaxKeystoresPerKey > 0 {
		s.MaxKeystoresPerKey = Ptr(v.MaxKeystoresPerKey)
	}
	if v.MaxHDWalletsPerKey > 0 {
		s.MaxHDWalletsPerKey = Ptr(v.MaxHDWalletsPerKey)
	}
	return s
}

// SecurityYAMLView is the loose-typed shape callers pass into
// SecurityFromConfigValues. Pointer fields preserve "unset" vs "false" so the
// helper can fall back to secure-by-default values when YAML omits a knob.
type SecurityYAMLView struct {
	MaxRequestAge                time.Duration
	RateLimitDefault             int
	IPRateLimit                  int
	IPWhitelistEnabled           bool
	IPWhitelistAllowedIPs        []string
	IPWhitelistTrustProxy        bool
	IPWhitelistTrustedProxies    []string
	ManualApprovalEnabled        bool
	ApprovalGuardEnabled         bool
	ApprovalGuardWindow          time.Duration
	ApprovalGuardRejectionPct    float64
	ApprovalGuardMinSamples      int
	ApprovalGuardResumeAfter     time.Duration
	NonceRequired                *bool
	RulesAPIReadonly             *bool
	SignersAPIReadonly           *bool
	APIKeysAPIReadonly           *bool
	AllowSIGHUPRulesReload       *bool
	MaxRulesPerAPIKey            int
	RequireApprovalForAgentRules *bool
	AutoLockTimeout              time.Duration
	SignTimeout                  time.Duration
	MaxKeystoresPerKey           int
	MaxHDWalletsPerKey           int
}

func fallbackDuration(v, def time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return def
}

func fallbackInt(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

func fallbackFloat(v, def float64) float64 {
	if v > 0 {
		return v
	}
	return def
}
