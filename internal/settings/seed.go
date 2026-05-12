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
	_, err := store.Get(ctx, GroupSecurity)
	if err == nil {
		return nil // already seeded
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	mgr := &Manager{store: store, interval: DefaultRefreshInterval}
	return mgr.put(ctx, GroupSecurity, snapshot, UpdatedByBootstrap)
}

// SecurityFromConfigValues constructs a snapshot from the loose-typed values
// that the YAML config layer hands the daemon. It exists so seed callers
// avoid importing the internal/config package (avoids an import cycle); the
// helper applies the same defaults config.setDefaults() would.
func SecurityFromConfigValues(v SecurityYAMLView) *SecuritySnapshot {
	s := DefaultSecurity()
	if v.MaxRequestAge > 0 {
		s.MaxRequestAge = v.MaxRequestAge
	}
	if v.RateLimitDefault > 0 {
		s.RateLimitDefault = v.RateLimitDefault
	}
	if v.IPRateLimit > 0 {
		s.IPRateLimit = v.IPRateLimit
	}
	s.IPWhitelist = IPWhitelist{
		Enabled:        v.IPWhitelistEnabled,
		AllowedIPs:     v.IPWhitelistAllowedIPs,
		TrustProxy:     v.IPWhitelistTrustProxy,
		TrustedProxies: v.IPWhitelistTrustedProxies,
	}
	s.ManualApprovalEnabled = v.ManualApprovalEnabled
	if v.ApprovalGuardEnabled {
		s.ApprovalGuard = ApprovalGuard{
			Enabled:               true,
			Window:                fallbackDuration(v.ApprovalGuardWindow, time.Hour),
			RejectionThresholdPct: fallbackFloat(v.ApprovalGuardRejectionPct, 50),
			MinSamples:            fallbackInt(v.ApprovalGuardMinSamples, 10),
			ResumeAfter:           fallbackDuration(v.ApprovalGuardResumeAfter, 2*time.Hour),
		}
	}
	if v.NonceRequired != nil {
		s.NonceRequired = *v.NonceRequired
	}
	if v.RulesAPIReadonly != nil {
		s.RulesAPIReadonly = *v.RulesAPIReadonly
	}
	if v.SignersAPIReadonly != nil {
		s.SignersAPIReadonly = *v.SignersAPIReadonly
	}
	if v.APIKeysAPIReadonly != nil {
		s.APIKeysAPIReadonly = *v.APIKeysAPIReadonly
	}
	if v.AllowSIGHUPRulesReload != nil {
		s.AllowSIGHUPRulesReload = *v.AllowSIGHUPRulesReload
	}
	if v.MaxRulesPerAPIKey > 0 {
		s.MaxRulesPerAPIKey = v.MaxRulesPerAPIKey
	}
	if v.RequireApprovalForAgentRules != nil {
		s.RequireApprovalForAgentRules = *v.RequireApprovalForAgentRules
	}
	if v.AutoLockTimeout > 0 {
		s.AutoLockTimeout = v.AutoLockTimeout
	}
	if v.SignTimeout > 0 {
		s.SignTimeout = v.SignTimeout
	}
	if v.MaxKeystoresPerKey > 0 {
		s.MaxKeystoresPerKey = v.MaxKeystoresPerKey
	}
	if v.MaxHDWalletsPerKey > 0 {
		s.MaxHDWalletsPerKey = v.MaxHDWalletsPerKey
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
