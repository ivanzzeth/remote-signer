package server

import (
	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/settings"
)

// applySecuritySnapshot copies every security field from the settings snapshot
// back into cfg.Security so downstream code that already reads cfg.Security.X
// transparently picks up the DB-backed values. After PR7b this is the only
// place security values cross the snapshot → config boundary; PR7e/g remove
// SecurityConfig from the YAML schema entirely and the rest of the daemon
// switches to mgr.Security() directly.
func applySecuritySnapshot(cfg *config.Config, s *settings.SecuritySnapshot) {
	cfg.Security.MaxRequestAge = s.MaxRequestAge
	cfg.Security.RateLimitDefault = s.RateLimitDefault
	cfg.Security.IPRateLimit = s.IPRateLimit
	cfg.Security.IPWhitelist = config.IPWhitelistConfig{
		Enabled:        s.IPWhitelist.Enabled,
		AllowedIPs:     append([]string(nil), s.IPWhitelist.AllowedIPs...),
		TrustProxy:     s.IPWhitelist.TrustProxy,
		TrustedProxies: append([]string(nil), s.IPWhitelist.TrustedProxies...),
	}
	cfg.Security.ManualApprovalEnabled = s.ManualApprovalEnabled
	cfg.Security.ApprovalGuard = config.ApprovalGuardConfig{
		Enabled:               s.ApprovalGuard.Enabled,
		Window:                s.ApprovalGuard.Window,
		RejectionThresholdPct: s.ApprovalGuard.RejectionThresholdPct,
		MinSamples:            s.ApprovalGuard.MinSamples,
		ResumeAfter:           s.ApprovalGuard.ResumeAfter,
	}
	nonce := s.NonceRequired
	cfg.Security.NonceRequired = &nonce
	rulesRO := s.RulesAPIReadonly
	cfg.Security.RulesAPIReadonly = &rulesRO
	signersRO := s.SignersAPIReadonly
	cfg.Security.SignersAPIReadonly = &signersRO
	apiKeysRO := s.APIKeysAPIReadonly
	cfg.Security.APIKeysAPIReadonly = &apiKeysRO
	sighup := s.AllowSIGHUPRulesReload
	cfg.Security.AllowSIGHUPRulesReload = &sighup
	cfg.Security.MaxRulesPerAPIKey = s.MaxRulesPerAPIKey
	agentApprov := s.RequireApprovalForAgentRules
	cfg.Security.RequireApprovalForAgentRules = &agentApprov
	cfg.Security.AutoLockTimeout = s.AutoLockTimeout
	cfg.Security.SignTimeout = s.SignTimeout
	cfg.Security.MaxKeystoresPerKey = s.MaxKeystoresPerKey
	cfg.Security.MaxHDWalletsPerKey = s.MaxHDWalletsPerKey
}

// securityYAMLView lifts the security-related fields out of the loaded
// config.Config into the loose-typed view the settings seed helper accepts.
// Kept in its own file so future PRs that prune SecurityConfig down to the
// fields actually still living in YAML have one place to update.
// SecurityYAMLViewFromConfig maps config.Config's security block onto the
// settings package's config-free view.
//
// Exported because the e2e harness must seed settings exactly the way the
// daemon does. It used to seed nothing, and the divergence was invisible until
// it wasn't: handleGuardResume gates on the runtime settings snapshot while the
// guard itself is constructed from cfg.Security, so with no SettingsManager the
// e2e server built a working guard whose endpoint answered 501 — one of the
// two sources said enabled, the other did not exist.
//
// ⚠️ Keep this the only config→SecurityYAMLView mapping. internal/settings
// deliberately does not import internal/config (see seed.go), which is why the
// view type exists at all; a second copy of the field list here would drift
// silently, since a field simply missing from the mapping reads as its zero
// value and nothing reports it.
func SecurityYAMLViewFromConfig(cfg *config.Config) settings.SecurityYAMLView {
	return securityYAMLView(cfg)
}

func securityYAMLView(cfg *config.Config) settings.SecurityYAMLView {
	sec := cfg.Security
	return settings.SecurityYAMLView{
		MaxRequestAge:                sec.MaxRequestAge,
		RateLimitDefault:             sec.RateLimitDefault,
		IPRateLimit:                  sec.IPRateLimit,
		IPWhitelistEnabled:           sec.IPWhitelist.Enabled,
		IPWhitelistAllowedIPs:        sec.IPWhitelist.AllowedIPs,
		IPWhitelistTrustProxy:        sec.IPWhitelist.TrustProxy,
		IPWhitelistTrustedProxies:    sec.IPWhitelist.TrustedProxies,
		ManualApprovalEnabled:        sec.ManualApprovalEnabled,
		ApprovalGuardEnabled:         sec.ApprovalGuard.Enabled,
		ApprovalGuardWindow:          sec.ApprovalGuard.Window,
		ApprovalGuardRejectionPct:    sec.ApprovalGuard.RejectionThresholdPct,
		ApprovalGuardMinSamples:      sec.ApprovalGuard.MinSamples,
		ApprovalGuardResumeAfter:     sec.ApprovalGuard.ResumeAfter,
		NonceRequired:                sec.NonceRequired,
		RulesAPIReadonly:             sec.RulesAPIReadonly,
		SignersAPIReadonly:           sec.SignersAPIReadonly,
		APIKeysAPIReadonly:           sec.APIKeysAPIReadonly,
		AllowSIGHUPRulesReload:       sec.AllowSIGHUPRulesReload,
		MaxRulesPerAPIKey:            sec.MaxRulesPerAPIKey,
		RequireApprovalForAgentRules: sec.RequireApprovalForAgentRules,
		AutoLockTimeout:              sec.AutoLockTimeout,
		SignTimeout:                  sec.SignTimeout,
		MaxKeystoresPerKey:           sec.MaxKeystoresPerKey,
		MaxHDWalletsPerKey:           sec.MaxHDWalletsPerKey,
	}
}
