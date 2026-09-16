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
// ⭐ 指针化(2026-09-16)之后这个函数两头的类型终于对上了:六个 `*bool` 以前要
// 「先把 snapshot 的裸 bool 复制进局部变量,再取地址」才能塞进 cfg 的 `*bool`,
// 现在直接传指针。⚠️ 那六行局部变量不是风格问题 —— 它们是把「没写」这个信息
// 补回来的徒劳尝试:信息在 snapshot 那一层就已经丢了,取地址取到的只是一个
// 必然非 nil 的 false。
//
// ⚠️ 数值与 duration 仍要 Deref:cfg.Security 那几个是裸值,接不住 nil。
// 兜底值全部取 Go 零值,与指针化之前「snapshot 裸字段的零值」逐字节等价 ——
// ⛔ 这里不是挑默认值的地方,默认值只有一个出处:settings.DefaultSecurity()。
func applySecuritySnapshot(cfg *config.Config, s *settings.SecuritySnapshot) {
	cfg.Security.MaxRequestAge = settings.Deref(s.MaxRequestAge, 0)
	cfg.Security.RateLimitDefault = settings.Deref(s.RateLimitDefault, 0)
	cfg.Security.IPRateLimit = settings.Deref(s.IPRateLimit, 0)
	wl := s.Whitelist()
	cfg.Security.IPWhitelist = config.IPWhitelistConfig{
		Enabled:        wl.Enabled,
		AllowedIPs:     append([]string(nil), wl.AllowedIPs...),
		TrustProxy:     wl.TrustProxy,
		TrustedProxies: append([]string(nil), wl.TrustedProxies...),
	}
	cfg.Security.ManualApprovalEnabled = settings.Deref(s.ManualApprovalEnabled, false)
	ag := s.Guard()
	cfg.Security.ApprovalGuard = config.ApprovalGuardConfig{
		Enabled:               ag.Enabled,
		Window:                ag.Window,
		RejectionThresholdPct: ag.RejectionThresholdPct,
		MinSamples:            ag.MinSamples,
		ResumeAfter:           ag.ResumeAfter,
	}
	cfg.Security.NonceRequired = s.NonceRequired
	cfg.Security.RulesAPIReadonly = s.RulesAPIReadonly
	cfg.Security.SignersAPIReadonly = s.SignersAPIReadonly
	cfg.Security.APIKeysAPIReadonly = s.APIKeysAPIReadonly
	cfg.Security.AllowSIGHUPRulesReload = s.AllowSIGHUPRulesReload
	cfg.Security.MaxRulesPerAPIKey = settings.Deref(s.MaxRulesPerAPIKey, 0)
	cfg.Security.RequireApprovalForAgentRules = s.RequireApprovalForAgentRules
	cfg.Security.AutoLockTimeout = settings.Deref(s.AutoLockTimeout, 0)
	cfg.Security.SignTimeout = settings.Deref(s.SignTimeout, 0)
	cfg.Security.MaxKeystoresPerKey = settings.Deref(s.MaxKeystoresPerKey, 0)
	cfg.Security.MaxHDWalletsPerKey = settings.Deref(s.MaxHDWalletsPerKey, 0)
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
