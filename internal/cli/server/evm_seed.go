package server

import (
	"time"

	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/settings"
)

// ---------------------------------------------------------------------------
// 两个方向,别混:
//
//	XxxToSnapshot   YAML/config → snapshot。**启动时播种**,给出的是一份完整快照,
//	                所以每个字段都 Ptr() —— 它们都是「明确说过的值」。
//	applyXxx        snapshot → cfg。读取侧,用 Deref 兜到**零值**。
//
// ⚠️ 兜底一律取 Go 零值,与这一组指针化之前的裸字段逐字节等价(那时读到的就是
// 零值)。⛔ 这里不是挑默认值的地方:这七组没有 DefaultXxx(),它们的出厂默认
// 本来就是零值,而 Web 那组的默认值只有 settings.DefaultWeb() 一个出处。
// ---------------------------------------------------------------------------

// foundryToSnapshot lifts cfg.Chains.EVM.Foundry into the settings snapshot.
func foundryToSnapshot(f config.FoundryConfig) *settings.FoundrySnapshot {
	return &settings.FoundrySnapshot{
		Enabled:   settings.Ptr(f.FoundryEnabled()),
		ForgePath: settings.Ptr(f.ForgePath),
		CacheDir:  settings.Ptr(f.CacheDir),
		TempDir:   settings.Ptr(f.TempDir),
		Timeout:   settings.Ptr(f.Timeout),
	}
}

// simulationToSnapshot lifts cfg.Chains.EVM.Simulation into the snapshot.
// AutoCreateBudget defaults to true here so a fresh install behaves the
// way the simulation engine has always behaved — auto-track unknown
// (signer, token) outflows. Admin can flip it off via Settings once
// they want to stop accumulating sim:* rows. MaxDynamicUnits has no
// YAML counterpart; default 100 matches the constant the rule code
// uses as a hard fallback.
func simulationToSnapshot(s config.SimulationConfig) *settings.SimulationSnapshot {
	return &settings.SimulationSnapshot{
		Enabled:              settings.Ptr(s.Enabled),
		Timeout:              settings.Ptr(s.Timeout),
		BatchWindow:          settings.Ptr(s.BatchWindow),
		BatchMaxSize:         settings.Ptr(s.BatchMaxSize),
		AutoCreateBudget:     settings.Ptr(true),
		MaxDynamicUnits:      settings.Ptr(100),
		BudgetNativeMaxTotal: settings.Ptr(s.BudgetNativeMaxTotal),
		BudgetNativeMaxPerTx: settings.Ptr(s.BudgetNativeMaxPerTx),
		BudgetERC20MaxTotal:  settings.Ptr(s.BudgetERC20MaxTotal),
		BudgetERC20MaxPerTx:  settings.Ptr(s.BudgetERC20MaxPerTx),
	}
}

// rpcGatewayToSnapshot lifts cfg.Chains.EVM.RPCGateway into the snapshot.
func rpcGatewayToSnapshot(g evm.RPCGatewayConfig) *settings.RPCGatewaySnapshot {
	return &settings.RPCGatewaySnapshot{
		BaseURL:  settings.Ptr(g.BaseURL),
		APIKey:   settings.Ptr(g.APIKey),
		CacheTTL: settings.Ptr(g.CacheTTL),
	}
}

// materialCheckToSnapshot lifts cfg.Chains.EVM.MaterialCheck into the snapshot.
func materialCheckToSnapshot(m config.SignerMaterialCheckConfig) *settings.MaterialCheckSnapshot {
	return &settings.MaterialCheckSnapshot{
		Enabled:      settings.Ptr(m.Enabled),
		StartupCheck: settings.Ptr(m.StartupCheck),
		Interval:     settings.Ptr(m.Interval),
	}
}

// blocklistToSnapshot lifts cfg.DynamicBlocklist into the snapshot (string
// sync_interval kept verbatim; consumers parse on use).
//
// ⚠️ b == nil 时返回**全 nil** 的空快照,而不是一份「填了零值」的快照:YAML 里
// 整块缺席就是「没配过」,那正是 nil 要表达的东西。
func blocklistToSnapshot(b *config.DynamicBlocklistConfig) *settings.BlocklistSnapshot {
	if b == nil {
		return &settings.BlocklistSnapshot{}
	}
	out := &settings.BlocklistSnapshot{
		Enabled:      settings.Ptr(b.Enabled),
		SyncInterval: settings.Ptr(b.SyncInterval),
		FailMode:     settings.Ptr(b.FailMode),
		CacheFile:    settings.Ptr(b.CacheFile),
	}
	for _, src := range b.Sources {
		out.Sources = append(out.Sources, settings.BlocklistEntry{
			Name:     src.Name,
			Type:     src.Type,
			URL:      src.URL,
			JSONPath: src.JSONPath,
		})
	}
	return out
}

// auditMonitorToSnapshot lifts cfg.AuditMonitor into the snapshot.
func auditMonitorToSnapshot(m audit.MonitorConfig) *settings.AuditMonitorSnapshot {
	return &settings.AuditMonitorSnapshot{
		Enabled:                  settings.Ptr(m.Enabled),
		Interval:                 settings.Ptr(m.Interval),
		LookbackHours:            settings.Ptr(m.LookbackHours),
		AuthFailureThreshold:     settings.Ptr(m.AuthFailureThreshold),
		BlocklistRejectThreshold: settings.Ptr(m.BlocklistRejectThreshold),
		HighFreqThreshold:        settings.Ptr(m.HighFreqThreshold),
		RetentionDays:            settings.Ptr(m.RetentionDays),
		CleanupInterval:          settings.Ptr(m.CleanupInterval),
	}
}

// applyEVMSnapshots overlays the foundry/simulation/rpcGateway/materialCheck
// snapshots back onto cfg.Chains.EVM so existing readers (Solidity evaluator,
// simulator, signer manager, JS RPC gateway) pick up DB values.
func applyEVMSnapshots(cfg *config.Config,
	foundry *settings.FoundrySnapshot,
	simulation *settings.SimulationSnapshot,
	rpcGateway *settings.RPCGatewaySnapshot,
	materialCheck *settings.MaterialCheckSnapshot,
) {
	if cfg.Chains.EVM == nil {
		return
	}
	if foundry != nil {
		cfg.Chains.EVM.Foundry = config.FoundryConfig{
			// ⭐ 两边都是 *bool,直接传。指针化之前这里要
			// `enabled := foundry.Enabled` 再取地址 —— 那两行是在给一个
			// 已经丢了「没写」信息的裸 bool 重新造一个必然非 nil 的指针。
			Enabled:   foundry.Enabled,
			ForgePath: settings.Deref(foundry.ForgePath, ""),
			CacheDir:  settings.Deref(foundry.CacheDir, ""),
			TempDir:   settings.Deref(foundry.TempDir, ""),
			Timeout:   settings.Deref(foundry.Timeout, 0),
		}
	}
	if simulation != nil {
		cfg.Chains.EVM.Simulation = config.SimulationConfig{
			Enabled:              settings.Deref(simulation.Enabled, false),
			Timeout:              settings.Deref(simulation.Timeout, 0),
			BatchWindow:          settings.Deref(simulation.BatchWindow, 0),
			BatchMaxSize:         settings.Deref(simulation.BatchMaxSize, 0),
			BudgetNativeMaxTotal: settings.Deref(simulation.BudgetNativeMaxTotal, ""),
			BudgetNativeMaxPerTx: settings.Deref(simulation.BudgetNativeMaxPerTx, ""),
			BudgetERC20MaxTotal:  settings.Deref(simulation.BudgetERC20MaxTotal, ""),
			BudgetERC20MaxPerTx:  settings.Deref(simulation.BudgetERC20MaxPerTx, ""),
		}
	}
	if rpcGateway != nil {
		cfg.Chains.EVM.RPCGateway = evm.RPCGatewayConfig{
			BaseURL:  settings.Deref(rpcGateway.BaseURL, ""),
			APIKey:   settings.Deref(rpcGateway.APIKey, ""),
			CacheTTL: settings.Deref(rpcGateway.CacheTTL, 0),
		}
	}
	if materialCheck != nil {
		cfg.Chains.EVM.MaterialCheck = config.SignerMaterialCheckConfig{
			Enabled:      settings.Deref(materialCheck.Enabled, false),
			StartupCheck: settings.Deref(materialCheck.StartupCheck, false),
			Interval:     settings.Deref(materialCheck.Interval, 0),
		}
	}
}

// applyBlocklistSnapshot overlays the snapshot back onto cfg.DynamicBlocklist.
// cfg.DynamicBlocklist may be nil when the YAML omits the block; create the
// pointer here so an admin can enable the blocklist purely through the API.
func applyBlocklistSnapshot(cfg *config.Config, s *settings.BlocklistSnapshot) {
	if s == nil {
		return
	}
	if cfg.DynamicBlocklist == nil {
		cfg.DynamicBlocklist = &config.DynamicBlocklistConfig{}
	}
	cfg.DynamicBlocklist.Enabled = settings.Deref(s.Enabled, false)
	cfg.DynamicBlocklist.SyncInterval = settings.Deref(s.SyncInterval, "")
	cfg.DynamicBlocklist.FailMode = settings.Deref(s.FailMode, "")
	cfg.DynamicBlocklist.CacheFile = settings.Deref(s.CacheFile, "")
	cfg.DynamicBlocklist.Sources = nil
	for _, e := range s.Sources {
		cfg.DynamicBlocklist.Sources = append(cfg.DynamicBlocklist.Sources, config.DynamicBlocklistSource{
			Name:     e.Name,
			Type:     e.Type,
			URL:      e.URL,
			JSONPath: e.JSONPath,
		})
	}
}

// applyAuditMonitorSnapshot overlays the snapshot back onto cfg.AuditMonitor.
func applyAuditMonitorSnapshot(cfg *config.Config, s *settings.AuditMonitorSnapshot) {
	if s == nil {
		return
	}
	cfg.AuditMonitor = audit.MonitorConfig{
		Enabled:                  settings.Deref(s.Enabled, false),
		Interval:                 settings.Deref(s.Interval, 0),
		LookbackHours:            settings.Deref(s.LookbackHours, 0),
		AuthFailureThreshold:     settings.Deref(s.AuthFailureThreshold, 0),
		BlocklistRejectThreshold: settings.Deref(s.BlocklistRejectThreshold, 0),
		HighFreqThreshold:        settings.Deref(s.HighFreqThreshold, 0),
		RetentionDays:            settings.Deref(s.RetentionDays, 0),
		CleanupInterval:          settings.Deref(s.CleanupInterval, 0),
	}
}

// asInterval is a small helper for tests/callers that want a parsed
// time.Duration out of the YAML-style string field on BlocklistSnapshot.
func asInterval(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return def
	}
	return d
}
