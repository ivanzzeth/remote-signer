package server

import (
	"time"

	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/settings"
)

// foundryToSnapshot lifts cfg.Chains.EVM.Foundry into the settings snapshot.
func foundryToSnapshot(f config.FoundryConfig) *settings.FoundrySnapshot {
	return &settings.FoundrySnapshot{
		Enabled:   f.FoundryEnabled(),
		ForgePath: f.ForgePath,
		CacheDir:  f.CacheDir,
		TempDir:   f.TempDir,
		Timeout:   f.Timeout,
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
		Enabled:              s.Enabled,
		Timeout:              s.Timeout,
		BatchWindow:          s.BatchWindow,
		BatchMaxSize:         s.BatchMaxSize,
		AutoCreateBudget:     true,
		MaxDynamicUnits:      100,
		BudgetNativeMaxTotal: s.BudgetNativeMaxTotal,
		BudgetNativeMaxPerTx: s.BudgetNativeMaxPerTx,
		BudgetERC20MaxTotal:  s.BudgetERC20MaxTotal,
		BudgetERC20MaxPerTx:  s.BudgetERC20MaxPerTx,
	}
}

// rpcGatewayToSnapshot lifts cfg.Chains.EVM.RPCGateway into the snapshot.
func rpcGatewayToSnapshot(g evm.RPCGatewayConfig) *settings.RPCGatewaySnapshot {
	return &settings.RPCGatewaySnapshot{
		BaseURL:  g.BaseURL,
		APIKey:   g.APIKey,
		CacheTTL: g.CacheTTL,
	}
}

// materialCheckToSnapshot lifts cfg.Chains.EVM.MaterialCheck into the snapshot.
func materialCheckToSnapshot(m config.SignerMaterialCheckConfig) *settings.MaterialCheckSnapshot {
	return &settings.MaterialCheckSnapshot{
		Enabled:      m.Enabled,
		StartupCheck: m.StartupCheck,
		Interval:     m.Interval,
	}
}

// blocklistToSnapshot lifts cfg.DynamicBlocklist into the snapshot (string
// sync_interval kept verbatim; consumers parse on use).
func blocklistToSnapshot(b *config.DynamicBlocklistConfig) *settings.BlocklistSnapshot {
	if b == nil {
		return &settings.BlocklistSnapshot{}
	}
	out := &settings.BlocklistSnapshot{
		Enabled:      b.Enabled,
		SyncInterval: b.SyncInterval,
		FailMode:     b.FailMode,
		CacheFile:    b.CacheFile,
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
		Enabled:                  m.Enabled,
		Interval:                 m.Interval,
		LookbackHours:            m.LookbackHours,
		AuthFailureThreshold:     m.AuthFailureThreshold,
		BlocklistRejectThreshold: m.BlocklistRejectThreshold,
		HighFreqThreshold:        m.HighFreqThreshold,
		RetentionDays:            m.RetentionDays,
		CleanupInterval:          m.CleanupInterval,
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
		enabled := foundry.Enabled
		cfg.Chains.EVM.Foundry = config.FoundryConfig{
			Enabled:   &enabled,
			ForgePath: foundry.ForgePath,
			CacheDir:  foundry.CacheDir,
			TempDir:   foundry.TempDir,
			Timeout:   foundry.Timeout,
		}
	}
	if simulation != nil {
		cfg.Chains.EVM.Simulation = config.SimulationConfig{
			Enabled:              simulation.Enabled,
			Timeout:              simulation.Timeout,
			BatchWindow:          simulation.BatchWindow,
			BatchMaxSize:         simulation.BatchMaxSize,
			BudgetNativeMaxTotal: simulation.BudgetNativeMaxTotal,
			BudgetNativeMaxPerTx: simulation.BudgetNativeMaxPerTx,
			BudgetERC20MaxTotal:  simulation.BudgetERC20MaxTotal,
			BudgetERC20MaxPerTx:  simulation.BudgetERC20MaxPerTx,
		}
	}
	if rpcGateway != nil {
		cfg.Chains.EVM.RPCGateway = evm.RPCGatewayConfig{
			BaseURL:  rpcGateway.BaseURL,
			APIKey:   rpcGateway.APIKey,
			CacheTTL: rpcGateway.CacheTTL,
		}
	}
	if materialCheck != nil {
		cfg.Chains.EVM.MaterialCheck = config.SignerMaterialCheckConfig{
			Enabled:      materialCheck.Enabled,
			StartupCheck: materialCheck.StartupCheck,
			Interval:     materialCheck.Interval,
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
	cfg.DynamicBlocklist.Enabled = s.Enabled
	cfg.DynamicBlocklist.SyncInterval = s.SyncInterval
	cfg.DynamicBlocklist.FailMode = s.FailMode
	cfg.DynamicBlocklist.CacheFile = s.CacheFile
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
		Enabled:                  s.Enabled,
		Interval:                 s.Interval,
		LookbackHours:            s.LookbackHours,
		AuthFailureThreshold:     s.AuthFailureThreshold,
		BlocklistRejectThreshold: s.BlocklistRejectThreshold,
		HighFreqThreshold:        s.HighFreqThreshold,
		RetentionDays:            s.RetentionDays,
		CleanupInterval:          s.CleanupInterval,
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
