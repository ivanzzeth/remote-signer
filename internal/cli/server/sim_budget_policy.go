package server

import (
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/settings"
)

// settingsSimBudgetPolicy adapts the runtime-mutable simulation snapshot
// to the evm.SimBudgetPolicy interface that SimulationBudgetRule polls
// on every auto-create attempt. Holding a *settings.Manager (not a
// captured snapshot) is intentional: admin flips of auto_create_budget
// take effect on the next sign request without restarting the daemon,
// since Manager.Simulation() reads an atomic pointer that the refresh
// loop swaps as DB writes land.
//
// The adapter is keyed at the cli/server package so chain/evm doesn't
// take a settings import — keeps the chain package free of operator-
// runtime concerns.
type settingsSimBudgetPolicy struct {
	mgr *settings.Manager
}

// AutoCreate returns false when the manager is unavailable so the rule
// fails closed (no synthetic budget rows written) rather than silently
// creating with whatever the defaults happen to be.
func (p *settingsSimBudgetPolicy) AutoCreate() bool {
	if p == nil || p.mgr == nil {
		return false
	}
	s := p.mgr.Simulation()
	if s == nil {
		return false
	}
	// ⛔ 兜底必须是 false,与上面 `p.mgr == nil` 那条分支同一个理由(见函数注释):
	// 读不到配置时**不**写合成预算行,而不是按某个默认值去写。
	return settings.Deref(s.AutoCreateBudget, false)
}

// Defaults projects the snapshot's budget fields into the shape the
// rule wants. Returns nil when the manager is unavailable; the rule
// treats nil as "no defaults configured" and short-circuits.
func (p *settingsSimBudgetPolicy) Defaults() *evm.SimBudgetDefaults {
	if p == nil || p.mgr == nil {
		return nil
	}
	s := p.mgr.Simulation()
	if s == nil {
		return nil
	}
	return &evm.SimBudgetDefaults{
		NativeMaxTotal:  settings.Deref(s.BudgetNativeMaxTotal, ""),
		NativeMaxPerTx:  settings.Deref(s.BudgetNativeMaxPerTx, ""),
		ERC20MaxTotal:   settings.Deref(s.BudgetERC20MaxTotal, ""),
		ERC20MaxPerTx:   settings.Deref(s.BudgetERC20MaxPerTx, ""),
		MaxDynamicUnits: settings.Deref(s.MaxDynamicUnits, 0),
	}
}
