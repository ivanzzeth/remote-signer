// Package server provides the daemon entrypoint for `remote-signer server start`.
// run_settings.go seeds runtime-mutable system_settings from config.yaml and returns
// the Manager that keeps the in-memory snapshot synchronised with the DB.
package server

import (
	"context"
	"fmt"
	"log/slog"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/settings"
)

// initSettingsStore creates the runtime-mutable settings store, seeds initial
// values from config.yaml, and returns a manager ready for the Reload() call.
func initSettingsStore(db *gorm.DB, cfg *config.Config, log *slog.Logger) (*settings.Manager, error) {
	ctx := context.Background()

	settingsStore, err := settings.NewGormStore(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create settings store: %w", err)
	}

	yamlSecurity := securityYAMLView(cfg)
	seedSnapshot := settings.SecurityFromConfigValues(yamlSecurity)
	if err := settings.SeedSecurity(ctx, settingsStore, seedSnapshot); err != nil {
		return nil, fmt.Errorf("failed to seed security settings: %w", err)
	}
	if err := settings.SeedNotify(ctx, settingsStore, notifyYAMLToSnapshot(&cfg.Notify, &cfg.NotifyChannel)); err != nil {
		return nil, fmt.Errorf("failed to seed notify settings: %w", err)
	}
	if err := settings.SeedAuditMonitor(ctx, settingsStore, auditMonitorToSnapshot(cfg.AuditMonitor)); err != nil {
		return nil, fmt.Errorf("failed to seed audit_monitor settings: %w", err)
	}
	if err := settings.SeedWeb(ctx, settingsStore, settings.DefaultWeb()); err != nil {
		return nil, fmt.Errorf("failed to seed web settings: %w", err)
	}
	if err := settings.SeedBlocklist(ctx, settingsStore, blocklistToSnapshot(cfg.DynamicBlocklist)); err != nil {
		return nil, fmt.Errorf("failed to seed blocklist settings: %w", err)
	}
	if cfg.Chains.EVM != nil {
		if err := settings.SeedFoundry(ctx, settingsStore, foundryToSnapshot(cfg.Chains.EVM.Foundry)); err != nil {
			return nil, fmt.Errorf("failed to seed foundry settings: %w", err)
		}
		if err := settings.SeedSimulation(ctx, settingsStore, simulationToSnapshot(cfg.Chains.EVM.Simulation)); err != nil {
			return nil, fmt.Errorf("failed to seed simulation settings: %w", err)
		}
		if err := settings.SeedRPCGateway(ctx, settingsStore, rpcGatewayToSnapshot(cfg.Chains.EVM.RPCGateway)); err != nil {
			return nil, fmt.Errorf("failed to seed rpc_gateway settings: %w", err)
		}
		if err := settings.SeedMaterialCheck(ctx, settingsStore, materialCheckToSnapshot(cfg.Chains.EVM.MaterialCheck)); err != nil {
			return nil, fmt.Errorf("failed to seed material_check settings: %w", err)
		}
	}

	settingsMgr := settings.NewManager(settingsStore, log)
	if err := settingsMgr.Reload(ctx); err != nil {
		return nil, fmt.Errorf("failed to load settings: %w", err)
	}

	// Overlay DB-backed snapshots back onto cfg so downstream code picks them up.
	applySecuritySnapshot(cfg, settingsMgr.Security())
	applyNotifySnapshot(&cfg.Notify, &cfg.NotifyChannel, settingsMgr.Notify())
	applyAuditMonitorSnapshot(cfg, settingsMgr.AuditMonitor())
	applyBlocklistSnapshot(cfg, settingsMgr.Blocklist())
	applyEVMSnapshots(cfg, settingsMgr.Foundry(), settingsMgr.Simulation(), settingsMgr.RPCGateway(), settingsMgr.MaterialCheck())

	return settingsMgr, nil
}
