// Package server provides the daemon entrypoint for `remote-signer server start`.
// Run is the entrypoint; cmd/remote-signer wires it as a cobra subcommand.
package server

import (
	"context"
	"log/slog"

	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/config"
)

// reloadRules re-reads config and syncs rules to DB (triggered by SIGHUP).
// Rule engine reads from DB per-request, so no engine restart is needed.
func reloadRules(configPath string, ruleInit *config.RuleInitializer, templateInit *config.TemplateInitializer, auditLogger *audit.AuditLogger, log *slog.Logger) {
	ctx := context.Background()

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Error("SIGHUP: failed to reload config", "error", err)
		if auditLogger != nil {
			auditLogger.LogConfigReloaded(ctx, false, err.Error())
		}
		return
	}

	// Re-expand template instance rules
	loadedTemplates, err := templateInit.GetLoadedTemplates(cfg.Templates)
	if err != nil {
		log.Error("SIGHUP: failed to get loaded templates", "error", err)
		if auditLogger != nil {
			auditLogger.LogConfigReloaded(ctx, false, err.Error())
		}
		return
	}
	expandedRules, err := config.ExpandInstanceRules(cfg.Rules, loadedTemplates)
	if err != nil {
		log.Error("SIGHUP: failed to expand instance rules", "error", err)
		if auditLogger != nil {
			auditLogger.LogConfigReloaded(ctx, false, err.Error())
		}
		return
	}

	if err := ruleInit.SyncFromConfig(ctx, expandedRules); err != nil {
		log.Error("SIGHUP: failed to sync rules from config", "error", err)
		if auditLogger != nil {
			auditLogger.LogConfigReloaded(ctx, false, err.Error())
		}
		return
	}

	if auditLogger != nil {
		auditLogger.LogConfigReloaded(ctx, true, "")
	}
	log.Info("SIGHUP: rules reloaded successfully")
}
