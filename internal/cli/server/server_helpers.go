package server

import (
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/rs/zerolog"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/notify"
)

// absDirRelativeToConfig resolves a directory path that may be relative
// to the config file directory. Empty input yields empty output (the
// Registry treats that as "no source", returning an empty list).
func absDirRelativeToConfig(dir, configPath string) string {
	if dir == "" {
		return ""
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(filepath.Dir(configPath), dir)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return dir
	}
	return abs
}

func parseZerologLevel(level string) (zerolog.Level, error) {
	switch level {
	case "debug":
		return zerolog.DebugLevel, nil
	case "info":
		return zerolog.InfoLevel, nil
	case "warn":
		return zerolog.WarnLevel, nil
	case "error":
		return zerolog.ErrorLevel, nil
	default:
		return zerolog.InfoLevel, fmt.Errorf("unknown log level: %s", level)
	}
}

func parseSlogLevel(level string) (slog.Level, error) {
	switch level {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level: %s", level)
	}
}

func notifyEnabled(cfg *notify.Config) bool {
	if cfg == nil {
		return false
	}
	if cfg.Slack != nil && cfg.Slack.Enabled {
		return true
	}
	if cfg.Pushover != nil && cfg.Pushover.Enabled {
		return true
	}
	if cfg.Webhook != nil && cfg.Webhook.Enabled {
		return true
	}
	if cfg.Telegram != nil && cfg.Telegram.Enabled {
		return true
	}
	return false
}

// auditEventToAlertType maps audit event types to security alert types for admin operation alerts.
func auditEventToAlertType(eventType types.AuditEventType) middleware.SecurityAlertType {
	switch eventType {
	case types.AuditEventTypeSignerCreated:
		return middleware.AlertSignerCreated
	case types.AuditEventTypeSignerUnlocked:
		return middleware.AlertSignerUnlocked
	case types.AuditEventTypeSignerLocked:
		return middleware.AlertSignerLocked
	case types.AuditEventTypeSignerAutoLocked:
		return middleware.AlertSignerAutoLocked
	case types.AuditEventTypeHDWalletCreated:
		return middleware.AlertHDWalletCreated
	case types.AuditEventTypeHDWalletDerived:
		return middleware.AlertHDWalletDerived
	case types.AuditEventTypeRuleCreated:
		return middleware.AlertRuleCreated
	case types.AuditEventTypeRuleUpdated:
		return middleware.AlertRuleUpdated
	case types.AuditEventTypeRuleDeleted:
		return middleware.AlertRuleDeleted
	case types.AuditEventTypeConfigReloaded:
		return middleware.AlertConfigReloaded
	case types.AuditEventTypeTemplateSynced:
		return middleware.AlertTemplateSynced
	case types.AuditEventTypeAPIKeySynced:
		return middleware.AlertAPIKeySynced
	case types.AuditEventTypePresetApplied:
		return middleware.AlertPresetApplied
	default:
		return middleware.SecurityAlertType("admin_operation")
	}
}
