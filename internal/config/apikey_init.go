package config

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// APIKeyInitializer handles syncing API keys from config to database
type APIKeyInitializer struct {
	repo        storage.APIKeyRepository
	logger      *slog.Logger
	auditLogger *audit.AuditLogger
}

// NewAPIKeyInitializer creates a new API key initializer
func NewAPIKeyInitializer(repo storage.APIKeyRepository, logger *slog.Logger) (*APIKeyInitializer, error) {
	if repo == nil {
		return nil, fmt.Errorf("API key repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &APIKeyInitializer{
		repo:   repo,
		logger: logger,
	}, nil
}

// SetAuditLogger sets the audit logger for recording config API key sync events.
func (i *APIKeyInitializer) SetAuditLogger(al *audit.AuditLogger) {
	i.auditLogger = al
}

// SyncFromConfig syncs API keys from config to database
// - Creates new keys that don't exist
// - Updates existing keys with new values from config
// - Deletes config-sourced keys that are no longer in config (preserves API-created keys)
func (i *APIKeyInitializer) SyncFromConfig(ctx context.Context, keys []APIKeyConfig) error {
	// Backward compatibility: set source='config' for any keys with empty source
	if err := i.backfillSource(ctx); err != nil {
		return fmt.Errorf("failed to backfill source: %w", err)
	}

	configIDs := make([]string, 0, len(keys))
	for _, keyCfg := range keys {
		if !keyCfg.Enabled {
			i.logger.Debug("Skipping disabled API key", "id", keyCfg.ID)
			continue
		}
		configIDs = append(configIDs, keyCfg.ID)
		if err := i.syncKey(ctx, keyCfg); err != nil {
			return fmt.Errorf("failed to sync API key %s: %w", keyCfg.ID, err)
		}
	}

	// Remove config-sourced keys that are no longer in config
	deleted, err := i.repo.DeleteBySourceExcluding(ctx, types.APIKeySourceConfig, configIDs)
	if err != nil {
		return fmt.Errorf("failed to clean stale config keys: %w", err)
	}
	if deleted > 0 {
		i.logger.Info("Removed stale config-sourced API keys", "count", deleted)
		if i.auditLogger != nil {
			i.auditLogger.LogAPIKeySynced(ctx, "cleanup", fmt.Sprintf("%d stale keys", deleted), "")
		}
	}

	i.logger.Info("API keys synced from config", "count", len(configIDs))
	return nil
}

func (i *APIKeyInitializer) backfillSource(ctx context.Context) error {
	count, err := i.repo.BackfillSource(ctx, types.APIKeySourceConfig)
	if err != nil {
		return err
	}
	if count > 0 {
		i.logger.Info("Backfilled source for existing API keys", "count", count)
	}
	return nil
}

func (i *APIKeyInitializer) syncKey(ctx context.Context, keyCfg APIKeyConfig) error {
	// Skip disabled keys without public key configured
	if !keyCfg.Enabled {
		i.logger.Debug("Skipping disabled API key", "id", keyCfg.ID)
		return nil
	}

	// Resolve public key (from hex or env var)
	publicKey, err := keyCfg.ResolvePublicKey()
	if err != nil {
		return err
	}

	// Check if key exists
	existing, err := i.repo.Get(ctx, keyCfg.ID)
	if err != nil && err != types.ErrNotFound {
		return fmt.Errorf("failed to check existing key: %w", err)
	}

	// Set default rate limit
	rateLimit := keyCfg.RateLimit
	if rateLimit <= 0 {
		rateLimit = 100
	}

	if existing == nil {
		// Create new key
		newKey := &types.APIKey{
			ID:           keyCfg.ID,
			Name:         keyCfg.Name,
			PublicKeyHex: publicKey,
			RateLimit:    rateLimit,
			Role:         types.APIKeyRole(keyCfg.Role),
			Enabled:      keyCfg.Enabled,
			Source:       types.APIKeySourceConfig,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		if err := i.repo.Create(ctx, newKey); err != nil {
			return fmt.Errorf("failed to create key: %w", err)
		}

		i.logger.Info("Created API key from config",
			"id", keyCfg.ID,
			"name", keyCfg.Name,
			"role", keyCfg.Role,
			"enabled", keyCfg.Enabled,
		)
		if i.auditLogger != nil {
			i.auditLogger.LogAPIKeySynced(ctx, "created", keyCfg.ID, keyCfg.Name)
		}
	} else {
		// Update existing key with config values
		existing.Name = keyCfg.Name
		existing.PublicKeyHex = publicKey
		existing.RateLimit = rateLimit
		existing.Role = types.APIKeyRole(keyCfg.Role)
		existing.Enabled = keyCfg.Enabled
		existing.Source = types.APIKeySourceConfig
		existing.UpdatedAt = time.Now()

		if err := i.repo.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update key: %w", err)
		}

		i.logger.Info("Updated API key from config",
			"id", keyCfg.ID,
			"name", keyCfg.Name,
			"role", keyCfg.Role,
			"enabled", keyCfg.Enabled,
		)
		if i.auditLogger != nil {
			i.auditLogger.LogAPIKeySynced(ctx, "updated", keyCfg.ID, keyCfg.Name)
		}
	}

	return nil
}
