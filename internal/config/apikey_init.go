package config

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/lib/pq"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// APIKeyInitializer handles syncing API keys from config to database
type APIKeyInitializer struct {
	repo   storage.APIKeyRepository
	logger *slog.Logger
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

// SyncFromConfig syncs API keys from config to database
// - Creates new keys that don't exist
// - Updates existing keys with new values from config
// - Does NOT delete keys that are in database but not in config (preserves API-created keys)
func (i *APIKeyInitializer) SyncFromConfig(ctx context.Context, keys []APIKeyConfig) error {
	if len(keys) == 0 {
		i.logger.Info("No API keys configured in config file")
		return nil
	}

	for _, keyCfg := range keys {
		if err := i.syncKey(ctx, keyCfg); err != nil {
			return fmt.Errorf("failed to sync API key %s: %w", keyCfg.ID, err)
		}
	}

	i.logger.Info("API keys synced from config", "count", len(keys))
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
			ID:                keyCfg.ID,
			Name:              keyCfg.Name,
			PublicKeyHex:      publicKey,
			AllowedChainTypes: pq.StringArray(keyCfg.AllowedChainTypes),
			AllowedSigners:    pq.StringArray(keyCfg.AllowedSigners),
			RateLimit:         rateLimit,
			Admin:             keyCfg.Admin,
			Enabled:           keyCfg.Enabled,
			CreatedAt:         time.Now(),
			UpdatedAt:         time.Now(),
		}

		if err := i.repo.Create(ctx, newKey); err != nil {
			return fmt.Errorf("failed to create key: %w", err)
		}

		i.logger.Info("Created API key from config",
			"id", keyCfg.ID,
			"name", keyCfg.Name,
			"admin", keyCfg.Admin,
			"enabled", keyCfg.Enabled,
		)
	} else {
		// Update existing key with config values
		existing.Name = keyCfg.Name
		existing.PublicKeyHex = publicKey
		existing.AllowedChainTypes = pq.StringArray(keyCfg.AllowedChainTypes)
		existing.AllowedSigners = pq.StringArray(keyCfg.AllowedSigners)
		existing.RateLimit = rateLimit
		existing.Admin = keyCfg.Admin
		existing.Enabled = keyCfg.Enabled
		existing.UpdatedAt = time.Now()

		if err := i.repo.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update key: %w", err)
		}

		i.logger.Info("Updated API key from config",
			"id", keyCfg.ID,
			"name", keyCfg.Name,
			"admin", keyCfg.Admin,
			"enabled", keyCfg.Enabled,
		)
	}

	return nil
}
