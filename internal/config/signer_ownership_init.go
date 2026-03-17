package config

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// SyncSignerOwnership ensures every known signer has an ownership record.
// For signers without a record, ownership is assigned to the first enabled admin API key.
// For signers whose owner key has been deleted, ownership is reassigned.
func SyncSignerOwnership(
	ctx context.Context,
	signerManager evm.SignerManager,
	ownershipRepo storage.SignerOwnershipRepository,
	apiKeyRepo storage.APIKeyRepository,
	logger *slog.Logger,
) error {
	// List all signers
	result, err := signerManager.ListSigners(ctx, types.SignerFilter{
		Offset: 0,
		Limit:  100000,
	})
	if err != nil {
		return fmt.Errorf("failed to list signers: %w", err)
	}

	if len(result.Signers) == 0 {
		logger.Info("No signers found, skipping ownership sync")
		return nil
	}

	// Find first admin key
	firstAdmin, err := findFirstAdmin(ctx, apiKeyRepo)
	if err != nil {
		return fmt.Errorf("failed to find admin key: %w", err)
	}
	if firstAdmin == "" {
		logger.Warn("No enabled admin API key found, skipping ownership sync")
		return nil
	}

	synced := 0
	reassigned := 0
	for _, signer := range result.Signers {
		existing, err := ownershipRepo.Get(ctx, signer.Address)
		if err != nil && !types.IsNotFound(err) {
			return fmt.Errorf("failed to check ownership for %s: %w", signer.Address, err)
		}

		if existing != nil {
			// Check if owner key still exists
			if _, keyErr := apiKeyRepo.Get(ctx, existing.OwnerID); keyErr != nil {
				if types.IsNotFound(keyErr) {
					// Owner key deleted, reassign to first admin
					if updateErr := ownershipRepo.UpdateOwner(ctx, signer.Address, firstAdmin); updateErr != nil {
						return fmt.Errorf("failed to reassign ownership for %s: %w", signer.Address, updateErr)
					}
					reassigned++
					logger.Info("Reassigned signer ownership (owner key deleted)",
						"signer_address", signer.Address,
						"old_owner", existing.OwnerID,
						"new_owner", firstAdmin,
					)
				}
			}
			continue
		}

		// No ownership record, assign to first admin
		ownership := &types.SignerOwnership{
			SignerAddress: signer.Address,
			OwnerID:       firstAdmin,
			Status:        types.SignerOwnershipActive,
		}
		if err := ownershipRepo.Upsert(ctx, ownership); err != nil {
			return fmt.Errorf("failed to create ownership for %s: %w", signer.Address, err)
		}
		synced++
	}

	logger.Info("Signer ownership sync complete",
		"total_signers", len(result.Signers),
		"new_records", synced,
		"reassigned", reassigned,
		"default_owner", firstAdmin,
	)
	return nil
}

// findFirstAdmin returns the ID of the first enabled admin API key (by creation time).
func findFirstAdmin(ctx context.Context, apiKeyRepo storage.APIKeyRepository) (string, error) {
	keys, err := apiKeyRepo.List(ctx, storage.APIKeyFilter{
		EnabledOnly: true,
		Limit:       1000,
	})
	if err != nil {
		return "", err
	}

	var firstAdmin string
	var earliest = int64(0)
	for _, key := range keys {
		if key.Role != types.RoleAdmin || !key.Enabled {
			continue
		}
		ts := key.CreatedAt.Unix()
		if firstAdmin == "" || ts < earliest {
			firstAdmin = key.ID
			earliest = ts
		}
	}
	return firstAdmin, nil
}
