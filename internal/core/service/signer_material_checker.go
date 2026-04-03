package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ivanzzeth/ethsig/keystore"

	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// SignerMaterialChecker reconciles DB signer inventory against local key material.
type SignerMaterialChecker struct {
	signerManager evmchain.SignerManager
	signerRepo    storage.SignerRepository
	keystoreDir   string
	hdWalletDir   string
	interval      time.Duration
	logger        *slog.Logger
}

func NewSignerMaterialChecker(
	signerManager evmchain.SignerManager,
	signerRepo storage.SignerRepository,
	keystoreDir string,
	hdWalletDir string,
	interval time.Duration,
	logger *slog.Logger,
) (*SignerMaterialChecker, error) {
	if signerManager == nil {
		return nil, fmt.Errorf("signer manager is required")
	}
	if signerRepo == nil {
		return nil, fmt.Errorf("signer repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if interval <= 0 {
		return nil, fmt.Errorf("interval must be > 0")
	}
	return &SignerMaterialChecker{
		signerManager: signerManager,
		signerRepo:    signerRepo,
		keystoreDir:   keystoreDir,
		hdWalletDir:   hdWalletDir,
		interval:      interval,
		logger:        logger,
	}, nil
}

// RunOnce performs a single reconciliation run.
func (c *SignerMaterialChecker) RunOnce(ctx context.Context) error {
	result, err := c.signerManager.ListSigners(ctx, types.SignerFilter{Offset: 0, Limit: 100000})
	if err != nil {
		return fmt.Errorf("list signers: %w", err)
	}

	keystoreSet := map[string]struct{}{}
	if c.keystoreDir != "" {
		ks, listErr := keystore.ListKeystores(c.keystoreDir)
		if listErr != nil {
			c.logger.Warn("failed to list keystore files", "error", listErr)
		} else {
			for _, item := range ks {
				keystoreSet[common.HexToAddress(item.Address).Hex()] = struct{}{}
			}
		}
	}

	hdPrimarySet := map[string]struct{}{}
	if c.hdWalletDir != "" {
		hw, listErr := keystore.ListHDWallets(c.hdWalletDir)
		if listErr != nil {
			c.logger.Warn("failed to list HD wallet files", "error", listErr)
		} else {
			for _, item := range hw {
				hdPrimarySet[common.HexToAddress(item.PrimaryAddress).Hex()] = struct{}{}
			}
		}
	}

	hierarchy := c.signerManager.GetHDHierarchy()
	now := time.Now().UTC()
	updated := 0
	for _, s := range result.Signers {
		addr := common.HexToAddress(s.Address).Hex()
		primary := addr
		var hdIndex *uint32
		if h, ok := hierarchy[addr]; ok {
			primary = common.HexToAddress(h.ParentAddress).Hex()
			idx := h.DerivationIndex
			hdIndex = &idx
		}

		status := types.SignerMaterialStatusPresent
		materialErr := ""
		switch types.SignerType(s.Type) {
		case types.SignerTypeKeystore:
			if _, ok := keystoreSet[addr]; !ok {
				status = types.SignerMaterialStatusMissing
				materialErr = "keystore file not found"
			}
		case types.SignerTypeHDWallet:
			if _, ok := hdPrimarySet[primary]; !ok {
				status = types.SignerMaterialStatusMissing
				materialErr = "hd wallet file not found"
			}
		default:
			status = types.SignerMaterialStatusPresent
		}

		var missingAt *time.Time
		if existing, getErr := c.signerRepo.Get(ctx, addr); getErr == nil {
			if status == types.SignerMaterialStatusMissing {
				if existing.MaterialMissingAt != nil {
					missingAt = existing.MaterialMissingAt
				} else {
					t := now
					missingAt = &t
				}
			}
		} else if status == types.SignerMaterialStatusMissing {
			t := now
			missingAt = &t
		}

		rec := &types.Signer{
			Address:           addr,
			Type:              types.SignerType(s.Type),
			PrimaryAddress:    primary,
			HDDerivationIndex: hdIndex,
			Enabled:           s.Enabled,
			Locked:            s.Locked,
			MaterialStatus:    status,
			MaterialCheckedAt: &now,
			MaterialMissingAt: missingAt,
			MaterialError:     strings.TrimSpace(materialErr),
		}
		if err := c.signerRepo.Upsert(ctx, rec); err != nil {
			return fmt.Errorf("upsert signer %s: %w", addr, err)
		}
		updated++
	}

	c.logger.Info("signer material reconciliation complete", "signers", len(result.Signers), "updated", updated)
	return nil
}

// Start runs periodic reconciliation until ctx is done.
func (c *SignerMaterialChecker) Start(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.RunOnce(ctx); err != nil {
				c.logger.Warn("signer material reconciliation failed", "error", err)
			}
		}
	}
}
