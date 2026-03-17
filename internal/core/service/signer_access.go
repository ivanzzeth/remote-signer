package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// HDWalletParentResolver resolves parent-child relationships for HD wallet addresses.
type HDWalletParentResolver interface {
	ListPrimaryAddresses() []string
	ListDerivedAddresses(primaryAddr string) ([]types.SignerInfo, error)
}

// SignerAccessService manages signer ownership and access control.
type SignerAccessService struct {
	ownershipRepo storage.SignerOwnershipRepository
	accessRepo    storage.SignerAccessRepository
	apiKeyRepo    storage.APIKeyRepository
	hdWalletMgrFn func() (HDWalletParentResolver, error)
	logger        *slog.Logger
}

// NewSignerAccessService creates a new SignerAccessService.
func NewSignerAccessService(
	ownershipRepo storage.SignerOwnershipRepository,
	accessRepo storage.SignerAccessRepository,
	apiKeyRepo storage.APIKeyRepository,
	hdWalletMgrFn func() (HDWalletParentResolver, error),
	logger *slog.Logger,
) (*SignerAccessService, error) {
	if ownershipRepo == nil {
		return nil, fmt.Errorf("ownership repository is required")
	}
	if accessRepo == nil {
		return nil, fmt.Errorf("access repository is required")
	}
	if apiKeyRepo == nil {
		return nil, fmt.Errorf("API key repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &SignerAccessService{
		ownershipRepo: ownershipRepo,
		accessRepo:    accessRepo,
		apiKeyRepo:    apiKeyRepo,
		hdWalletMgrFn: hdWalletMgrFn,
		logger:        logger,
	}, nil
}

// CheckAccess returns true if the caller (identified by API key ID) can use the signer.
// Access is granted if:
// 1. The caller owns the signer and it is active.
// 2. The caller has an explicit access grant and the signer is active.
// 3. The signer is a derived HD wallet address whose parent satisfies (1) or (2).
func (s *SignerAccessService) CheckAccess(ctx context.Context, callerKeyID, signerAddress string) (bool, error) {
	allowed, err := s.checkDirectAccess(ctx, callerKeyID, signerAddress)
	if err != nil {
		return false, err
	}
	if allowed {
		return true, nil
	}

	// Check if this is a derived address
	if s.hdWalletMgrFn == nil {
		return false, nil
	}
	hdMgr, err := s.hdWalletMgrFn()
	if err != nil || hdMgr == nil {
		return false, nil
	}

	parentAddr, found := s.findParentAddress(hdMgr, signerAddress)
	if !found {
		return false, nil
	}

	return s.checkDirectAccess(ctx, callerKeyID, parentAddr)
}

// checkDirectAccess checks ownership or explicit access for an address (not derived).
func (s *SignerAccessService) checkDirectAccess(ctx context.Context, callerKeyID, signerAddress string) (bool, error) {
	ownership, err := s.ownershipRepo.Get(ctx, signerAddress)
	if err != nil && !types.IsNotFound(err) {
		return false, fmt.Errorf("failed to get ownership: %w", err)
	}

	if ownership != nil && ownership.Status == types.SignerOwnershipActive {
		if ownership.OwnerID == callerKeyID {
			return true, nil
		}

		hasAccess, err := s.accessRepo.HasAccess(ctx, signerAddress, callerKeyID)
		if err != nil {
			return false, fmt.Errorf("failed to check access: %w", err)
		}
		if hasAccess {
			return true, nil
		}
	}

	return false, nil
}

// findParentAddress finds the HD wallet primary address for a derived address.
func (s *SignerAccessService) findParentAddress(hdMgr HDWalletParentResolver, derivedAddress string) (string, bool) {
	for _, primary := range hdMgr.ListPrimaryAddresses() {
		derived, err := hdMgr.ListDerivedAddresses(primary)
		if err != nil {
			continue
		}
		for _, d := range derived {
			if strings.EqualFold(d.Address, derivedAddress) {
				return primary, true
			}
		}
	}
	return "", false
}

// IsOwner returns true if the caller owns the signer.
func (s *SignerAccessService) IsOwner(ctx context.Context, callerKeyID, signerAddress string) (bool, error) {
	ownership, err := s.ownershipRepo.Get(ctx, signerAddress)
	if err != nil {
		if types.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to get ownership: %w", err)
	}
	return ownership.OwnerID == callerKeyID, nil
}

// GrantAccess grants access to a signer for a grantee API key. Only the owner can grant.
func (s *SignerAccessService) GrantAccess(ctx context.Context, ownerKeyID, signerAddress, granteeKeyID string) error {
	isOwner, err := s.IsOwner(ctx, ownerKeyID, signerAddress)
	if err != nil {
		return err
	}
	if !isOwner {
		return fmt.Errorf("not the owner of signer %s", signerAddress)
	}

	// Verify grantee API key exists
	if _, err := s.apiKeyRepo.Get(ctx, granteeKeyID); err != nil {
		if types.IsNotFound(err) {
			return fmt.Errorf("grantee API key %s not found", granteeKeyID)
		}
		return fmt.Errorf("failed to verify grantee: %w", err)
	}

	access := &types.SignerAccess{
		SignerAddress: signerAddress,
		APIKeyID:      granteeKeyID,
		GrantedBy:     ownerKeyID,
	}
	if err := s.accessRepo.Grant(ctx, access); err != nil {
		return fmt.Errorf("failed to grant access: %w", err)
	}

	s.logger.Info("signer access granted",
		"signer_address", signerAddress,
		"grantee", granteeKeyID,
		"granted_by", ownerKeyID,
	)
	return nil
}

// RevokeAccess revokes access for a grantee. Only the owner can revoke.
func (s *SignerAccessService) RevokeAccess(ctx context.Context, ownerKeyID, signerAddress, granteeKeyID string) error {
	isOwner, err := s.IsOwner(ctx, ownerKeyID, signerAddress)
	if err != nil {
		return err
	}
	if !isOwner {
		return fmt.Errorf("not the owner of signer %s", signerAddress)
	}

	if err := s.accessRepo.Revoke(ctx, signerAddress, granteeKeyID); err != nil {
		return fmt.Errorf("failed to revoke access: %w", err)
	}

	s.logger.Info("signer access revoked",
		"signer_address", signerAddress,
		"revoked_from", granteeKeyID,
		"revoked_by", ownerKeyID,
	)
	return nil
}

// ListAccess lists all access grants for a signer. Only the owner can list.
func (s *SignerAccessService) ListAccess(ctx context.Context, ownerKeyID, signerAddress string) ([]*types.SignerAccess, error) {
	isOwner, err := s.IsOwner(ctx, ownerKeyID, signerAddress)
	if err != nil {
		return nil, err
	}
	if !isOwner {
		return nil, fmt.Errorf("not the owner of signer %s", signerAddress)
	}

	return s.accessRepo.List(ctx, signerAddress)
}

// SetOwner sets the owner of a signer. Used during discovery and signer creation.
func (s *SignerAccessService) SetOwner(ctx context.Context, signerAddress, ownerID string, status types.SignerOwnershipStatus) error {
	ownership := &types.SignerOwnership{
		SignerAddress: signerAddress,
		OwnerID:       ownerID,
		Status:        status,
	}
	return s.ownershipRepo.Upsert(ctx, ownership)
}

// GetOwnership returns the ownership record for a signer.
func (s *SignerAccessService) GetOwnership(ctx context.Context, signerAddress string) (*types.SignerOwnership, error) {
	return s.ownershipRepo.Get(ctx, signerAddress)
}

// GetOwnedAddresses returns all signer addresses owned by the given API key.
func (s *SignerAccessService) GetOwnedAddresses(ctx context.Context, ownerID string) ([]string, error) {
	ownerships, err := s.ownershipRepo.GetByOwner(ctx, ownerID)
	if err != nil {
		return nil, err
	}
	addrs := make([]string, len(ownerships))
	for i, o := range ownerships {
		addrs[i] = o.SignerAddress
	}
	return addrs, nil
}

// GetAccessibleAddresses returns all signer addresses the API key has been granted access to.
func (s *SignerAccessService) GetAccessibleAddresses(ctx context.Context, apiKeyID string) ([]string, error) {
	return s.accessRepo.ListAccessibleAddresses(ctx, apiKeyID)
}
