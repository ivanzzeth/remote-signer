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
	ruleRepo      storage.RuleRepository
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

// SetRuleRepo sets the rule repository for cascade operations (API key delete).
func (s *SignerAccessService) SetRuleRepo(repo storage.RuleRepository) {
	s.ruleRepo = repo
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

// TransferOwnership atomically transfers signer ownership to a new owner and clears the access list.
// Only the current owner can transfer. The old owner loses ALL access.
func (s *SignerAccessService) TransferOwnership(ctx context.Context, callerKeyID, signerAddress, newOwnerID string) error {
	if callerKeyID == newOwnerID {
		return fmt.Errorf("cannot transfer signer to yourself")
	}

	isOwner, err := s.IsOwner(ctx, callerKeyID, signerAddress)
	if err != nil {
		return err
	}
	if !isOwner {
		return fmt.Errorf("not the owner of signer %s", signerAddress)
	}

	// Verify new owner API key exists
	if _, err := s.apiKeyRepo.Get(ctx, newOwnerID); err != nil {
		if types.IsNotFound(err) {
			return fmt.Errorf("new owner API key %s not found", newOwnerID)
		}
		return fmt.Errorf("failed to verify new owner: %w", err)
	}

	// Atomically: update owner + clear access list
	txRepo, ok := s.ownershipRepo.(storage.SignerOwnershipTransactional)
	if !ok {
		return fmt.Errorf("ownership repository does not support transactions")
	}

	if err := txRepo.RunInTransaction(ctx, func(txOwnership storage.SignerOwnershipRepository, txAccess storage.SignerAccessRepository) error {
		if updateErr := txOwnership.UpdateOwner(ctx, signerAddress, newOwnerID); updateErr != nil {
			return fmt.Errorf("failed to update owner: %w", updateErr)
		}
		if deleteErr := txAccess.DeleteBySigner(ctx, signerAddress); deleteErr != nil {
			return fmt.Errorf("failed to clear access list: %w", deleteErr)
		}
		return nil
	}); err != nil {
		return err
	}

	s.logger.Info("signer ownership transferred",
		"signer_address", signerAddress,
		"from", callerKeyID,
		"to", newOwnerID,
	)
	return nil
}

// DeleteSigner deletes the ownership record and cascades to delete all access records.
// Only the current owner can delete.
func (s *SignerAccessService) DeleteSigner(ctx context.Context, callerKeyID, signerAddress string) error {
	isOwner, err := s.IsOwner(ctx, callerKeyID, signerAddress)
	if err != nil {
		return err
	}
	if !isOwner {
		return fmt.Errorf("not the owner of signer %s", signerAddress)
	}

	// Cascade: delete access records first, then ownership
	if err := s.accessRepo.DeleteBySigner(ctx, signerAddress); err != nil {
		return fmt.Errorf("failed to delete access records: %w", err)
	}
	if err := s.ownershipRepo.Delete(ctx, signerAddress); err != nil {
		return fmt.Errorf("failed to delete ownership: %w", err)
	}

	s.logger.Info("signer deleted",
		"signer_address", signerAddress,
		"deleted_by", callerKeyID,
	)
	return nil
}

// CleanupForDeletedKey performs cascade cleanup when an API key is deleted:
// 1. DELETE rules WHERE owner = key
// 2. Remove key from all rules' applied_to (delete rule if applied_to becomes empty)
// 3. DELETE signer_access WHERE api_key_id = key
func (s *SignerAccessService) CleanupForDeletedKey(ctx context.Context, apiKeyID string) error {
	if s.ruleRepo == nil {
		// No rule repo: only clean up access records
		return s.accessRepo.DeleteByAPIKey(ctx, apiKeyID)
	}

	// 1. Delete rules owned by this key
	ownedRules, err := s.ruleRepo.List(ctx, storage.RuleFilter{Owner: &apiKeyID, Limit: 100000})
	if err != nil {
		return fmt.Errorf("failed to list owned rules: %w", err)
	}
	for _, r := range ownedRules {
		if delErr := s.ruleRepo.Delete(ctx, r.ID); delErr != nil {
			return fmt.Errorf("failed to delete rule %s: %w", r.ID, delErr)
		}
	}

	// 2. Remove key from applied_to in all rules (delete rule if applied_to becomes empty)
	allRules, err := s.ruleRepo.List(ctx, storage.RuleFilter{Limit: 100000})
	if err != nil {
		return fmt.Errorf("failed to list all rules: %w", err)
	}
	for _, r := range allRules {
		newAppliedTo := removeFromSlice(r.AppliedTo, apiKeyID)
		if len(newAppliedTo) == len(r.AppliedTo) {
			continue // key was not in applied_to
		}
		if len(newAppliedTo) == 0 {
			// applied_to became empty, delete the rule
			if delErr := s.ruleRepo.Delete(ctx, r.ID); delErr != nil {
				return fmt.Errorf("failed to delete rule %s (empty applied_to): %w", r.ID, delErr)
			}
		} else {
			r.AppliedTo = newAppliedTo
			if updateErr := s.ruleRepo.Update(ctx, r); updateErr != nil {
				return fmt.Errorf("failed to update rule %s applied_to: %w", r.ID, updateErr)
			}
		}
	}

	// 3. Delete signer_access records
	if err := s.accessRepo.DeleteByAPIKey(ctx, apiKeyID); err != nil {
		return fmt.Errorf("failed to delete access records: %w", err)
	}

	s.logger.Info("cascade cleanup completed for deleted API key",
		"api_key_id", apiKeyID,
	)
	return nil
}

// CountOwnedSigners returns how many signers the given API key owns.
func (s *SignerAccessService) CountOwnedSigners(ctx context.Context, ownerID string) (int64, error) {
	return s.ownershipRepo.CountByOwner(ctx, ownerID)
}

// removeFromSlice removes all occurrences of val from slice.
func removeFromSlice(slice []string, val string) []string {
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if s != val {
			result = append(result, s)
		}
	}
	return result
}
