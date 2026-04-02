package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// SignerAccessRepository manages signer access grants.
type SignerAccessRepository interface {
	Grant(ctx context.Context, access *types.SignerAccess) error
	Revoke(ctx context.Context, signerAddress, apiKeyID string) error
	List(ctx context.Context, signerAddress string) ([]*types.SignerAccess, error)
	HasAccess(ctx context.Context, signerAddress, apiKeyID string) (bool, error)
	HasAccessViaWallet(ctx context.Context, apiKeyID, walletID string) (bool, error)
	DeleteBySigner(ctx context.Context, signerAddress string) error
	DeleteByAPIKey(ctx context.Context, apiKeyID string) error
	ListAccessibleAddresses(ctx context.Context, apiKeyID string) ([]string, error)
}

// GormSignerAccessRepository implements SignerAccessRepository using GORM.
type GormSignerAccessRepository struct {
	db *gorm.DB
}

// NewGormSignerAccessRepository creates a new GORM-based signer access repository.
func NewGormSignerAccessRepository(db *gorm.DB) (*GormSignerAccessRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	return &GormSignerAccessRepository{db: db}, nil
}

func (r *GormSignerAccessRepository) Grant(ctx context.Context, access *types.SignerAccess) error {
	if access.ID == "" {
		access.ID = strings.ToLower(access.SignerAddress) + ":" + access.APIKeyID
	}
	if access.CreatedAt.IsZero() {
		access.CreatedAt = time.Now()
	}
	return r.db.WithContext(ctx).Create(access).Error
}

func (r *GormSignerAccessRepository) Revoke(ctx context.Context, signerAddress, apiKeyID string) error {
	result := r.db.WithContext(ctx).
		Where("LOWER(signer_address) = LOWER(?) AND api_key_id = ?", signerAddress, apiKeyID).
		Delete(&types.SignerAccess{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}

func (r *GormSignerAccessRepository) List(ctx context.Context, signerAddress string) ([]*types.SignerAccess, error) {
	var accesses []*types.SignerAccess
	err := r.db.WithContext(ctx).
		Where("LOWER(signer_address) = LOWER(?)", signerAddress).
		Find(&accesses).Error
	return accesses, err
}

func (r *GormSignerAccessRepository) HasAccess(ctx context.Context, signerAddress, apiKeyID string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&types.SignerAccess{}).
		Where("LOWER(signer_address) = LOWER(?) AND api_key_id = ?", signerAddress, apiKeyID).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *GormSignerAccessRepository) DeleteBySigner(ctx context.Context, signerAddress string) error {
	return r.db.WithContext(ctx).
		Where("LOWER(signer_address) = LOWER(?)", signerAddress).
		Delete(&types.SignerAccess{}).Error
}

func (r *GormSignerAccessRepository) DeleteByAPIKey(ctx context.Context, apiKeyID string) error {
	return r.db.WithContext(ctx).
		Where("api_key_id = ?", apiKeyID).
		Delete(&types.SignerAccess{}).Error
}

func (r *GormSignerAccessRepository) HasAccessViaWallet(ctx context.Context, apiKeyID, walletID string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&types.SignerAccess{}).
		Where("api_key_id = ? AND wallet_id = ?", apiKeyID, walletID).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *GormSignerAccessRepository) ListAccessibleAddresses(ctx context.Context, apiKeyID string) ([]string, error) {
	var addresses []string
	err := r.db.WithContext(ctx).Model(&types.SignerAccess{}).
		Where("api_key_id = ?", apiKeyID).
		Pluck("signer_address", &addresses).Error
	return addresses, err
}
