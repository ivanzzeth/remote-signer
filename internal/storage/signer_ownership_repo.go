package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// SignerOwnershipRepository manages signer ownership records.
type SignerOwnershipRepository interface {
	Upsert(ctx context.Context, ownership *types.SignerOwnership) error
	Get(ctx context.Context, signerAddress string) (*types.SignerOwnership, error)
	// GetBoth atomically fetches ownership records for two addresses.
	// Returns (senderOwnership, recipientOwnership, error).
	// If an address is not found, that ownership will be nil (not an error).
	GetBoth(ctx context.Context, senderAddress, recipientAddress string) (*types.SignerOwnership, *types.SignerOwnership, error)
	GetByOwner(ctx context.Context, ownerID string) ([]*types.SignerOwnership, error)
	Delete(ctx context.Context, signerAddress string) error
	UpdateOwner(ctx context.Context, signerAddress, newOwnerID string) error
	CountByOwner(ctx context.Context, ownerID string) (int64, error)
	CountByOwnerAndType(ctx context.Context, ownerID string, signerType types.SignerType) (int64, error)
}

// SignerOwnershipTransactional is implemented by ownership repos that support atomic operations
// spanning both ownership and access repos within a single DB transaction.
type SignerOwnershipTransactional interface {
	RunInTransaction(ctx context.Context, fn func(txOwnership SignerOwnershipRepository, txAccess SignerAccessRepository) error) error
}

// GormSignerOwnershipRepository implements SignerOwnershipRepository using GORM.
type GormSignerOwnershipRepository struct {
	db *gorm.DB
}

// NewGormSignerOwnershipRepository creates a new GORM-based signer ownership repository.
func NewGormSignerOwnershipRepository(db *gorm.DB) (*GormSignerOwnershipRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	return &GormSignerOwnershipRepository{db: db}, nil
}

func (r *GormSignerOwnershipRepository) Upsert(ctx context.Context, ownership *types.SignerOwnership) error {
	now := time.Now()
	if ownership.CreatedAt.IsZero() {
		ownership.CreatedAt = now
	}
	ownership.UpdatedAt = now

	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "signer_address"}},
		DoUpdates: clause.AssignmentColumns([]string{"owner_id", "status", "signer_type", "display_name", "tags", "updated_at"}),
	}).Create(ownership).Error
}

func (r *GormSignerOwnershipRepository) Get(ctx context.Context, signerAddress string) (*types.SignerOwnership, error) {
	var ownership types.SignerOwnership
	err := r.db.WithContext(ctx).Where("LOWER(signer_address) = LOWER(?)", signerAddress).First(&ownership).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return &ownership, nil
}

// GetBoth atomically fetches ownership records for two addresses in a single query.
// This prevents TOCTOU race conditions when comparing ownership.
func (r *GormSignerOwnershipRepository) GetBoth(ctx context.Context, senderAddress, recipientAddress string) (*types.SignerOwnership, *types.SignerOwnership, error) {
	var ownerships []types.SignerOwnership
	senderLower := strings.ToLower(senderAddress)
	recipientLower := strings.ToLower(recipientAddress)

	err := r.db.WithContext(ctx).
		Where("LOWER(signer_address) IN ?", []string{senderLower, recipientLower}).
		Find(&ownerships).Error
	if err != nil {
		return nil, nil, err
	}

	var senderOwnership, recipientOwnership *types.SignerOwnership
	for i := range ownerships {
		if strings.EqualFold(ownerships[i].SignerAddress, senderAddress) {
			senderOwnership = &ownerships[i]
		} else if strings.EqualFold(ownerships[i].SignerAddress, recipientAddress) {
			recipientOwnership = &ownerships[i]
		}
	}

	return senderOwnership, recipientOwnership, nil
}

func (r *GormSignerOwnershipRepository) GetByOwner(ctx context.Context, ownerID string) ([]*types.SignerOwnership, error) {
	var ownerships []*types.SignerOwnership
	err := r.db.WithContext(ctx).Where("owner_id = ?", ownerID).Find(&ownerships).Error
	if err != nil {
		return nil, err
	}
	return ownerships, nil
}

func (r *GormSignerOwnershipRepository) Delete(ctx context.Context, signerAddress string) error {
	result := r.db.WithContext(ctx).Where("LOWER(signer_address) = LOWER(?)", signerAddress).Delete(&types.SignerOwnership{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}

func (r *GormSignerOwnershipRepository) UpdateOwner(ctx context.Context, signerAddress, newOwnerID string) error {
	result := r.db.WithContext(ctx).Model(&types.SignerOwnership{}).
		Where("LOWER(signer_address) = LOWER(?)", signerAddress).
		Updates(map[string]interface{}{
			"owner_id":   newOwnerID,
			"updated_at": time.Now(),
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}

func (r *GormSignerOwnershipRepository) CountByOwner(ctx context.Context, ownerID string) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&types.SignerOwnership{}).Where("owner_id = ?", ownerID).Count(&count).Error
	return count, err
}

// CountByOwnerAndType counts signers owned by ownerID with a specific type.
func (r *GormSignerOwnershipRepository) CountByOwnerAndType(ctx context.Context, ownerID string, signerType types.SignerType) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&types.SignerOwnership{}).
		Where("owner_id = ? AND signer_type = ?", ownerID, signerType).
		Count(&count).Error
	return count, err
}

// RunInTransaction runs fn inside a database transaction with both ownership and access repos.
func (r *GormSignerOwnershipRepository) RunInTransaction(ctx context.Context, fn func(txOwnership SignerOwnershipRepository, txAccess SignerAccessRepository) error) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txOwnership := &GormSignerOwnershipRepository{db: tx}
		txAccess := &GormSignerAccessRepository{db: tx}
		return fn(txOwnership, txAccess)
	})
}
