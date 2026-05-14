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

// SignerRepository manages DB-backed signer inventory records.
type SignerRepository interface {
	Upsert(ctx context.Context, signer *types.Signer) error
	Get(ctx context.Context, address string) (*types.Signer, error)
	List(ctx context.Context, filter SignerListFilter) ([]types.Signer, int, error)
	Delete(ctx context.Context, address string) error
	UpdateMaterialStatus(ctx context.Context, address string, status types.SignerMaterialStatus, checkedAt time.Time, missingAt *time.Time, materialErr string) error
}

// SignerListFilter defines list filters for DB signers.
type SignerListFilter struct {
	Type   *types.SignerType
	Offset int
	Limit  int
}

// GormSignerRepository implements SignerRepository with GORM.
type GormSignerRepository struct {
	db *gorm.DB
}

// NewGormSignerRepository creates a signer repository.
func NewGormSignerRepository(db *gorm.DB) (*GormSignerRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	return &GormSignerRepository{db: db}, nil
}

func (r *GormSignerRepository) Upsert(ctx context.Context, signer *types.Signer) error {
	if signer == nil {
		return fmt.Errorf("signer cannot be nil")
	}
	now := time.Now().UTC()
	if signer.CreatedAt.IsZero() {
		signer.CreatedAt = now
	}
	signer.UpdatedAt = now
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "address"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"type",
			"primary_address",
			"hd_derivation_index",
			"enabled",
			"locked",
			"material_status",
			"material_checked_at",
			"material_missing_at",
			"material_error",
			"updated_at",
		}),
	}).Create(signer).Error
}

func (r *GormSignerRepository) Get(ctx context.Context, address string) (*types.Signer, error) {
	var signer types.Signer
	err := r.db.WithContext(ctx).Where("LOWER(address) = LOWER(?)", address).First(&signer).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return &signer, nil
}

func (r *GormSignerRepository) List(ctx context.Context, filter SignerListFilter) ([]types.Signer, int, error) {
	query := r.db.WithContext(ctx).Model(&types.Signer{})
	if filter.Type != nil {
		query = query.Where("type = ?", *filter.Type)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}
	var signers []types.Signer
	if err := query.Order("address ASC").Limit(limit).Find(&signers).Error; err != nil {
		return nil, 0, err
	}
	return signers, int(total), nil
}

func (r *GormSignerRepository) Delete(ctx context.Context, address string) error {
	res := r.db.WithContext(ctx).Where("LOWER(address) = LOWER(?)", address).Delete(&types.Signer{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}

func (r *GormSignerRepository) UpdateMaterialStatus(ctx context.Context, address string, status types.SignerMaterialStatus, checkedAt time.Time, missingAt *time.Time, materialErr string) error {
	updates := map[string]interface{}{
		"material_status":     status,
		"material_checked_at": checkedAt.UTC(),
		"material_error":      strings.TrimSpace(materialErr),
		"updated_at":          time.Now().UTC(),
	}
	if missingAt == nil {
		updates["material_missing_at"] = nil
	} else {
		updates["material_missing_at"] = missingAt.UTC()
	}
	res := r.db.WithContext(ctx).Model(&types.Signer{}).Where("LOWER(address) = LOWER(?)", address).Updates(updates)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}
