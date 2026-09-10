package storage

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// GormPresetRepository implements PresetRepository with GORM.
type GormPresetRepository struct {
	db *gorm.DB
}

// NewGormPresetRepository creates the GORM-backed preset repository.
func NewGormPresetRepository(db *gorm.DB) (*GormPresetRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	return &GormPresetRepository{db: db}, nil
}

// Create inserts a new preset row.
func (r *GormPresetRepository) Create(ctx context.Context, p *types.RulePreset) error {
	if p == nil {
		return fmt.Errorf("preset cannot be nil")
	}
	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now
	return r.db.WithContext(ctx).Create(p).Error
}

// Get retrieves a preset by ID.
func (r *GormPresetRepository) Get(ctx context.Context, id string) (*types.RulePreset, error) {
	var p types.RulePreset
	err := r.db.WithContext(ctx).First(&p, "id = ?", id).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, types.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get preset: %w", err)
	}
	return &p, nil
}

// Update writes back changes via Save.
func (r *GormPresetRepository) Update(ctx context.Context, p *types.RulePreset) error {
	if p == nil {
		return fmt.Errorf("preset cannot be nil")
	}
	p.UpdatedAt = time.Now()
	return r.db.WithContext(ctx).Save(p).Error
}

// Delete removes a preset row by ID.
func (r *GormPresetRepository) Delete(ctx context.Context, id string) error {
	result := r.db.WithContext(ctx).Delete(&types.RulePreset{}, "id = ?", id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete preset: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}

// List returns presets matching the filter (newest first).
func (r *GormPresetRepository) List(ctx context.Context, filter PresetFilter) ([]*types.RulePreset, error) {
	query := r.db.WithContext(ctx).Model(&types.RulePreset{})
	if filter.ChainType != nil {
		query = query.Where("chain_type = ?", *filter.ChainType)
	}
	if filter.Source != nil {
		query = query.Where("source = ?", *filter.Source)
	}
	if filter.EnabledOnly {
		query = query.Where("enabled = ?", true)
	}
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}
	if filter.Limit > 0 {
		query = query.Limit(filter.Limit)
	} else {
		query = query.Limit(200)
	}
	query = query.Order("created_at DESC")

	var presets []*types.RulePreset
	if err := query.Find(&presets).Error; err != nil {
		return nil, fmt.Errorf("failed to list presets: %w", err)
	}
	return presets, nil
}

// Count returns how many presets match the filter.
func (r *GormPresetRepository) Count(ctx context.Context, filter PresetFilter) (int, error) {
	query := r.db.WithContext(ctx).Model(&types.RulePreset{})
	if filter.ChainType != nil {
		query = query.Where("chain_type = ?", *filter.ChainType)
	}
	if filter.Source != nil {
		query = query.Where("source = ?", *filter.Source)
	}
	if filter.EnabledOnly {
		query = query.Where("enabled = ?", true)
	}
	var count int64
	if err := query.Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count presets: %w", err)
	}
	return int(count), nil
}

// Upsert inserts or updates p based on ContentHash. Presets carry no
// type/mode, so the hash alone decides whether the write can be skipped —
// see presetUpsert in catalogue_upsert.go, next to the template table's
// stricter answer to the same question.
func (r *GormPresetRepository) Upsert(ctx context.Context, p *types.RulePreset) (bool, error) {
	return upsertCatalogueRow(ctx, r.db, p, presetUpsert)
}

// ListIDsBySource returns IDs of presets sourced from `source`.
func (r *GormPresetRepository) ListIDsBySource(ctx context.Context, source types.RuleSource) ([]string, error) {
	var ids []string
	err := r.db.WithContext(ctx).Model(&types.RulePreset{}).
		Where("source = ?", source).Pluck("id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list preset ids by source: %w", err)
	}
	return ids, nil
}

// DeleteMany removes rows by ID.
func (r *GormPresetRepository) DeleteMany(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	if err := r.db.WithContext(ctx).
		Delete(&types.RulePreset{}, "id IN ?", ids).Error; err != nil {
		return fmt.Errorf("failed to delete presets: %w", err)
	}
	return nil
}
