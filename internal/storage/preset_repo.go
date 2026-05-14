package storage

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// PresetFilter for querying presets.
type PresetFilter struct {
	ChainType   *types.ChainType
	Source      *types.RuleSource
	EnabledOnly bool
	Offset      int
	Limit       int
}

// PresetRepository defines persistence for rule presets. Mirrors
// TemplateRepository's shape so the Registry can drive both with the
// same Sync algorithm.
type PresetRepository interface {
	Create(ctx context.Context, p *types.RulePreset) error
	Get(ctx context.Context, id string) (*types.RulePreset, error)
	Update(ctx context.Context, p *types.RulePreset) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter PresetFilter) ([]*types.RulePreset, error)
	Count(ctx context.Context, filter PresetFilter) (int, error)
	Upsert(ctx context.Context, p *types.RulePreset) (changed bool, err error)
	ListIDsBySource(ctx context.Context, source types.RuleSource) ([]string, error)
	DeleteMany(ctx context.Context, ids []string) error
}

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

// Upsert inserts or updates p based on ContentHash. Mirrors
// TemplateRepository.Upsert exactly — when the on-disk hash matches
// the cached row, skip the JSON marshal + UPDATE entirely.
func (r *GormPresetRepository) Upsert(ctx context.Context, p *types.RulePreset) (bool, error) {
	if p == nil {
		return false, fmt.Errorf("preset cannot be nil")
	}
	if p.ID == "" {
		return false, fmt.Errorf("preset id is required")
	}
	var existing types.RulePreset
	err := r.db.WithContext(ctx).Select("id, content_hash").
		First(&existing, "id = ?", p.ID).Error
	now := time.Now()
	if err == gorm.ErrRecordNotFound {
		p.CreatedAt = now
		p.UpdatedAt = now
		if err := r.db.WithContext(ctx).Create(p).Error; err != nil {
			return false, fmt.Errorf("failed to create preset: %w", err)
		}
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check existing preset: %w", err)
	}
	if existing.ContentHash != "" && existing.ContentHash == p.ContentHash {
		return false, nil
	}
	p.UpdatedAt = now
	if err := r.db.WithContext(ctx).Save(p).Error; err != nil {
		return false, fmt.Errorf("failed to update preset: %w", err)
	}
	return true, nil
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
