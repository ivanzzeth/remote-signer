package storage

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TemplateFilter for querying templates
type TemplateFilter struct {
	Type        *types.RuleType
	Source      *types.RuleSource
	EnabledOnly bool
	Offset      int
	Limit       int
}

// TemplateRepository defines the interface for template persistence
type TemplateRepository interface {
	Create(ctx context.Context, tmpl *types.RuleTemplate) error
	Get(ctx context.Context, id string) (*types.RuleTemplate, error)
	GetByName(ctx context.Context, name string) (*types.RuleTemplate, error)
	Update(ctx context.Context, tmpl *types.RuleTemplate) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter TemplateFilter) ([]*types.RuleTemplate, error)
	Count(ctx context.Context, filter TemplateFilter) (int, error)
	// Upsert writes tmpl, skipping the DB write when an existing row
	// has the same ContentHash. Returns changed=true when the row was
	// inserted or updated, false when the on-disk content matched the
	// cached one. Used by the Registry's Sync loop to avoid a full
	// JSON re-marshal on every boot.
	Upsert(ctx context.Context, tmpl *types.RuleTemplate) (changed bool, err error)
	// ListIDsBySource returns the IDs of every row whose Source matches
	// the given value. Registry.Sync calls this to compute the set of
	// rows that disappeared from a file source and need pruning.
	ListIDsBySource(ctx context.Context, source types.RuleSource) ([]string, error)
	// DeleteMany removes rows by ID in one statement.
	DeleteMany(ctx context.Context, ids []string) error
}

// GormTemplateRepository implements TemplateRepository using GORM
type GormTemplateRepository struct {
	db *gorm.DB
}

// NewGormTemplateRepository creates a new GORM-based template repository
func NewGormTemplateRepository(db *gorm.DB) (*GormTemplateRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	return &GormTemplateRepository{db: db}, nil
}

// Create creates a new template
func (r *GormTemplateRepository) Create(ctx context.Context, tmpl *types.RuleTemplate) error {
	if tmpl == nil {
		return fmt.Errorf("template cannot be nil")
	}
	now := time.Now()
	tmpl.CreatedAt = now
	tmpl.UpdatedAt = now
	return r.db.WithContext(ctx).Create(tmpl).Error
}

// Get retrieves a template by ID
func (r *GormTemplateRepository) Get(ctx context.Context, id string) (*types.RuleTemplate, error) {
	var tmpl types.RuleTemplate
	err := r.db.WithContext(ctx).First(&tmpl, "id = ?", id).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, types.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get template: %w", err)
	}
	return &tmpl, nil
}

// GetByName retrieves a template by name
func (r *GormTemplateRepository) GetByName(ctx context.Context, name string) (*types.RuleTemplate, error) {
	var tmpl types.RuleTemplate
	err := r.db.WithContext(ctx).First(&tmpl, "name = ?", name).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, types.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get template by name: %w", err)
	}
	return &tmpl, nil
}

// Update updates an existing template
func (r *GormTemplateRepository) Update(ctx context.Context, tmpl *types.RuleTemplate) error {
	if tmpl == nil {
		return fmt.Errorf("template cannot be nil")
	}
	tmpl.UpdatedAt = time.Now()
	return r.db.WithContext(ctx).Save(tmpl).Error
}

// Delete deletes a template by ID
func (r *GormTemplateRepository) Delete(ctx context.Context, id string) error {
	result := r.db.WithContext(ctx).Delete(&types.RuleTemplate{}, "id = ?", id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete template: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}

// List returns templates matching the filter
func (r *GormTemplateRepository) List(ctx context.Context, filter TemplateFilter) ([]*types.RuleTemplate, error) {
	query := r.db.WithContext(ctx).Model(&types.RuleTemplate{})

	if filter.Type != nil {
		query = query.Where("type = ?", *filter.Type)
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
		query = query.Limit(100) // default limit
	}

	query = query.Order("created_at DESC")

	var templates []*types.RuleTemplate
	err := query.Find(&templates).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list templates: %w", err)
	}
	return templates, nil
}

// Upsert inserts or updates tmpl based on content_hash. The Registry
// uses this on every Sync — most boots see no template changes, so the
// hash-equality fast path matters: it's a single SELECT vs. a full
// JSON marshal + UPDATE for every row in the source.
func (r *GormTemplateRepository) Upsert(ctx context.Context, tmpl *types.RuleTemplate) (bool, error) {
	if tmpl == nil {
		return false, fmt.Errorf("template cannot be nil")
	}
	if tmpl.ID == "" {
		return false, fmt.Errorf("template id is required")
	}
	var existing types.RuleTemplate
	err := r.db.WithContext(ctx).Select("id, content_hash").
		First(&existing, "id = ?", tmpl.ID).Error
	now := time.Now()
	if err == gorm.ErrRecordNotFound {
		tmpl.CreatedAt = now
		tmpl.UpdatedAt = now
		if err := r.db.WithContext(ctx).Create(tmpl).Error; err != nil {
			return false, fmt.Errorf("failed to create template: %w", err)
		}
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check existing template: %w", err)
	}
	// Skip the write when content_hash matches. Defensive on empty
	// hash: an unhashed existing row always loses to the incoming one.
	if existing.ContentHash != "" && existing.ContentHash == tmpl.ContentHash {
		return false, nil
	}
	tmpl.UpdatedAt = now
	if err := r.db.WithContext(ctx).Save(tmpl).Error; err != nil {
		return false, fmt.Errorf("failed to update template: %w", err)
	}
	return true, nil
}

// ListIDsBySource returns IDs of templates that came from the given source.
func (r *GormTemplateRepository) ListIDsBySource(ctx context.Context, source types.RuleSource) ([]string, error) {
	var ids []string
	err := r.db.WithContext(ctx).Model(&types.RuleTemplate{}).
		Where("source = ?", source).Pluck("id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list template ids by source: %w", err)
	}
	return ids, nil
}

// DeleteMany removes rows by ID.
func (r *GormTemplateRepository) DeleteMany(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	if err := r.db.WithContext(ctx).
		Delete(&types.RuleTemplate{}, "id IN ?", ids).Error; err != nil {
		return fmt.Errorf("failed to delete templates: %w", err)
	}
	return nil
}

// Count returns the total count of templates matching the filter
func (r *GormTemplateRepository) Count(ctx context.Context, filter TemplateFilter) (int, error) {
	query := r.db.WithContext(ctx).Model(&types.RuleTemplate{})

	if filter.Type != nil {
		query = query.Where("type = ?", *filter.Type)
	}
	if filter.Source != nil {
		query = query.Where("source = ?", *filter.Source)
	}
	if filter.EnabledOnly {
		query = query.Where("enabled = ?", true)
	}

	var count int64
	if err := query.Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count templates: %w", err)
	}
	return int(count), nil
}
