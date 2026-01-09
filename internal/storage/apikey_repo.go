package storage

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// APIKeyFilter for querying API keys
type APIKeyFilter struct {
	EnabledOnly bool
	Offset      int
	Limit       int
}

// APIKeyRepository defines the interface for API key persistence
type APIKeyRepository interface {
	Create(ctx context.Context, key *types.APIKey) error
	Get(ctx context.Context, id string) (*types.APIKey, error)
	Update(ctx context.Context, key *types.APIKey) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter APIKeyFilter) ([]*types.APIKey, error)
	UpdateLastUsed(ctx context.Context, id string) error
}

// GormAPIKeyRepository implements APIKeyRepository using GORM
type GormAPIKeyRepository struct {
	db *gorm.DB
}

// NewGormAPIKeyRepository creates a new GORM-based API key repository
func NewGormAPIKeyRepository(db *gorm.DB) (*GormAPIKeyRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	return &GormAPIKeyRepository{db: db}, nil
}

// Create creates a new API key
func (r *GormAPIKeyRepository) Create(ctx context.Context, key *types.APIKey) error {
	if key == nil {
		return fmt.Errorf("API key cannot be nil")
	}
	return r.db.WithContext(ctx).Create(key).Error
}

// Get retrieves an API key by ID
func (r *GormAPIKeyRepository) Get(ctx context.Context, id string) (*types.APIKey, error) {
	var key types.APIKey
	err := r.db.WithContext(ctx).First(&key, "id = ?", id).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, types.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}
	return &key, nil
}

// Update updates an existing API key
func (r *GormAPIKeyRepository) Update(ctx context.Context, key *types.APIKey) error {
	if key == nil {
		return fmt.Errorf("API key cannot be nil")
	}
	return r.db.WithContext(ctx).Save(key).Error
}

// Delete deletes an API key by ID
func (r *GormAPIKeyRepository) Delete(ctx context.Context, id string) error {
	result := r.db.WithContext(ctx).Delete(&types.APIKey{}, "id = ?", id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete API key: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}

// List returns API keys matching the filter
func (r *GormAPIKeyRepository) List(ctx context.Context, filter APIKeyFilter) ([]*types.APIKey, error) {
	query := r.db.WithContext(ctx).Model(&types.APIKey{})

	if filter.EnabledOnly {
		query = query.Where("enabled = ?", true)
		// Also filter out expired keys
		query = query.Where("expires_at IS NULL OR expires_at > ?", time.Now())
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

	var keys []*types.APIKey
	err := query.Find(&keys).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list API keys: %w", err)
	}
	return keys, nil
}

// UpdateLastUsed updates the last used timestamp for an API key
func (r *GormAPIKeyRepository) UpdateLastUsed(ctx context.Context, id string) error {
	now := time.Now()
	result := r.db.WithContext(ctx).Model(&types.APIKey{}).
		Where("id = ?", id).
		Update("last_used_at", now)
	if result.Error != nil {
		return fmt.Errorf("failed to update last used: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}
