package storage

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// RequestFilter for querying requests
type RequestFilter struct {
	APIKeyID      *string
	SignerAddress *string
	ChainType     *types.ChainType
	ChainID       *string
	Status        []types.SignRequestStatus
	// Cursor-based pagination (preferred over Offset)
	// Cursor is the created_at timestamp of the last item from previous page
	Cursor *time.Time
	// CursorID is the ID of the last item (for tie-breaking when timestamps are equal)
	CursorID *types.SignRequestID
	Limit    int
}

// RequestRepository defines the interface for sign request persistence
type RequestRepository interface {
	Create(ctx context.Context, req *types.SignRequest) error
	Get(ctx context.Context, id types.SignRequestID) (*types.SignRequest, error)
	Update(ctx context.Context, req *types.SignRequest) error
	List(ctx context.Context, filter RequestFilter) ([]*types.SignRequest, error)
	Count(ctx context.Context, filter RequestFilter) (int, error)
	UpdateStatus(ctx context.Context, id types.SignRequestID, status types.SignRequestStatus) error
}

// GormRequestRepository implements RequestRepository using GORM
type GormRequestRepository struct {
	db *gorm.DB
}

// NewGormRequestRepository creates a new GORM-based request repository
func NewGormRequestRepository(db *gorm.DB) (*GormRequestRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	return &GormRequestRepository{db: db}, nil
}

// Create creates a new sign request
func (r *GormRequestRepository) Create(ctx context.Context, req *types.SignRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	return r.db.WithContext(ctx).Create(req).Error
}

// Get retrieves a sign request by ID
func (r *GormRequestRepository) Get(ctx context.Context, id types.SignRequestID) (*types.SignRequest, error) {
	var req types.SignRequest
	err := r.db.WithContext(ctx).First(&req, "id = ?", id).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, types.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get request: %w", err)
	}
	return &req, nil
}

// Update updates an existing sign request
func (r *GormRequestRepository) Update(ctx context.Context, req *types.SignRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	return r.db.WithContext(ctx).Save(req).Error
}

// List returns sign requests matching the filter using cursor-based pagination
func (r *GormRequestRepository) List(ctx context.Context, filter RequestFilter) ([]*types.SignRequest, error) {
	query := r.buildFilterQuery(ctx, filter)

	// Cursor-based pagination: get items older than cursor
	// Uses (created_at, id) for stable ordering when timestamps are equal
	if filter.Cursor != nil {
		if filter.CursorID != nil {
			// Tie-breaking: items with same timestamp but smaller ID
			query = query.Where(
				"(created_at < ?) OR (created_at = ? AND id < ?)",
				*filter.Cursor, *filter.Cursor, *filter.CursorID,
			)
		} else {
			query = query.Where("created_at < ?", *filter.Cursor)
		}
	}

	if filter.Limit > 0 {
		query = query.Limit(filter.Limit)
	} else {
		query = query.Limit(100) // default limit
	}

	// Order by created_at DESC, id DESC for stable pagination
	query = query.Order("created_at DESC, id DESC")

	var requests []*types.SignRequest
	err := query.Find(&requests).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list requests: %w", err)
	}
	return requests, nil
}

// Count returns the total count of requests matching the filter (ignoring Offset/Limit)
func (r *GormRequestRepository) Count(ctx context.Context, filter RequestFilter) (int, error) {
	query := r.buildFilterQuery(ctx, filter)

	var count int64
	if err := query.Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count requests: %w", err)
	}
	return int(count), nil
}

// buildFilterQuery builds the base query with filters (without pagination)
func (r *GormRequestRepository) buildFilterQuery(ctx context.Context, filter RequestFilter) *gorm.DB {
	query := r.db.WithContext(ctx).Model(&types.SignRequest{})

	if filter.APIKeyID != nil {
		query = query.Where("api_key_id = ?", *filter.APIKeyID)
	}
	if filter.SignerAddress != nil {
		query = query.Where("signer_address = ?", *filter.SignerAddress)
	}
	if filter.ChainType != nil {
		query = query.Where("chain_type = ?", *filter.ChainType)
	}
	if filter.ChainID != nil {
		query = query.Where("chain_id = ?", *filter.ChainID)
	}
	if len(filter.Status) > 0 {
		query = query.Where("status IN ?", filter.Status)
	}

	return query
}

// UpdateStatus updates the status of a sign request
func (r *GormRequestRepository) UpdateStatus(ctx context.Context, id types.SignRequestID, status types.SignRequestStatus) error {
	result := r.db.WithContext(ctx).Model(&types.SignRequest{}).
		Where("id = ?", id).
		Update("status", status)
	if result.Error != nil {
		return fmt.Errorf("failed to update status: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}
