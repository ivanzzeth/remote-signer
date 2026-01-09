package storage

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// AuditFilter for querying audit records
type AuditFilter struct {
	RequestID *types.SignRequestID
	APIKeyID  *string
	EventType *types.AuditEventType
	ChainType *types.ChainType
	StartTime *time.Time
	EndTime   *time.Time
	// Cursor-based pagination (preferred over Offset)
	// Cursor is the timestamp of the last item from previous page
	Cursor *time.Time
	// CursorID is the ID of the last item (for tie-breaking when timestamps are equal)
	CursorID *types.AuditID
	Limit    int
}

// AuditRepository defines the interface for audit log persistence
type AuditRepository interface {
	Log(ctx context.Context, record *types.AuditRecord) error
	Query(ctx context.Context, filter AuditFilter) ([]*types.AuditRecord, error)
	Count(ctx context.Context, filter AuditFilter) (int, error)
	GetByRequestID(ctx context.Context, requestID types.SignRequestID) ([]*types.AuditRecord, error)
}

// GormAuditRepository implements AuditRepository using GORM
type GormAuditRepository struct {
	db *gorm.DB
}

// NewGormAuditRepository creates a new GORM-based audit repository
func NewGormAuditRepository(db *gorm.DB) (*GormAuditRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	return &GormAuditRepository{db: db}, nil
}

// Log creates a new audit record
func (r *GormAuditRepository) Log(ctx context.Context, record *types.AuditRecord) error {
	if record == nil {
		return fmt.Errorf("audit record cannot be nil")
	}
	return r.db.WithContext(ctx).Create(record).Error
}

// Query returns audit records matching the filter using cursor-based pagination
func (r *GormAuditRepository) Query(ctx context.Context, filter AuditFilter) ([]*types.AuditRecord, error) {
	query := r.buildFilterQuery(ctx, filter)

	// Cursor-based pagination: get items older than cursor
	// Uses (timestamp, id) for stable ordering when timestamps are equal
	if filter.Cursor != nil {
		if filter.CursorID != nil {
			// Tie-breaking: items with same timestamp but smaller ID
			query = query.Where(
				"(timestamp < ?) OR (timestamp = ? AND id < ?)",
				*filter.Cursor, *filter.Cursor, *filter.CursorID,
			)
		} else {
			query = query.Where("timestamp < ?", *filter.Cursor)
		}
	}

	if filter.Limit > 0 {
		query = query.Limit(filter.Limit)
	} else {
		query = query.Limit(100) // default limit
	}

	// Order by timestamp DESC, id DESC for stable pagination
	query = query.Order("timestamp DESC, id DESC")

	var records []*types.AuditRecord
	err := query.Find(&records).Error
	if err != nil {
		return nil, fmt.Errorf("failed to query audit records: %w", err)
	}
	return records, nil
}

// Count returns the total count of audit records matching the filter (ignoring Offset/Limit)
func (r *GormAuditRepository) Count(ctx context.Context, filter AuditFilter) (int, error) {
	query := r.buildFilterQuery(ctx, filter)

	var count int64
	if err := query.Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count audit records: %w", err)
	}
	return int(count), nil
}

// buildFilterQuery builds the base query with filters (without pagination)
func (r *GormAuditRepository) buildFilterQuery(ctx context.Context, filter AuditFilter) *gorm.DB {
	query := r.db.WithContext(ctx).Model(&types.AuditRecord{})

	if filter.RequestID != nil {
		query = query.Where("request_id = ?", *filter.RequestID)
	}
	if filter.APIKeyID != nil {
		query = query.Where("api_key_id = ?", *filter.APIKeyID)
	}
	if filter.EventType != nil {
		query = query.Where("event_type = ?", *filter.EventType)
	}
	if filter.ChainType != nil {
		query = query.Where("chain_type = ?", *filter.ChainType)
	}
	if filter.StartTime != nil {
		query = query.Where("timestamp >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("timestamp <= ?", *filter.EndTime)
	}

	return query
}

// GetByRequestID returns all audit records for a specific request
func (r *GormAuditRepository) GetByRequestID(ctx context.Context, requestID types.SignRequestID) ([]*types.AuditRecord, error) {
	return r.Query(ctx, AuditFilter{
		RequestID: &requestID,
		Limit:     1000, // Allow more records for a specific request
	})
}
