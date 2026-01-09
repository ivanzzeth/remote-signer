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
	Offset    int
	Limit     int
}

// AuditRepository defines the interface for audit log persistence
type AuditRepository interface {
	Log(ctx context.Context, record *types.AuditRecord) error
	Query(ctx context.Context, filter AuditFilter) ([]*types.AuditRecord, error)
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

// Query returns audit records matching the filter
func (r *GormAuditRepository) Query(ctx context.Context, filter AuditFilter) ([]*types.AuditRecord, error) {
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

	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}
	if filter.Limit > 0 {
		query = query.Limit(filter.Limit)
	} else {
		query = query.Limit(100) // default limit
	}

	query = query.Order("timestamp DESC")

	var records []*types.AuditRecord
	err := query.Find(&records).Error
	if err != nil {
		return nil, fmt.Errorf("failed to query audit records: %w", err)
	}
	return records, nil
}

// GetByRequestID returns all audit records for a specific request
func (r *GormAuditRepository) GetByRequestID(ctx context.Context, requestID types.SignRequestID) ([]*types.AuditRecord, error) {
	return r.Query(ctx, AuditFilter{
		RequestID: &requestID,
		Limit:     1000, // Allow more records for a specific request
	})
}
