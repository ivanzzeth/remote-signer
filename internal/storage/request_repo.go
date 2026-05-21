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

// ErrStateConflict is returned when a compare-and-update fails because the
// current status does not match the expected status (concurrent modification).
var ErrStateConflict = fmt.Errorf("state conflict: status was modified by another request")

// RequestRepository defines the interface for sign request persistence
type RequestRepository interface {
	Create(ctx context.Context, req *types.SignRequest) error
	Get(ctx context.Context, id types.SignRequestID) (*types.SignRequest, error)
	Update(ctx context.Context, req *types.SignRequest) error
	// CompareAndUpdate atomically updates a request only if its current status
	// matches expectedStatus. Returns ErrStateConflict if the status has changed.
	CompareAndUpdate(ctx context.Context, req *types.SignRequest, expectedStatus types.SignRequestStatus) error
	List(ctx context.Context, filter RequestFilter) ([]*types.SignRequest, error)
	Count(ctx context.Context, filter RequestFilter) (int, error)
	UpdateStatus(ctx context.Context, id types.SignRequestID, status types.SignRequestStatus) error
	// UpdateLastNoMatchReason records the whitelist engine's diagnostic
	// for "no rule matched" so it surfaces in the API + activity drawer.
	// Best-effort — callers swallow errors because the sign flow has
	// already moved on to manual approval / simulation.
	UpdateLastNoMatchReason(ctx context.Context, id types.SignRequestID, reason string) error
	// LookupBySignedData finds the most recent completed sign request
	// whose SignedData equals the supplied bytes. Used by the wallet
	// RPC proxy to link an eth_sendRawTransaction broadcast back to
	// the request that produced it. Returns ErrNotFound when no
	// match (third-party caller hit the proxy with a payload we
	// didn't sign).
	LookupBySignedData(ctx context.Context, signedData []byte) (*types.SignRequest, error)
	// SetTransactionID stores the FK after the proxy creates a
	// transactions row. Best-effort — sign_request retains its
	// completed status even if the back-ref write fails (the txs
	// table is still the source of truth).
	SetTransactionID(ctx context.Context, id types.SignRequestID, transactionID string) error
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

// CompareAndUpdate atomically updates a request only if its current status
// matches expectedStatus. Uses a SQL WHERE clause to ensure atomicity at
// the database level, preventing TOCTOU race conditions.
// Returns ErrStateConflict if the status has been modified concurrently.
func (r *GormRequestRepository) CompareAndUpdate(ctx context.Context, req *types.SignRequest, expectedStatus types.SignRequestStatus) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	// Use raw UPDATE ... WHERE id = ? AND status = ? for atomic CAS
	result := r.db.WithContext(ctx).
		Model(&types.SignRequest{}).
		Where("id = ? AND status = ?", req.ID, expectedStatus).
		Updates(map[string]interface{}{
			"status":         req.Status,
			"rule_matched_id": req.RuleMatchedID,
			"approved_by":    req.ApprovedBy,
			"approved_at":    req.ApprovedAt,
			"signature":      req.Signature,
			"signed_data":    req.SignedData,
			"error_message":  req.ErrorMessage,
			"completed_at":   req.CompletedAt,
			"updated_at":     req.UpdatedAt,
		})
	if result.Error != nil {
		return fmt.Errorf("failed to update request: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrStateConflict
	}
	return nil
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

// UpdateLastNoMatchReason persists the engine's no-match diagnostic
// against the request row. Idempotent on reason (the engine emits the
// same string for each re-evaluation), and a no-op if the row is gone.
func (r *GormRequestRepository) UpdateLastNoMatchReason(ctx context.Context, id types.SignRequestID, reason string) error {
	result := r.db.WithContext(ctx).Model(&types.SignRequest{}).
		Where("id = ?", id).
		Update("last_no_match_reason", reason)
	if result.Error != nil {
		return fmt.Errorf("failed to update last_no_match_reason: %w", result.Error)
	}
	return nil
}

// LookupBySignedData scans recently-completed requests for one whose
// SignedData equals the supplied bytes. Used by the wallet RPC proxy
// to associate a fresh eth_sendRawTransaction broadcast with the
// signing request that produced it. Bytea equality is the cheapest
// reliable match — hashing the payload would add no precision and
// requires a column we don't carry.
//
// Limited to the last 5 minutes of completed requests to keep the
// scan bounded on busy deployments; the broadcast typically lands
// seconds after the sign completes.
func (r *GormRequestRepository) LookupBySignedData(ctx context.Context, signedData []byte) (*types.SignRequest, error) {
	if len(signedData) == 0 {
		return nil, types.ErrNotFound
	}
	cutoff := time.Now().Add(-5 * time.Minute)
	var req types.SignRequest
	err := r.db.WithContext(ctx).
		Where("signed_data = ? AND status = ? AND updated_at >= ?",
			signedData, types.StatusCompleted, cutoff).
		Order("updated_at DESC").
		First(&req).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, types.ErrNotFound
		}
		return nil, fmt.Errorf("failed to lookup by signed_data: %w", err)
	}
	return &req, nil
}

// SetTransactionID writes the FK linking sign_request → transactions.
// No-op if the row doesn't exist (returns ErrNotFound) so callers can
// treat "we lost the race / the request was deleted" as benign.
func (r *GormRequestRepository) SetTransactionID(ctx context.Context, id types.SignRequestID, transactionID string) error {
	result := r.db.WithContext(ctx).Model(&types.SignRequest{}).
		Where("id = ?", id).
		Update("transaction_id", transactionID)
	if result.Error != nil {
		return fmt.Errorf("failed to set transaction_id: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}
