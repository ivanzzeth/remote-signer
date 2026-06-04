// Package storage — transaction_repo.go owns the on-chain Transaction
// persistence layer. Reuses the Gorm pattern of every other repo so the
// daemon's bootstrap, migrations, and observability paths don't have
// to special-case it.

package storage

import (
	"context"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TransactionRepository defines the persistence surface the wallet
// RPC proxy + receipt-polling service depend on.
type TransactionRepository interface {
	Create(ctx context.Context, tx *types.Transaction) error
	Get(ctx context.Context, id string) (*types.Transaction, error)
	GetByHash(ctx context.Context, chainID, txHash string) (*types.Transaction, error)
	GetBySignRequestID(ctx context.Context, signRequestID string) (*types.Transaction, error)
	// ListPending returns broadcasted-but-not-yet-mined txs ordered by
	// LastCheckedAt ASC so the poller naturally throttles fresh
	// checks (txs that were recently polled stay at the tail of the
	// queue until they age past the others).
	ListPending(ctx context.Context, limit int) ([]*types.Transaction, error)
	List(ctx context.Context, filter types.TransactionFilter) ([]*types.Transaction, error)
	Count(ctx context.Context, filter types.TransactionFilter) (int, error)
	Update(ctx context.Context, tx *types.Transaction) error
}

// GormTransactionRepository implements TransactionRepository against Gorm.
type GormTransactionRepository struct {
	db *gorm.DB
}

// NewGormTransactionRepository validates the handle and returns a ready repo.
func NewGormTransactionRepository(db *gorm.DB) (*GormTransactionRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	return &GormTransactionRepository{db: db}, nil
}

func (r *GormTransactionRepository) Create(ctx context.Context, tx *types.Transaction) error {
	if tx == nil {
		return fmt.Errorf("transaction cannot be nil")
	}
	return r.db.WithContext(ctx).Create(tx).Error
}

func (r *GormTransactionRepository) Get(ctx context.Context, id string) (*types.Transaction, error) {
	var tx types.Transaction
	if err := r.db.WithContext(ctx).First(&tx, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, types.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}
	return &tx, nil
}

// GetByHash looks up by the (chain_id, tx_hash) compound — tx hashes
// are not globally unique, only unique within a chain.
func (r *GormTransactionRepository) GetByHash(ctx context.Context, chainID, txHash string) (*types.Transaction, error) {
	var tx types.Transaction
	err := r.db.WithContext(ctx).
		Where("chain_id = ? AND lower(tx_hash) = ?", chainID, strings.ToLower(txHash)).
		First(&tx).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, types.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get transaction by hash: %w", err)
	}
	return &tx, nil
}

func (r *GormTransactionRepository) GetBySignRequestID(ctx context.Context, signRequestID string) (*types.Transaction, error) {
	var tx types.Transaction
	err := r.db.WithContext(ctx).
		Where("sign_request_id = ?", signRequestID).
		First(&tx).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, types.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get transaction by sign request: %w", err)
	}
	return &tx, nil
}

func (r *GormTransactionRepository) ListPending(ctx context.Context, limit int) ([]*types.Transaction, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []*types.Transaction
	// last_checked_at NULL first (never polled), then oldest checks
	// first — keeps the poller queue self-throttling without an
	// external scheduler. CASE WHEN works on both sqlite + postgres.
	err := r.db.WithContext(ctx).
		Where("status = ?", types.TxStatusBroadcasted).
		Order("CASE WHEN last_checked_at IS NULL THEN 0 ELSE 1 END ASC, last_checked_at ASC").
		Limit(limit).
		Find(&out).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list pending transactions: %w", err)
	}
	return out, nil
}

func (r *GormTransactionRepository) List(ctx context.Context, filter types.TransactionFilter) ([]*types.Transaction, error) {
	q := r.applyFilter(r.db.WithContext(ctx).Model(&types.Transaction{}), filter)
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 500 {
		filter.Limit = 500
	}
	var out []*types.Transaction
	if err := q.Order("created_at DESC").Limit(filter.Limit).Offset(filter.Offset).Find(&out).Error; err != nil {
		return nil, fmt.Errorf("failed to list transactions: %w", err)
	}
	return out, nil
}

func (r *GormTransactionRepository) Count(ctx context.Context, filter types.TransactionFilter) (int, error) {
	q := r.applyFilter(r.db.WithContext(ctx).Model(&types.Transaction{}), filter)
	var n int64
	if err := q.Count(&n).Error; err != nil {
		return 0, fmt.Errorf("failed to count transactions: %w", err)
	}
	return int(n), nil
}

func (r *GormTransactionRepository) Update(ctx context.Context, tx *types.Transaction) error {
	if tx == nil {
		return fmt.Errorf("transaction cannot be nil")
	}
	return r.db.WithContext(ctx).Save(tx).Error
}

func (r *GormTransactionRepository) applyFilter(q *gorm.DB, f types.TransactionFilter) *gorm.DB {
	if f.SignRequestID != "" {
		q = q.Where("sign_request_id = ?", f.SignRequestID)
	}
	if f.ChainID != "" {
		q = q.Where("chain_id = ?", f.ChainID)
	}
	if f.FromAddress != "" {
		q = q.Where("lower(from_address) = ?", strings.ToLower(f.FromAddress))
	}
	if f.Status != nil {
		q = q.Where("status = ?", *f.Status)
	}
	if f.APIKeyID != "" {
		// Subquery scope to "txs whose linked sign_request belongs to
		// this api key". Subquery (not join) so the row shape stays
		// the same — callers don't need to learn about the FK side.
		q = q.Where("sign_request_id IN (?)",
			r.db.Table("sign_requests").Select("id").Where("api_key_id = ?", f.APIKeyID))
	}
	if f.SignType != "" {
		q = q.Where("sign_request_id IN (?)",
			r.db.Table("sign_requests").Select("id").Where("sign_type = ?", f.SignType))
	}
	if f.APIKeyRole != "" {
		q = q.Where("sign_request_id IN (?)",
			r.db.Table("sign_requests").Select("id").Where("api_key_id IN (?)",
				r.db.Table("api_keys").Select("id").Where("role = ?", f.APIKeyRole)))
	}
	return q
}
