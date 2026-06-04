//go:build integration

package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func newTxTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=private", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.Transaction{}))
	return db
}

func TestTransactionRepo_CreateGetByHash(t *testing.T) {
	repo, err := NewGormTransactionRepository(newTxTestDB(t))
	require.NoError(t, err)
	ctx := context.Background()

	now := time.Now()
	tx := &types.Transaction{
		ID:            "tx-1",
		SignRequestID: "req-1",
		ChainID:       "56",
		TxHash:        "0xabcDEF",
		FromAddress:   "0xC0FFEE",
		Status:        types.TxStatusBroadcasted,
		BroadcastedAt: now,
	}
	require.NoError(t, repo.Create(ctx, tx))

	// Lookup is case-insensitive on tx_hash (chains return mixed
	// case, dApps sometimes lowercase) — the repo lowercases at
	// query time so callers don't have to.
	got, err := repo.GetByHash(ctx, "56", "0xABCdef")
	require.NoError(t, err)
	assert.Equal(t, "tx-1", got.ID)
	assert.Equal(t, types.TxStatusBroadcasted, got.Status)

	// (chain_id, tx_hash) is unique together — same hash on a
	// different chain is a distinct row.
	require.NoError(t, repo.Create(ctx, &types.Transaction{
		ID: "tx-1-on-mainnet", ChainID: "1", TxHash: "0xabcdef",
		Status: types.TxStatusBroadcasted, BroadcastedAt: now,
	}))
	on1, err := repo.GetByHash(ctx, "1", "0xabcdef")
	require.NoError(t, err)
	assert.Equal(t, "tx-1-on-mainnet", on1.ID)
}

func TestTransactionRepo_GetBySignRequestID(t *testing.T) {
	repo, err := NewGormTransactionRepository(newTxTestDB(t))
	require.NoError(t, err)
	ctx := context.Background()

	tx := &types.Transaction{
		ID: "tx-1", SignRequestID: "req-42", ChainID: "1", TxHash: "0xa",
		Status: types.TxStatusBroadcasted, BroadcastedAt: time.Now(),
	}
	require.NoError(t, repo.Create(ctx, tx))

	got, err := repo.GetBySignRequestID(ctx, "req-42")
	require.NoError(t, err)
	assert.Equal(t, "tx-1", got.ID)

	_, err = repo.GetBySignRequestID(ctx, "no-such-req")
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestTransactionRepo_ListPendingOrdering(t *testing.T) {
	// The poller relies on never-polled (LastCheckedAt NULL) txs
	// coming first, then oldest-checked. This test pins that order
	// so a future "let's just ORDER BY created_at" refactor
	// can't accidentally turn the queue into LIFO and starve fresh
	// txs behind ones that were polled minutes ago.
	repo, err := NewGormTransactionRepository(newTxTestDB(t))
	require.NoError(t, err)
	ctx := context.Background()

	now := time.Now()
	mins := func(n int) *time.Time { t := now.Add(time.Duration(-n) * time.Minute); return &t }

	insert := func(id string, last *time.Time, status types.TransactionStatus) {
		require.NoError(t, repo.Create(ctx, &types.Transaction{
			ID: id, ChainID: "1", TxHash: "0x" + id, Status: status,
			BroadcastedAt: now, LastCheckedAt: last,
		}))
	}
	insert("never", nil, types.TxStatusBroadcasted)
	insert("polled-5m", mins(5), types.TxStatusBroadcasted)
	insert("polled-1m", mins(1), types.TxStatusBroadcasted)
	insert("mined", nil, types.TxStatusMined) // must NOT appear in pending

	got, err := repo.ListPending(ctx, 10)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "never", got[0].ID)     // null last_checked first
	assert.Equal(t, "polled-5m", got[1].ID) // older check next
	assert.Equal(t, "polled-1m", got[2].ID)
}

func TestTransactionRepo_ListFilter_APIKeyIDScope(t *testing.T) {
	// The transactions handler enforces per-caller visibility by
	// passing APIKeyID to this filter. Test the join via sign_requests
	// works as intended: only txs whose sign_request.api_key_id
	// matches the filter come back, regardless of from_address.
	db := newTxTestDB(t)
	require.NoError(t, db.AutoMigrate(&types.SignRequest{}))
	txRepo, err := NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := NewGormRequestRepository(db)
	require.NoError(t, err)
	ctx := context.Background()
	now := time.Now()

	// Two sign requests, two keys.
	require.NoError(t, reqRepo.Create(ctx, &types.SignRequest{
		ID: "req-alice", APIKeyID: "alice", ChainType: types.ChainTypeEVM,
		ChainID: "1", Status: types.StatusCompleted, CreatedAt: now,
	}))
	require.NoError(t, reqRepo.Create(ctx, &types.SignRequest{
		ID: "req-bob", APIKeyID: "bob", ChainType: types.ChainTypeEVM,
		ChainID: "1", Status: types.StatusCompleted, CreatedAt: now,
	}))
	require.NoError(t, txRepo.Create(ctx, &types.Transaction{
		ID: "tx-alice", SignRequestID: "req-alice", ChainID: "1",
		TxHash: "0x1", Status: types.TxStatusMined, BroadcastedAt: now,
	}))
	require.NoError(t, txRepo.Create(ctx, &types.Transaction{
		ID: "tx-bob", SignRequestID: "req-bob", ChainID: "1",
		TxHash: "0x2", Status: types.TxStatusMined, BroadcastedAt: now,
	}))
	// Orphan tx (no sign request) — must NOT leak to either key.
	require.NoError(t, txRepo.Create(ctx, &types.Transaction{
		ID: "tx-orphan", ChainID: "1", TxHash: "0x3",
		Status: types.TxStatusBroadcasted, BroadcastedAt: now,
	}))

	got, err := txRepo.List(ctx, types.TransactionFilter{APIKeyID: "alice"})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "tx-alice", got[0].ID)
}

func TestTransactionRepo_ListFilter(t *testing.T) {
	repo, err := NewGormTransactionRepository(newTxTestDB(t))
	require.NoError(t, err)
	ctx := context.Background()

	now := time.Now()
	mk := func(id, chain, from string, status types.TransactionStatus) {
		require.NoError(t, repo.Create(ctx, &types.Transaction{
			ID: id, ChainID: chain, TxHash: "0x" + id, FromAddress: from,
			Status: status, BroadcastedAt: now,
		}))
	}
	mk("a", "1", "0xAA", types.TxStatusMined)
	mk("b", "1", "0xBB", types.TxStatusBroadcasted)
	mk("c", "56", "0xAA", types.TxStatusMined)

	// Filter by chain isolates rows.
	bsc, err := repo.List(ctx, types.TransactionFilter{ChainID: "56"})
	require.NoError(t, err)
	require.Len(t, bsc, 1)
	assert.Equal(t, "c", bsc[0].ID)

	// Filter by status.
	mined := types.TxStatusMined
	minedRows, err := repo.List(ctx, types.TransactionFilter{Status: &mined})
	require.NoError(t, err)
	assert.Len(t, minedRows, 2)

	// Filter by from address is case-insensitive (the repo
	// lowercases both sides at query time).
	from0xaa, err := repo.List(ctx, types.TransactionFilter{FromAddress: "0xaa"})
	require.NoError(t, err)
	assert.Len(t, from0xaa, 2)
}

func TestTransactionRepo_ListFilter_SignTypeAndRole(t *testing.T) {
	db := newTxTestDB(t)
	require.NoError(t, db.AutoMigrate(&types.SignRequest{}, &types.APIKey{}))
	reqRepo, err := NewGormRequestRepository(db)
	require.NoError(t, err)
	txRepo, err := NewGormTransactionRepository(db)
	require.NoError(t, err)
	ctx := context.Background()
	now := time.Now()

	require.NoError(t, db.Create(&types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}).Error)
	require.NoError(t, db.Create(&types.APIKey{ID: "admin-key", Role: types.RoleAdmin, Enabled: true}).Error)
	require.NoError(t, reqRepo.Create(ctx, &types.SignRequest{
		ID: "req-agent", APIKeyID: "agent-key", ChainType: types.ChainTypeEVM,
		ChainID: "1", SignType: "transaction", Status: types.StatusCompleted, CreatedAt: now,
	}))
	require.NoError(t, reqRepo.Create(ctx, &types.SignRequest{
		ID: "req-admin", APIKeyID: "admin-key", ChainType: types.ChainTypeEVM,
		ChainID: "1", SignType: "typed_data", Status: types.StatusCompleted, CreatedAt: now,
	}))
	require.NoError(t, txRepo.Create(ctx, &types.Transaction{
		ID: "tx-agent", SignRequestID: "req-agent", ChainID: "1", TxHash: "0xa",
		Status: types.TxStatusBroadcasted, BroadcastedAt: now,
	}))
	require.NoError(t, txRepo.Create(ctx, &types.Transaction{
		ID: "tx-admin", SignRequestID: "req-admin", ChainID: "1", TxHash: "0xb",
		Status: types.TxStatusBroadcasted, BroadcastedAt: now,
	}))

	byType, err := txRepo.List(ctx, types.TransactionFilter{SignType: "transaction"})
	require.NoError(t, err)
	require.Len(t, byType, 1)
	assert.Equal(t, "tx-agent", byType[0].ID)

	byRole, err := txRepo.List(ctx, types.TransactionFilter{APIKeyRole: types.RoleAgent})
	require.NoError(t, err)
	require.Len(t, byRole, 1)
	assert.Equal(t, "tx-agent", byRole[0].ID)
}
