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
