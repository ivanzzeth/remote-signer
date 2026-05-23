package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------------------------------------------------------------------------
// hexToUint64
// ---------------------------------------------------------------------------

func TestHexToUint64(t *testing.T) {
	tests := []struct {
		input    string
		expected uint64
		ok       bool
	}{
		{"0x0", 0, true},
		{"0x1", 1, true},
		{"0xff", 255, true},
		{"0x10", 16, true},
		{"0xABCDEF", 11259375, true},
		{"0X1", 1, true},
		{"0x", 0, false},
		{"", 0, false},
		{"0xGG", 0, false},
		{"nothex", 0, false},
		{"1", 1, true},  // without 0x prefix
		{"ff", 255, true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			v, ok := hexToUint64(tc.input)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.expected, v)
		})
	}
}

// ---------------------------------------------------------------------------
// isNullReceipt
// ---------------------------------------------------------------------------

func TestIsNullReceipt(t *testing.T) {
	tests := []struct {
		name  string
		input json.RawMessage
		null  bool
	}{
		{"null literal", json.RawMessage("null"), true},
		{"empty string", json.RawMessage(""), true},
		{"whitespace only", json.RawMessage("  "), true},
		{"null with spaces", json.RawMessage("  null  "), true},
		{"valid receipt", json.RawMessage(`{"blockNumber":"0x1"}`), false},
		{"empty object", json.RawMessage(`{}`), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.null, isNullReceipt(tc.input))
		})
	}
}

// ---------------------------------------------------------------------------
// decodeHexBytes
// ---------------------------------------------------------------------------

func TestDecodeHexBytes(t *testing.T) {
	t.Run("with_0x_prefix", func(t *testing.T) {
		b, err := decodeHexBytes("0xdeadbeef")
		assert.NoError(t, err)
		assert.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, b)
	})

	t.Run("with_0X_prefix", func(t *testing.T) {
		b, err := decodeHexBytes("0Xdeadbeef")
		assert.NoError(t, err)
		assert.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, b)
	})

	t.Run("without_prefix", func(t *testing.T) {
		b, err := decodeHexBytes("deadbeef")
		assert.NoError(t, err)
		assert.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, b)
	})

		t.Run("empty_string", func(t *testing.T) {
			b, err := decodeHexBytes("")
			assert.NoError(t, err)
			assert.Empty(t, b)
		})

	t.Run("invalid_hex", func(t *testing.T) {
		_, err := decodeHexBytes("0xgggg")
		assert.Error(t, err)
	})

	t.Run("with_whitespace", func(t *testing.T) {
		b, err := decodeHexBytes("  0xdead  ")
		assert.NoError(t, err)
		assert.Equal(t, []byte{0xde, 0xad}, b)
	})
}

// ---------------------------------------------------------------------------
// isLockedSignerErr (defined in sign.go)
// ---------------------------------------------------------------------------

func TestIsLockedSignerErr(t *testing.T) {
	t.Run("nil_error", func(t *testing.T) {
		assert.False(t, isLockedSignerErr(nil))
	})

	t.Run("error_contains_is_locked", func(t *testing.T) {
		err := errors.New("signer is locked")
		assert.True(t, isLockedSignerErr(err))
	})

	t.Run("error_contains_locked_signer_phrase", func(t *testing.T) {
		err := errors.New("failed to get signer: signer is locked")
		assert.True(t, isLockedSignerErr(err))
	})

	t.Run("error_does_not_contain_locked", func(t *testing.T) {
		err := errors.New("signer not found")
		assert.False(t, isLockedSignerErr(err))
	})

	t.Run("error_contains_is_locked_as_substring", func(t *testing.T) {
		err := errors.New("the device is locked and cannot be used")
		assert.True(t, isLockedSignerErr(err))
	})

	t.Run("empty_error", func(t *testing.T) {
		err := errors.New("")
		assert.False(t, isLockedSignerErr(err))
	})
}

// ---------------------------------------------------------------------------
// NewTransactionService validation
// ---------------------------------------------------------------------------

func TestNewTransactionServiceValidation(t *testing.T) {
	t.Run("nil_repo", func(t *testing.T) {
		_, err := NewTransactionService(nil, nil, nil, txServiceLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "transaction repository is required")
	})

	t.Run("nil_request_repo", func(t *testing.T) {
		db := newTxExtTestDB(t)
		txRepo, err := storage.NewGormTransactionRepository(db)
		require.NoError(t, err)
		_, err = NewTransactionService(txRepo, nil, nil, txServiceLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "request repository is required")
	})

	t.Run("nil_logger", func(t *testing.T) {
		db := newTxExtTestDB(t)
		txRepo, err := storage.NewGormTransactionRepository(db)
		require.NoError(t, err)
		reqRepo, err := storage.NewGormRequestRepository(db)
		require.NoError(t, err)
		_, err = NewTransactionService(txRepo, reqRepo, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})
}

// ---------------------------------------------------------------------------
// WithGracePeriod
// ---------------------------------------------------------------------------

func TestWithGracePeriodMethod(t *testing.T) {
	db := newTxExtTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)

	svc, err := NewTransactionService(txRepo, reqRepo, nil, txServiceLogger())
	require.NoError(t, err)

	t.Run("default_grace_period", func(t *testing.T) {
		assert.Equal(t, 10*time.Minute, svc.gracePeriod)
	})

	t.Run("overrides_with_duration", func(t *testing.T) {
		svc.WithGracePeriod(30 * time.Second)
		assert.Equal(t, 30*time.Second, svc.gracePeriod)
	})

	t.Run("zero_duration", func(t *testing.T) {
		svc.WithGracePeriod(0)
		assert.Equal(t, time.Duration(0), svc.gracePeriod)
	})

	t.Run("returns_self_for_chaining", func(t *testing.T) {
		result := svc.WithGracePeriod(5 * time.Minute)
		assert.Same(t, svc, result)
	})
}

// newTxExtTestDB creates an in-memory SQLite database for transaction ext tests.
func newTxExtTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=private", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.Transaction{}, &types.SignRequest{}))
	return db
}

// ---------------------------------------------------------------------------
// TestTransactionService_Run
// ---------------------------------------------------------------------------

func TestTransactionService_Run_NilRPC(t *testing.T) {
	// When RPC is nil, Run should return immediately (short circuit).
	db := newTxExtTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)
	svc, err := NewTransactionService(txRepo, reqRepo, nil, txServiceLogger())
	require.NoError(t, err)

	// Run with nil RPC returns immediately without blocking
	ctx := context.Background()
	svc.Run(ctx, time.Minute)
	// If we get here without deadlock, the nil RPC short-circuit works
}

func TestTransactionService_Run_CancelledCtx(t *testing.T) {
	// When ctx is cancelled, Run should exit cleanly even with an RPC provider.
	db := newTxExtTestDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)

	// Create an RPC provider with a dummy URL so the loop path is exercised
	rpc, err := evmchain.NewRPCProvider("http://127.0.0.1:1", "")
	require.NoError(t, err)

	svc, err := NewTransactionService(txRepo, reqRepo, rpc, txServiceLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	// Run should observe ctx.Done() and return without blocking
	svc.Run(ctx, 10*time.Millisecond)
}
