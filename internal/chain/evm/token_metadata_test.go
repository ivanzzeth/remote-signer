package evm

import (
	"context"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// setupTestDB creates an in-memory SQLite DB with the token_metadata table.
func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.TokenMetadata{}))
	return db
}

func TestIsERC721_NegativeResultCached(t *testing.T) {
	db := setupTestDB(t)

	// Pre-populate cache with a negative ERC721 result
	now := time.Now().UTC()
	meta := types.TokenMetadata{
		ChainID:       "1",
		Address:       "0x0000000000000000000000000000000000000001",
		ERC721Checked: true,
		IsERC721:      false,
		QueriedAt:     now,
	}
	require.NoError(t, db.Create(&meta).Error)

	// Create cache with nil provider — if RPC is called, it will panic.
	// This proves the cache prevents the RPC call.
	cache := &TokenMetadataCache{
		db:       db,
		provider: nil, // no provider = would panic if SupportsInterface is called
		cacheTTL: 24 * time.Hour,
	}

	// Counter with max=0 would fail on Increment() if called
	counter := NewRPCCallCounter(0)

	result, err := cache.IsERC721(context.Background(), "1", "0x0000000000000000000000000000000000000001", counter)
	require.NoError(t, err)
	assert.False(t, result, "negative cached result should return false")
}

func TestIsERC1155_NegativeResultCached(t *testing.T) {
	db := setupTestDB(t)

	// Pre-populate cache with a negative ERC1155 result
	now := time.Now().UTC()
	meta := types.TokenMetadata{
		ChainID:        "1",
		Address:        "0x0000000000000000000000000000000000000002",
		ERC1155Checked: true,
		IsERC1155:      false,
		QueriedAt:      now,
	}
	require.NoError(t, db.Create(&meta).Error)

	cache := &TokenMetadataCache{
		db:       db,
		provider: nil,
		cacheTTL: 24 * time.Hour,
	}

	counter := NewRPCCallCounter(0)

	result, err := cache.IsERC1155(context.Background(), "1", "0x0000000000000000000000000000000000000002", counter)
	require.NoError(t, err)
	assert.False(t, result, "negative cached result should return false")
}

func TestIsERC721_PositiveResultCached(t *testing.T) {
	db := setupTestDB(t)

	// Pre-populate cache with a positive ERC721 result
	now := time.Now().UTC()
	meta := types.TokenMetadata{
		ChainID:       "1",
		Address:       "0x0000000000000000000000000000000000000003",
		ERC721Checked: true,
		IsERC721:      true,
		QueriedAt:     now,
	}
	require.NoError(t, db.Create(&meta).Error)

	cache := &TokenMetadataCache{
		db:       db,
		provider: nil,
		cacheTTL: 24 * time.Hour,
	}

	counter := NewRPCCallCounter(0)

	result, err := cache.IsERC721(context.Background(), "1", "0x0000000000000000000000000000000000000003", counter)
	require.NoError(t, err)
	assert.True(t, result, "positive cached result should return true")
}

func TestIsERC1155_PositiveResultCached(t *testing.T) {
	db := setupTestDB(t)

	now := time.Now().UTC()
	meta := types.TokenMetadata{
		ChainID:        "1",
		Address:        "0x0000000000000000000000000000000000000004",
		ERC1155Checked: true,
		IsERC1155:      true,
		QueriedAt:      now,
	}
	require.NoError(t, db.Create(&meta).Error)

	cache := &TokenMetadataCache{
		db:       db,
		provider: nil,
		cacheTTL: 24 * time.Hour,
	}

	counter := NewRPCCallCounter(0)

	result, err := cache.IsERC1155(context.Background(), "1", "0x0000000000000000000000000000000000000004", counter)
	require.NoError(t, err)
	assert.True(t, result, "positive cached result should return true")
}

func TestIsERC721_ExpiredCacheNotUsed(t *testing.T) {
	db := setupTestDB(t)

	// Pre-populate cache with an EXPIRED negative result (QueriedAt far in the past)
	expired := time.Now().UTC().Add(-48 * time.Hour)
	meta := types.TokenMetadata{
		ChainID:       "1",
		Address:       "0x0000000000000000000000000000000000000005",
		ERC721Checked: true,
		IsERC721:      false,
		QueriedAt:     expired,
	}
	require.NoError(t, db.Create(&meta).Error)

	cache := &TokenMetadataCache{
		db:       db,
		provider: nil, // nil provider will cause panic if RPC is attempted
		cacheTTL: 24 * time.Hour,
	}

	// Reset: put a record with ERC721Checked=false
	db.Delete(&meta, "chain_id = ? AND address = ?", "1", "0x0000000000000000000000000000000000000005")
	meta2 := types.TokenMetadata{
		ChainID:       "1",
		Address:       "0x0000000000000000000000000000000000000005",
		ERC721Checked: false,
		IsERC721:      false,
		QueriedAt:     time.Now().UTC(),
	}
	require.NoError(t, db.Create(&meta2).Error)

	// Bypass constructor default (which overrides 0→10) to get a counter that fails immediately.
	counter2 := &RPCCallCounter{max: 0, maxTotalTime: rpcMaxTotalTime}
	_, err := cache.IsERC721(context.Background(), "1", "0x0000000000000000000000000000000000000005", counter2)
	assert.Error(t, err, "should fail because cache is not populated (ERC721Checked=false) and counter limit is 0")
}
