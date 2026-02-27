package storage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInMemoryNonceStore(t *testing.T) {
	store, err := NewInMemoryNonceStore(time.Minute)
	require.NoError(t, err)
	assert.NotNil(t, store)
	defer store.Close()
}

func TestNewInMemoryNonceStore_ZeroInterval(t *testing.T) {
	// Should default to 1 minute
	store, err := NewInMemoryNonceStore(0)
	require.NoError(t, err)
	assert.NotNil(t, store)
	defer store.Close()
}

func TestCheckAndStore_NewNonce(t *testing.T) {
	store, _ := NewInMemoryNonceStore(time.Minute)
	defer store.Close()

	ctx := context.Background()
	isNew, err := store.CheckAndStore(ctx, "key-1", "nonce-1", time.Minute)
	require.NoError(t, err)
	assert.True(t, isNew, "first nonce should be new")
}

func TestCheckAndStore_ReplayDetection(t *testing.T) {
	store, _ := NewInMemoryNonceStore(time.Minute)
	defer store.Close()

	ctx := context.Background()

	// First store
	isNew, err := store.CheckAndStore(ctx, "key-1", "nonce-1", time.Minute)
	require.NoError(t, err)
	assert.True(t, isNew)

	// Replay attempt
	isNew, err = store.CheckAndStore(ctx, "key-1", "nonce-1", time.Minute)
	require.NoError(t, err)
	assert.False(t, isNew, "duplicate nonce should be detected as replay")
}

func TestCheckAndStore_DifferentApiKeys(t *testing.T) {
	store, _ := NewInMemoryNonceStore(time.Minute)
	defer store.Close()

	ctx := context.Background()

	// Same nonce, different API keys should both be new
	isNew1, err := store.CheckAndStore(ctx, "key-1", "nonce-1", time.Minute)
	require.NoError(t, err)
	assert.True(t, isNew1)

	isNew2, err := store.CheckAndStore(ctx, "key-2", "nonce-1", time.Minute)
	require.NoError(t, err)
	assert.True(t, isNew2, "same nonce with different API key should be allowed")
}

func TestCheckAndStore_ExpiredNonceReuse(t *testing.T) {
	store, _ := NewInMemoryNonceStore(time.Minute)
	defer store.Close()

	ctx := context.Background()

	// Store with very short TTL
	isNew, err := store.CheckAndStore(ctx, "key-1", "nonce-exp", 10*time.Millisecond)
	require.NoError(t, err)
	assert.True(t, isNew)

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Should be new again (expired)
	isNew, err = store.CheckAndStore(ctx, "key-1", "nonce-exp", time.Minute)
	require.NoError(t, err)
	assert.True(t, isNew, "expired nonce should be reusable")
}

func TestCheckAndStore_KeyCollisionPrevention(t *testing.T) {
	store, _ := NewInMemoryNonceStore(time.Minute)
	defer store.Close()

	ctx := context.Background()

	// These would collide with simple concatenation "a:b:c"
	// But length-prefixed format makes them different
	isNew1, err := store.CheckAndStore(ctx, "a", "b:c", time.Minute)
	require.NoError(t, err)
	assert.True(t, isNew1)

	isNew2, err := store.CheckAndStore(ctx, "a:b", "c", time.Minute)
	require.NoError(t, err)
	assert.True(t, isNew2, "should not collide with different key/nonce combination")
}

func TestCleanup(t *testing.T) {
	store, _ := NewInMemoryNonceStore(time.Minute)
	defer store.Close()

	ctx := context.Background()

	// Add some nonces with short TTL
	store.CheckAndStore(ctx, "key-1", "n1", 10*time.Millisecond)
	store.CheckAndStore(ctx, "key-1", "n2", 10*time.Millisecond)
	store.CheckAndStore(ctx, "key-1", "n3", time.Hour) // this one doesn't expire

	time.Sleep(20 * time.Millisecond)

	// Manual cleanup
	store.cleanup()

	store.mu.RLock()
	count := len(store.nonces)
	store.mu.RUnlock()

	assert.Equal(t, 1, count, "only non-expired nonce should remain")
}

func TestClose(t *testing.T) {
	store, _ := NewInMemoryNonceStore(time.Minute)
	err := store.Close()
	assert.NoError(t, err)
}
