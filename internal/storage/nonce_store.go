package storage

import (
	"context"
	"sync"
	"time"
)

// NonceStore provides storage for request nonces to prevent replay attacks.
// Nonces are stored with TTL and automatically cleaned up.
type NonceStore interface {
	// CheckAndStore checks if a nonce exists and stores it if not.
	// Returns true if the nonce was stored (new), false if it already exists (replay).
	CheckAndStore(ctx context.Context, apiKeyID, nonce string, ttl time.Duration) (bool, error)
}

// InMemoryNonceStore implements NonceStore with in-memory storage.
// Suitable for single-instance deployments. For multi-instance deployments,
// use Redis-based implementation.
type InMemoryNonceStore struct {
	mu     sync.RWMutex
	nonces map[string]time.Time // key: apiKeyID:nonce, value: expiration time
	stopCh chan struct{}
}

// NewInMemoryNonceStore creates a new in-memory nonce store.
// cleanupInterval specifies how often to run cleanup of expired nonces.
func NewInMemoryNonceStore(cleanupInterval time.Duration) (*InMemoryNonceStore, error) {
	if cleanupInterval <= 0 {
		cleanupInterval = time.Minute
	}

	store := &InMemoryNonceStore{
		nonces: make(map[string]time.Time),
		stopCh: make(chan struct{}),
	}

	// Start cleanup goroutine
	go store.cleanupLoop(cleanupInterval)

	return store, nil
}

// CheckAndStore checks if a nonce exists and stores it if not.
// Returns true if the nonce was stored (new), false if it already exists (replay).
func (s *InMemoryNonceStore) CheckAndStore(ctx context.Context, apiKeyID, nonce string, ttl time.Duration) (bool, error) {
	key := apiKeyID + ":" + nonce
	expireAt := time.Now().Add(ttl)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if nonce exists and is not expired
	if existingExpire, exists := s.nonces[key]; exists {
		if time.Now().Before(existingExpire) {
			// Nonce exists and not expired - this is a replay attack
			return false, nil
		}
		// Nonce expired, can be reused (though unlikely with proper TTL)
	}

	// Store new nonce
	s.nonces[key] = expireAt
	return true, nil
}

// Close stops the cleanup goroutine
func (s *InMemoryNonceStore) Close() error {
	close(s.stopCh)
	return nil
}

// cleanupLoop periodically removes expired nonces
func (s *InMemoryNonceStore) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

// cleanup removes expired nonces
func (s *InMemoryNonceStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, expireAt := range s.nonces {
		if now.After(expireAt) {
			delete(s.nonces, key)
		}
	}
}

// Compile-time check
var _ NonceStore = (*InMemoryNonceStore)(nil)
