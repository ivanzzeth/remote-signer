package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// AdminMiddleware
// ---------------------------------------------------------------------------

func TestAdminMiddleware_NoAPIKeyInContext(t *testing.T) {
	logger := newTestLogger()
	mw := AdminMiddleware(logger)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called when there is no API key")
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestAdminMiddleware_NonAdminKey(t *testing.T) {
	logger := newTestLogger()
	mw := AdminMiddleware(logger)

	apiKey := &types.APIKey{
		ID:    "key-1",
		Name:  "regular-key",
		Admin: false,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called for non-admin key")
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	ctx := context.WithValue(req.Context(), APIKeyContextKey, apiKey)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestAdminMiddleware_AdminKey(t *testing.T) {
	logger := newTestLogger()
	mw := AdminMiddleware(logger)

	apiKey := &types.APIKey{
		ID:    "key-admin",
		Name:  "admin-key",
		Admin: true,
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	ctx := context.WithValue(req.Context(), APIKeyContextKey, apiKey)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.True(t, called, "next handler should be called for admin key")
	assert.Equal(t, http.StatusOK, rr.Code)
}

// ---------------------------------------------------------------------------
// GetAPIKey
// ---------------------------------------------------------------------------

func TestGetAPIKey_NoValueInContext(t *testing.T) {
	ctx := context.Background()
	result := GetAPIKey(ctx)
	assert.Nil(t, result)
}

func TestGetAPIKey_WrongTypeInContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), APIKeyContextKey, "not-an-api-key")
	result := GetAPIKey(ctx)
	assert.Nil(t, result)
}

func TestGetAPIKey_ValidAPIKey(t *testing.T) {
	apiKey := &types.APIKey{
		ID:   "key-valid",
		Name: "valid-key",
	}
	ctx := context.WithValue(context.Background(), APIKeyContextKey, apiKey)
	result := GetAPIKey(ctx)
	require.NotNil(t, result)
	assert.Equal(t, "key-valid", result.ID)
	assert.Equal(t, "valid-key", result.Name)
}

// ---------------------------------------------------------------------------
// LoggingMiddleware
// ---------------------------------------------------------------------------

func TestLoggingMiddleware_NormalRequest(t *testing.T) {
	logger := newTestLogger()
	mw := LoggingMiddleware(logger)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.True(t, called, "next handler should be called")
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestLoggingMiddleware_WithAPIKeyInContext(t *testing.T) {
	logger := newTestLogger()
	mw := LoggingMiddleware(logger)

	apiKey := &types.APIKey{
		ID:   "key-log-test",
		Name: "log-test-key",
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/sign", nil)
	ctx := context.WithValue(req.Context(), APIKeyContextKey, apiKey)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.True(t, called, "next handler should be called")
	assert.Equal(t, http.StatusCreated, rr.Code)
}

func TestResponseWriter_WriteHeader(t *testing.T) {
	rr := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: rr,
		statusCode:     http.StatusOK,
	}

	rw.WriteHeader(http.StatusNotFound)
	assert.Equal(t, http.StatusNotFound, rw.statusCode, "statusCode should be captured")
	assert.Equal(t, http.StatusNotFound, rr.Code, "underlying writer should also receive the status")
}

// ---------------------------------------------------------------------------
// RecoveryMiddleware
// ---------------------------------------------------------------------------

func TestRecoveryMiddleware_PanicHandler(t *testing.T) {
	logger := newTestLogger()
	mw := RecoveryMiddleware(logger)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("something went wrong")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRecoveryMiddleware_NormalHandler(t *testing.T) {
	logger := newTestLogger()
	mw := RecoveryMiddleware(logger)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.True(t, called, "next handler should be called")
	assert.Equal(t, http.StatusOK, rr.Code)
}

// ---------------------------------------------------------------------------
// RateLimiter / RateLimitMiddleware
// ---------------------------------------------------------------------------

func TestNewRateLimiter(t *testing.T) {
	logger := newTestLogger()
	rl := NewRateLimiter(logger)
	require.NotNil(t, rl)
	require.NotNil(t, rl.windows)
}

func TestRateLimiter_Allow_FirstRequest(t *testing.T) {
	logger := newTestLogger()
	rl := NewRateLimiter(logger)
	assert.True(t, rl.Allow("key1", 10), "first request should be allowed")
}

func TestRateLimiter_Allow_UpToLimit(t *testing.T) {
	logger := newTestLogger()
	rl := NewRateLimiter(logger)

	limit := 5
	for i := 0; i < limit; i++ {
		assert.True(t, rl.Allow("key-limit", limit), "request %d should be allowed", i+1)
	}
	// Next request should be denied
	assert.False(t, rl.Allow("key-limit", limit), "request beyond limit should be denied")
}

func TestRateLimiter_Allow_WindowExpiry(t *testing.T) {
	logger := newTestLogger()
	rl := NewRateLimiter(logger)

	// Use up the limit
	limit := 2
	for i := 0; i < limit; i++ {
		require.True(t, rl.Allow("key-expire", limit))
	}
	require.False(t, rl.Allow("key-expire", limit))

	// Simulate window expiry by manipulating the startTime
	rl.mu.Lock()
	w := rl.windows["key-expire"]
	w.startTime = time.Now().Add(-2 * time.Minute) // move startTime far into the past
	rl.mu.Unlock()

	// Now the window should have expired and a new one starts
	assert.True(t, rl.Allow("key-expire", limit), "request should be allowed after window expires")
}

func TestRateLimitMiddleware_NoAPIKey(t *testing.T) {
	logger := newTestLogger()
	rl := NewRateLimiter(logger)
	mw := RateLimitMiddleware(rl)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.True(t, called, "next handler should be called when no API key is present")
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRateLimitMiddleware_UnderLimit(t *testing.T) {
	logger := newTestLogger()
	rl := NewRateLimiter(logger)
	mw := RateLimitMiddleware(rl)

	apiKey := &types.APIKey{
		ID:        "key-under",
		Name:      "under-limit",
		RateLimit: 100,
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := context.WithValue(req.Context(), APIKeyContextKey, apiKey)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.True(t, called, "next handler should be called when under rate limit")
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRateLimitMiddleware_OverLimit(t *testing.T) {
	logger := newTestLogger()
	rl := NewRateLimiter(logger)
	mw := RateLimitMiddleware(rl)

	apiKey := &types.APIKey{
		ID:        "key-over",
		Name:      "over-limit",
		RateLimit: 1,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// First request should succeed
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx1 := context.WithValue(req1.Context(), APIKeyContextKey, apiKey)
	req1 = req1.WithContext(ctx1)
	rr1 := httptest.NewRecorder()
	mw(next).ServeHTTP(rr1, req1)
	assert.Equal(t, http.StatusOK, rr1.Code)

	// Second request should be rate limited
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx2 := context.WithValue(req2.Context(), APIKeyContextKey, apiKey)
	req2 = req2.WithContext(ctx2)
	rr2 := httptest.NewRecorder()
	mw(next).ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rr2.Code)
}

func TestRateLimiter_Cleanup(t *testing.T) {
	logger := newTestLogger()
	rl := NewRateLimiter(logger)

	// Add some windows
	rl.Allow("active-key", 100)
	rl.Allow("expired-key", 100)

	// Make the "expired-key" window old enough to be cleaned up (>= 2 minutes)
	rl.mu.Lock()
	rl.windows["expired-key"].startTime = time.Now().Add(-3 * time.Minute)
	rl.mu.Unlock()

	rl.Cleanup()

	rl.mu.Lock()
	_, activeExists := rl.windows["active-key"]
	_, expiredExists := rl.windows["expired-key"]
	rl.mu.Unlock()

	assert.True(t, activeExists, "active window should not be cleaned up")
	assert.False(t, expiredExists, "expired window should be cleaned up")
}

func TestRateLimiter_StartCleanupRoutine(t *testing.T) {
	logger := newTestLogger()
	rl := NewRateLimiter(logger)

	stop := make(chan struct{})
	rl.StartCleanupRoutine(50*time.Millisecond, stop)

	// Let it run for a bit
	time.Sleep(150 * time.Millisecond)

	// Stop gracefully
	close(stop)

	// Give goroutine time to exit
	time.Sleep(100 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// PermissionMiddleware
// ---------------------------------------------------------------------------

func TestPermissionMiddleware_NoAPIKey(t *testing.T) {
	logger := newTestLogger()
	mw := PermissionMiddleware(logger)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/signers", nil)
	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.True(t, called, "next handler should be called when no API key is present")
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestPermissionMiddleware_WithAPIKey(t *testing.T) {
	logger := newTestLogger()
	mw := PermissionMiddleware(logger)

	apiKey := &types.APIKey{
		ID:   "key-perm",
		Name: "perm-key",
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/signers", nil)
	ctx := context.WithValue(req.Context(), APIKeyContextKey, apiKey)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.True(t, called, "next handler should be called when API key is present")
	assert.Equal(t, http.StatusOK, rr.Code)
}

// ---------------------------------------------------------------------------
// CheckChainPermission
// ---------------------------------------------------------------------------

func TestCheckChainPermission_NilAPIKey(t *testing.T) {
	assert.False(t, CheckChainPermission(nil, types.ChainTypeEVM))
}

func TestCheckChainPermission_AllowedChain(t *testing.T) {
	apiKey := &types.APIKey{
		ID:                "key-chain",
		AllowedChainTypes: []string{"evm"},
	}
	assert.True(t, CheckChainPermission(apiKey, types.ChainTypeEVM))
}

func TestCheckChainPermission_DisallowedChain(t *testing.T) {
	apiKey := &types.APIKey{
		ID:                "key-chain-no",
		AllowedChainTypes: []string{"solana"},
	}
	assert.False(t, CheckChainPermission(apiKey, types.ChainTypeEVM))
}

func TestCheckChainPermission_EmptyAllowedChains(t *testing.T) {
	apiKey := &types.APIKey{
		ID:                "key-chain-all",
		AllowedChainTypes: []string{},
	}
	// Empty means all chains allowed
	assert.True(t, CheckChainPermission(apiKey, types.ChainTypeEVM))
}

// ---------------------------------------------------------------------------
// CheckSignerPermission
// ---------------------------------------------------------------------------

func TestCheckSignerPermission_NilAPIKey(t *testing.T) {
	assert.False(t, CheckSignerPermission(nil, "0xabc"))
}

func TestCheckSignerPermission_AllowedSigner(t *testing.T) {
	apiKey := &types.APIKey{
		ID:             "key-signer",
		AllowedSigners: []string{"0xABC123"},
	}
	assert.True(t, CheckSignerPermission(apiKey, "0xABC123"))
}

func TestCheckSignerPermission_DisallowedSigner(t *testing.T) {
	apiKey := &types.APIKey{
		ID:             "key-signer-no",
		AllowedSigners: []string{"0xABC123"},
	}
	assert.False(t, CheckSignerPermission(apiKey, "0xDEF456"))
}

func TestCheckSignerPermission_CaseInsensitive(t *testing.T) {
	apiKey := &types.APIKey{
		ID:             "key-signer-ci",
		AllowedSigners: []string{"0xABC123"},
	}
	assert.True(t, CheckSignerPermission(apiKey, "0xabc123"))
}

func TestCheckSignerPermission_EmptyAllowedSigners_NoAccess(t *testing.T) {
	apiKey := &types.APIKey{
		ID:             "key-signer-empty",
		AllowedSigners: []string{},
	}
	// Empty AllowedSigners = no access (unless AllowAllSigners is true)
	assert.False(t, CheckSignerPermission(apiKey, "0xANYTHING"))
}

func TestCheckSignerPermission_AllowAllSigners(t *testing.T) {
	apiKey := &types.APIKey{
		ID:               "key-signer-all",
		AllowAllSigners:  true,
		AllowedSigners:   []string{},
	}
	assert.True(t, CheckSignerPermission(apiKey, "0xANYTHING"))
}

// ---------------------------------------------------------------------------
// SecurityHeadersMiddleware
// ---------------------------------------------------------------------------

func TestSecurityHeadersMiddleware(t *testing.T) {
	mw := SecurityHeadersMiddleware()

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)

	assert.True(t, called, "next handler should be called")
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", rr.Header().Get("X-Frame-Options"))
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	assert.Equal(t, "default-src 'none'", rr.Header().Get("Content-Security-Policy"))
}
