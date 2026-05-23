package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestIPRateLimitMiddleware_WithClientIPInContext(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	rl := NewRateLimiter(logger)
	wl := &IPWhitelist{enabled: false}

	mw := IPRateLimitMiddleware(rl, wl, 5)

	callCount := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})

	// Set client IP in context.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), ClientIPContextKey, "10.0.0.1")
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()
		mw(next).ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	}
	assert.Equal(t, 5, callCount)
}

func TestIPRateLimitMiddleware_ExceedsRateLimit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	rl := NewRateLimiter(logger)
	wl := &IPWhitelist{enabled: false}

	mw := IPRateLimitMiddleware(rl, wl, 2)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Two requests should succeed.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), ClientIPContextKey, "10.0.0.2")
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()
		mw(next).ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	}

	// Third request should be rate limited.
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := context.WithValue(req.Context(), ClientIPContextKey, "10.0.0.2")
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusTooManyRequests, rr.Code)
}

func TestIPRateLimitMiddleware_WithoutClientIPInContext(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	rl := NewRateLimiter(logger)
	cfg := config.IPWhitelistConfig{Enabled: false}
	wl, err := NewIPWhitelist(cfg, logger)
	assert.NoError(t, err)

	mw := IPRateLimitMiddleware(rl, wl, 100)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	// No client IP in context, but whitelist provides it from RemoteAddr.
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.3:12345"
	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)
	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestIPRateLimitMiddleware_DisabledWithZeroLimit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	rl := NewRateLimiter(logger)
	wl := &IPWhitelist{enabled: false}

	// limit <= 0 means pass-through.
	mw := IPRateLimitMiddleware(rl, wl, 0)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	mw(next).ServeHTTP(rr, req)
	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rr.Code)
}
