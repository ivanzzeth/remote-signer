package middleware

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// RateLimiter implements a simple sliding window rate limiter
type RateLimiter struct {
	mu      sync.Mutex
	windows map[string]*window
	logger  *slog.Logger
}

type window struct {
	count     int
	startTime time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(logger *slog.Logger) *RateLimiter {
	return &RateLimiter{
		windows: make(map[string]*window),
		logger:  logger,
	}
}

// RateLimitMiddleware creates a rate limiting middleware
func RateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := GetAPIKey(r.Context())
			if apiKey == nil {
				// No API key in context, skip rate limiting
				next.ServeHTTP(w, r)
				return
			}

			// Check rate limit
			if !limiter.Allow(apiKey.ID, apiKey.RateLimit) {
				limiter.logger.Warn("rate limit exceeded",
					"api_key_id", apiKey.ID,
					"rate_limit", apiKey.RateLimit,
				)
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Allow checks if a request is allowed under the rate limit
// limit is requests per minute
func (r *RateLimiter) Allow(key string, limit int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	windowDuration := time.Minute

	w, exists := r.windows[key]
	if !exists || now.Sub(w.startTime) >= windowDuration {
		// Start a new window
		r.windows[key] = &window{
			count:     1,
			startTime: now,
		}
		return true
	}

	// Check if within limit
	if w.count >= limit {
		return false
	}

	w.count++
	return true
}

// Cleanup removes expired windows (should be called periodically)
func (r *RateLimiter) Cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	windowDuration := time.Minute

	for key, w := range r.windows {
		if now.Sub(w.startTime) >= windowDuration*2 {
			delete(r.windows, key)
		}
	}
}

// StartCleanupRoutine starts a goroutine to periodically clean up expired windows
func (r *RateLimiter) StartCleanupRoutine(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				r.Cleanup()
			case <-stop:
				ticker.Stop()
				return
			}
		}
	}()
}

// PermissionMiddleware checks if the API key has permission for the request
func PermissionMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := GetAPIKey(r.Context())
			if apiKey == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Extract chain type from URL path
			// Expected format: /api/v1/{chain_type}/...
			// Permission checking is done at the handler level where we have more context
			// This middleware just ensures the API key is valid

			next.ServeHTTP(w, r)
		})
	}
}

// CheckChainPermission checks if the API key is allowed to access the given chain type
func CheckChainPermission(apiKey *types.APIKey, chainType types.ChainType) bool {
	if apiKey == nil {
		return false
	}
	return apiKey.IsAllowedChain(chainType)
}

// CheckSignerPermission checks if the API key is allowed to use the given signer
func CheckSignerPermission(apiKey *types.APIKey, signerAddress string) bool {
	if apiKey == nil {
		return false
	}
	return apiKey.IsAllowedSigner(signerAddress)
}
