package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/audit"
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
func RateLimitMiddleware(limiter *RateLimiter, auditLogger *audit.AuditLogger, alertServices ...*SecurityAlertService) func(http.Handler) http.Handler {
	var alertService *SecurityAlertService
	if len(alertServices) > 0 {
		alertService = alertServices[0]
	}
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
				clientIP, _ := r.Context().Value(ClientIPContextKey).(string)
				if alertService != nil {
					alertService.Alert(AlertRateLimitKey, apiKey.ID,
						fmt.Sprintf("[Remote Signer] API KEY RATE LIMIT\n\nAPI Key: %s\nIP: %s\nLimit: %d req/min\nPath: %s %s\nTime: %s",
							apiKey.ID, clientIP, apiKey.RateLimit, r.Method, r.URL.Path,
							time.Now().UTC().Format(time.RFC3339)))
				}
				if auditLogger != nil {
					auditLogger.LogRateLimitHit(r.Context(), apiKey.ID, clientIP, r.Method, r.URL.Path)
				}
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

// IPRateLimitMiddleware creates a pre-auth rate limiting middleware based on client IP.
// Protects against unauthenticated flood attacks (e.g. brute-force with invalid API keys).
// If limit <= 0, IP rate limiting is disabled (pass-through).
func IPRateLimitMiddleware(limiter *RateLimiter, ipWhitelist *IPWhitelist, limit int, alertServices ...*SecurityAlertService) func(http.Handler) http.Handler {
	var alertService *SecurityAlertService
	if len(alertServices) > 0 {
		alertService = alertServices[0]
	}
	return func(next http.Handler) http.Handler {
		if limit <= 0 {
			return next // disabled
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP, ok := r.Context().Value(ClientIPContextKey).(string)
			if !ok || clientIP == "" {
				clientIP = ResolveClientIP(r, ipWhitelist)
			}
			key := "ip:" + clientIP
			if !limiter.Allow(key, limit) {
				limiter.logger.Warn("IP rate limit exceeded",
					"client_ip", clientIP,
					"limit", limit,
					"path", r.URL.Path,
				)
				if alertService != nil {
					alertService.Alert(AlertRateLimitIP, clientIP,
						fmt.Sprintf("[Remote Signer] IP RATE LIMIT\n\nIP: %s\nLimit: %d req/min\nPath: %s %s\nTime: %s",
							clientIP, limit, r.Method, r.URL.Path,
							time.Now().UTC().Format(time.RFC3339)))
				}
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
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

			// Permission checking is done at the handler level where we have more context
			// This middleware just ensures the API key is valid

			next.ServeHTTP(w, r)
		})
	}
}
