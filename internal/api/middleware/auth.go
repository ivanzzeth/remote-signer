package middleware

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/core/auth"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ContextKey is the type for context keys
type ContextKey string

const (
	// APIKeyContextKey is the context key for the authenticated API key
	APIKeyContextKey ContextKey = "api_key"
)

// AuthMiddleware creates an authentication middleware
func AuthMiddleware(verifier *auth.Verifier, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract auth headers
			apiKeyID := r.Header.Get("X-API-Key-ID")
			timestampStr := r.Header.Get("X-Timestamp")
			signature := r.Header.Get("X-Signature")

			if apiKeyID == "" || timestampStr == "" || signature == "" {
				logger.Warn("missing auth headers",
					"path", r.URL.Path,
					"api_key_id", apiKeyID,
				)
				http.Error(w, "missing authentication headers", http.StatusUnauthorized)
				return
			}

			// Parse timestamp
			timestamp, err := auth.ParseTimestamp(timestampStr)
			if err != nil {
				logger.Warn("invalid timestamp", "error", err)
				http.Error(w, "invalid timestamp", http.StatusUnauthorized)
				return
			}

			// Read body for verification
			body, err := io.ReadAll(r.Body)
			if err != nil {
				logger.Error("failed to read body", "error", err)
				http.Error(w, "failed to read request body", http.StatusInternalServerError)
				return
			}
			// Restore body for downstream handlers
			r.Body = io.NopCloser(bytes.NewBuffer(body))

			// Verify request
			apiKey, err := verifier.VerifyRequest(
				r.Context(),
				apiKeyID,
				timestamp,
				signature,
				r.Method,
				r.URL.Path,
				body,
			)
			if err != nil {
				if types.IsUnauthorized(err) {
					logger.Warn("unauthorized request",
						"path", r.URL.Path,
						"api_key_id", apiKeyID,
						"error", err,
					)
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				logger.Error("auth verification error",
					"error", err,
					"path", r.URL.Path,
				)
				http.Error(w, "authentication error", http.StatusInternalServerError)
				return
			}

			// Add API key to context
			ctx := context.WithValue(r.Context(), APIKeyContextKey, apiKey)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetAPIKey retrieves the API key from the request context
func GetAPIKey(ctx context.Context) *types.APIKey {
	apiKey, ok := ctx.Value(APIKeyContextKey).(*types.APIKey)
	if !ok {
		return nil
	}
	return apiKey
}
