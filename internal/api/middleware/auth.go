package middleware

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/auth"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ContextKey is the type for context keys
type ContextKey string

const (
	// APIKeyContextKey is the context key for the authenticated API key
	APIKeyContextKey ContextKey = "api_key"
	// ClientIPContextKey is the context key for the resolved client IP (set by ClientIPMiddleware)
	ClientIPContextKey ContextKey = "client_ip"
)

// AuthMiddleware creates an authentication middleware
// Authentication format: timestamp|nonce|method|path|sha256(body)
// Nonce is required when NonceRequired is configured (recommended for production)
func AuthMiddleware(verifier *auth.Verifier, logger *slog.Logger, alertServices ...*SecurityAlertService) func(http.Handler) http.Handler {
	var alertService *SecurityAlertService
	if len(alertServices) > 0 {
		alertService = alertServices[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract auth headers
			apiKeyID := r.Header.Get("X-API-Key-ID")
			timestampStr := r.Header.Get("X-Timestamp")
			signature := r.Header.Get("X-Signature")
			nonce := r.Header.Get("X-Nonce")

			// Validate header lengths to prevent memory abuse
			const (
				maxAPIKeyIDLen  = 128
				maxTimestampLen = 24
				maxSignatureLen = 256
				maxNonceLen     = 256
			)
			if len(apiKeyID) > maxAPIKeyIDLen || len(timestampStr) > maxTimestampLen ||
				len(signature) > maxSignatureLen || len(nonce) > maxNonceLen {
				logger.Warn("auth header exceeds maximum length",
					"path", r.URL.Path,
					"api_key_id_len", len(apiKeyID),
					"nonce_len", len(nonce),
				)
				http.Error(w, "invalid authentication headers", http.StatusBadRequest)
				return
			}

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

			// Read body for verification (with size limit)
			const maxBodySize = 10 << 20 // 10 MB
			r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				logger.Error("failed to read body", "error", err)
				http.Error(w, "failed to read request body", http.StatusInternalServerError)
				return
			}
			// Restore body for downstream handlers
			r.Body = io.NopCloser(bytes.NewBuffer(body))

			// Build full path with query string (client signs with query params)
			path := r.URL.Path
			if r.URL.RawQuery != "" {
				path = path + "?" + r.URL.RawQuery
			}

			// Verify request (nonce may be empty; verifier enforces NonceRequired)
			apiKey, err := verifier.VerifyRequestWithNonce(
				r.Context(),
				apiKeyID,
				timestamp,
				nonce,
				signature,
				r.Method,
				path,
				body,
			)

			if err != nil {
				if types.IsUnauthorized(err) {
					logger.Warn("unauthorized request",
						"path", r.URL.Path,
						"api_key_id", apiKeyID,
						"has_nonce", nonce != "",
						"error", err,
					)
					if alertService != nil {
						errMsg := err.Error()
						clientIP, _ := r.Context().Value(ClientIPContextKey).(string)
						alertType := AlertAuthFailure
						source := apiKeyID
						if source == "" {
							source = clientIP
						}
						// Escalate specific attack patterns to their own alert types
						if strings.Contains(errMsg, "nonce") && strings.Contains(errMsg, "already used") {
							alertType = AlertNonceReplay
						} else if strings.Contains(errMsg, "disabled") {
							alertType = AlertDisabledKey
						} else if strings.Contains(errMsg, "expired") {
							alertType = AlertExpiredKey
						}
						alertService.Alert(alertType, source,
							fmt.Sprintf("[Remote Signer] %s\n\nAPI Key: %s\nIP: %s\nPath: %s %s\nError: %s\nTime: %s",
								strings.ToUpper(string(alertType)),
								apiKeyID, clientIP, r.Method, r.URL.Path, errMsg,
								time.Now().UTC().Format(time.RFC3339)))
					}
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				logger.Error("auth verification error",
					"error", err,
					"path", r.URL.Path,
					"has_nonce", nonce != "",
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
