package middleware

import (
	"log/slog"
	"net/http"
)

// AdminMiddleware creates a middleware that requires admin permissions.
// Must be used after AuthMiddleware as it depends on the API key in context.
func AdminMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := GetAPIKey(r.Context())
			if apiKey == nil {
				// This should not happen if AuthMiddleware is applied first
				logger.Error("admin middleware: no API key in context",
					"path", r.URL.Path,
				)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if !apiKey.Admin {
				logger.Warn("admin permission required",
					"path", r.URL.Path,
					"api_key_id", apiKey.ID,
					"api_key_name", apiKey.Name,
				)
				http.Error(w, "admin permission required", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
