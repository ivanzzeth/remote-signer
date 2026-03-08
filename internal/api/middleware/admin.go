package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// AdminMiddleware creates a middleware that requires admin permissions.
// Must be used after AuthMiddleware as it depends on the API key in context.
func AdminMiddleware(logger *slog.Logger, alertServices ...*SecurityAlertService) func(http.Handler) http.Handler {
	var alertService *SecurityAlertService
	if len(alertServices) > 0 {
		alertService = alertServices[0]
	}
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
				if alertService != nil {
					clientIP, _ := r.Context().Value(ClientIPContextKey).(string)
					alertService.Alert(AlertAdminDenied, apiKey.ID,
						fmt.Sprintf("[Remote Signer] ADMIN ACCESS DENIED\n\nAPI Key: %s (%s)\nIP: %s\nPath: %s %s\nTime: %s",
							apiKey.ID, apiKey.Name, clientIP, r.Method, r.URL.Path,
							time.Now().UTC().Format(time.RFC3339)))
				}
				http.Error(w, "admin permission required", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
