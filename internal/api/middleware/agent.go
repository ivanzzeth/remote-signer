package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// AgentOrAdminMiddleware creates a middleware that requires agent or admin permissions.
// Agent keys get read-only access (GET only); admin keys get full access.
// Must be used after AuthMiddleware as it depends on the API key in context.
func AgentOrAdminMiddleware(logger *slog.Logger, alertServices ...*SecurityAlertService) func(http.Handler) http.Handler {
	var alertService *SecurityAlertService
	if len(alertServices) > 0 {
		alertService = alertServices[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := GetAPIKey(r.Context())
			if apiKey == nil {
				logger.Error("agent-or-admin middleware: no API key in context",
					"path", r.URL.Path,
				)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// Admin: full access
			if apiKey.Admin {
				next.ServeHTTP(w, r)
				return
			}

			// Agent: read-only (GET only)
			if apiKey.Agent {
				if r.Method != http.MethodGet {
					logger.Warn("agent key attempted non-GET operation",
						"path", r.URL.Path,
						"method", r.Method,
						"api_key_id", apiKey.ID,
					)
					http.Error(w, "agent keys have read-only access", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Neither admin nor agent: deny
			logger.Warn("admin or agent permission required",
				"path", r.URL.Path,
				"api_key_id", apiKey.ID,
				"api_key_name", apiKey.Name,
			)
			if alertService != nil {
				clientIP, _ := r.Context().Value(ClientIPContextKey).(string)
				alertService.Alert(AlertAdminDenied, apiKey.ID,
					fmt.Sprintf("[Remote Signer] ADMIN/AGENT ACCESS DENIED\n\nAPI Key: %s (%s)\nIP: %s\nPath: %s %s\nTime: %s",
						apiKey.ID, apiKey.Name, clientIP, r.Method, r.URL.Path,
						time.Now().UTC().Format(time.RFC3339)))
			}
			http.Error(w, "admin or agent permission required", http.StatusForbidden)
		})
	}
}
