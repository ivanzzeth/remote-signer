package middleware

import (
	"encoding/json"
	"net/http"
	"strings"
)

// ContentTypeMiddleware rejects POST/PUT/PATCH requests that do not carry
// an "application/json" Content-Type header. GET, DELETE, OPTIONS, and HEAD
// are allowed through unconditionally.
func ContentTypeMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost, http.MethodPut, http.MethodPatch:
				// Only enforce Content-Type when there is a body.
				// ContentLength == 0 or -1 (unknown/empty) with no Content-Type is OK
				// for bodyless POST endpoints (e.g., guard resume).
				ct := r.Header.Get("Content-Type")
				if r.ContentLength > 0 && !strings.HasPrefix(ct, "application/json") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnsupportedMediaType)
					// #nosec G104 -- HTTP response write error cannot be meaningfully handled
					json.NewEncoder(w).Encode(map[string]string{
						"error": "Content-Type must be application/json",
					})
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
