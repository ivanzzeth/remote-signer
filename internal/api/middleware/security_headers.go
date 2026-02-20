package middleware

import "net/http"

// SecurityHeadersMiddleware adds standard security response headers to all responses.
// These headers protect against common web attacks:
//   - X-Content-Type-Options: nosniff — prevents MIME type sniffing
//   - X-Frame-Options: DENY — prevents clickjacking via iframe embedding
//   - Cache-Control: no-store — prevents caching of sensitive API responses
//   - Content-Security-Policy: default-src 'none' — restricts resource loading (API-only server)
func SecurityHeadersMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Security-Policy", "default-src 'none'")
			next.ServeHTTP(w, r)
		})
	}
}
