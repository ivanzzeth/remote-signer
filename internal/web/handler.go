package web

import (
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"sync/atomic"

	"github.com/ivanzzeth/remote-signer/internal/settings"
)

// Handler serves the React SPA. It dispatches like a typical
// history-mode SPA: any request whose path looks like an asset (has a
// known extension) is looked up in the embedded filesystem; everything
// else falls back to index.html so client-side routing works.
//
// When the runtime settings.web snapshot has Enabled=false, the handler
// short-circuits with 404 — admins can flip the UI off without restarting.
//
// When DevProxy is non-empty, the handler reverse-proxies to a Vite dev
// server (typically http://localhost:5173) so the front-end developer
// gets HMR while the daemon still owns /api/v1/* and /metrics. The proxy
// target is re-read on every request so toggling the setting takes effect
// within one Manager refresh cycle.
type Handler struct {
	mgr      *settings.Manager
	log      *slog.Logger
	fsys     fs.FS
	devProxy atomic.Pointer[httputil.ReverseProxy]
	devURL   atomic.Pointer[string] // cached so we only rebuild proxy when URL changes
}

// NewHandler binds a fresh handler to the embedded filesystem and the
// shared settings manager.
func NewHandler(mgr *settings.Manager, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{mgr: mgr, log: log, fsys: Dist()}
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Go's ServeMux falls through to "/" for any path that doesn't have a
	// more specific match. We never want to serve HTML for an unknown API
	// route (eg. /api/v1/typo) — that would mask 404s as 200s and confuse
	// clients. Explicitly bail for these system-prefix paths so the SPA
	// only sees end-user navigation.
	switch {
	case strings.HasPrefix(r.URL.Path, "/api/"),
		r.URL.Path == "/health",
		r.URL.Path == "/metrics":
		http.NotFound(w, r)
		return
	}

	snap := h.mgr.Web()
	if snap == nil || !snap.Enabled {
		http.NotFound(w, r)
		return
	}

	if snap.DevProxy != "" {
		h.serveDevProxy(w, r, snap.DevProxy)
		return
	}

	h.serveStatic(w, r)
}

// serveDevProxy reverse-proxies to a running Vite dev server. The proxy
// instance is cached and rebuilt only when the target URL changes so each
// request reuses one Transport.
func (h *Handler) serveDevProxy(w http.ResponseWriter, r *http.Request, target string) {
	current := h.devURL.Load()
	if current == nil || *current != target {
		parsed, err := url.Parse(target)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			h.log.Warn("invalid web.dev_proxy URL", "value", target, "err", err)
			http.Error(w, "invalid dev_proxy URL", http.StatusInternalServerError)
			return
		}
		proxy := httputil.NewSingleHostReverseProxy(parsed)
		h.devProxy.Store(proxy)
		h.devURL.Store(&target)
	}
	if p := h.devProxy.Load(); p != nil {
		p.ServeHTTP(w, r)
		return
	}
	http.Error(w, "dev_proxy not initialised", http.StatusInternalServerError)
}

// serveStatic serves the SPA from the embedded filesystem with history
// fallback. Requests that look like files are served directly; everything
// else (paths without an extension, paths that don't exist on disk) fall
// back to index.html so React Router can pick them up.
func (h *Handler) serveStatic(w http.ResponseWriter, r *http.Request) {
	clean := path.Clean(r.URL.Path)
	clean = strings.TrimPrefix(clean, "/")
	if clean == "" || clean == "." {
		h.serveIndex(w, r)
		return
	}

	// File path with an extension → try to serve as-is.
	if ext := path.Ext(clean); ext != "" {
		f, err := h.fsys.Open(clean)
		if err == nil {
			defer f.Close()
			info, err := f.Stat()
			if err == nil && !info.IsDir() {
				w.Header().Set("Content-Type", contentTypeFor(ext))
				_, _ = io.Copy(w, f)
				return
			}
		}
		// Not a known asset; fall through to index.html so the SPA can
		// render a 404 page itself rather than the browser showing
		// "asset/404.png not found" raw.
	}

	h.serveIndex(w, r)
}

func (h *Handler) serveIndex(w http.ResponseWriter, r *http.Request) {
	f, err := h.fsys.Open("index.html")
	if err != nil {
		h.log.Error("web: index.html missing from embed", "err", err)
		http.Error(w, "web UI bundle missing; rebuild with `make web`", http.StatusServiceUnavailable)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// SPA index is the single mutable entry point — don't long-cache it
	// or users will be stuck on stale bundles after every deploy.
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	_, _ = io.Copy(w, f)
}

// contentTypeFor returns a sensible Content-Type for the well-known
// extensions Vite emits. http.ServeContent's auto-detection works for
// most but adds latency by reading bytes; a static map is faster and
// avoids reads on a non-seekable embed.File.
func contentTypeFor(ext string) string {
	switch strings.ToLower(ext) {
	case ".js", ".mjs":
		return "application/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".html":
		return "text/html; charset=utf-8"
	case ".json":
		return "application/json"
	case ".map":
		return "application/json"
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".webp":
		return "image/webp"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ico":
		return "image/x-icon"
	case ".txt":
		return "text/plain; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}
