package web

import (
	"context"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/settings"
)

func TestNewHandler_NilLogger(t *testing.T) {
	store := newMemStore()
	_ = store.Put(context.Background(), settings.GroupWeb, `{"enabled":true}`, "test")
	mgr := settings.NewManager(store, nil)
	if err := mgr.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(mgr, nil)
	if h.log == nil {
		t.Fatal("expected a non-nil logger after NewHandler with nil arg")
	}
}

func TestServeDevProxy_ValidURL(t *testing.T) {
	store := newMemStore()
	_ = store.Put(context.Background(), settings.GroupWeb, `{"enabled":true,"dev_proxy":"http://127.0.0.1:1"}`, "test")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := settings.NewManager(store, log)
	_ = mgr.Reload(context.Background())
	h := NewHandler(mgr, log)

	// First request caches the proxy.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// Connection will fail (no server on port 1), but the proxy caching
	// (devURL.Load / devProxy.Store) is exercised. A non-200 proves the
	// proxy path was taken rather than falling through to serveStatic.
	if rec.Code == http.StatusNotFound || rec.Code == http.StatusOK {
		t.Errorf("expected proxy error status, got %d", rec.Code)
	}
}

func TestServeIndex_ErrorPath(t *testing.T) {
	// Use a temp dir with NO index.html to trigger the error branch in serveIndex.
	tmp := t.TempDir()
	var fsys fs.FS = os.DirFS(tmp) // empty directory

	store := newMemStore()
	_ = store.Put(context.Background(), settings.GroupWeb, `{"enabled":true}`, "test")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := settings.NewManager(store, log)
	_ = mgr.Reload(context.Background())

	h := &Handler{mgr: mgr, log: log, fsys: fsys}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (ServiceUnavailable) for missing index.html", rec.Code)
	}
}

func TestContentTypeFor_MissingExtensions(t *testing.T) {
	tests := []struct {
		ext  string
		want string
	}{
		{".map", "application/json"},
		{".jpg", "image/jpeg"},
		{".webp", "image/webp"},
		{".woff", "font/woff"},
		{".ico", "image/x-icon"},
		{".txt", "text/plain; charset=utf-8"},
	}
	for _, tc := range tests {
		got := contentTypeFor(tc.ext)
		if got != tc.want {
			t.Errorf("contentTypeFor(%q) = %q, want %q", tc.ext, got, tc.want)
		}
	}
}
