package web

import (
	"context"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/settings"
)

// memStore is a minimal in-memory Store for testing the web Handler.
type memStore struct {
	mu   sync.Mutex
	data map[string]*settings.Setting
}

func (s *memStore) Get(_ context.Context, key settings.Group) (*settings.Setting, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.data[string(key)]
	if !ok {
		return nil, settings.ErrNotFound
	}
	return row, nil
}

func (s *memStore) Put(_ context.Context, key settings.Group, valueJSON string, updatedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[string(key)] = &settings.Setting{
		Key:       string(key),
		ValueJSON: valueJSON,
		UpdatedAt: time.Now(),
		UpdatedBy: updatedBy,
	}
	return nil
}

func (s *memStore) List(_ context.Context) ([]*settings.Setting, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*settings.Setting, 0, len(s.data))
	for _, v := range s.data {
		out = append(out, v)
	}
	return out, nil
}

func newMemStore() *memStore {
	return &memStore{data: make(map[string]*settings.Setting)}
}

func realDistFS(t *testing.T) fs.FS {
	t.Helper()
	return Dist()
}

func newEnabledHandler(log *slog.Logger) *Handler {
	store := newMemStore()
	// Seed web = enabled
	_ = store.Put(context.Background(), settings.GroupWeb, `{"enabled":true}`, "test")
	mgr := settings.NewManager(store, log)
	if err := mgr.Reload(context.Background()); err != nil {
		panic(err)
	}
	return NewHandler(mgr, log)
}

func newDisabledHandler(log *slog.Logger) *Handler {
	store := newMemStore()
	_ = store.Put(context.Background(), settings.GroupWeb, `{"enabled":false}`, "test")
	mgr := settings.NewManager(store, log)
	if err := mgr.Reload(context.Background()); err != nil {
		panic(err)
	}
	return NewHandler(mgr, log)
}

func TestHandlerWebDisabledReturns404(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := newDisabledHandler(log)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestHandlerAPIPrefixReturns404(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := newEnabledHandler(log)

	for _, path := range []string{"/api/v1/sign", "/health", "/metrics"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("path %s: status = %d, want 404", path, rec.Code)
		}
	}
}

func TestHandlerServesIndexHTML(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := newEnabledHandler(log)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %s", ct)
	}

	body := rec.Body.String()
	if len(body) < 100 {
		t.Fatalf("index.html too short: %d bytes", len(body))
	}
}

func TestHandlerHistoryFallback(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := newEnabledHandler(log)

	req := httptest.NewRequest(http.MethodGet, "/some/react/route", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %s", ct)
	}
}

func TestHandlerContentTypeForExtensions(t *testing.T) {
	tests := []struct {
		ext  string
		want string
	}{
		{".js", "application/javascript; charset=utf-8"},
		{".mjs", "application/javascript; charset=utf-8"},
		{".css", "text/css; charset=utf-8"},
		{".html", "text/html; charset=utf-8"},
		{".json", "application/json"},
		{".svg", "image/svg+xml"},
		{".png", "image/png"},
		{".woff2", "font/woff2"},
		{".unknown", "application/octet-stream"},
	}
	for _, tc := range tests {
		got := contentTypeFor(tc.ext)
		if got != tc.want {
			t.Errorf("contentTypeFor(%q) = %q, want %q", tc.ext, got, tc.want)
		}
	}
}

func TestHandlerServesExistingAsset(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := newEnabledHandler(log)

	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestHandlerDevProxyInvalidURL(t *testing.T) {
	store := newMemStore()
	_ = store.Put(context.Background(), settings.GroupWeb, `{"enabled":true,"dev_proxy":"://invalid"}`, "test")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := settings.NewManager(store, log)
	_ = mgr.Reload(context.Background())
	h := NewHandler(mgr, log)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 for invalid dev proxy URL", rec.Code)
	}
}

func TestContentTypeCaseInsensitive(t *testing.T) {
	if got := contentTypeFor(".JS"); got != "application/javascript; charset=utf-8" {
		t.Errorf(".JS -> %q", got)
	}
	if got := contentTypeFor(".Png"); got != "image/png" {
		t.Errorf(".Png -> %q", got)
	}
}

func TestHandlerMissingAssetFallsBackToIndex(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "index.html"), []byte("<html></html>"), 0644); err != nil {
		t.Fatal(err)
	}
	fsys := os.DirFS(tmp)

	store := newMemStore()
	_ = store.Put(context.Background(), settings.GroupWeb, `{"enabled":true}`, "test")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := settings.NewManager(store, log)
	_ = mgr.Reload(context.Background())

	h := &Handler{mgr: mgr, log: log, fsys: fsys}

	req := httptest.NewRequest(http.MethodGet, "/missing.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (fallback to index)", rec.Code)
	}
	if rec.Body.String() != "<html></html>" {
		t.Errorf("body = %q, expected index.html", rec.Body.String())
	}
}
