//go:build integration

package integration

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestWeb_DefaultEnabledServesIndex pins the v0.4 web UI default. A fresh
// daemon serves the placeholder index.html under "/" — production builds
// will overwrite the placeholder with the real Vite bundle, but the
// catch-all wiring is the same.
func TestWeb_DefaultEnabledServesIndex(t *testing.T) {
	d := startDaemon(t)
	resp, err := http.Get(d.url() + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/ status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("/ content-type = %q, want text/html prefix", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	// Either the real bundle or the placeholder must come back; both are
	// HTML documents that start with a doctype declaration.
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(string(body))), "<!doctype html") {
		t.Errorf("/ body did not look like an HTML document; got first 120 chars: %q", string(body)[:min(120, len(body))])
	}
}

// TestWeb_HistoryFallback verifies that an arbitrary client-side route
// (one that does not exist as a real file in the embedded FS) falls back
// to index.html so React Router can render it. This is the whole point
// of "history mode" routing.
func TestWeb_HistoryFallback(t *testing.T) {
	d := startDaemon(t)
	resp, err := http.Get(d.url() + "/dashboard/rules/abc-123")
	if err != nil {
		t.Fatalf("GET /dashboard/...: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q, want text/html prefix", ct)
	}
}

// TestWeb_UnknownAPIRouteIsNotSwallowed guards against the regression where
// the catch-all "/" handler accidentally serves HTML for unknown
// /api/v1/* paths — that would mask 404s as 200s and confuse clients.
func TestWeb_UnknownAPIRouteIsNotSwallowed(t *testing.T) {
	d := startDaemon(t)
	resp, err := http.Get(d.url() + "/api/v1/this-route-does-not-exist")
	if err != nil {
		t.Fatalf("GET /api/v1/typo: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("/api/v1/typo status = %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "text/html") {
		t.Errorf("unknown API path should not return HTML; got content-type %q", ct)
	}
}

// TestWeb_DisableThroughSettings drives the runtime toggle: PUT
// /api/v1/admin/settings/web with enabled=false, wait for the Manager's
// 5s poll to pick it up, then assert "/" returns 404. Confirms admins can
// kill the UI without restarting the daemon.
func TestWeb_DisableThroughSettings(t *testing.T) {
	d := startDaemon(t)

	// Confirm enabled at baseline.
	resp, err := http.Get(d.url() + "/")
	if err != nil {
		t.Fatalf("baseline GET /: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("baseline / status = %d, want 200", resp.StatusCode)
	}

	if _, _, err := d.runCLI(t, "settings", "set", "web", "enabled=false"); err != nil {
		t.Fatalf("disable web: %v", err)
	}

	// Wait up to 8s (one poll cycle + slack) for the snapshot to propagate.
	deadline := time.Now().Add(8 * time.Second)
	for {
		resp, err := http.Get(d.url() + "/")
		if err != nil {
			t.Fatalf("GET / after disable: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("/ still returning %d 8s after disable; web toggle did not propagate", resp.StatusCode)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
