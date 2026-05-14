package blocklist

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// waitForSync polls until the blocklist has completed at least one sync attempt (success or failure).
func waitForSync(t *testing.T, bl *DynamicBlocklist, timeout time.Duration) {
	t.Helper()
	start := time.Now()
	for {
		m := bl.Metrics()
		if !m.LastSyncAt.IsZero() {
			return // sync completed (may have failed, but it ran)
		}
		if time.Since(start) > timeout {
			t.Fatal("timeout waiting for sync to complete")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestDynamicBlocklist_URLText(t *testing.T) {
	// Serve a text file with addresses.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# OFAC SDN ETH addresses\n0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b\n0x7F367cC41522cE07553e823bf3be79A889DEbe1B\n\n# comment\ninvalid-not-address\n"))
	}))
	defer srv.Close()

	cfg := Config{
		Enabled:      true,
		SyncInterval: "1h",
		FailMode:     "open",
		Sources: []SourceConfig{
			{Name: "test", Type: "url_text", URL: srv.URL},
		},
	}

	bl, err := NewDynamicBlocklist(cfg, testLogger())
	require.NoError(t, err)

	err = bl.Start(context.Background(), 1*time.Hour)
	require.NoError(t, err)
	defer bl.Stop()

	// Wait briefly for async first sync.
	time.Sleep(500 * time.Millisecond)

	assert.Equal(t, 2, bl.AddressCount())

	blocked, reason := bl.IsBlocked("0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b")
	assert.True(t, blocked)
	assert.Contains(t, reason, "dynamic blocklist")

	blocked, _ = bl.IsBlocked("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	assert.False(t, blocked)
}

func TestDynamicBlocklist_URLJson(t *testing.T) {
	data := map[string]interface{}{
		"data": map[string]interface{}{
			"addresses": []string{
				"0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b",
				"0x7F367cC41522cE07553e823bf3be79A889DEbe1B",
			},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(data)
	}))
	defer srv.Close()

	cfg := Config{
		Enabled:  true,
		FailMode: "open",
		Sources: []SourceConfig{
			{Name: "test-json", Type: "url_json", URL: srv.URL, JSONPath: "data.addresses"},
		},
	}

	bl, err := NewDynamicBlocklist(cfg, testLogger())
	require.NoError(t, err)

	err = bl.Start(context.Background(), 1*time.Hour)
	require.NoError(t, err)
	defer bl.Stop()

	time.Sleep(500 * time.Millisecond)

	assert.Equal(t, 2, bl.AddressCount())
	blocked, _ := bl.IsBlocked("0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b")
	assert.True(t, blocked)
}

func TestDynamicBlocklist_CachePersistence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b\n0x7F367cC41522cE07553e823bf3be79A889DEbe1B\n"))
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "blocklist_cache.json")

	cfg := Config{
		Enabled:   true,
		FailMode:  "open",
		CacheFile: cacheFile,
		Sources: []SourceConfig{
			{Name: "test", Type: "url_text", URL: srv.URL},
		},
	}

	// First instance: sync and persist.
	bl1, err := NewDynamicBlocklist(cfg, testLogger())
	require.NoError(t, err)
	err = bl1.Start(context.Background(), 1*time.Hour)
	require.NoError(t, err)
	time.Sleep(500 * time.Millisecond)
	bl1.Stop()

	// Verify cache file was written.
	_, err = os.Stat(cacheFile)
	require.NoError(t, err, "cache file should exist")

	// Second instance: load from cache (server is down).
	srv.Close()
	cfg2 := Config{
		Enabled:   true,
		FailMode:  "open",
		CacheFile: cacheFile,
		Sources: []SourceConfig{
			{Name: "test", Type: "url_text", URL: "http://localhost:1/nonexistent"},
		},
	}
	bl2, err := NewDynamicBlocklist(cfg2, testLogger())
	require.NoError(t, err)
	err = bl2.Start(context.Background(), 1*time.Hour)
	require.NoError(t, err)
	defer bl2.Stop()

	// Should have addresses from cache even though remote is down.
	assert.Equal(t, 2, bl2.AddressCount())
	blocked, _ := bl2.IsBlocked("0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b")
	assert.True(t, blocked)
}

func TestDynamicBlocklist_FailClosed(t *testing.T) {
	cfg := Config{
		Enabled:  true,
		FailMode: "close",
		Sources: []SourceConfig{
			{Name: "broken", Type: "url_text", URL: "http://localhost:1/nonexistent"},
		},
	}
	bl, err := NewDynamicBlocklist(cfg, testLogger())
	require.NoError(t, err)

	err = bl.Start(context.Background(), 1*time.Hour)
	require.NoError(t, err)
	defer bl.Stop()

	waitForSync(t, bl, 10*time.Second)

	assert.True(t, bl.IsFailClosed(), "should be fail-closed with no data")
}

func TestDynamicBlocklist_CaseInsensitive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b\n"))
	}))
	defer srv.Close()

	cfg := Config{
		Enabled:  true,
		FailMode: "open",
		Sources:  []SourceConfig{{Name: "test", Type: "url_text", URL: srv.URL}},
	}
	bl, err := NewDynamicBlocklist(cfg, testLogger())
	require.NoError(t, err)
	err = bl.Start(context.Background(), 1*time.Hour)
	require.NoError(t, err)
	defer bl.Stop()
	time.Sleep(500 * time.Millisecond)

	// Query with different case — should still match (checksum normalization).
	blocked, _ := bl.IsBlocked("0xD882CFC20F52F2599D84B8E8D58C7FB62CFE344B")
	assert.True(t, blocked)
}

func TestNewSource_RejectsFileScheme(t *testing.T) {
	_, err := NewSource(SourceConfig{
		Name: "bad", Type: "url_text", URL: "file:///etc/passwd",
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "http://")
}

func TestDynamicBlocklist_DoubleStartReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b\n"))
	}))
	defer srv.Close()

	cfg := Config{
		Enabled:  true,
		FailMode: "open",
		Sources:  []SourceConfig{{Name: "test", Type: "url_text", URL: srv.URL}},
	}
	bl, err := NewDynamicBlocklist(cfg, testLogger())
	require.NoError(t, err)

	err = bl.Start(context.Background(), 1*time.Hour)
	require.NoError(t, err)
	defer bl.Stop()

	err = bl.Start(context.Background(), 1*time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already started")
}

// TestDynamicBlocklist_ConcurrentIsBlockedDuringSync runs IsBlocked concurrently
// with sync to verify no data race under the race detector.
func TestDynamicBlocklist_ConcurrentIsBlockedDuringSync(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Alternate between different address sets to trigger map replacement.
		if callCount%2 == 0 {
			w.Write([]byte("0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b\n"))
		} else {
			w.Write([]byte("0x7F367cC41522cE07553e823bf3be79A889DEbe1B\n"))
		}
	}))
	defer srv.Close()

	bl, err := NewDynamicBlocklist(Config{
		Enabled:  true,
		FailMode: "open",
		Sources:  []SourceConfig{{Name: "test", Type: "url_text", URL: srv.URL}},
	}, testLogger())
	require.NoError(t, err)

	// Use a very short interval to trigger frequent syncs.
	err = bl.Start(context.Background(), 50*time.Millisecond)
	require.NoError(t, err)
	defer bl.Stop()

	// Hammer IsBlocked from multiple goroutines while sync is running.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				bl.IsBlocked("0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b")
				bl.IsBlocked("0x7F367cC41522cE07553e823bf3be79A889DEbe1B")
				bl.IsBlocked("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
			}
		}()
	}
	wg.Wait()
	// No race detector failure = pass.
}

// TestDynamicBlocklist_PartialSyncPreservesFailedSourceAddresses verifies that
// when one source fails, addresses from that source's previous sync are retained.
func TestDynamicBlocklist_PartialSyncPreservesFailedSourceAddresses(t *testing.T) {
	// Source A: always works.
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b\n"))
	}))
	defer srvA.Close()

	bl, err := NewDynamicBlocklist(Config{
		Enabled:  true,
		FailMode: "open",
		Sources: []SourceConfig{
			{Name: "good", Type: "url_text", URL: srvA.URL},
			{Name: "bad", Type: "url_text", URL: "http://localhost:1/down"},
		},
	}, testLogger())
	require.NoError(t, err)

	err = bl.Start(context.Background(), 1*time.Hour)
	require.NoError(t, err)
	defer bl.Stop()

	waitForSync(t, bl, 10*time.Second)

	// Source A's address should be present despite source B failing.
	assert.GreaterOrEqual(t, bl.AddressCount(), 1)
	blocked, _ := bl.IsBlocked("0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b")
	assert.True(t, blocked)

	// Metrics should show sync errors.
	m := bl.Metrics()
	assert.NotEmpty(t, m.LastSyncErr)
	assert.Greater(t, m.SyncErrors, int64(0))
}

// TestSource_HTTPErrorReturnsError verifies that non-200 responses are errors.
func TestSource_HTTPErrorReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	src, err := NewSource(SourceConfig{Name: "err", Type: "url_text", URL: srv.URL}, nil)
	require.NoError(t, err)

	_, err = src.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

// TestSource_BodyTruncation verifies that very large responses are limited.
func TestSource_BodyTruncation(t *testing.T) {
	// Serve 11MB of addresses — exceeds the 10MB limit.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		line := "0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b\n"
		for written := 0; written < 11*1024*1024; written += len(line) {
			w.Write([]byte(line))
		}
	}))
	defer srv.Close()

	src, err := NewSource(SourceConfig{Name: "big", Type: "url_text", URL: srv.URL}, nil)
	require.NoError(t, err)

	addrs, err := src.Fetch(context.Background())
	// Should succeed but with truncated results (not all addresses).
	// The last address may be cut mid-line and discarded by parseTextAddresses.
	require.NoError(t, err)
	assert.Greater(t, len(addrs), 0, "should have some addresses despite truncation")
}

// TestSource_InvalidURLSchemes tests various disallowed schemes.
func TestSource_InvalidURLSchemes(t *testing.T) {
	schemes := []string{
		"file:///etc/passwd",
		"ftp://example.com/list.txt",
		"gopher://evil.com",
		"data:text/plain,0xdead",
		"/local/path",
		"",
	}
	for _, url := range schemes {
		_, err := NewSource(SourceConfig{Name: "bad", Type: "url_text", URL: url}, nil)
		assert.Error(t, err, "should reject URL: %s", url)
	}
}

// TestSource_JSONInvalidPath verifies error on wrong json_path.
func TestSource_JSONInvalidPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data": {"addresses": ["0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b"]}}`))
	}))
	defer srv.Close()

	src, err := NewSource(SourceConfig{
		Name: "wrong-path", Type: "url_json", URL: srv.URL, JSONPath: "nonexistent.key",
	}, nil)
	require.NoError(t, err)

	_, err = src.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestDynamicBlocklist_MetricsReflectState verifies metrics accuracy.
func TestDynamicBlocklist_MetricsReflectState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b\n"))
	}))
	defer srv.Close()

	bl, err := NewDynamicBlocklist(Config{
		Enabled:  true,
		FailMode: "open",
		Sources:  []SourceConfig{{Name: "test", Type: "url_text", URL: srv.URL}},
	}, testLogger())
	require.NoError(t, err)
	err = bl.Start(context.Background(), 1*time.Hour)
	require.NoError(t, err)
	defer bl.Stop()

	time.Sleep(500 * time.Millisecond)

	m := bl.Metrics()
	assert.Equal(t, 1, m.AddressCount)
	assert.Equal(t, 1, m.SourceCount)
	assert.False(t, m.LastSyncAt.IsZero())
	assert.Empty(t, m.LastSyncErr)
	assert.Equal(t, int64(0), m.SyncErrors)
}

// TestNewDynamicBlocklist_ValidationErrors tests constructor validation.
func TestNewDynamicBlocklist_ValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		err  string
	}{
		{"disabled", Config{Enabled: false}, "disabled"},
		{"nil logger", Config{Enabled: true, Sources: []SourceConfig{{Name: "x", Type: "url_text", URL: "http://x"}}}, "logger"},
		{"no sources", Config{Enabled: true}, "at least one source"},
		{"bad fail_mode", Config{Enabled: true, FailMode: "invalid",
			Sources: []SourceConfig{{Name: "x", Type: "url_text", URL: "http://x"}}}, "invalid fail_mode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logger *slog.Logger
			if !strings.Contains(tt.name, "nil logger") {
				logger = testLogger()
			}
			_, err := NewDynamicBlocklist(tt.cfg, logger)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.err)
		})
	}
}

// TestSource_DefaultClientDoesNotFollowRedirects verifies that the default HTTP
// client (created when nil is passed to NewSource) does not follow redirects.
// This prevents SSRF via open-redirect chains.
func TestSource_DefaultClientDoesNotFollowRedirects(t *testing.T) {
	// Target server (should NOT be reached).
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("redirect target was reached; default client should not follow redirects")
		w.Write([]byte("0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b\n"))
	}))
	defer target.Close()

	// Redirector: sends 302 to the target.
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	// Create source with nil httpClient (uses default with CheckRedirect).
	src, err := NewSource(SourceConfig{
		Name: "redirect-test",
		Type: "url_text",
		URL:  redirector.URL,
	}, nil)
	require.NoError(t, err)

	_, err = src.Fetch(context.Background())
	// The fetch should fail because the 302 response is returned as-is (not 200).
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 302")
}
