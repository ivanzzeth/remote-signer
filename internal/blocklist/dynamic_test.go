package blocklist

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
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

	time.Sleep(500 * time.Millisecond)

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
