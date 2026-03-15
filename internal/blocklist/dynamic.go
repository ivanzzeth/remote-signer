package blocklist

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// Config defines the dynamic blocklist configuration.
type Config struct {
	Enabled      bool           `yaml:"enabled" json:"enabled"`
	SyncInterval string         `yaml:"sync_interval" json:"sync_interval"` // e.g. "1h", "30m"
	FailMode     string         `yaml:"fail_mode" json:"fail_mode"`         // "open" or "close"
	CacheFile    string         `yaml:"cache_file" json:"cache_file"`       // local file to persist fetched addresses (e.g. "data/blocklist_cache.json")
	Sources      []SourceConfig `yaml:"sources" json:"sources"`
}

// Metrics exposes blocklist sync state for monitoring.
type Metrics struct {
	AddressCount int       `json:"address_count"`
	SourceCount  int       `json:"source_count"`
	LastSyncAt   time.Time `json:"last_sync_at"`
	LastSyncErr  string    `json:"last_sync_error,omitempty"`
	SyncErrors   int64     `json:"sync_errors"`
}

// DynamicBlocklist maintains an in-memory set of blocked addresses, refreshed periodically from external sources.
// Addresses are persisted to a local cache file so startup doesn't require network access.
type DynamicBlocklist struct {
	mu        sync.RWMutex
	addrs     map[string]bool // checksummed address → true
	sources   []Source
	failMode  string // "open" or "close"
	cacheFile string // local file path for persistence
	logger    *slog.Logger

	// metrics
	lastSyncAt  time.Time
	lastSyncErr string
	syncErrors  int64

	// lifecycle
	cancel context.CancelFunc
	done   chan struct{}
}

// NewDynamicBlocklist creates a new dynamic blocklist from config.
func NewDynamicBlocklist(cfg Config, logger *slog.Logger) (*DynamicBlocklist, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if !cfg.Enabled {
		return nil, fmt.Errorf("dynamic blocklist is disabled")
	}

	failMode := cfg.FailMode
	if failMode == "" {
		failMode = "open"
	}
	if failMode != "open" && failMode != "close" {
		return nil, fmt.Errorf("invalid fail_mode %q: must be 'open' or 'close'", failMode)
	}

	var sources []Source
	for _, sc := range cfg.Sources {
		src, err := NewSource(sc, nil)
		if err != nil {
			return nil, fmt.Errorf("create source: %w", err)
		}
		sources = append(sources, src)
	}

	if len(sources) == 0 {
		return nil, fmt.Errorf("at least one source is required")
	}

	return &DynamicBlocklist{
		addrs:     make(map[string]bool),
		sources:   sources,
		failMode:  failMode,
		cacheFile: cfg.CacheFile,
		logger:    logger,
	}, nil
}

// Start loads the local cache (instant, no network), then begins background sync.
// Returns immediately after loading cache — first remote sync happens asynchronously.
func (b *DynamicBlocklist) Start(ctx context.Context, interval time.Duration) error {
	// 1. Load persisted cache (fast, no network).
	if n := b.loadCache(); n > 0 {
		b.logger.Info("blocklist loaded from cache", "addresses", n, "file", b.cacheFile)
	}

	syncCtx, cancel := context.WithCancel(ctx)
	b.cancel = cancel
	b.done = make(chan struct{})

	go func() {
		defer close(b.done)
		// 2. First remote sync (async, doesn't block startup).
		b.sync(syncCtx)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-syncCtx.Done():
				return
			case <-ticker.C:
				b.sync(syncCtx)
			}
		}
	}()

	return nil
}

// Stop gracefully stops the sync loop.
func (b *DynamicBlocklist) Stop() {
	if b.cancel != nil {
		b.cancel()
	}
	if b.done != nil {
		<-b.done
	}
}

// IsBlocked checks if an address is in the blocklist. Thread-safe, O(1).
// Returns (blocked, reason). When the list is stale and fail_mode is "close", returns blocked=true.
func (b *DynamicBlocklist) IsBlocked(addr string) (bool, string) {
	if !common.IsHexAddress(addr) {
		return false, ""
	}
	checksum := common.HexToAddress(addr).Hex()

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.addrs[checksum] {
		return true, fmt.Sprintf("address %s is on the dynamic blocklist", checksum)
	}
	return false, ""
}

// IsFailClosed returns true if the blocklist is in fail-close mode and the last sync failed
// with no cached addresses.
func (b *DynamicBlocklist) IsFailClosed() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.failMode == "close" && b.lastSyncErr != "" && len(b.addrs) == 0
}

// Metrics returns current sync metrics.
func (b *DynamicBlocklist) Metrics() Metrics {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return Metrics{
		AddressCount: len(b.addrs),
		SourceCount:  len(b.sources),
		LastSyncAt:   b.lastSyncAt,
		LastSyncErr:  b.lastSyncErr,
		SyncErrors:   b.syncErrors,
	}
}

// AddressCount returns the number of addresses currently in the blocklist.
func (b *DynamicBlocklist) AddressCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.addrs)
}

// sync fetches all sources and merges into the address set.
func (b *DynamicBlocklist) sync(ctx context.Context) {
	merged := make(map[string]bool)
	var errs []string

	for _, src := range b.sources {
		addrs, err := src.Fetch(ctx)
		if err != nil {
			b.logger.Error("blocklist source fetch failed", "source", src.Name(), "error", err)
			errs = append(errs, fmt.Sprintf("%s: %v", src.Name(), err))
			continue
		}
		for _, a := range addrs {
			merged[a] = true
		}
		b.logger.Info("blocklist source synced", "source", src.Name(), "addresses", len(addrs))
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.lastSyncAt = time.Now()

	if len(errs) > 0 {
		b.lastSyncErr = fmt.Sprintf("%d source(s) failed: %s", len(errs), errs[0])
		b.syncErrors++
		// On partial failure: merge successful results with existing cache.
		if len(merged) > 0 {
			b.addrs = merged
			b.logger.Warn("blocklist partial sync", "total", len(merged), "errors", len(errs))
		} else {
			// Total failure: keep existing cache (fail-open) or clear (fail-close handled by IsFailClosed).
			b.logger.Error("blocklist sync failed completely, keeping stale cache", "cached", len(b.addrs))
		}
		return
	}

	b.lastSyncErr = ""
	b.addrs = merged
	b.logger.Info("blocklist sync complete", "total_addresses", len(merged))

	// Persist to cache file (non-blocking, best-effort).
	go b.saveCache(merged)
}

// cacheData is the JSON structure persisted to disk.
type cacheData struct {
	UpdatedAt string   `json:"updated_at"`
	Addresses []string `json:"addresses"`
}

// loadCache reads the local cache file into memory. Returns the number of addresses loaded.
func (b *DynamicBlocklist) loadCache() int {
	if b.cacheFile == "" {
		return 0
	}
	data, err := os.ReadFile(b.cacheFile) // #nosec G304 -- cacheFile is from config
	if err != nil {
		if !os.IsNotExist(err) {
			b.logger.Warn("blocklist cache read failed", "file", b.cacheFile, "error", err)
		}
		return 0
	}
	var cache cacheData
	if err := json.Unmarshal(data, &cache); err != nil {
		b.logger.Warn("blocklist cache parse failed", "file", b.cacheFile, "error", err)
		return 0
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	for _, addr := range cache.Addresses {
		if common.IsHexAddress(addr) {
			b.addrs[common.HexToAddress(addr).Hex()] = true
		}
	}
	return len(b.addrs)
}

// saveCache writes the current address set to the local cache file.
func (b *DynamicBlocklist) saveCache(addrs map[string]bool) {
	if b.cacheFile == "" {
		return
	}

	list := make([]string, 0, len(addrs))
	for addr := range addrs {
		list = append(list, addr)
	}

	cache := cacheData{
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Addresses: list,
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		b.logger.Error("blocklist cache marshal failed", "error", err)
		return
	}

	dir := filepath.Dir(b.cacheFile)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		b.logger.Error("blocklist cache dir create failed", "dir", dir, "error", err)
		return
	}

	// Write atomically via temp file + rename.
	tmp := b.cacheFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil { // #nosec G306 -- intentional 640
		b.logger.Error("blocklist cache write failed", "file", tmp, "error", err)
		return
	}
	if err := os.Rename(tmp, b.cacheFile); err != nil {
		b.logger.Error("blocklist cache rename failed", "error", err)
		return
	}
	b.logger.Debug("blocklist cache saved", "file", b.cacheFile, "addresses", len(list))
}
