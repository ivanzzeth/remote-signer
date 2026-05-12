package settings

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	_ "modernc.org/sqlite"
)

func newTestStore(t *testing.T) Store {
	t.Helper()
	db, err := gorm.Open(sqlite.New(sqlite.Config{DSN: ":memory:", DriverName: "sqlite"}), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&Setting{}); err != nil {
		t.Fatal(err)
	}
	store, err := NewGormStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestManagerDefaultsBeforeReload(t *testing.T) {
	mgr := NewManager(newTestStore(t), discardLog())
	if mgr.Security() == nil {
		t.Fatal("Security() returned nil pointer before any Reload")
	}
	if mgr.Security().IPRateLimit != 200 {
		t.Errorf("default IPRateLimit = %d, want 200", mgr.Security().IPRateLimit)
	}
}

func TestUpdateSecurityRoundTrip(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	ctx := context.Background()

	patch := DefaultSecurity()
	patch.IPRateLimit = 5000
	patch.MaxRulesPerAPIKey = 7
	if err := mgr.UpdateSecurity(ctx, patch, UpdatedByAPI); err != nil {
		t.Fatal(err)
	}
	if got := mgr.Security().IPRateLimit; got != 5000 {
		t.Errorf("after update IPRateLimit = %d, want 5000", got)
	}

	// New Manager reading from the same store should see the write.
	mgr2 := NewManager(store, discardLog())
	if err := mgr2.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if got := mgr2.Security().IPRateLimit; got != 5000 {
		t.Errorf("reloaded IPRateLimit = %d, want 5000", got)
	}
	if got := mgr2.Security().MaxRulesPerAPIKey; got != 7 {
		t.Errorf("reloaded MaxRulesPerAPIKey = %d, want 7", got)
	}
}

func TestBackgroundRefreshPicksUpRemoteChange(t *testing.T) {
	store := newTestStore(t)
	a := NewManager(store, discardLog(), WithRefreshInterval(20*time.Millisecond))
	b := NewManager(store, discardLog(), WithRefreshInterval(20*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.Start(ctx)
	b.Start(ctx)

	// Manager `a` writes a value. `b` should observe it via the poll loop.
	patch := DefaultSecurity()
	patch.IPRateLimit = 9999
	if err := a.UpdateSecurity(ctx, patch, "test"); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(2 * time.Second)
	for {
		if b.Security().IPRateLimit == 9999 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("manager b did not pick up the change in time: got IPRateLimit=%d", b.Security().IPRateLimit)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestApplyRowIgnoresUnknownGroup(t *testing.T) {
	mgr := NewManager(newTestStore(t), discardLog())
	mgr.applyRow(&Setting{Key: "totally-unknown", ValueJSON: "{}"})
	// Should not panic or affect any known snapshot.
	if mgr.Security().IPRateLimit != 200 {
		t.Errorf("unknown group leaked into security")
	}
}

// Ensures concurrent reads after a write don't see partial state. Smoke test
// for the atomic.Pointer contract.
func TestConcurrentReadAfterWrite(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	ctx := context.Background()

	patch := DefaultSecurity()
	patch.IPRateLimit = 4242
	if err := mgr.UpdateSecurity(ctx, patch, "test"); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	const readers = 16
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if mgr.Security().IPRateLimit != 4242 {
					t.Errorf("snapshot tear")
				}
			}
		}()
	}
	wg.Wait()
}
