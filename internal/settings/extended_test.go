package settings

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestManagerGetSetSnapshot(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())

	// Should return defaults before any Reload
	if mgr.Security() == nil {
		t.Fatal("Security() is nil")
	}
	if mgr.Notify() == nil {
		t.Fatal("Notify() is nil")
	}
	if mgr.Web() == nil || !mgr.Web().Enabled {
		t.Fatal("Web default should be enabled")
	}
	if mgr.Blocklist() == nil {
		t.Fatal("Blocklist() is nil")
	}
}

func TestUpdateNotifyRoundTrip(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	ctx := context.Background()

	patch := &NotifySnapshot{
		Providers: NotifyProviders{
			Slack: &NotifySlackProvider{Enabled: true, BotToken: "xoxb-test"},
		},
		Channels: NotifyChannels{
			Slack: []string{"#alerts"},
		},
	}
	if err := mgr.UpdateNotify(ctx, patch, UpdatedByAPI); err != nil {
		t.Fatal(err)
	}

	got := mgr.Notify()
	if got.Providers.Slack == nil || !got.Providers.Slack.Enabled {
		t.Fatal("slack provider not persisted")
	}
	if got.Providers.Slack.BotToken != "xoxb-test" {
		t.Fatalf("token = %s", got.Providers.Slack.BotToken)
	}

	// Second Manager should see the same value
	mgr2 := NewManager(store, discardLog())
	if err := mgr2.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if mgr2.Notify().Providers.Slack == nil || !mgr2.Notify().Providers.Slack.Enabled {
		t.Fatal("second manager did not pick up notify change")
	}
}

func TestUpdateNilSnapshotReturnsError(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	ctx := context.Background()

	if err := mgr.UpdateSecurity(ctx, nil, "test"); err == nil {
		t.Fatal("expected error for nil snapshot")
	}
	if err := mgr.UpdateWeb(ctx, nil, "test"); err == nil {
		t.Fatal("expected error for nil web snapshot")
	}
	if err := mgr.UpdateNotify(ctx, nil, "test"); err == nil {
		t.Fatal("expected error for nil notify snapshot")
	}
}

func TestConcurrentReadsOnAllSnapshots(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	ctx := context.Background()

	if err := mgr.UpdateWeb(ctx, &WebSnapshot{Enabled: false}, "test"); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	const readers = 8
	const iterations = 50
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = mgr.Security()
				_ = mgr.Notify()
				_ = mgr.Web()
				_ = mgr.Foundry()
				_ = mgr.Simulation()
				_ = mgr.Blocklist()
				_ = mgr.AuditMonitor()
				_ = mgr.RPCGateway()
				_ = mgr.MaterialCheck()
			}
		}()
	}
	wg.Wait()

	// After concurrent reads, the web update must still be visible.
	if mgr.Web().Enabled {
		t.Fatal("web should be disabled after update")
	}
}

func TestSeedDataInitialization(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if err := SeedSecurity(ctx, store, DefaultSecurity()); err != nil {
		t.Fatal(err)
	}
	if err := SeedNotify(ctx, store, &NotifySnapshot{}); err != nil {
		t.Fatal(err)
	}
	if err := SeedWeb(ctx, store, DefaultWeb()); err != nil {
		t.Fatal(err)
	}
	if err := SeedFoundry(ctx, store, &FoundrySnapshot{Enabled: true}); err != nil {
		t.Fatal(err)
	}

	// Seed again should be no-op (already exists)
	if err := SeedSecurity(ctx, store, DefaultSecurity()); err != nil {
		t.Fatal(err)
	}

	// Verify via a fresh Manager
	mgr := NewManager(store, discardLog())
	if err := mgr.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if mgr.Security().IPRateLimit != 200 {
		t.Fatalf("IPRateLimit = %d", mgr.Security().IPRateLimit)
	}
	if mgr.Web().Enabled != true {
		t.Fatal("web should be enabled")
	}
	if !mgr.Foundry().Enabled {
		t.Fatal("foundry should be enabled after seed")
	}
}

func TestReloadGroupHandlesNotFound(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	ctx := context.Background()

	// ReloadGroup for a non-existent key should not error
	if err := mgr.ReloadGroup(ctx, GroupWeb); err != nil {
		t.Fatalf("unexpected error on missing group: %v", err)
	}
}

func TestManagerStartStop(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog(), WithRefreshInterval(10*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	mgr.Start(ctx)

	// Write through a second Manager sharing the same store
	mgr2 := NewManager(store, discardLog())
	if err := mgr2.UpdateSecurity(ctx, &SecuritySnapshot{IPRateLimit: 7777}, "test"); err != nil {
		t.Fatal(err)
	}

	// Wait for the background loop to pick it up
	deadline := time.After(2 * time.Second)
	for {
		if mgr.Security().IPRateLimit == 7777 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("background refresh did not pick up IPRateLimit=7777, got %d", mgr.Security().IPRateLimit)
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	time.Sleep(20 * time.Millisecond) // let the goroutine exit
}

func TestApplyRowBadJSON(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())

	// Simulate a store that has bad JSON for a valid group
	ctx := context.Background()
	if err := store.Put(ctx, GroupSecurity, "not-json", "test"); err != nil {
		t.Fatal(err)
	}
	// Reload should not fail — it logs and skips
	if err := mgr.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	// Snapshot should still have defaults
	if mgr.Security().IPRateLimit != 200 {
		t.Fatalf("IPRateLimit = %d after bad JSON", mgr.Security().IPRateLimit)
	}
}

func TestSnapshotDefaultsWebEnabled(t *testing.T) {
	snap := DefaultWeb()
	if snap == nil {
		t.Fatal("DefaultWeb() returned nil")
	}
	if !snap.Enabled {
		t.Fatal("DefaultWeb().Enabled should be true")
	}
}
