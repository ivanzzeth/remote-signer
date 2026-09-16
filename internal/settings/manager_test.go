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
	if *mgr.Security().IPRateLimit != 200 {
		t.Errorf("default IPRateLimit = %d, want 200", *mgr.Security().IPRateLimit)
	}
}

func TestUpdateSecurityRoundTrip(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	ctx := context.Background()

	patch := DefaultSecurity()
	patch.IPRateLimit = Ptr(5000)
	patch.MaxRulesPerAPIKey = Ptr(7)
	if err := mgr.UpdateSecurity(ctx, patch, UpdatedByAPI); err != nil {
		t.Fatal(err)
	}
	if got := *mgr.Security().IPRateLimit; got != 5000 {
		t.Errorf("after update IPRateLimit = %d, want 5000", got)
	}

	// New Manager reading from the same store should see the write.
	mgr2 := NewManager(store, discardLog())
	if err := mgr2.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if got := *mgr2.Security().IPRateLimit; got != 5000 {
		t.Errorf("reloaded IPRateLimit = %d, want 5000", got)
	}
	if got := *mgr2.Security().MaxRulesPerAPIKey; got != 7 {
		t.Errorf("reloaded MaxRulesPerAPIKey = %d, want 7", got)
	}
}

// TestUpdateSecurity_PartialPatchKeepsTheRest 钉住这次指针化改动的**全部意义**。
//
// ⛔ 2026-09-15 之前这条会失败,而且失败在安全的反方向:handler 把 body 解进一个
// **全零值**结构体再整份存下去。于是一个只想调限流的 PUT(`{"rate_limit_default":500}`)
// 会顺手把 nonce_required / manual_approval_enabled / require_approval_for_agent_rules
// 写成 false(默认都是 true),并把三个「每 key 上限」写成 0 —— 而 0 在
// max_keystores_per_key / max_hd_wallets_per_key 上的含义是**无限制**
// (internal/config/config.go:341,345)。
//
// ⭐ 判据一句话:*少写一个字段,后果会不会更松?* 不会,才算修好。
// 这正是 PRD §6 的 N3(「没设置」不许被当成「不限制」)与 N1(配置写错不许更宽松)。
func TestUpdateSecurity_PartialPatchKeepsTheRest(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	ctx := context.Background()

	// 只提到一个字段,其余全是 nil —— 即「这次请求没有提到它们」。
	if err := mgr.UpdateSecurity(ctx, &SecuritySnapshot{RateLimitDefault: Ptr(500)}, UpdatedByAPI); err != nil {
		t.Fatal(err)
	}

	got := mgr.Security()
	if v := *got.RateLimitDefault; v != 500 {
		t.Errorf("RateLimitDefault = %d, want 500 —— patch 本身没生效", v)
	}

	// ⛔ 三个安全开关:不在 patch 里,一个都不许动。
	for _, c := range []struct {
		name string
		on   bool
	}{
		{"NonceRequired", *got.NonceRequired},
		{"ManualApprovalEnabled", *got.ManualApprovalEnabled},
		{"RequireApprovalForAgentRules", *got.RequireApprovalForAgentRules},
	} {
		if !c.on {
			t.Errorf("%s 被这次 patch 关掉了 —— 它不在 patch 里,不该动", c.name)
		}
	}

	// ⛔ 三个上限:归零等于**取消限制**,比开关被关掉更隐蔽。
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"MaxRulesPerAPIKey", *got.MaxRulesPerAPIKey, 50},
		{"MaxKeystoresPerKey", *got.MaxKeystoresPerKey, 5},
		{"MaxHDWalletsPerKey", *got.MaxHDWalletsPerKey, 3},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d —— 归零在这几个字段上意味着「无限制」", c.name, c.got, c.want)
		}
	}

	// ⚠️ 落库也要查:合并结果只活在内存里的话,重启就原形毕露。
	mgr2 := NewManager(store, discardLog())
	if err := mgr2.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if v := *mgr2.Security().NonceRequired; !v {
		t.Error("重新载入后 NonceRequired = false —— 存进库的是一份被清零的配置")
	}
}

// TestUpdateSecurity_ExplicitFalseStillApplies 是上一条的**反方向**。
//
// ⚠️ 合并语义有一个经典的做坏法:把「零值」当成「没提供」。那样修完之后
// nonce_required 就再也关不掉了 —— 而一个改不动的开关,和一个会被误关的开关,
// 同样糟。nil 才是「没提供」,显式写下来的 false 必须照写进去。
func TestUpdateSecurity_ExplicitFalseStillApplies(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	ctx := context.Background()

	if v := *mgr.Security().NonceRequired; !v {
		t.Fatal("前提不成立:出厂默认的 NonceRequired 应为 true")
	}
	if err := mgr.UpdateSecurity(ctx, &SecuritySnapshot{NonceRequired: Ptr(false)}, UpdatedByAPI); err != nil {
		t.Fatal(err)
	}
	if v := *mgr.Security().NonceRequired; v {
		t.Error("显式发 nonce_required=false 没生效 —— 合并把零值误当成了「没提供」")
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
	patch.IPRateLimit = Ptr(9999)
	if err := a.UpdateSecurity(ctx, patch, "test"); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(2 * time.Second)
	for {
		if *b.Security().IPRateLimit == 9999 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("manager b did not pick up the change in time: got IPRateLimit=%d", *b.Security().IPRateLimit)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestApplyRowIgnoresUnknownGroup(t *testing.T) {
	mgr := NewManager(newTestStore(t), discardLog())
	mgr.applyRow(&Setting{Key: "totally-unknown", ValueJSON: "{}"})
	// Should not panic or affect any known snapshot.
	if *mgr.Security().IPRateLimit != 200 {
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
	patch.IPRateLimit = Ptr(4242)
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
				if *mgr.Security().IPRateLimit != 4242 {
					t.Errorf("snapshot tear")
				}
			}
		}()
	}
	wg.Wait()
}
