package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"
)

// DefaultRefreshInterval is the cadence at which Manager polls the store for
// updates. 5 seconds matches the chosen latency budget for hot reload (see
// docs/deployment.md). Tests may override via WithRefreshInterval.
const DefaultRefreshInterval = 5 * time.Second

// Manager owns one atomic snapshot per configuration group. Reads are O(1)
// (atomic.Pointer.Load) so the request-path hot loop has no locking.
//
// Writes happen via the typed Update<Group> methods (and the admin API
// surface that wraps them). They persist to the store, then reload the local
// snapshot synchronously so the calling goroutine never sees stale state for
// the value it just wrote.
//
// Background refresh keeps replicas of the daemon in sync when an admin in a
// different process mutates the store (today: cluster scenarios; tomorrow:
// the CLI does this too). The interval is intentionally fixed — anyone who
// needs the change to take effect immediately can invoke an admin endpoint
// that calls Reload(group) explicitly.
type Manager struct {
	store    Store
	log      *slog.Logger
	interval time.Duration

	security      atomic.Pointer[SecuritySnapshot]
	notify        atomic.Pointer[NotifySnapshot]
	foundry       atomic.Pointer[FoundrySnapshot]
	simulation    atomic.Pointer[SimulationSnapshot]
	blocklist     atomic.Pointer[BlocklistSnapshot]
	auditMonitor  atomic.Pointer[AuditMonitorSnapshot]
	rpcGateway    atomic.Pointer[RPCGatewaySnapshot]
	materialCheck atomic.Pointer[MaterialCheckSnapshot]
	web           atomic.Pointer[WebSnapshot]
}

// Option configures a Manager.
type Option func(*Manager)

// WithRefreshInterval overrides the default poll interval.
func WithRefreshInterval(d time.Duration) Option {
	return func(m *Manager) {
		if d > 0 {
			m.interval = d
		}
	}
}

// NewManager constructs a Manager seeded with the secure-by-default snapshots
// for every group. Callers typically invoke Reload(ctx) once at startup to
// pull live values from the store, then Start(ctx) to begin background
// refresh.
func NewManager(store Store, log *slog.Logger, opts ...Option) *Manager {
	if log == nil {
		log = slog.Default()
	}
	m := &Manager{
		store:    store,
		log:      log,
		interval: DefaultRefreshInterval,
	}
	for _, opt := range opts {
		opt(m)
	}
	// Seed defaults so callers never get nil pointers before the first Reload.
	m.security.Store(DefaultSecurity())
	m.notify.Store(&NotifySnapshot{})
	m.foundry.Store(&FoundrySnapshot{})
	m.simulation.Store(&SimulationSnapshot{})
	m.blocklist.Store(&BlocklistSnapshot{})
	m.auditMonitor.Store(&AuditMonitorSnapshot{})
	m.rpcGateway.Store(&RPCGatewaySnapshot{})
	m.materialCheck.Store(&MaterialCheckSnapshot{})
	m.web.Store(DefaultWeb())
	return m
}

// Security returns the current security snapshot. The returned pointer must
// be treated as immutable; callers that need to mutate must go through
// UpdateSecurity.
func (m *Manager) Security() *SecuritySnapshot { return m.security.Load() }

// Notify returns the current notify snapshot (providers + recipient channels).
func (m *Manager) Notify() *NotifySnapshot { return m.notify.Load() }

// Foundry returns the current foundry snapshot.
func (m *Manager) Foundry() *FoundrySnapshot { return m.foundry.Load() }

// Simulation returns the current simulation snapshot.
func (m *Manager) Simulation() *SimulationSnapshot { return m.simulation.Load() }

// Blocklist returns the current dynamic blocklist snapshot.
func (m *Manager) Blocklist() *BlocklistSnapshot { return m.blocklist.Load() }

// AuditMonitor returns the current audit-monitor snapshot.
func (m *Manager) AuditMonitor() *AuditMonitorSnapshot { return m.auditMonitor.Load() }

// RPCGateway returns the current RPC-gateway snapshot.
func (m *Manager) RPCGateway() *RPCGatewaySnapshot { return m.rpcGateway.Load() }

// MaterialCheck returns the current material-check snapshot.
func (m *Manager) MaterialCheck() *MaterialCheckSnapshot { return m.materialCheck.Load() }

// Web returns the current web-UI snapshot.
func (m *Manager) Web() *WebSnapshot { return m.web.Load() }

// Reload performs a single full refresh from the store. Used at startup to
// hydrate from any existing system_settings rows and after writes to publish
// the new value to the caller's goroutine.
func (m *Manager) Reload(ctx context.Context) error {
	rows, err := m.store.List(ctx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		m.applyRow(row)
	}
	return nil
}

// ReloadGroup refreshes a single group; admin handlers call this immediately
// after Put so the writer doesn't see stale state on the next request.
func (m *Manager) ReloadGroup(ctx context.Context, key Group) error {
	row, err := m.store.Get(ctx, key)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	m.applyRow(row)
	return nil
}

// applyRow decodes one row into the matching atomic snapshot. Unknown groups
// are skipped with a debug log so adding new groups is backwards-compatible.
func (m *Manager) applyRow(row *Setting) {
	switch Group(row.Key) {
	case GroupSecurity:
		var s SecuritySnapshot
		if err := json.Unmarshal([]byte(row.ValueJSON), &s); err != nil {
			m.log.Warn("settings: bad json", "group", row.Key, "err", err)
			return
		}
		m.security.Store(&s)
	case GroupNotify:
		var s NotifySnapshot
		if err := json.Unmarshal([]byte(row.ValueJSON), &s); err != nil {
			m.log.Warn("settings: bad json", "group", row.Key, "err", err)
			return
		}
		m.notify.Store(&s)
	case GroupFoundry:
		var s FoundrySnapshot
		if err := json.Unmarshal([]byte(row.ValueJSON), &s); err != nil {
			m.log.Warn("settings: bad json", "group", row.Key, "err", err)
			return
		}
		m.foundry.Store(&s)
	case GroupSimulation:
		var s SimulationSnapshot
		if err := json.Unmarshal([]byte(row.ValueJSON), &s); err != nil {
			m.log.Warn("settings: bad json", "group", row.Key, "err", err)
			return
		}
		m.simulation.Store(&s)
	case GroupBlocklist:
		var s BlocklistSnapshot
		if err := json.Unmarshal([]byte(row.ValueJSON), &s); err != nil {
			m.log.Warn("settings: bad json", "group", row.Key, "err", err)
			return
		}
		m.blocklist.Store(&s)
	case GroupAuditMonitor:
		var s AuditMonitorSnapshot
		if err := json.Unmarshal([]byte(row.ValueJSON), &s); err != nil {
			m.log.Warn("settings: bad json", "group", row.Key, "err", err)
			return
		}
		m.auditMonitor.Store(&s)
	case GroupRPCGateway:
		var s RPCGatewaySnapshot
		if err := json.Unmarshal([]byte(row.ValueJSON), &s); err != nil {
			m.log.Warn("settings: bad json", "group", row.Key, "err", err)
			return
		}
		m.rpcGateway.Store(&s)
	case GroupMaterialCheck:
		var s MaterialCheckSnapshot
		if err := json.Unmarshal([]byte(row.ValueJSON), &s); err != nil {
			m.log.Warn("settings: bad json", "group", row.Key, "err", err)
			return
		}
		m.materialCheck.Store(&s)
	case GroupWeb:
		var s WebSnapshot
		if err := json.Unmarshal([]byte(row.ValueJSON), &s); err != nil {
			m.log.Warn("settings: bad json", "group", row.Key, "err", err)
			return
		}
		m.web.Store(&s)
	}
}

// UpdateSecurity persists the patch to the store and refreshes the local
// snapshot. actor identifies the caller (e.g. an api_key_id) for audit; pass
// UpdatedBySystem for daemon-initiated writes.
// UpdateSecurity merges patch into the current snapshot and persists the result.
//
// ⛔ **合并,不是替换 —— 这一半不能省。** 指针只负责「表达」调用方没提到某个字段;
// 真正让「没提到」等于「别动它」的是这里。少了这一步,指针化只会把
// 「没填的字段被写成 false」换成「被写成 null」,比原来更糟。
//
// ⚠️ 2026-09-15 之前这里是整份替换:handler 把 body 解进一个**全零值**结构体再原样
// 存下去,于是一个只想改限流的 PUT 会顺手关掉防重放、人工审批、agent 规则审批,
// 并把三个「每 key 上限」写成 0(= 无限制)。详见 SecuritySnapshot 的类型注释。
//
// ⭐ 基线取 m.Security() 而不是 DefaultSecurity():要保留的是**当前生效值**,
// 不是出厂值。⚠️ 那个快照由不变式保证不含 nil(NewManager 播种 + 这里只增不减),
// 所以合并结果同样不含 nil —— 存进库的永远是一份完整配置,读回来不会有 null。
func (m *Manager) UpdateSecurity(ctx context.Context, patch *SecuritySnapshot, actor string) error {
	if patch == nil {
		return fmt.Errorf("nil security snapshot")
	}
	return m.put(ctx, GroupSecurity, mergeSecurity(m.Security(), patch), actor)
}

// mergeSecurity returns base with every non-nil field of patch applied.
//
// ⛔ Written out field by field on purpose. Reflection would survive a new field
// being added without anyone thinking about it — and "a field nobody thought
// about" is exactly the failure this whole change is about. A new field added to
// SecuritySnapshot and forgotten here stops being settable through the API,
// which is loud; the reflective version would instead silently do the wrong
// thing in whichever direction the zero value points.
func mergeSecurity(base, patch *SecuritySnapshot) *SecuritySnapshot {
	if base == nil {
		base = DefaultSecurity()
	}
	out := *base
	if patch.MaxRequestAge != nil {
		out.MaxRequestAge = patch.MaxRequestAge
	}
	if patch.RateLimitDefault != nil {
		out.RateLimitDefault = patch.RateLimitDefault
	}
	if patch.IPRateLimit != nil {
		out.IPRateLimit = patch.IPRateLimit
	}
	if patch.IPWhitelist != nil {
		out.IPWhitelist = patch.IPWhitelist
	}
	if patch.ManualApprovalEnabled != nil {
		out.ManualApprovalEnabled = patch.ManualApprovalEnabled
	}
	if patch.ApprovalGuard != nil {
		out.ApprovalGuard = patch.ApprovalGuard
	}
	if patch.NonceRequired != nil {
		out.NonceRequired = patch.NonceRequired
	}
	if patch.RulesAPIReadonly != nil {
		out.RulesAPIReadonly = patch.RulesAPIReadonly
	}
	if patch.SignersAPIReadonly != nil {
		out.SignersAPIReadonly = patch.SignersAPIReadonly
	}
	if patch.APIKeysAPIReadonly != nil {
		out.APIKeysAPIReadonly = patch.APIKeysAPIReadonly
	}
	if patch.AllowSIGHUPRulesReload != nil {
		out.AllowSIGHUPRulesReload = patch.AllowSIGHUPRulesReload
	}
	if patch.MaxRulesPerAPIKey != nil {
		out.MaxRulesPerAPIKey = patch.MaxRulesPerAPIKey
	}
	if patch.RequireApprovalForAgentRules != nil {
		out.RequireApprovalForAgentRules = patch.RequireApprovalForAgentRules
	}
	if patch.AutoLockTimeout != nil {
		out.AutoLockTimeout = patch.AutoLockTimeout
	}
	if patch.SignTimeout != nil {
		out.SignTimeout = patch.SignTimeout
	}
	if patch.MaxKeystoresPerKey != nil {
		out.MaxKeystoresPerKey = patch.MaxKeystoresPerKey
	}
	if patch.MaxHDWalletsPerKey != nil {
		out.MaxHDWalletsPerKey = patch.MaxHDWalletsPerKey
	}
	return &out
}

// UpdateNotify persists a new notify snapshot (providers + channels).
func (m *Manager) UpdateNotify(ctx context.Context, s *NotifySnapshot, actor string) error {
	if s == nil {
		return fmt.Errorf("nil notify snapshot")
	}
	return m.put(ctx, GroupNotify, s, actor)
}

// UpdateFoundry persists a new foundry snapshot.
func (m *Manager) UpdateFoundry(ctx context.Context, s *FoundrySnapshot, actor string) error {
	if s == nil {
		return fmt.Errorf("nil foundry snapshot")
	}
	return m.put(ctx, GroupFoundry, s, actor)
}

// UpdateSimulation persists a new simulation snapshot.
func (m *Manager) UpdateSimulation(ctx context.Context, s *SimulationSnapshot, actor string) error {
	if s == nil {
		return fmt.Errorf("nil simulation snapshot")
	}
	return m.put(ctx, GroupSimulation, s, actor)
}

// UpdateBlocklist persists a new blocklist snapshot.
func (m *Manager) UpdateBlocklist(ctx context.Context, s *BlocklistSnapshot, actor string) error {
	if s == nil {
		return fmt.Errorf("nil blocklist snapshot")
	}
	return m.put(ctx, GroupBlocklist, s, actor)
}

// UpdateAuditMonitor persists a new audit-monitor snapshot.
func (m *Manager) UpdateAuditMonitor(ctx context.Context, s *AuditMonitorSnapshot, actor string) error {
	if s == nil {
		return fmt.Errorf("nil audit monitor snapshot")
	}
	return m.put(ctx, GroupAuditMonitor, s, actor)
}

// UpdateRPCGateway persists a new RPC gateway snapshot.
func (m *Manager) UpdateRPCGateway(ctx context.Context, s *RPCGatewaySnapshot, actor string) error {
	if s == nil {
		return fmt.Errorf("nil rpc gateway snapshot")
	}
	return m.put(ctx, GroupRPCGateway, s, actor)
}

// UpdateMaterialCheck persists a new material-check snapshot.
func (m *Manager) UpdateMaterialCheck(ctx context.Context, s *MaterialCheckSnapshot, actor string) error {
	if s == nil {
		return fmt.Errorf("nil material check snapshot")
	}
	return m.put(ctx, GroupMaterialCheck, s, actor)
}

// UpdateWeb persists a new web-UI snapshot.
func (m *Manager) UpdateWeb(ctx context.Context, s *WebSnapshot, actor string) error {
	if s == nil {
		return fmt.Errorf("nil web snapshot")
	}
	return m.put(ctx, GroupWeb, s, actor)
}

func (m *Manager) put(ctx context.Context, key Group, value any, actor string) error {
	blob, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", key, err)
	}
	if err := m.store.Put(ctx, key, string(blob), actor); err != nil {
		return err
	}
	return m.ReloadGroup(ctx, key)
}

// Start spins up the background refresh loop. It returns immediately; the
// goroutine exits when ctx is cancelled.
func (m *Manager) Start(ctx context.Context) {
	go m.loop(ctx)
}

func (m *Manager) loop(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Reload(ctx); err != nil && !errors.Is(err, context.Canceled) {
				m.log.Warn("settings refresh failed", "err", err)
			}
		}
	}
}
