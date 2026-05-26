package settings

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Update methods for groups that are currently untested
// =============================================================================

func TestUpdateFoundry_RoundTrip(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	ctx := context.Background()

	patch := &FoundrySnapshot{Enabled: true, ForgePath: "/usr/bin/forge", Timeout: 30 * time.Second}
	err := mgr.UpdateFoundry(ctx, patch, UpdatedByAPI)
	require.NoError(t, err)

	got := mgr.Foundry()
	assert.True(t, got.Enabled)
	assert.Equal(t, "/usr/bin/forge", got.ForgePath)
	assert.Equal(t, 30*time.Second, got.Timeout)

	// Verify via second manager
	mgr2 := NewManager(store, discardLog())
	require.NoError(t, mgr2.Reload(ctx))
	assert.True(t, mgr2.Foundry().Enabled)
}

func TestUpdateFoundry_Nil(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	err := mgr.UpdateFoundry(context.Background(), nil, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil foundry snapshot")
}

func TestUpdateSimulation_RoundTrip(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	ctx := context.Background()

	patch := &SimulationSnapshot{Enabled: true, Timeout: 60 * time.Second, BatchWindow: 1 * time.Second}
	err := mgr.UpdateSimulation(ctx, patch, UpdatedByAPI)
	require.NoError(t, err)

	got := mgr.Simulation()
	assert.True(t, got.Enabled)
	assert.Equal(t, 60*time.Second, got.Timeout)
	assert.Equal(t, 1*time.Second, got.BatchWindow)

	// Verify persist
	mgr2 := NewManager(store, discardLog())
	require.NoError(t, mgr2.Reload(ctx))
	assert.True(t, mgr2.Simulation().Enabled)
}

func TestUpdateSimulation_Nil(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	err := mgr.UpdateSimulation(context.Background(), nil, "test")
	assert.Error(t, err)
}

func TestUpdateBlocklist_RoundTrip(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	ctx := context.Background()

	patch := &BlocklistSnapshot{Enabled: true, SyncInterval: "1h", FailMode: "deny"}
	err := mgr.UpdateBlocklist(ctx, patch, UpdatedByAPI)
	require.NoError(t, err)

	got := mgr.Blocklist()
	assert.True(t, got.Enabled)
	assert.Equal(t, "1h", got.SyncInterval)

	mgr2 := NewManager(store, discardLog())
	require.NoError(t, mgr2.Reload(ctx))
	assert.True(t, mgr2.Blocklist().Enabled)
}

func TestUpdateBlocklist_Nil(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	err := mgr.UpdateBlocklist(context.Background(), nil, "test")
	assert.Error(t, err)
}

func TestUpdateAuditMonitor_RoundTrip(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	ctx := context.Background()

	patch := &AuditMonitorSnapshot{Enabled: true, Interval: 5 * time.Minute, LookbackHours: 2}
	err := mgr.UpdateAuditMonitor(ctx, patch, UpdatedByAPI)
	require.NoError(t, err)

	got := mgr.AuditMonitor()
	assert.True(t, got.Enabled)
	assert.Equal(t, 5*time.Minute, got.Interval)

	mgr2 := NewManager(store, discardLog())
	require.NoError(t, mgr2.Reload(ctx))
	assert.True(t, mgr2.AuditMonitor().Enabled)
}

func TestUpdateAuditMonitor_Nil(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	err := mgr.UpdateAuditMonitor(context.Background(), nil, "test")
	assert.Error(t, err)
}

func TestUpdateRPCGateway_RoundTrip(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	ctx := context.Background()

	patch := &RPCGatewaySnapshot{BaseURL: "https://eth.example.com", APIKey: "key123", CacheTTL: 10 * time.Minute}
	err := mgr.UpdateRPCGateway(ctx, patch, UpdatedByAPI)
	require.NoError(t, err)

	got := mgr.RPCGateway()
	assert.Equal(t, "https://eth.example.com", got.BaseURL)
	assert.Equal(t, "key123", got.APIKey)

	mgr2 := NewManager(store, discardLog())
	require.NoError(t, mgr2.Reload(ctx))
	assert.Equal(t, "https://eth.example.com", mgr2.RPCGateway().BaseURL)
}

func TestUpdateRPCGateway_Nil(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	err := mgr.UpdateRPCGateway(context.Background(), nil, "test")
	assert.Error(t, err)
}

func TestUpdateMaterialCheck_RoundTrip(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	ctx := context.Background()

	patch := &MaterialCheckSnapshot{Enabled: true, StartupCheck: true, Interval: 30 * time.Minute}
	err := mgr.UpdateMaterialCheck(ctx, patch, UpdatedByAPI)
	require.NoError(t, err)

	got := mgr.MaterialCheck()
	assert.True(t, got.Enabled)
	assert.True(t, got.StartupCheck)

	mgr2 := NewManager(store, discardLog())
	require.NoError(t, mgr2.Reload(ctx))
	assert.True(t, mgr2.MaterialCheck().Enabled)
}

func TestUpdateMaterialCheck_Nil(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	err := mgr.UpdateMaterialCheck(context.Background(), nil, "test")
	assert.Error(t, err)
}

// =============================================================================
// Seed functions for currently untested groups
// =============================================================================

func TestSeedAuditMonitor(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := SeedAuditMonitor(ctx, store, &AuditMonitorSnapshot{Enabled: true, Interval: 5 * time.Minute})
	require.NoError(t, err)

	// Second call overwrites because first was also bootstrap-created.
	err = SeedAuditMonitor(ctx, store, &AuditMonitorSnapshot{Enabled: false})
	require.NoError(t, err)

	mgr := NewManager(store, discardLog())
	require.NoError(t, mgr.Reload(ctx))
	assert.False(t, mgr.AuditMonitor().Enabled)
}

func TestSeedBlocklist(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := SeedBlocklist(ctx, store, &BlocklistSnapshot{Enabled: true})
	require.NoError(t, err)

	err = SeedBlocklist(ctx, store, &BlocklistSnapshot{Enabled: false})
	require.NoError(t, err)

	mgr := NewManager(store, discardLog())
	require.NoError(t, mgr.Reload(ctx))
	assert.False(t, mgr.Blocklist().Enabled)
}

func TestSeedSimulation(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := SeedSimulation(ctx, store, &SimulationSnapshot{Enabled: true, Timeout: 30 * time.Second})
	require.NoError(t, err)

	err = SeedSimulation(ctx, store, &SimulationSnapshot{Enabled: false})
	require.NoError(t, err)

	mgr := NewManager(store, discardLog())
	require.NoError(t, mgr.Reload(ctx))
	assert.False(t, mgr.Simulation().Enabled)
}

func TestSeedRPCGateway(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := SeedRPCGateway(ctx, store, &RPCGatewaySnapshot{BaseURL: "https://rpc.example.com"})
	require.NoError(t, err)

	// Overwrites because first was also bootstrap-created.
	err = SeedRPCGateway(ctx, store, &RPCGatewaySnapshot{BaseURL: "https://other.example.com"})
	require.NoError(t, err)

	mgr := NewManager(store, discardLog())
	require.NoError(t, mgr.Reload(ctx))
	assert.Equal(t, "https://other.example.com", mgr.RPCGateway().BaseURL)
}

func TestSeedMaterialCheck(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := SeedMaterialCheck(ctx, store, &MaterialCheckSnapshot{Enabled: true})
	require.NoError(t, err)

	err = SeedMaterialCheck(ctx, store, &MaterialCheckSnapshot{Enabled: false})
	require.NoError(t, err)

	mgr := NewManager(store, discardLog())
	require.NoError(t, mgr.Reload(ctx))
	assert.False(t, mgr.MaterialCheck().Enabled)
}

// =============================================================================
// SecurityFromConfigValues
// =============================================================================

func TestSecurityFromConfigValues_Defaults(t *testing.T) {
	s := SecurityFromConfigValues(SecurityYAMLView{})
	assert.NotNil(t, s)
	assert.Equal(t, 60*time.Second, s.MaxRequestAge)
	assert.Equal(t, 100, s.RateLimitDefault)
	assert.Equal(t, 200, s.IPRateLimit)
	assert.True(t, s.NonceRequired)
	assert.False(t, s.ManualApprovalEnabled)
}

func TestSecurityFromConfigValues_Overrides(t *testing.T) {
	v := SecurityYAMLView{
		MaxRequestAge:    120 * time.Second,
		RateLimitDefault: 500,
		IPRateLimit:      1000,
	}
	s := SecurityFromConfigValues(v)
	assert.Equal(t, 120*time.Second, s.MaxRequestAge)
	assert.Equal(t, 500, s.RateLimitDefault)
	assert.Equal(t, 1000, s.IPRateLimit)
}

func TestSecurityFromConfigValues_ApprovalGuard(t *testing.T) {
	v := SecurityYAMLView{
		ApprovalGuardEnabled:      true,
		ApprovalGuardWindow:       2 * time.Hour,
		ApprovalGuardRejectionPct: 75,
		ApprovalGuardMinSamples:   20,
		ApprovalGuardResumeAfter:  4 * time.Hour,
	}
	s := SecurityFromConfigValues(v)
	assert.True(t, s.ApprovalGuard.Enabled)
	assert.Equal(t, 2*time.Hour, s.ApprovalGuard.Window)
	assert.Equal(t, float64(75), s.ApprovalGuard.RejectionThresholdPct)
	assert.Equal(t, 20, s.ApprovalGuard.MinSamples)
	assert.Equal(t, 4*time.Hour, s.ApprovalGuard.ResumeAfter)
}

func TestSecurityFromConfigValues_ApprovalGuardDefaults(t *testing.T) {
	v := SecurityYAMLView{ApprovalGuardEnabled: true}
	s := SecurityFromConfigValues(v)
	assert.True(t, s.ApprovalGuard.Enabled)
	assert.Equal(t, time.Hour, s.ApprovalGuard.Window)
	assert.Equal(t, float64(50), s.ApprovalGuard.RejectionThresholdPct)
	assert.Equal(t, 10, s.ApprovalGuard.MinSamples)
	assert.Equal(t, 2*time.Hour, s.ApprovalGuard.ResumeAfter)
}

func TestSecurityFromConfigValues_IPWhitelist(t *testing.T) {
	v := SecurityYAMLView{
		IPWhitelistEnabled:        true,
		IPWhitelistAllowedIPs:     []string{"10.0.0.1"},
		IPWhitelistTrustProxy:     true,
		IPWhitelistTrustedProxies: []string{"10.0.0.0/8"},
	}
	s := SecurityFromConfigValues(v)
	assert.True(t, s.IPWhitelist.Enabled)
	assert.Equal(t, []string{"10.0.0.1"}, s.IPWhitelist.AllowedIPs)
	assert.True(t, s.IPWhitelist.TrustProxy)
	assert.Equal(t, []string{"10.0.0.0/8"}, s.IPWhitelist.TrustedProxies)
}

func TestSecurityFromConfigValues_BoolPointers(t *testing.T) {
	trueVal := true
	v := SecurityYAMLView{
		NonceRequired:                &trueVal,
		RulesAPIReadonly:             &trueVal,
		SignersAPIReadonly:           &trueVal,
		APIKeysAPIReadonly:           &trueVal,
		AllowSIGHUPRulesReload:       &trueVal,
		RequireApprovalForAgentRules: &trueVal,
	}
	s := SecurityFromConfigValues(v)
	assert.True(t, s.NonceRequired)
	assert.True(t, s.RulesAPIReadonly)
	assert.True(t, s.SignersAPIReadonly)
	assert.True(t, s.APIKeysAPIReadonly)
	assert.True(t, s.AllowSIGHUPRulesReload)
	assert.True(t, s.RequireApprovalForAgentRules)
}

func TestSecurityFromConfigValues_OverflowFields(t *testing.T) {
	v := SecurityYAMLView{
		MaxRulesPerAPIKey:  100,
		AutoLockTimeout:    5 * time.Minute,
		SignTimeout:        60 * time.Second,
		MaxKeystoresPerKey: 10,
		MaxHDWalletsPerKey: 5,
	}
	s := SecurityFromConfigValues(v)
	assert.Equal(t, 100, s.MaxRulesPerAPIKey)
	assert.Equal(t, 5*time.Minute, s.AutoLockTimeout)
	assert.Equal(t, 60*time.Second, s.SignTimeout)
	assert.Equal(t, 10, s.MaxKeystoresPerKey)
	assert.Equal(t, 5, s.MaxHDWalletsPerKey)
}

// =============================================================================
// fallback helper functions
// =============================================================================

func TestFallbackDuration_Zero(t *testing.T) {
	assert.Equal(t, 5*time.Minute, fallbackDuration(0, 5*time.Minute))
}

func TestFallbackDuration_Positive(t *testing.T) {
	assert.Equal(t, 10*time.Second, fallbackDuration(10*time.Second, 5*time.Minute))
}

func TestFallbackInt_Zero(t *testing.T) {
	assert.Equal(t, 42, fallbackInt(0, 42))
}

func TestFallbackInt_Positive(t *testing.T) {
	assert.Equal(t, 99, fallbackInt(99, 42))
}

func TestFallbackFloat_Zero(t *testing.T) {
	assert.Equal(t, float64(3.14), fallbackFloat(0, 3.14))
}

func TestFallbackFloat_Positive(t *testing.T) {
	assert.Equal(t, float64(2.71), fallbackFloat(2.71, 3.14))
}

// =============================================================================
// DefaultSecurity checks for remaining fields
// =============================================================================

func TestDefaultSecurity_Full(t *testing.T) {
	s := DefaultSecurity()
	assert.Equal(t, 60*time.Second, s.MaxRequestAge)
	assert.Equal(t, 100, s.RateLimitDefault)
	assert.Equal(t, 200, s.IPRateLimit)
	assert.True(t, s.NonceRequired)
	assert.True(t, s.ManualApprovalEnabled)
	assert.False(t, s.RulesAPIReadonly)
	assert.False(t, s.SignersAPIReadonly)
	assert.False(t, s.APIKeysAPIReadonly)
	assert.False(t, s.AllowSIGHUPRulesReload)
	assert.Equal(t, 50, s.MaxRulesPerAPIKey)
	assert.True(t, s.RequireApprovalForAgentRules)
	assert.Equal(t, 30*time.Second, s.SignTimeout)
	assert.Equal(t, 5, s.MaxKeystoresPerKey)
	assert.Equal(t, 3, s.MaxHDWalletsPerKey)
	assert.Equal(t, ApprovalGuard{}, s.ApprovalGuard)
	assert.Equal(t, IPWhitelist{}, s.IPWhitelist)
}

// =============================================================================
// DefaultWeb
// =============================================================================

func TestDefaultWeb_Snapshot(t *testing.T) {
	s := DefaultWeb()
	require.NotNil(t, s)
	assert.True(t, s.Enabled)
	assert.Empty(t, s.DevProxy)
}

// =============================================================================
// SeedSecurity / SeedNotify / SeedFoundry / SeedWeb — extra coverage
// =============================================================================

func TestSeedSecurity_AlreadyExists(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, SeedSecurity(ctx, store, DefaultSecurity()))
	// Second call should be no-op (not error)
	require.NoError(t, SeedSecurity(ctx, store, DefaultSecurity()))
}

// =============================================================================
// ReloadGroup with non-existent key
// =============================================================================

func TestReloadGroup_NonExistent(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())
	ctx := context.Background()

	// Should not error for non-existent groups
	assert.NoError(t, mgr.ReloadGroup(ctx, GroupFoundry))
	assert.NoError(t, mgr.ReloadGroup(ctx, GroupSimulation))
}

// =============================================================================
// Manager with nil logger
// =============================================================================

func TestNewManager_NilLogger(t *testing.T) {
	mgr := NewManager(newTestStore(t), nil)
	assert.NotNil(t, mgr)
	assert.NotNil(t, mgr.Security())
}

// =============================================================================
// applyRow with bad JSON for various groups
// =============================================================================

func TestApplyRow_BadJSONForAllGroups(t *testing.T) {
	store := newTestStore(t)
	mgr := NewManager(store, discardLog())

	groups := []Group{GroupNotify, GroupFoundry, GroupSimulation, GroupBlocklist,
		GroupAuditMonitor, GroupRPCGateway, GroupMaterialCheck, GroupWeb}
	for _, g := range groups {
		mgr.applyRow(&Setting{Key: string(g), ValueJSON: "not-json"})
		// Should not panic; snapshot stays at defaults
	}
	assert.NotNil(t, mgr.Notify())
	assert.NotNil(t, mgr.Foundry())
	assert.NotNil(t, mgr.Simulation())
}
