package server

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/notify"
	"github.com/ivanzzeth/remote-signer/internal/settings"
)

func TestSecurityYAMLView(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.RateLimitDefault = 200
	cfg.Security.IPRateLimit = 300
	cfg.Security.AutoLockTimeout = 5 * time.Minute

	view := securityYAMLView(cfg)
	if view.RateLimitDefault != 200 {
		t.Errorf("RateLimitDefault = %d", view.RateLimitDefault)
	}
	if view.IPRateLimit != 300 {
		t.Errorf("IPRateLimit = %d", view.IPRateLimit)
	}
	if view.AutoLockTimeout != 5*time.Minute {
		t.Errorf("AutoLockTimeout = %v", view.AutoLockTimeout)
	}
}

func TestNotifyYAMLToSnapshot(t *testing.T) {
	cfg := &notify.Config{
		Slack: &notify.SlackConfig{Enabled: true, BotToken: "xoxb-123"},
		Telegram: &notify.TelegramConfig{Enabled: true, BotToken: "tg-456"},
	}
	channels := &notify.Channel{
		Slack:    []string{"#general", "#alerts"},
		Telegram: []string{"@user"},
	}

	snap := notifyYAMLToSnapshot(cfg, channels)
	if snap.Providers.Slack == nil || !snap.Providers.Slack.Enabled {
		t.Fatal("slack provider missing")
	}
	if snap.Providers.Slack.BotToken != "xoxb-123" {
		t.Fatalf("token = %s", snap.Providers.Slack.BotToken)
	}
	if snap.Providers.Telegram == nil || !snap.Providers.Telegram.Enabled {
		t.Fatal("telegram provider missing")
	}
	if len(snap.Channels.Slack) != 2 || snap.Channels.Slack[0] != "#general" {
		t.Fatalf("slack channels = %v", snap.Channels.Slack)
	}
}

func TestApplySecuritySnapshot(t *testing.T) {
	cfg := &config.Config{}
	snap := &settings.SecuritySnapshot{
		MaxRequestAge:    120 * time.Second,
		RateLimitDefault: 500,
		NonceRequired:    true,
		IPWhitelist: settings.IPWhitelist{
			Enabled:    true,
			AllowedIPs: []string{"10.0.0.0/8"},
		},
	}
	applySecuritySnapshot(cfg, snap)

	if cfg.Security.RateLimitDefault != 500 {
		t.Errorf("RateLimitDefault = %d", cfg.Security.RateLimitDefault)
	}
	if *cfg.Security.NonceRequired != true {
		t.Errorf("NonceRequired = %v", *cfg.Security.NonceRequired)
	}
	if !cfg.Security.IPWhitelist.Enabled {
		t.Errorf("IPWhitelist.Enabled = false")
	}
	if len(cfg.Security.IPWhitelist.AllowedIPs) != 1 {
		t.Errorf("AllowedIPs = %v", cfg.Security.IPWhitelist.AllowedIPs)
	}
}

func TestApplyNotifySnapshot(t *testing.T) {
	cfg := &notify.Config{}
	channels := &notify.Channel{}
	snap := &settings.NotifySnapshot{
		Providers: settings.NotifyProviders{
			Pushover: &settings.NotifyPushoverProvider{Enabled: true, AppToken: "po-token", Retry: 30},
		},
		Channels: settings.NotifyChannels{
			Pushover: []string{"user1"},
		},
	}

	applyNotifySnapshot(cfg, channels, snap)
	if cfg.Pushover == nil || !cfg.Pushover.Enabled {
		t.Fatal("pushover not applied")
	}
	if cfg.Pushover.AppToken != "po-token" {
		t.Fatalf("token = %s", cfg.Pushover.AppToken)
	}
}

func TestEVMSnapshotConversionRoundTrip(t *testing.T) {
	foundryCfg := config.FoundryConfig{Enabled: true, ForgePath: "/usr/bin/forge", Timeout: 30 * time.Second}
	foundrySnap := foundryToSnapshot(foundryCfg)
	if !foundrySnap.Enabled || foundrySnap.ForgePath != "/usr/bin/forge" {
		t.Fatalf("foundry: %+v", foundrySnap)
	}

	simCfg := config.SimulationConfig{Enabled: true, Timeout: 5 * time.Second}
	simSnap := simulationToSnapshot(simCfg)
	if !simSnap.Enabled || simSnap.AutoCreateBudget != true {
		t.Fatalf("simulation: %+v", simSnap)
	}
	if simSnap.MaxDynamicUnits != 100 {
		t.Fatalf("MaxDynamicUnits = %d", simSnap.MaxDynamicUnits)
	}

	rpcCfg := evm.RPCGatewayConfig{BaseURL: "https://rpc.example.com", CacheTTL: 24 * time.Hour}
	rpcSnap := rpcGatewayToSnapshot(rpcCfg)
	if rpcSnap.BaseURL != "https://rpc.example.com" {
		t.Fatalf("rpc: %+v", rpcSnap)
	}

	matCfg := config.SignerMaterialCheckConfig{Enabled: true, StartupCheck: true}
	matSnap := materialCheckToSnapshot(matCfg)
	if !matSnap.Enabled || !matSnap.StartupCheck {
		t.Fatalf("material: %+v", matSnap)
	}
}

func TestBlocklistToSnapshot(t *testing.T) {
	b := &config.DynamicBlocklistConfig{
		Enabled:      true,
		SyncInterval: "1h",
		Sources: []config.DynamicBlocklistSource{
			{Name: "ofac", Type: "json", URL: "https://example.com/list.json"},
		},
	}
	snap := blocklistToSnapshot(b)
	if !snap.Enabled || snap.SyncInterval != "1h" {
		t.Fatalf("basic: %+v", snap)
	}
	if len(snap.Sources) != 1 || snap.Sources[0].Name != "ofac" {
		t.Fatalf("sources: %+v", snap.Sources)
	}

	nilSnap := blocklistToSnapshot(nil)
	if nilSnap == nil || nilSnap.Enabled {
		t.Fatal("nil input should yield empty snapshot")
	}
}

func TestAuditMonitorToSnapshot(t *testing.T) {
	m := audit.MonitorConfig{
		Enabled:                  true,
		Interval:                 5 * time.Minute,
		AuthFailureThreshold:     10,
		BlocklistRejectThreshold: 5,
	}
	snap := auditMonitorToSnapshot(m)
	if !snap.Enabled || snap.Interval != 5*time.Minute {
		t.Fatalf("basic: %+v", snap)
	}
	if snap.AuthFailureThreshold != 10 {
		t.Fatalf("threshold = %d", snap.AuthFailureThreshold)
	}
}

func TestApplyEVMSnapshots(t *testing.T) {
	cfg := &config.Config{Chains: config.ChainsConfig{EVM: &config.EVMConfig{}}}
	applyEVMSnapshots(cfg,
		&settings.FoundrySnapshot{Enabled: true, ForgePath: "/test/forge"},
		&settings.SimulationSnapshot{Enabled: true, Timeout: 10 * time.Second},
		&settings.RPCGatewaySnapshot{BaseURL: "https://rpc.test"},
		&settings.MaterialCheckSnapshot{Enabled: true, Interval: 1 * time.Hour},
	)
	if !cfg.Chains.EVM.Foundry.Enabled || cfg.Chains.EVM.Foundry.ForgePath != "/test/forge" {
		t.Fatal("foundry not applied")
	}
	if !cfg.Chains.EVM.Simulation.Enabled || cfg.Chains.EVM.Simulation.Timeout != 10*time.Second {
		t.Fatal("simulation not applied")
	}
	if cfg.Chains.EVM.RPCGateway.BaseURL != "https://rpc.test" {
		t.Fatal("rpc gateway not applied")
	}
	if !cfg.Chains.EVM.MaterialCheck.Enabled {
		t.Fatal("material check not applied")
	}

	// nil EVM should be a no-op
	cfg2 := &config.Config{}
	applyEVMSnapshots(cfg2,
		&settings.FoundrySnapshot{Enabled: true},
		nil, nil, nil,
	)
}

func TestApplyBlocklistSnapshot(t *testing.T) {
	cfg := &config.Config{}
	applyBlocklistSnapshot(cfg, &settings.BlocklistSnapshot{
		Enabled: true, SyncInterval: "30m",
		Sources: []settings.BlocklistEntry{{Name: "test"}},
	})
	if cfg.DynamicBlocklist == nil || !cfg.DynamicBlocklist.Enabled {
		t.Fatal("blocklist not created")
	}
	if len(cfg.DynamicBlocklist.Sources) != 1 {
		t.Fatalf("sources = %d", len(cfg.DynamicBlocklist.Sources))
	}
}

func TestApplyAuditMonitorSnapshot(t *testing.T) {
	cfg := &config.Config{}
	applyAuditMonitorSnapshot(cfg, &settings.AuditMonitorSnapshot{
		Enabled: true, LookbackHours: 24,
	})
	if !cfg.AuditMonitor.Enabled || cfg.AuditMonitor.LookbackHours != 24 {
		t.Fatal("audit monitor not applied")
	}
}

func TestAbsDirRelativeToConfig(t *testing.T) {
	got := absDirRelativeToConfig("/absolute/path", "/some/config.yaml")
	if got != "/absolute/path" {
		t.Fatalf("abs path = %s", got)
	}

	got = absDirRelativeToConfig("rules/templates", "/home/user/.remote-signer/config.yaml")
	want := "/home/user/.remote-signer/rules/templates"
	if got != want {
		t.Fatalf("relative = %s, want %s", got, want)
	}

	if got := absDirRelativeToConfig("", "/cfg.yaml"); got != "" {
		t.Fatalf("empty = %s", got)
	}
}

func TestAsInterval(t *testing.T) {
	if d := asInterval("1h", 5*time.Minute); d != time.Hour {
		t.Fatalf("1h = %v", d)
	}
	if d := asInterval("", 5*time.Minute); d != 5*time.Minute {
		t.Fatalf("empty = %v", d)
	}
	if d := asInterval("invalid", time.Minute); d != time.Minute {
		t.Fatalf("invalid = %v", d)
	}
}

func TestNotifyEnabled(t *testing.T) {
	if notifyEnabled(nil) {
		t.Fatal("nil should be disabled")
	}
	if notifyEnabled(&notify.Config{}) {
		t.Fatal("empty config should be disabled")
	}
	if !notifyEnabled(&notify.Config{Slack: &notify.SlackConfig{Enabled: true}}) {
		t.Fatal("slack enabled should return true")
	}
}

func TestBootstrapWithRateLimit(t *testing.T) {
	tmp := t.TempDir()
	priv := filepath.Join(tmp, "admin.key.priv")
	pub := filepath.Join(tmp, "admin.key.pub")
	repo := newTestRepo(t)

	if err := bootstrapAdminKeyIfNeeded(context.Background(), repo, priv, pub, 500, discardLogger()); err != nil {
		t.Fatal(err)
	}

	row, err := repo.Get(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if row.RateLimit != 500 {
		t.Errorf("RateLimit = %d, want 500", row.RateLimit)
	}
}

func TestBootstrapExistingKeysNoReplace(t *testing.T) {
	tmp := t.TempDir()
	priv := filepath.Join(tmp, "admin.key.priv")
	pub := filepath.Join(tmp, "admin.key.pub")
	repo := newTestRepo(t)

	if err := bootstrapAdminKeyIfNeeded(context.Background(), repo, priv, pub, 100, discardLogger()); err != nil {
		t.Fatal(err)
	}

	if err := bootstrapAdminKeyIfNeeded(context.Background(), repo, priv, pub, 999, discardLogger()); err != nil {
		t.Fatal(err)
	}

	row, err := repo.Get(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if row.RateLimit != 100 {
		t.Errorf("RateLimit = %d, want 100 (should not be overwritten)", row.RateLimit)
	}
}

func TestBootstrapAdminKeyPEMFormat(t *testing.T) {
	tmp := t.TempDir()
	priv := filepath.Join(tmp, "admin.key.priv")
	pub := filepath.Join(tmp, "admin.key.pub")
	repo := newTestRepo(t)

	if err := bootstrapAdminKeyIfNeeded(context.Background(), repo, priv, pub, 0, discardLogger()); err != nil {
		t.Fatal(err)
	}

	privPEM, _ := os.ReadFile(priv)
	block, _ := pem.Decode(privPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("priv PEM block invalid: %v", block)
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("priv key parse: %v", err)
	}
	if _, ok := parsedKey.(ed25519.PrivateKey); !ok {
		t.Fatalf("expected ed25519 key, got %T", parsedKey)
	}

	pubPEM, _ := os.ReadFile(pub)
	pubBlock, _ := pem.Decode(pubPEM)
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		t.Fatalf("pub PEM block invalid: %v", pubBlock)
	}
	parsedPub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("pub key parse: %v", err)
	}
	if _, ok := parsedPub.(ed25519.PublicKey); !ok {
		t.Fatalf("expected ed25519 pubkey, got %T", parsedPub)
	}
}

func TestCopyStringMap(t *testing.T) {
	src := map[string]string{"key1": "val1", "key2": "val2"}
	dst := copyStringMap(src)
	if len(dst) != 2 || dst["key1"] != "val1" {
		t.Fatalf("copy failed: %v", dst)
	}
	src["key1"] = "changed"
	if dst["key1"] != "val1" {
		t.Fatal("copy is not independent")
	}
	if copyStringMap(nil) != nil {
		t.Fatal("nil should produce nil")
	}
}
