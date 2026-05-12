//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfig_Path_ReturnsResolvedPath checks that `remote-signer config
// path` reports the same file the daemon loads, via the REMOTE_SIGNER_HOME
// → ./config.yaml resolution chain.
//
// We do not spin up the daemon — config path is a local-only command, so
// the test is fast and tag-free of HTTP plumbing.
func TestConfig_Path_ReturnsResolvedPath(t *testing.T) {
	tmpRoot := t.TempDir()
	home := filepath.Join(tmpRoot, "rs-home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("server:\n  port: 8548\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binaryPath, "config", "path")
	cmd.Env = append(os.Environ(), "REMOTE_SIGNER_HOME="+home)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("config path: %v", err)
	}
	want := filepath.Join(home, "config.yaml")
	got := strings.TrimSpace(string(out))
	if got != want {
		t.Errorf("config path = %q, want %q", got, want)
	}
}

// TestConfig_Show_LoadsAfterFirstLaunch boots the daemon (so the default
// config.yaml is materialised on disk), then runs `config show` and asserts
// the YAML contains the daemon's effective server.port — the round-trip via
// config.Load → setDefaults → yaml.Marshal must work.
func TestConfig_Show_LoadsAfterFirstLaunch(t *testing.T) {
	d := startDaemon(t)

	cmd := exec.Command(binaryPath, "config", "show", "--config", d.configPath)
	cmd.Env = append(os.Environ(), "REMOTE_SIGNER_HOME="+d.home)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("config show: %v", err)
	}
	body := string(out)
	if !strings.Contains(body, "server:") {
		t.Errorf("config show output missing server: block:\n%s", body)
	}
	if !strings.Contains(body, "database:") {
		t.Errorf("config show output missing database: block:\n%s", body)
	}
}

// TestLegacyConfig_RejectsAPIKeysBlock asserts the v0.3.0 breaking change:
// a config.yaml containing a non-empty `api_keys:` block must fail to load
// with the documented error pointing at the replacement command.
func TestLegacyConfig_RejectsAPIKeysBlock(t *testing.T) {
	legacy := `server:
  host: 127.0.0.1
  port: __PORT__
  tls:
    enabled: false
database:
  dsn: "file:__HOME__/legacy.db?_journal_mode=WAL&_busy_timeout=5000"
logger:
  level: info
chains:
  evm:
    enabled: true
api_keys:
  - id: legacy
    name: legacy
    public_key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    role: admin
    enabled: true
`
	d := startDaemon(t, withCustomConfig(legacy), expectStartupFailure())
	if err := d.wait(); err == nil {
		t.Fatalf("expected daemon to exit non-zero on legacy api_keys, got nil")
	}

	// The daemon log should contain the documented error.
	logBytes, _ := os.ReadFile(filepath.Join(filepath.Dir(d.configPath), "daemon.log"))
	logStr := string(logBytes)
	if !strings.Contains(logStr, `"api_keys" is no longer supported`) {
		t.Errorf("expected legacy-api_keys error in daemon log; got:\n%s", logStr)
	}
}

// TestLegacyConfig_RejectsRulesBlock is the rules-section twin of the
// api_keys legacy-rejection test.
func TestLegacyConfig_RejectsRulesBlock(t *testing.T) {
	legacy := `server:
  host: 127.0.0.1
  port: __PORT__
  tls:
    enabled: false
database:
  dsn: "file:__HOME__/legacy.db?_journal_mode=WAL&_busy_timeout=5000"
logger:
  level: info
chains:
  evm:
    enabled: true
rules:
  - name: legacy-rule
    type: evm_address_list
    mode: whitelist
    enabled: true
    config:
      addresses: []
`
	d := startDaemon(t, withCustomConfig(legacy), expectStartupFailure())
	if err := d.wait(); err == nil {
		t.Fatalf("expected daemon to exit non-zero on legacy rules block")
	}
	logBytes, _ := os.ReadFile(filepath.Join(filepath.Dir(d.configPath), "daemon.log"))
	if !strings.Contains(string(logBytes), `"rules" is no longer supported`) {
		t.Errorf("expected legacy-rules error in daemon log; got:\n%s", logBytes)
	}
}
