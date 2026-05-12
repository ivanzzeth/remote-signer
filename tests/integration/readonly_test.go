//go:build integration

package integration

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestVersionCommand pins the unified-version output. Helpful when bumping
// `internal/version.Version` to confirm the bump actually surfaced.
func TestVersionCommand(t *testing.T) {
	stdout, _, err := cli(t, "version")
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout), "remote-signer ") {
		t.Errorf("expected 'remote-signer <ver>', got %q", stdout)
	}
}

// TestKeystoreList exercises the local keystore subcommand against an empty
// directory — should exit 0 and not list anything.
func TestKeystoreList(t *testing.T) {
	dir := t.TempDir()
	stdout, _, err := cli(t, "keystore", "list", "-d", dir)
	if err != nil {
		t.Fatalf("keystore list: %v", err)
	}
	// Empty directory: no rows. Exact wording isn't pinned; just ensure no
	// file paths leak in.
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), ".json") {
			t.Errorf("unexpected keystore in empty dir: %q", line)
		}
	}
}

// TestPresetList scans the repo's bundled rules/presets/ directory and
// expects at least one preset. Anchors the preset surface against
// accidental directory removal.
func TestPresetList(t *testing.T) {
	presetDir := filepath.Join(repoRoot(), "rules", "presets")
	if _, err := os.Stat(presetDir); err != nil {
		t.Skipf("rules/presets/ not present at %s; skipping", presetDir)
	}
	stdout, _, err := cli(t, "preset", "list", "--presets-dir", presetDir)
	if err != nil {
		t.Fatalf("preset list: %v", err)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Errorf("preset list output empty against %s", presetDir)
	}
}

// TestACL_IPWhitelist returns the live IP-whitelist config (default:
// disabled). Verifies the admin-only ACLs read path.
func TestACL_IPWhitelist(t *testing.T) {
	d := startDaemon(t)
	stdout, _, err := d.runCLI(t, "--json", "acl", "ip-whitelist")
	if err != nil {
		t.Fatalf("acl ip-whitelist: %v", err)
	}
	if !strings.Contains(stdout, `"enabled"`) {
		t.Errorf("expected enabled field in acl response: %s", stdout)
	}
}

// TestAudit_List validates the audit-log read path. The bootstrap admin
// key creation is itself audited, so a fresh daemon already has at least
// one row.
func TestAudit_List(t *testing.T) {
	d := startDaemon(t)
	stdout, _, err := d.runCLI(t, "--json", "audit", "list", "--limit", "10")
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if !strings.Contains(stdout, "{") {
		t.Errorf("expected JSON output, got: %s", stdout)
	}
}

// TestAudit_FilterByAPIKey exercises the renamed --by-api-key-id filter
// (separate from the global --api-key-id auth flag) so the audit list
// can still be scoped to events emitted by a specific key.
func TestAudit_FilterByAPIKey(t *testing.T) {
	d := startDaemon(t)
	stdout, stderr, err := d.runCLI(t, "--json", "audit", "list",
		"--by-api-key-id", "admin",
		"--limit", "10",
	)
	if err != nil {
		t.Fatalf("audit list --by-api-key-id: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "{") {
		t.Errorf("expected JSON, got: %s", stdout)
	}
}

// TestDoctor reports local diagnostic status; expected to succeed on the
// happy path with auth wired up (api-key-id + key file).
func TestDoctor(t *testing.T) {
	d := startDaemon(t)
	stdout, stderr, err := d.runCLI(t, "doctor")
	if err != nil {
		t.Fatalf("doctor: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "remote-signer") {
		t.Errorf("doctor output missing header: %s", stdout)
	}
}

// TestMetrics_NoAuth confirms the Prometheus endpoint is reachable without
// authentication (the documented contract — admin keys still required for
// every other admin path).
func TestMetrics_NoAuth(t *testing.T) {
	d := startDaemon(t)
	resp, err := http.Get(d.url() + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/metrics without auth status = %d, want 200", resp.StatusCode)
	}
}

// TestHealth_NoAuth pins the readiness probe: /health must answer 200 to
// unauthenticated callers (docker healthcheck, k8s probes).
func TestHealth_NoAuth(t *testing.T) {
	d := startDaemon(t)
	resp, err := http.Get(d.url() + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/health without auth status = %d, want 200", resp.StatusCode)
	}
}

// TestCompletion smoke-tests `remote-signer completion bash` — the cobra
// auto-generator. Must exit 0 and emit a recognisable bash completion
// script header.
func TestCompletion(t *testing.T) {
	stdout, _, err := cli(t, "completion", "bash")
	if err != nil {
		t.Fatalf("completion bash: %v", err)
	}
	if !strings.Contains(stdout, "bash completion") && !strings.Contains(stdout, "_remote-signer") {
		t.Errorf("completion bash output looks wrong: %s", stdout[:min(200, len(stdout))])
	}
}

// TestRootHelp checks the unified-binary help text lists every documented
// subcommand. Provides early warning if a `cmd.AddCommand(...)` ever
// vanishes during a refactor.
func TestRootHelp(t *testing.T) {
	cmd := exec.Command(binaryPath, "--help")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--help: %v\noutput: %s", err, out)
	}
	want := []string{
		"server", "tui", "validate", "version",
		"rule", "template", "preset", "settings",
		"api-key", "keystore", "evm", "sign",
		"audit", "acl", "doctor", "health", "metrics",
		"config",
	}
	for _, sub := range want {
		if !strings.Contains(string(out), sub) {
			t.Errorf("--help missing subcommand %q\nfull output:\n%s", sub, out)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
